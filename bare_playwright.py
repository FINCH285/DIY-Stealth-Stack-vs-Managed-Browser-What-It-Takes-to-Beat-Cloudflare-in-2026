import argparse
import hashlib
import json
import os
import random
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version as package_version
from pathlib import Path

from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
from playwright.sync_api import sync_playwright

PROTOCOL_VERSION = "benchmark-v1.7-persistent-only"
SETUP_NAME = "bare_playwright"
PLAYWRIGHT_VERSION = package_version("playwright")
NAVIGATION_TIMEOUT_MS = 120_000
ACCESS_DEADLINE_MS = 120_000
DEFAULT_ACTION_TIMEOUT_MS = 10_000
DEFAULT_SEED = 20260916
DEFAULT_MIN_TARGET_INTERVAL_SECONDS = 60
DEFAULT_MAX_ATTEMPTS = 3

ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
SCREENSHOT_DIR = RESULTS_DIR / "screenshots" / SETUP_NAME
RESULTS_FILE = RESULTS_DIR / f"{SETUP_NAME}.jsonl"
PROFILE_ROOT = RESULTS_DIR / "profiles" / SETUP_NAME


@dataclass(frozen=True)
class Target:
    name: str
    url: str
    expected_host: str
    expected_path_fragment: str
    loaded_markers: tuple[str, ...]


# These positive content markers are verified during the unscored pilot and then frozen for scored runs.
TARGETS = (
    Target("indeed_google_reviews", "https://www.indeed.com/cmp/Google/reviews", "indeed.com", "/cmp/google/reviews", ("Google Reviews", "Work wellbeing", "Ratings by category")),
    Target("indeed_google_company", "https://www.indeed.com/cmp/Google", "indeed.com", "/cmp/google", ("Google", "Work wellbeing", "Why join us")),
    Target("glassdoor_google_salaries", "https://www.glassdoor.com/Salary/Google-Salaries-E9079.htm", "glassdoor.com", "/salary/google-salaries-e9079", ("Google Salaries", "salaries at Google", "Google salary")),
    Target("capterra_crm", "https://www.capterra.com/customer-relationship-management-software/", "capterra.com", "/customer-relationship-management-software", ("Customer Relationship Management", "CRM Software", "Customer Relationship Management Software")),
    Target("stockx_white_thunder", "https://stockx.com/air-jordan-4-retro-white-thunder", "stockx.com", "/air-jordan-4-retro-white-thunder", ("Air Jordan 4 Retro White Thunder", "White Thunder", "Jordan 4 Retro")),
)

TARGET_BY_NAME = {target.name: target for target in TARGETS}

CLOUDFLARE_TEXT_PATTERNS = (
    r"additional verification required",
    r"verify you are human",
    r"just a moment",
    r"checking your browser",
    r"security verification",
    r"cloudflare ray id",
    r"cf-chl",
)

CLOUDFLARE_RESOURCE_PATTERNS = (
    "/cdn-cgi/challenge-platform/",
    "challenges.cloudflare.com",
    "turnstile",
)


# Small helpers keep timestamps, filenames, and evidence capture consistent.
def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def slug(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", value).strip("-")


def elapsed_ms(started: float) -> float:
    return round((time.perf_counter() - started) * 1000, 2)


def identity_dir(batch_id: str) -> Path:
    return PROFILE_ROOT / slug(batch_id)


def identity_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]



def identity_record(identity_mode: str, identity_id: str | None, persistent_hit_index: int | None = None) -> dict:
    reused = identity_mode == "persistent" and (persistent_hit_index or 0) > 1
    return {
        "identity_mode": identity_mode,
        "identity_id": identity_id,
        "persistent_context": identity_mode == "persistent",
        "session_state_reused": reused,
        "persistent_hit_index": persistent_hit_index if identity_mode == "persistent" else None,
        "new_identity_this_attempt": identity_mode == "fresh",
    }


def acquire_profile_lock(profile_path: Path) -> Path:
    profile_path.mkdir(parents=True, exist_ok=True)
    lock_path = profile_path / "benchmark.lock"
    if lock_path.exists():
        raise RuntimeError(
            f"Persistent profile already in use: {profile_path}. "
            "Stop the other runner or delete benchmark.lock if it is stale."
        )
    lock_path.write_text(str(os.getpid()), encoding="utf-8")
    return lock_path


def release_profile_lock(lock_path: Path | None) -> None:
    if lock_path is None:
        return
    try:
        lock_path.unlink()
    except FileNotFoundError:
        pass


def page_evaluate(page, expression, arg=None):
    try:
        if arg is None:
            return page.evaluate(expression, isolated_context=True)
        return page.evaluate(expression, arg, isolated_context=True)
    except TypeError:
        if arg is None:
            return page.evaluate(expression)
        return page.evaluate(expression, arg)


def page_wait_for_function(page, expression, arg=None, timeout_ms: int = 0):
    try:
        page.wait_for_function(expression, arg=arg, timeout=timeout_ms, isolated_context=True)
    except TypeError:
        page.wait_for_function(expression, arg=arg, timeout=timeout_ms)


def safe_body_text(page) -> str:
    try:
        return page.locator("body").inner_text(timeout=5_000)
    except Exception:
        try:
            return page.content()
        except Exception:
            return ""


# Count success only when the expected host, path, and page content all match.
def target_loaded(page, target: Target) -> bool:
    expected = {
        "host": target.expected_host,
        "path": target.expected_path_fragment,
        "markers": list(target.loaded_markers),
    }
    return bool(page_evaluate(
        page,
        """expected => {
            const host = location.hostname.toLowerCase();
            const path = location.pathname.toLowerCase();
            const text = (document.body?.innerText || '').toLowerCase();
            const hostOk = host === expected.host || host.endsWith('.' + expected.host);
            const pathOk = path.includes(expected.path.toLowerCase());
            const markerOk = expected.markers.some(marker => text.includes(marker.toLowerCase()));
            return hostOk && pathOk && markerOk;
        }""",
        expected,
    ))


def wait_for_target(page, target: Target, timeout_ms: int) -> bool:
    expected = {
        "host": target.expected_host,
        "path": target.expected_path_fragment,
        "markers": list(target.loaded_markers),
    }
    try:
        page_wait_for_function(
            page,
            """expected => {
                const host = location.hostname.toLowerCase();
                const path = location.pathname.toLowerCase();
                const text = (document.body?.innerText || '').toLowerCase();
                const hostOk = host === expected.host || host.endsWith('.' + expected.host);
                const pathOk = path.includes(expected.path.toLowerCase());
                const markerOk = expected.markers.some(marker => text.includes(marker.toLowerCase()));
                return hostOk && pathOk && markerOk;
            }""",
            arg=expected,
            timeout_ms=timeout_ms,
        )
        return True
    except Exception as exc:
        if "Timeout" in type(exc).__name__:
            return False
        raise


def cloudflare_text_markers(text: str) -> list[str]:
    return [pattern for pattern in CLOUDFLARE_TEXT_PATTERNS if re.search(pattern, text, re.I)]


def response_snapshot(response) -> dict:
    headers = response.headers
    return {
        "url": response.url,
        "status": response.status,
        "server": headers.get("server"),
        "cf_ray": headers.get("cf-ray"),
        "content_type": headers.get("content-type"),
    }


# Convert browser evidence into scored outcomes without treating every failure as Cloudflare.
def classify_outcome(
    loaded: bool,
    access_timed_out: bool,
    navigation_error: str | None,
    final_text: str,
    document_responses: list[dict],
    challenge_resources: list[str],
) -> tuple[str, str | None, bool]:
    text_markers = cloudflare_text_markers(final_text)
    cf_headers_seen = any(
        (str(item.get("server") or "").lower() == "cloudflare") or item.get("cf_ray")
        for item in document_responses
    )
    verification_seen = bool(text_markers or challenge_resources)

    if loaded:
        classification = "loaded_after_cloudflare_verification" if verification_seen else "loaded"
        return classification, None, True

    if navigation_error and not document_responses:
        return "infrastructure_error", "navigation_error", False

    latest_status = document_responses[-1]["status"] if document_responses else None
    if text_markers:
        return "blocked_by_cloudflare", "cloudflare_verification_page", True
    if latest_status == 403 and cf_headers_seen:
        return "blocked_by_cloudflare", "cloudflare_403", True
    if verification_seen:
        return "blocked_by_cloudflare", "cloudflare_verification_page", True
    if access_timed_out:
        return "blocked_by_cloudflare", "timeout", True
    if latest_status and latest_status >= 400:
        return "target_error", f"http_{latest_status}", False
    return "target_error", "unexpected_response", False


# Execute one browser attempt and return all timing, response, and challenge evidence.
def run_once(
    target: Target,
    batch_id: str,
    replicate: int,
    attempt: int,
    shared_context,
    identity_id: str | None = None,
    persistent_hit_index: int | None = None,
) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp_utc = now_iso()
    setup_started = time.perf_counter()
    context = shared_context
    page = None
    document_responses: list[dict] = []
    request_failures: list[dict] = []
    challenge_resources: list[str] = []
    unexpected_pages: list[str] = []
    navigation_error = None
    access_timed_out = False
    identity_fields = identity_record("persistent", identity_id, persistent_hit_index)

    try:
        browser = shared_context.browser
        browser_version = browser.version if browser is not None else "unknown"
        page = context.new_page()
        setup_ms = elapsed_ms(setup_started)
    except Exception as exc:
        setup_ms = elapsed_ms(setup_started)
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
        return {
            "protocol_version": PROTOCOL_VERSION,
            "setup": SETUP_NAME,
            "batch_id": batch_id,
            "target_name": target.name,
            "target_url": target.url,
            "replicate": replicate,
            "attempt": attempt,
            "timestamp_utc": timestamp_utc,
            "playwright_version": PLAYWRIGHT_VERSION,
            "browser_distribution": "playwright_bundled_chromium",
            **identity_fields,
            "viewport_mode": "playwright_default",
            "proxy_enabled": False,
            "classification": "infrastructure_error",
            "failure_type": "browser_setup_error",
            "valid_scored_evaluation": False,
            "setup_ms": setup_ms,
            "error": f"{type(exc).__name__}: {exc}",
        }

    # Capture document responses and Cloudflare challenge resources during the attempt.
    def on_response(response):
        url = response.url
        if response.request.resource_type == "document":
            document_responses.append(response_snapshot(response))
        if any(pattern in url.lower() for pattern in CLOUDFLARE_RESOURCE_PATTERNS):
            if url not in challenge_resources:
                challenge_resources.append(url)

    def on_request_failed(request):
        request_failures.append({
            "url": request.url,
            "method": request.method,
            "resource_type": request.resource_type,
            "failure": request.failure,
        })

    page.on("response", on_response)
    page.on("requestfailed", on_request_failed)
    context.on("page", lambda new_page: unexpected_pages.append(new_page.url) if new_page is not page else None)

    # Start the measured access window immediately before target navigation.
    access_started = time.perf_counter()
    main_response = None
    access_error = None
    try:
        main_response = page.goto(
            target.url,
            wait_until="domcontentloaded",
            timeout=NAVIGATION_TIMEOUT_MS,
        )
    except PlaywrightTimeoutError as exc:
        navigation_error = f"TimeoutError: {exc}"
    except Exception as exc:
        navigation_error = f"{type(exc).__name__}: {exc}"

    remaining_ms = max(0, ACCESS_DEADLINE_MS - int((time.perf_counter() - access_started) * 1000))
    try:
        loaded = target_loaded(page, target) if remaining_ms == 0 else wait_for_target(page, target, remaining_ms)
    except Exception as exc:
        loaded = False
        access_error = f"{type(exc).__name__}: {exc}"
    access_ms = elapsed_ms(access_started)
    access_timed_out = not loaded and access_ms >= ACCESS_DEADLINE_MS - 50

    # Collect reproducibility evidence only after the access timer has stopped.
    evidence_started = time.perf_counter()
    title = ""
    final_url = ""
    final_text = ""
    browser_identity = {}
    evidence_error = None

    try:
        title = page.title()
        final_url = page.url
        final_text = safe_body_text(page)
        # Record browser defaults for reproducibility without changing them.
        browser_identity = page.evaluate("""() => ({
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            languages: navigator.languages,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            viewport: {width: innerWidth, height: innerHeight},
            screen: {width: screen.width, height: screen.height, colorDepth: screen.colorDepth}
        })""")
    except Exception as exc:
        evidence_error = f"{type(exc).__name__}: {exc}"

    if access_error:
        classification = "infrastructure_error"
        failure_type = "browser_runtime_error"
        valid_scored_evaluation = False
    else:
        classification, failure_type, valid_scored_evaluation = classify_outcome(
            loaded=loaded,
            access_timed_out=access_timed_out,
            navigation_error=navigation_error,
            final_text=f"{title}\n{final_url}\n{final_text}",
            document_responses=document_responses,
            challenge_resources=challenge_resources,
        )

    verification_observed = bool(
        cloudflare_text_markers(f"{title}\n{final_url}\n{final_text}")
        or challenge_resources
    )

    # Save the screenshot after classification so it does not affect access latency.
    screenshot_path = SCREENSHOT_DIR / (
        f"{slug(batch_id)}_persistent_{target.name}_r{replicate:02d}_a{attempt:02d}_{classification}.png"
    )
    screenshot_error = None
    try:
        page.screenshot(path=str(screenshot_path), full_page=False)
    except Exception as exc:
        screenshot_error = f"{type(exc).__name__}: {exc}"
        screenshot_path = None

    evidence_ms = elapsed_ms(evidence_started)
    main_response_data = response_snapshot(main_response) if main_response else None
    latest_document = document_responses[-1] if document_responses else None

    # Close browser resources outside the measured access window.
    cleanup_started = time.perf_counter()
    cleanup_error = None
    try:
        page.close()
    except Exception as exc:
        cleanup_error = f"page_close: {type(exc).__name__}: {exc}"
    cleanup_ms = elapsed_ms(cleanup_started)

    return {
        "protocol_version": PROTOCOL_VERSION,
        "setup": SETUP_NAME,
        "batch_id": batch_id,
        "target_name": target.name,
        "target_url": target.url,
        "replicate": replicate,
        "attempt": attempt,
        "timestamp_utc": timestamp_utc,
        "headed": True,
        "playwright_version": PLAYWRIGHT_VERSION,
        "browser_distribution": "playwright_bundled_chromium",
        **identity_fields,
        "viewport_mode": "playwright_default",
        "proxy_enabled": False,
        "fingerprint_injection": False,
        "browser_version": browser_version,
        "browser_identity": browser_identity,
        "navigation_timeout_ms": NAVIGATION_TIMEOUT_MS,
        "access_deadline_ms": ACCESS_DEADLINE_MS,
        "setup_ms": setup_ms,
        "access_ms": access_ms,
        "attempt_ms": round(setup_ms + access_ms, 2),
        "evidence_ms": evidence_ms,
        "cleanup_ms": cleanup_ms,
        "classification": classification,
        "failure_type": failure_type,
        "valid_scored_evaluation": valid_scored_evaluation,
        "target_loaded": loaded,
        "verification_observed": verification_observed,
        "main_response": main_response_data,
        "latest_document_response": latest_document,
        "final_url": final_url,
        "title": title,
        "cloudflare_text_markers": cloudflare_text_markers(f"{title}\n{final_text}"),
        "challenge_resources": challenge_resources[:50],
        "document_responses": document_responses[:50],
        "request_failures": request_failures[:50],
        "unexpected_pages": unexpected_pages[:20],
        "text_sample": final_text[:700].replace("\n", " "),
        "screenshot_path": str(screenshot_path) if screenshot_path else None,
        "navigation_error": navigation_error,
        "access_error": access_error,
        "evidence_error": evidence_error,
        "screenshot_error": screenshot_error,
        "cleanup_error": cleanup_error,
    }


# Keep every raw attempt, including non-scored retries, in the JSONL output.
def append_result(row: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with RESULTS_FILE.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, ensure_ascii=False) + "\n")


# Enforce the minimum delay between navigations to the same target.
def wait_for_spacing(last_navigation: dict[str, float], target_name: str, minimum_seconds: int) -> float:
    previous = last_navigation.get(target_name)
    if previous is None or minimum_seconds <= 0:
        return 0.0

    remaining = minimum_seconds - (time.monotonic() - previous)
    if remaining <= 0:
        return 0.0

    time.sleep(remaining)
    return round(remaining * 1000, 2)


def domain_key(target: Target) -> str:
    return target.expected_host.lower().removeprefix("www.")


# Shuffle each round while preventing consecutive requests to the same domain.
def ordered_round(targets, rng: random.Random, previous_domain: str | None):
    targets = list(targets)
    if len(targets) < 2:
        return targets

    for _ in range(200):
        ordered = list(targets)
        rng.shuffle(ordered)
        domains = [domain_key(target) for target in ordered]
        if previous_domain and domains[0] == previous_domain:
            continue
        if any(left == right for left, right in zip(domains, domains[1:])):
            continue
        return ordered

    raise RuntimeError("Could not build a round without consecutive targets from the same domain")


# Run rounds sequentially and retry only attempts that are excluded from scoring.
def main() -> None:
    parser = argparse.ArgumentParser(description="Bare Playwright runner for the Cloudflare benchmark.")
    parser.add_argument("--target", choices=[*TARGET_BY_NAME.keys(), "all"], default="all")
    parser.add_argument("--runs", type=int, default=1, help="Rounds per selected target.")
    parser.add_argument("--attempt", type=int, default=1, help="Starting attempt number for replacement runs.")
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--min-target-interval", type=int, default=DEFAULT_MIN_TARGET_INTERVAL_SECONDS)
    parser.add_argument("--batch-id", help="Stable batch identifier shared with the benchmark schedule.")
    args = parser.parse_args()

    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.attempt < 1:
        parser.error("--attempt must be at least 1")
    if args.max_attempts < 1:
        parser.error("--max-attempts must be at least 1")
    if args.min_target_interval < 0:
        parser.error("--min-target-interval cannot be negative")

    batch_id = args.batch_id or datetime.now(timezone.utc).strftime("bare-%Y%m%dT%H%M%SZ")
    selected_targets = TARGETS if args.target == "all" else (TARGET_BY_NAME[args.target],)
    last_navigation: dict[str, float] = {}
    previous_domain = None

    with sync_playwright() as playwright:
        rng = random.Random(args.seed)
        previous_domain = None
        persistent_hit_index = 0
        profile_path = identity_dir(batch_id)
        lock_path = acquire_profile_lock(profile_path)
        identity_id = identity_hash(str(profile_path))
        # Official Playwright persistent profile: one user_data_dir, bundled Chromium.
        shared_context = playwright.chromium.launch_persistent_context(
            str(profile_path),
            headless=False,
        )
        shared_context.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
        shared_context.set_default_timeout(DEFAULT_ACTION_TIMEOUT_MS)
        try:
            for replicate in range(1, args.runs + 1):
                for target in ordered_round(selected_targets, rng, previous_domain):
                    for retry_index in range(args.max_attempts):
                        pre_run_wait_ms = wait_for_spacing(
                            last_navigation,
                            target.name,
                            args.min_target_interval,
                        )
                        last_navigation[target.name] = time.monotonic()
                        attempt = args.attempt + retry_index
                        persistent_hit_index += 1
                        row = run_once(
                            target,
                            batch_id,
                            replicate,
                            attempt,
                            shared_context=shared_context,
                            identity_id=identity_id,
                            persistent_hit_index=persistent_hit_index,
                        )
                        row["seed"] = args.seed
                        row["pre_run_wait_ms"] = pre_run_wait_ms
                        row["scheduled_domain"] = domain_key(target)
                        append_result(row)
                        print(json.dumps({
                            "identity_mode": row.get("identity_mode"),
                            "target": row["target_name"],
                            "replicate": row["replicate"],
                            "attempt": row["attempt"],
                            "classification": row["classification"],
                            "failure_type": row.get("failure_type"),
                            "access_ms": row.get("access_ms"),
                            "pre_run_wait_ms": row.get("pre_run_wait_ms"),
                            "valid_scored_evaluation": row["valid_scored_evaluation"],
                        }, ensure_ascii=False), flush=True)

                        if row["valid_scored_evaluation"]:
                            break

                    previous_domain = domain_key(target)
        finally:
            try:
                shared_context.close()
            except Exception:
                pass
            release_profile_lock(lock_path)


if __name__ == "__main__":
    main()
