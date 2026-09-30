import argparse
import json
import os
import random
import re
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.metadata import version as package_version
from pathlib import Path
from urllib.parse import unquote, urlsplit

from patchright.sync_api import sync_playwright

# Reuse the frozen targets and scoring rules so only the browser stack changes.
from bare_playwright import (
    ACCESS_DEADLINE_MS as BARE_ACCESS_DEADLINE_MS,
    DEFAULT_ACTION_TIMEOUT_MS,
    NAVIGATION_TIMEOUT_MS as BARE_NAVIGATION_TIMEOUT_MS,
    TARGETS,
    TARGET_BY_NAME,
    acquire_profile_lock,
    classify_outcome,
    cloudflare_text_markers,
    domain_key,
    elapsed_ms,
    identity_hash,
    identity_record,
    now_iso,
    ordered_round,
    release_profile_lock,
    response_snapshot,
    safe_body_text,
    slug,
    target_loaded,
    wait_for_spacing,
    wait_for_target,
    page_evaluate,
)
PROTOCOL_VERSION = "benchmark-v1.6-patchright-persistent"
SETUP_NAME = "patchright_proxy"
PATCHRIGHT_VERSION = package_version("patchright")
DEFAULT_SEED = 20260916
DEFAULT_MIN_TARGET_INTERVAL_SECONDS = 60
NAVIGATION_TIMEOUT_MS = 120_000
ACCESS_DEADLINE_MS = 120_000
DEFAULT_MAX_ATTEMPTS = 3

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
RESULTS_DIR = ROOT / "results"
SCREENSHOT_DIR = RESULTS_DIR / "screenshots" / SETUP_NAME
RESULTS_FILE = RESULTS_DIR / f"{SETUP_NAME}.jsonl"
PROFILE_ROOT = RESULTS_DIR / "profiles" / SETUP_NAME


# Render proxy credentials and a fresh sticky residential session for each attempt.
@dataclass(frozen=True)
class ResidentialProxyConfig:
    server_template: str
    username_template: str
    password_template: str
    country: str
    locale: str
    timezone_id: str

    def _render(self, template: str, session_id: str) -> str:
        return (
            template.replace("{session}", session_id)
            .replace("{country}", self.country)
            .replace("{country_lower}", self.country.lower())
        )
    def session(self, fixed_session_id: str | None = None) -> tuple[dict, dict]:
        rotates_session = any(
            "{session}" in template
            for template in (self.server_template, self.username_template, self.password_template)
        )
        session_id = fixed_session_id or (uuid.uuid4().hex[:16] if rotates_session else "fixed-proxy")
        rendered = self._render(self.server_template, session_id)
        parsed = urlsplit(rendered)
        username = unquote(parsed.username or "") or self._render(self.username_template, session_id)
        password = unquote(parsed.password or "") or self._render(self.password_template, session_id)
        safe_server = f"{parsed.scheme}://{parsed.hostname or ''}"
        if parsed.port:
            safe_server += f":{parsed.port}"

        # Playwright wants host on server and auth in separate fields.
        proxy = {"server": safe_server}
        if username:
            proxy["username"] = username
        if password:
            proxy["password"] = password

        metadata = {
            "server": safe_server,
            "country": self.country,
            "locale": self.locale,
            "timezone": self.timezone_id,
            "session_id": session_id,
            "rotating_session": rotates_session,
        }
        return proxy, metadata


# Load local proxy settings without overriding values already set in the shell.
def load_env_file() -> None:
    if not ENV_FILE.exists():
        return

    for raw_line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


# Validate the proxy endpoint and the browser geography used with it.
def load_proxy_config() -> ResidentialProxyConfig:
    proxy_url = os.getenv("PROXY_URL", "").strip()
    values = {
        "server_template": proxy_url or os.getenv("DIY_PROXY_SERVER_TEMPLATE", "").strip(),
        "username_template": os.getenv("DIY_PROXY_USERNAME_TEMPLATE", "").strip(),
        "password_template": os.getenv("DIY_PROXY_PASSWORD_TEMPLATE", "").strip(),
        "country": os.getenv("DIY_PROXY_COUNTRY", "").strip(),
        "locale": os.getenv("DIY_PROXY_LOCALE", "").strip(),
        "timezone_id": os.getenv("DIY_PROXY_TIMEZONE", "").strip(),
    }
    required = ("server_template", "country", "locale", "timezone_id")
    missing = [name for name in required if not values[name]]
    if missing:
        raise RuntimeError(f"Missing DIY proxy configuration: {', '.join(missing)}")

    if not re.match(r"^(https?|socks5)://", values["server_template"], re.I):
        raise RuntimeError("DIY_PROXY_SERVER_TEMPLATE must start with http://, https://, or socks5://")

    return ResidentialProxyConfig(**values)


# Record browser signals for reproducibility without overriding the fingerprint.
def browser_identity(page) -> dict:
    return page_evaluate(page, """() => {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        const debug = gl && gl.getExtension('WEBGL_debug_renderer_info');
        return {
            userAgent: navigator.userAgent,
            platform: navigator.platform,
            languages: navigator.languages,
            webdriver: navigator.webdriver,
            vendor: navigator.vendor,
            hardwareConcurrency: navigator.hardwareConcurrency,
            plugins: navigator.plugins.length,
            mimeTypes: navigator.mimeTypes.length,
            userAgentData: navigator.userAgentData ? {
                brands: navigator.userAgentData.brands,
                mobile: navigator.userAgentData.mobile,
                platform: navigator.userAgentData.platform
            } : null,
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            viewport: {width: innerWidth, height: innerHeight},
            screen: {width: screen.width, height: screen.height, colorDepth: screen.colorDepth},
            webglVendor: debug ? gl.getParameter(debug.UNMASKED_VENDOR_WEBGL) : null,
            webglRenderer: debug ? gl.getParameter(debug.UNMASKED_RENDERER_WEBGL) : null
        };
    }""")


# Normalize proxy failures so infrastructure retries stay separate from scored blocks.
def proxy_failure_type(error: str | None) -> str:
    value = (error or "").lower()
    if "proxy" in value and "auth" in value:
        return "proxy_auth_error"
    if "err_tunnel_connection_failed" in value or "tunnel" in value:
        return "proxy_tunnel_error"
    if "err_proxy_connection_failed" in value or "proxy connection" in value:
        return "proxy_connection_error"
    if "err_name_not_resolved" in value:
        return "proxy_dns_error"
    return "navigation_error"


# One hit on the shared persistent Chrome profile and sticky proxy session.
def run_once(
    config,
    target,
    batch_id: str,
    replicate: int,
    attempt: int,
    shared_context,
    identity_id: str,
    proxy,
    proxy_metadata,
    persistent_hit_index: int,
) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp_utc = now_iso()
    setup_started = time.perf_counter()
    browser = None
    context = shared_context
    page = None
    identity_fields = identity_record("persistent", identity_id, persistent_hit_index)
    document_responses = []
    request_failures = []
    challenge_resources = []
    unexpected_pages = []
    navigation_error = None
    try:
        page = context.new_page()
        browser = context.browser
        browser_version = browser.version if browser is not None else "unknown"
        setup_ms = elapsed_ms(setup_started)
    except Exception as exc:
        setup_ms = elapsed_ms(setup_started)
        if page is not None:
            try:
                page.close()
            except Exception:
                pass
        error = f"{type(exc).__name__}: {exc}"
        return {
            "protocol_version": PROTOCOL_VERSION,
            "setup": SETUP_NAME,
            "batch_id": batch_id,
            "target_name": target.name,
            "target_url": target.url,
            "replicate": replicate,
            "attempt": attempt,
            "timestamp_utc": timestamp_utc,
            "patchright_version": PATCHRIGHT_VERSION,
            "browser_channel": "chrome",
            **identity_fields,
            "no_viewport": True,
            "classification": "infrastructure_error",
            "failure_type": proxy_failure_type(error) if "proxy" in error.lower() else "browser_setup_error",
            "valid_scored_evaluation": False,
            "setup_ms": setup_ms,
            "proxy": proxy_metadata,
            "error": error,
        }

    # Capture the same response and Cloudflare evidence as the Bare runner.
    def on_response(response):
        url = response.url
        if response.request.resource_type == "document":
            document_responses.append(response_snapshot(response))
        if any(pattern in url.lower() for pattern in (
            "/cdn-cgi/challenge-platform/",
            "challenges.cloudflare.com",
            "turnstile",
        )):
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
    except Exception as exc:
        navigation_error = f"{type(exc).__name__}: {exc}"

    remaining_ms = max(
        0,
        ACCESS_DEADLINE_MS - int((time.perf_counter() - access_started) * 1000),
    )
    try:
        loaded = target_loaded(page, target) if remaining_ms == 0 else wait_for_target(page, target, remaining_ms)
    except Exception as exc:
        loaded = False
        access_error = f"{type(exc).__name__}: {exc}"
    access_ms = elapsed_ms(access_started)
    access_timed_out = not loaded and access_ms >= ACCESS_DEADLINE_MS - 50

    # Collect browser and page evidence only after the access timer has stopped.
    evidence_started = time.perf_counter()
    title = ""
    final_url = ""
    final_text = ""
    identity = {}
    evidence_error = None

    try:
        title = page.title()
        final_url = page.url
        final_text = safe_body_text(page)
        identity = browser_identity(page)
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

        if classification == "infrastructure_error":
            failure_type = proxy_failure_type(navigation_error)

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
        "patchright_version": PATCHRIGHT_VERSION,
        "browser_channel": "chrome",
        **identity_fields,
        "no_viewport": True,
        "custom_user_agent": False,
        "custom_browser_headers": False,
        "browser_version": browser_version,
        "browser_identity": identity,
        "proxy": proxy_metadata,
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


# Run rounds sequentially and retry only attempts that are excluded from scoring.
def main() -> None:
    parser = argparse.ArgumentParser(
        description="Patchright + residential proxy benchmark using one persistent Chrome profile."
    )
    parser.add_argument("--target", choices=[*TARGET_BY_NAME.keys(), "all"], default="all")
    parser.add_argument("--runs", type=int, default=1, help="Rounds per selected target.")
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--min-target-interval", type=int, default=DEFAULT_MIN_TARGET_INTERVAL_SECONDS)
    parser.add_argument("--batch-id")
    parser.add_argument("--check-config", action="store_true")
    args = parser.parse_args()
    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.max_attempts < 1:
        parser.error("--max-attempts must be at least 1")
    if args.min_target_interval < 0:
        parser.error("--min-target-interval cannot be negative")

    load_env_file()
    config = load_proxy_config()
    if args.check_config:
        _, metadata = config.session()
        if metadata["rotating_session"]:
            metadata["session_id"] = "generated-per-run"
        print(json.dumps(metadata, ensure_ascii=False, indent=2))
        return

    batch_id = args.batch_id or datetime.now(timezone.utc).strftime("patchright-%Y%m%dT%H%M%SZ")
    selected_targets = TARGETS if args.target == "all" else (TARGET_BY_NAME[args.target],)
    last_navigation: dict[str, float] = {}
    previous_domain = None

    with sync_playwright() as playwright:
        rng = random.Random(args.seed)
        previous_domain = None
        persistent_hit_index = 0
        profile_path = PROFILE_ROOT / slug(batch_id)
        lock_path = acquire_profile_lock(profile_path)
        identity_id = identity_hash(str(profile_path))
        sticky_proxy, sticky_proxy_metadata = config.session(
            fixed_session_id=f"persist-{slug(batch_id)[:16]}"
        )
        shared_context = playwright.chromium.launch_persistent_context(
            user_data_dir=str(profile_path),
            channel="chrome",
            headless=False,
            no_viewport=True,
            proxy=sticky_proxy,
        )
        shared_context.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
        shared_context.set_default_timeout(DEFAULT_ACTION_TIMEOUT_MS)
        try:
            for replicate in range(1, args.runs + 1):
                for target in ordered_round(selected_targets, rng, previous_domain):
                    for attempt in range(1, args.max_attempts + 1):
                        pre_run_wait_ms = wait_for_spacing(
                            last_navigation,
                            target.name,
                            args.min_target_interval,
                        )
                        last_navigation[target.name] = time.monotonic()
                        persistent_hit_index += 1
                        row = run_once(
                            config,
                            target,
                            batch_id,
                            replicate,
                            attempt,
                            shared_context=shared_context,
                            identity_id=identity_id,
                            proxy=sticky_proxy,
                            proxy_metadata=sticky_proxy_metadata,
                            persistent_hit_index=persistent_hit_index,
                        )
                        row["seed"] = args.seed
                        row["pre_run_wait_ms"] = pre_run_wait_ms
                        row["scheduled_domain"] = domain_key(target)
                        append_result(row)
                        print(json.dumps({
                            "identity_mode": row.get("identity_mode"),
                            "persistent_hit_index": row.get("persistent_hit_index"),
                            "target": row["target_name"],
                            "replicate": row["replicate"],
                            "attempt": row["attempt"],
                            "classification": row["classification"],
                            "failure_type": row.get("failure_type"),
                            "access_ms": row.get("access_ms"),
                            "proxy_session": row.get("proxy", {}).get("session_id"),
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
