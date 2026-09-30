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

import requests

from patchright.sync_api import TimeoutError as PatchrightTimeoutError
from patchright.sync_api import sync_playwright

from bare_playwright import (
    ACCESS_DEADLINE_MS,
    CLOUDFLARE_RESOURCE_PATTERNS,
    DEFAULT_ACTION_TIMEOUT_MS,
    DEFAULT_MAX_ATTEMPTS,
    DEFAULT_MIN_TARGET_INTERVAL_SECONDS,
    DEFAULT_SEED,
    NAVIGATION_TIMEOUT_MS,
    TARGETS,
    TARGET_BY_NAME,
    classify_outcome,
    cloudflare_text_markers,
    domain_key,
    elapsed_ms,
    now_iso,
    ordered_round,
    response_snapshot,
    safe_body_text,
    slug,
    target_loaded,
    identity_hash,
    identity_record,
)

PROTOCOL_VERSION = "benchmark-v1.7-persistent-only"
SETUP_NAME = "surfsky_managed"
PATCHRIGHT_VERSION = package_version("patchright")

ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"
RESULTS_DIR = ROOT / "results"
SCREENSHOT_DIR = RESULTS_DIR / "screenshots" / SETUP_NAME
RESULTS_FILE = RESULTS_DIR / f"{SETUP_NAME}.jsonl"
BATCH_FILE = RESULTS_DIR / f"{SETUP_NAME}_batches.jsonl"

SURFSKY_HTTP_TIMEOUT_SECONDS = 120
SURFSKY_PROXY_TIER = "premium"
SURFSKY_PROXY_TYPE = "residential"
SURFSKY_PROXY_COUNTRY = "us"
SURFSKY_PROXY_REGION = "texas"
SURFSKY_PROXY_SESSION_MINUTES = 180
SURFSKY_KEEP_IP = True
SURFSKY_UNIQUE_IP = True
SURFSKY_KEEP_ASN = False
SURFSKY_INACTIVE_KILL_TIMEOUT = 180
SURFSKY_FINGERPRINT_OS = "win"
SURFSKY_FINGERPRINT_FALLBACK_OS = "android"
SURFSKY_CACHE_ENABLED = True
SURFSKY_PROXY_BLACKLIST = (
    "*.doubleclick.net",
    "*.facebook.net",
    "analytics.google.com",
)
CAPTCHA_EVENT_NAMES = (
    "Captcha.detectionStarted",
    "Captcha.detectionCompleted",
    "Captcha.solveStarted",
    "Captcha.solveCompleted",
    "Captcha.solveFailed",
)

CAPTCHA_VERIFICATION_EVENTS = {
    "Captcha.solveStarted",
    "Captcha.solveCompleted",
    "Captcha.solveFailed",
}

TRANSIENT_START_CODES = {
    "cluster_is_full",
    "profile_start_failed",
    "service_unavailable",
    "app_outdated",
    "rate_limits_reached",
}


@dataclass(frozen=True)
class SurfskyConfig:
    base_url: str
    token: str


class SurfskyAPIError(RuntimeError):
    def __init__(self, status, code, detail, tracing_uuid=None):
        super().__init__(detail)
        self.status = status
        self.code = code
        self.detail = detail
        self.tracing_uuid = tracing_uuid

def load_env_file() -> None:
    if not ENV_FILE.exists():
        return

    for raw_line in ENV_FILE.read_text(encoding="utf-8-sig").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def load_surfsky_config() -> SurfskyConfig:
    base_url = os.environ.get("SURFSKY_API_BASE_URL", "").strip().rstrip("/")
    token = os.environ.get("SURFSKY_API_TOKEN", "").strip()
    if not base_url:
        raise RuntimeError("SURFSKY_API_BASE_URL is required in the environment or .env")
    if not token:
        raise RuntimeError("SURFSKY_API_TOKEN is required in the environment or .env")
    if not base_url.startswith(("https://", "http://")):
        raise RuntimeError("SURFSKY_API_BASE_URL must start with http:// or https://")
    return SurfskyConfig(base_url=base_url, token=token)


def redact_runtime_secrets(text: str, config: SurfskyConfig, ws_url: str | None = None) -> str:
    value = str(text or "")
    if config.token:
        value = value.replace(config.token, "<redacted-token>")
    if ws_url:
        value = value.replace(ws_url, "<redacted-ws-url>")
    value = re.sub(r"wss://\S+", "<redacted-ws-url>", value)
    return value

def safe_api_headers(headers) -> dict:
    wanted = (
        "X-Ratelimit-Limit",
        "X-Ratelimit-Limit-Hour",
        "X-Ratelimit-Remaining",
        "X-Ratelimit-Remaining-Hour",
        "X-Cloud-Tracing-UUID",
    )
    return {name.lower(): headers.get(name) for name in wanted if headers.get(name) is not None}


def api_json(config: SurfskyConfig, method: str, path: str, payload=None, timeout=None):
    url = f"{config.base_url}{path}"
    try:
        response = requests.request(
            method=method,
            url=url,
            json=payload,
            headers={
                "X-Cloud-Api-Token": config.token,
                "Accept": "application/json",
            },
            timeout=timeout or SURFSKY_HTTP_TIMEOUT_SECONDS,
        )
        raw = response.text
        try:
            body = response.json() if raw.strip() else {}
        except ValueError:
            body = {}
        if not response.ok:
            code = body.get("code") or body.get("error") or f"http_{response.status_code}"
            detail = body.get("msg") or body.get("detail") or raw or response.reason
            tracing = response.headers.get("X-Cloud-Tracing-UUID")
            raise SurfskyAPIError(
                response.status_code,
                str(code),
                redact_runtime_secrets(detail, config),
                tracing,
            )
        return body, safe_api_headers(response.headers)
    except SurfskyAPIError:
        raise
    except requests.RequestException as exc:
        raise RuntimeError(
            f"Surfsky request transport error: {redact_runtime_secrets(exc, config)}"
        ) from exc

def surfsky_start_payload(keep_ip: bool | None = None, cache_key: str | None = None) -> dict:
    keep = SURFSKY_KEEP_IP if keep_ip is None else keep_ip
    browser_settings = {"inactive_kill_timeout": SURFSKY_INACTIVE_KILL_TIMEOUT}
    if SURFSKY_CACHE_ENABLED and cache_key:
        browser_settings["cache_enabled"] = True
        browser_settings["cache_key"] = re.sub(r"[^A-Za-z0-9._-]", "", cache_key)[:255]
    return {
        "proxy": {
            "tier": SURFSKY_PROXY_TIER,
            "type": SURFSKY_PROXY_TYPE,
            "country": SURFSKY_PROXY_COUNTRY,
            "region": SURFSKY_PROXY_REGION,
            "session_minutes": SURFSKY_PROXY_SESSION_MINUTES,
            "keep_ip": keep,
            "unique_ip": SURFSKY_UNIQUE_IP,
            "keep_asn": SURFSKY_KEEP_ASN,
        },
        "anti_captcha": {
            "enabled": True,
            "disable_external_providers": True,
            "auto_captcha_types": ["turnstile"],
        },
        "browser_settings": browser_settings,
        "proxy_blacklist": list(SURFSKY_PROXY_BLACKLIST),
    }


def surfsky_method_metadata(identity_mode: str | None = None, keep_ip: bool | None = None) -> dict:
    if keep_ip is None:
        if identity_mode == "fresh":
            keep_ip = False
        elif identity_mode == "persistent":
            keep_ip = True
        else:
            keep_ip = SURFSKY_KEEP_IP
    return {
        "identity_mode": identity_mode,
        "proxy": {
            "tier": SURFSKY_PROXY_TIER,
            "type": SURFSKY_PROXY_TYPE,
            "country": SURFSKY_PROXY_COUNTRY,
            "region": SURFSKY_PROXY_REGION,
            "session_minutes": SURFSKY_PROXY_SESSION_MINUTES,
            "keep_ip": keep_ip,
        },
        "anti_captcha": {
            "enabled": True,
            "disable_external_providers": True,
            "auto_captcha_types": ["turnstile"],
        },
        "fingerprint_os": SURFSKY_FINGERPRINT_OS,
        "fingerprint_fallback_os": SURFSKY_FINGERPRINT_FALLBACK_OS,
        "fingerprint_overrides": False,
        "human_input_enabled": False,
        "unique_ip": SURFSKY_UNIQUE_IP,
        "cache_enabled": SURFSKY_CACHE_ENABLED,
        "proxy_blacklist": list(SURFSKY_PROXY_BLACKLIST),
        "saved_persistent_profile": identity_mode == "persistent",
        "one_time_profile": False,
    }

def start_surfsky_session(config: SurfskyConfig, keep_ip: bool | None = None):
    payload = surfsky_start_payload(keep_ip=keep_ip)
    started = time.perf_counter()
    body, headers = api_json(config, "POST", "/profiles/one_time", payload=payload)
    start_ms = elapsed_ms(started)

    internal_uuid = body.get("internal_uuid")
    ws_url = body.get("ws_url")
    if not internal_uuid or not ws_url:
        raise RuntimeError("Surfsky start response did not contain internal_uuid and ws_url")

    return {
        "internal_uuid": internal_uuid,
        "ws_url": ws_url,
        "session_hash": hashlib.sha256(internal_uuid.encode("utf-8")).hexdigest()[:12],
        "start_ms": start_ms,
        "rate_limit_headers": headers,
    }


def start_surfsky_session_with_retry(config: SurfskyConfig, max_attempts: int = 3, keep_ip: bool | None = None):
    for attempt in range(1, max_attempts + 1):
        try:
            return start_surfsky_session(config, keep_ip=keep_ip), attempt
        except SurfskyAPIError as exc:
            retryable = exc.code in TRANSIENT_START_CODES or exc.status in (502, 503)
            if not retryable or attempt >= max_attempts:
                raise
            time.sleep(min(8.0, 1.5 * (2 ** (attempt - 1))))
    raise RuntimeError("Surfsky start retry loop exited unexpectedly")


def _connection_fields(body: dict) -> tuple[str, str]:
    internal_uuid = body.get("internal_uuid") or (body.get("data") or {}).get("internal_uuid")
    ws_url = body.get("ws_url") or (body.get("data") or {}).get("ws_url")
    if not internal_uuid or not ws_url:
        raise RuntimeError("Surfsky start response did not contain internal_uuid and ws_url")
    return internal_uuid, ws_url


def create_persistent_profile(config: SurfskyConfig, title: str, fingerprint_os: str = SURFSKY_FINGERPRINT_OS) -> str:
    payload = {
        "title": title,
        "fingerprint": {"os": fingerprint_os},
        "storage_options": {"cookies": True, "localstorage": True},
        "proxy": {
            "tier": SURFSKY_PROXY_TIER,
            "type": SURFSKY_PROXY_TYPE,
            "country": SURFSKY_PROXY_COUNTRY,
            "region": SURFSKY_PROXY_REGION,
            "session_minutes": SURFSKY_PROXY_SESSION_MINUTES,
            "keep_ip": True,
            "unique_ip": SURFSKY_UNIQUE_IP,
        },
    }
    body, _headers = api_json(config, "POST", "/profiles", payload=payload)
    data = body.get("data") if isinstance(body.get("data"), dict) else body
    profile_uuid = (data or {}).get("uuid") or body.get("uuid")
    if not profile_uuid:
        raise RuntimeError("Surfsky create-profile response did not contain data.uuid")
    return profile_uuid


def start_persistent_profile(config: SurfskyConfig, profile_uuid: str, cache_key: str | None = None) -> dict:
    payload = surfsky_start_payload(keep_ip=True, cache_key=cache_key)
    started = time.perf_counter()
    body, headers = api_json(config, "POST", f"/profiles/{profile_uuid}/start", payload=payload)
    internal_uuid, ws_url = _connection_fields(body)
    inspector = body.get("inspector") or (body.get("data") or {}).get("inspector")
    return {
        "profile_uuid": profile_uuid,
        "internal_uuid": internal_uuid,
        "ws_url": ws_url,
        "inspector": inspector,
        "session_hash": hashlib.sha256(internal_uuid.encode("utf-8")).hexdigest()[:12],
        "identity_id": identity_hash(profile_uuid),
        "start_ms": elapsed_ms(started),
        "rate_limit_headers": headers,
        "saved_persistent_profile": True,
    }


def close_surfsky_browser(browser) -> str:
    try:
        browser.new_browser_cdp_session().send("Browser.close")
        return "browser_close_cdp"
    except Exception:
        try:
            browser.close()
            return "browser_close_client"
        except Exception:
            return "browser_close_failed"


def stop_surfsky_session(config: SurfskyConfig, internal_uuid: str) -> dict:
    started = time.perf_counter()
    try:
        body, headers = api_json(config, "POST", f"/profiles/{internal_uuid}/stop")
        return {"status": "stopped", "stop_ms": elapsed_ms(started), "response": body, "headers": headers}
    except SurfskyAPIError as exc:
        if exc.status == 404:
            return {"status": "already_stopped", "stop_ms": elapsed_ms(started)}
        return {
            "status": "stop_error",
            "stop_ms": elapsed_ms(started),
            "http_status": exc.status,
            "code": exc.code,
            "detail": exc.detail,
            "tracing_uuid": exc.tracing_uuid,
        }

def preflight(config: SurfskyConfig) -> dict:
    checks = {}
    endpoints = {
        "active_sessions": "/profiles/active",
        "browser_limits": "/users/browser-limits",
        "plan": "/users/plan",
        "premium_quota": "/proxies/premium/quota",
        "us_regions": "/proxies/regions/us",
    }
    for name, path in endpoints.items():
        try:
            body, headers = api_json(config, "GET", path)
            checks[name] = {"ok": True, "data": body, "headers": headers}
        except SurfskyAPIError as exc:
            checks[name] = {
                "ok": False,
                "http_status": exc.status,
                "code": exc.code,
                "detail": exc.detail,
                "tracing_uuid": exc.tracing_uuid,
            }
        except Exception as exc:
            checks[name] = {"ok": False, "error": redact_runtime_secrets(exc, config)}

    regions_blob = json.dumps(checks.get("us_regions", {}), ensure_ascii=False).lower()
    checks["texas_available"] = "texas" in regions_blob
    return checks


def wait_for_target_patchright(page, target, timeout_ms: int) -> bool:
    expected = {
        "host": target.expected_host,
        "path": target.expected_path_fragment,
        "markers": list(target.loaded_markers),
    }
    try:
        page.wait_for_function(
            """expected => {
                const host = location.hostname.toLowerCase();
                const path = location.pathname.toLowerCase();
                const text = (document.body?.innerText || '').toLowerCase();
                const hostOk = host === expected.host || host.endsWith('.' + expected.host);
                const pathOk = path.includes(expected.path.toLowerCase());
                return hostOk && pathOk && expected.markers.some(m => text.includes(m.toLowerCase()));
            }""",
            arg=expected,
            timeout=timeout_ms,
        )
        return True
    except PatchrightTimeoutError:
        return False

def browser_identity(page) -> dict:
    return page.evaluate("""() => {
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
            deviceMemory: navigator.deviceMemory ?? null,
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


def compact_captcha_payload(payload) -> dict:
    if not isinstance(payload, dict):
        return {}
    allowed = ("type", "status", "error")
    return {key: payload.get(key) for key in allowed if payload.get(key) is not None}


def session_loss_error(error: str | None) -> bool:
    value = (error or "").lower()
    return any(marker in value for marker in (
        "target closed",
        "browser has been closed",
        "browser closed",
        "connection closed",
        "websocket",
        "profile not found",
        "session closed",
    ))

def infrastructure_row(
    target,
    batch_id: str,
    replicate: int,
    attempt: int,
    session_meta: dict,
    session_start_ms: float,
    cdp_connect_ms: float,
    setup_ms: float,
    failure_type: str,
    error: str,
    fatal_session_loss: bool,
    identity_mode: str = "fresh",
    identity_id: str | None = None,
    persistent_hit_index: int | None = None,
) -> dict:
    return {
        "protocol_version": PROTOCOL_VERSION,
        "setup": SETUP_NAME,
        "batch_id": batch_id,
        "target_name": target.name,
        "target_url": target.url,
        "replicate": replicate,
        "attempt": attempt,
        "timestamp_utc": now_iso(),
        "patchright_version": PATCHRIGHT_VERSION,
        "remote_browser": "surfsky_antidetect_chrome",
        "remote_headless": True,
        **identity_record(identity_mode, identity_id, persistent_hit_index),
        "one_time_profile": identity_mode != "persistent",
        "shared_browser_context": identity_mode == "persistent",
        "proxy_session_reused": identity_mode == "persistent",
        "saved_persistent_profile": identity_mode == "persistent",
        "surfsky_session_hash": session_meta["session_hash"],
        "surfsky_method": surfsky_method_metadata(identity_mode=identity_mode),
        "session_start_ms": session_start_ms,
        "cdp_connect_ms": cdp_connect_ms,
        "browser_setup_ms": round(session_start_ms + cdp_connect_ms, 2),
        "setup_ms": setup_ms,
        "classification": "infrastructure_error",
        "failure_type": failure_type,
        "valid_scored_evaluation": False,
        "fatal_session_loss": fatal_session_loss,
        "error": error,
    }

def run_once(
    context,
    browser_version: str,
    session_meta: dict,
    session_start_ms: float,
    cdp_connect_ms: float,
    target,
    batch_id: str,
    replicate: int,
    attempt: int,
    config: SurfskyConfig,
    identity_mode: str = "fresh",
    identity_id: str | None = None,
    persistent_hit_index: int | None = None,
) -> dict:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp_utc = now_iso()
    setup_started = time.perf_counter()
    page = None
    cdp = None
    captcha_events = []
    document_responses = []
    request_failures = []
    challenge_resources = []
    unexpected_pages = []
    access_started_ref = [None]

    try:
        page = context.new_page()
        cdp = context.new_cdp_session(page)
    except Exception as exc:
        error = redact_runtime_secrets(f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"])
        return infrastructure_row(
            target, batch_id, replicate, attempt, session_meta,
            session_start_ms, cdp_connect_ms, elapsed_ms(setup_started),
            "browser_runtime_error", error, session_loss_error(error),
            identity_mode=identity_mode, identity_id=identity_id,
            persistent_hit_index=persistent_hit_index,
        )

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

    def event_handler(event_name):
        def handler(payload):
            started = access_started_ref[0]
            relative_ms = None if started is None else round((time.perf_counter() - started) * 1000, 2)
            captcha_events.append({
                "event": event_name,
                "relative_to_navigation_ms": relative_ms,
                "payload": compact_captcha_payload(payload),
            })
        return handler

    page.on("response", on_response)
    page.on("requestfailed", on_request_failed)
    page.on("popup", lambda popup: unexpected_pages.append(popup.url))
    for event_name in CAPTCHA_EVENT_NAMES:
        cdp.on(event_name, event_handler(event_name))

    captcha_auto_solve_status = None
    captcha_auto_solve_error = None
    try:
        # Docs: start auto-detect before navigation. status started = loop on; keep CDP attached.
        auto_response = cdp.send("Captcha.autoSolve", {"type": "turnstile"})
        captcha_auto_solve_status = (auto_response or {}).get("status")
    except Exception as exc:
        captcha_auto_solve_error = redact_runtime_secrets(
            f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"]
        )

    setup_ms = elapsed_ms(setup_started)

    access_started = time.perf_counter()
    access_started_ref[0] = access_started
    main_response = None
    navigation_error = None
    access_error = None

    try:
        main_response = page.goto(
            target.url,
            wait_until="domcontentloaded",
            timeout=NAVIGATION_TIMEOUT_MS,
        )
    except PatchrightTimeoutError as exc:
        navigation_error = f"TimeoutError: {exc}"
    except Exception as exc:
        navigation_error = redact_runtime_secrets(
            f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"]
        )

    remaining_ms = max(
        0,
        ACCESS_DEADLINE_MS - int((time.perf_counter() - access_started) * 1000),
    )
    captcha_solve_status = None
    captcha_solve_error = None
    try:
        loaded = target_loaded(page, target) if remaining_ms == 0 else wait_for_target_patchright(
            page, target, remaining_ms
        )
    except Exception as exc:
        loaded = False
        access_error = redact_runtime_secrets(
            f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"]
        )

    # Docs Method 1: if Turnstile is still on the page, solve once, then wait again.
    if not loaded:
        try:
            widget = page.query_selector(".cf-turnstile, iframe[src*='turnstile'], iframe[src*='challenges.cloudflare.com']")
        except Exception:
            widget = None
        if widget is not None:
            try:
                solve_response = cdp.send("Captcha.solve", {"type": "turnstile", "timeout": 60_000})
                captcha_solve_status = (solve_response or {}).get("status")
            except Exception as exc:
                captcha_solve_error = redact_runtime_secrets(
                    f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"]
                )
            extra_ms = max(
                0,
                ACCESS_DEADLINE_MS - int((time.perf_counter() - access_started) * 1000),
            )
            if extra_ms > 0 and captcha_solve_error is None:
                try:
                    loaded = wait_for_target_patchright(page, target, extra_ms)
                except Exception as exc:
                    access_error = redact_runtime_secrets(
                        f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"]
                    )

    human_actions = []

    access_ms = elapsed_ms(access_started)
    access_timed_out = not loaded and access_ms >= ACCESS_DEADLINE_MS - 50

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
        evidence_error = redact_runtime_secrets(
            f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"]
        )

    solver_verification_seen = any(
        item["event"] in CAPTCHA_VERIFICATION_EVENTS for item in captcha_events
    )
    classifier_challenge_evidence = list(challenge_resources)
    if solver_verification_seen:
        classifier_challenge_evidence.append("surfsky:turnstile-solver-event")

    if access_error and session_loss_error(access_error):
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
            challenge_resources=classifier_challenge_evidence,
        )

    fatal_session_loss = session_loss_error(access_error) or session_loss_error(navigation_error)
    verification_observed = bool(
        cloudflare_text_markers(f"{title}\n{final_url}\n{final_text}")
        or challenge_resources
        or solver_verification_seen
    )

    screenshot_path = SCREENSHOT_DIR / (
        f"{slug(batch_id)}_{target.name}_r{replicate:02d}_a{attempt:02d}_{classification}.png"
    )
    screenshot_error = None
    try:
        page.screenshot(path=str(screenshot_path), full_page=False)
    except Exception as exc:
        screenshot_error = redact_runtime_secrets(
            f"{type(exc).__name__}: {exc}", config, session_meta["ws_url"]
        )
        screenshot_path = None

    evidence_ms = elapsed_ms(evidence_started)
    main_response_data = response_snapshot(main_response) if main_response else None
    latest_document = document_responses[-1] if document_responses else None

    cleanup_started = time.perf_counter()
    cleanup_errors = []
    try:
        cdp.detach()
    except Exception as exc:
        cleanup_errors.append(f"cdp_detach: {type(exc).__name__}: {exc}")
    try:
        page.close()
    except Exception as exc:
        cleanup_errors.append(f"page_close: {type(exc).__name__}: {exc}")
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
        "patchright_version": PATCHRIGHT_VERSION,
        "remote_browser": "surfsky_antidetect_chrome",
        "remote_headless": True,
        **identity_record(identity_mode, identity_id, persistent_hit_index),
        "one_time_profile": identity_mode != "persistent",
        "shared_browser_context": identity_mode == "persistent",
        "proxy_session_reused": identity_mode == "persistent",
        "saved_persistent_profile": identity_mode == "persistent",
        "custom_user_agent": False,
        "custom_browser_headers": False,
        "fingerprint_managed_by_surfsky": True,
        "surfsky_session_hash": session_meta["session_hash"],
        "surfsky_method": surfsky_method_metadata(identity_mode=identity_mode),
        "browser_version": browser_version,
        "browser_identity": identity,
        "navigation_timeout_ms": NAVIGATION_TIMEOUT_MS,
        "access_deadline_ms": ACCESS_DEADLINE_MS,
        "session_start_ms": session_start_ms,
        "cdp_connect_ms": cdp_connect_ms,
        "browser_setup_ms": round(session_start_ms + cdp_connect_ms, 2),
        "setup_ms": setup_ms,
        "access_ms": access_ms,
        "attempt_ms": round(setup_ms + access_ms, 2),
        "evidence_ms": evidence_ms,
        "cleanup_ms": cleanup_ms,
        "classification": classification,
        "failure_type": failure_type,
        "valid_scored_evaluation": valid_scored_evaluation,
        "fatal_session_loss": fatal_session_loss,
        "target_loaded": loaded,
        "verification_observed": verification_observed,
        "captcha_auto_solve_status": captcha_auto_solve_status,
        "captcha_auto_solve_error": captcha_auto_solve_error,
        "captcha_solve_status": captcha_solve_status,
        "captcha_solve_error": captcha_solve_error,
        "human_actions": human_actions,
        "captcha_events": captcha_events[:100],
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
        "cleanup_error": "; ".join(cleanup_errors) if cleanup_errors else None,
    }


def append_jsonl(path: Path, row: dict) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as output:
        output.write(json.dumps(row, ensure_ascii=False) + "\n")


def wait_for_spacing(last_navigation: dict[str, float], target_name: str, minimum_seconds: int) -> float:
    previous = last_navigation.get(target_name)
    if previous is None or minimum_seconds <= 0:
        return 0.0
    remaining = minimum_seconds - (time.monotonic() - previous)
    if remaining <= 0:
        return 0.0
    time.sleep(remaining)
    return round(remaining * 1000, 2)

def safe_api_error(exc: Exception, config: SurfskyConfig) -> dict:
    if isinstance(exc, SurfskyAPIError):
        return {
            "http_status": exc.status,
            "code": exc.code,
            "detail": exc.detail,
            "tracing_uuid": exc.tracing_uuid,
        }
    return {"error": redact_runtime_secrets(f"{type(exc).__name__}: {exc}", config)}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Surfsky managed-browser Cloudflare benchmark. One saved persistent profile for the batch."
    )
    parser.add_argument("--target", choices=[*TARGET_BY_NAME.keys(), "all"], default="all")
    parser.add_argument("--runs", type=int, default=1, help="Rounds per selected target.")
    parser.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    parser.add_argument("--seed", type=int, default=DEFAULT_SEED)
    parser.add_argument("--min-target-interval", type=int, default=DEFAULT_MIN_TARGET_INTERVAL_SECONDS)
    parser.add_argument("--batch-id")
    parser.add_argument(
        "--results-file",
        help="JSONL path for this run. Relative paths go under results/. Default: results/surfsky_managed.jsonl",
    )
    parser.add_argument(
        "--batch-file",
        help="Batch-event JSONL path. Relative paths go under results/. Default: results/surfsky_managed_batches.jsonl",
    )
    parser.add_argument("--check-config", action="store_true")
    parser.add_argument("--preflight", action="store_true")
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Required to create a billable Surfsky browser and run target evaluations.",
    )
    parser.add_argument(
        "--profile-uuid",
        help="Reuse an existing Surfsky persistent profile instead of creating an empty one.",
    )
    args = parser.parse_args()
    global RESULTS_FILE, BATCH_FILE
    if args.results_file:
        results_path = Path(args.results_file)
        RESULTS_FILE = results_path if results_path.is_absolute() else RESULTS_DIR / results_path
    if args.batch_file:
        batch_path = Path(args.batch_file)
        BATCH_FILE = batch_path if batch_path.is_absolute() else RESULTS_DIR / batch_path
    RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    BATCH_FILE.parent.mkdir(parents=True, exist_ok=True)

    if args.runs < 1:
        parser.error("--runs must be at least 1")
    if args.max_attempts < 1:
        parser.error("--max-attempts must be at least 1")
    if args.min_target_interval < 0:
        parser.error("--min-target-interval cannot be negative")

    load_env_file()
    config = load_surfsky_config()

    if args.check_config:
        print(json.dumps({
            "base_url_configured": True,
            "token_configured": True,
            "method": surfsky_method_metadata(),
            "access_deadline_ms": ACCESS_DEADLINE_MS,
            "navigation_timeout_ms": NAVIGATION_TIMEOUT_MS,
        }, ensure_ascii=False, indent=2))
        return

    if args.preflight:
        print(json.dumps(preflight(config), ensure_ascii=False, indent=2))
        return

    if not args.execute:
        parser.error("Refusing to start a billable Surfsky browser without --execute")

    batch_id = args.batch_id or datetime.now(timezone.utc).strftime(
        "surfsky-managed-%Y%m%dT%H%M%SZ"
    )
    selected_targets = TARGETS if args.target == "all" else (TARGET_BY_NAME[args.target],)
    last_navigation: dict[str, float] = {}

    def emit_row(row, target):
        row["seed"] = args.seed
        row["scheduled_domain"] = domain_key(target)
        append_jsonl(RESULTS_FILE, row)
        print(json.dumps({
            "identity_mode": row.get("identity_mode"),
            "persistent_hit_index": row.get("persistent_hit_index"),
            "target": row["target_name"],
            "replicate": row["replicate"],
            "attempt": row["attempt"],
            "classification": row["classification"],
            "failure_type": row.get("failure_type"),
            "access_ms": row.get("access_ms"),
            "captcha_status": row.get("captcha_auto_solve_status"),
            "valid_scored_evaluation": row["valid_scored_evaluation"],
        }, ensure_ascii=False), flush=True)

    def connect_browser(playwright, ws_url, max_attempts: int = 4):
        connect_started = time.perf_counter()
        last_error = None
        for attempt in range(1, max_attempts + 1):
            try:
                if attempt == 1:
                    time.sleep(3.0)
                browser = playwright.chromium.connect_over_cdp(ws_url, timeout=60_000)
                if not browser.contexts:
                    raise RuntimeError("Surfsky browser exposed no BrowserContext over CDP")
                context = browser.contexts[0]
                context.set_default_navigation_timeout(NAVIGATION_TIMEOUT_MS)
                context.set_default_timeout(DEFAULT_ACTION_TIMEOUT_MS)
                return browser, context, browser.version, elapsed_ms(connect_started)
            except Exception as exc:
                last_error = exc
                print(json.dumps({
                    "warning": "cdp_connect_retry",
                    "attempt": attempt,
                    "max_attempts": max_attempts,
                    "error": type(exc).__name__,
                }), flush=True)
                if attempt < max_attempts:
                    time.sleep(min(12.0, 3.0 * attempt))
        raise last_error

    def score_attempt(identity_mode, session_meta, context, browser_version, cdp_connect_ms, target, replicate, attempt, identity_id, persistent_hit_index=None):
        pre_run_wait_ms = wait_for_spacing(last_navigation, target.name, args.min_target_interval)
        last_navigation[target.name] = time.monotonic()
        row = run_once(
            context=context,
            browser_version=browser_version,
            session_meta=session_meta,
            session_start_ms=session_meta["start_ms"],
            cdp_connect_ms=cdp_connect_ms,
            target=target,
            batch_id=batch_id,
            replicate=replicate,
            attempt=attempt,
            config=config,
            identity_mode=identity_mode,
            identity_id=identity_id,
            persistent_hit_index=persistent_hit_index,
        )
        row["pre_run_wait_ms"] = pre_run_wait_ms
        emit_row(row, target)
        if row.get("fatal_session_loss"):
            raise RuntimeError("Surfsky browser/session continuity was lost")
        return row

    def run_grid(identity_mode, session_meta, context, browser_version, cdp_connect_ms, identity_id):
        previous_domain = None
        rng = random.Random(args.seed)
        persistent_hit_index = 0
        for replicate in range(1, args.runs + 1):
            for target in ordered_round(selected_targets, rng, previous_domain):
                scored = False
                for attempt in range(1, args.max_attempts + 1):
                    persistent_hit_index += 1
                    hit_index = persistent_hit_index
                    row = score_attempt(
                        identity_mode, session_meta, context, browser_version,
                        cdp_connect_ms, target, replicate, attempt, identity_id, hit_index,
                    )
                    if row["valid_scored_evaluation"]:
                        scored = True
                        break
                if not scored:
                    print(json.dumps({
                        "warning": "replicate_exhausted_without_valid_score",
                        "identity_mode": identity_mode,
                        "target": target.name,
                        "replicate": replicate,
                    }), flush=True)
                previous_domain = domain_key(target)

    session_meta = None
    browser = None
    try:
        fingerprint_os = SURFSKY_FINGERPRINT_OS
        if args.profile_uuid:
            profile_uuid = args.profile_uuid.strip()
            session_meta = start_persistent_profile(
                config, profile_uuid, cache_key=slug(batch_id)
            )
        else:
            try:
                profile_uuid = create_persistent_profile(
                    config, f"benchmark-{batch_id}", fingerprint_os=fingerprint_os
                )
                session_meta = start_persistent_profile(
                    config, profile_uuid, cache_key=slug(batch_id)
                )
            except Exception:
                fingerprint_os = SURFSKY_FINGERPRINT_FALLBACK_OS
                profile_uuid = create_persistent_profile(
                    config, f"benchmark-{batch_id}-{fingerprint_os}", fingerprint_os=fingerprint_os
                )
                session_meta = start_persistent_profile(
                    config, profile_uuid, cache_key=slug(batch_id)
                )
        session_meta["fingerprint_os"] = fingerprint_os
        append_jsonl(BATCH_FILE, {
            "event": "session_started",
            "identity_mode": "persistent",
            "batch_id": batch_id,
            "timestamp_utc": now_iso(),
            "profile_uuid": profile_uuid,
            "fingerprint_os": fingerprint_os,
            "session_hash": session_meta["session_hash"],
            "inspector": session_meta.get("inspector"),
        })
        with sync_playwright() as playwright:
            browser, context, browser_version, cdp_connect_ms = connect_browser(
                playwright, session_meta["ws_url"]
            )
            run_grid(
                "persistent",
                session_meta,
                context,
                browser_version,
                cdp_connect_ms,
                session_meta["identity_id"],
            )
    except Exception as exc:
        if session_meta is not None:
            append_jsonl(BATCH_FILE, {
                "event": "batch_error",
                "identity_mode": "persistent",
                "batch_id": batch_id,
                "timestamp_utc": now_iso(),
                "session_hash": session_meta.get("session_hash"),
                "error": redact_runtime_secrets(exc, config, session_meta.get("ws_url")),
                "api_error": safe_api_error(exc, config),
            })
        raise
    finally:
        if browser is not None:
            close_surfsky_browser(browser)
        if session_meta is not None:
            stop_result = stop_surfsky_session(config, session_meta["internal_uuid"])
            append_jsonl(BATCH_FILE, {
                "event": "batch_finished",
                "identity_mode": "persistent",
                "batch_id": batch_id,
                "timestamp_utc": now_iso(),
                "session_hash": session_meta["session_hash"],
                "stop": stop_result,
            })


if __name__ == "__main__":
    main()
