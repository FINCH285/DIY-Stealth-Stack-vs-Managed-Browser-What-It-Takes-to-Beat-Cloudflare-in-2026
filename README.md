# DIY Stealth Stack vs Managed Browser

Benchmark runners used for **DIY Stealth Stack vs Managed Browser: What It Takes to Beat Cloudflare in 2026**.

Three headed, persistent setups hit the same five Cloudflare-protected targets. Each setup records whether the target content loaded, whether Cloudflare challenged or blocked the session, and how long a successful load took.

## Setups

| Runner | Stack |
| --- | --- |
| `bare_playwright.py` | Stock Playwright, bundled Chromium, persistent profile, no proxy |
| `patchright_proxy.py` | Patchright, installed Google Chrome (`channel="chrome"`), persistent profile, sticky residential proxy |
| `surfsky_managed.py` | Playwright/Patchright attached to a Surfsky Chrome session over CDP, managed residential proxy, Turnstile handling |

Shared scoring lives in `bare_playwright.py`. The other two runners import the same targets, markers, and `classify_outcome` rules so only the browser stack changes.

## Targets

Each scored batch uses 20 headed sequential attempts per target (100 runs per setup):

- Indeed Google reviews — `https://www.indeed.com/cmp/Google/reviews`
- Indeed Google company profile — `https://www.indeed.com/cmp/Google`
- Glassdoor Google salaries — `https://www.glassdoor.com/Salary/Google-Salaries-E9079.htm`
- Capterra CRM — `https://www.capterra.com/customer-relationship-management-software/`
- StockX White Thunder — `https://stockx.com/air-jordan-4-retro-white-thunder`

Protocol defaults: 120-second access deadline and a minimum 60-second gap between hits on the same target.

A run counts as success only when host, path, and frozen page markers all match. HTTP 200 on a Cloudflare challenge page is not success.

## Classifications

- `loaded` — target content with no Cloudflare challenge observed
- `loaded_after_cloudflare_verification` — target content after a challenge
- `blocked_by_cloudflare` — no target content within 120 seconds

Blocked runs also store a failure type: `cloudflare_verification_page`, `cloudflare_403`, or `timeout`.

## Requirements

- Python 3.10+
- Playwright 1.62.0 and Patchright 1.62.3 (see `requirements.txt`)
- Installed Google Chrome for the DIY stealth runner
- A residential proxy endpoint for `patchright_proxy.py`
- A Surfsky API host and token for `surfsky_managed.py`

## Setup

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
playwright install chromium
```

Copy `.env.example` to `.env` and fill in real values.

| Variable | Used by |
| --- | --- |
| `PROXY_URL` or `DIY_PROXY_SERVER_TEMPLATE` | DIY stealth stack |
| `DIY_PROXY_USERNAME_TEMPLATE`, `DIY_PROXY_PASSWORD_TEMPLATE` | Optional split credentials |
| `DIY_PROXY_COUNTRY`, `DIY_PROXY_LOCALE`, `DIY_PROXY_TIMEZONE` | Required with the proxy |
| `DIY_PROXY_LANGUAGES`, `DIY_PROXY_LATITUDE`, `DIY_PROXY_LONGITUDE` | Geography alignment |
| `SURFSKY_API_BASE_URL`, `SURFSKY_API_TOKEN` | Managed browser |

`{country}` and `{session}` in the proxy URL are filled by `patchright_proxy.py` for sticky sessions.

## Run a scored batch

Twenty rounds on every target:

```bash
python bare_playwright.py --target all --runs 20 --batch-id your-batch-id
python patchright_proxy.py --target all --runs 20 --batch-id your-batch-id
python surfsky_managed.py --target all --runs 20 --batch-id your-batch-id --execute
```

`--batch-id` is any stable label you choose. It names the persistent profile folder and the JSONL rows. If you omit it, each runner generates its own timestamped id.

Surfsky will not start a billable browser without `--execute`. Use `--check-config` or `--preflight` first.

Rows append to `results/<setup>.jsonl`. Screenshots go under `results/screenshots/<setup>/`.
