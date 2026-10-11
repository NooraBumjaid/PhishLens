# PhishLens

**See the signals. Spot the risk.**

PhishLens is an educational cybersecurity analysis application for inspecting suspicious characteristics in URLs and emails. It combines local heuristic analysis with optional, explicit-controlled destination inspection and external reputation lookups.

Results are explainable labels — **Low Risk**, **Suspicious**, or **High Risk** — not proof that a URL, webpage, or email is safe or malicious. PhishLens is a heuristic learning and triage aid, not a guarantee of safety.

---

## Features

### URL Analysis
- Structural URL parsing and explainable indicators
- Typosquatting / lookalike domain signals
- Shortened-URL detection
- Correlation rules and deterministic URL risk scoring

### Email Analysis
- Safe local email parsing (no outbound send of the message body to VirusTotal)
- Sender/header indicators and authentication-header interpretation
- Embedded URL analysis, attachment metadata, email risk score, and correlations

### Safe Destination Inspection
- Explicit user action required
- Controlled redirect resolution with SSRF protections
- Redirect validation, timeouts, hop limits, and TLS verification
- Connections pinned to validated public IPs (DNS-rebinding resistant connect path)

### Static Page Analysis
- Fetches limited HTML only (no JavaScript execution, no image/CSS/iframe loading, no form submission)
- Detects login/credential fields, payment fields, fine/penalty and urgency language, external form actions, and brand/domain consistency signals
- Page-content risk scoring with size and timeout limits

### External Reputation
- Optional VirusTotal lookup (existing records only)
- Requires `ENABLE_REPUTATION_CHECKS` + API key + explicit **Check Reputation** action
- Does **not** automatically submit unknown URLs for scanning
- Stored reputation results are shown later without re-contacting the provider

### Combined Assessment
- Deterministic merge of local URL, destination, page, and optional reputation evidence
- Starts from the strongest completed layer score (never sums layer scores)
- Applies small named cross-layer and VirusTotal adjustments, then clamps to 0–100
- Evidence Coverage: LIMITED / MODERATE / STRONG (independent of risk score)
- Zero VirusTotal detections never reduce local risk

### Platform
- SQLite scan history (URL + email), scan detail pages, security dashboard
- PDF reports generated from stored results only
- Responsive UI with shared `base.html` layout, CSRF-protected forms, and security headers

---

## Technology stack

| Layer | Choice |
|-------|--------|
| Language | Python 3.11+ |
| Web framework | Flask |
| Forms / CSRF | Flask-WTF |
| Rate limiting | Flask-Limiter |
| HTML parsing | Beautiful Soup |
| PDF reports | ReportLab / pypdf |
| Persistence | SQLite |
| WSGI (staging) | Gunicorn |
| Tests | pytest |

---

## Architecture

```
User Input
    |
    v
Local Analysis
    |
    +--> URL Risk Engine
    |
    +--> Email Risk Engine
    |
    v
Optional Controlled Checks (explicit action)
    |
    +--> Redirect Resolution
    +--> Static Page Inspection
    +--> VirusTotal Reputation
    |
    v
Combined Assessment
    |
    +--> SQLite History
    +--> Dashboard
    +--> PDF Report
```

---

## Security architecture overview

Implemented in the application:

- Input limits (URL length, email size, POST body size, search/filter bounds)
- Jinja auto-escaping for attacker-controlled values
- CSRF protection on state-changing POST forms
- Rate limiting on analysis and inspection endpoints
- Security headers: CSP, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`
- HSTS only when `PHISHLENS_ENV=production` **and** the request is HTTPS (not forced on localhost HTTP)
- Parameterized SQL for user-influenced queries
- SSRF protections with IP validation before connect
- HTTP(S) connections pinned to a previously validated public IP (Host / SNI preserved)
- Redirect revalidation before each hop
- TLS verification, connect/read timeouts, response-size limits
- Secrets from environment variables (never from frontend code)
- No JavaScript execution, form submission, or attachment download during page inspection
- Production refuses to start without `FLASK_SECRET_KEY`

CSP note: `style-src` allows `'unsafe-inline'` because risk meters and dashboard charts use dynamic element `style` attributes for geometry. Scripts remain `script-src 'self'` only (local `static/js/ui.js`).

Rate limiting is disabled automatically only when the pytest package is already loaded in the same process (test runner). That bypass cannot be toggled by HTTP requests or environment variables.

---

## Privacy considerations

- Initial local URL analysis does **not** visit the destination.
- Email analysis does **not** send the email to VirusTotal.
- Destination and page inspection require an explicit user action and use controlled outbound HTTPS.
- Reputation checks may share the selected URL with VirusTotal when you start that check.
- Raw email HTML is not rendered as a live page.
- Full webpage HTML is not stored long-term as a browsable page; analysis stores structured findings.
- API keys are not stored in analysis records, HTML, or PDF reports.
- Local SQLite history may contain URLs and email content you analyzed — treat `scans.db` as sensitive and do not commit it.

---

## Known limitations

- Heuristic analysis can produce false positives and false negatives.
- **Low Risk** does not guarantee safety.
- **High Risk** does not prove malicious intent.
- Page analysis does not execute JavaScript; dynamic content may be invisible.
- External reputation can be incomplete, delayed, or outdated.
- Unknown reputation does not mean safe.
- Supplied email authentication headers are interpreted from the pasted message; PhishLens does not independently re-validate them against DNS/mail infrastructure.
- Page inspection analyzes limited static HTML only.
- Optional network features depend on remote websites and third-party providers being reachable.
- SQLite history is only as durable as the filesystem you configure (see Deployment).

---

## Installation

```powershell
# 1. Clone / open the repository root (PhishLens lives at the repo root)
cd security_Analyzer

# 2. Create and activate a virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# 3. Install dependencies
python -m pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env: set FLASK_SECRET_KEY for any shared/production use.

# 5. Run (development)
python app.py

# 6. Open
# http://127.0.0.1:5000
```

On first analysis, SQLite schema initializes automatically. Re-running initialization is idempotent and does not wipe existing scans.

---

## Environment variable setup

Copy `.env.example` to `.env` and fill in values as needed. Never commit `.env`.

| Variable | Purpose |
|----------|---------|
| `FLASK_SECRET_KEY` | Session/CSRF signing key (**required** in production) |
| `PHISHLENS_ENV` | `development` or `production` |
| `FLASK_DEBUG` | Local debug only; ignored/forced off in production |
| `DATABASE_PATH` | Optional SQLite file path (default: `database/scans.db`) |
| `ENABLE_REPUTATION_CHECKS` | Enable optional VirusTotal UI/actions |
| `VIRUSTOTAL_API_KEY` | VirusTotal API key (server-side only) |
| `TRUST_PROXY_HOPS` | Optional reverse-proxy hop count (integer); leave empty for direct exposure |

### VirusTotal (optional)

```env
ENABLE_REPUTATION_CHECKS=true
VIRUSTOTAL_API_KEY=your_key_here
```

- Never commit `.env`.
- Do not put the key in templates, JavaScript, or source files.
- With `ENABLE_REPUTATION_CHECKS=false`, the app runs normally without reputation.
- Lookups still require the on-page **Check Reputation** action.

---

## How to run locally

```powershell
python app.py
```

Open `http://127.0.0.1:5000`. Landing page at `/`. Health check at `/health`.

Flask’s built-in server is for **development only**.

---

## How to run tests

From the repository root with the virtual environment active:

```powershell
python -m pytest -q
```

Tests use temporary SQLite databases and mock outbound network calls for destination/reputation paths. They do not require a real VirusTotal API key. Keep `ENABLE_REPUTATION_CHECKS` unset or `false` in CI unless a specific test temporarily patches the environment.

---

## Screenshots

Add screenshots here after capturing them locally (do not commit real phishing samples or personal email content).

| View | Placeholder |
|------|-------------|
| Home / landing | `docs/screenshots/home.png` *(add when available)* |
| URL analysis results | `docs/screenshots/url-results.png` *(add when available)* |
| Email analysis results | `docs/screenshots/email-results.png` *(add when available)* |
| Dashboard | `docs/screenshots/dashboard.png` *(add when available)* |

---

## Project structure

```
.
├── app.py                      # Flask routes + WSGI entry (app:app)
├── view_helpers.py             # Presentation helpers for routes/templates
├── security_bootstrap.py       # CSRF, rate limits, headers, error pages
├── time_format.py              # Shared Bahrain timestamp display helpers
├── Procfile                    # gunicorn entry for platform deploys
├── requirements.txt
├── .env.example
├── .github/workflows/          # CI (pytest)
├── analyzers/                  # URL, email, reputation analyzers
├── config/                     # Scoring, security, resolver, page rules
├── database/                   # SQLite access + migrations (no *.db in git)
├── services/                   # Risk engines, resolver, page/PDF/combined
├── docs/                       # Readiness report and historical validation notes
├── static/
│   ├── css/style.css
│   ├── js/ui.js
│   └── img/                    # PhishLens logos
├── templates/                  # Jinja pages + _partials (url.html, home.html, …)
└── tests/                      # pytest suite (code only)
```

---

## Staging / production run

**Do not use `python app.py` in staging.** Prefer Gunicorn on Linux.

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export PHISHLENS_ENV=production
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export DATABASE_PATH=/var/data/phishlens/scans.db
export ENABLE_REPUTATION_CHECKS=false
# Optional, only behind one trusted TLS-terminating proxy:
# export TRUST_PROXY_HOPS=1
mkdir -p "$(dirname "$DATABASE_PATH")"
gunicorn --bind 0.0.0.0:8000 --workers 2 --threads 2 --timeout 90 --access-logfile - --error-logfile - app:app
```

WSGI entry point: **`app:app`**. Health check: **`GET /health`** → `{"status":"ok"}`.

### Deployment checklist

- Python 3.11+; install `requirements.txt`
- `PHISHLENS_ENV=production`, `FLASK_DEBUG` forced off, `FLASK_SECRET_KEY` ≥ 32 unique random characters
- Terminate HTTPS in front of Gunicorn; do not expose Gunicorn publicly without TLS
- Persistent `DATABASE_PATH` if scan history must survive restarts
- Backup SQLite while idle: `cp "$DATABASE_PATH" "/backups/phishlens-$(date -u +%Y%m%dT%H%M%SZ).db"`
- Local URL/email analysis works offline; destination/page/VirusTotal need controlled outbound HTTPS
- Set `TRUST_PROXY_HOPS` only for a known reverse-proxy hop count you control
- Copy `.env.example` → `.env` for local development only; never commit `.env`

---

## Disclaimer

PhishLens is an educational security-analysis tool. Its results are heuristic and should not be treated as proof that a URL, webpage, or email is safe or malicious.
