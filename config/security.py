"""Central security limits and policy for PhishLens."""

# --- Request / input limits ---
MAX_CONTENT_LENGTH = 1 * 1024 * 1024  # 1 MB overall POST body
MAX_URL_LENGTH = 2048
MAX_EMAIL_BYTES = 100 * 1024
MAX_EMAIL_CHARS = 100_000  # existing email analyzer character cap
MAX_SEARCH_LENGTH = 200
MAX_FORM_FIELD_LENGTH = 256
MAX_VT_RESPONSE_BYTES = 256 * 1024

# --- Network / inspection (shared with resolver) ---
CONNECT_TIMEOUT = 3.0
READ_TIMEOUT = 5.0
MAX_REDIRECTS = 5
MAX_PAGE_BYTES = 512 * 1024
MAX_REDIRECT_BODY_BYTES = 2048

# --- Rate limits (Flask-Limiter strings) ---
RATE_LIMIT_ANALYZE_URL = "30 per minute"
RATE_LIMIT_ANALYZE_EMAIL = "20 per minute"
RATE_LIMIT_INSPECT_DESTINATION = "10 per minute"
RATE_LIMIT_INSPECT_PAGE = "10 per minute"
RATE_LIMIT_REPUTATION = "5 per minute"

# --- Content Security Policy ---
# style-src includes 'unsafe-inline' because dashboard/email meters use
# dynamic element style attributes for chart geometry (no external styles).
CONTENT_SECURITY_POLICY = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "frame-ancestors 'none'; "
    "form-action 'self'; "
    "connect-src 'self'"
)

PERMISSIONS_POLICY = "camera=(), microphone=(), geolocation=()"

# --- Environment helpers ---
TRUE_VALUES = frozenset({"true", "1", "yes", "on"})


def env_flag(name, default=False):
    import os

    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in TRUE_VALUES


def is_production():
    import os

    return (os.getenv("PHISHLENS_ENV") or "development").strip().lower() == "production"
