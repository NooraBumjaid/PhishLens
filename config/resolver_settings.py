"""Limits and policy for optional safe destination / page inspection."""

from config.security import (
    CONNECT_TIMEOUT,
    MAX_PAGE_BYTES as SECURITY_MAX_PAGE_BYTES,
    MAX_REDIRECT_BODY_BYTES,
    MAX_REDIRECTS as SECURITY_MAX_REDIRECTS,
    READ_TIMEOUT,
)

CONNECT_TIMEOUT_SECONDS = CONNECT_TIMEOUT
READ_TIMEOUT_SECONDS = READ_TIMEOUT
MAX_REDIRECTS = SECURITY_MAX_REDIRECTS
MAX_RESPONSE_BYTES = MAX_REDIRECT_BODY_BYTES
MAX_PAGE_BYTES = SECURITY_MAX_PAGE_BYTES
USER_AGENT = "PhishLens-SafeResolver/1.0"

ALLOWED_SCHEMES = frozenset({"http", "https"})
REDIRECT_STATUS_CODES = frozenset({301, 302, 303, 307, 308})
ACCEPTED_HTML_CONTENT_TYPES = frozenset(
    {
        "text/html",
        "application/xhtml+xml",
    }
)

BLOCKED_HOSTNAMES = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
        "metadata.google.internal",
    }
)

BLOCKED_HOSTNAME_SUFFIXES = (
    ".localhost",
    ".local",
    ".internal",
    ".intranet",
    ".lan",
)
