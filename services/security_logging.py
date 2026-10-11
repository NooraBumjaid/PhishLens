"""Safe logging helpers that avoid leaking secrets and URL tokens."""

from __future__ import annotations

from urllib.parse import urlsplit, urlunsplit


def redact_url(url):
    """Return scheme://host/path with query/fragment removed or redacted.

    Useful when logging destinations that may contain tokens in the query.
    """
    if url is None:
        return ""
    text = str(url).strip()
    if not text:
        return ""
    try:
        parts = urlsplit(text)
    except Exception:
        return "[unparseable-url]"

    if not parts.scheme and not parts.netloc:
        if "?" in text or "#" in text:
            return text.split("?", 1)[0].split("#", 1)[0] + "?[REDACTED]"
        return text[:120]

    path = parts.path or "/"
    if parts.query or parts.fragment:
        return urlunsplit((parts.scheme, parts.netloc, path, "REDACTED", ""))
    return urlunsplit((parts.scheme, parts.netloc, path, "", ""))
