"""Optional external reputation lookups (VirusTotal v3).

This module performs LOOKUP only. It does not submit unknown URLs for scanning
and does not visit the submitted website directly. Visiting user-supplied URLs
from the server would create a server-side request forgery risk; the request
goes only to the configured provider API.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone

from config.reputation_settings import (
    ENABLED_VALUES,
    PROVIDER_NAME,
    VIRUSTOTAL_API_BASE,
    VIRUSTOTAL_MAX_RESPONSE_BYTES,
    VIRUSTOTAL_TIMEOUT_SECONDS,
)

logger = logging.getLogger(__name__)


def _environment_enabled(value):
    return (value or "").strip().lower() in ENABLED_VALUES


def _load_settings():
    """Read reputation settings from the process environment.

    .env is loaded once during app startup (see security_bootstrap.configure_app).
    This function does not call load_dotenv again so process/env values stay
    authoritative after startup.
    """
    enabled = _environment_enabled(os.getenv("ENABLE_REPUTATION_CHECKS"))
    api_key = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()
    return enabled, api_key


def virustotal_url_id(url):
    """Return the VirusTotal v3 URL identifier (unpadded URL-safe base64)."""
    text = (url or "").strip()
    if not text:
        raise ValueError("URL is required to build a VirusTotal identifier.")
    return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")


def _empty_counts():
    return {
        "malicious": None,
        "suspicious": None,
        "harmless": None,
        "undetected": None,
        "total_engines": None,
    }


def _result(
    status,
    message,
    *,
    source_available=False,
    checked_at=None,
    error_code=None,
    counts=None,
    target_url=None,
    target_type=None,
):
    payload = {
        "provider": PROVIDER_NAME,
        "status": status,
        "message": message,
        "source_available": source_available,
        "available": source_available and status in {"completed", "unknown"},
        "checked_at": checked_at,
        "error_code": error_code,
        "target_url": target_url,
        "target_type": target_type,
    }
    payload.update(counts or _empty_counts())
    return payload


def get_reputation_availability():
    """Return whether reputation checks can run. Makes no network request."""
    enabled, api_key = _load_settings()
    if not enabled:
        return _result(
            "disabled",
            "Not enabled",
            source_available=False,
        )
    if not api_key:
        return _result(
            "not_configured",
            "Not configured",
            source_available=False,
        )
    return _result(
        "available",
        "Available",
        source_available=True,
    )


def _parse_stats(payload):
    try:
        stats = payload["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, TypeError) as error:
        raise ValueError("Malformed VirusTotal response.") from error

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    total = sum(int(value or 0) for value in stats.values())
    return {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
    }


def _provider_get(url_id, api_key):
    """Perform the VirusTotal GET. Patchable in tests."""
    endpoint = f"{VIRUSTOTAL_API_BASE}/urls/{url_id}"
    request = urllib.request.Request(
        endpoint,
        headers={
            "Accept": "application/json",
            "x-apikey": api_key,
            "User-Agent": "PhishLens-Reputation/1.0",
        },
        method="GET",
    )
    with urllib.request.urlopen(request, timeout=VIRUSTOTAL_TIMEOUT_SECONDS) as response:
        body = response.read(VIRUSTOTAL_MAX_RESPONSE_BYTES + 1)
        if len(body) > VIRUSTOTAL_MAX_RESPONSE_BYTES:
            raise ValueError("VirusTotal response exceeded size limit.")
        status_code = getattr(response, "status", None) or response.getcode()
        return status_code, body


def check_url_reputation(url, target_type=None):
    """Look up existing VirusTotal reputation for one URL.

    Does not submit the URL for a new scan. Does not visit the URL itself.
    """
    target_url = (url or "").strip()
    enabled, api_key = _load_settings()

    if not enabled:
        return _result(
            "disabled",
            "External reputation checking is disabled.",
            target_url=target_url or None,
            target_type=target_type,
        )
    if not api_key:
        return _result(
            "not_configured",
            "VirusTotal reputation checking is not configured.",
            target_url=target_url or None,
            target_type=target_type,
        )
    if not target_url:
        return _result(
            "failed",
            "A URL is required for reputation lookup.",
            error_code="missing_url",
            target_type=target_type,
        )

    try:
        url_id = virustotal_url_id(target_url)
    except ValueError:
        return _result(
            "failed",
            "The URL could not be prepared for reputation lookup.",
            error_code="invalid_url",
            target_url=target_url,
            target_type=target_type,
        )

    checked_at = datetime.now(timezone.utc).isoformat()
    try:
        status_code, body = _provider_get(url_id, api_key)
    except urllib.error.HTTPError as error:
        # Never log response bodies or headers that might echo secrets.
        logger.warning(
            "Reputation provider HTTP error status=%s target_type=%s",
            error.code,
            target_type,
        )
        if error.code in (401, 403):
            return _result(
                "failed",
                "Reputation check unavailable. API authentication failed.",
                error_code=str(error.code),
                checked_at=checked_at,
                target_url=target_url,
                target_type=target_type,
            )
        if error.code == 404:
            return _result(
                "unknown",
                "No existing reputation record.",
                source_available=True,
                checked_at=checked_at,
                target_url=target_url,
                target_type=target_type,
            )
        if error.code == 429:
            return _result(
                "rate_limited",
                "Reputation check temporarily unavailable. Provider rate limit reached.",
                error_code="429",
                checked_at=checked_at,
                target_url=target_url,
                target_type=target_type,
            )
        if error.code >= 500:
            return _result(
                "failed",
                "Reputation provider temporarily unavailable.",
                error_code=str(error.code),
                checked_at=checked_at,
                target_url=target_url,
                target_type=target_type,
            )
        return _result(
            "failed",
            "Reputation check could not be completed.",
            error_code=str(error.code),
            checked_at=checked_at,
            target_url=target_url,
            target_type=target_type,
        )
    except TimeoutError:
        logger.warning("Reputation provider timed out target_type=%s", target_type)
        return _result(
            "failed",
            "Reputation check timed out.",
            error_code="timeout",
            checked_at=checked_at,
            target_url=target_url,
            target_type=target_type,
        )
    except urllib.error.URLError as error:
        reason = str(getattr(error, "reason", error))
        if "timed out" in reason.lower():
            logger.warning("Reputation provider timed out target_type=%s", target_type)
            return _result(
                "failed",
                "Reputation check timed out.",
                error_code="timeout",
                checked_at=checked_at,
                target_url=target_url,
                target_type=target_type,
            )
        logger.warning("Reputation provider connection error target_type=%s", target_type)
        return _result(
            "failed",
            "Reputation provider temporarily unavailable.",
            error_code="connection_error",
            checked_at=checked_at,
            target_url=target_url,
            target_type=target_type,
        )
    except Exception:
        logger.exception("Reputation lookup failed unexpectedly")
        return _result(
            "failed",
            "Reputation check could not be completed.",
            error_code="unexpected_error",
            checked_at=checked_at,
            target_url=target_url,
            target_type=target_type,
        )

    try:
        payload = json.loads(body.decode("utf-8"))
        counts = _parse_stats(payload)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
        logger.warning("Reputation provider returned a malformed response")
        return _result(
            "failed",
            "Reputation provider returned an unreadable response.",
            error_code="malformed_response",
            checked_at=checked_at,
            target_url=target_url,
            target_type=target_type,
        )

    if counts["malicious"] == 0 and counts["suspicious"] == 0:
        message = (
            "No malicious or suspicious classifications were reported in the "
            "available provider result."
        )
    else:
        message = (
            f"{counts['malicious']} security engines classified this URL as "
            f"malicious and {counts['suspicious']} as suspicious in the "
            "available VirusTotal analysis."
        )

    return _result(
        "completed",
        message,
        source_available=True,
        checked_at=checked_at,
        counts=counts,
        target_url=target_url,
        target_type=target_type,
    )
