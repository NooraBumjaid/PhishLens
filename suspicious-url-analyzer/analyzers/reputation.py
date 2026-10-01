"""Optional external reputation status.

This module does not visit the submitted URL and does not call VirusTotal.
A future live check must send the URL to the reputation provider's API.
It must not fetch the submitted website with requests.get(submitted_url)
or any other request to that address. Visiting user-supplied URLs from
the server would create a server-side request forgery risk.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"
PROVIDER = "VirusTotal"
ENABLED_VALUES = {"true", "1", "yes"}


def _environment_enabled(value):
    """Return True only for the documented on values."""
    return (value or "").strip().lower() in ENABLED_VALUES


def _reputation_result(status, message):
    """Return the stable reputation record. Counts stay at zero until a live check exists."""
    return {
        "available": False,
        "provider": PROVIDER,
        "status": status,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "message": message,
    }


def check_url_reputation(url):
    """Report whether a future reputation check could run.

    The url argument is reserved for a future provider API call. This step
    does not send it anywhere and does not open it.
    """
    # Keep the parameter in the public interface without fetching it.
    if url is None:
        url = ""
    load_dotenv(ENV_PATH, override=False)

    enabled = _environment_enabled(os.getenv("ENABLE_REPUTATION_CHECKS"))
    api_key = (os.getenv("VIRUSTOTAL_API_KEY") or "").strip()

    if not enabled:
        return _reputation_result(
            "disabled",
            "External reputation checking is disabled.",
        )

    if not api_key:
        return _reputation_result(
            "not_configured",
            "VirusTotal reputation checking is not configured.",
        )

    # The key is present, but this step still must not contact VirusTotal
    # or the submitted website.
    return _reputation_result(
        "ready",
        "VirusTotal integration is configured and ready for a future live reputation check.",
    )
