"""Shared helpers for PhishLens tests (CSRF-aware client and fixtures)."""

from __future__ import annotations

import re

from app import app
from security_bootstrap import limiter

_TOKEN_RE = re.compile(r'name="csrf_token"\s+value="([^"]+)"')


class PhishLensClient:
    """Wrap Flask's test client and attach CSRF tokens to POST bodies."""

    def __init__(self, client=None):
        app.config["TESTING"] = True
        app.config["RATELIMIT_ENABLED"] = False
        app.config["WTF_CSRF_ENABLED"] = True
        limiter.enabled = False
        self._client = client or app.test_client()
        self._token = None

    def _csrf_token(self):
        if self._token:
            return self._token
        response = self._client.get("/url")
        match = _TOKEN_RE.search(response.get_data(as_text=True))
        if not match:
            raise AssertionError("CSRF token was not found on /url")
        self._token = match.group(1)
        return self._token

    def post(self, path, data=None, **kwargs):
        payload = dict(data or {})
        if "csrf_token" not in payload:
            payload["csrf_token"] = self._csrf_token()
        return self._client.post(path, data=payload, **kwargs)

    def get(self, *args, **kwargs):
        return self._client.get(*args, **kwargs)

    def open(self, *args, **kwargs):
        return self._client.open(*args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._client, name)


def make_client():
    """Return a CSRF-aware test client with rate limits disabled."""
    return PhishLensClient()


def raw_client():
    """Return the bare Flask test client (no automatic CSRF token)."""
    app.config["TESTING"] = True
    app.config["RATELIMIT_ENABLED"] = False
    return app.test_client()


def sample_parsed(hostname="example.com", normalized_url=None, submitted_url=None):
    """URL fields accepted by save_scan (shared test fixture)."""
    if normalized_url is None:
        normalized_url = f"https://{hostname}"
    return {
        "hostname": hostname,
        "normalized_url": normalized_url,
        "submitted_url": submitted_url or normalized_url,
    }


def sample_risk(
    score=10,
    classification="Low Risk",
    indicators=None,
    correlations=None,
    recommendation="Stored recommendation.",
):
    """Completed URL risk payload for storage/route tests."""
    return {
        "final_score": score,
        "classification": classification,
        "recommendation": recommendation,
        "indicators": indicators or [],
        "correlations": correlations or [],
    }
