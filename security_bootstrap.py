"""Register Flask security middleware: CSRF, rate limits, headers, errors."""

from __future__ import annotations

import logging
import os
import sys
from pathlib import Path

from dotenv import load_dotenv
from flask import render_template, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFError, CSRFProtect
from werkzeug.exceptions import RequestEntityTooLarge

from config.security import (
    CONTENT_SECURITY_POLICY,
    MAX_CONTENT_LENGTH,
    PERMISSIONS_POLICY,
    env_flag,
    is_production,
)

ENV_PATH = Path(__file__).resolve().parent / ".env"
csrf = CSRFProtect()
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri="memory://",
    default_limits=[],
)

logger = logging.getLogger("phishlens")

# Reject these values in production even if they are long enough.
_INSECURE_SECRET_VALUES = frozenset(
    {
        "phishlens-dev-only-change-me",
        "change-me",
        "changeme",
        "secret",
        "secret-key",
        "flask-secret-key",
        "dev",
        "development",
        "password",
        "12345678901234567890123456789012",
    }
)
_MIN_PRODUCTION_SECRET_LENGTH = 32


def _require_production_secret(secret):
    """Fail closed when the production signing key is missing or weak."""
    if not secret:
        raise RuntimeError(
            "FLASK_SECRET_KEY must be set when PHISHLENS_ENV=production."
        )
    if secret in _INSECURE_SECRET_VALUES or secret.casefold() in _INSECURE_SECRET_VALUES:
        raise RuntimeError(
            "FLASK_SECRET_KEY is insecure. Set a unique random value "
            f"of at least {_MIN_PRODUCTION_SECRET_LENGTH} characters."
        )
    if len(secret) < _MIN_PRODUCTION_SECRET_LENGTH:
        raise RuntimeError(
            "FLASK_SECRET_KEY must be at least "
            f"{_MIN_PRODUCTION_SECRET_LENGTH} characters when "
            "PHISHLENS_ENV=production."
        )
    return secret


def _apply_proxy_fix(app, production):
    """Optionally trust a known number of reverse-proxy hops.

    Set TRUST_PROXY_HOPS to a positive integer only when PhishLens sits behind
    a reverse proxy you control. Do not enable this for direct public exposure.
    """
    raw = (os.getenv("TRUST_PROXY_HOPS") or "").strip()
    if not raw:
        return
    try:
        hops = int(raw)
    except ValueError as error:
        raise RuntimeError(
            "TRUST_PROXY_HOPS must be a non-negative integer when set."
        ) from error
    if hops < 0:
        raise RuntimeError("TRUST_PROXY_HOPS must be a non-negative integer when set.")
    if hops == 0:
        return
    if not production:
        logger.info(
            "TRUST_PROXY_HOPS=%s is set outside production; applying ProxyFix.",
            hops,
        )
    from werkzeug.middleware.proxy_fix import ProxyFix

    app.wsgi_app = ProxyFix(
        app.wsgi_app,
        x_for=hops,
        x_proto=hops,
        x_host=hops,
        x_prefix=hops,
    )


def configure_app(app):
    """Apply security configuration to the Flask application."""
    production = False
    # Load PHISHLENS_ENV first with non-overriding fill so is_production works,
    # then reload project .env with override in development so local .env wins
    # over stale process/reloader environment values.
    load_dotenv(ENV_PATH, override=False)
    production = is_production()
    if production:
        # Platform/environment variables remain authoritative in production.
        load_dotenv(ENV_PATH, override=False)
    else:
        # Local .env must win after edits + Flask reloads (override=False would
        # keep a stale ENABLE_REPUTATION_CHECKS=false from the parent process).
        load_dotenv(ENV_PATH, override=True)
        production = is_production()

    debug = env_flag("FLASK_DEBUG", default=False) and not production
    if production:
        debug = False

    secret = (os.getenv("FLASK_SECRET_KEY") or "").strip()
    if production:
        secret = _require_production_secret(secret)
    elif not secret:
        # Development fallback only — not for production use.
        secret = "phishlens-dev-only-change-me"

    # Rate-limit bypass is process-local and pytest-only. It cannot be enabled
    # by HTTP requests or environment variables. Importing pytest in a
    # production worker is not supported and must not be done.
    under_pytest = "pytest" in sys.modules

    app.config.update(
        SECRET_KEY=secret,
        DEBUG=debug,
        TESTING=under_pytest or bool(app.config.get("TESTING")),
        TEMPLATES_AUTO_RELOAD=not production,
        MAX_CONTENT_LENGTH=MAX_CONTENT_LENGTH,
        WTF_CSRF_ENABLED=True,
        WTF_CSRF_TIME_LIMIT=None,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Production staging must terminate TLS in front of the app.
        SESSION_COOKIE_SECURE=production,
        RATELIMIT_ENABLED=True,
        PHISHLENS_PRODUCTION=production,
    )

    _apply_proxy_fix(app, production)
    csrf.init_app(app)
    limiter.init_app(app)
    if under_pytest:
        app.config["RATELIMIT_ENABLED"] = False
        limiter.enabled = False

    _configure_logging()
    if not production and not under_pytest:
        # Safe diagnostic only — never log the API key or any secret value.
        reputation_enabled = env_flag("ENABLE_REPUTATION_CHECKS", default=False)
        api_key_configured = bool((os.getenv("VIRUSTOTAL_API_KEY") or "").strip())
        logger.info(
            "Reputation checks enabled: %s",
            reputation_enabled,
        )
        logger.info(
            "VirusTotal API key configured: %s",
            api_key_configured,
        )
    _register_security_headers(app)
    _register_error_handlers(app)

    return app


def _configure_logging():
    if logging.getLogger().handlers:
        return
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def _register_security_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = PERMISSIONS_POLICY

        if app.config.get("PHISHLENS_PRODUCTION") and request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        endpoint = request.endpoint or ""
        if endpoint.startswith("static"):
            return response

        # Avoid caching analysis results and saved-scan HTML.
        if request.path.startswith("/scan/") or request.path in {
            "/analyze",
            "/analyze-email",
        }:
            response.headers["Cache-Control"] = "no-store"
        elif endpoint in {"history", "scan_detail"}:
            response.headers["Cache-Control"] = "no-store"

        return response


def _register_error_handlers(app):
    @app.errorhandler(400)
    def bad_request(_error):
        return (
            render_template(
                "error.html",
                title="Bad Request",
                heading="Bad Request",
                message="The request could not be processed.",
            ),
            400,
        )

    @app.errorhandler(403)
    def forbidden(_error):
        return (
            render_template(
                "error.html",
                title="Forbidden",
                heading="Forbidden",
                message="This action is not allowed.",
            ),
            403,
        )

    @app.errorhandler(404)
    def not_found(_error):
        return render_template("not_found.html"), 404

    @app.errorhandler(413)
    @app.errorhandler(RequestEntityTooLarge)
    def too_large(_error):
        return (
            render_template(
                "error.html",
                title="Submission Too Large",
                heading="Submission is too large",
                message="Submission is too large to analyze.",
            ),
            413,
        )

    @app.errorhandler(429)
    def rate_limited(_error):
        return (
            render_template(
                "error.html",
                title="Too Many Requests",
                heading="Too many requests",
                message="Too many requests. Please wait and try again.",
            ),
            429,
        )

    @app.errorhandler(500)
    def server_error(_error):
        logger.exception("Unhandled application error")
        return (
            render_template(
                "error.html",
                title="Server Error",
                heading="Something went wrong",
                message="An unexpected error occurred. Please try again.",
            ),
            500,
        )

    @app.errorhandler(CSRFError)
    def csrf_error(_error):
        return (
            render_template(
                "error.html",
                title="Security Check Failed",
                heading="Security check failed",
                message="The form security token was missing or invalid. Please reload the page and try again.",
            ),
            400,
        )
