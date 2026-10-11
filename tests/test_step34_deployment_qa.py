"""Step 34 — deployment readiness and configuration regressions."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzers.email_analyzer import (
    EmailValidationError,
    MAX_EMAIL_INPUT_LENGTH,
    validate_email_input,
)
from config.security import MAX_EMAIL_BYTES, MAX_EMAIL_CHARS
from services.safe_redirect_resolver import validate_destination_url
from tests.support import make_client


class TestStep34EmailSizeLimits(unittest.TestCase):
    def test_character_limit_still_enforced(self):
        with self.assertRaises(EmailValidationError) as ctx:
            validate_email_input("a" * (MAX_EMAIL_CHARS + 1))
        self.assertIn("100,000 characters", str(ctx.exception))

    def test_utf8_byte_limit_rejects_dense_unicode(self):
        # Each emoji is 4 UTF-8 bytes. Stay under the character cap but over 100 KB.
        emoji = "😀"
        char_count = (MAX_EMAIL_BYTES // 4) + 8
        self.assertLess(char_count, MAX_EMAIL_CHARS)
        payload = emoji * char_count
        self.assertGreater(len(payload.encode("utf-8")), MAX_EMAIL_BYTES)
        with self.assertRaises(EmailValidationError) as ctx:
            validate_email_input(payload)
        self.assertIn("100 KB", str(ctx.exception))

    def test_route_returns_controlled_byte_limit_error(self):
        client = make_client()
        emoji = "😀"
        char_count = (MAX_EMAIL_BYTES // 4) + 8
        response = client.post(
            "/analyze-email",
            data={"raw_email": emoji * char_count},
        )
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("too large", page.lower())
        self.assertIn("100 KB", page)

    def test_max_email_input_length_alias_matches_chars(self):
        self.assertEqual(MAX_EMAIL_INPUT_LENGTH, MAX_EMAIL_CHARS)


class TestStep34ProductionConfig(unittest.TestCase):
    def test_production_rejects_short_secret(self):
        with patch.dict(
            os.environ,
            {
                "PHISHLENS_ENV": "production",
                "FLASK_SECRET_KEY": "too-short-secret-key",
                "TRUST_PROXY_HOPS": "",
            },
            clear=False,
        ):
            from flask import Flask
            from security_bootstrap import configure_app

            with self.assertRaises(RuntimeError) as ctx:
                configure_app(Flask("probe-short-secret"))
            self.assertIn("at least 32", str(ctx.exception))

    def test_production_rejects_insecure_placeholder_secret(self):
        with patch.dict(
            os.environ,
            {
                "PHISHLENS_ENV": "production",
                "FLASK_SECRET_KEY": "phishlens-dev-only-change-me",
                "TRUST_PROXY_HOPS": "",
            },
            clear=False,
        ):
            from flask import Flask
            from security_bootstrap import configure_app

            with self.assertRaises(RuntimeError) as ctx:
                configure_app(Flask("probe-insecure-secret"))
            self.assertIn("insecure", str(ctx.exception).lower())

    def test_development_keeps_usable_fallback_secret(self):
        with patch.dict(
            os.environ,
            {
                "PHISHLENS_ENV": "development",
                "FLASK_SECRET_KEY": "",
                "FLASK_DEBUG": "false",
                "TRUST_PROXY_HOPS": "",
            },
            clear=False,
        ):
            from flask import Flask
            from security_bootstrap import configure_app

            probe = Flask("probe-dev")
            configure_app(probe)
            self.assertEqual(probe.config["SECRET_KEY"], "phishlens-dev-only-change-me")
            self.assertFalse(probe.config["SESSION_COOKIE_SECURE"])
            self.assertFalse(probe.config["PHISHLENS_PRODUCTION"])

    def test_trust_proxy_hops_wraps_wsgi_app(self):
        with patch.dict(
            os.environ,
            {
                "PHISHLENS_ENV": "production",
                "FLASK_SECRET_KEY": "staging-ready-secret-key-value-32+",
                "TRUST_PROXY_HOPS": "1",
            },
            clear=False,
        ):
            from flask import Flask
            from security_bootstrap import configure_app
            from werkzeug.middleware.proxy_fix import ProxyFix

            probe = Flask("probe-proxy")
            configure_app(probe)
            self.assertIsInstance(probe.wsgi_app, ProxyFix)

    def test_invalid_trust_proxy_hops_fails_closed(self):
        with patch.dict(
            os.environ,
            {
                "PHISHLENS_ENV": "production",
                "FLASK_SECRET_KEY": "staging-ready-secret-key-value-32+",
                "TRUST_PROXY_HOPS": "abc",
            },
            clear=False,
        ):
            from flask import Flask
            from security_bootstrap import configure_app

            with self.assertRaises(RuntimeError) as ctx:
                configure_app(Flask("probe-bad-hops"))
            self.assertIn("TRUST_PROXY_HOPS", str(ctx.exception))


class TestStep34NetworkSecuritySmoke(unittest.TestCase):
    def test_private_and_loopback_destinations_remain_blocked(self):
        for url in (
            "http://127.0.0.1/",
            "http://10.0.0.5/admin",
            "http://192.168.1.10/",
            "http://169.254.169.254/latest/meta-data",
        ):
            with self.assertRaises(Exception):
                validate_destination_url(url)

    def test_history_and_health_do_not_require_network(self):
        temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(temp_dir.cleanup)
        db_path = Path(temp_dir.name) / "scans.db"
        with patch("database.database.DB_PATH", db_path), patch(
            "socket.create_connection",
            side_effect=AssertionError("network"),
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            from database.database import init_db

            init_db()
            client = make_client()
            health = client.get("/health")
            self.assertEqual(health.status_code, 200)
            self.assertEqual(health.get_json(), {"status": "ok"})
            history = client.get("/history")
            self.assertEqual(history.status_code, 200)


class TestStep34EnvExample(unittest.TestCase):
    def test_env_example_documents_required_keys(self):
        root = Path(__file__).resolve().parents[1]
        example = (root / ".env.example").read_text(encoding="utf-8")
        self.assertIn("FLASK_SECRET_KEY", example)
        self.assertIn("TRUST_PROXY_HOPS", example)
        self.assertIn("DATABASE_PATH", example)
        self.assertTrue((root / "README.md").is_file())


if __name__ == "__main__":
    unittest.main()
