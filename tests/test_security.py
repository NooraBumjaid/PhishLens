import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
from config.security import MAX_CONTENT_LENGTH, MAX_URL_LENGTH
from database.database import get_scans, init_db
from services.security_logging import redact_url
from tests.support import make_client, raw_client


FAKE_VT_KEY = "SUPER_SECRET_TEST_KEY"


class TestSecurityLogging(unittest.TestCase):
    def test_redact_url_query(self):
        result = redact_url("https://example.com/reset?token=SECRET&x=1")
        self.assertIn("example.com", result)
        self.assertIn("REDACTED", result)
        self.assertNotIn("SECRET", result)


class TestSecurityHeaders(unittest.TestCase):
    def setUp(self):
        self.client = make_client()

    def test_html_responses_include_security_headers(self):
        response = self.client.get("/url")
        self.assertEqual(response.status_code, 200)
        self.assertIn("default-src 'self'", response.headers.get("Content-Security-Policy", ""))
        self.assertEqual(response.headers.get("X-Content-Type-Options"), "nosniff")
        self.assertEqual(response.headers.get("Referrer-Policy"), "no-referrer")
        self.assertIn("camera=()", response.headers.get("Permissions-Policy", ""))

    def test_hsts_not_forced_on_localhost_http(self):
        with patch.dict(os.environ, {"PHISHLENS_ENV": "development"}, clear=False):
            app.config["PHISHLENS_PRODUCTION"] = False
            response = self.client.get("/url")
        self.assertNotIn("Strict-Transport-Security", response.headers)


class TestInputLimits(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        self.client = make_client()
        init_db()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_url_too_long_is_rejected(self):
        with patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ):
            response = self.client.post(
                "/analyze",
                data={"url": "https://example.com/" + ("a" * (MAX_URL_LENGTH + 50))},
            )
        html = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("URL is too long to analyze.", html)

    def test_email_too_large_is_rejected(self):
        huge = "From: a@b.com\nSubject: x\n\n" + ("A" * 120_000)
        response = self.client.post("/analyze-email", data={"raw_email": huge})
        html = response.get_data(as_text=True)
        self.assertIn("too large", html.lower())

    def test_request_body_over_max_content_length_returns_413(self):
        # Bypass CSRF helper body construction with a raw oversized request.
        client = raw_client()
        token_page = client.get("/url").get_data(as_text=True)
        import re

        match = re.search(r'name="csrf_token"\s+value="([^"]+)"', token_page)
        self.assertIsNotNone(match)
        token = match.group(1)
        oversized = "x" * (MAX_CONTENT_LENGTH + 1024)
        response = client.post(
            "/analyze",
            data={"csrf_token": token, "url": "https://example.com", "pad": oversized},
            content_type="application/x-www-form-urlencoded",
        )
        self.assertEqual(response.status_code, 413)
        self.assertIn("too large", response.get_data(as_text=True).lower())


class TestCsrfAndRateLimit(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        init_db()

    def tearDown(self):
        from security_bootstrap import limiter

        app.config["RATELIMIT_ENABLED"] = False
        limiter.enabled = False
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_post_without_csrf_token_fails(self):
        client = raw_client()
        response = client.post("/analyze", data={"url": "https://example.com"})
        self.assertIn(response.status_code, {400, 403})
        self.assertIn("security", response.get_data(as_text=True).lower())

    def test_rate_limit_returns_friendly_429(self):
        from security_bootstrap import limiter

        client = make_client()
        with patch("app.resolve_redirect_chain") as resolve:
            resolve.return_value = {
                "status": "failed",
                "reason": "x",
                "final_url": None,
                "redirect_count": 0,
                "hops": [],
            }
            analyze_resp = client.post(
                "/analyze",
                data={"url": "https://example.com/rl"},
            )
            self.assertEqual(analyze_resp.status_code, 200)
            scan_id = get_scans(scan_type="url")[0]["id"]

            app.config["RATELIMIT_ENABLED"] = True
            limiter.enabled = True
            try:
                statuses = []
                for _ in range(12):
                    response = client.post(
                        "/inspect-destination",
                        data={"scan_id": scan_id},
                    )
                    statuses.append(response.status_code)
                    if response.status_code == 429:
                        self.assertIn(
                            "too many requests",
                            response.get_data(as_text=True).lower(),
                        )
                        break
                self.assertIn(429, statuses)
            finally:
                app.config["RATELIMIT_ENABLED"] = False
                limiter.enabled = False


class TestXssAndSql(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        self.client = make_client()
        init_db()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_script_in_url_is_escaped(self):
        response = self.client.post(
            "/analyze",
            data={"url": "https://example.com/<script>alert(1)</script>"},
        )
        # Invalid hostname path may fail validation; either way script tags must not execute.
        html = response.get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        if response.status_code == 200 and "example.com" in html:
            self.assertIn("&lt;script&gt;", html)

    def test_history_search_sql_injection_safe(self):
        self.client.post("/analyze", data={"url": "https://example.com/safe"})
        before = len(get_scans())
        response = self.client.get("/history?q=%27%20OR%201%3D1%20--")
        self.assertEqual(response.status_code, 200)
        after = len(get_scans())
        self.assertEqual(before, after)
        html = response.get_data(as_text=True)
        self.assertNotIn("<script>", html)

    def test_history_search_script_escaped(self):
        response = self.client.get("/history?q=<script>alert(1)</script>")
        html = response.get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)


class TestApiKeyLeak(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        self.client = make_client()
        init_db()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_virustotal_key_not_leaked(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": FAKE_VT_KEY,
            },
        ):
            page = self.client.post(
                "/analyze",
                data={"url": "https://example.com/key-leak"},
            ).get_data(as_text=True)
            self.assertNotIn(FAKE_VT_KEY, page)

            scan_id = get_scans(scan_type="url")[0]["id"]
            with patch(
                "analyzers.reputation._provider_get",
                side_effect=TimeoutError("timed out"),
            ):
                detail = self.client.post(
                    "/check-reputation",
                    data={"scan_id": scan_id, "target_type": "submitted_url"},
                    follow_redirects=True,
                ).get_data(as_text=True)
            self.assertNotIn(FAKE_VT_KEY, detail)

            report = self.client.get(f"/scan/{scan_id}/report")
            self.assertNotIn(FAKE_VT_KEY.encode("utf-8"), report.get_data())


class TestDebugConfig(unittest.TestCase):
    def test_production_disables_debug(self):
        with patch.dict(
            os.environ,
            {
                "PHISHLENS_ENV": "production",
                "FLASK_DEBUG": "true",
                "FLASK_SECRET_KEY": "test-production-secret-key-32chars!!",
            },
            clear=False,
        ):
            from security_bootstrap import configure_app
            from flask import Flask

            probe = Flask("probe")
            configure_app(probe)
            self.assertFalse(probe.config["DEBUG"])
            self.assertTrue(probe.config["PHISHLENS_PRODUCTION"])
            self.assertTrue(probe.config["SESSION_COOKIE_SECURE"])
            self.assertFalse(probe.config["TEMPLATES_AUTO_RELOAD"])

    def test_production_requires_secret_key(self):
        with patch.dict(
            os.environ,
            {"PHISHLENS_ENV": "production", "FLASK_SECRET_KEY": ""},
            clear=False,
        ):
            from security_bootstrap import configure_app
            from flask import Flask

            probe = Flask("probe-missing-secret")
            with self.assertRaises(RuntimeError) as ctx:
                configure_app(probe)
            self.assertIn("FLASK_SECRET_KEY", str(ctx.exception))


class TestHealthEndpoint(unittest.TestCase):
    def setUp(self):
        self.client = make_client()

    def test_health_returns_ok(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})

    def test_health_does_not_expose_internals(self):
        response = self.client.get("/health")
        body = response.get_data(as_text=True)
        self.assertNotIn("VIRUSTOTAL", body.upper())
        self.assertNotIn("SECRET", body.upper())
        self.assertNotIn("scans.db", body)
        self.assertNotIn("traceback", body.lower())


class TestDatabasePathConfig(unittest.TestCase):
    def test_resolve_db_path_uses_environment(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            configured = str(Path(temp_dir) / "custom-phishlens.db")
            with patch.dict(os.environ, {"DATABASE_PATH": configured}, clear=False):
                from database.database import resolve_db_path

                self.assertEqual(resolve_db_path(), Path(configured).resolve())


if __name__ == "__main__":
    unittest.main()
