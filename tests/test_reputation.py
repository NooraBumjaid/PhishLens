import base64
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader

from analyzers.reputation import (
    check_url_reputation,
    get_reputation_availability,
    virustotal_url_id,
)
from app import app
from database.database import get_scan_by_id, get_scans, init_db, save_reputation_check
from services.report_generator import generate_url_report
from tests.support import make_client


FAKE_API_KEY = "vt-test-key-should-never-leak-xyz"


def _vt_stats_body(malicious=0, suspicious=0, harmless=70, undetected=15):
    stats = {
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "timeout": 0,
    }
    return json.dumps(
        {"data": {"attributes": {"last_analysis_stats": stats}}}
    ).encode("utf-8")


class TestVirusTotalUrlId(unittest.TestCase):
    def test_url_id_matches_v3_spec(self):
        url = "https://www.example.com/path?q=1"
        expected = (
            base64.urlsafe_b64encode(url.encode("utf-8")).decode("ascii").rstrip("=")
        )
        self.assertEqual(virustotal_url_id(url), expected)

    def test_url_id_preserves_path_and_query(self):
        url = "https://example.com/a/b?token=abc&x=1"
        url_id = virustotal_url_id(url)
        # Unpadded URL-safe base64; padding restored for decode check.
        padded = url_id + "=" * (-len(url_id) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        self.assertEqual(decoded, url)
        self.assertIn("token=abc", decoded)


class TestReputationAvailability(unittest.TestCase):
    def test_disabled_makes_no_http_request(self):
        with patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "false",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "disabled")
        self.assertFalse(result["source_available"])
        self.assertEqual(result["provider"], "VirusTotal")
        self.assertNotIn(FAKE_API_KEY, result["message"])

    def test_enabled_without_api_key(self):
        with patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            with patch.dict(
                os.environ,
                {"ENABLE_REPUTATION_CHECKS": "true", "VIRUSTOTAL_API_KEY": ""},
                clear=False,
            ):
                result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "not_configured")
        self.assertFalse(result["source_available"])

    def test_availability_available_without_network(self):
        with patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = get_reputation_availability()

        self.assertEqual(result["status"], "available")
        self.assertTrue(result["source_available"])
        self.assertEqual(result["message"], "Available")

    def test_availability_disabled_even_when_key_present(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "false",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            result = get_reputation_availability()
        self.assertEqual(result["status"], "disabled")
        self.assertFalse(result["source_available"])

    def test_availability_not_configured_when_flag_true_without_key(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": "",
            },
        ):
            result = get_reputation_availability()
        self.assertEqual(result["status"], "not_configured")
        self.assertFalse(result["source_available"])


class TestReputationLookup(unittest.TestCase):
    def test_clean_response_wording(self):
        with patch(
            "analyzers.reputation._provider_get",
            return_value=(200, _vt_stats_body(0, 0, 70, 15)),
        ):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = check_url_reputation(
                    "https://example.com",
                    target_type="submitted_url",
                )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["malicious"], 0)
        self.assertEqual(result["suspicious"], 0)
        self.assertEqual(result["harmless"], 70)
        self.assertEqual(result["undetected"], 15)
        self.assertEqual(result["total_engines"], 85)
        self.assertIn("No malicious or suspicious classifications", result["message"])
        self.assertNotIn("Safe", result["message"])
        self.assertNotIn(FAKE_API_KEY, result["message"])

    def test_detections_and_total(self):
        with patch(
            "analyzers.reputation._provider_get",
            return_value=(200, _vt_stats_body(5, 2, 60, 20)),
        ):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = check_url_reputation("https://g00gle.com/login")

        self.assertEqual(result["malicious"], 5)
        self.assertEqual(result["suspicious"], 2)
        self.assertEqual(result["total_engines"], 87)
        self.assertIn("security engines classified", result["message"].lower())
        self.assertNotIn("voted", result["message"].lower())

    def test_unknown_404(self):
        import urllib.error

        error = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/urls/x",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )
        with patch("analyzers.reputation._provider_get", side_effect=error):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = check_url_reputation("https://unknown.example/path")

        self.assertEqual(result["status"], "unknown")
        self.assertIn("No existing reputation record", result["message"])
        self.assertIsNone(result["malicious"])

    def test_rate_limit_429(self):
        import urllib.error

        error = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/urls/x",
            code=429,
            msg="Too Many Requests",
            hdrs=None,
            fp=None,
        )
        with patch("analyzers.reputation._provider_get", side_effect=error):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "rate_limited")
        self.assertIn("rate limit", result["message"].lower())

    def test_server_error_500(self):
        import urllib.error

        error = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/urls/x",
            code=500,
            msg="Server Error",
            hdrs=None,
            fp=None,
        )
        with patch("analyzers.reputation._provider_get", side_effect=error):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "failed")
        self.assertIn("temporarily unavailable", result["message"].lower())

    def test_timeout(self):
        import urllib.error

        error = urllib.error.URLError(TimeoutError("timed out"))
        with patch("analyzers.reputation._provider_get", side_effect=error):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "timeout")


class TestReputationIntegration(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        app.config["TESTING"] = True
        self.client = make_client()
        init_db()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_analyze_does_not_call_virustotal(self):
        with patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "true",
                    "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
                },
            ):
                response = self.client.post(
                    "/analyze",
                    data={"url": "https://example.com"},
                )

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("Available", html)
        self.assertIn("Check Reputation", html)
        self.assertIn("Not checked", html)
        self.assertNotIn("Not enabled", html)
        self.assertIn("share the analyzed URL", html)
        self.assertNotIn(FAKE_API_KEY, html)

    def test_opening_scan_does_not_call_virustotal(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            self.client.post("/analyze", data={"url": "https://example.com/stored-rep"})
            scan_id = get_scans(scan_type="url")[0]["id"]
            with patch(
                "analyzers.reputation._provider_get",
                side_effect=AssertionError("VirusTotal must not run on scan GET"),
            ):
                detail = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
        self.assertIn("Check Reputation", detail)
        self.assertNotIn(FAKE_API_KEY, detail)

    def test_health_never_exposes_api_key(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), {"status": "ok"})
        body = response.get_data(as_text=True)
        self.assertNotIn(FAKE_API_KEY, body)
        self.assertNotIn("VIRUSTOTAL", body.upper())

    def test_disabled_ui_label(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "false",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            response = self.client.post(
                "/analyze",
                data={"url": "https://example.com"},
            )
        html = response.get_data(as_text=True)
        self.assertIn("Not enabled", html)
        self.assertNotIn("Check Reputation", html)

    def test_score_independence_after_reputation(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            analyze = self.client.post(
                "/analyze",
                data={"url": "https://g00gle.com/login"},
            )
            self.assertEqual(analyze.status_code, 200)
            html = analyze.get_data(as_text=True)
            self.assertIn("45", html)
            self.assertIn("Suspicious", html)

            scan_id = get_scans(scan_type="url")[0]["id"]
            before = get_scan_by_id(scan_id)["scan"]["risk_score"]

            with patch(
                "analyzers.reputation._provider_get",
                return_value=(200, _vt_stats_body(5, 2, 60, 20)),
            ):
                check = self.client.post(
                    "/check-reputation",
                    data={"scan_id": scan_id, "target_type": "submitted_url"},
                    follow_redirects=True,
                )

            self.assertEqual(check.status_code, 200)
            after = get_scan_by_id(scan_id)["scan"]["risk_score"]
            self.assertEqual(before, 45)
            self.assertEqual(after, 45)
            body = check.get_data(as_text=True)
            self.assertIn("Malicious", body)
            self.assertIn("rep-malicious", body)
            self.assertRegex(body, r'rep-malicious[\s\S]*?>5<')
            self.assertRegex(body, r'rep-suspicious[\s\S]*?>2<')
            self.assertNotIn(FAKE_API_KEY, body)
            self.assertNotIn("Safe", body)

            record = get_scan_by_id(scan_id)
            stored = record["reputation_checks"]["submitted_url"]
            self.assertEqual(stored["malicious_count"], 5)
            self.assertEqual(stored["suspicious_count"], 2)
            self.assertEqual(stored["total_engines"], 87)
            blob = json.dumps(stored)
            self.assertNotIn(FAKE_API_KEY, blob)

    def test_history_shows_stored_result_without_api(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            self.client.post("/analyze", data={"url": "https://example.com/rep"})
            scan_id = get_scans(scan_type="url")[0]["id"]
            save_reputation_check(
                scan_id,
                {
                    "target_type": "submitted_url",
                    "target_url": "https://example.com/rep",
                    "provider": "VirusTotal",
                    "status": "completed",
                    "message": "No malicious or suspicious classifications were reported in the available provider result.",
                    "malicious": 0,
                    "suspicious": 0,
                    "harmless": 70,
                    "undetected": 15,
                    "total_engines": 85,
                    "checked_at": "2026-10-03T20:15:00+00:00",
                },
            )

            with patch(
                "analyzers.reputation._provider_get",
                side_effect=AssertionError("network"),
            ):
                detail = self.client.get(f"/scan/{scan_id}")

        self.assertEqual(detail.status_code, 200)
        html = detail.get_data(as_text=True)
        self.assertIn("Submitted URL Reputation", html)
        self.assertIn("Harmless", html)
        self.assertIn("70", html)
        self.assertIn("Checked", html)
        self.assertNotIn(FAKE_API_KEY, html)

    def test_pdf_uses_stored_reputation_without_api(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            self.client.post("/analyze", data={"url": "https://example.com/pdf-rep"})
            scan_id = get_scans(scan_type="url")[0]["id"]
            save_reputation_check(
                scan_id,
                {
                    "target_type": "submitted_url",
                    "target_url": "https://example.com/pdf-rep",
                    "provider": "VirusTotal",
                    "status": "completed",
                    "message": "test",
                    "malicious": 4,
                    "suspicious": 2,
                    "harmless": 63,
                    "undetected": 20,
                    "total_engines": 89,
                    "checked_at": "2026-10-03T20:15:00+00:00",
                },
            )
            record = get_scan_by_id(scan_id)

            with patch(
                "analyzers.reputation._provider_get",
                side_effect=AssertionError("network"),
            ):
                pdf_bytes = generate_url_report(record)
                report = self.client.get(f"/scan/{scan_id}/report")

        self.assertEqual(report.status_code, 200)
        text = _pdf_text(pdf_bytes)
        self.assertIn("External Reputation", text)
        self.assertIn("VirusTotal", text)
        self.assertIn("Malicious classifications", text)
        self.assertIn("4", text)
        self.assertIn("time of the check", text.lower())
        self.assertNotIn(FAKE_API_KEY, text)
        report_bytes = report.get_data()
        self.assertNotIn(FAKE_API_KEY.encode("utf-8"), report_bytes)

    def test_unknown_ui_from_route(self):
        import urllib.error

        error = urllib.error.HTTPError(
            url="https://www.virustotal.com/api/v3/urls/x",
            code=404,
            msg="Not Found",
            hdrs=None,
            fp=None,
        )
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "true",
                "VIRUSTOTAL_API_KEY": FAKE_API_KEY,
            },
        ):
            self.client.post("/analyze", data={"url": "https://example.com/unknown"})
            scan_id = get_scans(scan_type="url")[0]["id"]
            with patch("analyzers.reputation._provider_get", side_effect=error):
                response = self.client.post(
                    "/check-reputation",
                    data={"scan_id": scan_id, "target_type": "submitted_url"},
                    follow_redirects=True,
                )

        html = response.get_data(as_text=True)
        self.assertIn("No existing reputation record", html)
        self.assertNotIn("0 malicious = safe", html.lower())
        self.assertNotIn("guaranteed safe", html.lower())


def _pdf_text(pdf_bytes):
    path = Path(tempfile.mkdtemp()) / "report.pdf"
    path.write_bytes(pdf_bytes)
    try:
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    finally:
        path.unlink(missing_ok=True)
        path.parent.rmdir()


if __name__ == "__main__":
    unittest.main()
