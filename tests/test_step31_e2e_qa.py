"""Step 31 — end-to-end QA regressions across PhishLens workflows.

Uses Flask test client + mocked network only. No browser automation.
"""

from __future__ import annotations

import re
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader

from analyzers.url_analyzer import URLValidationError, analyze_url
from app import app
from database.database import (
    get_dashboard_summary,
    get_db_connection,
    get_scan_by_id,
    get_scans,
    init_db,
)
from services.combined_assessment import build_combined_assessment
from services.page_analyzer import analyze_page_html
from services.page_risk_engine import calculate_page_risk
from services.risk_engine import calculate_risk
from tests.support import make_client

URL_SCORE_REGRESSION = [
    ("https://example.com/login", 10, "Low Risk"),
    ("https://g00gle.com/login", 45, "Suspicious"),
    ("https://g00gle.com", 25, "Low Risk"),
    ("https://bit.ly/example", 25, "Low Risk"),
    ("https://bit.ly/account-verify", 45, "Suspicious"),
    ("https://example.com@evil.example/login", 40, "Suspicious"),
    ("http://192.168.1.10/account/verify", 60, "Suspicious"),
    ("http://192.168.1.10:8080/account/verify/password", 75, "High Risk"),
]


def _pdf_text(pdf_bytes: bytes) -> str:
    path = Path(tempfile.mkdtemp()) / "report.pdf"
    path.write_bytes(pdf_bytes)
    try:
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    finally:
        path.unlink(missing_ok=True)
        path.parent.rmdir()


class TestStep31UrlWorkflow(unittest.TestCase):
    def test_score_regressions_unchanged(self):
        for url, score, label in URL_SCORE_REGRESSION:
            risk = calculate_risk(analyze_url(url)["indicators"])
            self.assertEqual(risk["final_score"], score, url)
            self.assertEqual(risk["classification"], label, url)

    def test_malformed_urls_rejected(self):
        for bad in ("", "not a url", "ftp://example.com/x", "javascript:alert(1)"):
            with self.assertRaises(URLValidationError):
                analyze_url(bad)

    def test_http_https_and_keyword_ui_persistence(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        with patch("database.database.DB_PATH", Path(temp.name) / "scans.db"):
            app.config["TESTING"] = True
            client = make_client()
            init_db()
            for url, score, label in (
                ("https://example.com", 5, "LOW RISK"),
                ("http://example.com", 20, "LOW RISK"),
                ("https://example.com/login", 10, "LOW RISK"),
            ):
                page = client.post("/analyze", data={"url": url}).get_data(as_text=True)
                self.assertRegex(
                    page,
                    rf'assessment-top-score">\s*<span>{score}</span>\s*/ 100',
                    url,
                )
                self.assertIn(label, page)
                self.assertIn("PhishLens Assessment", page)
                self.assertLess(
                    page.find("PhishLens Assessment"),
                    page.find("View Detailed Analysis"),
                )
            self.assertEqual(len(get_scans(scan_type="url")), 3)


class TestStep31DestinationAndPageUi(unittest.TestCase):
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

    def test_shortener_single_destination_card_and_waiting_page(self):
        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            page = self.client.post(
                "/analyze", data={"url": "https://linkr.it/gKin2"}
            ).get_data(as_text=True)
            exchange.assert_not_called()
        self.assertEqual(page.count("<h2>Destination Analysis</h2>"), 1)
        self.assertEqual(page.count("<h2>Page Content Analysis</h2>"), 1)
        self.assertEqual(page.count("<h2>Hidden Destination</h2>"), 0)
        self.assertEqual(page.count("<h2>Inspect Final Destination</h2>"), 0)
        self.assertEqual(page.count("<h2>Destination Inspection</h2>"), 0)
        self.assertIn("Hidden Destination", page)
        self.assertEqual(page.count("Inspect Final Destination"), 1)
        self.assertIn("Status: <strong>WAITING</strong>", page)
        self.assertNotIn("Inspect Page Content", page)
        self.assertNotIn("NOT PERFORMED", page.upper())
        self.assertRegex(page, r'assessment-top-score">\s*<span>25</span>\s*/ 100')

    def test_direct_url_not_hidden_destination(self):
        page = self.client.post(
            "/analyze", data={"url": "https://example.com"}
        ).get_data(as_text=True)
        self.assertIn("NOT INSPECTED", page.upper())
        self.assertNotIn("Hidden Destination", page)
        self.assertIn("Inspect Final Destination", page)
        self.assertIn("WAITING", page)

    def test_destination_success_unlocks_page_and_recomputes_combined(self):
        self.client.post("/analyze", data={"url": "https://example.com/e2e"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        before = get_scan_by_id(scan_id)["combined_assessment"]
        self.assertEqual(before["score"], 5)

        with patch(
            "app.resolve_redirect_chain",
            return_value={
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://example.com/e2e",
                "final_url": "https://example.com/e2e-final",
                "redirect_count": 1,
                "hops": [
                    {"url_text": "https://example.com/e2e", "http_status": 302},
                    {"url_text": "https://example.com/e2e-final", "http_status": 200},
                ],
            },
        ):
            detail = self.client.post(
                "/inspect-destination",
                data={"scan_id": scan_id},
                follow_redirects=True,
            ).get_data(as_text=True)

        self.assertIn("Completed", detail)
        self.assertIn("https://example.com/e2e-final", detail)
        self.assertIn("Inspect Page Content", detail)
        self.assertNotIn("Hidden Destination", detail)
        after = get_scan_by_id(scan_id)["combined_assessment"]
        self.assertIsNotNone(after.get("score"))
        # Coverage should rise once a resolved destination is stored.
        self.assertIn(after.get("coverage"), {"moderate", "strong"})
        self.assertEqual(after.get("label"), "Low Risk")

    def test_history_and_pdf_offline_after_inspection(self):
        self.client.post("/analyze", data={"url": "https://bit.ly/example"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        with patch(
            "app.resolve_redirect_chain",
            return_value={
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://bit.ly/example",
                "final_url": "https://example.com/resolved",
                "redirect_count": 1,
                "hops": [],
            },
        ):
            self.client.post("/inspect-destination", data={"scan_id": scan_id})

        with patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ), patch(
            "app.resolve_redirect_chain",
            side_effect=AssertionError("network"),
        ):
            detail = self.client.get(f"/scan/{scan_id}")
            report = self.client.get(f"/scan/{scan_id}/report")
        self.assertEqual(detail.status_code, 200)
        self.assertEqual(report.status_code, 200)
        text = _pdf_text(report.data)
        self.assertIn("Destination Analysis", text)
        self.assertIn("Overall PhishLens Assessment", text)


class TestStep31CombinedAssessment(unittest.TestCase):
    def test_max_not_sum_and_vt_zero_noop(self):
        result = build_combined_assessment(
            submitted_url_result={
                "score": 25,
                "classification": "Low Risk",
                "indicators": [],
                "has_shortener": False,
            },
            final_url_result={"score": 45, "classification": "Suspicious", "indicators": []},
            page_result={"score": 60, "classification": "Suspicious", "indicators": []},
            reputation_result={
                "status": "completed",
                "malicious": 0,
                "suspicious": 0,
            },
        )
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["label"], "Suspicious")

    def test_blocked_destination_adds_no_points(self):
        result = build_combined_assessment(
            submitted_url_result={
                "score": 75,
                "classification": "High Risk",
                "indicators": [],
                "has_shortener": False,
            },
            destination_status="blocked",
        )
        self.assertEqual(result["score"], 75)

    def test_credential_cross_layer_once(self):
        result = build_combined_assessment(
            submitted_url_result={
                "score": 25,
                "classification": "Low Risk",
                "indicators": [],
                "has_shortener": False,
            },
            final_url_result={"score": 45, "classification": "Suspicious", "indicators": []},
            page_result={
                "score": 60,
                "classification": "Suspicious",
                "indicators": [{"rule": "password_login_form"}],
            },
        )
        self.assertEqual(result["score"], 70)
        self.assertEqual(
            result["triggered_rules"].count("suspicious_final_with_credentials"),
            1,
        )


class TestStep31PageFixtures(unittest.TestCase):
    def test_empty_and_normal_pages(self):
        empty = analyze_page_html("", page_url="https://example.com/")
        empty_risk = calculate_page_risk(empty["indicators"])
        self.assertEqual(empty_risk["final_score"], 0)
        self.assertEqual(empty_risk["classification"], "Low Concern")

        normal = analyze_page_html(
            "<html><title>Hi</title><body><p>Hello</p></body></html>",
            page_url="https://example.com/",
        )
        normal_risk = calculate_page_risk(normal["indicators"])
        self.assertEqual(normal["page_title"], "Hi")
        self.assertEqual(normal_risk["final_score"], 0)

    def test_malformed_html_with_password_is_still_scored(self):
        analysis = analyze_page_html(
            "<html><form><input type=password name=p><bad",
            page_url="https://example.com/login",
        )
        risk = calculate_page_risk(analysis["indicators"])
        self.assertGreaterEqual(risk["final_score"], 20)
        rules = {item.get("rule") for item in analysis["indicators"]}
        self.assertTrue(rules & {"password_login_form", "credential_input_fields"})


class TestStep31EmailAndSecurity(unittest.TestCase):
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

    def test_email_body_secret_not_persisted(self):
        raw = (
            "From: alerts@example.com\n"
            "To: user@example.com\n"
            "Subject: Private\n\n"
            "SECRET_TOKEN_XYZ_DO_NOT_STORE\n"
        )
        response = self.client.post("/analyze-email", data={"raw_email": raw})
        self.assertEqual(response.status_code, 200)
        scan_id = get_scans(scan_type="email")[0]["id"]
        record = get_scan_by_id(scan_id)
        blob = str(record)
        self.assertNotIn("SECRET_TOKEN_XYZ_DO_NOT_STORE", blob)
        connection = get_db_connection()
        try:
            row = connection.execute(
                "SELECT * FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
            self.assertNotIn("SECRET_TOKEN_XYZ_DO_NOT_STORE", str(dict(row)))
        finally:
            connection.close()

    def test_script_in_url_escaped_in_results(self):
        page = self.client.post(
            "/analyze",
            data={"url": "https://example.com/<script>alert(1)</script>"},
        ).get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)

    def test_dashboard_and_history_offline(self):
        self.client.post("/analyze", data={"url": "https://example.com/dash-e2e"})
        with patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ), patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ):
            dash = self.client.get("/dashboard")
            hist = self.client.get("/history")
        self.assertEqual(dash.status_code, 200)
        self.assertEqual(hist.status_code, 200)
        summary = get_dashboard_summary()
        self.assertGreaterEqual(summary["total"], 1)

    def test_malformed_url_form_shows_error(self):
        page = self.client.post("/analyze", data={"url": "not a url"}).get_data(
            as_text=True
        )
        self.assertIn("error", page.lower())
        self.assertEqual(len(get_scans(scan_type="url")), 0)


class TestStep31MigrationIdempotent(unittest.TestCase):
    def test_init_db_twice_preserves_scan(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        db_path = Path(temp.name) / "scans.db"
        with patch("database.database.DB_PATH", db_path):
            app.config["TESTING"] = True
            client = make_client()
            init_db()
            client.post("/analyze", data={"url": "https://example.com/migrate"})
            init_db()
            init_db()
            scans = get_scans(scan_type="url")
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0]["normalized_url"], "https://example.com/migrate")


if __name__ == "__main__":
    unittest.main()
