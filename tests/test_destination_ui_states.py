"""Regression tests for state-aware Destination / Page Content UI."""

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
from analyzers.url_analyzer import analyze_url
from database.database import (
    get_scans,
    init_db,
    save_page_inspection,
    save_redirect_inspection,
    update_scan_coverage,
)
from services.risk_engine import calculate_risk
from tests.support import make_client


class TestDestinationPageUiStates(unittest.TestCase):
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

    def test_a_shortener_before_destination_inspection(self):
        with patch("services.safe_redirect_resolver.http_exchange") as exchange, patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            page = self.client.post(
                "/analyze",
                data={"url": "https://linkr.it/gKin2"},
            ).get_data(as_text=True)
            exchange.assert_not_called()

        self.assertEqual(page.count("<h2>Destination Analysis</h2>"), 1)
        self.assertEqual(page.count("Destination Analysis"), 1)
        self.assertIn("Hidden Destination", page)
        self.assertEqual(page.count("<h2>Hidden Destination</h2>"), 0)
        self.assertEqual(page.count("<h2>Inspect Final Destination</h2>"), 0)
        self.assertEqual(page.count("<h2>Destination Inspection</h2>"), 0)
        self.assertEqual(page.count("Inspect Final Destination"), 1)
        self.assertIn("Final destination: Unknown", page)
        self.assertNotIn("Destination Inspection", page)
        self.assertNotIn("NOT PERFORMED", page.upper())
        self.assertEqual(page.count("<h2>Page Content Analysis</h2>"), 1)
        self.assertIn("Status: <strong>WAITING</strong>", page)
        self.assertNotIn("Inspect Page Content", page)
        details_idx = page.find("View Detailed Analysis")
        assess_idx = page.find("PhishLens Assessment")
        dest_idx = page.find("<h2>Destination Analysis</h2>")
        self.assertLess(assess_idx, details_idx)
        self.assertLess(details_idx, dest_idx)

    def test_b_direct_url_before_destination_inspection(self):
        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            page = self.client.post(
                "/analyze",
                data={"url": "https://example.com"},
            ).get_data(as_text=True)
            exchange.assert_not_called()

        self.assertIn("Destination Analysis", page)
        self.assertIn("Inspect Final Destination", page)
        self.assertIn("NOT INSPECTED", page.upper())
        self.assertNotIn("Hidden Destination", page)
        self.assertIn("WAITING", page)
        self.assertNotIn("Inspect Page Content", page)

    def test_c_successful_destination_inspection(self):
        self.client.post("/analyze", data={"url": "https://example.com/state-c"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        with patch(
            "app.resolve_redirect_chain",
            return_value={
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://example.com/state-c",
                "final_url": "https://example.com/final-c",
                "redirect_count": 1,
                "hops": [
                    {"url_text": "https://example.com/state-c", "http_status": 302},
                    {"url_text": "https://example.com/final-c", "http_status": 200},
                ],
            },
        ):
            detail = self.client.post(
                "/inspect-destination",
                data={"scan_id": scan_id},
                follow_redirects=True,
            ).get_data(as_text=True)

        self.assertEqual(detail.count("Destination Analysis"), 1)
        self.assertIn("Completed", detail)
        self.assertIn("https://example.com/final-c", detail)
        self.assertIn("Final Destination Risk", detail)
        self.assertIn("AVAILABLE", detail)
        self.assertIn("Inspect Page Content", detail)
        self.assertNotIn("Hidden Destination", detail)
        self.assertNotIn("WAITING", detail)

    def test_d_blocked_destination(self):
        self.client.post("/analyze", data={"url": "https://example.com/state-d"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        save_redirect_inspection(
            scan_id,
            {
                "status": "blocked",
                "reason": "The destination resolves to a non-public network address.",
                "submitted_url": "https://example.com/state-d",
                "final_url": None,
                "redirect_count": 0,
                "redirect_chain": [],
            },
        )
        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
            exchange.assert_not_called()

        self.assertIn("Destination Analysis", page)
        self.assertIn("BLOCKED", page)
        self.assertIn("non-public network address", page)
        self.assertIn(
            "A blocked destination is a safety control for PhishLens",
            page,
        )
        self.assertNotIn("Inspect Page Content", page)
        self.assertIn("UNAVAILABLE", page)
        self.assertIn(
            "Page content inspection cannot continue because destination inspection was blocked",
            page,
        )
        self.assertNotIn("WAITING", page)

    def test_e_failed_destination(self):
        self.client.post("/analyze", data={"url": "https://example.com/state-e"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        save_redirect_inspection(
            scan_id,
            {
                "status": "failed",
                "reason": "The destination could not be reached within the allowed time.",
                "submitted_url": "https://example.com/state-e",
                "final_url": None,
                "redirect_count": 0,
                "redirect_chain": [],
            },
        )
        page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
        self.assertIn("Destination Analysis", page)
        self.assertIn("FAILED", page)
        self.assertIn("could not be reached within the allowed time", page)
        self.assertNotIn("Traceback", page)
        self.assertNotIn("Exception", page)
        self.assertNotIn("Inspect Page Content", page)
        self.assertIn("UNAVAILABLE", page)

    def test_f_completed_page_inspection(self):
        self.client.post("/analyze", data={"url": "https://example.com/state-f"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        save_redirect_inspection(
            scan_id,
            {
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://example.com/state-f",
                "final_url": "https://example.com/state-f",
                "redirect_count": 0,
                "redirect_chain": [
                    {"url": "https://example.com/state-f", "http_status": 200},
                ],
            },
            final_risk={
                "final_score": 5,
                "classification": "Low Risk",
                "recommendation": "ok",
            },
            final_indicators=[],
        )
        update_scan_coverage(scan_id, "comprehensive", "resolved")
        save_page_inspection(
            scan_id,
            {
                "status": "completed",
                "reason": None,
                "page_url": "https://example.com/state-f",
                "truncated": False,
            },
            analysis={
                "page_title": "Example",
                "page_url": "https://example.com/state-f",
                "limited_static_content": False,
                "indicators": [],
            },
            page_risk={
                "final_score": 10,
                "classification": "Low Concern",
                "indicators": [],
                "correlations": [],
            },
        )
        with patch("services.safe_redirect_resolver.http_exchange") as exchange, patch(
            "services.safe_redirect_resolver.fetch_safe_page",
            side_effect=AssertionError("network"),
        ):
            page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
            exchange.assert_not_called()

        self.assertEqual(page.count("Page Content Analysis"), 1)
        self.assertIn("Page Risk Score", page)
        self.assertIn("Low Concern", page)
        self.assertNotIn("Inspect Page Content", page)
        self.assertNotIn("WAITING", page)
        self.assertNotIn("AVAILABLE", page)

    def test_g_reputation_actions_remain_explicit(self):
        with patch(
            "app.get_reputation_availability",
            return_value={
                "provider": "VirusTotal",
                "status": "available",
                "message": "Ready",
            },
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            page = self.client.post(
                "/analyze",
                data={"url": "https://example.com/state-g"},
            ).get_data(as_text=True)

        self.assertIn("Reputation Check", page)
        self.assertIn("Submitted URL Reputation", page)
        self.assertIn("Check Reputation", page)
        self.assertNotIn('value="final_url"', page)

        scan_id = get_scans(scan_type="url")[0]["id"]
        save_redirect_inspection(
            scan_id,
            {
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://example.com/state-g",
                "final_url": "https://example.com/state-g-final",
                "redirect_count": 0,
                "redirect_chain": [],
            },
            final_risk={
                "final_score": 5,
                "classification": "Low Risk",
                "recommendation": "ok",
            },
        )
        update_scan_coverage(scan_id, "comprehensive", "resolved")
        with patch(
            "app.get_reputation_availability",
            return_value={
                "provider": "VirusTotal",
                "status": "available",
                "message": "Ready",
            },
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            detail = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)

        self.assertIn('value="submitted_url"', detail)
        self.assertIn('value="final_url"', detail)
        self.assertIn("Final Destination Reputation", detail)

    def test_h_saved_scan_render_performs_no_network(self):
        self.client.post("/analyze", data={"url": "https://bit.ly/example"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        with patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ), patch(
            "app.resolve_redirect_chain",
            side_effect=AssertionError("network"),
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            detail = self.client.get(f"/scan/{scan_id}")
        self.assertEqual(detail.status_code, 200)
        html = detail.get_data(as_text=True)
        self.assertIn("Destination Analysis", html)
        self.assertIn("Hidden Destination", html)
        self.assertIn("WAITING", html)

    def test_i_scoring_regressions_unchanged(self):
        cases = [
            ("https://example.com/login", 10, "Low Risk"),
            ("https://g00gle.com/login", 45, "Suspicious"),
            ("https://bit.ly/example", 25, "Low Risk"),
            ("http://192.168.1.10:8080/account/verify/password", 75, "High Risk"),
        ]
        for url, score, label in cases:
            analysis = analyze_url(url)
            risk = calculate_risk(analysis["indicators"])
            self.assertEqual(risk["final_score"], score, url)
            self.assertEqual(risk["classification"], label, url)


if __name__ == "__main__":
    unittest.main()
