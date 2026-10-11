import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader

from app import app
from tests.support import make_client
from database.database import (
    get_dashboard_summary,
    get_db_connection,
    get_scan_by_id,
    get_scans,
    init_db,
    save_combined_assessment,
)
from services.combined_assessment import build_combined_assessment
from services.report_generator import generate_url_report
from services.risk_engine import calculate_risk
from analyzers.url_analyzer import analyze_url


def _submitted(score, classification, indicators=None, shortener=False):
    return {
        "score": score,
        "classification": classification,
        "indicators": indicators or [],
        "has_shortener": shortener,
    }


def _final(score, classification, indicators=None):
    return {
        "score": score,
        "classification": classification,
        "indicators": indicators or [],
    }


def _page(score, classification, indicators=None):
    return {
        "score": score,
        "classification": classification,
        "indicators": indicators or [],
    }


def _reputation(status="completed", malicious=0, suspicious=0):
    return {
        "provider": "VirusTotal",
        "status": status,
        "malicious": malicious,
        "suspicious": suspicious,
        "malicious_count": malicious,
        "suspicious_count": suspicious,
        "harmless": 60,
        "undetected": 20,
        "total_engines": 80,
    }


class TestCombinedAssessmentEngine(unittest.TestCase):
    def test_case_a_submitted_only(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(5, "Low Risk")
        )
        self.assertEqual(result["score"], 5)
        self.assertEqual(result["label"], "Low Risk")
        self.assertEqual(result["coverage_label"], "LIMITED")

    def test_case_b_max_not_sum(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(25, "Low Risk"),
            final_url_result=_final(45, "Suspicious"),
        )
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["label"], "Suspicious")
        self.assertNotEqual(result["score"], 70)

    def test_case_c_page_strongest_no_correlation(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(25, "Low Risk"),
            final_url_result=_final(45, "Suspicious"),
            page_result=_page(60, "Suspicious"),
        )
        self.assertEqual(result["score"], 60)
        self.assertEqual(result["label"], "Suspicious")

    def test_case_d_credential_cross_layer(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(25, "Low Risk"),
            final_url_result=_final(45, "Suspicious"),
            page_result=_page(
                60,
                "Suspicious",
                indicators=[{"rule": "password_login_form"}],
            ),
        )
        self.assertEqual(result["score"], 70)
        self.assertEqual(result["label"], "High Risk")
        self.assertIn(
            "suspicious_final_with_credentials",
            result["triggered_rules"],
        )

    def test_case_e_zero_vt_no_change(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(45, "Suspicious"),
            reputation_result=_reputation(malicious=0, suspicious=0),
        )
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["label"], "Suspicious")

    def test_case_f_vt_two_malicious(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(45, "Suspicious"),
            reputation_result=_reputation(malicious=2),
        )
        self.assertEqual(result["score"], 55)
        self.assertEqual(result["label"], "Suspicious")

    def test_case_g_vt_four_malicious(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(45, "Suspicious"),
            reputation_result=_reputation(malicious=4),
        )
        self.assertEqual(result["score"], 65)
        self.assertEqual(result["label"], "High Risk")

    def test_case_h_blocked_destination_no_points(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(75, "High Risk"),
            destination_status="blocked",
        )
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["label"], "High Risk")
        self.assertTrue(
            any("could not safely be completed" in reason for reason in result["reasons"])
        )

    def test_case_i_coverage_strong_risk_unchanged(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(25, "Low Risk"),
            final_url_result=_final(25, "Low Risk"),
            page_result=_page(10, "Low Concern"),
            reputation_result=_reputation(malicious=0, suspicious=0),
        )
        self.assertEqual(result["score"], 25)
        self.assertEqual(result["label"], "Low Risk")
        self.assertEqual(result["coverage_label"], "STRONG")

    def test_shortener_with_risky_final_adds_ten(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(25, "Low Risk", shortener=True),
            final_url_result=_final(45, "Suspicious"),
        )
        self.assertEqual(result["score"], 55)
        self.assertIn("shortener_with_risky_final", result["triggered_rules"])

    def test_payment_cross_layer(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(25, "Low Risk"),
            final_url_result=_final(45, "Suspicious"),
            page_result=_page(
                40,
                "Suspicious",
                indicators=[{"rule": "payment_information_requested"}],
            ),
        )
        self.assertEqual(result["score"], 55)
        self.assertIn("suspicious_final_with_payment", result["triggered_rules"])

    def test_vt_suspicious_only(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(45, "Suspicious"),
            reputation_result=_reputation(malicious=0, suspicious=3),
        )
        self.assertEqual(result["score"], 50)

    def test_unknown_vt_does_not_change_score(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(45, "Suspicious"),
            reputation_result=_reputation(status="unknown"),
        )
        self.assertEqual(result["score"], 45)
        self.assertEqual(result["label"], "Suspicious")

    def test_zero_vt_does_not_downgrade(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(75, "High Risk"),
            reputation_result=_reputation(malicious=0, suspicious=0),
        )
        self.assertEqual(result["score"], 75)
        self.assertEqual(result["label"], "High Risk")

    def test_breakdown_structure(self):
        result = build_combined_assessment(
            submitted_url_result=_submitted(25, "Low Risk"),
            final_url_result=_final(45, "Suspicious"),
            page_result=_page(
                60,
                "Suspicious",
                indicators=[{"rule": "password_login_form"}],
            ),
            reputation_result=_reputation(malicious=2),
        )
        breakdown = result["breakdown"]
        self.assertEqual(breakdown["strongest_layer_score"], 60)
        self.assertEqual(breakdown["virustotal_adjustment"], 10)
        self.assertEqual(len(breakdown["cross_layer_adjustments"]), 1)
        self.assertEqual(breakdown["final_score"], 80)

    def test_engine_has_no_network_imports(self):
        source = Path("services/combined_assessment.py").read_text(encoding="utf-8")
        self.assertNotIn("urllib", source)
        self.assertNotIn("requests", source)
        self.assertNotIn("socket", source)


class TestCombinedAssessmentIntegration(unittest.TestCase):
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

    def test_analyze_shows_combined_assessment(self):
        response = self.client.post(
            "/analyze",
            data={"url": "https://example.com/login"},
        )
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("PhishLens Assessment", html)
        self.assertIn("LOW RISK", html)
        self.assertIn("Evidence Coverage", html)
        self.assertIn("LIMITED", html)
        self.assertIn("assessment-top-score", html)
        self.assertRegex(html, r'assessment-top-score">\s*<span>10</span>\s*/ 100')
        self.assertIn("URL Structure Analysis", html)
        self.assertIn("Complete", html)
        self.assertIn("Combined Assessment Breakdown", html)
        self.assertIn("Submitted URL Score Breakdown", html)
        self.assertNotIn("Analysis Coverage", html)
        # Hidden Destination / Inspect belong inside detailed analysis only.
        hidden_idx = html.find("Hidden Destination")
        details_idx = html.find("View Detailed Analysis")
        self.assertEqual(hidden_idx, -1)
        self.assertGreater(details_idx, -1)

    def test_score_regression_unchanged(self):
        cases = [
            ("https://example.com/login", 10, "Low Risk"),
            ("https://g00gle.com/login", 45, "Suspicious"),
            ("https://g00gle.com", 25, "Low Risk"),
            ("https://bit.ly/example", 25, "Low Risk"),
            ("https://bit.ly/account-verify", 45, "Suspicious"),
            ("https://example.com@evil.example/login", 40, "Suspicious"),
            ("http://192.168.1.10/account/verify", 60, "Suspicious"),
            ("http://192.168.1.10:8080/account/verify/password", 75, "High Risk"),
        ]
        for url, score, label in cases:
            analysis = analyze_url(url)
            risk = calculate_risk(analysis["indicators"])
            self.assertEqual(risk["final_score"], score, url)
            self.assertEqual(risk["classification"], label, url)

    def test_history_shows_stored_assessment_without_network(self):
        response = self.client.post(
            "/analyze",
            data={"url": "https://example.com/history-combined"},
        )
        self.assertEqual(response.status_code, 200)
        scan_id = get_scans(scan_type="url")[0]["id"]
        save_combined_assessment(
            scan_id,
            {
                "assessment": "high_risk",
                "label": "High Risk",
                "coverage": "strong",
                "coverage_label": "STRONG",
                "score": 80,
                "summary": "Stored summary.",
                "recommendation": "Avoid entering credentials.",
                "reasons": ["Stored reason about page content."],
                "breakdown": {
                    "strongest_layer": "page_content",
                    "strongest_layer_label": "Static Page Content",
                    "strongest_layer_score": 60,
                    "cross_layer_adjustments": [],
                    "virustotal_adjustment": 20,
                    "final_score": 80,
                },
            },
        )
        with patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ), patch(
            "services.safe_redirect_resolver.resolve_redirect_chain",
            side_effect=AssertionError("network"),
        ):
            detail = self.client.get(f"/scan/{scan_id}")
        html = detail.get_data(as_text=True)
        self.assertIn("HIGH RISK", html)
        self.assertIn("Stored reason about page content.", html)
        self.assertIn("STRONG", html)
        self.assertIn("80", html)

    def test_pdf_includes_combined_assessment_without_network(self):
        self.client.post("/analyze", data={"url": "https://example.com/pdf-combined"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        save_combined_assessment(
            scan_id,
            {
                "assessment": "suspicious",
                "label": "Suspicious",
                "coverage": "moderate",
                "coverage_label": "MODERATE",
                "score": 45,
                "summary": "Caution warranted.",
                "recommendation": "Use caution.",
                "reasons": ["Final destination shows suspicious characteristics."],
                "breakdown": {
                    "strongest_layer": "final_destination",
                    "strongest_layer_label": "Final Destination",
                    "strongest_layer_score": 45,
                    "cross_layer_adjustments": [],
                    "virustotal_adjustment": 0,
                    "final_score": 45,
                },
            },
        )
        record = get_scan_by_id(scan_id)
        with patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            pdf_bytes = generate_url_report(record)
        text = _pdf_text(pdf_bytes)
        self.assertIn("Overall PhishLens Assessment", text)
        self.assertIn("Suspicious", text)
        self.assertIn("MODERATE", text)
        self.assertIn("Why this assessment?", text)
        self.assertIn("Use caution", text)
        self.assertIn("Combined Assessment Breakdown", text)
        self.assertIn("45/100", text)

    def test_old_database_migration_is_idempotent(self):
        connection = get_db_connection()
        try:
            with connection:
                connection.execute("DROP TABLE IF EXISTS combined_assessment_reasons")
                connection.execute("DROP TABLE IF EXISTS combined_assessments")
                connection.execute(
                    """
                    INSERT INTO scans (
                        scan_type, target, normalized_url, risk_score,
                        classification, recommendation, created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        "url",
                        "legacy.example",
                        "https://legacy.example",
                        10,
                        "Low Risk",
                        "ok",
                        "2026-01-01T00:00:00+00:00",
                    ),
                )
        finally:
            connection.close()

        init_db()
        init_db()
        detail = self.client.get("/scan/1")
        self.assertEqual(detail.status_code, 200)
        html = detail.get_data(as_text=True)
        self.assertIn("PhishLens Assessment", html)
        self.assertIn("LOW RISK", html)

    def test_dashboard_uses_combined_label_when_present(self):
        self.client.post("/analyze", data={"url": "https://example.com/dash"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        save_combined_assessment(
            scan_id,
            {
                "assessment": "high_risk",
                "label": "High Risk",
                "coverage": "strong",
                "coverage_label": "STRONG",
                "score": 80,
                "summary": "Escalated.",
                "recommendation": "Avoid.",
                "reasons": ["Page high concern"],
            },
        )
        summary = get_dashboard_summary()
        self.assertEqual(summary["high_risk"], 1)
        self.assertEqual(summary["low_risk"], 0)
        self.assertEqual(summary["average_risk"], 80)
        page = self.client.get("/dashboard")
        html = page.get_data(as_text=True)
        self.assertIn("Final Assessment Distribution", html)


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
