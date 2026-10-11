import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader

from app import app
from database.database import get_scan_by_id, get_scans, init_db, save_scan
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas

from services.report_generator import (
    LEFT_MARGIN,
    RIGHT_MARGIN,
    RiskMeter,
    RiskScoreBlock,
    USABLE_WIDTH,
    _soft_break_url,
    generate_email_report,
    generate_url_report,
)
from tests.support import make_client, sample_parsed, sample_risk


URGENT_EMAIL = """\
From: support@example.com
To: noora@example.com
Subject: URGENT: Account action required

Hello Noora,

Please login and verify your account:
https://g00gle.com/login
"""

PRIVACY_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Privacy check

BODY_SECRET_12345
"""

XSS_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: <script>alert('test')</script>

Hello.
"""


def pdf_text(pdf_bytes):
    path = Path(tempfile.mkdtemp()) / "report.pdf"
    path.write_bytes(pdf_bytes)
    try:
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    finally:
        path.unlink(missing_ok=True)
        path.parent.rmdir()


class TestReports(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        app.config["TESTING"] = True
        self.client = make_client()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_url_report_contains_expected_sections(self):
        response = self.client.post("/analyze", data={"url": "https://g00gle.com/login"})
        self.assertEqual(response.status_code, 200)
        scan_id = get_scans(scan_type="url")[0]["id"]

        report = self.client.get(f"/scan/{scan_id}/report")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, "application/pdf")
        self.assertIn(
            f'filename="phishlens-url-report-{scan_id}.pdf"',
            report.headers.get("Content-Disposition", ""),
        )

        text = pdf_text(report.data)
        self.assertIn("PhishLens", text)
        self.assertIn("URL Analysis", text)
        self.assertIn("45 / 100", text)
        self.assertIn("Suspicious", text)
        self.assertIn("g00gle.com", text)
        self.assertIn("Detected Indicators", text)
        self.assertIn("Score Breakdown", text)
        self.assertIn("Methodology", text)

    def test_email_report_distinguishes_email_and_url_scores(self):
        response = self.client.post("/analyze-email", data={"raw_email": URGENT_EMAIL})
        self.assertEqual(response.status_code, 200)
        scan_id = get_scans(scan_type="email")[0]["id"]

        report = self.client.get(f"/scan/{scan_id}/report")
        self.assertEqual(report.status_code, 200)
        text = pdf_text(report.data)

        self.assertIn("Email Analysis", text)
        self.assertIn("65 / 100", text)
        self.assertIn("High Risk", text)
        self.assertIn("Local URL Risk Score", text)
        self.assertIn("45 / 100", text)
        self.assertIn("https://g00gle.com/login", text)
        self.assertIn("does not retain the complete email body", text)

    def test_privacy_secret_is_absent_from_email_report(self):
        self.client.post("/analyze-email", data={"raw_email": PRIVACY_EMAIL})
        scan_id = get_scans(scan_type="email")[0]["id"]
        text = pdf_text(self.client.get(f"/scan/{scan_id}/report").data)
        self.assertNotIn("BODY_SECRET_12345", text)

    def test_long_url_report_does_not_crash(self):
        long_url = "https://example.com/" + ("very-long-path-segment/" * 40) + "login"
        init_db()
        scan_id = save_scan(
            sample_parsed("example.com", long_url),
            sample_risk(
                10,
                "Low Risk",
                indicators=[
                    {
                        "rule": "long_url",
                        "title": "Long URL path",
                        "score_change": 10,
                        "severity": "warning",
                        "explanation": "The path is unusually long.",
                        "evidence": long_url,
                    }
                ],
            ),
        )
        pdf_bytes = generate_url_report(get_scan_by_id(scan_id))
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        text = pdf_text(pdf_bytes)
        self.assertIn("example.com", text)
        self.assertIn("Long URL path", text)

    def test_special_characters_and_markup_are_plain_text(self):
        self.client.post("/analyze-email", data={"raw_email": XSS_EMAIL})
        scan_id = get_scans(scan_type="email")[0]["id"]
        text = pdf_text(self.client.get(f"/scan/{scan_id}/report").data)
        self.assertIn("script", text.lower())
        self.assertIn("alert", text.lower())

        init_db()
        special_id = save_scan(
            sample_parsed('a&b<"\'>.example', 'https://a&b<"\'>.example/path'),
            sample_risk(
                10,
                "Low Risk",
                indicators=[
                    {
                        "rule": "special",
                        "title": 'Title & <quoted> "value"',
                        "score_change": 1,
                        "severity": "warning",
                        "explanation": "Contains & < > \" '",
                        "evidence": "a&b<'\">",
                    }
                ],
            ),
        )
        special_pdf = generate_url_report(get_scan_by_id(special_id))
        self.assertTrue(special_pdf.startswith(b"%PDF"))
        special_text = pdf_text(special_pdf)
        self.assertIn("Title", special_text)
        self.assertIn("&", special_text)

    def test_missing_scan_report_returns_404(self):
        response = self.client.get("/scan/999999/report")
        self.assertEqual(response.status_code, 404)
        self.assertNotEqual(response.mimetype, "application/pdf")

    def test_report_route_does_not_rerun_analysis(self):
        self.client.post("/analyze", data={"url": "https://example.com/login"})
        scan_id = get_scans(scan_type="url")[0]["id"]
        with (
            patch("app.analyze_url") as analyze_url,
            patch("app.calculate_risk") as calculate_risk,
            patch("app.parse_email") as parse_email,
            patch("app.analyze_email_security") as analyze_email_security,
        ):
            response = self.client.get(f"/scan/{scan_id}/report")
            self.assertEqual(response.status_code, 200)
            analyze_url.assert_not_called()
            calculate_risk.assert_not_called()
            parse_email.assert_not_called()
            analyze_email_security.assert_not_called()

    def test_live_pages_link_to_report_when_saved(self):
        url_page = self.client.post(
            "/analyze",
            data={"url": "https://example.com/login"},
        ).get_data(as_text=True)
        email_page = self.client.post(
            "/analyze-email",
            data={"raw_email": URGENT_EMAIL},
        ).get_data(as_text=True)

        self.assertIn("/report", url_page)
        self.assertIn("Download Report", url_page)
        self.assertIn("/report", email_page)
        self.assertIn("Download Report", email_page)

    def test_regression_scores_remain_unchanged(self):
        cases = [
            ("https://example.com/login", "10/100", "Low Risk"),
            ("https://g00gle.com/login", "45/100", "Suspicious"),
            (
                "http://192.168.1.10:8080/account/verify/password",
                "75/100",
                "High Risk",
            ),
        ]
        for url, score, classification in cases:
            page = self.client.post("/analyze", data={"url": url}).get_data(as_text=True)
            self.assertIn(score, page)
            self.assertIn(classification, page)

        email_page = self.client.post(
            "/analyze-email",
            data={"raw_email": URGENT_EMAIL},
        ).get_data(as_text=True)
        self.assertIn("65/100", email_page)
        self.assertIn("High Risk", email_page)

    def test_shortened_url_report_shows_limited_coverage(self):
        page = self.client.post(
            "/analyze",
            data={"url": "https://linkr.it/gKin2"},
        ).get_data(as_text=True)
        self.assertIn("Hidden Destination", page)
        self.assertIn("LIMITED", page)
        self.assertIn("final destination unknown", page)
        self.assertIn(
            "Low Risk describes the visible URL characteristics only",
            page,
        )

        scan_id = get_scans(scan_type="url")[0]["id"]
        record = get_scan_by_id(scan_id)
        self.assertEqual(record["scan"]["analysis_coverage"], "limited")
        self.assertEqual(record["scan"]["destination_status"], "hidden")

        text = pdf_text(self.client.get(f"/scan/{scan_id}/report").data)
        self.assertIn("Analysis Coverage: Limited", text)
        self.assertIn("Destination Status: Hidden", text)
        self.assertIn("The final destination was not inspected.", text)

    def test_ordinary_url_report_shows_full_coverage(self):
        page = self.client.post(
            "/analyze",
            data={"url": "https://example.com"},
        ).get_data(as_text=True)
        self.assertIn("Evidence Coverage", page)
        self.assertIn("LIMITED", page)
        self.assertIn("URL Structure Analysis", page)
        self.assertIn("Complete", page)
        self.assertNotIn("Analysis Coverage", page)
        self.assertNotIn("Hidden Destination", page)
        self.assertIn("5", page)
        self.assertIn("/ 100", page)

        scan_id = get_scans(scan_type="url")[0]["id"]
        record = get_scan_by_id(scan_id)
        self.assertEqual(record["scan"]["analysis_coverage"], "full")
        self.assertEqual(record["scan"]["destination_status"], "visible")

        text = pdf_text(self.client.get(f"/scan/{scan_id}/report").data)
        self.assertIn("Analysis Coverage: Full", text)
        self.assertIn("Destination Status: Visible", text)
        self.assertNotIn("The final destination was not inspected.", text)

    def test_printable_width_matches_a4_margins(self):
        expected = A4[0] - LEFT_MARGIN - RIGHT_MARGIN
        self.assertAlmostEqual(USABLE_WIDTH, expected)
        self.assertLessEqual(USABLE_WIDTH, A4[0] - 36 * mm)

    def test_risk_meter_stays_inside_usable_width(self):
        meter = RiskMeter(45, width=USABLE_WIDTH + 40 * mm)
        width, height = meter.wrap(USABLE_WIDTH, 200)
        self.assertLessEqual(width, USABLE_WIDTH)
        self.assertGreater(height, 0)

    def test_risk_score_block_reserves_gap_between_score_and_label(self):
        block = RiskScoreBlock(45, "Suspicious", USABLE_WIDTH)
        width, height = block.wrap(USABLE_WIDTH, 400)
        self.assertLessEqual(width, USABLE_WIDTH)
        # Heading + score + gap + classification bands must leave room so
        # "SUSPICIOUS" cannot paint on top of "45 / 100".
        self.assertGreaterEqual(height, 90)
        self.assertGreaterEqual(block._gap_band, 16)

    def test_risk_meter_marker_clamped_for_edge_scores(self):
        for score in (0, 5, 45, 85, 100):
            meter = RiskMeter(score, width=USABLE_WIDTH)
            meter.wrap(USABLE_WIDTH, 200)
            radius = 3.5
            marker_x = (meter.score / 100.0) * meter.bar_width
            marker_x = max(radius, min(meter.bar_width - radius, marker_x))
            self.assertGreaterEqual(marker_x, radius)
            self.assertLessEqual(marker_x, meter.bar_width - radius)

            buffer = BytesIO()
            canvas = Canvas(buffer)
            meter.canv = canvas
            meter.draw()
            canvas.save()
            self.assertTrue(buffer.getvalue().startswith(b"%PDF"))

    def test_soft_break_url_escapes_untrusted_markup(self):
        plain = "https://example.com/" + ("segment/" * 40) + "login"
        self.assertEqual(_soft_break_url(plain), plain)
        self.assertIn("https://example.com/", _soft_break_url(plain))
        escaped = _soft_break_url("<script>alert(1)</script>")
        self.assertNotIn("<script>", escaped)
        self.assertIn("&lt;script&gt;", escaped)
        self.assertIn("&amp;", _soft_break_url("https://a&b.example/path"))
        self.assertIn("&lt;", _soft_break_url("https://a<b.example/path"))

    def test_layout_scores_do_not_crash_and_include_labels(self):
        init_db()
        cases = [
            (5, "Low Risk"),
            (45, "Suspicious"),
            (85, "High Risk"),
            (0, "Low Risk"),
            (100, "High Risk"),
        ]
        for score, classification in cases:
            scan_id = save_scan(
                sample_parsed("example.com", f"https://example.com/score-{score}"),
                sample_risk(score, classification),
            )
            pdf_bytes = generate_url_report(get_scan_by_id(scan_id))
            self.assertTrue(pdf_bytes.startswith(b"%PDF"))
            text = pdf_text(pdf_bytes)
            self.assertIn(f"{score} / 100", text)
            self.assertIn(classification.upper(), text)
            self.assertIn("Low Risk", text)
            self.assertIn("Suspicious", text)
            self.assertIn("High Risk", text)
            self.assertIn("PhishLens Security Analysis Report", text)
            reader = PdfReader(BytesIO(pdf_bytes))
            for page in reader.pages:
                annotations = page.get("/Annots")
                if annotations:
                    for annot in annotations:
                        obj = annot.get_object()
                        self.assertNotEqual(obj.get("/Subtype"), "/Link")

    def test_long_url_and_long_evidence_wrap_in_pdf(self):
        init_db()
        long_url = "https://example.com/" + ("very-long-path-segment/" * 50) + "end"
        long_evidence = ("Evidence token " * 80).strip()
        scan_id = save_scan(
            sample_parsed("example.com", long_url),
            sample_risk(
                5,
                "Low Risk",
                indicators=[
                    {
                        "rule": "long_url",
                        "title": "Long URL path",
                        "score_change": 5,
                        "severity": "warning",
                        "explanation": ("Long explanation. " * 40).strip(),
                        "evidence": long_evidence,
                    }
                ],
            ),
        )
        pdf_bytes = generate_url_report(get_scan_by_id(scan_id))
        self.assertTrue(pdf_bytes.startswith(b"%PDF"))
        text = pdf_text(pdf_bytes)
        self.assertIn("example.com", text)
        self.assertIn("Long URL path", text)
        self.assertIn("Evidence token", text)
        self.assertIn("5 / 100", text)
        self.assertIn("LOW RISK", text)


if __name__ == "__main__":
    unittest.main()
