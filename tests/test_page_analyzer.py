import ipaddress
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from pypdf import PdfReader

from app import app
from database.database import get_scan_by_id, get_scans, init_db, save_redirect_inspection
from services.page_analyzer import analyze_page_html
from services.page_risk_engine import calculate_page_risk
from services.safe_redirect_resolver import fetch_safe_page
from services import safe_redirect_resolver as resolver
from tests.support import make_client


def pdf_text(pdf_bytes):
    path = Path(tempfile.mkdtemp()) / "report.pdf"
    path.write_bytes(pdf_bytes)
    try:
        reader = PdfReader(str(path))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    finally:
        path.unlink(missing_ok=True)
        path.parent.rmdir()


def indicators_by_rule(analysis):
    return {item["rule"]: item for item in analysis["indicators"]}


class FakePageExchange:
    def __init__(self, responses):
        self.responses = dict(responses)
        self.calls = []

    def __call__(self, url, pinned_ip, max_body_bytes=2048, include_body=False):
        self.calls.append(
            {
                "url": url,
                "pinned_ip": pinned_ip,
                "max_body_bytes": max_body_bytes,
                "include_body": include_body,
            }
        )
        if url not in self.responses:
            raise AssertionError(f"Unexpected page request for {url}")
        value = self.responses[url]
        if isinstance(value, Exception):
            raise value
        payload = dict(value)
        payload.setdefault("body", b"")
        payload.setdefault("truncated", False)
        payload.setdefault("url", url)
        if not include_body:
            payload["body"] = b""
        return payload


class TestPageAnalyzer(unittest.TestCase):
    def test_login_page_detects_password_and_credentials(self):
        html = """
        <html><head><title>Account Login</title></head>
        <body>
        <form>
        <input type="email" name="email">
        <input type="password" name="password">
        </form>
        </body></html>
        """
        analysis = analyze_page_html(html, "https://example.com/login")
        rules = indicators_by_rule(analysis)
        self.assertIn("password_login_form", rules)
        self.assertIn("credential_input_fields", rules)

    def test_payment_page_triggers_once(self):
        html = """
        <form>
        <label>Card Number</label>
        <input name="card_number">
        <label>Expiry</label>
        <input name="expiry">
        <label>CVV</label>
        <input name="cvv">
        </form>
        """
        analysis = analyze_page_html(html, "https://shop.example/pay")
        rules = indicators_by_rule(analysis)
        self.assertIn("payment_information_requested", rules)
        self.assertEqual(
            sum(1 for item in analysis["indicators"] if item["rule"] == "payment_information_requested"),
            1,
        )

    def test_traffic_fine_page_and_correlations(self):
        html = """
        <html>
        <head><title>Final Notice - Unpaid Traffic Fine</title></head>
        <body>
        <h1>Unpaid Traffic Penalty</h1>
        <p>Pay your fine immediately to avoid additional penalties.</p>
        <form>
        <input name="card_number">
        <input name="expiry">
        <input name="cvv">
        </form>
        </body></html>
        """
        analysis = analyze_page_html(html, "https://penalty.example/pay")
        risk = calculate_page_risk(analysis["indicators"])
        rules = {item["rule"] for item in risk["indicators"]}
        corr = {item["rule"] for item in risk["correlations"]}
        self.assertIn("payment_information_requested", rules)
        self.assertIn("urgency_pressure_language", rules)
        self.assertIn("fine_penalty_language", rules)
        self.assertIn("urgent_payment_request", corr)
        self.assertIn("penalty_with_payment_request", corr)
        self.assertEqual(risk["final_score"], 70)
        self.assertEqual(risk["classification"], "High Concern")

    def test_external_form_is_detected_without_request(self):
        html = '<form action="https://collector.example.net/submit"><input name="email"></form>'
        with patch.object(resolver, "http_exchange") as exchange:
            analysis = analyze_page_html(html, "https://example.com/login")
            exchange.assert_not_called()
        self.assertIn("external_form_submission", indicators_by_rule(analysis))

    def test_brand_mismatch_and_legitimate_brand(self):
        bad_html = """
        <html><head><title>PayPal Account Verification</title></head>
        <body><h1>PayPal Login</h1>
        <form><input type="password" name="password"></form>
        </body></html>
        """
        bad = analyze_page_html(bad_html, "https://random-example.test/login")
        self.assertIn("brand_domain_mismatch", indicators_by_rule(bad))

        good_html = """
        <html><head><title>PayPal Login</title></head>
        <body><form><input type="password" name="password"></form></body></html>
        """
        good = analyze_page_html(good_html, "https://www.paypal.com/signin")
        self.assertNotIn("brand_domain_mismatch", indicators_by_rule(good))

    def test_script_and_image_and_iframe_are_not_fetched(self):
        html = """
        <html><body>
        <script>fetch('https://example.com/secret')</script>
        <img src="https://example.com/image.jpg">
        <iframe src="https://example.com/frame"></iframe>
        <form><input type="password" name="password"></form>
        </body></html>
        """
        with patch.object(resolver, "http_exchange") as exchange:
            analysis = analyze_page_html(html, "https://example.com/page")
            exchange.assert_not_called()
        self.assertIn("password_login_form", indicators_by_rule(analysis))

    def test_html_title_escape_path_is_plain_text(self):
        html = "<html><head><title><script>alert('x')</script></title></head><body>Hi</body></html>"
        analysis = analyze_page_html(html, "https://example.com/")
        self.assertIn("script", analysis["page_title"].lower())


class TestSafePageFetch(unittest.TestCase):
    def test_unsupported_content_type(self):
        fake = FakePageExchange(
            {
                "https://files.example/doc.pdf": {
                    "status_code": 200,
                    "headers": {"content-type": "application/pdf"},
                    "body": b"%PDF-1.4",
                }
            }
        )
        with (
            patch.object(
                resolver,
                "dns_lookup",
                return_value=[ipaddress.ip_address("1.1.1.1")],
            ),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = fetch_safe_page("https://files.example/doc.pdf")
        self.assertEqual(result["status"], "unsupported_content_type")
        self.assertIsNone(result["html"])

    def test_oversized_response_is_truncated(self):
        body = b"<html><body>" + (b"A" * 600000) + b"</body></html>"
        fake = FakePageExchange(
            {
                "https://big.example/": {
                    "status_code": 200,
                    "headers": {"content-type": "text/html"},
                    "body": body[: 512 * 1024],
                    "truncated": True,
                }
            }
        )
        with (
            patch.object(
                resolver,
                "dns_lookup",
                return_value=[ipaddress.ip_address("1.1.1.1")],
            ),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = fetch_safe_page("https://big.example/")
        self.assertEqual(result["status"], "completed")
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["html"].encode("utf-8", errors="ignore")), 512 * 1024)

    def test_timeout_is_controlled_failure(self):
        with (
            patch.object(
                resolver,
                "dns_lookup",
                return_value=[ipaddress.ip_address("1.1.1.1")],
            ),
            patch.object(
                resolver,
                "http_exchange",
                side_effect=resolver.SafeResolveError("failed", "Connection timed out."),
            ),
        ):
            result = fetch_safe_page("https://slow.example/")
        self.assertEqual(result["status"], "failed")
        self.assertIn("timed out", result["reason"].lower())

    def test_private_redirect_is_blocked(self):
        fake = FakePageExchange(
            {
                "https://public.example/start": {
                    "status_code": 302,
                    "headers": {
                        "content-type": "text/html",
                        "location": "http://127.0.0.1/",
                    },
                    "body": b"",
                }
            }
        )
        with (
            patch.object(
                resolver,
                "dns_lookup",
                return_value=[ipaddress.ip_address("8.8.8.8")],
            ),
            patch.object(resolver, "http_exchange", side_effect=fake),
        ):
            result = fetch_safe_page("https://public.example/start")
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(len(fake.calls), 1)


class TestPageInspectionRoutes(unittest.TestCase):
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

    def _prepare_resolved_scan(self):
        response = self.client.post("/analyze", data={"url": "https://linkr.it/gKin2"})
        self.assertEqual(response.status_code, 200)
        scan_id = get_scans(scan_type="url")[0]["id"]
        save_redirect_inspection(
            scan_id,
            {
                "status": "resolved",
                "reason": None,
                "submitted_url": "https://linkr.it/gKin2",
                "final_url": "https://final.example/login",
                "redirect_count": 1,
                "redirect_chain": [
                    {"url": "https://linkr.it/gKin2", "http_status": 302},
                    {"url": "https://final.example/login", "http_status": 200},
                ],
            },
            final_risk={
                "final_score": 10,
                "classification": "Low Risk",
                "recommendation": "Stored.",
            },
            final_indicators=[],
            final_correlations=[],
        )
        from database.database import update_scan_coverage

        update_scan_coverage(scan_id, "comprehensive", "resolved")
        return scan_id

    def test_page_inspection_stores_history_and_pdf_without_network_on_view(self):
        scan_id = self._prepare_resolved_scan()
        html = """
        <html><head><title><script>alert('x')</script></title></head>
        <body>
        <h1>Account Login</h1>
        <form>
        <input type="email" name="email">
        <input type="password" name="password">
        </form>
        </body></html>
        """
        with patch(
            "app.fetch_safe_page",
            return_value={
                "status": "completed",
                "reason": None,
                "page_url": "https://final.example/login",
                "content_type": "text/html",
                "html": html,
                "truncated": False,
                "redirect_chain": [],
            },
        ) as fetch:
            response = self.client.post(
                "/inspect-page",
                data={"scan_id": scan_id},
                follow_redirects=False,
            )
            fetch.assert_called_once()
        self.assertEqual(response.status_code, 302)

        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            detail = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
            exchange.assert_not_called()

        self.assertIn("Page Content Analysis", detail)
        self.assertIn("Password / Login Form Detected", detail)
        self.assertIn("&lt;script&gt;", detail)
        self.assertNotIn("<script>alert('x')</script>", detail)
        self.assertIn("PhishLens Analysis", detail)
        self.assertIn("Static Page Content", detail)

        record = get_scan_by_id(scan_id)
        self.assertEqual(record["page_inspection"]["status"], "completed")
        self.assertIn("script", (record["page_inspection"]["page_title"] or "").lower())

        with patch("services.safe_redirect_resolver.http_exchange") as exchange:
            report = self.client.get(f"/scan/{scan_id}/report")
            exchange.assert_not_called()
        text = pdf_text(report.data)
        self.assertIn("Static Page Content Analysis", text)
        self.assertIn("Page Risk Score", text)
        self.assertIn("script", text.lower())

    def test_failed_page_inspection_keeps_url_scores(self):
        scan_id = self._prepare_resolved_scan()
        with patch(
            "app.fetch_safe_page",
            return_value={
                "status": "failed",
                "reason": "Connection timed out.",
                "page_url": None,
                "content_type": None,
                "html": None,
                "truncated": False,
                "redirect_chain": [],
            },
        ):
            self.client.post("/inspect-page", data={"scan_id": scan_id})
        page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)
        self.assertIn("25/100", page)
        self.assertIn("Connection timed out.", page)
        record = get_scan_by_id(scan_id)
        self.assertEqual(record["scan"]["risk_score"], 25)
        self.assertEqual(record["page_inspection"]["status"], "failed")


if __name__ == "__main__":
    unittest.main()
