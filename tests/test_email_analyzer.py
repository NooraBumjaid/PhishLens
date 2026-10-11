import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from analyzers.email_analyzer import (
    MAX_EMAIL_INPUT_LENGTH,
    parse_email,
)
from app import app
from tests.support import make_client


BASIC_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Hello
Date: Thu, 01 Oct 2026 10:00:00 +0000

This is a test email.
"""

MISSING_HEADER_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Hello

This is a test email.
"""

RECEIVED_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Route
Received: from laptop.example by mx1.example
Received: from mx1.example by mx2.example

Body text.
"""

AUTH_EMAIL = """\
From: sender@example.com
To: user@example.com
Reply-To: reply@example.com
Return-Path: <bounce@example.com>
Subject: Auth
Authentication-Results: example.com; spf=neutral (synthetic)
Received-SPF: neutral (synthetic) client-ip=192.0.2.10
DKIM-Signature: v=1; a=rsa-sha256; d=example.com; s=test; b=synthetic

Hello.
"""

URL_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Link

Visit https://example.com/login for more information.
"""

DUPLICATE_URL_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Links

Visit https://example.com/login for more information.
Visit https://example.com/login again.
"""

HTML_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Login
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<p><a href="https://example.com/login">Login</a></p>
<script>alert('test')</script>
<img src="https://tracking.example/pixel.png">
"""


def attachment_email():
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "user@example.com"
    message["Subject"] = "Invoice"
    message.set_content("See the attachment.")
    payload = b"%PDF-1.4 synthetic"
    message.add_attachment(
        payload,
        maintype="application",
        subtype="pdf",
        filename="invoice.pdf",
    )
    return message.as_string(), payload


class TestEmailParser(unittest.TestCase):
    def test_basic_email_fields_and_body(self):
        parsed = parse_email(BASIC_EMAIL)

        self.assertEqual(parsed["headers"]["from"], "sender@example.com")
        self.assertEqual(parsed["headers"]["to"], "user@example.com")
        self.assertEqual(parsed["headers"]["subject"], "Hello")
        self.assertIn("This is a test email.", parsed["body"]["plain_text"])

    def test_missing_headers_do_not_crash(self):
        parsed = parse_email(MISSING_HEADER_EMAIL)

        self.assertIsNone(parsed["headers"]["reply_to"])
        self.assertIsNone(parsed["headers"]["return_path"])
        self.assertIsNone(parsed["headers"]["message_id"])
        self.assertEqual(parsed["headers"]["subject"], "Hello")

    def test_multiple_received_headers_are_kept_in_order(self):
        parsed = parse_email(RECEIVED_EMAIL)

        self.assertEqual(len(parsed["received_headers"]), 2)
        self.assertIn("mx1.example", parsed["received_headers"][0])
        self.assertIn("mx2.example", parsed["received_headers"][1])

    def test_authentication_headers_are_extracted_as_text(self):
        parsed = parse_email(AUTH_EMAIL)

        self.assertEqual(parsed["headers"]["from"], "sender@example.com")
        self.assertEqual(parsed["headers"]["reply_to"], "reply@example.com")
        self.assertEqual(parsed["headers"]["return_path"], "<bounce@example.com>")
        self.assertIn(
            "spf=neutral (synthetic)",
            parsed["authentication"]["authentication_results"][0],
        )
        self.assertIn("neutral (synthetic)", parsed["authentication"]["received_spf"][0])
        self.assertIn("b=synthetic", parsed["authentication"]["dkim_signatures"][0])

    def test_url_is_extracted_from_plain_text(self):
        parsed = parse_email(URL_EMAIL)

        self.assertEqual(parsed["urls"], ["https://example.com/login"])

    def test_duplicate_urls_are_returned_once(self):
        parsed = parse_email(DUPLICATE_URL_EMAIL)

        self.assertEqual(parsed["urls"], ["https://example.com/login"])

    def test_html_href_is_extracted_without_opening_it(self):
        with patch("socket.socket", side_effect=AssertionError("socket used")):
            parsed = parse_email(HTML_EMAIL)

        self.assertIn("https://example.com/login", parsed["urls"])
        self.assertIn("<a href=", parsed["body"]["html_text"])

    def test_html_script_stays_text(self):
        parsed = parse_email(HTML_EMAIL)

        self.assertIn("<script>alert('test')</script>", parsed["body"]["html_text"])

    def test_remote_image_is_not_requested(self):
        with patch("socket.socket", side_effect=AssertionError("socket used")):
            parsed = parse_email(HTML_EMAIL)

        self.assertIn("https://tracking.example/pixel.png", parsed["body"]["html_text"])
        self.assertIn("https://tracking.example/pixel.png", parsed["urls"])

    def test_attachment_metadata_is_extracted_without_saving_a_file(self):
        raw_email, payload = attachment_email()
        parsed = parse_email(raw_email)

        self.assertEqual(len(parsed["attachments"]), 1)
        attachment = parsed["attachments"][0]
        self.assertEqual(attachment["filename"], "invoice.pdf")
        self.assertEqual(attachment["content_type"], "application/pdf")
        self.assertEqual(attachment["size"], len(payload))
        self.assertIn("See the attachment.", parsed["body"]["plain_text"])
        self.assertNotIn("synthetic", parsed["body"]["plain_text"])
        self.assertFalse(Path("invoice.pdf").exists())

    def test_parser_source_does_not_import_network_libraries(self):
        source_path = Path(__file__).resolve().parents[1] / "analyzers" / "email_analyzer.py"
        source = source_path.read_text(encoding="utf-8")
        imports = [
            line
            for line in source.splitlines()
            if line.startswith("import ") or line.startswith("from ")
        ]
        imported = "\n".join(imports)
        self.assertNotIn("socket", imported)
        self.assertNotIn("urllib", imported)
        self.assertNotIn("requests", imported)


class TestEmailRoutes(unittest.TestCase):
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

    def test_email_page_loads(self):
        response = self.client.get("/email")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Email Analyzer", page)
        self.assertIn("Analyze Email", page)

    def test_valid_email_result_shows_text_not_a_link(self):
        response = self.client.post("/analyze-email", data={"raw_email": URL_EMAIL})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("sender@example.com", page)
        self.assertIn("Link", page)
        self.assertIn("Visit https://example.com/login", page)
        self.assertIn("https://example.com/login", page)
        self.assertNotIn('href="https://example.com/login"', page)
        self.assertIn("should not be interpreted as a probability that the email is phishing", page)

    def test_rendered_script_is_escaped(self):
        response = self.client.post("/analyze-email", data={"raw_email": HTML_EMAIL})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>alert('test')</script>", page)
        self.assertNotIn("<img", page.lower())
        self.assertNotIn('href="https://tracking.example/pixel.png"', page)

    def test_empty_email_is_rejected(self):
        with patch("app.parse_email") as parse:
            response = self.client.post("/analyze-email", data={"raw_email": "   \n"})
            parse.assert_not_called()

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Please paste an email before analyzing.", page)

    def test_oversized_email_is_rejected_before_parsing(self):
        with patch("app.parse_email") as parse:
            response = self.client.post(
                "/analyze-email",
                data={"raw_email": "a" * (MAX_EMAIL_INPUT_LENGTH + 1)},
            )
            parse.assert_not_called()

        page = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn("too large", page)

    def test_live_email_result_has_progressive_disclosure_controls(self):
        response = self.client.post("/analyze-email", data={"raw_email": URL_EMAIL})
        page = response.get_data(as_text=True)
        csp = response.headers.get("Content-Security-Policy", "")

        self.assertEqual(response.status_code, 200)
        self.assertIn("View Full Analysis Report", page)
        self.assertIn('<details class="full-analysis-details">', page)
        self.assertIn('class="full-analysis-summary"', page)
        self.assertIn('id="email-full-analysis"', page)
        self.assertIn("Email Score Breakdown", page)
        self.assertNotIn('<details class="full-analysis-details" open', page)
        self.assertIn("/static/js/ui.js", page)
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp.split("script-src", 1)[-1].split(";", 1)[0])
        self.assertNotIn("onclick=", page.lower())


if __name__ == "__main__":
    unittest.main()
