"""Step 33 — Email Analyzer QA & Security Validation regressions.

Covers parsing edge cases, indicator/score fixtures, privacy, history/PDF,
and results UI markup. Network I/O is mocked; no live destinations are used.
"""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from email.message import EmailMessage
from pathlib import Path
from unittest.mock import patch

from analyzers.email_analyzer import MAX_EMAIL_INPUT_LENGTH, parse_email
from analyzers.email_security import analyze_email_security
from app import app
from database.database import (
    get_db_connection,
    get_scan_by_id,
    get_scan_statistics,
    get_scans,
    init_db,
)
from services.email_risk_engine import (
    HIGH_RISK,
    LOW_RISK,
    SUSPICIOUS,
    calculate_email_risk,
)
from tests.support import make_client


MEETING_EMAIL = """\
From: colleague@example.com
To: noora@example.com
Subject: Meeting tomorrow

Hello Noora,

The meeting starts at 10 AM.
"""

CREDENTIAL_URL_EMAIL = """\
From: support@example.com
To: noora@example.com
Subject: Account update

Please login and verify your account:
https://g00gle.com/login
"""

URGENT_EMAIL = """\
From: support@example.com
To: noora@example.com
Subject: URGENT: Account action required

Please login and verify your account:
https://g00gle.com/login
"""

FAKE_BANK_EMAIL = """\
From: "First National Bank" <alerts@fnb-secure-login.com>
To: user@example.com
Subject: Payment failed - update payment method

Dear customer,

Your payment failed. Please update payment method immediately.
https://g00gle.com/login
"""

PASSWORD_RESET_EMAIL = """\
From: security@example.com
To: user@example.com
Subject: Reset password - action required

Please reset password for your account.
https://example.com/reset
"""

MISSING_HEADERS_EMAIL = """\
Subject: Incomplete

Body only.
"""

MALFORMED_MIME_EMAIL = (
    "Content-Type: multipart/mixed; boundary=AAA\n\n"
    "--AAA\nContent-Type: text/plain\n\nHi\n--AAA-- truncated"
)

XSS_HTML_EMAIL = """\
From: "Evil <script>alert(1)</script>" <evil@example.com>
To: user@example.com
Subject: <img src=x onerror=alert(1)>
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<html><body>
<a href="https://example.com/login">Safe text</a>
<script>alert('xss')</script>
<img src="https://tracker.example/pixel.gif">
</body></html>
"""

PRIVACY_EMAIL = """\
From: sender@example.com
To: user@example.com
Subject: Privacy check

BODY_SECRET_STEP33_DO_NOT_STORE
"""


def _score(raw_email, attachments=None):
    parsed = parse_email(raw_email)
    if attachments is not None:
        parsed["attachments"] = attachments
    security = analyze_email_security(parsed)
    return calculate_email_risk(security["indicators"]), security, parsed


def _rules(security):
    return [item["rule_name"] for item in security["indicators"]]


def multipart_alternative_email():
    message = EmailMessage()
    message["From"] = "a@example.com"
    message["To"] = "b@example.com"
    message["Subject"] = "Multipart notice"
    message.set_content("Plain path https://example.com/plain")
    message.add_alternative(
        '<p><a href="https://g00gle.com/login">Open account</a></p>',
        subtype="html",
    )
    return message.as_string()


def unicode_email():
    body = "Bonjour café 世界\n"
    return (
        "From: noreply@example.com\n"
        "To: user@example.com\n"
        "Subject: Verification café 世界\n"
        "MIME-Version: 1.0\n"
        'Content-Type: text/plain; charset="utf-8"\n'
        "\n"
        + body
    ), body


class TestStep33EmailParsing(unittest.TestCase):
    def test_meeting_email_extracts_core_fields(self):
        parsed = parse_email(MEETING_EMAIL)
        self.assertEqual(parsed["headers"]["from"], "colleague@example.com")
        self.assertEqual(parsed["headers"]["to"], "noora@example.com")
        self.assertEqual(parsed["headers"]["subject"], "Meeting tomorrow")
        self.assertIn("meeting starts", (parsed["body"]["plain_text"] or "").lower())
        self.assertEqual(parsed["urls"], [])
        self.assertEqual(parsed["attachments"], [])

    def test_multipart_html_and_plain_collects_both_bodies_and_urls(self):
        parsed = parse_email(multipart_alternative_email())
        self.assertTrue(parsed["body"]["plain_text"])
        self.assertTrue(parsed["body"]["html_text"])
        self.assertIn("https://example.com/plain", parsed["urls"])
        self.assertIn("https://g00gle.com/login", parsed["urls"])
        self.assertTrue(any(link["href"] == "https://g00gle.com/login" for link in parsed["links"]))

    def test_unicode_subject_and_body_are_preserved(self):
        raw, body = unicode_email()
        parsed = parse_email(raw)
        self.assertIn("café", parsed["headers"]["subject"])
        self.assertIn("世界", parsed["headers"]["subject"])
        self.assertEqual(parsed["body"]["plain_text"], body)

    def test_missing_headers_do_not_crash(self):
        parsed = parse_email(MISSING_HEADERS_EMAIL)
        self.assertIsNone(parsed["headers"]["from"])
        self.assertIsNone(parsed["headers"]["to"])
        self.assertEqual(parsed["headers"]["subject"], "Incomplete")
        self.assertIn("Body only", parsed["body"]["plain_text"] or "")

    def test_malformed_mime_returns_controlled_parse(self):
        parsed = parse_email(MALFORMED_MIME_EMAIL)
        self.assertIsInstance(parsed["urls"], list)
        self.assertIsInstance(parsed["attachments"], list)

    def test_null_byte_body_does_not_raise(self):
        raw = "From: a@example.com\nSubject: x\n\nhello\x00world\n"
        parsed = parse_email(raw)
        self.assertIn("hello", parsed["body"]["plain_text"] or "")

    def test_javascript_and_mailto_hrefs_are_not_collected_as_urls(self):
        raw = """\
From: a@example.com
To: b@example.com
Subject: Links
MIME-Version: 1.0
Content-Type: text/html; charset="utf-8"

<a href="javascript:alert(1)">x</a>
<a href="mailto:user@example.com">mail</a>
<a href="https://example.com/ok">ok</a>
"""
        parsed = parse_email(raw)
        self.assertEqual(parsed["urls"], ["https://example.com/ok"])


class TestStep33EmailSecurityAndScores(unittest.TestCase):
    def test_regression_meeting_is_10_low_risk(self):
        risk, security, _parsed = _score(MEETING_EMAIL)
        self.assertEqual(security["indicators"], [])
        self.assertEqual(risk["base_score"], 10)
        self.assertEqual(risk["final_score"], 10)
        self.assertEqual(risk["classification"], LOW_RISK)

    def test_regression_credential_suspicious_url_is_55(self):
        risk, security, _parsed = _score(CREDENTIAL_URL_EMAIL)
        self.assertIn("credential_language", _rules(security))
        self.assertIn("suspicious_embedded_link", _rules(security))
        self.assertEqual(risk["final_score"], 55)
        self.assertEqual(risk["classification"], SUSPICIOUS)
        self.assertEqual(risk["raw_score"], risk["final_score"])

    def test_regression_urgent_credential_url_is_65(self):
        risk, security, _parsed = _score(URGENT_EMAIL)
        self.assertIn("urgency_language", _rules(security))
        self.assertEqual(risk["final_score"], 65)
        self.assertEqual(risk["classification"], HIGH_RISK)

    def test_fake_bank_notification_scores_high_with_expected_signals(self):
        risk, security, _parsed = _score(FAKE_BANK_EMAIL)
        rules = set(_rules(security))
        self.assertTrue(
            {"credential_language", "financial_language", "suspicious_embedded_link"}
            <= rules
        )
        self.assertGreaterEqual(risk["final_score"], 61)
        self.assertEqual(risk["classification"], HIGH_RISK)
        self.assertLessEqual(risk["final_score"], 100)

    def test_password_reset_urgency_and_credentials_stay_within_bounds(self):
        risk, security, _parsed = _score(PASSWORD_RESET_EMAIL)
        rules = set(_rules(security))
        self.assertIn("credential_language", rules)
        self.assertIn("urgency_language", rules)
        self.assertEqual(risk["final_score"], 30)
        self.assertEqual(risk["classification"], LOW_RISK)

    def test_missing_auth_headers_are_not_treated_as_failures(self):
        risk, security, _parsed = _score(MEETING_EMAIL)
        auth_rules = {
            "spf_fail",
            "spf_softfail",
            "dkim_fail",
            "dmarc_fail",
        }
        self.assertFalse(auth_rules & set(_rules(security)))
        self.assertEqual(risk["final_score"], 10)
        for indicator in security["indicators"]:
            self.assertNotIn("independently verify", indicator.get("title", "").lower())

    def test_reported_auth_failures_include_non_verification_disclaimer(self):
        raw = """\
From: a@example.com
To: b@example.com
Return-Path: <other@evil.com>
Subject: Note
Authentication-Results: mx.example; spf=fail; dkim=fail; dmarc=fail

Please review.
"""
        risk, security, _parsed = _score(raw)
        rules = set(_rules(security))
        self.assertIn("spf_fail", rules)
        self.assertIn("dkim_fail", rules)
        self.assertIn("dmarc_fail", rules)
        self.assertIn("return_path_mismatch", rules)
        for indicator in security["indicators"]:
            if indicator["rule_name"] in {"spf_fail", "dkim_fail", "dmarc_fail"}:
                self.assertIn("does not independently verify", indicator["explanation"])
        self.assertEqual(risk["final_score"], 75)
        self.assertEqual(risk["classification"], HIGH_RISK)

    def test_credential_only_is_20_low_risk(self):
        risk, security, _parsed = _score(
            "From: a@example.com\nTo: b@example.com\nSubject: Account\n\n"
            "Please sign in to verify your account.\n"
        )
        self.assertEqual(_rules(security), ["credential_language"])
        self.assertEqual(risk["final_score"], 20)
        self.assertEqual(risk["classification"], LOW_RISK)

    def test_risky_attachment_with_invoice_is_43_suspicious(self):
        risk, security, _parsed = _score(
            "From: a@example.com\nTo: b@example.com\nSubject: Invoice\n\n"
            "Your invoice is ready.\n",
            attachments=[
                {
                    "filename": "invoice.exe",
                    "content_type": "application/octet-stream",
                    "size": 12,
                }
            ],
        )
        self.assertIn("financial_language", _rules(security))
        self.assertIn("risky_attachment_extension", _rules(security))
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]],
            ["risky_attachment_with_financial_context"],
        )
        self.assertEqual(risk["final_score"], 43)
        self.assertEqual(risk["classification"], SUSPICIOUS)

    def test_dmarc_fail_with_return_path_mismatch_is_45(self):
        raw = """\
From: a@example.com
To: b@example.com
Return-Path: <other@evil.com>
Subject: Note
Authentication-Results: mx; dmarc=fail
Received-SPF: pass

Please review.
"""
        risk, security, _parsed = _score(raw)
        self.assertEqual(risk["final_score"], 45)
        self.assertEqual(risk["classification"], SUSPICIOUS)

    def test_duplicate_credential_terms_and_urls_do_not_multiply(self):
        raw = """\
From: support@example.com
To: user@example.com
Subject: Update

Please login login login and verify your account verify your account:
https://g00gle.com/login
https://g00gle.com/login
"""
        risk, security, _parsed = _score(raw)
        self.assertEqual(_rules(security).count("credential_language"), 1)
        self.assertEqual(_rules(security).count("suspicious_embedded_link"), 1)
        self.assertEqual(risk["final_score"], 55)

    def test_scores_remain_between_zero_and_one_hundred(self):
        risk, _security, _parsed = _score(FAKE_BANK_EMAIL)
        self.assertGreaterEqual(risk["final_score"], 0)
        self.assertLessEqual(risk["final_score"], 100)
        self.assertEqual(risk["final_score"], min(100, max(0, risk["raw_score"])))


class TestStep33EmailRoutesPrivacyHistoryPdf(unittest.TestCase):
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

    def test_empty_and_oversized_input_rejected(self):
        empty = self.client.post("/analyze-email", data={"raw_email": "   \n"})
        self.assertEqual(empty.status_code, 200)
        self.assertIn("Please paste an email", empty.get_data(as_text=True))

        huge = self.client.post(
            "/analyze-email",
            data={"raw_email": "a" * (MAX_EMAIL_INPUT_LENGTH + 1)},
        )
        self.assertEqual(huge.status_code, 200)
        self.assertIn("too large", huge.get_data(as_text=True).lower())

    def test_malformed_input_does_not_500(self):
        with patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ), patch(
            "socket.create_connection",
            side_effect=AssertionError("network"),
        ):
            response = self.client.post(
                "/analyze-email",
                data={"raw_email": MALFORMED_MIME_EMAIL},
            )
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertNotIn("Internal Server Error", page)

    def test_results_ui_initial_view_and_closed_report(self):
        page = self.client.post(
            "/analyze-email", data={"raw_email": MEETING_EMAIL}
        ).get_data(as_text=True)
        self.assertIn("Email Risk Score", page)
        self.assertIn("10", page)
        self.assertIn("Low Risk", page)
        self.assertIn("risk-meter", page)
        self.assertIn("View Full Analysis Report", page)
        self.assertIn('class="full-analysis-details"', page)
        self.assertNotIn('class="full-analysis-details" open', page)
        self.assertIn("Email Score Breakdown", page)
        self.assertIn("Security Indicators", page)
        self.assertIn("Embedded Link Analysis", page)
        self.assertIn("Technical Email Details", page)
        self.assertIn("Authentication Headers", page)
        self.assertIn("class=\"tech-details\"", page)
        self.assertNotIn('class="tech-details" open', page)

    def test_xss_html_is_escaped_and_urls_not_clickable(self):
        page = self.client.post(
            "/analyze-email", data={"raw_email": XSS_HTML_EMAIL}
        ).get_data(as_text=True)
        self.assertNotIn("<script>alert('xss')</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<img src=x onerror=alert(1)>", page)
        self.assertNotIn('href="https://example.com/login"', page)
        self.assertNotIn('src="https://tracker.example/pixel.gif"', page)
        self.assertIn("https://example.com/login", page)

    def test_analyze_email_makes_no_network_calls(self):
        with patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ), patch(
            "socket.create_connection",
            side_effect=AssertionError("network"),
        ), patch(
            "socket.getaddrinfo",
            side_effect=AssertionError("dns"),
        ):
            response = self.client.post(
                "/analyze-email",
                data={"raw_email": URGENT_EMAIL},
            )
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("65", page)
        self.assertIn("High Risk", page)

    def test_body_secret_not_persisted_and_history_offline(self):
        before = get_scan_statistics()["total"]
        self.client.post("/analyze-email", data={"raw_email": PRIVACY_EMAIL})
        after = get_scan_statistics()["total"]
        self.assertEqual(after, before + 1)

        scan = get_scans(scan_type="email")[0]
        record = get_scan_by_id(scan["id"])
        self.assertNotIn("BODY_SECRET_STEP33_DO_NOT_STORE", str(record))

        connection = get_db_connection()
        try:
            tables = [
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            ]
            blob_parts = []
            for table in tables:
                rows = connection.execute(f"SELECT * FROM {table}").fetchall()
                blob_parts.append(str([dict(row) for row in rows]))
            self.assertNotIn("BODY_SECRET_STEP33_DO_NOT_STORE", "\n".join(blob_parts))
        finally:
            connection.close()

        with patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            history = self.client.get("/history").get_data(as_text=True)
            detail = self.client.get(f"/scan/{scan['id']}").get_data(as_text=True)
        self.assertIn("Privacy check", history)
        self.assertIn("EMAIL", history)
        self.assertNotIn("BODY_SECRET_STEP33_DO_NOT_STORE", history)
        self.assertNotIn("BODY_SECRET_STEP33_DO_NOT_STORE", detail)
        self.assertEqual(get_scan_statistics()["total"], after)

    def test_urgent_email_history_score_and_pdf(self):
        from tests.test_reports import pdf_text

        response = self.client.post("/analyze-email", data={"raw_email": URGENT_EMAIL})
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("Download Report (PDF)", page)

        scan = get_scans(scan_type="email")[0]
        self.assertEqual(scan["risk_score"], 65)
        self.assertEqual(scan["classification"], "High Risk")

        history = self.client.get("/history").get_data(as_text=True)
        self.assertIn("URGENT: Account action required", history)
        self.assertIn("HIGH RISK", history)

        detail = self.client.get(f"/scan/{scan['id']}").get_data(as_text=True)
        self.assertIn("65", detail)
        self.assertIn("High Risk", detail)
        self.assertIn("https://g00gle.com/login", detail)
        self.assertNotIn('href="https://g00gle.com/login"', detail)

        report = self.client.get(f"/scan/{scan['id']}/report")
        self.assertEqual(report.status_code, 200)
        self.assertEqual(report.mimetype, "application/pdf")
        text = pdf_text(report.data)
        self.assertIn("65 / 100", text)
        self.assertIn("High Risk", text)
        self.assertIn("https://g00gle.com/login", text)
        self.assertIn("does not retain the complete email body", text)
        self.assertNotIn("Please login and verify your account:", text)

    def test_unicode_subject_survives_history_and_pdf(self):
        from tests.test_reports import pdf_text

        raw, _body = unicode_email()
        self.client.post("/analyze-email", data={"raw_email": raw})
        scan = get_scans(scan_type="email")[0]
        history = self.client.get("/history").get_data(as_text=True)
        self.assertIn("café", history)
        self.assertIn("世界", history)
        text = pdf_text(self.client.get(f"/scan/{scan['id']}/report").data)
        self.assertTrue("café" in text or "cafe" in text.lower() or "Verification" in text)

    def test_parse_failure_log_message_omits_raw_email(self):
        with self.assertLogs("app", level="ERROR") as captured:
            with patch(
                "app.parse_email",
                side_effect=RuntimeError("synthetic parse failure"),
            ):
                response = self.client.post(
                    "/analyze-email",
                    data={"raw_email": PRIVACY_EMAIL},
                )
        self.assertEqual(response.status_code, 200)
        self.assertIn("could not be parsed", response.get_data(as_text=True).lower())
        joined = "\n".join(captured.output)
        self.assertIn("The email could not be parsed", joined)
        self.assertNotIn("BODY_SECRET_STEP33_DO_NOT_STORE", joined)

    def test_attachment_metadata_only_no_bytes_in_db(self):
        message = EmailMessage()
        message["From"] = "billing@example.com"
        message["To"] = "user@example.com"
        message["Subject"] = "Invoice attached"
        message.set_content("Your invoice is attached.")
        message.add_attachment(
            b"MZ-FAKE-EXECUTABLE-BYTES",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.exe",
        )
        self.client.post("/analyze-email", data={"raw_email": message.as_string()})
        scan = get_scans(scan_type="email")[0]
        record = get_scan_by_id(scan["id"])
        self.assertNotIn("MZ-FAKE-EXECUTABLE-BYTES", str(record))
        connection = get_db_connection()
        try:
            rows = connection.execute(
                "SELECT filename, content_type, size FROM email_attachments WHERE scan_id = ?",
                (scan["id"],),
            ).fetchall()
        finally:
            connection.close()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["filename"], "invoice.exe")
        self.assertGreater(rows[0]["size"], 0)


if __name__ == "__main__":
    unittest.main()
