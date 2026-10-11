import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzers.email_analyzer import parse_email
from analyzers.email_security import analyze_email_security
from app import app
from tests.support import make_client


def _email(headers, body="", content_type="text/plain"):
    lines = [f"{name}: {value}" for name, value in headers]
    lines.append("MIME-Version: 1.0")
    lines.append(f'Content-Type: {content_type}; charset="utf-8"')
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _rules(result):
    return {indicator["rule_name"]: indicator for indicator in result["indicators"]}


class TestEmailSecurityIndicators(unittest.TestCase):
    def test_reply_to_mismatch_and_same_domain(self):
        mismatch = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Reply-To", "attacker@different.example"),
                        ("Subject", "Hello"),
                    ],
                    "Hello.",
                )
            )
        )
        indicator = _rules(mismatch)["reply_to_mismatch"]
        self.assertEqual(indicator["title"], "From and Reply-To domains differ")
        self.assertEqual(indicator["score_change"], 0)
        self.assertIn("example.com", indicator["evidence"])
        self.assertIn("different.example", indicator["evidence"])

        same = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Reply-To", "other@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "Hello.",
                )
            )
        )
        self.assertNotIn("reply_to_mismatch", _rules(same))

    def test_missing_reply_to_does_not_trigger(self):
        result = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "Hello.",
                )
            )
        )
        self.assertNotIn("reply_to_mismatch", _rules(result))

    def test_return_path_mismatch_mentions_legitimate_mail(self):
        result = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Return-Path", "<bounce@mailer.example.net>"),
                        ("Subject", "Hello"),
                    ],
                    "Hello.",
                )
            )
        )
        indicator = _rules(result)["return_path_mismatch"]
        self.assertEqual(indicator["severity"], "low")
        self.assertIn("legitimate", indicator["explanation"].lower())
        self.assertIn("return-path", indicator["explanation"].lower())

    def test_display_name_conflict_and_ordinary_name(self):
        conflict = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", '"support@paypal.com" <attacker@example.net>'),
                        ("To", "user@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "Hello.",
                )
            )
        )
        indicator = _rules(conflict)["display_name_deception"]
        self.assertIn("paypal.com", indicator["evidence"].lower())
        self.assertIn("attacker@example.net", indicator["evidence"].lower())

        ordinary = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", '"Noora Bumjaid" <noora@example.com>'),
                        ("To", "user@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "Hello.",
                )
            )
        )
        self.assertNotIn("display_name_deception", _rules(ordinary))

    def test_urgency_is_one_case_insensitive_indicator(self):
        result = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Subject", "URGENT: Verify your account immediately"),
                    ],
                    "Hello.",
                )
            )
        )
        matches = [
            indicator
            for indicator in result["indicators"]
            if indicator["rule_name"] == "urgency_language"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIn("urgent", matches[0]["evidence"])
        self.assertIn("immediately", matches[0]["evidence"])

    def test_credential_language_is_one_indicator(self):
        result = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "Please login and verify your account.",
                )
            )
        )
        matches = [
            indicator
            for indicator in result["indicators"]
            if indicator["rule_name"] == "credential_language"
        ]
        self.assertEqual(len(matches), 1)
        self.assertIn("login", matches[0]["evidence"])
        self.assertIn("verify your account", matches[0]["evidence"])

    def test_generic_greeting(self):
        generic = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "Dear customer,\nPlease read this note.",
                )
            )
        )
        self.assertIn("generic_greeting", _rules(generic))
        self.assertIn("dear customer", _rules(generic)["generic_greeting"]["evidence"])

        named = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "Hello Noora,\nPlease read this note.",
                )
            )
        )
        self.assertNotIn("generic_greeting", _rules(named))

    def test_suspicious_embedded_url_is_not_saved(self):
        raw = _email(
            [
                ("From", "support@example.com"),
                ("To", "user@example.com"),
                ("Subject", "Hello"),
            ],
            "Please login:\nhttps://g00gle.com/login",
        )
        with patch("database.database.save_scan") as save_scan:
            result = analyze_email_security(parse_email(raw))
            save_scan.assert_not_called()

        embedded = result["embedded_urls"][0]
        self.assertEqual(embedded["url"], "https://g00gle.com/login")
        self.assertEqual(embedded["score"], 45)
        self.assertEqual(embedded["classification"], "Suspicious")
        indicator = _rules(result)["suspicious_embedded_link"]
        self.assertIn("https://g00gle.com/login", indicator["evidence"])
        self.assertIn("45/100", indicator["evidence"])
        self.assertEqual(indicator["score_change"], 0)

    def test_low_risk_embedded_url_does_not_create_suspicious_link(self):
        result = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Subject", "Hello"),
                    ],
                    "See https://example.com/login",
                )
            )
        )
        embedded = result["embedded_urls"][0]
        self.assertEqual(embedded["score"], 10)
        self.assertEqual(embedded["classification"], "Low Risk")
        self.assertNotIn("suspicious_embedded_link", _rules(result))

    def test_displayed_link_mismatch_without_network(self):
        raw = _email(
            [
                ("From", "support@example.com"),
                ("To", "user@example.com"),
                ("Subject", "Hello"),
            ],
            '<a href="https://evil.example/login">https://paypal.com</a>',
            content_type="text/html",
        )
        with patch("socket.socket", side_effect=AssertionError("socket used")):
            result = analyze_email_security(parse_email(raw))
        indicator = _rules(result)["link_text_mismatch"]
        self.assertIn("https://paypal.com", indicator["evidence"])
        self.assertIn("https://evil.example/login", indicator["evidence"])

    def test_ordinary_link_label_is_not_a_mismatch(self):
        raw = _email(
            [
                ("From", "support@example.com"),
                ("To", "user@example.com"),
                ("Subject", "Hello"),
            ],
            '<a href="https://example.com">Click here</a>',
            content_type="text/html",
        )
        result = analyze_email_security(parse_email(raw))
        self.assertNotIn("link_text_mismatch", _rules(result))

    def test_risky_attachment_uses_filename_only(self):
        raw = _email(
            [
                ("From", "support@example.com"),
                ("To", "user@example.com"),
                ("Subject", "Invoice"),
            ],
            "See the attachment.",
        )
        parsed = parse_email(raw)
        parsed["attachments"] = [
            {"filename": "invoice.exe", "content_type": "application/octet-stream", "size": 4}
        ]
        result = analyze_email_security(parsed)
        indicator = _rules(result)["risky_attachment_extension"]
        self.assertIn("invoice.exe", indicator["evidence"])
        self.assertIn(".exe", indicator["evidence"])
        self.assertIn("was not opened", indicator["explanation"])
        self.assertNotIn("this file contains malware", indicator["explanation"].lower())

    def test_double_extension(self):
        parsed = parse_email(
            _email(
                [
                    ("From", "support@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "File"),
                ],
                "See the attachment.",
            )
        )
        parsed["attachments"] = [
            {"filename": "invoice.pdf.exe", "content_type": "application/octet-stream", "size": 4}
        ]
        flagged = _rules(analyze_email_security(parsed))
        self.assertIn("misleading_double_extension", flagged)

        parsed["attachments"] = [
            {"filename": "report.final.pdf", "content_type": "application/pdf", "size": 4}
        ]
        clear = _rules(analyze_email_security(parsed))
        self.assertNotIn("misleading_double_extension", clear)
        self.assertNotIn("risky_attachment_extension", clear)

    def test_reported_authentication_failures(self):
        raw = _email(
            [
                ("From", "support@example.com"),
                ("To", "user@example.com"),
                ("Subject", "Auth"),
                (
                    "Authentication-Results",
                    "mx.example; spf=fail; dkim=fail; dmarc=fail",
                ),
                ("Received-SPF", "softfail (synthetic)"),
            ],
            "Hello.",
        )
        # Received-SPF softfail wording varies. Include the explicit token too.
        raw = raw.replace(
            "Received-SPF: softfail (synthetic)",
            "Received-SPF: spf=softfail",
        )
        result = analyze_email_security(parse_email(raw))
        rules = _rules(result)
        self.assertIn("header reports", rules["spf_fail"]["explanation"])
        self.assertIn("does not independently verify", rules["spf_fail"]["explanation"])
        self.assertEqual(rules["spf_softfail"]["title"], "Email header reports SPF soft failure")
        self.assertIn("dkim_fail", rules)
        self.assertIn("dmarc_fail", rules)
        self.assertNotIn("verification failed", rules["spf_fail"]["explanation"].lower())

    def test_authentication_pass_creates_no_failure(self):
        result = analyze_email_security(
            parse_email(
                _email(
                    [
                        ("From", "support@example.com"),
                        ("To", "user@example.com"),
                        ("Subject", "Auth"),
                        (
                            "Authentication-Results",
                            "mx.example; spf=pass; dkim=pass; dmarc=pass",
                        ),
                    ],
                    "Hello.",
                )
            )
        )
        names = set(_rules(result))
        self.assertNotIn("spf_fail", names)
        self.assertNotIn("spf_softfail", names)
        self.assertNotIn("dkim_fail", names)
        self.assertNotIn("dmarc_fail", names)
        combined = " ".join(indicator["explanation"] for indicator in result["indicators"])
        self.assertNotIn("safe", combined.lower())

    def test_security_module_does_not_import_network_or_database(self):
        source = (
            Path(__file__).resolve().parents[1] / "analyzers" / "email_security.py"
        ).read_text(encoding="utf-8")
        imports = "\n".join(
            line
            for line in source.splitlines()
            if line.startswith("import ") or line.startswith("from ")
        )
        self.assertNotIn("socket", imports)
        self.assertNotIn("urllib.request", imports)
        self.assertNotIn("requests", imports)
        self.assertNotIn("database", imports)
        self.assertNotIn("save_scan", source)


class TestEmailSecurityRoutes(unittest.TestCase):
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

    def test_indicator_evidence_is_escaped(self):
        raw = _email(
            [
                ("From", '"paypal.com <script>alert(\'test\')</script>" <attacker@example.net>'),
                ("To", "user@example.com"),
                ("Subject", "Hello"),
            ],
            "Hello.",
        )
        page = self.client.post("/analyze-email", data={"raw_email": raw}).get_data(as_text=True)
        self.assertIn("&lt;script&gt;", page)
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("|safe", page)

    def test_results_do_not_show_an_email_score(self):
        raw = _email(
            [
                ("From", "support@example.com"),
                ("To", "user@example.com"),
                ("Subject", "Hello"),
            ],
            "Hello Noora.",
        )
        page = self.client.post("/analyze-email", data={"raw_email": raw}).get_data(as_text=True)
        self.assertIn("Email Risk Score", page)
        self.assertIn("10", page)
        self.assertIn("/ 100", page)
        self.assertIn("Low Risk", page)
        self.assertIn("does not guarantee that the email is safe", page)
        self.assertNotIn("<span>0</span>", page)
