import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from analyzers.email_analyzer import parse_email
from analyzers.email_security import analyze_email_security
from analyzers.url_analyzer import analyze_url
from database.database import init_db
from services.email_risk_engine import (
    HIGH_RISK,
    LOW_RISK,
    SUSPICIOUS,
    calculate_email_risk,
    classify_email_score,
)
from services.risk_engine import calculate_risk


def _email(headers, body="", content_type="text/plain"):
    lines = [f"{name}: {value}" for name, value in headers]
    lines.append("MIME-Version: 1.0")
    lines.append(f'Content-Type: {content_type}; charset="utf-8"')
    lines.append("")
    lines.append(body)
    return "\n".join(lines)


def _score(raw_email, attachments=None):
    parsed = parse_email(raw_email)
    if attachments is not None:
        parsed["attachments"] = attachments
    security = analyze_email_security(parsed)
    return calculate_email_risk(security["indicators"]), security


def _contribution(risk, rule_name):
    matches = [
        item
        for item in risk["indicator_contributions"]
        if item["rule_name"] == rule_name
    ]
    return matches


class TestEmailRiskScoring(unittest.TestCase):
    def test_simple_email_is_base_score_only(self):
        risk, security = _score(
            _email(
                [
                    ("From", "colleague@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "Meeting tomorrow"),
                ],
                "Hello Noora,\n\nThe meeting starts at 10 AM.",
            )
        )
        self.assertEqual(security["indicators"], [])
        self.assertEqual(risk["final_score"], 10)
        self.assertEqual(risk["classification"], LOW_RISK)
        self.assertIn("does not guarantee", risk["recommendation"])

    def test_urgency_alone_stays_low_risk(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "colleague@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "URGENT: Meeting changed"),
                ],
                "Hello Noora,\n\nThe room has changed.",
            )
        )
        self.assertEqual(_contribution(risk, "urgency_language")[0]["score_change"], 5)
        self.assertEqual(risk["final_score"], 15)
        self.assertEqual(risk["classification"], LOW_RISK)

    def test_greeting_and_financial_language_stay_low_risk(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "billing@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "Note"),
                ],
                "Dear customer,\n\nYour invoice is attached.",
            )
        )
        self.assertEqual(_contribution(risk, "generic_greeting")[0]["score_change"], 3)
        self.assertEqual(_contribution(risk, "financial_language")[0]["score_change"], 3)
        self.assertEqual(risk["final_score"], 16)
        self.assertEqual(risk["classification"], LOW_RISK)

    def test_suspicious_url_with_credentials(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "support@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "Update"),
                ],
                "Please login and verify your account:\nhttps://g00gle.com/login",
            )
        )
        self.assertEqual(_contribution(risk, "credential_language")[0]["score_change"], 10)
        self.assertEqual(
            _contribution(risk, "suspicious_embedded_link")[0]["score_change"], 20
        )
        correlations = [item["rule"] for item in risk["correlations"]]
        self.assertEqual(correlations.count("suspicious_link_with_credentials"), 1)
        self.assertEqual(risk["raw_score"], 55)
        self.assertEqual(risk["final_score"], 55)
        self.assertEqual(risk["classification"], SUSPICIOUS)

    def test_urgency_credentials_and_suspicious_url(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "support@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "URGENT: Account action required"),
                ],
                "Please login and verify your account:\nhttps://g00gle.com/login",
            )
        )
        self.assertEqual(_contribution(risk, "urgency_language")[0]["score_change"], 5)
        self.assertEqual(_contribution(risk, "credential_language")[0]["score_change"], 10)
        self.assertEqual(
            _contribution(risk, "suspicious_embedded_link")[0]["score_change"], 20
        )
        names = [item["rule"] for item in risk["correlations"]]
        self.assertIn("urgency_with_credentials", names)
        self.assertIn("suspicious_link_with_credentials", names)
        self.assertEqual(names.count("suspicious_link_with_credentials"), 1)
        self.assertEqual(risk["final_score"], 65)
        self.assertEqual(risk["classification"], HIGH_RISK)

    def test_reply_to_mismatch_with_credentials(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "support@example.com"),
                    ("To", "user@example.com"),
                    ("Reply-To", "security@different.example"),
                    ("Subject", "Account"),
                ],
                "Please verify your account.",
            )
        )
        self.assertEqual(_contribution(risk, "reply_to_mismatch")[0]["score_change"], 10)
        self.assertEqual(_contribution(risk, "credential_language")[0]["score_change"], 10)
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]],
            ["sender_mismatch_with_credentials"],
        )
        self.assertEqual(risk["final_score"], 40)
        self.assertEqual(risk["classification"], SUSPICIOUS)

    def test_displayed_link_mismatch_with_credentials(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "support@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "Sign in"),
                ],
                'Please sign in:\n<a href="https://evil.example/login">https://paypal.com</a>',
                content_type="text/html",
            )
        )
        self.assertEqual(_contribution(risk, "link_text_mismatch")[0]["score_change"], 20)
        self.assertEqual(_contribution(risk, "credential_language")[0]["score_change"], 10)
        names = [item["rule"] for item in risk["correlations"]]
        self.assertEqual(names.count("deceptive_link_with_credentials"), 1)
        self.assertEqual(risk["final_score"], 55)

    def test_risky_financial_attachment_correlates_once(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "billing@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "Invoice"),
                ],
                "Please review the attached invoice.",
            ),
            attachments=[
                {
                    "filename": "invoice.exe",
                    "content_type": "application/octet-stream",
                    "size": 4,
                }
            ],
        )
        self.assertIn("financial_language", {item["rule_name"] for item in risk["indicator_contributions"]})
        self.assertEqual(
            _contribution(risk, "risky_attachment_extension")[0]["score_change"], 20
        )
        names = [item["rule"] for item in risk["correlations"]]
        self.assertEqual(names.count("risky_attachment_with_financial_context"), 1)

    def test_reported_dmarc_failure_with_return_path_mismatch(self):
        risk, _security = _score(
            _email(
                [
                    ("From", "support@example.com"),
                    ("To", "user@example.com"),
                    ("Return-Path", "<bounce@different.example>"),
                    ("Subject", "Notice"),
                    ("Authentication-Results", "mx.example; dmarc=fail"),
                ],
                "Hello.",
            )
        )
        rules = {item["rule_name"] for item in risk["indicator_contributions"]}
        self.assertIn("dmarc_fail", rules)
        self.assertIn("return_path_mismatch", rules)
        names = [item["rule"] for item in risk["correlations"]]
        self.assertEqual(names.count("reported_auth_failure_with_sender_mismatch"), 1)
        self.assertIn("did not independently validate DMARC", risk["correlations"][0]["explanation"])

    def test_score_is_clamped_at_100(self):
        indicators = [
            {"rule_name": name, "title": name}
            for name in (
                "reply_to_mismatch",
                "return_path_mismatch",
                "display_name_deception",
                "urgency_language",
                "credential_language",
                "financial_language",
                "generic_greeting",
                "suspicious_embedded_link",
                "link_text_mismatch",
                "risky_attachment_extension",
                "misleading_double_extension",
                "spf_fail",
                "spf_softfail",
                "dkim_fail",
                "dmarc_fail",
            )
        ]
        risk = calculate_email_risk(indicators)
        self.assertGreater(risk["raw_score"], 100)
        self.assertEqual(risk["final_score"], 100)
        self.assertEqual(risk["classification"], HIGH_RISK)

    def test_classification_boundaries(self):
        self.assertEqual(classify_email_score(0), LOW_RISK)
        self.assertEqual(classify_email_score(30), LOW_RISK)
        self.assertEqual(classify_email_score(31), SUSPICIOUS)
        self.assertEqual(classify_email_score(60), SUSPICIOUS)
        self.assertEqual(classify_email_score(61), HIGH_RISK)
        self.assertEqual(classify_email_score(100), HIGH_RISK)

    def test_unknown_indicator_contributes_zero(self):
        risk = calculate_email_risk(
            [{"rule_name": "future_rule", "title": "A future signal"}]
        )
        self.assertEqual(risk["indicator_contributions"][0]["score_change"], 0)
        self.assertEqual(risk["indicator_contributions"][0]["title"], "A future signal")
        self.assertEqual(risk["final_score"], 10)

    def test_repeated_evidence_does_not_repeat_the_correlation(self):
        risk, security = _score(
            _email(
                [
                    ("From", "support@example.com"),
                    ("To", "user@example.com"),
                    ("Subject", "Account"),
                ],
                (
                    "Please login with your password and verify account.\n"
                    "https://g00gle.com/login\n"
                    "https://g00gle.com/verify"
                ),
            )
        )
        suspicious = [
            item
            for item in security["indicators"]
            if item["rule_name"] == "suspicious_embedded_link"
        ]
        self.assertEqual(len(suspicious), 1)
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]].count(
                "suspicious_link_with_credentials"
            ),
            1,
        )
        self.assertEqual(_contribution(risk, "credential_language")[0]["score_change"], 10)
        self.assertEqual(
            _contribution(risk, "suspicious_embedded_link")[0]["score_change"], 20
        )
        self.assertEqual(risk["final_score"], 55)

    def test_email_analysis_does_not_insert_url_history(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "scans.db"
            with patch("database.database.DB_PATH", db_path):
                init_db()
                connection = sqlite3.connect(db_path)
                try:
                    before = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                finally:
                    connection.close()
                _score(
                    _email(
                        [
                            ("From", "support@example.com"),
                            ("To", "user@example.com"),
                            ("Subject", "Update"),
                        ],
                        "Please login:\nhttps://g00gle.com/login",
                    )
                )
                connection = sqlite3.connect(db_path)
                try:
                    after = connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
                finally:
                    connection.close()
        self.assertEqual(before, 0)
        self.assertEqual(after, 0)

    def test_scoring_module_does_not_import_network_libraries(self):
        source = (
            Path(__file__).resolve().parents[1] / "services" / "email_risk_engine.py"
        ).read_text(encoding="utf-8")
        imports = "\n".join(
            line
            for line in source.splitlines()
            if line.startswith("import ") or line.startswith("from ")
        )
        self.assertNotIn("socket", imports)
        self.assertNotIn("urllib", imports)
        self.assertNotIn("requests", imports)

    def test_url_analyzer_scores_stay_unchanged(self):
        cases = (
            ("https://example.com/login", 10, "Low Risk"),
            ("https://g00gle.com/login", 45, "Suspicious"),
            ("http://192.168.1.10:8080/account/verify/password", 75, "High Risk"),
        )
        for url, score, classification in cases:
            risk = calculate_risk(analyze_url(url)["indicators"])
            self.assertEqual(risk["final_score"], score, url)
            self.assertEqual(risk["classification"], classification, url)
