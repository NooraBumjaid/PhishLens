import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from app import app
from database.database import (
    get_db_connection,
    get_dashboard_summary,
    get_recent_activity,
    get_recent_scans,
    get_top_indicators,
    init_db,
    save_email_scan,
    save_scan,
)
from tests.support import make_client, sample_parsed, sample_risk


def sample_email(subject="Account notice", from_addr="alerts@example.com"):
    return {
        "headers": {
            "from": from_addr,
            "to": "user@example.com",
            "subject": subject,
            "date": "Sat, 03 Oct 2026 10:00:00 +0000",
        },
        "body_text": "Please review your account.",
        "urls": [],
        "attachments": [],
    }


def sample_email_security(indicators=None):
    return {"indicators": indicators or []}


def sample_email_risk(score=65, classification="High Risk", contributions=None):
    return {
        "final_score": score,
        "classification": classification,
        "recommendation": "Treat with caution.",
        "base_score": 10,
        "raw_score": score,
        "indicator_contributions": contributions or [],
        "correlations": [],
    }


def set_created_at(scan_id, when):
    connection = get_db_connection()
    try:
        with connection:
            connection.execute(
                "UPDATE scans SET created_at = ? WHERE id = ?",
                (when.isoformat(), scan_id),
            )
    finally:
        connection.close()


class TestDashboard(unittest.TestCase):
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

    def test_empty_dashboard(self):
        response = self.client.get("/dashboard")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("PhishLens | Security Dashboard", page)
        self.assertIn("Total Scans", page)
        self.assertIn("URL Scans", page)
        self.assertIn("Email Scans", page)
        self.assertIn("Average Risk Score", page)
        self.assertRegex(page, r"Total Scans[\s\S]*?>0<")
        self.assertIn("—", page)
        self.assertIn("No analyses yet", page)
        self.assertIn("Analyze a URL", page)
        self.assertIn("Analyze an Email", page)
        self.assertNotIn("Risk Distribution", page)
        self.assertNotIn('class="risk-donut"', page)

    def test_summary_and_risk_distribution(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(10, "Low Risk"))
        save_scan(
            sample_parsed("g00gle.com", "https://g00gle.com/login"),
            sample_risk(45, "Suspicious"),
        )
        save_email_scan(
            sample_email("URGENT: Account action required"),
            sample_email_security(),
            sample_email_risk(65, "High Risk"),
        )

        summary = get_dashboard_summary()
        page = self.client.get("/dashboard").get_data(as_text=True)

        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["url_scans"], 2)
        self.assertEqual(summary["email_scans"], 1)
        self.assertEqual(summary["average_risk"], 40)
        self.assertEqual(summary["low_risk"], 1)
        self.assertEqual(summary["suspicious"], 1)
        self.assertEqual(summary["high_risk"], 1)
        self.assertIn("40", page)
        self.assertIn("/ 100", page)
        self.assertIn("Low Risk", page)
        self.assertIn("Suspicious", page)
        self.assertIn("High Risk", page)
        self.assertIn("View Full Scan History", page)
        self.assertIn('href="/history"', page)

    def test_top_indicators_use_distinct_scan_count(self):
        init_db()
        indicator = {
            "rule": "possible_typosquatting",
            "title": "Possible Domain Impersonation",
            "score_change": 20,
            "severity": "warning",
            "explanation": "Looks like a known brand.",
            "evidence": "g00gle.com",
        }
        scan_a = save_scan(
            sample_parsed("g00gle.com", "https://g00gle.com/login"),
            sample_risk(45, "Suspicious", indicators=[indicator, indicator]),
        )
        save_scan(
            sample_parsed("go0gle.com", "https://go0gle.com"),
            sample_risk(45, "Suspicious", indicators=[indicator]),
        )
        save_email_scan(
            sample_email("Reset password"),
            sample_email_security(
                [
                    {
                        "rule_name": "credential_language",
                        "title": "Credential-related language",
                        "severity": "warning",
                        "explanation": "Mentions passwords.",
                        "evidence": "password",
                    }
                ]
            ),
            sample_email_risk(
                40,
                "Suspicious",
                contributions=[
                    {"rule_name": "credential_language", "score_change": 10}
                ],
            ),
        )

        top = get_top_indicators(limit=5)
        page = self.client.get("/dashboard").get_data(as_text=True)

        self.assertEqual(top[0]["rule_name"], "possible_typosquatting")
        self.assertEqual(top[0]["scan_count"], 2)
        self.assertEqual(top[0]["title"], "Possible Domain Impersonation")
        self.assertEqual(top[0]["source_type"], "URL")
        self.assertIn("Possible Domain Impersonation", page)
        self.assertIn("2 scans", page)
        self.assertIn("Credential-related language", page)
        self.assertNotIn("possible_typosquatting", page)
        self.assertIsNotNone(scan_a)

    def test_recent_activity_includes_zero_days(self):
        init_db()
        now = datetime.now(timezone.utc)
        first = save_scan(sample_parsed("a.example"), sample_risk(10, "Low Risk"))
        second = save_scan(sample_parsed("b.example"), sample_risk(10, "Low Risk"))
        third = save_scan(sample_parsed("c.example"), sample_risk(10, "Low Risk"))
        set_created_at(first, now - timedelta(days=6))
        set_created_at(second, now - timedelta(days=6))
        set_created_at(third, now - timedelta(days=2))

        activity = get_recent_activity(days=7)

        self.assertEqual(len(activity), 7)
        self.assertEqual(activity[0]["total"], 2)
        self.assertEqual(activity[1]["total"], 0)
        self.assertEqual(activity[4]["total"], 1)
        self.assertEqual(sum(item["total"] for item in activity), 3)
        page = self.client.get("/dashboard").get_data(as_text=True)
        self.assertIn("Analysis Activity", page)
        self.assertIn("UTC", page)

    def test_recent_scans_limit_and_order(self):
        init_db()
        now = datetime.now(timezone.utc)
        ids = []
        for index in range(7):
            scan_id = save_scan(
                sample_parsed(f"host{index}.example"),
                sample_risk(10 + index, "Low Risk"),
            )
            set_created_at(scan_id, now - timedelta(minutes=7 - index))
            ids.append(scan_id)

        recent = get_recent_scans(limit=5)
        page = self.client.get("/dashboard").get_data(as_text=True)

        self.assertEqual(len(recent), 5)
        self.assertEqual([row["id"] for row in recent], list(reversed(ids[-5:])))
        self.assertIn("host6.example", page)
        self.assertIn("host2.example", page)
        self.assertNotIn("host0.example", page)
        self.assertNotIn("host1.example", page)

    def test_dashboard_escapes_user_content_and_urls_are_not_links(self):
        init_db()
        save_scan(
            sample_parsed("g00gle.com", "https://g00gle.com/login"),
            sample_risk(45, "Suspicious"),
        )
        save_email_scan(
            sample_email("<script>alert('dashboard')</script>"),
            sample_email_security(),
            sample_email_risk(65, "High Risk"),
        )

        page = self.client.get("/dashboard").get_data(as_text=True)

        self.assertIn("https://g00gle.com/login", page)
        self.assertNotIn('href="https://g00gle.com/login"', page)
        self.assertNotIn("<script>alert('dashboard')</script>", page)
        self.assertIn("&lt;script&gt;alert(&#39;dashboard&#39;)&lt;/script&gt;", page)
        self.assertIn('href="/scan/', page)
        self.assertIn(">View<", page)

    def test_no_indicators_message_when_scans_exist(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(10, "Low Risk"))

        page = self.client.get("/dashboard").get_data(as_text=True)

        self.assertIn("No security indicators have been recorded yet.", page)
        self.assertIn("Recent Analyses", page)

    def test_nav_and_landing_include_dashboard(self):
        home = self.client.get("/").get_data(as_text=True)
        dashboard = self.client.get("/dashboard").get_data(as_text=True)

        self.assertIn("Security Dashboard", home)
        self.assertIn("Open Dashboard", home)
        self.assertIn('href="/dashboard"', home)
        self.assertIn("View analysis activity, risk trends, and recent PhishLens results.", home)
        self.assertIn(">Dashboard<", dashboard)
        self.assertIn(">Scan History<", dashboard)
        self.assertIn('href="/history"', dashboard)


if __name__ == "__main__":
    unittest.main()
