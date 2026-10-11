import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app
from database.database import (
    get_db_connection,
    get_scan_by_id,
    get_scan_statistics,
    get_scans,
    init_db,
    migrate_db,
    save_email_scan,
    save_scan,
)
from tests.support import make_client, sample_parsed as sample_url_parsed, sample_risk as sample_url_risk


MEETING_EMAIL = """\
From: colleague@example.com
To: noora@example.com
Subject: Meeting tomorrow

Hello Noora,

The meeting starts at 10 AM.
"""

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
Subject: <script>alert('history')</script>

Hello.
"""


def create_legacy_url_database(db_path):
    """Create a pre-Step-20 scans table with one URL row."""
    connection = sqlite3.connect(db_path)
    try:
        connection.executescript(
            """
            CREATE TABLE scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                normalized_url TEXT,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                recommendation TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                score_change INTEGER NOT NULL,
                severity TEXT,
                explanation TEXT,
                evidence TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                score_change INTEGER NOT NULL,
                explanation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            """
        )
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
                "Legacy recommendation.",
                "2026-01-01T00:00:00+00:00",
            ),
        )
        connection.commit()
    finally:
        connection.close()


class TestEmailHistory(unittest.TestCase):
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

    def _all_text_from_database(self):
        connection = get_db_connection()
        try:
            chunks = []
            for table in ("scans", "indicators", "correlations", "email_links", "email_attachments"):
                rows = connection.execute(f"SELECT * FROM {table}").fetchall()
                for row in rows:
                    for value in dict(row).values():
                        if value is not None:
                            chunks.append(str(value))
            return "\n".join(chunks)
        finally:
            connection.close()

    def test_simple_email_is_saved_without_body(self):
        response = self.client.post("/analyze-email", data={"raw_email": MEETING_EMAIL})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("10/100", page)
        self.assertIn("Low Risk", page)

        connection = get_db_connection()
        try:
            rows = connection.execute("SELECT * FROM scans").fetchall()
        finally:
            connection.close()

        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["scan_type"], "email")
        self.assertEqual(row["email_subject"], "Meeting tomorrow")
        self.assertEqual(row["email_from"], "colleague@example.com")
        self.assertEqual(row["risk_score"], 10)
        self.assertEqual(row["classification"], "Low Risk")
        self.assertNotIn("The meeting starts at 10 AM.", self._all_text_from_database())

    def test_suspicious_email_stores_score_indicators_and_links(self):
        response = self.client.post("/analyze-email", data={"raw_email": URGENT_EMAIL})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("65/100", page)
        self.assertIn("High Risk", page)

        connection = get_db_connection()
        try:
            scan = connection.execute("SELECT * FROM scans").fetchone()
            indicators = connection.execute("SELECT * FROM indicators").fetchall()
            correlations = connection.execute("SELECT * FROM correlations").fetchall()
            links = connection.execute("SELECT * FROM email_links").fetchall()
        finally:
            connection.close()

        self.assertEqual(scan["scan_type"], "email")
        self.assertEqual(scan["risk_score"], 65)
        self.assertEqual(scan["classification"], "High Risk")
        self.assertEqual(scan["base_score"], 10)
        self.assertEqual(scan["raw_score"], 65)
        self.assertGreaterEqual(len(indicators), 3)
        self.assertGreaterEqual(len(correlations), 2)
        self.assertEqual(len(links), 1)
        self.assertEqual(links[0]["url_text"], "https://g00gle.com/login")
        self.assertEqual(links[0]["risk_score"], 45)
        self.assertEqual(links[0]["classification"], "Suspicious")

    def test_history_shows_url_and_email_with_type_badges(self):
        init_db()
        save_scan(sample_url_parsed("g00gle.com"), sample_url_risk(45, "Suspicious"))
        self.client.post("/analyze-email", data={"raw_email": MEETING_EMAIL})

        page = self.client.get("/history").get_data(as_text=True)

        self.assertIn("g00gle.com", page)
        self.assertIn("Meeting tomorrow", page)
        self.assertIn(">URL</span>", page)
        self.assertIn(">EMAIL</span>", page)
        self.assertIn("URL Scans:", page)
        self.assertIn("Email Scans:", page)

    def test_type_filter_separates_url_and_email(self):
        init_db()
        save_scan(sample_url_parsed("url-host.test"), sample_url_risk(10, "Low Risk"))
        self.client.post("/analyze-email", data={"raw_email": MEETING_EMAIL})

        url_page = self.client.get("/history", query_string={"type": "url"}).get_data(as_text=True)
        email_page = self.client.get("/history", query_string={"type": "email"}).get_data(as_text=True)
        all_page = self.client.get("/history").get_data(as_text=True)

        self.assertIn("url-host.test", url_page)
        self.assertNotIn("Meeting tomorrow", url_page)
        self.assertIn("Meeting tomorrow", email_page)
        self.assertNotIn("url-host.test", email_page)
        self.assertIn("url-host.test", all_page)
        self.assertIn("Meeting tomorrow", all_page)

    def test_combined_filters_preserve_query_parameters(self):
        init_db()
        for number in range(12):
            self.client.post(
                "/analyze-email",
                data={
                    "raw_email": (
                        f"From: support@example.com\n"
                        f"To: user@example.com\n"
                        f"Subject: URGENT item {number}\n\n"
                        "Please login and verify your account:\n"
                        "https://g00gle.com/login\n"
                    )
                },
            )
        save_scan(sample_url_parsed("other.example"), sample_url_risk(45, "Suspicious"))

        response = self.client.get(
            "/history",
            query_string={
                "q": "urgent",
                "classification": "High Risk",
                "type": "email",
                "page": 2,
            },
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Page 2 of 2", page)
        self.assertIn("q=urgent", page)
        self.assertIn("classification=High+Risk", page)
        self.assertIn("type=email", page)
        self.assertIn("URGENT item", page)
        self.assertNotIn("other.example", page)

    def test_email_saved_details_use_stored_result_without_reanalysis(self):
        response = self.client.post("/analyze-email", data={"raw_email": URGENT_EMAIL})
        self.assertEqual(response.status_code, 200)
        scan_id = get_scans(scan_type="email")[0]["id"]

        with (
            patch("app.parse_email") as parse_email,
            patch("app.analyze_email_security") as analyze_security,
            patch("app.calculate_email_risk") as calculate_risk,
        ):
            detail = self.client.get(f"/scan/{scan_id}")
            page = detail.get_data(as_text=True)

            parse_email.assert_not_called()
            analyze_security.assert_not_called()
            calculate_risk.assert_not_called()

        self.assertEqual(detail.status_code, 200)
        self.assertIn("65/100", page)
        self.assertIn("High Risk", page)
        self.assertIn("has not been re-analyzed", page)
        self.assertIn("Stored Email Metadata", page)
        self.assertIn("does not retain the full email body", page)
        self.assertIn("View Full Analysis Report", page)
        self.assertIn('<details class="full-analysis-details">', page)
        self.assertIn('class="full-analysis-summary"', page)
        self.assertIn('id="email-full-analysis"', page)
        self.assertIn("Email Score Breakdown", page)
        self.assertNotIn('<details class="full-analysis-details" open', page)
        self.assertIn("/static/js/ui.js", page)
        csp = detail.headers.get("Content-Security-Policy", "")
        self.assertIn("script-src 'self'", csp)
        self.assertNotIn("unsafe-inline", csp.split("script-src", 1)[-1].split(";", 1)[0])
        self.assertNotIn("onclick=", page.lower())

    def test_body_secret_is_not_stored(self):
        self.client.post("/analyze-email", data={"raw_email": PRIVACY_EMAIL})
        stored = self._all_text_from_database()

        self.assertNotIn("BODY_SECRET_12345", stored)
        self.assertNotIn("<html", stored.lower())

    def test_xss_subject_is_escaped_in_history_and_detail(self):
        self.client.post("/analyze-email", data={"raw_email": XSS_EMAIL})
        scan_id = get_scans(scan_type="email")[0]["id"]

        history_page = self.client.get("/history").get_data(as_text=True)
        detail_page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)

        self.assertNotIn("<script>alert('history')</script>", history_page)
        self.assertNotIn("<script>alert('history')</script>", detail_page)
        self.assertIn("&lt;script&gt;", history_page)
        self.assertIn("&lt;script&gt;", detail_page)

    def test_stored_embedded_url_is_not_clickable(self):
        self.client.post("/analyze-email", data={"raw_email": URGENT_EMAIL})
        scan_id = get_scans(scan_type="email")[0]["id"]
        page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)

        self.assertIn("https://g00gle.com/login", page)
        self.assertNotIn('href="https://g00gle.com/login"', page)

    def test_legacy_database_migration_is_idempotent(self):
        create_legacy_url_database(self.db_path)

        init_db()
        connection = get_db_connection()
        try:
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(scans)").fetchall()
            }
            tables = {
                row["name"]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                ).fetchall()
            }
            legacy = connection.execute(
                "SELECT target, risk_score FROM scans WHERE target = ?",
                ("legacy.example",),
            ).fetchone()
        finally:
            connection.close()

        self.assertIn("email_from", columns)
        self.assertIn("email_subject", columns)
        self.assertIn("base_score", columns)
        self.assertIn("raw_score", columns)
        self.assertIn("email_links", tables)
        self.assertIn("email_attachments", tables)
        self.assertEqual(legacy["target"], "legacy.example")
        self.assertEqual(legacy["risk_score"], 10)

        migrate_db()
        migrate_db()
        self.assertEqual(get_scan_statistics()["total"], 1)
        self.assertEqual(get_scan_by_id(1)["scan"]["target"], "legacy.example")

    def test_search_matches_email_subject_and_sender(self):
        self.client.post("/analyze-email", data={"raw_email": MEETING_EMAIL})
        self.client.post("/analyze-email", data={"raw_email": URGENT_EMAIL})

        by_subject = get_scans(search="Meeting")
        by_sender = get_scans(search="support@example.com")

        self.assertEqual(len(by_subject), 1)
        self.assertEqual(by_subject[0]["email_subject"], "Meeting tomorrow")
        self.assertEqual(len(by_sender), 1)
        self.assertEqual(by_sender[0]["email_from"], "support@example.com")

    def test_failed_email_save_does_not_leave_a_scan_row(self):
        init_db()
        from analyzers.email_analyzer import parse_email
        from analyzers.email_security import analyze_email_security
        from services.email_risk_engine import calculate_email_risk

        parsed = parse_email(URGENT_EMAIL)
        security = analyze_email_security(parsed)
        risk = calculate_email_risk(security["indicators"])
        self.assertTrue(security["indicators"])

        real_get_db_connection = get_db_connection

        class FailingConnection:
            def __init__(self, connection):
                self._connection = connection

            def __enter__(self):
                self._connection.__enter__()
                return self

            def __exit__(self, exc_type, exc, traceback):
                return self._connection.__exit__(exc_type, exc, traceback)

            def execute(self, sql, params=()):
                if "INSERT INTO indicators" in sql:
                    raise sqlite3.Error("boom")
                return self._connection.execute(sql, params)

            def close(self):
                self._connection.close()

        def failing_get_db_connection():
            return FailingConnection(real_get_db_connection())

        with patch("database.database.get_db_connection", side_effect=failing_get_db_connection):
            with self.assertRaises(sqlite3.Error):
                save_email_scan(parsed, security, risk)

        self.assertEqual(get_scan_statistics()["total"], 0)


if __name__ == "__main__":
    unittest.main()
