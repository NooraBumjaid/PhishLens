import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database.database import get_db_connection, init_db, save_scan


def sample_parsed(hostname="example.com", normalized_url="https://example.com"):
    """Build the URL fields that scan storage keeps."""
    return {
        "hostname": hostname,
        "normalized_url": normalized_url,
    }


def sample_risk(
    score=5,
    classification="Low Risk",
    indicators=None,
    correlations=None,
):
    """Build a completed risk result for storage tests."""
    return {
        "final_score": score,
        "classification": classification,
        "recommendation": "Test recommendation.",
        "indicators": indicators or [],
        "correlations": correlations or [],
    }


class TestDatabase(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def table_names(self):
        connection = get_db_connection()
        try:
            rows = connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        finally:
            connection.close()
        return {row["name"] for row in rows}

    def test_init_db_creates_tables(self):
        init_db()
        names = self.table_names()

        self.assertIn("scans", names)
        self.assertIn("indicators", names)
        self.assertIn("correlations", names)

    def test_save_basic_scan(self):
        init_db()
        save_scan(sample_parsed(), sample_risk(score=10, classification="Low Risk"))

        connection = get_db_connection()
        try:
            rows = connection.execute("SELECT * FROM scans").fetchall()
        finally:
            connection.close()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["target"], "example.com")
        self.assertEqual(rows[0]["scan_type"], "url")
        self.assertEqual(rows[0]["risk_score"], 10)
        self.assertEqual(rows[0]["classification"], "Low Risk")
        self.assertTrue(rows[0]["created_at"].endswith("+00:00"))

    def test_save_indicators_for_the_scan(self):
        init_db()
        indicators = [
            {
                "rule": "https_present",
                "title": "HTTPS detected",
                "score_change": -5,
                "severity": "positive",
                "explanation": "Encrypted.",
            },
            {
                "rule": "suspicious_keywords",
                "title": "Suspicious keywords detected",
                "score_change": 5,
                "severity": "warning",
                "explanation": "Login word.",
                "evidence": "Detected keywords: login",
            },
        ]
        scan_id = save_scan(sample_parsed(), sample_risk(indicators=indicators))

        connection = get_db_connection()
        try:
            rows = connection.execute(
                "SELECT * FROM indicators WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(len(rows), 2)
        self.assertEqual({row["rule_name"] for row in rows}, {"https_present", "suspicious_keywords"})
        self.assertTrue(all(row["scan_id"] == scan_id for row in rows))

    def test_save_correlation_for_the_scan(self):
        init_db()
        correlations = [
            {
                "rule": "ip_with_credentials",
                "title": "IP address combined with credential-related language",
                "score_change": 10,
                "explanation": "IP plus account language.",
            }
        ]
        scan_id = save_scan(sample_parsed(), sample_risk(correlations=correlations))

        connection = get_db_connection()
        try:
            rows = connection.execute(
                "SELECT * FROM correlations WHERE scan_id = ?",
                (scan_id,),
            ).fetchall()
        finally:
            connection.close()

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["scan_id"], scan_id)
        self.assertEqual(rows[0]["rule_name"], "ip_with_credentials")
        self.assertEqual(rows[0]["score_change"], 10)

    def test_save_scan_returns_an_integer_id(self):
        init_db()
        scan_id = save_scan(sample_parsed(), sample_risk())

        self.assertIsInstance(scan_id, int)
        self.assertGreater(scan_id, 0)

    def test_multiple_scans_keep_different_ids(self):
        init_db()
        first_id = save_scan(sample_parsed("example.com"), sample_risk(score=10))
        second_id = save_scan(sample_parsed("g00gle.com"), sample_risk(score=45, classification="Suspicious"))

        self.assertNotEqual(first_id, second_id)

        connection = get_db_connection()
        try:
            count = connection.execute("SELECT COUNT(*) AS total FROM scans").fetchone()["total"]
        finally:
            connection.close()

        self.assertEqual(count, 2)

    def test_parameterized_queries_store_sql_text_safely(self):
        init_db()
        hostile_text = "'; DROP TABLE scans; --"
        save_scan(
            sample_parsed(hostname=hostile_text, normalized_url=hostile_text),
            sample_risk(),
        )

        self.assertIn("scans", self.table_names())

        connection = get_db_connection()
        try:
            row = connection.execute("SELECT target, normalized_url FROM scans").fetchone()
        finally:
            connection.close()

        self.assertEqual(row["target"], hostile_text)
        self.assertEqual(row["normalized_url"], hostile_text)

    def test_indicator_cannot_reference_a_missing_scan(self):
        init_db()
        connection = get_db_connection()
        try:
            with self.assertRaises(sqlite3.IntegrityError):
                with connection:
                    connection.execute(
                        """
                        INSERT INTO indicators (scan_id, rule_name, title, score_change)
                        VALUES (?, ?, ?, ?)
                        """,
                        (999999, "fake_rule", "Fake indicator", 1),
                    )
        finally:
            connection.close()

        connection = get_db_connection()
        try:
            count = connection.execute("SELECT COUNT(*) AS total FROM indicators").fetchone()["total"]
        finally:
            connection.close()

        self.assertEqual(count, 0)

    def test_failed_indicator_insert_rolls_back_the_scan(self):
        init_db()
        indicators = [
            {
                "rule": "https_present",
                "title": None,
                "score_change": -5,
            }
        ]

        with self.assertRaises(sqlite3.IntegrityError):
            save_scan(sample_parsed(), sample_risk(indicators=indicators))

        connection = get_db_connection()
        try:
            count = connection.execute("SELECT COUNT(*) AS total FROM scans").fetchone()["total"]
        finally:
            connection.close()

        self.assertEqual(count, 0)


if __name__ == "__main__":
    unittest.main()
