import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from database.database import (
    count_scans,
    get_all_scans,
    get_db_connection,
    get_scan_by_id,
    get_scan_statistics,
    get_scans,
    init_db,
    save_scan,
)
from tests.support import sample_parsed, sample_risk as _shared_risk


def sample_risk(
    score=5,
    classification="Low Risk",
    indicators=None,
    correlations=None,
):
    """Storage-test risk payload (default score 5, storage recommendation)."""
    return _shared_risk(
        score=score,
        classification=classification,
        indicators=indicators,
        correlations=correlations,
        recommendation="Test recommendation.",
    )


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
        self.assertEqual(rows[0]["target"], "https://example.com")
        self.assertEqual(rows[0]["scan_type"], "url")
        self.assertEqual(rows[0]["risk_score"], 10)
        self.assertEqual(rows[0]["classification"], "Low Risk")
        self.assertTrue(rows[0]["created_at"].endswith("+00:00"))

    def test_url_coverage_fields_are_stored_and_nullable(self):
        init_db()
        limited = sample_risk(score=25, classification="Low Risk")
        limited["analysis_coverage"] = "limited"
        limited["destination_status"] = "hidden"
        limited_id = save_scan(
            sample_parsed("linkr.it", "https://linkr.it/gKin2"),
            limited,
        )
        legacy_id = save_scan(sample_parsed(), sample_risk(score=10))

        limited_record = get_scan_by_id(limited_id)["scan"]
        legacy_record = get_scan_by_id(legacy_id)["scan"]

        self.assertEqual(limited_record["analysis_coverage"], "limited")
        self.assertEqual(limited_record["destination_status"], "hidden")
        self.assertIsNone(legacy_record["analysis_coverage"])
        self.assertIsNone(legacy_record["destination_status"])

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

    def test_get_all_scans_returns_newest_first(self):
        init_db()
        first_id = save_scan(sample_parsed("example.com"), sample_risk(score=10, classification="Low Risk"))
        second_id = save_scan(sample_parsed("g00gle.com"), sample_risk(score=45, classification="Suspicious"))

        scans = get_all_scans()

        self.assertEqual([scan["id"] for scan in scans], [second_id, first_id])
        self.assertEqual(scans[0]["target"], "https://g00gle.com")
        self.assertEqual(scans[1]["classification"], "Low Risk")

    def test_get_scan_by_id_returns_related_rows(self):
        init_db()
        indicators = [
            {
                "rule": "https_present",
                "title": "HTTPS detected",
                "score_change": -5,
                "severity": "positive",
                "explanation": "Encrypted connection.",
                "evidence": "Scheme is https",
            }
        ]
        correlations = [
            {
                "rule": "impersonation_with_credentials",
                "title": "Domain impersonation combined with credential-related language",
                "score_change": 15,
                "explanation": "Lookalike plus login language.",
            }
        ]
        scan_id = save_scan(
            sample_parsed("g00gle.com", "https://g00gle.com/login"),
            sample_risk(score=45, classification="Suspicious", indicators=indicators, correlations=correlations),
        )

        record = get_scan_by_id(scan_id)

        self.assertEqual(record["scan"]["id"], scan_id)
        self.assertEqual(record["scan"]["risk_score"], 45)
        self.assertEqual(record["scan"]["classification"], "Suspicious")
        self.assertEqual(record["indicators"][0]["scan_id"], scan_id)
        self.assertEqual(record["indicators"][0]["title"], "HTTPS detected")
        self.assertEqual(record["indicators"][0]["evidence"], "Scheme is https")
        self.assertEqual(record["correlations"][0]["scan_id"], scan_id)
        self.assertEqual(record["correlations"][0]["score_change"], 15)

    def test_get_scan_by_id_returns_none_when_missing(self):
        init_db()

        self.assertIsNone(get_scan_by_id(999999))

    def test_get_scan_statistics_counts_each_classification(self):
        init_db()
        save_scan(sample_parsed("one.example"), sample_risk(classification="Low Risk"))
        save_scan(sample_parsed("two.example"), sample_risk(classification="Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))
        save_scan(sample_parsed("bit.ly"), sample_risk(45, "Suspicious"))
        save_scan(sample_parsed("192.168.1.10"), sample_risk(75, "High Risk"))

        self.assertEqual(
            get_scan_statistics(),
            {
                "total": 5,
                "low_risk": 2,
                "suspicious": 2,
                "high_risk": 1,
                "url_scans": 5,
                "email_scans": 0,
            },
        )

    def test_search_matches_a_target_substring(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(classification="Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))
        save_scan(sample_parsed("192.168.1.10"), sample_risk(75, "High Risk"))

        self.assertEqual(
            [scan["target"] for scan in get_scans(search="example")],
            ["https://example.com"],
        )
        self.assertEqual(
            [scan["target"] for scan in get_scans(search="192.168")],
            ["https://192.168.1.10"],
        )

    def test_classification_filter_returns_only_that_class(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(classification="Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))
        save_scan(sample_parsed("192.168.1.10"), sample_risk(75, "High Risk"))

        matches = get_scans(classification="Suspicious")

        self.assertEqual([scan["target"] for scan in matches], ["https://g00gle.com"])

    def test_search_and_classification_apply_together(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(classification="Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))
        save_scan(sample_parsed("login.example"), sample_risk(40, "Suspicious"))

        matches = get_scans(search="g00gle", classification="Suspicious")

        self.assertEqual([scan["target"] for scan in matches], ["https://g00gle.com"])

    def test_invalid_classification_falls_back_to_all(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(classification="Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))

        self.assertEqual(
            [scan["target"] for scan in get_scans(classification="INVALID")],
            [scan["target"] for scan in get_scans()],
        )

    def test_sql_like_search_text_does_not_return_every_scan(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(classification="Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))
        save_scan(sample_parsed("192.168.1.10"), sample_risk(75, "High Risk"))

        matches = get_scans(search="' OR 1=1 --")

        self.assertEqual(matches, [])
        self.assertEqual(get_scan_statistics()["total"], 3)
        self.assertIn("scans", self.table_names())

    def _save_numbered_scans(self, count, target_prefix="host", classification="Low Risk"):
        scan_ids = []
        for number in range(1, count + 1):
            scan_ids.append(
                save_scan(
                    sample_parsed(f"{target_prefix}-{number}"),
                    sample_risk(classification=classification),
                )
            )
        return scan_ids

    def test_get_scans_returns_distinct_pages_newest_first(self):
        init_db()
        self._save_numbered_scans(25)

        page_one = get_scans(page=1, per_page=10)
        page_two = get_scans(page=2, per_page=10)
        page_three = get_scans(page=3, per_page=10)
        ids = [scan["id"] for scan in page_one + page_two + page_three]

        self.assertEqual(len(page_one), 10)
        self.assertEqual(len(page_two), 10)
        self.assertEqual(len(page_three), 5)
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(ids, sorted(ids, reverse=True))

    def test_count_scans_respects_search_and_classification(self):
        init_db()
        self._save_numbered_scans(20, target_prefix="example", classification="Low Risk")
        self._save_numbered_scans(3, target_prefix="g00gle", classification="Suspicious")
        self._save_numbered_scans(2, target_prefix="other", classification="High Risk")

        self.assertEqual(count_scans(), 25)
        self.assertEqual(count_scans(classification="Suspicious"), 3)
        self.assertEqual(count_scans(search="example"), 20)
        self.assertEqual(count_scans(search="g00gle", classification="Suspicious"), 3)
        self.assertEqual(get_scan_statistics()["total"], 25)


if __name__ == "__main__":
    unittest.main()
