import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app, format_scan_timestamp
from database.database import init_db, save_scan
from tests.support import make_client, sample_parsed, sample_risk


class TestHistoryRoutes(unittest.TestCase):
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

    def test_history_page_loads(self):
        response = self.client.get("/history")

        self.assertEqual(response.status_code, 200)

    def test_empty_history_shows_empty_state(self):
        response = self.client.get("/history")
        page = response.get_data(as_text=True)

        self.assertIn("No scans have been saved yet", page)
        self.assertIn("Analyze a URL", page)
        self.assertNotIn("Page 1 of 0", page)
        self.assertNotIn('class="pagination"', page)
        self.assertIn('class="stat-value">0</p>', page)

    def test_history_lists_saved_scans(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(10, "Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))

        page = self.client.get("/history").get_data(as_text=True)

        self.assertIn("example.com", page)
        self.assertIn("g00gle.com", page)
        self.assertIn("Low Risk", page)
        self.assertIn("Suspicious", page)
        self.assertLess(page.index("g00gle.com"), page.index("example.com"))

    def test_scan_detail_shows_stored_result(self):
        init_db()
        scan_id = save_scan(
            sample_parsed("192.168.1.10", "http://192.168.1.10/account/verify"),
            sample_risk(
                60,
                "Suspicious",
                indicators=[
                    {
                        "rule": "ip_hostname",
                        "title": "IP address used instead of domain",
                        "score_change": 20,
                        "severity": "warning",
                        "explanation": "The hostname is an IP address.",
                        "evidence": "Hostname is an IP address",
                    }
                ],
                correlations=[
                    {
                        "rule": "ip_with_credentials",
                        "title": "IP address combined with credential-related language",
                        "score_change": 10,
                        "explanation": "IP plus account language.",
                    }
                ],
            ),
        )

        response = self.client.get(f"/scan/{scan_id}")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("60/100", page)
        self.assertIn("Suspicious", page)
        self.assertIn("IP address used instead of domain", page)
        self.assertIn("Hostname is an IP address", page)
        self.assertIn("IP address combined with credential-related language", page)
        self.assertIn("Stored Analysis", page)
        self.assertIn("Not rechecked", page)
        self.assertNotIn(
            "This page displays the result stored when the scan was originally performed",
            page,
        )
        self.assertNotIn(f'href="http://192.168.1.10', page)

    def test_opening_a_saved_scan_does_not_create_another_row(self):
        init_db()
        scan_id = save_scan(sample_parsed(), sample_risk())

        self.client.get(f"/scan/{scan_id}")
        self.client.get(f"/scan/{scan_id}")

        from database.database import get_all_scans

        self.assertEqual(len(get_all_scans()), 1)

    def test_missing_scan_returns_404(self):
        response = self.client.get("/scan/999999")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 404)
        self.assertIn("Scan not found", page)
        self.assertIn("Back to Scan History", page)

    def test_regression_scans_appear_newest_first_without_new_rows_on_refresh(self):
        urls = [
            ("https://example.com/login", "Low Risk"),
            ("https://g00gle.com/login", "Suspicious"),
            ("http://192.168.1.10:8080/account/verify/password", "High Risk"),
        ]
        for url, classification in urls:
            response = self.client.post("/analyze", data={"url": url})
            self.assertEqual(response.status_code, 200)
            self.assertIn(classification, response.get_data(as_text=True))

        history = self.client.get("/history").get_data(as_text=True)
        self.assertLess(history.index("192.168.1.10"), history.index("g00gle.com"))
        self.assertLess(history.index("g00gle.com"), history.index("example.com"))

        from database.database import get_all_scans

        scans = get_all_scans()
        self.assertEqual([scan["risk_score"] for scan in scans], [75, 45, 10])
        before = len(scans)
        self.client.get(f"/scan/{scans[0]['id']}")
        self.assertEqual(len(get_all_scans()), before)

    def test_history_and_detail_show_readable_utc_without_changing_storage(self):
        init_db()
        scan_id = save_scan(sample_parsed("example.com"), sample_risk())

        from database.database import get_scan_by_id

        stored = get_scan_by_id(scan_id)["scan"]["created_at"]
        shown = format_scan_timestamp(stored)
        history_page = self.client.get("/history").get_data(as_text=True)
        detail_page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)

        self.assertIn(shown, history_page)
        self.assertIn(shown, detail_page)
        self.assertNotIn(stored, history_page)
        self.assertNotIn(stored, detail_page)
        self.assertTrue(stored.endswith("+00:00"))
        self.assertEqual(get_scan_by_id(scan_id)["scan"]["created_at"], stored)

    def test_stored_html_is_escaped(self):
        init_db()
        hostile = "<script>alert('test')</script>"
        scan_id = save_scan(
            sample_parsed(hostile, hostile),
            sample_risk(
                indicators=[
                    {
                        "rule": "test_rule",
                        "title": hostile,
                        "score_change": 1,
                        "severity": "warning",
                        "explanation": hostile,
                        "evidence": hostile,
                    }
                ]
            ),
        )

        history_page = self.client.get("/history").get_data(as_text=True)
        detail_page = self.client.get(f"/scan/{scan_id}").get_data(as_text=True)

        self.assertNotIn(hostile, history_page)
        self.assertNotIn(hostile, detail_page)
        self.assertIn("&lt;script&gt;", history_page)
        self.assertIn("&lt;script&gt;", detail_page)

    def _save_sample_history(self):
        init_db()
        save_scan(sample_parsed("example.com"), sample_risk(10, "Low Risk"))
        save_scan(sample_parsed("g00gle.com"), sample_risk(45, "Suspicious"))
        save_scan(sample_parsed("192.168.1.10"), sample_risk(75, "High Risk"))

    def test_search_query_returns_matching_target(self):
        self._save_sample_history()

        response = self.client.get("/history", query_string={"q": "example"})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("example.com", page)
        self.assertNotIn("g00gle.com", page)
        self.assertNotIn("192.168.1.10", page)
        self.assertIn("Showing 1 of 1 matching scan.", page)
        self.assertIn('class="stat-value">3</p>', page)

    def test_classification_query_returns_that_class(self):
        self._save_sample_history()

        response = self.client.get("/history", query_string={"classification": "Suspicious"})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("g00gle.com", page)
        self.assertNotIn("example.com", page)
        self.assertNotIn("192.168.1.10", page)

    def test_search_and_classification_query_work_together(self):
        self._save_sample_history()

        response = self.client.get(
            "/history",
            query_string={"q": "g00gle", "classification": "Suspicious"},
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("g00gle.com", page)
        self.assertNotIn("example.com", page)
        self.assertIn('value="g00gle"', page)
        self.assertIn("Clear Filters", page)

    def test_invalid_classification_query_shows_every_scan(self):
        self._save_sample_history()

        response = self.client.get("/history", query_string={"classification": "INVALID"})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("example.com", page)
        self.assertIn("g00gle.com", page)
        self.assertIn("192.168.1.10", page)
        self.assertIn("Showing 1–3 of 3 scans.", page)

    def test_search_html_is_escaped(self):
        self._save_sample_history()
        hostile = "<script>alert('test')</script>"

        response = self.client.get("/history", query_string={"q": hostile})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(hostile, page)
        self.assertIn("&lt;script&gt;", page)

    def test_filtered_history_keeps_full_database_statistics(self):
        urls = [
            "https://example.com",
            "https://example.com/login",
            "https://g00gle.com/login",
            "https://bit.ly/account-verify",
            "http://192.168.1.10:8080/account/verify/password",
        ]
        for url in urls:
            response = self.client.post("/analyze", data={"url": url})
            self.assertEqual(response.status_code, 200)

        page = self.client.get("/history").get_data(as_text=True)
        self.assertIn('class="stat-value">5</p>', page)
        self.assertIn('class="stat-value">2</p>', page)
        self.assertIn('class="stat-value">1</p>', page)

        search_page = self.client.get("/history", query_string={"q": "g00gle"}).get_data(as_text=True)
        self.assertIn("g00gle.com", search_page)
        self.assertNotIn("bit.ly", search_page)
        self.assertIn('class="stat-value">5</p>', search_page)

        suspicious_page = self.client.get(
            "/history",
            query_string={"classification": "Suspicious"},
        ).get_data(as_text=True)
        self.assertIn("g00gle.com", suspicious_page)
        self.assertIn("bit.ly", suspicious_page)
        self.assertNotIn("example.com", suspicious_page)
        self.assertNotIn("192.168.1.10", suspicious_page)

        combined_page = self.client.get(
            "/history",
            query_string={"q": "bit.ly", "classification": "Suspicious"},
        ).get_data(as_text=True)
        self.assertIn("bit.ly", combined_page)
        self.assertNotIn("g00gle.com", combined_page)

        cleared_page = self.client.get("/history").get_data(as_text=True)
        self.assertIn("example.com", cleared_page)
        self.assertIn("g00gle.com", cleared_page)
        self.assertIn("bit.ly", cleared_page)
        self.assertIn("192.168.1.10", cleared_page)
        self.assertIn("Showing 1–5 of 5 scans.", cleared_page)

    def _save_numbered_scans(self, count, target_prefix="host", classification="Low Risk"):
        init_db()
        for number in range(1, count + 1):
            save_scan(
                sample_parsed(f"{target_prefix}-{number}.example"),
                sample_risk(classification=classification),
            )

    def test_history_page_count_rounds_up(self):
        from app import history_page_count

        self.assertEqual(history_page_count(0, 10), 0)
        self.assertEqual(history_page_count(1, 10), 1)
        self.assertEqual(history_page_count(10, 10), 1)
        self.assertEqual(history_page_count(11, 10), 2)
        self.assertEqual(history_page_count(20, 10), 2)
        self.assertEqual(history_page_count(21, 10), 3)

    def test_history_pages_preserve_classification(self):
        self._save_numbered_scans(15, target_prefix="lookalike", classification="Suspicious")
        save_scan(sample_parsed("example.com"), sample_risk(10, "Low Risk"))

        response = self.client.get(
            "/history",
            query_string={"classification": "Suspicious", "page": 2},
        )
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Showing 11–15 of 15 matching scans.", page)
        self.assertIn("lookalike-1.example", page)
        self.assertNotIn("lookalike-15.example", page)
        self.assertNotIn("example.com", page)
        self.assertIn("classification=Suspicious", page)
        self.assertIn("page=1", page)
        self.assertIn('class="stat-value">16</p>', page)
        self.assertNotIn(">example.com<", page)

    def test_history_pages_preserve_search(self):
        self._save_numbered_scans(15, target_prefix="test", classification="Low Risk")
        save_scan(sample_parsed("example.com"), sample_risk(10, "Low Risk"))

        response = self.client.get("/history", query_string={"q": "test", "page": 2})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Showing 11–15 of 15 matching scans.", page)
        self.assertIn("test-1.example", page)
        self.assertNotIn("example.com", page)
        self.assertIn("q=test", page)
        self.assertIn("page=1", page)
        self.assertNotIn("page=3", page)

    def test_history_pages_preserve_search_and_classification(self):
        self._save_numbered_scans(12, target_prefix="google", classification="Suspicious")
        save_scan(sample_parsed("google-low.example"), sample_risk(10, "Low Risk"))
        save_scan(sample_parsed("other.example"), sample_risk(45, "Suspicious"))

        first = self.client.get(
            "/history",
            query_string={"q": "google", "classification": "Suspicious", "page": 1},
        )
        second = self.client.get(
            "/history",
            query_string={"q": "google", "classification": "Suspicious", "page": 2},
        )
        first_page = first.get_data(as_text=True)
        second_page = second.get_data(as_text=True)

        self.assertEqual(second.status_code, 200)
        self.assertIn("Page 1 of 2", first_page)
        self.assertIn("page=2", first_page)
        self.assertIn("q=google", first_page)
        self.assertIn("classification=Suspicious", first_page)
        self.assertIn("Showing 11–12 of 12 matching scans.", second_page)
        self.assertIn("google-1.example", second_page)
        self.assertNotIn("google-12.example", second_page)
        self.assertNotIn("google-low.example", second_page)
        self.assertNotIn("other.example", second_page)
        self.assertIn("page=1", second_page)

    def test_invalid_history_pages_do_not_crash(self):
        self._save_numbered_scans(25)

        for bad_page in ("abc", "0", "-5", "<script>alert('test')</script>", "1 OR 1=1"):
            response = self.client.get("/history", query_string={"page": bad_page})
            page = response.get_data(as_text=True)
            self.assertEqual(response.status_code, 200, bad_page)
            self.assertIn("Page 1 of 3", page)
            self.assertIn("host-25.example", page)
            self.assertNotIn("<script>", page)
            self.assertNotIn("1 OR 1=1", page)

        last = self.client.get("/history", query_string={"page": "999999"})
        last_page = last.get_data(as_text=True)
        self.assertEqual(last.status_code, 200)
        self.assertIn("Page 3 of 3", last_page)
        self.assertIn("Showing 21–25 of 25 scans.", last_page)
        self.assertIn("host-1.example", last_page)
        self.assertNotIn("host-25.example", last_page)
        self.assertIn("page=2", last_page)
        self.assertNotIn("page=999999", last_page)
        self.assertNotIn("page=0", last_page)

    def test_zero_filter_results_keep_statistics_and_hide_pagination(self):
        self._save_sample_history()

        response = self.client.get("/history", query_string={"q": "missing-target"})
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("No scans match your current search or filter.", page)
        self.assertIn("Clear Filters", page)
        self.assertNotIn('class="pagination"', page)
        self.assertNotIn("Page 1 of 0", page)
        self.assertIn('class="stat-value">3</p>', page)

    def test_opening_a_history_page_does_not_create_scans(self):
        self._save_numbered_scans(12)
        from database.database import get_scan_statistics

        before = get_scan_statistics()["total"]
        page = self.client.get("/history", query_string={"page": 2}).get_data(as_text=True)
        self.assertIn("View Details", page)
        scan_id = page.split("/scan/", 1)[1].split('"', 1)[0]
        self.client.get(f"/scan/{scan_id}")
        self.assertEqual(get_scan_statistics()["total"], before)

    def test_history_shows_full_submitted_url_and_copy_control(self):
        init_db()
        save_scan(
            sample_parsed(
                "g00gle.com",
                "https://g00gle.com/login",
                submitted_url="https://g00gle.com/login",
            ),
            sample_risk(45, "Suspicious"),
        )
        with patch(
            "services.safe_redirect_resolver.http_exchange",
            side_effect=AssertionError("network"),
        ), patch(
            "analyzers.reputation._provider_get",
            side_effect=AssertionError("network"),
        ):
            page = self.client.get("/history").get_data(as_text=True)
        self.assertIn("https://g00gle.com/login", page)
        self.assertIn('class="copy-url-button"', page)
        self.assertIn('data-copy-text="https://g00gle.com/login"', page)
        self.assertIn("Copy full URL", page)
        self.assertNotIn('href="https://g00gle.com/login"', page)

    def test_history_escapes_hostile_url_characters(self):
        init_db()
        hostile = "https://example.com/<script>alert('x')</script>"
        save_scan(
            sample_parsed(
                "example.com",
                hostile,
                submitted_url=hostile,
            ),
            sample_risk(10, "Low Risk"),
        )
        page = self.client.get("/history").get_data(as_text=True)
        self.assertNotIn("<script>alert('x')</script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("data-copy-text=", page)

    def test_history_marks_repeated_normalized_urls(self):
        init_db()
        save_scan(
            sample_parsed("example.com", "https://example.com/login"),
            sample_risk(10, "Low Risk"),
        )
        save_scan(
            sample_parsed("example.com", "https://example.com/login"),
            sample_risk(10, "Low Risk"),
        )
        save_scan(
            sample_parsed("other.example", "https://other.example/"),
            sample_risk(10, "Low Risk"),
        )
        page = self.client.get("/history").get_data(as_text=True)
        self.assertIn("Repeated Scan", page)
        self.assertIn("2×", page)
        self.assertEqual(page.count("Repeated Scan"), 2)

    def test_filter_form_resets_to_page_one(self):
        self._save_numbered_scans(15, target_prefix="paged", classification="Low Risk")
        page = self.client.get(
            "/history",
            query_string={"q": "paged", "classification": "Low Risk"},
        ).get_data(as_text=True)
        self.assertIn('name="q"', page)
        self.assertIn('value="paged"', page)
        self.assertNotIn('name="page"', page)
        self.assertIn("Clear Filters", page)
        self.assertIn("Showing 1–10 of 15 matching scans.", page)

    def test_search_matches_path_in_normalized_url(self):
        init_db()
        save_scan(
            sample_parsed("example.com", "https://example.com/account/verify"),
            sample_risk(20, "Low Risk"),
        )
        save_scan(
            sample_parsed("other.example", "https://other.example/home"),
            sample_risk(10, "Low Risk"),
        )
        page = self.client.get(
            "/history", query_string={"q": "account/verify"}
        ).get_data(as_text=True)
        self.assertIn("https://example.com/account/verify", page)
        self.assertNotIn("other.example", page)

    def test_legacy_hostname_target_falls_back_to_normalized_url(self):
        init_db()
        from database.database import get_db_connection

        connection = get_db_connection()
        try:
            with connection:
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
                        "https://legacy.example/path?q=1",
                        10,
                        "Low Risk",
                        "ok",
                        "2026-01-01T00:00:00+00:00",
                    ),
                )
        finally:
            connection.close()
        page = self.client.get("/history").get_data(as_text=True)
        self.assertIn("https://legacy.example/path?q=1", page)
        self.assertIn('data-copy-text="https://legacy.example/path?q=1"', page)


if __name__ == "__main__":
    unittest.main()
