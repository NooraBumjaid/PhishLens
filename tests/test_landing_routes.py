import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import app


class TestLandingRoutes(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "scans.db"
        self.path_patch = patch("database.database.DB_PATH", self.db_path)
        self.path_patch.start()
        app.config["TESTING"] = True
        self.client = app.test_client()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_landing_page_offers_the_three_tools(self):
        response = self.client.get("/")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("PhishLens", page)
        self.assertIn("URL Analyzer", page)
        self.assertIn("Email Analyzer", page)
        self.assertIn("Security Dashboard", page)
        self.assertIn('href="/url"', page)
        self.assertIn('href="/dashboard"', page)
        self.assertNotIn('name="url"', page)

    def test_url_analyzer_page_loads(self):
        response = self.client.get("/url")
        page = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("Enter a URL to analyze", page)
        self.assertIn('name="url"', page)
        self.assertIn("Analyze URL", page)

    def test_email_analyzer_page_loads(self):
        response = self.client.get("/email")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Email Analyzer", response.get_data(as_text=True))

    def test_history_page_loads(self):
        response = self.client.get("/history")

        self.assertEqual(response.status_code, 200)
        self.assertIn("Scan History", response.get_data(as_text=True))
