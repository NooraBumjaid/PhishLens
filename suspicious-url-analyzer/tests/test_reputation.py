import os
import unittest
from unittest.mock import patch

from analyzers.reputation import check_url_reputation


class TestReputation(unittest.TestCase):
    def test_disabled_does_not_raise(self):
        with patch.dict(
            os.environ,
            {
                "ENABLE_REPUTATION_CHECKS": "false",
                "VIRUSTOTAL_API_KEY": "test-key",
            },
        ):
            result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "disabled")
        self.assertFalse(result["available"])
        self.assertEqual(result["provider"], "VirusTotal")

    def test_enabled_without_api_key(self):
        with patch.dict(
            os.environ,
            {"ENABLE_REPUTATION_CHECKS": "true", "VIRUSTOTAL_API_KEY": ""},
        ):
            result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "not_configured")
        self.assertFalse(result["available"])

    def test_ready_with_fake_key_makes_no_network_request(self):
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            with patch.dict(
                os.environ,
                {
                    "ENABLE_REPUTATION_CHECKS": "True",
                    "VIRUSTOTAL_API_KEY": "test-key",
                },
            ):
                result = check_url_reputation("https://example.com")

        self.assertEqual(result["status"], "ready")
        self.assertFalse(result["available"])
        self.assertNotIn("test-key", result["message"])
        self.assertIn("future live reputation check", result["message"])


if __name__ == "__main__":
    unittest.main()
