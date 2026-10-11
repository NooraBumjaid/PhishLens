import unittest

from analyzers.url_analyzer import analyze_url
from config.scoring_rules import (
    BASE_SCORE,
    LOW_RISK_MAX,
    SUSPICIOUS_MAX,
    URL_RULES,
)
from services.risk_engine import calculate_risk


class TestScoringConfig(unittest.TestCase):
    def test_important_configuration_values(self):
        self.assertEqual(BASE_SCORE, 10)
        self.assertEqual(URL_RULES["https_present"]["weight"], -5)
        self.assertEqual(URL_RULES["http_only"]["weight"], 10)
        self.assertEqual(URL_RULES["ip_hostname"]["weight"], 20)
        self.assertEqual(URL_RULES["suspicious_keywords"]["max_contribution"], 15)
        self.assertEqual(LOW_RISK_MAX, 30)
        self.assertEqual(SUSPICIOUS_MAX, 60)

    def test_https_homepage_stays_low_risk(self):
        result = analyze_url("https://www.google.com/")
        risk = calculate_risk(result["indicators"])
        scores = {
            indicator["rule"]: indicator["score_change"]
            for indicator in result["indicators"]
        }

        self.assertEqual(scores, {"https_present": -5})
        self.assertEqual(risk["base_score"], 10)
        self.assertEqual(risk["final_score"], 5)
        self.assertEqual(risk["classification"], "Low Risk")

    def test_http_ip_login_url_stays_high_risk(self):
        result = analyze_url("http://192.168.1.10:8080/account/verify/password")
        risk = calculate_risk(result["indicators"])
        scores = {
            indicator["rule"]: indicator["score_change"]
            for indicator in result["indicators"]
        }

        self.assertEqual(scores["http_only"], 10)
        self.assertEqual(scores["ip_hostname"], 20)
        self.assertEqual(scores["suspicious_keywords"], 15)
        self.assertEqual(scores["suspicious_port"], 10)
        self.assertEqual(risk["correlations"][0]["rule"], "ip_with_credentials")
        self.assertEqual(risk["correlations"][0]["score_change"], 10)
        self.assertEqual(risk["base_score"], 10)
        self.assertEqual(risk["final_score"], 75)
        self.assertEqual(risk["classification"], "High Risk")


if __name__ == "__main__":
    unittest.main()
