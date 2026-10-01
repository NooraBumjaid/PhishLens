import unittest

from services.risk_engine import (
    BASE_SCORE,
    classify_score,
    calculate_risk,
    get_recommendation,
)


def make_indicator(score_change, title="Test indicator", rule="test"):
    """Build a minimal indicator for scoring tests."""
    return {
        "rule": rule,
        "title": title,
        "explanation": "Test explanation.",
        "severity": "warning",
        "score_change": score_change,
    }


class TestRiskEngine(unittest.TestCase):
    def test_no_indicators_uses_the_base_score(self):
        result = calculate_risk([])

        self.assertEqual(result["base_score"], BASE_SCORE)
        self.assertEqual(result["raw_score"], 10)
        self.assertEqual(result["final_score"], 10)
        self.assertEqual(result["classification"], "Low Risk")

    def test_https_only(self):
        result = calculate_risk([make_indicator(-5, "HTTPS detected")])

        self.assertEqual(result["raw_score"], 5)
        self.assertEqual(result["final_score"], 5)
        self.assertEqual(result["classification"], "Low Risk")

    def test_http_only(self):
        result = calculate_risk([make_indicator(10, "HTTP connection")])

        self.assertEqual(result["raw_score"], 20)
        self.assertEqual(result["final_score"], 20)
        self.assertEqual(result["classification"], "Low Risk")

    def test_multiple_indicators_are_suspicious(self):
        result = calculate_risk(
            [
                make_indicator(10),
                make_indicator(20),
                make_indicator(15),
            ]
        )

        self.assertEqual(result["raw_score"], 55)
        self.assertEqual(result["final_score"], 55)
        self.assertEqual(result["classification"], "Suspicious")
        self.assertEqual(len(result["indicators"]), 3)

    def test_high_risk_combination(self):
        result = calculate_risk(
            [
                make_indicator(20),
                make_indicator(20),
                make_indicator(15),
            ]
        )

        self.assertEqual(result["final_score"], 65)
        self.assertGreater(result["final_score"], 60)
        self.assertEqual(result["classification"], "High Risk")

    def test_score_is_clamped_to_100(self):
        result = calculate_risk([make_indicator(20) for _ in range(6)])

        self.assertGreater(result["raw_score"], 100)
        self.assertEqual(result["final_score"], 100)
        self.assertEqual(result["classification"], "High Risk")

    def test_score_is_clamped_to_0(self):
        result = calculate_risk([make_indicator(-50)])

        self.assertLess(result["raw_score"], 0)
        self.assertEqual(result["final_score"], 0)
        self.assertEqual(result["classification"], "Low Risk")

    def test_classification_boundaries(self):
        self.assertEqual(classify_score(0), "Low Risk")
        self.assertEqual(classify_score(30), "Low Risk")
        self.assertEqual(classify_score(31), "Suspicious")
        self.assertEqual(classify_score(60), "Suspicious")
        self.assertEqual(classify_score(61), "High Risk")
        self.assertEqual(classify_score(100), "High Risk")

    def test_validation_maximum_clamp(self):
        result = calculate_risk([make_indicator(50) for _ in range(3)])

        self.assertGreater(result["raw_score"], 100)
        self.assertEqual(result["final_score"], 100)
        self.assertEqual(result["classification"], "High Risk")

    def test_validation_minimum_clamp(self):
        result = calculate_risk([make_indicator(-30), make_indicator(-30)])

        self.assertLess(result["raw_score"], 0)
        self.assertEqual(result["final_score"], 0)
        self.assertEqual(result["classification"], "Low Risk")

    def test_validation_classification_boundaries(self):
        expected = {
            0: "Low Risk",
            30: "Low Risk",
            31: "Suspicious",
            60: "Suspicious",
            61: "High Risk",
            100: "High Risk",
        }
        for score, classification in expected.items():
            self.assertEqual(classify_score(score), classification, score)

    def test_recommendations_stay_cautious(self):
        low = get_recommendation("Low Risk").lower()
        suspicious = get_recommendation("Suspicious").lower()
        high = get_recommendation("High Risk").lower()

        self.assertIn("does not guarantee", low)
        self.assertNotIn("this website is safe", low)
        self.assertNotIn("definitely malicious", suspicious)
        self.assertNotIn("this is phishing", high)

    def test_unrelated_indicators_have_no_correlation(self):
        result = calculate_risk(
            [
                make_indicator(-5, rule="https_present"),
                make_indicator(5, rule="suspicious_keywords"),
            ]
        )

        self.assertEqual(result["correlations"], [])
        self.assertEqual(result["final_score"], 10)

    def test_impersonation_with_keywords_adds_correlation_once(self):
        result = calculate_risk(
            [
                make_indicator(20, rule="possible_typosquatting"),
                make_indicator(5, rule="suspicious_keywords"),
                make_indicator(5, rule="suspicious_keywords"),
            ]
        )
        rules = [item["rule"] for item in result["correlations"]]

        self.assertEqual(rules, ["impersonation_with_credentials"])
        self.assertEqual(result["correlations"][0]["score_change"], 15)
        self.assertEqual(result["final_score"], 55)

    def test_shortener_with_keywords_adds_one_correlation(self):
        result = calculate_risk(
            [
                make_indicator(20, rule="url_shortener"),
                make_indicator(10, rule="suspicious_keywords"),
            ]
        )

        self.assertEqual(result["correlations"][0]["rule"], "shortener_with_credentials")
        self.assertEqual(result["correlations"][0]["score_change"], 10)
        self.assertEqual(result["final_score"], 50)

    def test_at_symbol_with_keywords_adds_one_correlation(self):
        result = calculate_risk(
            [
                make_indicator(20, rule="at_symbol"),
                make_indicator(5, rule="suspicious_keywords"),
            ]
        )

        self.assertEqual(result["correlations"][0]["rule"], "at_symbol_with_credentials")
        self.assertEqual(result["final_score"], 45)

    def test_ip_with_keywords_adds_one_correlation(self):
        result = calculate_risk(
            [
                make_indicator(20, rule="ip_hostname"),
                make_indicator(10, rule="suspicious_keywords"),
            ]
        )

        self.assertEqual(result["correlations"][0]["rule"], "ip_with_credentials")
        self.assertEqual(result["final_score"], 50)

    def test_different_correlations_are_each_applied_once(self):
        result = calculate_risk(
            [
                make_indicator(20, rule="possible_typosquatting"),
                make_indicator(20, rule="url_shortener"),
                make_indicator(20, rule="at_symbol"),
                make_indicator(20, rule="ip_hostname"),
                make_indicator(15, rule="suspicious_keywords"),
            ]
        )
        rules = [item["rule"] for item in result["correlations"]]

        self.assertEqual(
            rules,
            [
                "impersonation_with_credentials",
                "shortener_with_credentials",
                "at_symbol_with_credentials",
                "ip_with_credentials",
            ],
        )
        self.assertEqual(len(rules), len(set(rules)))
        self.assertEqual(result["raw_score"], 150)
        self.assertEqual(result["final_score"], 100)


if __name__ == "__main__":
    unittest.main()
