import unittest

from analyzers.url_analyzer import LONG_URL_THRESHOLD, analyze_url, check_punycode
from config.scoring_rules import URL_RULES
from services.risk_engine import calculate_risk


def indicators_by_rule(result):
    """Return the detected indicators keyed by rule name."""
    return {indicator["rule"]: indicator for indicator in result["indicators"]}


class TestUrlAnalyzer(unittest.TestCase):
    def test_https_domain_is_positive_and_not_an_ip(self):
        result = analyze_url("https://example.com")
        indicators = indicators_by_rule(result)

        self.assertIn("https_present", indicators)
        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assertEqual(indicators["https_present"]["severity"], "positive")
        self.assertNotIn("ip_hostname", indicators)

    def test_http_domain_is_a_warning_and_not_an_ip(self):
        result = analyze_url("http://example.com")
        indicators = indicators_by_rule(result)

        self.assertIn("http_only", indicators)
        self.assertEqual(indicators["http_only"]["score_change"], 10)
        self.assertEqual(indicators["http_only"]["severity"], "warning")
        self.assertNotIn("ip_hostname", indicators)

    def test_http_ipv4_hostname_detects_both_rules(self):
        result = analyze_url("http://192.168.1.10/login")
        indicators = indicators_by_rule(result)

        self.assertEqual(indicators["http_only"]["score_change"], 10)
        self.assertEqual(indicators["ip_hostname"]["score_change"], 20)

    def test_https_ipv4_hostname_detects_both_rules(self):
        result = analyze_url("https://8.8.8.8/test")
        indicators = indicators_by_rule(result)

        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assertEqual(indicators["ip_hostname"]["score_change"], 20)

    def test_https_subdomain_does_not_detect_an_ip(self):
        result = analyze_url("https://login.example.com")
        indicators = indicators_by_rule(result)

        self.assertIn("https_present", indicators)
        self.assertNotIn("ip_hostname", indicators)

    def test_ipv6_hostname_is_detected(self):
        result = analyze_url("https://[2001:db8::1]/test")
        indicators = indicators_by_rule(result)

        self.assertIn("https_present", indicators)
        self.assertIn("ip_hostname", indicators)

    def test_long_url_triggers_warning(self):
        prefix = "https://example.com/"
        url = prefix + ("a" * (LONG_URL_THRESHOLD - len(prefix) + 1))
        result = analyze_url(url)
        indicators = indicators_by_rule(result)

        self.assertGreater(len(url), LONG_URL_THRESHOLD)
        self.assertIn("long_url", indicators)
        self.assertEqual(indicators["long_url"]["score_change"], 10)
        self.assertEqual(
            indicators["long_url"]["evidence"],
            f"URL length: {len(url)} characters",
        )
        self.assertNotIn(url, indicators["long_url"]["evidence"])

    def test_normal_url_is_not_flagged_as_long(self):
        result = analyze_url("https://example.com")
        self.assertNotIn("long_url", indicators_by_rule(result))

    def test_url_at_length_threshold_is_not_flagged(self):
        prefix = "https://example.com/"
        url = prefix + ("a" * (LONG_URL_THRESHOLD - len(prefix)))
        self.assertEqual(len(url), LONG_URL_THRESHOLD)
        self.assertNotIn("long_url", indicators_by_rule(analyze_url(url)))

    def test_simple_domains_are_not_excessive_subdomains(self):
        for url in (
            "https://example.com",
            "https://www.example.com",
            "https://login.example.com",
        ):
            indicators = indicators_by_rule(analyze_url(url))
            self.assertNotIn("excessive_subdomains", indicators, url)

    def test_many_subdomain_labels_are_detected(self):
        result = analyze_url("https://a.b.c.d.example.com/login")
        indicators = indicators_by_rule(result)

        self.assertIn("excessive_subdomains", indicators)
        self.assertEqual(indicators["excessive_subdomains"]["score_change"], 10)
        self.assertEqual(
            indicators["excessive_subdomains"]["evidence"],
            "Detected subdomain levels: 4",
        )

    def test_ip_hostname_is_not_checked_as_subdomains(self):
        result = analyze_url("http://192.168.1.10/login")
        self.assertNotIn("excessive_subdomains", indicators_by_rule(result))

    def test_at_symbol_is_detected(self):
        result = analyze_url("https://example.com@evil.example/login")
        indicators = indicators_by_rule(result)

        self.assertIn("at_symbol", indicators)
        self.assertEqual(indicators["at_symbol"]["score_change"], 20)
        self.assertEqual(indicators["at_symbol"]["title"], "@ symbol detected")

    def test_punycode_hostname_is_detected(self):
        result = analyze_url("https://xn--example-xxxx.com")
        indicators = indicators_by_rule(result)

        self.assertIn("punycode", indicators)
        self.assertEqual(indicators["punycode"]["score_change"], 15)

    def test_normal_hostname_is_not_punycode(self):
        result = analyze_url("https://example.com")
        self.assertNotIn("punycode", indicators_by_rule(result))

    def test_punycode_prefix_is_case_insensitive(self):
        indicator = check_punycode("XN--Example-xxxx.com")
        self.assertIsNotNone(indicator)
        self.assertEqual(indicator["rule"], "punycode")

    def test_one_suspicious_keyword(self):
        result = analyze_url("https://example.com/login")
        indicators = indicators_by_rule(result)

        self.assertIn("suspicious_keywords", indicators)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 5)
        self.assertEqual(
            indicators["suspicious_keywords"]["evidence"],
            "Detected keywords: login",
        )

    def test_two_suspicious_keywords(self):
        result = analyze_url("https://example.com/account/verify")
        indicators = indicators_by_rule(result)

        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 10)
        self.assertEqual(
            indicators["suspicious_keywords"]["evidence"],
            "Detected keywords: account, verify",
        )

    def test_suspicious_keyword_score_is_capped(self):
        result = analyze_url(
            "https://example.com/login/verify/account/update/password"
        )
        indicator = indicators_by_rule(result)["suspicious_keywords"]

        self.assertLessEqual(indicator["score_change"], 15)
        self.assertEqual(indicator["score_change"], 15)
        for keyword in ("login", "verify", "account", "update", "password"):
            self.assertIn(keyword, indicator["evidence"])

    def test_duplicate_keyword_is_counted_once(self):
        result = analyze_url("https://example.com/login/login/login")
        indicator = indicators_by_rule(result)["suspicious_keywords"]

        self.assertEqual(indicator["score_change"], 5)
        self.assertEqual(indicator["evidence"], "Detected keywords: login")

    def test_suspicious_keyword_is_case_insensitive(self):
        result = analyze_url("https://example.com/LOGIN")
        indicator = indicators_by_rule(result)["suspicious_keywords"]

        self.assertIn("login", indicator["evidence"])

    def test_ordinary_path_has_no_suspicious_keywords(self):
        result = analyze_url("https://example.com/products")
        self.assertNotIn("suspicious_keywords", indicators_by_rule(result))

    def test_standard_https_port_is_not_flagged(self):
        result = analyze_url("https://example.com:443")
        self.assertNotIn("suspicious_port", indicators_by_rule(result))

    def test_standard_http_port_is_not_flagged(self):
        result = analyze_url("http://example.com:80")
        self.assertNotIn("suspicious_port", indicators_by_rule(result))

    def test_nonstandard_https_port_is_flagged(self):
        result = analyze_url("https://example.com:8080/login")
        indicator = indicators_by_rule(result)["suspicious_port"]

        self.assertEqual(indicator["score_change"], 10)
        self.assertEqual(
            indicator["evidence"],
            "HTTPS URL explicitly uses port 8080",
        )

    def test_url_shortener_hostname_is_detected(self):
        result = analyze_url("https://bit.ly/example")
        indicator = indicators_by_rule(result)["url_shortener"]

        self.assertEqual(indicator["score_change"], 20)
        self.assertEqual(indicator["evidence"], "Shortening service: bit.ly")

    def test_shortener_text_in_the_path_is_not_a_shortener(self):
        result = analyze_url("https://example.com/path/bit.ly/test")
        self.assertNotIn("url_shortener", indicators_by_rule(result))

    def test_legitimate_reference_domains_are_not_impersonation(self):
        for url in (
            "https://google.com",
            "https://accounts.google.com",
            "https://microsoft.com",
            "https://login.microsoft.com",
            "https://paypal.com",
        ):
            indicators = indicators_by_rule(analyze_url(url))
            self.assertNotIn("possible_typosquatting", indicators, url)

    def test_digit_substitution_resembles_google(self):
        result = analyze_url("https://g00gle.com")
        indicator = indicators_by_rule(result)["possible_typosquatting"]

        self.assertEqual(indicator["score_change"], 20)
        self.assertEqual(indicator["title"], "Possible domain impersonation")
        self.assertIn("Hostname resembles google.com", indicator["evidence"])
        self.assertIn(
            'Lookalike character substitution detected (for example, "0" resembles "o").',
            indicator["evidence"],
        )
        self.assertIn("Text similarity: 67%", indicator["evidence"])
        self.assertNotIn("Similarity: 100%", indicator["evidence"])
        self.assertNotIn("Text similarity: 100%", indicator["evidence"])

    def test_extra_character_resembles_google(self):
        result = analyze_url("https://gooogle.com")
        indicator = indicators_by_rule(result)["possible_typosquatting"]

        self.assertIn("Hostname resembles google.com", indicator["evidence"])
        self.assertNotIn("Lookalike character substitution", indicator["evidence"])
        self.assertIn("Text similarity: 92%", indicator["evidence"])

    def test_microsoft_substitution_is_detected(self):
        result = analyze_url("https://micros0ft.com")
        indicator = indicators_by_rule(result)["possible_typosquatting"]
        self.assertIn("Hostname resembles microsoft.com", indicator["evidence"])
        self.assertIn("Text similarity: 89%", indicator["evidence"])
        self.assertNotIn("Text similarity: 100%", indicator["evidence"])

    def test_paypal_substitution_is_detected(self):
        result = analyze_url("https://paypa1.com")
        indicator = indicators_by_rule(result)["possible_typosquatting"]
        self.assertIn("Hostname resembles paypal.com", indicator["evidence"])
        self.assertIn("Text similarity: 83%", indicator["evidence"])
        self.assertNotIn("Text similarity: 100%", indicator["evidence"])

    def test_brand_word_in_the_path_is_not_impersonation(self):
        for url in (
            "https://example.com/google/login",
            "https://example.com/paypal/help",
        ):
            indicators = indicators_by_rule(analyze_url(url))
            self.assertNotIn("possible_typosquatting", indicators, url)

    def test_unrelated_domain_is_not_impersonation(self):
        result = analyze_url("https://example.com")
        self.assertNotIn("possible_typosquatting", indicators_by_rule(result))

    def test_ip_hostname_is_not_typosquatting(self):
        result = analyze_url("http://192.168.1.10")
        self.assertNotIn("possible_typosquatting", indicators_by_rule(result))

    def test_lookalike_login_url_score_stays_rule_based(self):
        result = analyze_url("https://g00gle.com/login")
        indicators = indicators_by_rule(result)
        risk = calculate_risk(result["indicators"])

        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 5)
        evidence = indicators["possible_typosquatting"]["evidence"]
        self.assertEqual(indicators["possible_typosquatting"]["score_change"], 20)
        self.assertIn("Text similarity: 67%", evidence)
        self.assertNotIn("Text similarity: 100%", evidence)
        self.assertEqual(risk["final_score"], 45)
        self.assertEqual(risk["classification"], "Suspicious")


def analyze_scored(url):
    """Return detected indicators and the current risk result for a URL."""
    result = analyze_url(url)
    return indicators_by_rule(result), calculate_risk(result["indicators"])


class TestScoringValidation(unittest.TestCase):
    """Check current configured scores without changing any weights."""

    def assert_score(self, risk, final_score, classification):
        self.assertEqual(risk["base_score"], 10)
        self.assertEqual(risk["final_score"], final_score)
        self.assertEqual(risk["classification"], classification)

    def test_normal_https_url(self):
        indicators, risk = analyze_scored("https://example.com")

        self.assertEqual(set(indicators), {"https_present"})
        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assert_score(risk, 5, "Low Risk")

    def test_https_login_keyword_stays_low_risk(self):
        indicators, risk = analyze_scored("https://example.com/login")

        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 5)
        self.assertEqual(indicators["suspicious_keywords"]["evidence"], "Detected keywords: login")
        self.assertEqual(risk["correlations"], [])
        self.assert_score(risk, 10, "Low Risk")

    def test_http_website(self):
        indicators, risk = analyze_scored("http://example.com")

        self.assertEqual(set(indicators), {"http_only"})
        self.assertEqual(indicators["http_only"]["score_change"], 10)
        self.assert_score(risk, 20, "Low Risk")

    def test_ip_hostname_is_suspicious(self):
        indicators, risk = analyze_scored("http://192.168.1.10")

        self.assertEqual(indicators["http_only"]["score_change"], 10)
        self.assertEqual(indicators["ip_hostname"]["score_change"], 20)
        self.assertNotIn("possible_typosquatting", indicators)
        self.assert_score(risk, 40, "Suspicious")

    def test_multiple_credential_keywords_stay_low_risk(self):
        indicators, risk = analyze_scored("https://example.com/account/verify/password")

        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 15)
        self.assert_score(risk, 20, "Low Risk")

    def test_nonstandard_port_with_login_stays_low_risk(self):
        indicators, risk = analyze_scored("https://example.com:8080/login")

        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 5)
        self.assertEqual(indicators["suspicious_port"]["score_change"], 10)
        self.assert_score(risk, 20, "Low Risk")

    def test_url_shortener_stays_low_risk(self):
        indicators, risk = analyze_scored("https://bit.ly/example")

        self.assertEqual(indicators["https_present"]["score_change"], -5)
        self.assertEqual(indicators["url_shortener"]["score_change"], 20)
        self.assertEqual(risk["correlations"], [])
        self.assert_score(risk, 25, "Low Risk")

    def test_punycode_uses_configured_weight(self):
        indicators, risk = analyze_scored("https://xn--example-xxxx.com")

        self.assertIn("punycode", indicators)
        self.assertEqual(
            indicators["punycode"]["score_change"],
            URL_RULES["punycode"]["weight"],
        )
        self.assertEqual(risk["base_score"], 10)
        self.assertEqual(risk["final_score"], 20)
        self.assertEqual(risk["classification"], "Low Risk")

    def test_at_symbol_with_login_keyword(self):
        indicators, risk = analyze_scored("https://example.com@evil.example/login")

        self.assertIn("https_present", indicators)
        self.assertEqual(indicators["at_symbol"]["score_change"], 20)
        self.assertEqual(indicators["suspicious_keywords"]["evidence"], "Detected keywords: login")
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]],
            ["at_symbol_with_credentials"],
        )
        self.assertEqual(risk["correlations"][0]["score_change"], 10)
        self.assert_score(risk, 40, "Suspicious")

    def test_excessive_subdomains_with_login(self):
        indicators, risk = analyze_scored("https://a.b.c.d.example.com/login")

        self.assertIn("https_present", indicators)
        self.assertIn("excessive_subdomains", indicators)
        self.assertEqual(indicators["suspicious_keywords"]["evidence"], "Detected keywords: login")
        self.assertEqual(indicators["excessive_subdomains"]["evidence"], "Detected subdomain levels: 4")
        self.assertEqual(risk["final_score"], 20)
        self.assertEqual(risk["classification"], "Low Risk")

    def test_long_url_uses_configured_weight(self):
        prefix = "https://example.com/"
        url = prefix + ("a" * (LONG_URL_THRESHOLD - len(prefix) + 1))
        indicators, risk = analyze_scored(url)

        self.assertGreater(len(url), LONG_URL_THRESHOLD)
        self.assertEqual(
            indicators["long_url"]["score_change"],
            URL_RULES["long_url"]["weight"],
        )
        self.assertEqual(risk["final_score"], 15)
        self.assertEqual(risk["classification"], "Low Risk")

    def test_lookalike_login_wording_and_score(self):
        indicators, risk = analyze_scored("https://g00gle.com/login")
        indicator = indicators["possible_typosquatting"]

        self.assertEqual(indicator["score_change"], 20)
        self.assertEqual(indicator["title"], "Possible domain impersonation")
        self.assertIn("Lookalike character substitution detected", indicator["evidence"])
        self.assertIn("Text similarity: 67%", indicator["evidence"])
        self.assertNotIn("Text similarity: 100%", indicator["evidence"])
        self.assertNotIn("This domain is impersonating", indicator["explanation"])
        self.assertIn("does not prove malicious intent", indicator["explanation"])
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]],
            ["impersonation_with_credentials"],
        )
        self.assertEqual(risk["correlations"][0]["score_change"], 15)
        self.assert_score(risk, 45, "Suspicious")

    def test_legitimate_google_hosts_are_not_impersonation(self):
        for url in ("https://google.com", "https://accounts.google.com"):
            indicators, risk = analyze_scored(url)
            self.assertNotIn("possible_typosquatting", indicators, url)
            self.assertEqual(set(indicators), {"https_present"})
            self.assert_score(risk, 5, "Low Risk")

    def test_brand_in_path_is_not_domain_impersonation(self):
        indicators, risk = analyze_scored("https://example.com/google/login")

        self.assertNotIn("possible_typosquatting", indicators)
        self.assertEqual(indicators["suspicious_keywords"]["evidence"], "Detected keywords: login")
        self.assert_score(risk, 10, "Low Risk")

    def test_combined_ip_port_and_keywords_stay_high_risk(self):
        indicators, risk = analyze_scored(
            "http://192.168.1.10:8080/account/verify/password"
        )

        self.assertEqual(indicators["http_only"]["score_change"], 10)
        self.assertEqual(indicators["ip_hostname"]["score_change"], 20)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 15)
        self.assertEqual(indicators["suspicious_port"]["score_change"], 10)
        self.assertNotIn("possible_typosquatting", indicators)
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]],
            ["ip_with_credentials"],
        )
        self.assertEqual(risk["correlations"][0]["score_change"], 10)
        self.assert_score(risk, 75, "High Risk")

    def test_secure_keyword_uses_only_the_keyword_weight(self):
        indicators, risk = analyze_scored("https://secure.example.com")

        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 5)
        self.assertEqual(indicators["suspicious_keywords"]["evidence"], "Detected keywords: secure")
        self.assertNotIn("possible_typosquatting", indicators)
        self.assert_score(risk, 10, "Low Risk")

    def test_google_login_subdomain_is_not_impersonation(self):
        indicators, risk = analyze_scored("https://accounts.google.com/login")

        self.assertNotIn("possible_typosquatting", indicators)
        self.assertEqual(indicators["suspicious_keywords"]["evidence"], "Detected keywords: login")
        self.assert_score(risk, 10, "Low Risk")

    def test_paypal_in_path_is_not_impersonation(self):
        indicators, risk = analyze_scored("https://example.com/paypal/help")

        self.assertNotIn("possible_typosquatting", indicators)
        self.assertNotIn("suspicious_keywords", indicators)
        self.assert_score(risk, 5, "Low Risk")

    def test_explicit_standard_https_port_is_not_flagged(self):
        indicators, risk = analyze_scored("https://example.com:443")

        self.assertNotIn("suspicious_port", indicators)
        self.assert_score(risk, 5, "Low Risk")

    def test_duplicate_login_keyword_counts_once(self):
        indicators, risk = analyze_scored("https://example.com/login/login/login")

        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 5)
        self.assertEqual(indicators["suspicious_keywords"]["evidence"], "Detected keywords: login")
        self.assert_score(risk, 10, "Low Risk")

    def test_keyword_contribution_stays_capped(self):
        indicators, risk = analyze_scored(
            "https://example.com/login/verify/account/update/password/secure"
        )
        evidence = indicators["suspicious_keywords"]["evidence"]

        for keyword in ("login", "verify", "account", "update", "password", "secure"):
            self.assertIn(keyword, evidence)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 15)
        self.assertLessEqual(
            indicators["suspicious_keywords"]["score_change"],
            URL_RULES["suspicious_keywords"]["max_contribution"],
        )
        self.assertEqual(risk["correlations"], [])
        self.assert_score(risk, 20, "Low Risk")

    def test_typosquatting_without_keywords_stays_low_risk(self):
        indicators, risk = analyze_scored("https://g00gle.com")

        self.assertEqual(indicators["possible_typosquatting"]["score_change"], 20)
        self.assertEqual(risk["correlations"], [])
        self.assert_score(risk, 25, "Low Risk")

    def test_shortener_with_credential_keywords_is_suspicious(self):
        indicators, risk = analyze_scored("https://bit.ly/account-verify")

        self.assertEqual(indicators["url_shortener"]["score_change"], 20)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 10)
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]],
            ["shortener_with_credentials"],
        )
        self.assert_score(risk, 45, "Suspicious")

    def test_ip_with_credential_keywords_is_suspicious(self):
        indicators, risk = analyze_scored("http://192.168.1.10/account/verify")

        self.assertEqual(indicators["http_only"]["score_change"], 10)
        self.assertEqual(indicators["ip_hostname"]["score_change"], 20)
        self.assertEqual(indicators["suspicious_keywords"]["score_change"], 10)
        self.assertEqual(
            [item["rule"] for item in risk["correlations"]],
            ["ip_with_credentials"],
        )
        self.assert_score(risk, 60, "Suspicious")


if __name__ == "__main__":
    unittest.main()
