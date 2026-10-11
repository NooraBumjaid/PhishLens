"""Turn detected URL indicators into a transparent 0–100 risk score.

The score is a rule-based total. It is not a probability that a URL is malicious.
"""

from config.scoring_rules import (
    BASE_SCORE,
    CORRELATION_RULES,
    LOW_RISK_MAX,
    SUSPICIOUS_MAX,
)

LOW_RISK = "Low Risk"
SUSPICIOUS = "Suspicious"
HIGH_RISK = "High Risk"


def classify_score(score):
    """Classify a 0–100 score as Low Risk, Suspicious, or High Risk."""
    if score <= LOW_RISK_MAX:
        return LOW_RISK
    if score <= SUSPICIOUS_MAX:
        return SUSPICIOUS
    return HIGH_RISK


def get_recommendation(classification):
    """Return cautious guidance for a classification."""
    if classification == LOW_RISK:
        return (
            "Few suspicious URL characteristics were detected by the current "
            "rule set. This does not guarantee that the website is safe. "
            "Continue to verify the domain before entering sensitive information."
        )
    if classification == SUSPICIOUS:
        return (
            "Several suspicious URL characteristics were detected. Verify the "
            "destination independently before visiting the website or providing "
            "personal, financial, or authentication information."
        )
    if classification == HIGH_RISK:
        return (
            "Multiple high-risk URL characteristics were detected. Avoid "
            "visiting the URL or providing sensitive information unless the "
            "destination has been independently verified through a trusted source."
        )
    raise ValueError(f"Unknown classification: {classification}")


def find_correlations(indicators):
    """Return each correlation whose required indicator IDs are present.

    A correlation is applied once. Repeated text, such as login/login/login,
    does not apply it again, because the check uses rule IDs rather than
    how many times a word appears.
    """
    present_rules = {indicator["rule"] for indicator in indicators}
    correlations = []

    for rule in CORRELATION_RULES:
        if all(required in present_rules for required in rule["requires"]):
            correlations.append(
                {
                    "rule": rule["rule"],
                    "title": rule["title"],
                    "score_change": rule["weight"],
                    "explanation": rule["explanation"],
                }
            )

    return correlations


def calculate_risk(indicators):
    """Add indicator and correlation contributions, then clamp to 0–100."""
    correlations = find_correlations(indicators)
    raw_score = BASE_SCORE

    for indicator in indicators:
        raw_score += indicator["score_change"]
    for correlation in correlations:
        raw_score += correlation["score_change"]

    final_score = max(0, min(100, raw_score))
    classification = classify_score(final_score)

    return {
        "base_score": BASE_SCORE,
        "raw_score": raw_score,
        "final_score": final_score,
        "classification": classification,
        "recommendation": get_recommendation(classification),
        "indicators": indicators,
        "correlations": correlations,
    }
