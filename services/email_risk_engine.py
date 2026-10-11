"""Turn email security indicators into a transparent 0–100 score.

The score is a rule-based total. It is not a probability that an email
is phishing, and it does not prove that a sender is malicious.
"""

from config.email_rules import (
    EMAIL_BASE_SCORE,
    EMAIL_CORRELATION_RULES,
    EMAIL_INDICATOR_WEIGHTS,
    EMAIL_LOW_RISK_MAX,
    EMAIL_SUSPICIOUS_MAX,
)
from services.risk_engine import HIGH_RISK, LOW_RISK, SUSPICIOUS


def classify_email_score(score):
    """Classify a 0–100 email score as Low Risk, Suspicious, or High Risk."""
    if score <= EMAIL_LOW_RISK_MAX:
        return LOW_RISK
    if score <= EMAIL_SUSPICIOUS_MAX:
        return SUSPICIOUS
    return HIGH_RISK


def get_email_recommendation(classification):
    """Return cautious guidance for an email classification."""
    if classification == LOW_RISK:
        return (
            "Few suspicious email characteristics were detected by the local "
            "rules. This does not guarantee that the email is safe. Verify "
            "unexpected requests through a trusted channel."
        )
    if classification == SUSPICIOUS:
        return (
            "Several suspicious email characteristics were detected. Verify "
            "the sender and any requested action independently before "
            "replying, opening links, or sharing information."
        )
    if classification == HIGH_RISK:
        return (
            "Multiple high-risk or correlated characteristics were detected. "
            "Avoid using links or attachments from the email until the sender "
            "and request have been independently verified."
        )
    raise ValueError(f"Unknown classification: {classification}")


def find_email_correlations(indicators):
    """Return each correlation whose required rule names are present, once."""
    present = {indicator.get("rule_name") for indicator in indicators}
    correlations = []
    for rule in EMAIL_CORRELATION_RULES:
        if not all(name in present for name in rule["requires_all"]):
            continue
        alternatives = rule["requires_any"]
        if alternatives and not any(name in present for name in alternatives):
            continue
        correlations.append(
            {
                "rule": rule["rule"],
                "title": rule["title"],
                "score_change": rule["weight"],
                "explanation": rule["explanation"],
            }
        )
    return correlations


def calculate_email_risk(indicators):
    """Add configured weights and correlations, then clamp to 0–100.

    Each rule name contributes its configured weight at most once. A rule
    with no configured weight contributes 0 and is still listed.
    """
    seen_rules = set()
    contributions = []
    for indicator in indicators:
        rule_name = indicator.get("rule_name")
        if rule_name in seen_rules:
            weight = 0
        else:
            seen_rules.add(rule_name)
            weight = EMAIL_INDICATOR_WEIGHTS.get(rule_name, 0)
        contributions.append(
            {
                "rule_name": rule_name,
                "title": indicator.get("title") or rule_name,
                "score_change": weight,
            }
        )

    correlations = find_email_correlations(indicators)
    raw_score = EMAIL_BASE_SCORE
    raw_score += sum(item["score_change"] for item in contributions)
    raw_score += sum(item["score_change"] for item in correlations)
    final_score = max(0, min(100, raw_score))
    classification = classify_email_score(final_score)

    return {
        "base_score": EMAIL_BASE_SCORE,
        "indicator_contributions": contributions,
        "correlations": correlations,
        "raw_score": raw_score,
        "final_score": final_score,
        "classification": classification,
        "recommendation": get_email_recommendation(classification),
    }
