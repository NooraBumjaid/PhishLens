"""Score static page-content indicators separately from URL scores."""

from config.page_rules import BASE_PAGE_SCORE, PAGE_CORRELATION_RULES, PAGE_RULES


def _clamp(score):
    return max(0, min(100, int(score)))


def classify_page_score(score):
    value = _clamp(score)
    if value <= 20:
        return "Low Concern"
    if value <= 50:
        return "Suspicious"
    return "High Concern"


def calculate_page_risk(indicators):
    """Return a page-content risk score from page indicators."""
    indicator_list = list(indicators or [])
    present = {
        item.get("rule") or item.get("rule_name")
        for item in indicator_list
        if item.get("rule") or item.get("rule_name")
    }

    raw_score = BASE_PAGE_SCORE
    for item in indicator_list:
        rule_name = item.get("rule") or item.get("rule_name")
        if rule_name in PAGE_RULES:
            change = PAGE_RULES[rule_name]["weight"]
            item["score_change"] = change
            raw_score += change
        else:
            raw_score += int(item.get("score_change") or 0)

    correlations = []
    for rule in PAGE_CORRELATION_RULES:
        required = set(rule["requires"])
        if required.issubset(present):
            correlations.append(
                {
                    "rule": rule["rule"],
                    "title": rule["title"],
                    "score_change": rule["weight"],
                    "explanation": rule["explanation"],
                }
            )
            raw_score += rule["weight"]

    final_score = _clamp(raw_score)
    return {
        "base_score": BASE_PAGE_SCORE,
        "raw_score": raw_score,
        "final_score": final_score,
        "classification": classify_page_score(final_score),
        "indicators": indicator_list,
        "correlations": correlations,
        "recommendation": (
            "Page-content findings are heuristic signals from static HTML. "
            "They do not prove that the page is phishing or safe."
        ),
    }
