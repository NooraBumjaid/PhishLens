"""Deterministic combined assessment from already-produced analysis layers.

This module never fetches URLs, resolves DNS, calls VirusTotal, or inspects
pages. It only evaluates stored or in-memory results.

Combined score model:
1. Start from the strongest completed structural/content layer score (max, not sum).
2. Apply a small set of named cross-layer adjustments once each.
3. Apply VirusTotal supporting evidence points (never a downgrade).
4. Clamp to 0–100 and classify with URL thresholds.
"""

from __future__ import annotations

from config.combined_assessment_settings import (
    ASSESSMENT_DISCLAIMER,
    COMBINED_LOW_RISK_MAX,
    COMBINED_SUSPICIOUS_MAX,
    CREDENTIAL_PAGE_RULES,
    CROSS_LAYER_ADJUSTMENTS,
    MAX_ASSESSMENT_REASONS,
    NO_WARNING_GUARANTEE,
    PAYMENT_PAGE_RULES,
    RECOMMENDATIONS,
    VT_MALICIOUS_BANDS,
    VT_SUSPICIOUS_ONLY_WEIGHT,
)

_LEVEL_TO_KEY = {0: "low_risk", 1: "suspicious", 2: "high_risk"}
_LEVEL_TO_LABEL = {0: "Low Risk", 1: "Suspicious", 2: "High Risk"}

_LAYER_LABELS = {
    "submitted_url": "Submitted URL",
    "final_destination": "Final Destination",
    "page_content": "Static Page Content",
}


def _clamp(score):
    return max(0, min(100, int(score)))


def classify_combined_score(score):
    value = _clamp(score)
    if value <= COMBINED_LOW_RISK_MAX:
        return 0, "low_risk", "Low Risk"
    if value <= COMBINED_SUSPICIOUS_MAX:
        return 1, "suspicious", "Suspicious"
    return 2, "high_risk", "High Risk"


def _score_of(result):
    if result is None:
        return None
    if result.get("score") is not None:
        return _clamp(result.get("score"))
    if result.get("final_score") is not None:
        return _clamp(result.get("final_score"))
    return None


def _is_suspicious_or_higher(result):
    if result is None:
        return False
    score = _score_of(result)
    if score is not None and score >= COMBINED_LOW_RISK_MAX + 1:
        return True
    label = (result.get("classification") or "").strip()
    return label in {"Suspicious", "High Risk", "High Concern"}


def _indicator_rules(result):
    rules = set()
    for item in (result or {}).get("indicators") or []:
        name = item.get("rule_name") or item.get("rule")
        if name:
            rules.add(name)
    return rules


def _malicious_count(reputation):
    if reputation is None:
        return None
    if reputation.get("malicious") is not None:
        return int(reputation.get("malicious") or 0)
    if reputation.get("malicious_count") is not None:
        return int(reputation.get("malicious_count") or 0)
    return None


def _suspicious_count(reputation):
    if reputation is None:
        return None
    if reputation.get("suspicious") is not None:
        return int(reputation.get("suspicious") or 0)
    if reputation.get("suspicious_count") is not None:
        return int(reputation.get("suspicious_count") or 0)
    return None


def _reputation_usable(reputation):
    return bool(reputation) and (reputation.get("status") or "").strip().lower() == "completed"


def _reputation_successful_lookup(reputation):
    status = (reputation.get("status") or "").strip().lower() if reputation else ""
    return status in {"completed", "unknown"}


def _add_reason(bucket, rule, text, priority=50):
    if any(item["rule"] == rule for item in bucket):
        return
    bucket.append({"rule": rule, "text": text, "priority": priority})


def _compute_coverage(submitted, final, page, reputation):
    has_submitted = submitted is not None
    has_final = final is not None
    has_page = page is not None
    has_rep = _reputation_successful_lookup(reputation)

    if has_submitted and has_final and has_page and has_rep:
        return "strong", "STRONG"
    if has_submitted and has_final and has_page:
        return "moderate", "MODERATE"
    if has_submitted and (has_final or has_page or has_rep):
        return "moderate", "MODERATE"
    return "limited", "LIMITED"


def _layers(submitted, final, page, reputation):
    checked = []
    not_checked = []
    if submitted is not None:
        checked.append("submitted_url")
    else:
        not_checked.append("submitted_url")

    if final is not None:
        checked.append("final_url")
    else:
        not_checked.append("final_destination")

    if page is not None:
        checked.append("page_content")
    else:
        not_checked.append("page_content")

    if _reputation_successful_lookup(reputation):
        checked.append("external_reputation")
    else:
        not_checked.append("external_reputation")

    return checked, not_checked


def _strongest_layer(submitted, final, page):
    candidates = []
    submitted_score = _score_of(submitted)
    if submitted_score is not None:
        candidates.append(("submitted_url", submitted_score))
    final_score = _score_of(final)
    if final_score is not None:
        candidates.append(("final_destination", final_score))
    page_score = _score_of(page)
    if page_score is not None:
        candidates.append(("page_content", page_score))
    if not candidates:
        return "submitted_url", 0
    return max(candidates, key=lambda item: item[1])


def build_combined_assessment(
    submitted_url_result=None,
    final_url_result=None,
    page_result=None,
    reputation_result=None,
    destination_status=None,
):
    """Return a combined assessment from available layer results.

    Partial evidence is supported. Missing layers affect coverage, not crashes.
    Layer scores are never summed; the strongest completed layer is the base.
    """
    submitted = submitted_url_result
    final = final_url_result
    page = page_result
    reputation = reputation_result
    dest_status = (destination_status or "").strip().lower()

    reason_bucket = []
    triggered = []
    adjustments = []

    strongest_name, strongest_score = _strongest_layer(submitted, final, page)
    combined_score = strongest_score

    # Layer-specific reasons (explainability).
    if final is not None and _is_suspicious_or_higher(final):
        _add_reason(
            reason_bucket,
            "local_suspicious_final",
            "Final destination shows suspicious URL characteristics.",
            priority=20,
        )
    elif submitted is not None and _is_suspicious_or_higher(submitted):
        _add_reason(
            reason_bucket,
            "local_suspicious_submitted",
            "The submitted URL shows suspicious structural characteristics.",
            priority=25,
        )

    if page is not None:
        page_label = (page.get("classification") or "").strip()
        page_score = _score_of(page) or 0
        if page_label == "High Concern" or page_score >= 61:
            _add_reason(
                reason_bucket,
                "page_high_concern",
                "Static page inspection detected high-concern content characteristics.",
                priority=15,
            )
        elif page_label in {"Suspicious", "Elevated Concern"} or page_score >= 31:
            _add_reason(
                reason_bucket,
                "page_elevated",
                "Static page inspection detected elevated concern signals.",
                priority=22,
            )

    page_rules = _indicator_rules(page) if page is not None else set()
    has_credentials = bool(page_rules & CREDENTIAL_PAGE_RULES)
    has_payment = bool(page_rules & PAYMENT_PAGE_RULES)
    if has_credentials:
        _add_reason(
            reason_bucket,
            "credential_page",
            "Static page inspection detected a credential-entry form or credential language.",
            priority=18,
        )
    if has_payment:
        _add_reason(
            reason_bucket,
            "payment_page",
            "Static page inspection detected payment or sensitive-data collection signals.",
            priority=19,
        )

    # Cross-layer adjustments (once each, never multiplied).
    if final is not None and _is_suspicious_or_higher(final) and has_credentials:
        rule = "suspicious_final_with_credentials"
        meta = CROSS_LAYER_ADJUSTMENTS[rule]
        adjustments.append(
            {
                "rule": rule,
                "title": meta["title"],
                "score_change": meta["weight"],
                "explanation": meta["explanation"],
            }
        )
        triggered.append(rule)
        combined_score += meta["weight"]
        _add_reason(
            reason_bucket,
            rule,
            "The final destination and credential collection signals reinforce each other.",
            priority=10,
        )

    if final is not None and _is_suspicious_or_higher(final) and has_payment:
        rule = "suspicious_final_with_payment"
        meta = CROSS_LAYER_ADJUSTMENTS[rule]
        adjustments.append(
            {
                "rule": rule,
                "title": meta["title"],
                "score_change": meta["weight"],
                "explanation": meta["explanation"],
            }
        )
        triggered.append(rule)
        combined_score += meta["weight"]
        _add_reason(
            reason_bucket,
            rule,
            "The final destination and payment-collection signals reinforce each other.",
            priority=11,
        )

    if (
        submitted is not None
        and submitted.get("has_shortener")
        and final is not None
        and _is_suspicious_or_higher(final)
    ):
        rule = "shortener_with_risky_final"
        meta = CROSS_LAYER_ADJUSTMENTS[rule]
        adjustments.append(
            {
                "rule": rule,
                "title": meta["title"],
                "score_change": meta["weight"],
                "explanation": meta["explanation"],
            }
        )
        triggered.append(rule)
        combined_score += meta["weight"]
        _add_reason(
            reason_bucket,
            rule,
            "A shortened submitted URL resolved to a Suspicious or High Risk destination.",
            priority=12,
        )

    # VirusTotal supporting evidence — zero detections add nothing.
    vt_points = 0
    vt_rule = None
    if _reputation_usable(reputation):
        malicious = _malicious_count(reputation) or 0
        suspicious = _suspicious_count(reputation) or 0
        if malicious > 0:
            for threshold, points, rule_name in VT_MALICIOUS_BANDS:
                if malicious >= threshold:
                    vt_points = points
                    vt_rule = rule_name
                    break
            if vt_rule:
                triggered.append(vt_rule)
                _add_reason(
                    reason_bucket,
                    vt_rule,
                    f"VirusTotal reported {malicious} malicious detection(s).",
                    priority=5,
                )
        elif suspicious > 0:
            vt_points = VT_SUSPICIOUS_ONLY_WEIGHT
            vt_rule = "vt_suspicious_only"
            triggered.append(vt_rule)
            _add_reason(
                reason_bucket,
                vt_rule,
                f"VirusTotal reported {suspicious} suspicious detection(s) and no malicious detections.",
                priority=30,
            )
    combined_score += vt_points

    # Blocked destination is a safety control — mention only, no phishing points.
    if dest_status == "blocked" and final is None:
        _add_reason(
            reason_bucket,
            "destination_blocked",
            "Destination inspection could not safely be completed.",
            priority=40,
        )

    if (
        submitted is not None
        and submitted.get("has_shortener")
        and final is None
        and dest_status != "blocked"
    ):
        _add_reason(
            reason_bucket,
            "shortener_hidden_destination",
            "The destination behind this shortened URL has not been inspected.",
            priority=35,
        )

    combined_score = _clamp(combined_score)
    level, assessment_key, label = classify_combined_score(combined_score)

    coverage_key, coverage_label = _compute_coverage(
        submitted, final, page, reputation
    )
    layers_checked, layers_not_checked = _layers(
        submitted, final, page, reputation
    )

    reasons_sorted = sorted(reason_bucket, key=lambda item: item["priority"])
    reasons = [item["text"] for item in reasons_sorted[:MAX_ASSESSMENT_REASONS]]
    ordered_triggered = []
    for name in triggered:
        if name not in ordered_triggered:
            ordered_triggered.append(name)

    if level >= 2:
        summary = (
            "PhishLens found strong warning signals across multiple analysis layers."
        )
    elif level == 1:
        summary = (
            "PhishLens found warning signals that warrant caution based on "
            "the available evidence."
        )
    else:
        summary = (
            "PhishLens did not identify major warning signals in the "
            "completed checks."
        )
        if submitted and submitted.get("has_shortener") and final is None:
            summary = (
                "Limited evidence is available. The shortened URL itself shows "
                "few warning signals, but the destination has not been inspected."
            )

    breakdown = {
        "strongest_layer": strongest_name,
        "strongest_layer_label": _LAYER_LABELS.get(strongest_name, strongest_name),
        "strongest_layer_score": strongest_score,
        "cross_layer_adjustments": adjustments,
        "virustotal_adjustment": vt_points,
        "virustotal_rule": vt_rule,
        "final_score": combined_score,
    }

    return {
        "score": combined_score,
        "classification": label,
        "assessment": assessment_key,
        "label": label,
        "confidence": coverage_key,
        "coverage": coverage_key,
        "coverage_label": coverage_label,
        "summary": summary,
        "recommendation": RECOMMENDATIONS[assessment_key],
        "reasons": reasons,
        "layers_checked": layers_checked,
        "layers_not_checked": layers_not_checked,
        "triggered_rules": ordered_triggered,
        "breakdown": breakdown,
        "disclaimer": ASSESSMENT_DISCLAIMER,
        "safety_note": NO_WARNING_GUARANTEE,
    }


def pick_reputation_result(reputation_checks):
    """Choose the strongest usable reputation result from stored checks."""
    checks = reputation_checks or {}
    candidates = [item for item in checks.values() if item]
    if not candidates:
        return None

    completed = [
        item
        for item in candidates
        if (item.get("status") or "").strip().lower() == "completed"
    ]
    if completed:
        return max(
            completed,
            key=lambda item: _malicious_count(item) or 0,
        )

    for status in ("unknown", "rate_limited", "failed", "not_configured", "disabled"):
        for item in candidates:
            if (item.get("status") or "").strip().lower() == status:
                return item
    return candidates[0]


def evidence_from_scan_record(record):
    """Build engine inputs from a stored URL scan record. No network I/O."""
    scan = (record or {}).get("scan") or {}
    indicators = (record or {}).get("indicators") or []
    submitted = {
        "score": scan.get("risk_score"),
        "classification": scan.get("classification"),
        "indicators": indicators,
        "has_shortener": any(
            (item or {}).get("rule_name") == "url_shortener" for item in indicators
        ),
    }

    final = None
    destination_status = None
    inspection = (record or {}).get("redirect_inspection")
    if inspection:
        status = (inspection.get("status") or "").lower()
        destination_status = status
        if status == "resolved":
            final = {
                "score": inspection.get("final_risk_score"),
                "classification": inspection.get("final_classification"),
                "indicators": inspection.get("final_indicators")
                or inspection.get("indicators")
                or [],
            }

    page = None
    page_inspection = (record or {}).get("page_inspection")
    if page_inspection and (page_inspection.get("status") or "").lower() == "completed":
        page = {
            "score": page_inspection.get("risk_score"),
            "classification": page_inspection.get("classification"),
            "indicators": page_inspection.get("indicators") or [],
        }

    reputation = pick_reputation_result((record or {}).get("reputation_checks"))
    return submitted, final, page, reputation, destination_status


def assess_scan_record(record):
    """Convenience: combined assessment for a stored URL scan record."""
    submitted, final, page, reputation, destination_status = evidence_from_scan_record(
        record
    )
    return build_combined_assessment(
        submitted_url_result=submitted,
        final_url_result=final,
        page_result=page,
        reputation_result=reputation,
        destination_status=destination_status,
    )
