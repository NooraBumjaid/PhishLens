"""Presentation helpers used by Flask routes and Jinja templates.

Kept separate from app.py so route handlers stay focused on request/response
flow. Behavior is intentionally presentation-only (or thin orchestration for
rebuilding stored views); scoring and network logic live elsewhere.
"""

from analyzers.url_analyzer import coverage_for_indicators
from database.database import get_scan_by_id, save_combined_assessment
from services.combined_assessment import assess_scan_record
from time_format import format_bahrain_date, format_bahrain_datetime


def format_scan_timestamp(value):
    """Turn a stored ISO 8601 timestamp into a readable Bahrain time label."""
    return format_bahrain_datetime(value, missing="Unknown time")


def format_dashboard_date(value):
    """Return a short Bahrain calendar date for dashboard lists."""
    return format_bahrain_date(value, missing="—")


def dashboard_scan_label(scan):
    """Return the display target for a dashboard recent-scan row."""
    if (scan.get("scan_type") or "").lower() == "email":
        subject = scan.get("email_subject")
        if subject is None:
            subject = scan.get("target")
        text = str(subject).strip() if subject is not None else ""
        return text or "(No subject)"
    url = scan.get("normalized_url") or scan.get("target") or ""
    return str(url).strip()


def resolve_url_coverage(scan, indicators, inspection=None):
    """Return analysis coverage metadata for a URL scan.

    Newer scans store the values. Older rows may be NULL; those fall back
    to inference from stored shortener indicators, then to full/visible.
    A successful destination inspection upgrades coverage to comprehensive.
    """
    coverage = (scan.get("analysis_coverage") or "").strip().lower()
    status = (scan.get("destination_status") or "").strip().lower()
    if inspection and inspection.get("status") == "resolved":
        return {
            "analysis_coverage": "comprehensive",
            "destination_status": "resolved",
        }
    if coverage in ("full", "limited", "comprehensive") and status in (
        "visible",
        "hidden",
        "resolved",
    ):
        return {
            "analysis_coverage": coverage,
            "destination_status": status,
        }

    inferred = coverage_for_indicators(indicators)
    return {
        "analysis_coverage": (
            coverage
            if coverage in ("full", "limited", "comprehensive")
            else inferred["analysis_coverage"]
        ),
        "destination_status": (
            status
            if status in ("visible", "hidden", "resolved")
            else inferred["destination_status"]
        ),
    }


def inspection_label(inspection):
    """Return a short stored-inspection label for templates."""
    if not inspection:
        return "Not performed"
    status = (inspection.get("status") or "").lower()
    labels = {
        "resolved": "Resolved",
        "blocked": "Blocked",
        "failed": "Failed",
        "redirect_loop": "Failed",
        "redirect_limit_exceeded": "Failed",
        "completed": "Completed",
        "unsupported_content_type": "Failed",
    }
    return labels.get(status, status.replace("_", " ").capitalize() or "Not performed")


def page_inspection_label(inspection):
    """Return a short label for static page inspection status."""
    if not inspection:
        return "Not performed"
    status = (inspection.get("status") or "").lower()
    labels = {
        "completed": "Completed",
        "blocked": "Blocked",
        "failed": "Failed",
        "unsupported_content_type": "Failed",
        "redirect_loop": "Failed",
        "redirect_limit_exceeded": "Failed",
    }
    return labels.get(status, status.replace("_", " ").capitalize() or "Not performed")


def recompute_and_save_combined_assessment(scan_id):
    """Rebuild and store the combined assessment from current scan evidence."""
    record = get_scan_by_id(scan_id)
    if record is None or (record["scan"].get("scan_type") or "url") != "url":
        return None
    assessment = assess_scan_record(record)
    save_combined_assessment(scan_id, assessment)
    return assessment


def parse_history_page(value):
    """Return a page number of at least 1.

    Missing, blank, and non-numeric values become page 1.
    """
    if value is None:
        return 1
    try:
        page = int(str(value).strip())
    except (TypeError, ValueError):
        return 1
    if page < 1:
        return 1
    return page


def history_page_count(matching_count, per_page):
    """Return how many pages are needed for the matching scans."""
    if matching_count <= 0 or per_page <= 0:
        return 0
    return (matching_count + per_page - 1) // per_page


def stored_email_risk(scan, indicators, correlations):
    """Rebuild the email risk view from stored fields only."""
    return {
        "base_score": scan.get("base_score") if scan.get("base_score") is not None else 10,
        "indicator_contributions": [
            {
                "rule_name": item.get("rule_name"),
                "title": item.get("title"),
                "score_change": item.get("score_change", 0),
            }
            for item in indicators
        ],
        "correlations": [
            {
                "rule": item.get("rule_name"),
                "title": item.get("title"),
                "score_change": item.get("score_change", 0),
                "explanation": item.get("explanation"),
            }
            for item in correlations
        ],
        "raw_score": (
            scan.get("raw_score")
            if scan.get("raw_score") is not None
            else scan.get("risk_score")
        ),
        "final_score": scan.get("risk_score"),
        "classification": scan.get("classification"),
        "recommendation": scan.get("recommendation"),
    }


def stored_email_security(indicators, email_links):
    """Rebuild the email security view from stored fields only."""
    embedded_urls = []
    for item in email_links:
        summary = item.get("indicator_summary") or ""
        url_indicators = []
        for line in summary.splitlines():
            line = line.strip()
            if not line:
                continue
            if ": " in line:
                title, evidence = line.split(": ", 1)
                url_indicators.append({"title": title, "evidence": evidence})
            else:
                url_indicators.append({"title": line, "evidence": ""})
        embedded_urls.append(
            {
                "url": item.get("url_text"),
                "score": item.get("risk_score"),
                "classification": item.get("classification"),
                "indicators": url_indicators,
            }
        )
    return {
        "indicators": indicators,
        "embedded_urls": embedded_urls,
    }
