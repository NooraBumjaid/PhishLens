import sqlite3

from flask import Flask, Response, redirect, render_template, request

from analyzers.email_analyzer import EmailValidationError, parse_email, validate_email_input
from analyzers.email_security import analyze_email_security
from analyzers.reputation import check_url_reputation, get_reputation_availability
from analyzers.url_analyzer import (
    URLValidationError,
    analyze_url,
)
from config.reputation_settings import ALLOWED_TARGET_TYPES
from config.security import (
    MAX_FORM_FIELD_LENGTH,
    MAX_SEARCH_LENGTH,
    RATE_LIMIT_ANALYZE_EMAIL,
    RATE_LIMIT_ANALYZE_URL,
    RATE_LIMIT_INSPECT_DESTINATION,
    RATE_LIMIT_INSPECT_PAGE,
    RATE_LIMIT_REPUTATION,
)
from database.database import (
    ALLOWED_CLASSIFICATIONS,
    ALLOWED_SCAN_TYPES,
    count_scans,
    get_dashboard_summary,
    get_recent_activity,
    get_recent_scans,
    get_scan_by_id,
    get_scan_statistics,
    get_scans,
    get_top_indicators,
    init_db,
    save_combined_assessment,
    save_email_scan,
    save_page_inspection,
    save_redirect_inspection,
    save_reputation_check,
    save_scan,
    update_scan_coverage,
)
from security_bootstrap import configure_app, limiter
from services.combined_assessment import (
    assess_scan_record,
    build_combined_assessment,
)
from services.email_risk_engine import calculate_email_risk
from services.page_analyzer import analyze_page_html
from services.page_risk_engine import calculate_page_risk
from services.report_generator import generate_email_report, generate_url_report
from services.risk_engine import calculate_risk
from services.safe_redirect_resolver import fetch_safe_page, resolve_redirect_chain
from view_helpers import (
    dashboard_scan_label,
    format_dashboard_date,
    format_scan_timestamp,
    history_page_count,
    inspection_label,
    page_inspection_label,
    parse_history_page,
    recompute_and_save_combined_assessment,
    resolve_url_coverage,
    stored_email_risk,
    stored_email_security,
)

app = Flask(__name__)
configure_app(app)

HISTORY_PAGE_SIZE = 10

app.template_filter("format_timestamp")(format_scan_timestamp)


@app.route("/")
def home():
    """Show the PhishLens landing page."""
    return render_template("home.html")


@app.route("/health")
def health():
    """Lightweight liveness check for load balancers and deploy platforms.

    Does not touch the database, resolve URLs, inspect pages, or call VirusTotal.
    """
    return {"status": "ok"}


@app.route("/url")
def url_analyzer():
    """Show the URL analyzer form."""
    return render_template("url.html")


@app.route("/analyze", methods=["POST"])
@limiter.limit(RATE_LIMIT_ANALYZE_URL)
def analyze():
    """Receive a submitted URL and show it on the results page."""
    submitted_url = (request.form.get("url") or "").strip()

    if not submitted_url:
        return render_template(
            "url.html",
            error="Please enter a URL.",
        )

    try:
        result = analyze_url(submitted_url)
    except URLValidationError as error:
        return render_template("url.html", error=str(error))

    risk = calculate_risk(result["indicators"])
    risk["analysis_coverage"] = result["analysis_coverage"]
    risk["destination_status"] = result["destination_status"]
    # Availability only — never call VirusTotal during local analysis.
    reputation = get_reputation_availability()
    scan_id = None
    save_error = None
    combined = build_combined_assessment(
        submitted_url_result={
            "score": risk.get("final_score"),
            "classification": risk.get("classification"),
            "indicators": result["indicators"],
            "has_shortener": any(
                (item or {}).get("rule") == "url_shortener"
                or (item or {}).get("rule_name") == "url_shortener"
                for item in result["indicators"]
            ),
        }
    )
    # Always expose an integer for the top card (never rely on Jinja Undefined).
    if combined.get("score") is None:
        combined["score"] = int(risk.get("final_score") or 0)

    try:
        init_db()
        scan_id = save_scan(result["parsed"], risk)
        if scan_id is not None:
            save_combined_assessment(scan_id, combined)
    except sqlite3.Error:
        app.logger.exception("The analysis could not be saved")
        save_error = (
            "The analysis completed, but the result could not be saved "
            "to scan history."
        )

    return render_template(
        "results.html",
        parsed=result["parsed"],
        indicators=result["indicators"],
        risk=risk,
        analysis_coverage=result["analysis_coverage"],
        destination_status=result["destination_status"],
        reputation=reputation,
        reputation_checks={},
        combined_assessment=combined,
        scan_id=scan_id,
        save_error=save_error,
        can_inspect_destination=bool(scan_id),
        can_inspect_page=False,
        can_check_reputation=bool(scan_id and reputation.get("status") == "available"),
        can_check_final_reputation=False,
        redirect_inspection=None,
        page_inspection=None,
        inspection_status_label="Not performed",
        page_inspection_status_label="Not performed",
    )


@app.route("/dashboard")
def dashboard():
    """Show descriptive analytics from locally stored analyses."""
    try:
        init_db()
        summary = get_dashboard_summary()
        activity = get_recent_activity(days=7)
        indicators = get_top_indicators(limit=5)
        recent = get_recent_scans(limit=5)
    except sqlite3.Error:
        app.logger.exception("Security dashboard could not be loaded")
        return render_template("dashboard.html", load_error=True)

    total = summary["total"]
    risk_total = (
        summary["low_risk"] + summary["suspicious"] + summary["high_risk"]
    )
    if risk_total:
        risk_segments = {
            "low_pct": round(100 * summary["low_risk"] / risk_total, 2),
            "suspicious_pct": round(100 * summary["suspicious"] / risk_total, 2),
            "high_pct": round(100 * summary["high_risk"] / risk_total, 2),
        }
    else:
        risk_segments = {
            "low_pct": 0,
            "suspicious_pct": 0,
            "high_pct": 0,
        }

    activity_max = max((item["total"] for item in activity), default=0)
    recent_rows = [
        {
            **scan,
            "display_target": dashboard_scan_label(scan),
            "date_label": format_dashboard_date(scan.get("created_at")),
        }
        for scan in recent
    ]

    return render_template(
        "dashboard.html",
        summary=summary,
        risk_segments=risk_segments,
        activity=activity,
        activity_max=activity_max,
        indicators=indicators,
        recent_scans=recent_rows,
        load_error=False,
        is_empty=total == 0,
    )


@app.route("/history")
def history():
    """Show saved scans without analyzing them again."""
    search = (request.args.get("q") or "").strip()[:MAX_SEARCH_LENGTH]
    requested_classification = (request.args.get("classification") or "").strip()
    if len(requested_classification) > MAX_FORM_FIELD_LENGTH:
        requested_classification = requested_classification[:MAX_FORM_FIELD_LENGTH]
    if requested_classification in ALLOWED_CLASSIFICATIONS:
        classification = requested_classification
    else:
        classification = ""
    requested_type = (request.args.get("type") or "").strip().lower()
    if len(requested_type) > MAX_FORM_FIELD_LENGTH:
        requested_type = requested_type[:MAX_FORM_FIELD_LENGTH]
    if requested_type in ALLOWED_SCAN_TYPES:
        scan_type = requested_type
    else:
        scan_type = ""
    page = parse_history_page(request.args.get("page"))

    try:
        init_db()
        statistics = get_scan_statistics()
        matching_count = count_scans(
            search=search,
            classification=classification or None,
            scan_type=scan_type or None,
        )
        total_pages = history_page_count(matching_count, HISTORY_PAGE_SIZE)
        if total_pages and page > total_pages:
            page = total_pages
        scans = get_scans(
            search=search,
            classification=classification or None,
            scan_type=scan_type or None,
            page=page,
            per_page=HISTORY_PAGE_SIZE,
        )
    except sqlite3.Error:
        app.logger.exception("Scan history could not be loaded")
        return render_template("history.html", load_error=True)

    if scans:
        range_start = (page - 1) * HISTORY_PAGE_SIZE + 1
        range_end = range_start + len(scans) - 1
    else:
        range_start = None
        range_end = None

    return render_template(
        "history.html",
        scans=scans,
        statistics=statistics,
        search=search,
        classification=classification,
        scan_type=scan_type,
        filters_active=bool(search or classification or scan_type),
        matching_count=matching_count,
        page=page,
        total_pages=total_pages,
        range_start=range_start,
        range_end=range_end,
        load_error=False,
    )


@app.route("/scan/<int:scan_id>")
def scan_detail(scan_id):
    """Show the result that was stored for this scan."""
    try:
        init_db()
        record = get_scan_by_id(scan_id)
    except sqlite3.Error:
        app.logger.exception("A saved scan could not be loaded")
        return render_template("not_found.html", load_error=True), 500

    if record is None:
        return render_template("not_found.html"), 404

    scan = record["scan"]
    if scan.get("scan_type") == "email":
        return render_template(
            "email_scan_detail.html",
            scan=scan,
            indicators=record["indicators"],
            correlations=record["correlations"],
            risk=stored_email_risk(
                scan,
                record["indicators"],
                record["correlations"],
            ),
            security=stored_email_security(
                record["indicators"],
                record["email_links"],
            ),
            attachments=record["email_attachments"],
        )

    inspection = record.get("redirect_inspection")
    page_inspection = record.get("page_inspection")
    reputation_checks = record.get("reputation_checks") or {}
    combined_assessment = record.get("combined_assessment")
    # Recompute offline from stored layers for missing fields / legacy rows.
    # Prefer stored label/reasons/score when present (historical integrity).
    fresh = assess_scan_record(record)
    if combined_assessment is None:
        combined_assessment = fresh
    else:
        if combined_assessment.get("score") is None:
            combined_assessment["score"] = fresh.get("score")
        if not combined_assessment.get("breakdown"):
            combined_assessment["breakdown"] = fresh.get("breakdown")
        if not combined_assessment.get("reasons"):
            combined_assessment["reasons"] = fresh.get("reasons") or []
        if not combined_assessment.get("layers_not_checked"):
            combined_assessment["layers_not_checked"] = fresh.get(
                "layers_not_checked"
            )
        if not combined_assessment.get("layers_checked"):
            combined_assessment["layers_checked"] = fresh.get("layers_checked")
        if not combined_assessment.get("summary"):
            combined_assessment["summary"] = fresh.get("summary")
    reputation = get_reputation_availability()
    coverage = resolve_url_coverage(scan, record["indicators"], inspection)
    can_inspect_page = bool(
        inspection
        and inspection.get("status") == "resolved"
        and inspection.get("final_url")
        and (not page_inspection or page_inspection.get("status") != "completed")
    )
    return render_template(
        "scan_detail.html",
        scan=scan,
        indicators=record["indicators"],
        correlations=record["correlations"],
        analysis_coverage=coverage["analysis_coverage"],
        destination_status=coverage["destination_status"],
        redirect_inspection=inspection,
        page_inspection=page_inspection,
        reputation=reputation,
        reputation_checks=reputation_checks,
        combined_assessment=combined_assessment,
        inspection_status_label=inspection_label(inspection),
        page_inspection_status_label=page_inspection_label(page_inspection),
        can_inspect_destination=bool(
            not inspection or (inspection.get("status") or "").strip().lower() != "resolved"
        ),
        can_inspect_page=can_inspect_page,
        can_check_reputation=reputation.get("status") == "available",
        can_check_final_reputation=bool(
            reputation.get("status") == "available"
            and inspection
            and inspection.get("status") == "resolved"
            and inspection.get("final_url")
        ),
    )


@app.route("/inspect-destination", methods=["POST"])
@limiter.limit(RATE_LIMIT_INSPECT_DESTINATION)
def inspect_destination():
    """Optionally resolve redirects for a stored URL scan and analyze the final URL."""
    raw_scan_id = (request.form.get("scan_id") or "").strip()[:MAX_FORM_FIELD_LENGTH]
    try:
        scan_id = int(raw_scan_id)
    except (TypeError, ValueError):
        return render_template("not_found.html"), 404

    try:
        init_db()
        record = get_scan_by_id(scan_id)
    except sqlite3.Error:
        app.logger.exception("Destination inspection could not load the scan")
        return render_template("not_found.html", load_error=True), 500

    if record is None or (record["scan"].get("scan_type") or "url") != "url":
        return render_template("not_found.html"), 404

    scan = record["scan"]
    target_url = (scan.get("normalized_url") or "").strip()
    if not target_url:
        hostname = (scan.get("target") or "").strip()
        target_url = f"https://{hostname}" if hostname else ""

    if not target_url:
        return render_template("not_found.html"), 404

    resolution = resolve_redirect_chain(target_url)
    final_risk = None
    final_indicators = []
    final_correlations = []

    if resolution.get("status") == "resolved" and resolution.get("final_url"):
        try:
            final_analysis = analyze_url(resolution["final_url"])
            final_risk = calculate_risk(final_analysis["indicators"])
            final_indicators = final_analysis["indicators"]
            final_correlations = final_risk.get("correlations") or []
            update_scan_coverage(scan_id, "comprehensive", "resolved")
        except URLValidationError:
            app.logger.exception("Final destination URL failed local validation")
            resolution = {
                **resolution,
                "status": "failed",
                "reason": "The final destination URL could not be analyzed locally.",
                "final_url": None,
            }
            final_risk = None
            final_indicators = []
            final_correlations = []

    try:
        save_redirect_inspection(
            scan_id,
            resolution,
            final_risk=final_risk,
            final_indicators=final_indicators,
            final_correlations=final_correlations,
        )
        recompute_and_save_combined_assessment(scan_id)
    except sqlite3.Error:
        app.logger.exception("Destination inspection could not be saved")
        return render_template("not_found.html", load_error=True), 500

    return redirect(f"/scan/{scan_id}")


@app.route("/check-reputation", methods=["POST"])
@limiter.limit(RATE_LIMIT_REPUTATION)
def check_reputation():
    """Look up stored VirusTotal reputation for a submitted or final URL."""
    raw_scan_id = (request.form.get("scan_id") or "").strip()[:MAX_FORM_FIELD_LENGTH]
    target_type = (request.form.get("target_type") or "submitted_url").strip().lower()
    target_type = target_type[:MAX_FORM_FIELD_LENGTH]
    try:
        scan_id = int(raw_scan_id)
    except (TypeError, ValueError):
        return render_template("not_found.html"), 404

    if target_type not in ALLOWED_TARGET_TYPES:
        return render_template("not_found.html"), 404

    try:
        init_db()
        record = get_scan_by_id(scan_id)
    except sqlite3.Error:
        app.logger.exception("Reputation check could not load the scan")
        return render_template("not_found.html", load_error=True), 500

    if record is None or (record["scan"].get("scan_type") or "url") != "url":
        return render_template("not_found.html"), 404

    scan = record["scan"]
    if target_type == "submitted_url":
        target_url = (scan.get("normalized_url") or "").strip()
        if not target_url:
            hostname = (scan.get("target") or "").strip()
            target_url = f"https://{hostname}" if hostname else ""
    else:
        redirect_record = record.get("redirect_inspection") or {}
        if redirect_record.get("status") != "resolved":
            return redirect(f"/scan/{scan_id}")
        target_url = (redirect_record.get("final_url") or "").strip()

    if not target_url:
        return redirect(f"/scan/{scan_id}")

    result = check_url_reputation(target_url, target_type=target_type)
    try:
        if result.get("status") not in {"disabled", "not_configured"}:
            save_reputation_check(scan_id, result)
        recompute_and_save_combined_assessment(scan_id)
    except sqlite3.Error:
        app.logger.exception("Reputation check could not be saved")
        return render_template("not_found.html", load_error=True), 500

    return redirect(f"/scan/{scan_id}")


@app.route("/inspect-page", methods=["POST"])
@limiter.limit(RATE_LIMIT_INSPECT_PAGE)
def inspect_page():
    """Optionally fetch and statically analyze limited HTML from a resolved URL."""
    raw_scan_id = (request.form.get("scan_id") or "").strip()[:MAX_FORM_FIELD_LENGTH]
    try:
        scan_id = int(raw_scan_id)
    except (TypeError, ValueError):
        return render_template("not_found.html"), 404

    try:
        init_db()
        record = get_scan_by_id(scan_id)
    except sqlite3.Error:
        app.logger.exception("Page inspection could not load the scan")
        return render_template("not_found.html", load_error=True), 500

    if record is None or (record["scan"].get("scan_type") or "url") != "url":
        return render_template("not_found.html"), 404

    redirect_record = record.get("redirect_inspection")
    if not redirect_record or redirect_record.get("status") != "resolved":
        return redirect(f"/scan/{scan_id}")

    page_url = (redirect_record.get("final_url") or "").strip()
    if not page_url:
        return redirect(f"/scan/{scan_id}")

    fetch_result = fetch_safe_page(page_url)
    analysis = None
    page_risk = None

    if fetch_result.get("status") == "completed" and fetch_result.get("html") is not None:
        analysis = analyze_page_html(fetch_result["html"], fetch_result.get("page_url") or page_url)
        page_risk = calculate_page_risk(analysis.get("indicators") or [])
        # Do not retain HTML after analysis.
        fetch_result = {**fetch_result, "html": None}

    try:
        save_page_inspection(
            scan_id,
            fetch_result,
            analysis=analysis,
            page_risk=page_risk,
        )
        recompute_and_save_combined_assessment(scan_id)
    except sqlite3.Error:
        app.logger.exception("Page inspection could not be saved")
        return render_template("not_found.html", load_error=True), 500

    return redirect(f"/scan/{scan_id}")


@app.route("/scan/<int:scan_id>/report")
def scan_report(scan_id):
    """Download a PDF built from the stored scan result.

    The analysis is not run again. Missing scans return 404.
    """
    try:
        init_db()
        record = get_scan_by_id(scan_id)
    except sqlite3.Error:
        app.logger.exception("A saved scan report could not be loaded")
        return render_template("not_found.html", load_error=True), 500

    if record is None:
        return render_template("not_found.html"), 404

    scan = record["scan"]
    if scan.get("scan_type") == "email":
        pdf_bytes = generate_email_report(record)
        filename = f"phishlens-email-report-{scan_id}.pdf"
    else:
        pdf_bytes = generate_url_report(record)
        filename = f"phishlens-url-report-{scan_id}.pdf"

    return Response(
        pdf_bytes,
        mimetype="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
        },
    )


@app.route("/email")
def email():
    """Show the email paste form."""
    return render_template("email.html")


@app.route("/analyze-email", methods=["POST"])
@limiter.limit(RATE_LIMIT_ANALYZE_EMAIL)
def analyze_email():
    """Parse pasted email text and score the local indicators. No network calls."""
    raw_email = request.form.get("raw_email", "")
    try:
        validate_email_input(raw_email)
    except EmailValidationError as error:
        return render_template("email.html", error=str(error))

    try:
        parsed = parse_email(raw_email)
    except EmailValidationError as error:
        return render_template("email.html", error=str(error))
    except Exception:
        app.logger.exception("The email could not be parsed")
        return render_template(
            "email.html",
            error="The email could not be parsed.",
        )

    security = analyze_email_security(parsed)
    risk = calculate_email_risk(security["indicators"])
    scan_id = None
    save_error = None

    try:
        init_db()
        scan_id = save_email_scan(parsed, security, risk)
    except sqlite3.Error:
        app.logger.exception("The email analysis could not be saved")
        save_error = (
            "The analysis completed, but the result could not be saved "
            "to scan history."
        )

    return render_template(
        "email_results.html",
        parsed=parsed,
        security=security,
        risk=risk,
        scan_id=scan_id,
        save_error=save_error,
    )


if __name__ == "__main__":
    # Development entrypoint only. Production must use a WSGI server (Step 30).
    app.run(
        debug=bool(app.config.get("DEBUG")),
        use_reloader=bool(app.config.get("DEBUG")),
    )
