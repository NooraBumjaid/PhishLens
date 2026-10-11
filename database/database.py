"""Store completed URL and email analyses in a local SQLite database.

Python creates the database file the first time a connection is opened.
Starting the app again does not delete existing scans.

Override the path with DATABASE_PATH for production persistent storage.
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

from time_format import format_month_day


def resolve_db_path():
    """Return the configured SQLite path (env override or development default)."""
    raw = (os.getenv("DATABASE_PATH") or "").strip()
    if raw:
        return Path(raw).expanduser().resolve()
    return Path(__file__).resolve().parent / "scans.db"


# Tests may patch this module attribute to use a temporary database.
DB_PATH = resolve_db_path()

ALLOWED_CLASSIFICATIONS = ("Low Risk", "Suspicious", "High Risk")
ALLOWED_SCAN_TYPES = ("url", "email")

_EMAIL_SCAN_COLUMNS = (
    ("email_from", "TEXT"),
    ("email_to", "TEXT"),
    ("email_subject", "TEXT"),
    ("email_date", "TEXT"),
    ("base_score", "INTEGER"),
    ("raw_score", "INTEGER"),
)

_URL_COVERAGE_COLUMNS = (
    ("analysis_coverage", "TEXT"),
    ("destination_status", "TEXT"),
)

# Combined assessment score/breakdown for historical integrity (idempotent).
_COMBINED_ASSESSMENT_COLUMNS = (
    ("score", "INTEGER"),
    ("breakdown_json", "TEXT"),
)


def get_db_connection():
    """Open SQLite with foreign keys enabled."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def _table_columns(connection, table_name):
    """Return the column names for one table."""
    rows = connection.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {row["name"] for row in rows}


def _ensure_column(connection, table_name, column_name, column_type):
    """Add one column when an older database does not already have it."""
    if column_name in _table_columns(connection, table_name):
        return
    connection.execute(
        f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"
    )


def migrate_db(connection=None):
    """Apply Step 20 email columns and related tables safely.

    Safe to run on an existing URL-only database and to run more than once.
    """
    owns_connection = connection is None
    if owns_connection:
        connection = get_db_connection()
    try:
        for column_name, column_type in _EMAIL_SCAN_COLUMNS:
            _ensure_column(connection, "scans", column_name, column_type)
        for column_name, column_type in _URL_COVERAGE_COLUMNS:
            _ensure_column(connection, "scans", column_name, column_type)

        # Ensure combined_assessments exists before adding newer columns.
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS combined_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL UNIQUE,
                assessment TEXT NOT NULL,
                label TEXT NOT NULL,
                coverage TEXT NOT NULL,
                summary TEXT,
                recommendation TEXT,
                score INTEGER,
                breakdown_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS combined_assessment_reasons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL,
                position INTEGER NOT NULL,
                reason_text TEXT NOT NULL,
                FOREIGN KEY (assessment_id) REFERENCES combined_assessments(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_combined_assessments_scan_id
                ON combined_assessments (scan_id);
            """
        )
        for column_name, column_type in _COMBINED_ASSESSMENT_COLUMNS:
            _ensure_column(connection, "combined_assessments", column_name, column_type)

        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS email_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                url_text TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                indicator_summary TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS email_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                filename TEXT,
                content_type TEXT,
                size INTEGER,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scans_scan_type
                ON scans (scan_type);

            CREATE INDEX IF NOT EXISTS idx_indicators_scan_id
                ON indicators (scan_id);

            CREATE INDEX IF NOT EXISTS idx_indicators_rule_name
                ON indicators (rule_name);

            CREATE TABLE IF NOT EXISTS redirect_inspections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                submitted_url TEXT,
                final_url TEXT,
                redirect_count INTEGER,
                final_risk_score INTEGER,
                final_classification TEXT,
                final_recommendation TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS redirect_hops (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inspection_id INTEGER NOT NULL,
                hop_number INTEGER NOT NULL,
                url_text TEXT NOT NULL,
                http_status INTEGER,
                FOREIGN KEY (inspection_id) REFERENCES redirect_inspections(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS final_url_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inspection_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                score_change INTEGER NOT NULL,
                severity TEXT,
                explanation TEXT,
                evidence TEXT,
                FOREIGN KEY (inspection_id) REFERENCES redirect_inspections(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS final_url_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inspection_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                score_change INTEGER NOT NULL,
                explanation TEXT,
                FOREIGN KEY (inspection_id) REFERENCES redirect_inspections(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_redirect_inspections_scan_id
                ON redirect_inspections (scan_id);

            CREATE INDEX IF NOT EXISTS idx_redirect_hops_inspection_id
                ON redirect_hops (inspection_id, hop_number);

            CREATE INDEX IF NOT EXISTS idx_final_url_indicators_inspection_id
                ON final_url_indicators (inspection_id);

            CREATE TABLE IF NOT EXISTS page_inspections (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                reason TEXT,
                page_url TEXT,
                page_title TEXT,
                risk_score INTEGER,
                classification TEXT,
                limited_static_content INTEGER DEFAULT 0,
                truncated INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS page_indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inspection_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT,
                score_change INTEGER NOT NULL,
                explanation TEXT,
                evidence TEXT,
                FOREIGN KEY (inspection_id) REFERENCES page_inspections(id)
                    ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS page_correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                inspection_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                score_change INTEGER NOT NULL,
                explanation TEXT,
                FOREIGN KEY (inspection_id) REFERENCES page_inspections(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_page_inspections_scan_id
                ON page_inspections (scan_id);

            CREATE TABLE IF NOT EXISTS reputation_checks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                target_type TEXT NOT NULL,
                target_url TEXT,
                provider TEXT NOT NULL,
                status TEXT NOT NULL,
                message TEXT,
                malicious_count INTEGER,
                suspicious_count INTEGER,
                harmless_count INTEGER,
                undetected_count INTEGER,
                total_engines INTEGER,
                checked_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_reputation_checks_scan_id
                ON reputation_checks (scan_id);

            CREATE INDEX IF NOT EXISTS idx_reputation_checks_scan_target
                ON reputation_checks (scan_id, target_type, created_at);

            CREATE TABLE IF NOT EXISTS combined_assessments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL UNIQUE,
                assessment TEXT NOT NULL,
                label TEXT NOT NULL,
                coverage TEXT NOT NULL,
                summary TEXT,
                recommendation TEXT,
                score INTEGER,
                breakdown_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS combined_assessment_reasons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                assessment_id INTEGER NOT NULL,
                position INTEGER NOT NULL,
                reason_text TEXT NOT NULL,
                FOREIGN KEY (assessment_id) REFERENCES combined_assessments(id)
                    ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_combined_assessments_scan_id
                ON combined_assessments (scan_id);
            """
        )
        if owns_connection:
            connection.commit()
    finally:
        if owns_connection:
            connection.close()


def init_db():
    """Create scan tables if they do not exist yet, then migrate."""
    connection = get_db_connection()
    try:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                normalized_url TEXT,
                risk_score INTEGER NOT NULL,
                classification TEXT NOT NULL,
                recommendation TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS indicators (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                score_change INTEGER NOT NULL,
                severity TEXT,
                explanation TEXT,
                evidence TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS correlations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id INTEGER NOT NULL,
                rule_name TEXT NOT NULL,
                title TEXT NOT NULL,
                score_change INTEGER NOT NULL,
                explanation TEXT,
                FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_scans_created_at_id
                ON scans (created_at, id);

            CREATE INDEX IF NOT EXISTS idx_scans_classification
                ON scans (classification);
            """
        )
        migrate_db(connection)
        connection.commit()
    finally:
        connection.close()


def save_scan(parsed, risk, scan_type="url"):
    """Save one completed URL analysis and return its scan id.

    The scan, its indicators, and its correlations are written in one
    transaction. If any insert fails, none of that scan is kept.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    connection = get_db_connection()
    try:
        with connection:
            result = connection.execute(
                """
                INSERT INTO scans (
                    scan_type,
                    target,
                    normalized_url,
                    risk_score,
                    classification,
                    recommendation,
                    created_at,
                    analysis_coverage,
                    destination_status
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_type,
                    # Prefer the original submitted URL for history display/copy.
                    (
                        parsed.get("submitted_url")
                        or parsed.get("normalized_url")
                        or parsed.get("hostname")
                        or ""
                    ),
                    parsed.get("normalized_url"),
                    risk["final_score"],
                    risk["classification"],
                    risk.get("recommendation"),
                    created_at,
                    risk.get("analysis_coverage"),
                    risk.get("destination_status"),
                ),
            )
            scan_id = result.lastrowid

            for indicator in risk.get("indicators", []):
                connection.execute(
                    """
                    INSERT INTO indicators (
                        scan_id,
                        rule_name,
                        title,
                        score_change,
                        severity,
                        explanation,
                        evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        indicator["rule"],
                        indicator["title"],
                        indicator["score_change"],
                        indicator.get("severity"),
                        indicator.get("explanation"),
                        indicator.get("evidence"),
                    ),
                )

            for correlation in risk.get("correlations", []):
                connection.execute(
                    """
                    INSERT INTO correlations (
                        scan_id,
                        rule_name,
                        title,
                        score_change,
                        explanation
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        correlation["rule"],
                        correlation["title"],
                        correlation["score_change"],
                        correlation.get("explanation"),
                    ),
                )
        return scan_id
    finally:
        connection.close()


def _email_subject(parsed):
    """Return a concise subject for history display."""
    subject = (parsed.get("headers") or {}).get("subject")
    if subject is None:
        return "(No subject)"
    text = str(subject).strip()
    if not text:
        return "(No subject)"
    return text


def _link_indicator_summary(indicators):
    """Build a compact plain-text summary of local URL indicators."""
    lines = []
    for indicator in indicators or []:
        title = (indicator.get("title") or "").strip()
        if not title:
            continue
        evidence = (indicator.get("evidence") or "").strip()
        if evidence:
            lines.append(f"{title}: {evidence}")
        else:
            lines.append(title)
    return "\n".join(lines) if lines else None


def save_email_scan(parsed, security, risk):
    """Save one completed email analysis without the raw message body.

    Indicators, correlations, embedded-link summaries, and attachment
    metadata are written in one transaction. The full email body is not stored.
    """
    headers = parsed.get("headers") or {}
    subject = _email_subject(parsed)
    created_at = datetime.now(timezone.utc).isoformat()
    contribution_weights = {
        item.get("rule_name"): item.get("score_change", 0)
        for item in risk.get("indicator_contributions", [])
    }

    connection = get_db_connection()
    try:
        with connection:
            result = connection.execute(
                """
                INSERT INTO scans (
                    scan_type,
                    target,
                    normalized_url,
                    risk_score,
                    classification,
                    recommendation,
                    created_at,
                    email_from,
                    email_to,
                    email_subject,
                    email_date,
                    base_score,
                    raw_score
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "email",
                    subject,
                    None,
                    risk["final_score"],
                    risk["classification"],
                    risk.get("recommendation"),
                    created_at,
                    headers.get("from") or None,
                    headers.get("to") or None,
                    subject,
                    headers.get("date") or None,
                    risk.get("base_score"),
                    risk.get("raw_score"),
                ),
            )
            scan_id = result.lastrowid

            for indicator in security.get("indicators", []):
                rule_name = indicator.get("rule_name")
                connection.execute(
                    """
                    INSERT INTO indicators (
                        scan_id,
                        rule_name,
                        title,
                        score_change,
                        severity,
                        explanation,
                        evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        rule_name,
                        indicator.get("title") or rule_name,
                        contribution_weights.get(rule_name, 0),
                        indicator.get("severity"),
                        indicator.get("explanation"),
                        indicator.get("evidence"),
                    ),
                )

            for correlation in risk.get("correlations", []):
                connection.execute(
                    """
                    INSERT INTO correlations (
                        scan_id,
                        rule_name,
                        title,
                        score_change,
                        explanation
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        correlation.get("rule"),
                        correlation.get("title"),
                        correlation.get("score_change"),
                        correlation.get("explanation"),
                    ),
                )

            for item in security.get("embedded_urls", []):
                connection.execute(
                    """
                    INSERT INTO email_links (
                        scan_id,
                        url_text,
                        risk_score,
                        classification,
                        indicator_summary
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        item.get("url") or "",
                        item.get("score"),
                        item.get("classification"),
                        _link_indicator_summary(item.get("indicators")),
                    ),
                )

            for attachment in parsed.get("attachments") or []:
                connection.execute(
                    """
                    INSERT INTO email_attachments (
                        scan_id,
                        filename,
                        content_type,
                        size
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        attachment.get("filename"),
                        attachment.get("content_type"),
                        attachment.get("size"),
                    ),
                )
        return scan_id
    finally:
        connection.close()


def get_all_scans():
    """Return all saved scans, newest first (unpaginated helper)."""
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                id,
                scan_type,
                target,
                normalized_url,
                risk_score,
                classification,
                recommendation,
                created_at,
                email_from,
                email_to,
                email_subject,
                email_date,
                base_score,
                raw_score
            FROM scans
            ORDER BY created_at DESC, id DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def _search_like_pattern(search):
    """Turn search text into a literal substring pattern.

    % and _ are escaped so they match those characters, not every row.
    """
    escaped = (
        str(search)
        .replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
    )
    return f"%{escaped}%"


def get_scan_statistics():
    """Count every saved scan by its stored classification and type."""
    connection = get_db_connection()
    try:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN classification = 'Low Risk' THEN 1 ELSE 0 END), 0) AS low_risk,
                COALESCE(SUM(CASE WHEN classification = 'Suspicious' THEN 1 ELSE 0 END), 0) AS suspicious,
                COALESCE(SUM(CASE WHEN classification = 'High Risk' THEN 1 ELSE 0 END), 0) AS high_risk,
                COALESCE(SUM(CASE WHEN scan_type = 'url' THEN 1 ELSE 0 END), 0) AS url_scans,
                COALESCE(SUM(CASE WHEN scan_type = 'email' THEN 1 ELSE 0 END), 0) AS email_scans
            FROM scans
            """
        ).fetchone()
        return {
            "total": row["total"],
            "low_risk": row["low_risk"],
            "suspicious": row["suspicious"],
            "high_risk": row["high_risk"],
            "url_scans": row["url_scans"],
            "email_scans": row["email_scans"],
        }
    finally:
        connection.close()


def _scan_filter(search, classification, scan_type=None, table_alias=""):
    """Build a parameterized WHERE clause for history search and filters.

    The returned SQL contains only fixed clause text. Search text,
    classification, and scan type are returned separately for binding.
    Optional table_alias (for example ``s``) prefixes column names.
    """
    prefix = f"{table_alias}." if table_alias else ""
    clauses = []
    params = []
    if search is not None and str(search).strip():
        pattern = _search_like_pattern(str(search).strip())
        clauses.append(
            "("
            f"{prefix}target LIKE ? ESCAPE '\\' OR "
            f"COALESCE({prefix}normalized_url, '') LIKE ? ESCAPE '\\' OR "
            f"COALESCE({prefix}email_subject, '') LIKE ? ESCAPE '\\' OR "
            f"COALESCE({prefix}email_from, '') LIKE ? ESCAPE '\\'"
            ")"
        )
        params.extend([pattern, pattern, pattern, pattern])
    if classification in ALLOWED_CLASSIFICATIONS:
        clauses.append(f"{prefix}classification = ?")
        params.append(classification)
    if scan_type in ALLOWED_SCAN_TYPES:
        clauses.append(f"{prefix}scan_type = ?")
        params.append(scan_type)
    if not clauses:
        return "", params
    return "WHERE " + " AND ".join(clauses), params


def _page_bounds(page, per_page):
    """Turn a page request into a safe LIMIT and OFFSET."""
    try:
        page_number = int(page)
    except (TypeError, ValueError):
        page_number = 1
    try:
        page_size = int(per_page)
    except (TypeError, ValueError):
        page_size = 10
    if page_number < 1:
        page_number = 1
    if page_size < 1:
        page_size = 10
    offset = (page_number - 1) * page_size
    return page_size, offset


def count_scans(search=None, classification=None, scan_type=None):
    """Count scans that match the current search and filters.

    This is not the dashboard total. An unknown classification or type
    counts every scan for that filter, matching the All fallback.
    """
    where, params = _scan_filter(search, classification, scan_type)
    connection = get_db_connection()
    try:
        row = connection.execute(
            f"SELECT COUNT(*) AS total FROM scans {where}",
            params,
        ).fetchone()
        return row["total"]
    finally:
        connection.close()


def get_scans(search=None, classification=None, scan_type=None, page=1, per_page=10):
    """Return one page of saved scans, newest first.

    Search text, classification, type, limit, and offset are bound parameters.
    An unknown classification or type is ignored, which is the same as All.

    URL rows include url_scan_count from one grouped join (not per-row queries)
    so the history UI can mark repeated normalized URLs.
    """
    where, params = _scan_filter(
        search, classification, scan_type, table_alias="s"
    )
    limit, offset = _page_bounds(page, per_page)
    connection = get_db_connection()
    try:
        rows = connection.execute(
            f"""
            SELECT
                s.id,
                s.scan_type,
                s.target,
                s.normalized_url,
                s.risk_score,
                s.classification,
                s.recommendation,
                s.created_at,
                s.email_from,
                s.email_to,
                s.email_subject,
                s.email_date,
                s.base_score,
                s.raw_score,
                CASE
                    WHEN s.scan_type = 'url'
                         AND s.normalized_url IS NOT NULL
                         AND TRIM(s.normalized_url) != ''
                    THEN COALESCE(dup.url_scan_count, 1)
                    ELSE 1
                END AS url_scan_count
            FROM scans AS s
            LEFT JOIN (
                SELECT normalized_url, COUNT(*) AS url_scan_count
                FROM scans
                WHERE scan_type = 'url'
                  AND normalized_url IS NOT NULL
                  AND TRIM(normalized_url) != ''
                GROUP BY normalized_url
            ) AS dup
                ON s.scan_type = 'url'
               AND s.normalized_url = dup.normalized_url
            {where}
            ORDER BY s.created_at DESC, s.id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, limit, offset],
        ).fetchall()
        results = []
        for row in rows:
            item = dict(row)
            item["url_scan_count"] = int(item.get("url_scan_count") or 1)
            item["is_repeated_url"] = (
                (item.get("scan_type") or "url") == "url" and item["url_scan_count"] > 1
            )
            results.append(item)
        return results
    finally:
        connection.close()


def get_scan_by_id(scan_id):
    """Return one stored scan with its indicators and correlations.

    Missing scans return None. This does not analyze the URL or email again.
    """
    connection = get_db_connection()
    try:
        scan = connection.execute(
            """
            SELECT
                id,
                scan_type,
                target,
                normalized_url,
                risk_score,
                classification,
                recommendation,
                created_at,
                email_from,
                email_to,
                email_subject,
                email_date,
                base_score,
                raw_score,
                analysis_coverage,
                destination_status
            FROM scans
            WHERE id = ?
            """,
            (scan_id,),
        ).fetchone()
        if scan is None:
            return None

        indicators = connection.execute(
            """
            SELECT
                id,
                scan_id,
                rule_name,
                title,
                score_change,
                severity,
                explanation,
                evidence
            FROM indicators
            WHERE scan_id = ?
            ORDER BY id
            """,
            (scan_id,),
        ).fetchall()
        correlations = connection.execute(
            """
            SELECT
                id,
                scan_id,
                rule_name,
                title,
                score_change,
                explanation
            FROM correlations
            WHERE scan_id = ?
            ORDER BY id
            """,
            (scan_id,),
        ).fetchall()

        result = {
            "scan": dict(scan),
            "indicators": [dict(row) for row in indicators],
            "correlations": [dict(row) for row in correlations],
            "email_links": [],
            "email_attachments": [],
        }

        if scan["scan_type"] == "email":
            links = connection.execute(
                """
                SELECT
                    id,
                    scan_id,
                    url_text,
                    risk_score,
                    classification,
                    indicator_summary
                FROM email_links
                WHERE scan_id = ?
                ORDER BY id
                """,
                (scan_id,),
            ).fetchall()
            attachments = connection.execute(
                """
                SELECT
                    id,
                    scan_id,
                    filename,
                    content_type,
                    size
                FROM email_attachments
                WHERE scan_id = ?
                ORDER BY id
                """,
                (scan_id,),
            ).fetchall()
            result["email_links"] = [dict(row) for row in links]
            result["email_attachments"] = [dict(row) for row in attachments]

        result["redirect_inspection"] = _load_latest_redirect_inspection(
            connection,
            scan_id,
        )
        result["page_inspection"] = _load_latest_page_inspection(
            connection,
            scan_id,
        )
        result["reputation_checks"] = _load_reputation_checks(connection, scan_id)
        result["combined_assessment"] = _load_combined_assessment(connection, scan_id)
        return result
    finally:
        connection.close()


def _load_combined_assessment(connection, scan_id):
    """Return the stored combined assessment for a scan, or None."""
    row = connection.execute(
        """
        SELECT
            id,
            scan_id,
            assessment,
            label,
            coverage,
            summary,
            recommendation,
            score,
            breakdown_json,
            created_at,
            updated_at
        FROM combined_assessments
        WHERE scan_id = ?
        """,
        (scan_id,),
    ).fetchone()
    if row is None:
        return None

    item = dict(row)
    reasons = connection.execute(
        """
        SELECT reason_text
        FROM combined_assessment_reasons
        WHERE assessment_id = ?
        ORDER BY position ASC, id ASC
        """,
        (item["id"],),
    ).fetchall()
    item["reasons"] = [reason["reason_text"] for reason in reasons]
    coverage = (item.get("coverage") or "").strip().lower()
    item["coverage"] = coverage or "limited"
    item["coverage_label"] = coverage.upper() if coverage else "LIMITED"
    item["confidence"] = item["coverage"]
    item["classification"] = item.get("label")
    breakdown_raw = item.pop("breakdown_json", None)
    if breakdown_raw:
        try:
            item["breakdown"] = json.loads(breakdown_raw)
        except (TypeError, ValueError, json.JSONDecodeError):
            item["breakdown"] = None
    else:
        item["breakdown"] = None
    item["disclaimer"] = (
        "This assessment is based on the evidence available to PhishLens and is "
        "not a guarantee that a website is safe or malicious."
    )
    item["safety_note"] = (
        "No detected warning signals guarantee that a website is safe."
    )
    return item


def save_combined_assessment(scan_id, result):
    """Insert or update the combined assessment for a URL scan."""
    now = datetime.now(timezone.utc).isoformat()
    breakdown = result.get("breakdown")
    breakdown_json = None
    if breakdown is not None:
        breakdown_json = json.dumps(breakdown)
    coverage_value = result.get("coverage") or result.get("coverage_label") or "limited"
    if isinstance(coverage_value, str):
        coverage_value = coverage_value.strip().lower() or "limited"
    connection = get_db_connection()
    try:
        with connection:
            existing = connection.execute(
                "SELECT id, created_at FROM combined_assessments WHERE scan_id = ?",
                (scan_id,),
            ).fetchone()
            if existing:
                assessment_id = existing["id"]
                connection.execute(
                    """
                    UPDATE combined_assessments
                    SET assessment = ?,
                        label = ?,
                        coverage = ?,
                        summary = ?,
                        recommendation = ?,
                        score = ?,
                        breakdown_json = ?,
                        updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        result.get("assessment"),
                        result.get("label"),
                        coverage_value,
                        result.get("summary"),
                        result.get("recommendation"),
                        result.get("score"),
                        breakdown_json,
                        now,
                        assessment_id,
                    ),
                )
                connection.execute(
                    "DELETE FROM combined_assessment_reasons WHERE assessment_id = ?",
                    (assessment_id,),
                )
            else:
                result = connection.execute(
                    """
                    INSERT INTO combined_assessments (
                        scan_id,
                        assessment,
                        label,
                        coverage,
                        summary,
                        recommendation,
                        score,
                        breakdown_json,
                        created_at,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        result.get("assessment"),
                        result.get("label"),
                        coverage_value,
                        result.get("summary"),
                        result.get("recommendation"),
                        result.get("score"),
                        breakdown_json,
                        now,
                        now,
                    ),
                )
                assessment_id = result.lastrowid

            for position, reason in enumerate(result.get("reasons") or []):
                connection.execute(
                    """
                    INSERT INTO combined_assessment_reasons (
                        assessment_id,
                        position,
                        reason_text
                    )
                    VALUES (?, ?, ?)
                    """,
                    (assessment_id, position, reason),
                )
            return assessment_id
    finally:
        connection.close()


def _load_reputation_checks(connection, scan_id):
    """Return the newest reputation check for each target type on a scan."""
    rows = connection.execute(
        """
        SELECT
            id,
            scan_id,
            target_type,
            target_url,
            provider,
            status,
            message,
            malicious_count,
            suspicious_count,
            harmless_count,
            undetected_count,
            total_engines,
            checked_at,
            created_at
        FROM reputation_checks
        WHERE scan_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (scan_id,),
    ).fetchall()
    latest = {}
    for row in rows:
        item = dict(row)
        # Alias count columns for templates/report helpers.
        item["malicious"] = item.get("malicious_count")
        item["suspicious"] = item.get("suspicious_count")
        item["harmless"] = item.get("harmless_count")
        item["undetected"] = item.get("undetected_count")
        target_type = item.get("target_type")
        if target_type and target_type not in latest:
            latest[target_type] = item
    return latest


def save_reputation_check(scan_id, result):
    """Store one reputation lookup result for a URL scan."""
    created_at = datetime.now(timezone.utc).isoformat()
    connection = get_db_connection()
    try:
        with connection:
            result = connection.execute(
                """
                INSERT INTO reputation_checks (
                    scan_id,
                    target_type,
                    target_url,
                    provider,
                    status,
                    message,
                    malicious_count,
                    suspicious_count,
                    harmless_count,
                    undetected_count,
                    total_engines,
                    checked_at,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    result.get("target_type"),
                    result.get("target_url"),
                    result.get("provider"),
                    result.get("status"),
                    result.get("message"),
                    result.get("malicious"),
                    result.get("suspicious"),
                    result.get("harmless"),
                    result.get("undetected"),
                    result.get("total_engines"),
                    result.get("checked_at"),
                    created_at,
                ),
            )
            return result.lastrowid
    finally:
        connection.close()


def _load_latest_page_inspection(connection, scan_id):
    """Return the newest page inspection for a scan, if any."""
    inspection = connection.execute(
        """
        SELECT
            id,
            scan_id,
            status,
            reason,
            page_url,
            page_title,
            risk_score,
            classification,
            limited_static_content,
            truncated,
            created_at
        FROM page_inspections
        WHERE scan_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (scan_id,),
    ).fetchone()
    if inspection is None:
        return None

    payload = dict(inspection)
    payload["limited_static_content"] = bool(payload.get("limited_static_content"))
    payload["truncated"] = bool(payload.get("truncated"))
    indicators = connection.execute(
        """
        SELECT
            rule_name,
            title,
            severity,
            score_change,
            explanation,
            evidence
        FROM page_indicators
        WHERE inspection_id = ?
        ORDER BY id ASC
        """,
        (payload["id"],),
    ).fetchall()
    correlations = connection.execute(
        """
        SELECT
            rule_name,
            title,
            score_change,
            explanation
        FROM page_correlations
        WHERE inspection_id = ?
        ORDER BY id ASC
        """,
        (payload["id"],),
    ).fetchall()
    payload["indicators"] = [dict(row) for row in indicators]
    payload["correlations"] = [dict(row) for row in correlations]
    return payload


def _load_latest_redirect_inspection(connection, scan_id):
    """Return the newest destination inspection for a scan, if any."""
    inspection = connection.execute(
        """
        SELECT
            id,
            scan_id,
            status,
            reason,
            submitted_url,
            final_url,
            redirect_count,
            final_risk_score,
            final_classification,
            final_recommendation,
            created_at
        FROM redirect_inspections
        WHERE scan_id = ?
        ORDER BY created_at DESC, id DESC
        LIMIT 1
        """,
        (scan_id,),
    ).fetchone()
    if inspection is None:
        return None

    payload = dict(inspection)
    hops = connection.execute(
        """
        SELECT hop_number, url_text, http_status
        FROM redirect_hops
        WHERE inspection_id = ?
        ORDER BY hop_number ASC, id ASC
        """,
        (payload["id"],),
    ).fetchall()
    indicators = connection.execute(
        """
        SELECT
            rule_name,
            title,
            score_change,
            severity,
            explanation,
            evidence
        FROM final_url_indicators
        WHERE inspection_id = ?
        ORDER BY id ASC
        """,
        (payload["id"],),
    ).fetchall()
    correlations = connection.execute(
        """
        SELECT
            rule_name,
            title,
            score_change,
            explanation
        FROM final_url_correlations
        WHERE inspection_id = ?
        ORDER BY id ASC
        """,
        (payload["id"],),
    ).fetchall()
    payload["hops"] = [dict(row) for row in hops]
    payload["final_indicators"] = [dict(row) for row in indicators]
    payload["final_correlations"] = [dict(row) for row in correlations]
    return payload


def update_scan_coverage(scan_id, analysis_coverage, destination_status):
    """Update coverage metadata on an existing URL scan."""
    connection = get_db_connection()
    try:
        with connection:
            connection.execute(
                """
                UPDATE scans
                SET analysis_coverage = ?, destination_status = ?
                WHERE id = ?
                """,
                (analysis_coverage, destination_status, scan_id),
            )
    finally:
        connection.close()


def save_redirect_inspection(
    scan_id,
    resolution,
    final_risk=None,
    final_indicators=None,
    final_correlations=None,
):
    """Store one destination-inspection attempt for a URL scan."""
    created_at = datetime.now(timezone.utc).isoformat()
    final_risk = final_risk or {}
    connection = get_db_connection()
    try:
        with connection:
            result = connection.execute(
                """
                INSERT INTO redirect_inspections (
                    scan_id,
                    status,
                    reason,
                    submitted_url,
                    final_url,
                    redirect_count,
                    final_risk_score,
                    final_classification,
                    final_recommendation,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    resolution.get("status"),
                    resolution.get("reason"),
                    resolution.get("submitted_url"),
                    resolution.get("final_url"),
                    resolution.get("redirect_count"),
                    final_risk.get("final_score"),
                    final_risk.get("classification"),
                    final_risk.get("recommendation"),
                    created_at,
                ),
            )
            inspection_id = result.lastrowid

            for index, hop in enumerate(resolution.get("redirect_chain") or [], start=1):
                connection.execute(
                    """
                    INSERT INTO redirect_hops (
                        inspection_id,
                        hop_number,
                        url_text,
                        http_status
                    )
                    VALUES (?, ?, ?, ?)
                    """,
                    (
                        inspection_id,
                        index,
                        hop.get("url"),
                        hop.get("http_status"),
                    ),
                )

            for indicator in final_indicators or []:
                connection.execute(
                    """
                    INSERT INTO final_url_indicators (
                        inspection_id,
                        rule_name,
                        title,
                        score_change,
                        severity,
                        explanation,
                        evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inspection_id,
                        indicator.get("rule") or indicator.get("rule_name"),
                        indicator.get("title"),
                        indicator.get("score_change", 0),
                        indicator.get("severity"),
                        indicator.get("explanation"),
                        indicator.get("evidence"),
                    ),
                )

            for correlation in final_correlations or []:
                connection.execute(
                    """
                    INSERT INTO final_url_correlations (
                        inspection_id,
                        rule_name,
                        title,
                        score_change,
                        explanation
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        inspection_id,
                        correlation.get("rule") or correlation.get("rule_name"),
                        correlation.get("title"),
                        correlation.get("score_change", 0),
                        correlation.get("explanation"),
                    ),
                )

        return inspection_id
    finally:
        connection.close()


def save_page_inspection(scan_id, fetch_result, analysis=None, page_risk=None):
    """Store one static page-inspection attempt for a URL scan."""
    created_at = datetime.now(timezone.utc).isoformat()
    analysis = analysis or {}
    page_risk = page_risk or {}
    connection = get_db_connection()
    try:
        with connection:
            result = connection.execute(
                """
                INSERT INTO page_inspections (
                    scan_id,
                    status,
                    reason,
                    page_url,
                    page_title,
                    risk_score,
                    classification,
                    limited_static_content,
                    truncated,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    fetch_result.get("status"),
                    fetch_result.get("reason"),
                    fetch_result.get("page_url") or analysis.get("page_url"),
                    analysis.get("page_title"),
                    page_risk.get("final_score"),
                    page_risk.get("classification"),
                    1 if analysis.get("limited_static_content") else 0,
                    1 if fetch_result.get("truncated") else 0,
                    created_at,
                ),
            )
            inspection_id = result.lastrowid

            for indicator in page_risk.get("indicators") or analysis.get("indicators") or []:
                connection.execute(
                    """
                    INSERT INTO page_indicators (
                        inspection_id,
                        rule_name,
                        title,
                        severity,
                        score_change,
                        explanation,
                        evidence
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        inspection_id,
                        indicator.get("rule") or indicator.get("rule_name"),
                        indicator.get("title"),
                        indicator.get("severity"),
                        indicator.get("score_change", 0),
                        indicator.get("explanation"),
                        indicator.get("evidence"),
                    ),
                )

            for correlation in page_risk.get("correlations") or []:
                connection.execute(
                    """
                    INSERT INTO page_correlations (
                        inspection_id,
                        rule_name,
                        title,
                        score_change,
                        explanation
                    )
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (
                        inspection_id,
                        correlation.get("rule") or correlation.get("rule_name"),
                        correlation.get("title"),
                        correlation.get("score_change", 0),
                        correlation.get("explanation"),
                    ),
                )
        return inspection_id
    finally:
        connection.close()


def get_dashboard_summary():
    """Return overview counts and average risk from stored scans.

    Final assessment distribution uses the stored combined assessment label
    for URL scans when present; otherwise falls back to the scan classification.
    Email scans always use their stored email classification.
    """
    connection = get_db_connection()
    try:
        row = connection.execute(
            """
            SELECT
                COUNT(*) AS total,
                COALESCE(SUM(CASE WHEN scan_type = 'url' THEN 1 ELSE 0 END), 0) AS url_scans,
                COALESCE(SUM(CASE WHEN scan_type = 'email' THEN 1 ELSE 0 END), 0) AS email_scans,
                COALESCE(
                    SUM(CASE WHEN effective_label = 'Low Risk' THEN 1 ELSE 0 END),
                    0
                ) AS low_risk,
                COALESCE(
                    SUM(CASE WHEN effective_label = 'Suspicious' THEN 1 ELSE 0 END),
                    0
                ) AS suspicious,
                COALESCE(
                    SUM(CASE WHEN effective_label = 'High Risk' THEN 1 ELSE 0 END),
                    0
                ) AS high_risk,
                -- Average prefers stored combined score when present; otherwise
                -- falls back to the submitted-layer risk_score (email scans and
                -- legacy URL rows without a combined score).
                AVG(risk_score) AS average_risk
            FROM (
                SELECT
                    s.scan_type AS scan_type,
                    CASE
                        WHEN s.scan_type = 'url' AND ca.score IS NOT NULL THEN ca.score
                        ELSE s.risk_score
                    END AS risk_score,
                    CASE
                        WHEN s.scan_type = 'url' AND ca.label IS NOT NULL THEN ca.label
                        ELSE s.classification
                    END AS effective_label
                FROM scans AS s
                LEFT JOIN combined_assessments AS ca ON ca.scan_id = s.id
            )
            """
        ).fetchone()
        total = row["total"]
        average = None
        if total and row["average_risk"] is not None:
            average = int(round(row["average_risk"]))
        return {
            "total": total,
            "url_scans": row["url_scans"],
            "email_scans": row["email_scans"],
            "low_risk": row["low_risk"],
            "suspicious": row["suspicious"],
            "high_risk": row["high_risk"],
            "average_risk": average,
        }
    finally:
        connection.close()


def get_recent_activity(days=7):
    """Return daily scan counts for the latest UTC days, including zeros."""
    try:
        day_count = int(days)
    except (TypeError, ValueError):
        day_count = 7
    if day_count < 1:
        day_count = 7

    end = datetime.now(timezone.utc).date()
    start = end - timedelta(days=day_count - 1)
    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS total
            FROM scans
            WHERE substr(created_at, 1, 10) >= ?
              AND substr(created_at, 1, 10) <= ?
            GROUP BY substr(created_at, 1, 10)
            """,
            (start.isoformat(), end.isoformat()),
        ).fetchall()
        counts = {row["day"]: row["total"] for row in rows}
    finally:
        connection.close()

    activity = []
    current = start
    while current <= end:
        key = current.isoformat()
        activity.append(
            {
                "day": key,
                "label": format_month_day(current.month, current.day),
                "total": counts.get(key, 0),
            }
        )
        current += timedelta(days=1)
    return activity


def get_top_indicators(limit=5):
    """Return the most common indicators by distinct scan count."""
    try:
        limit_value = int(limit)
    except (TypeError, ValueError):
        limit_value = 5
    if limit_value < 1:
        limit_value = 5

    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                i.rule_name AS rule_name,
                MAX(i.title) AS title,
                COUNT(DISTINCT i.scan_id) AS scan_count,
                CASE
                    WHEN COUNT(DISTINCT CASE WHEN s.scan_type = 'url' THEN s.id END) > 0
                     AND COUNT(DISTINCT CASE WHEN s.scan_type = 'email' THEN s.id END) = 0
                    THEN 'URL'
                    WHEN COUNT(DISTINCT CASE WHEN s.scan_type = 'email' THEN s.id END) > 0
                     AND COUNT(DISTINCT CASE WHEN s.scan_type = 'url' THEN s.id END) = 0
                    THEN 'Email'
                    ELSE 'Mixed'
                END AS source_type
            FROM indicators AS i
            INNER JOIN scans AS s ON s.id = i.scan_id
            GROUP BY i.rule_name
            ORDER BY scan_count DESC, title ASC
            LIMIT ?
            """,
            (limit_value,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()


def get_recent_scans(limit=5):
    """Return the newest scans for the dashboard recent list."""
    try:
        limit_value = int(limit)
    except (TypeError, ValueError):
        limit_value = 5
    if limit_value < 1:
        limit_value = 5

    connection = get_db_connection()
    try:
        rows = connection.execute(
            """
            SELECT
                id,
                scan_type,
                target,
                normalized_url,
                risk_score,
                classification,
                created_at,
                email_from,
                email_subject
            FROM scans
            ORDER BY created_at DESC, id DESC
            LIMIT ?
            """,
            (limit_value,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        connection.close()
