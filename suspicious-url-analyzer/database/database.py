"""Store completed URL analyses in a local SQLite database.

Python creates database/scans.db the first time a connection is opened.
Starting the app again does not delete existing scans.
"""

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent / "scans.db"


def get_db_connection():
    """Open SQLite with foreign keys enabled."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    """Create scan tables if they do not exist yet."""
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
            """
        )
    finally:
        connection.close()


def save_scan(parsed, risk, scan_type="url"):
    """Save one completed analysis and return its scan id.

    The scan, its indicators, and its correlations are written in one
    transaction. If any insert fails, none of that scan is kept.
    """
    created_at = datetime.now(timezone.utc).isoformat()
    connection = get_db_connection()
    try:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO scans (
                    scan_type,
                    target,
                    normalized_url,
                    risk_score,
                    classification,
                    recommendation,
                    created_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_type,
                    parsed.get("hostname") or "",
                    parsed.get("normalized_url"),
                    risk["final_score"],
                    risk["classification"],
                    risk.get("recommendation"),
                    created_at,
                ),
            )
            scan_id = cursor.lastrowid

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
