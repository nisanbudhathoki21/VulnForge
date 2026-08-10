#!/usr/bin/env python3
"""
Database layer for VulnForge.

Uses SQLite for local persistence.

Important:
- The database is stored relative to the VulnForge project root.
- Retrieval functions return normal dictionaries, not sqlite3.Row,
  so dashboard.py can safely use .get().
- Each operation opens and closes its own SQLite connection.
"""

import sqlite3
from pathlib import Path
from datetime import datetime


# ============================================================
# Project root & database path
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "vulnforge.db"


# ============================================================
# Database initialization
# ============================================================

def init_db():
    """
    Create the VulnForge database tables if they do not exist.
    """

    conn = sqlite3.connect(str(DB_PATH))

    try:
        cur = conn.cursor()

        # ----------------------------------------------------
        # Scans table
        # ----------------------------------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                start_time TEXT,
                end_time TEXT,
                fingerprint TEXT,
                findings_count INTEGER DEFAULT 0,
                scan_duration REAL,
                status TEXT DEFAULT 'completed',
                scan_depth INTEGER DEFAULT 1,
                templates_loaded INTEGER DEFAULT 0,
                requests_sent INTEGER DEFAULT 0,
                errors_count INTEGER DEFAULT 0
            )
        """)

        # ----------------------------------------------------
        # Findings table
        # ----------------------------------------------------
        cur.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL,
                template_id TEXT,
                name TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                impact TEXT,
                chain TEXT,
                evidence TEXT,
                extracted TEXT,
                confirmed BOOLEAN DEFAULT 0,
                exploit_attempted BOOLEAN DEFAULT 0,
                exploit_success BOOLEAN DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                cwe TEXT,
                owasp TEXT,
                remediation TEXT,
                created_at TEXT,
                ai_explanation TEXT,
                FOREIGN KEY (scan_id)
                    REFERENCES scans(scan_id)
                    ON DELETE CASCADE
            )
        """)

        conn.commit()

    finally:
        conn.close()


# ============================================================
# Internal connection helper
# ============================================================

def _connect():
    """
    Create a SQLite connection.

    Foreign keys are enabled for this connection.
    """

    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ============================================================
# Data retrieval functions
# ============================================================

def get_scans(limit=50):
    """
    Return the most recent scans.

    IMPORTANT:
    sqlite3.Row objects are converted to dictionaries so that
    dashboard.py can safely use:

        scan.get("scan_id")
        scan.get("target")
        scan.get("status")
    """

    conn = _connect()

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute(
            """
            SELECT *
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (limit,)
        )

        rows = cur.fetchall()

        # Convert sqlite3.Row -> normal dict
        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_scan(scan_id):
    """
    Return a single scan as a normal dictionary.

    Returns:
        dict if found
        None if not found
    """

    conn = _connect()

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute(
            """
            SELECT *
            FROM scans
            WHERE scan_id = ?
            """,
            (scan_id,)
        )

        row = cur.fetchone()

        if row is None:
            return None

        return dict(row)

    finally:
        conn.close()


def get_findings(limit=100):
    """
    Return the most recent findings as dictionaries.
    """

    conn = _connect()

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                id,
                scan_id,
                name,
                severity,
                evidence,
                created_at
            FROM findings
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,)
        )

        rows = cur.fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_targets():
    """
    Return unique targets with the number of scans
    performed against each target.
    """

    conn = _connect()

    try:
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                target,
                COUNT(*) AS scan_count
            FROM scans
            GROUP BY target
            ORDER BY scan_count DESC
            """
        )

        rows = cur.fetchall()

        return [dict(row) for row in rows]

    finally:
        conn.close()


def get_statistics():
    """
    Return summary statistics for the dashboard.

    Returns:
        dict containing:
            total_scans
            total_findings
            unique_targets
            last_scan_time
            avg_findings_per_scan
            severity_counts
    """

    conn = _connect()

    try:
        cur = conn.cursor()

        # ----------------------------------------------------
        # Total scans
        # ----------------------------------------------------
        cur.execute("SELECT COUNT(*) FROM scans")
        total_scans = cur.fetchone()[0]

        # ----------------------------------------------------
        # Total findings
        # ----------------------------------------------------
        cur.execute("SELECT COUNT(*) FROM findings")
        total_findings = cur.fetchone()[0]

        # ----------------------------------------------------
        # Unique targets
        # ----------------------------------------------------
        cur.execute(
            "SELECT COUNT(DISTINCT target) FROM scans"
        )
        unique_targets = cur.fetchone()[0]

        # ----------------------------------------------------
        # Last scan timestamp
        # ----------------------------------------------------
        cur.execute(
            """
            SELECT timestamp
            FROM scans
            ORDER BY timestamp DESC
            LIMIT 1
            """
        )

        row = cur.fetchone()
        last_scan_time = row[0] if row else None

        # ----------------------------------------------------
        # Average findings per scan
        # ----------------------------------------------------
        if total_scans:
            avg_findings_per_scan = total_findings / total_scans
        else:
            avg_findings_per_scan = 0.0

        # ----------------------------------------------------
        # Findings by severity
        # ----------------------------------------------------
        cur.execute(
            """
            SELECT
                severity,
                COUNT(*) AS count
            FROM findings
            GROUP BY severity
            """
        )

        severity_rows = cur.fetchall()

        severity_counts = {
            row[0] or "info": row[1]
            for row in severity_rows
        }

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "unique_targets": unique_targets,
            "last_scan_time": last_scan_time,
            "avg_findings_per_scan": avg_findings_per_scan,
            "severity_counts": severity_counts,
        }

    finally:
        conn.close()


# ============================================================
# Save scan
# ============================================================

def save_scan(
    scan_id,
    target,
    timestamp,
    start_time=None,
    status="completed",
    **kwargs
):
    """
    Insert or replace a scan record.

    Additional scan fields can be supplied through kwargs.
    """

    conn = _connect()

    try:
        cur = conn.cursor()

        cur.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id,
                target,
                timestamp,
                start_time,
                end_time,
                fingerprint,
                findings_count,
                scan_duration,
                status,
                scan_depth,
                templates_loaded,
                requests_sent,
                errors_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                target,
                timestamp,
                start_time,
                kwargs.get("end_time"),
                kwargs.get("fingerprint"),
                kwargs.get("findings_count", 0),
                kwargs.get("scan_duration"),
                status,
                kwargs.get("scan_depth", 1),
                kwargs.get("templates_loaded", 0),
                kwargs.get("requests_sent", 0),
                kwargs.get("errors_count", 0),
            )
        )

        conn.commit()

    finally:
        conn.close()


# ============================================================
# Update scan status
# ============================================================

def update_scan_status(
    scan_id,
    status,
    end_time=None
):
    """
    Update the status of a scan.

    If end_time is supplied, it is updated as well.
    """

    conn = _connect()

    try:
        cur = conn.cursor()

        if end_time:
            cur.execute(
                """
                UPDATE scans
                SET
                    status = ?,
                    end_time = ?
                WHERE scan_id = ?
                """,
                (
                    status,
                    end_time,
                    scan_id,
                )
            )
        else:
            cur.execute(
                """
                UPDATE scans
                SET status = ?
                WHERE scan_id = ?
                """,
                (
                    status,
                    scan_id,
                )
            )

        conn.commit()

    finally:
        conn.close()


# ============================================================
# Save finding
# ============================================================

def save_finding(
    scan_id,
    name,
    severity="info",
    created_at=None,
    **kwargs
):
    """
    Insert a new vulnerability finding.

    Additional finding metadata can be supplied through kwargs.
    """

    if created_at is None:
        created_at = datetime.utcnow().isoformat()

    conn = _connect()

    try:
        cur = conn.cursor()

        cur.execute(
            """
            INSERT INTO findings (
                scan_id,
                template_id,
                name,
                severity,
                impact,
                chain,
                evidence,
                extracted,
                confirmed,
                exploit_attempted,
                exploit_success,
                confidence,
                cwe,
                owasp,
                remediation,
                created_at,
                ai_explanation
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                kwargs.get("template_id"),
                name,
                severity,
                kwargs.get("impact"),
                kwargs.get("chain"),
                kwargs.get("evidence"),
                kwargs.get("extracted"),
                kwargs.get("confirmed", 0),
                kwargs.get("exploit_attempted", 0),
                kwargs.get("exploit_success", 0),
                kwargs.get("confidence", 0.0),
                kwargs.get("cwe"),
                kwargs.get("owasp"),
                kwargs.get("remediation"),
                created_at,
                kwargs.get("ai_explanation"),
            )
        )

        conn.commit()

    finally:
        conn.close()


# ============================================================
# Count findings for a scan
# ============================================================

def count_findings_for_scan(scan_id):
    """
    Return the number of findings belonging to a scan.
    """

    conn = _connect()

    try:
        cur = conn.cursor()

        cur.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE scan_id = ?
            """,
            (scan_id,)
        )

        count = cur.fetchone()[0]

        return count

    finally:
        conn.close()


# ============================================================
# Optional helper: update findings count
# ============================================================

def update_findings_count(scan_id):
    """
    Synchronize scans.findings_count with the actual number
    of findings stored for the scan.
    """

    count = count_findings_for_scan(scan_id)

    conn = _connect()

    try:
        cur = conn.cursor()

        cur.execute(
            """
            UPDATE scans
            SET findings_count = ?
            WHERE scan_id = ?
            """,
            (
                count,
                scan_id,
            )
        )

        conn.commit()

    finally:
        conn.close()

    return count


# ============================================================
# Automatic database initialization
# ============================================================

# Ensure the database and tables exist when this module
# is imported.
init_db()
