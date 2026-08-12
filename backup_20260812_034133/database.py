#!/usr/bin/env python3

"""
VulnForge SQLite Database Layer

This file is intentionally compatible with the existing VulnForge
database schema.

Existing schema:

scans
    scan_id TEXT PRIMARY KEY
    target
    timestamp
    start_time
    end_time
    fingerprint
    findings_count
    scan_duration
    status
    scan_depth
    templates_loaded
    requests_sent
    errors_count
    confirmed_count

findings
    id INTEGER PRIMARY KEY
    scan_id
    template_id
    name
    severity
    impact
    chain
    evidence
    extracted
    confirmed
    exploit_attempted
    exploit_success
    confidence
    cwe
    owasp
    remediation
    created_at
    ai_explanation
    description
    category
    endpoint
    method
    http_status
    details

The database is migrated safely when older columns are missing.

IMPORTANT:
    Do NOT assume scans.id exists.
    scans.scan_id is the primary key.
"""

# ============================================================
# IMPORTS
# ============================================================

import json
import logging
import os
import sqlite3
from datetime import datetime
from pathlib import Path


# ============================================================
# PROJECT PATH
# ============================================================

PROJECT_ROOT = (
    Path(__file__)
    .resolve()
    .parents[1]
)

DEFAULT_DB_PATH = (
    PROJECT_ROOT / "vulnforge.db"
)

DB_PATH = os.environ.get(
    "VULNFORGE_DB_PATH",
    str(DEFAULT_DB_PATH),
)


# ============================================================
# OLLAMA CONFIGURATION
# ============================================================

OLLAMA_URL = os.environ.get(
    "VULNFORGE_OLLAMA_URL",
    "http://localhost:11434",
).rstrip("/")

OLLAMA_MODEL = os.environ.get(
    "VULNFORGE_OLLAMA_MODEL",
    "tinyllama:latest",
)

try:
    OLLAMA_TIMEOUT = float(
        os.environ.get(
            "VULNFORGE_OLLAMA_TIMEOUT",
            "20",
        )
    )
except ValueError:
    OLLAMA_TIMEOUT = 20.0


AI_EXPLANATIONS_ENABLED = (
    os.environ.get(
        "VULNFORGE_AI_EXPLANATIONS",
        "0",
    )
    .strip()
    .lower()
    not in {
        "0",
        "false",
        "no",
        "off",
    }
)


# ============================================================
# LOGGER
# ============================================================

logger = logging.getLogger(
    __name__
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    """
    Create a fresh SQLite connection.

    A fresh connection per operation is important because
    VulnForge can use multiple scanner workers.
    """

    database_path = Path(
        DB_PATH
    )

    database_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    connection = sqlite3.connect(
        str(database_path),
        timeout=30,
    )

    connection.row_factory = sqlite3.Row

    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    connection.execute(
        "PRAGMA busy_timeout = 30000"
    )

    connection.execute(
        "PRAGMA journal_mode = WAL"
    )

    return connection


# ============================================================
# HELPERS
# ============================================================

def get_db_path():
    """
    Return the absolute path of the active database.
    """

    return str(
        Path(DB_PATH).resolve()
    )


def _now():
    """
    Current local timestamp.
    """

    return datetime.now().isoformat(
        timespec="seconds"
    )


def _json(value):
    """
    Convert Python data into JSON safely.
    """

    if value is None:
        return "{}"

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )
    except Exception:
        return json.dumps(
            str(value),
            ensure_ascii=False,
        )


def _from_json(value):
    """
    Convert JSON stored in SQLite back to Python data.
    """

    if value is None:
        return {}

    if isinstance(
        value,
        (dict, list),
    ):
        return value

    try:
        return json.loads(
            value
        )
    except Exception:
        return {}


def _bool(value):
    """
    Normalize booleans for SQLite.
    """

    if isinstance(
        value,
        bool,
    ):
        return int(value)

    if value is None:
        return 0

    if isinstance(
        value,
        str,
    ):
        return int(
            value.strip().lower()
            in {
                "1",
                "true",
                "yes",
                "on",
                "confirmed",
            }
        )

    try:
        return int(bool(value))
    except Exception:
        return 0


def _float(value):
    """
    Safely normalize confidence values.
    """

    try:

        value = float(
            value
        )

    except (
        TypeError,
        ValueError,
    ):

        value = 0.0

    return max(
        0.0,
        min(
            1.0,
            value,
        ),
    )


# ============================================================
# SCHEMA HELPERS
# ============================================================

def _table_exists(
    cursor,
    table_name,
):
    """
    Check whether a table exists.
    """

    row = cursor.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
        AND name = ?
        """,
        (
            table_name,
        ),
    ).fetchone()

    return row is not None


def _columns(
    cursor,
    table_name,
):
    """
    Return column names for a table.
    """

    if not _table_exists(
        cursor,
        table_name,
    ):
        return set()

    rows = cursor.execute(
        f"PRAGMA table_info({table_name})"
    ).fetchall()

    return {
        row["name"]
        for row in rows
    }


def _ensure_column(
    cursor,
    table_name,
    column_name,
    definition,
):
    """
    Add a column only when it does not already exist.
    """

    existing = _columns(
        cursor,
        table_name,
    )

    if column_name not in existing:

        cursor.execute(
            f"""
            ALTER TABLE {table_name}
            ADD COLUMN {column_name} {definition}
            """
        )

        logger.info(
            "Added missing column %s.%s",
            table_name,
            column_name,
        )


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def init_db():
    """
    Create or migrate the VulnForge database.

    Existing data is preserved.

    This function is safe to call repeatedly.
    """

    connection = get_connection()

    try:

        cursor = connection.cursor()

        # ====================================================
        # SCANS TABLE
        # ====================================================

        cursor.execute(
            """
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
                errors_count INTEGER DEFAULT 0,
                confirmed_count INTEGER NOT NULL DEFAULT 0
            )
            """
        )

        # ====================================================
        # FINDINGS TABLE
        # ====================================================

        cursor.execute(
            """
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
                description TEXT,
                category TEXT,
                endpoint TEXT,
                method TEXT,
                http_status TEXT,
                details TEXT
            )
            """
        )

        # ====================================================
        # MIGRATE SCANS
        # ====================================================

        _ensure_column(
            cursor,
            "scans",
            "timestamp",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "scans",
            "start_time",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "scans",
            "end_time",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "scans",
            "fingerprint",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "scans",
            "findings_count",
            "INTEGER DEFAULT 0",
        )

        _ensure_column(
            cursor,
            "scans",
            "scan_duration",
            "REAL",
        )

        _ensure_column(
            cursor,
            "scans",
            "status",
            "TEXT DEFAULT 'completed'",
        )

        _ensure_column(
            cursor,
            "scans",
            "scan_depth",
            "INTEGER DEFAULT 1",
        )

        _ensure_column(
            cursor,
            "scans",
            "templates_loaded",
            "INTEGER DEFAULT 0",
        )

        _ensure_column(
            cursor,
            "scans",
            "requests_sent",
            "INTEGER DEFAULT 0",
        )

        _ensure_column(
            cursor,
            "scans",
            "errors_count",
            "INTEGER DEFAULT 0",
        )

        _ensure_column(
            cursor,
            "scans",
            "confirmed_count",
            "INTEGER NOT NULL DEFAULT 0",
        )

        # ====================================================
        # MIGRATE FINDINGS
        # ====================================================

        _ensure_column(
            cursor,
            "findings",
            "template_id",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "impact",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "chain",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "evidence",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "extracted",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "confirmed",
            "BOOLEAN DEFAULT 0",
        )

        _ensure_column(
            cursor,
            "findings",
            "exploit_attempted",
            "BOOLEAN DEFAULT 0",
        )

        _ensure_column(
            cursor,
            "findings",
            "exploit_success",
            "BOOLEAN DEFAULT 0",
        )

        _ensure_column(
            cursor,
            "findings",
            "confidence",
            "REAL DEFAULT 0.0",
        )

        _ensure_column(
            cursor,
            "findings",
            "cwe",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "owasp",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "remediation",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "created_at",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "ai_explanation",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "description",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "category",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "endpoint",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "method",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "http_status",
            "TEXT",
        )

        _ensure_column(
            cursor,
            "findings",
            "details",
            "TEXT",
        )

        # ====================================================
        # REPAIR LEGACY NULL VALUES
        # ====================================================

        cursor.execute(
            """
            UPDATE scans
            SET
                findings_count = 0
            WHERE findings_count IS NULL
            """
        )

        cursor.execute(
            """
            UPDATE scans
            SET
                confirmed_count = 0
            WHERE confirmed_count IS NULL
            """
        )

        cursor.execute(
            """
            UPDATE scans
            SET
                status = 'completed'
            WHERE status IS NULL
            OR status = ''
            """
        )

        cursor.execute(
            """
            UPDATE findings
            SET
                confirmed = 0
            WHERE confirmed IS NULL
            """
        )

        cursor.execute(
            """
            UPDATE findings
            SET
                confidence = 0.0
            WHERE confidence IS NULL
            """
        )

        # ====================================================
        # REPAIR TIMESTAMPS
        # ====================================================

        cursor.execute(
            """
            UPDATE scans
            SET timestamp = ?
            WHERE timestamp IS NULL
            OR timestamp = ''
            """,
            (
                _now(),
            ),
        )

        cursor.execute(
            """
            UPDATE findings
            SET created_at = ?
            WHERE created_at IS NULL
            OR created_at = ''
            """,
            (
                _now(),
            ),
        )

        # ====================================================
        # REBUILD SCAN COUNTERS
        # ====================================================
        #
        # IMPORTANT:
        #
        # We DO NOT use scans.id.
        #
        # scans.scan_id is the primary key.
        # ====================================================

        cursor.execute(
            """
            UPDATE scans
            SET findings_count = (
                SELECT COUNT(*)
                FROM findings
                WHERE findings.scan_id = scans.scan_id
            )
            """
        )

        cursor.execute(
            """
            UPDATE scans
            SET confirmed_count = (
                SELECT COUNT(*)
                FROM findings
                WHERE findings.scan_id = scans.scan_id
                AND findings.confirmed = 1
            )
            """
        )

        # ====================================================
        # INDEXES
        # ====================================================

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_scans_timestamp
            ON scans(timestamp)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_scans_scan_id
            ON scans(scan_id)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_findings_scan_id
            ON findings(scan_id)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_findings_severity
            ON findings(severity)
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS
            idx_findings_confirmed
            ON findings(confirmed)
            """
        )

        connection.commit()

        logger.info(
            "Database initialized: %s",
            DB_PATH,
        )

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# ============================================================
# FINDING NORMALIZATION
# ============================================================

def _normalize_finding(
    finding,
):
    """
    Convert scanner finding output into the project's database
    schema.
    """

    if not isinstance(
        finding,
        dict,
    ):
        finding = {
            "name": str(finding)
        }

    evidence = finding.get(
        "evidence",
        {},
    )

    if not isinstance(
        evidence,
        (dict, list, str),
    ):
        evidence = str(
            evidence
        )

    severity = str(
        finding.get(
            "severity",
            "info",
        )
    ).lower()

    confirmed = _bool(
        finding.get(
            "confirmed",
            False,
        )
    )

    confidence = _float(
        finding.get(
            "confidence",
            0.0,
        )
    )

    endpoint = (
        finding.get(
            "endpoint"
        )
        or finding.get(
            "url"
        )
        or (
            evidence.get("url", "")
            if isinstance(
                evidence,
                dict,
            )
            else ""
        )
    )

    method = (
        finding.get(
            "method"
        )
        or (
            evidence.get("method", "")
            if isinstance(
                evidence,
                dict,
            )
            else ""
        )
    )

    http_status = (
        finding.get(
            "status"
        )
        or finding.get(
            "http_status"
        )
        or (
            evidence.get("status", "")
            if isinstance(
                evidence,
                dict,
            )
            else ""
        )
    )

    description = (
        finding.get(
            "description"
        )
        or finding.get(
            "impact"
        )
        or ""
    )

    return {
        "template_id": finding.get(
            "template_id"
        ),

        "name": str(
            finding.get(
                "name",
                "Unnamed finding",
            )
        ),

        "severity": severity,

        "impact": str(
            finding.get(
                "impact",
                "",
            )
        ),

        "chain": finding.get(
            "chain"
        ),

        "evidence": evidence,

        "extracted": finding.get(
            "extracted"
        ),

        "confirmed": confirmed,

        "exploit_attempted": _bool(
            finding.get(
                "exploit_attempted",
                finding.get(
                    "exploit",
                    False,
                ),
            )
        ),

        "exploit_success": _bool(
            finding.get(
                "exploit_success",
                False,
            )
        ),

        "confidence": confidence,

        "cwe": finding.get(
            "cwe"
        ),

        "owasp": finding.get(
            "owasp"
        ),

        "remediation": finding.get(
            "remediation",
            finding.get(
                "solution",
                "",
            ),
        ),

        "ai_explanation": finding.get(
            "ai_explanation"
        ),

        "description": description,

        "category": finding.get(
            "category",
            finding.get(
                "type",
                "",
            ),
        ),

        "endpoint": endpoint or "",

        "method": method or "",

        "http_status": http_status or "",

        "details": finding,
    }


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    scan_id,
    target,
    fingerprint=None,
    findings=None,
    start_time=None,
    end_time=None,
    **kwargs,
):
    """
    Save a complete scan.

    Existing scan_id:
        Updated.

    Existing findings belonging to that scan:
        Replaced.

    This prevents duplicate findings when a result is persisted
    more than once.
    """

    init_db()

    if not scan_id:

        raise ValueError(
            "scan_id is required"
        )

    if not target:

        raise ValueError(
            "target is required"
        )

    if findings is None:

        findings = []

    normalized = [
        _normalize_finding(
            finding
        )
        for finding in findings
    ]

    findings_count = len(
        normalized
    )

    confirmed_count = sum(
        item["confirmed"]
        for item in normalized
    )

    start = (
        start_time
        or _now()
    )

    end = (
        end_time
        or _now()
    )

    # Duration.

    duration = kwargs.get(
        "scan_duration"
    )

    if duration is None:

        try:

            start_dt = datetime.fromisoformat(
                str(start)
            )

            end_dt = datetime.fromisoformat(
                str(end)
            )

            duration = (
                end_dt - start_dt
            ).total_seconds()

        except Exception:

            duration = 0.0

    connection = get_connection()

    try:

        cursor = connection.cursor()

        # ====================================================
        # INSERT OR UPDATE SCAN
        # ====================================================

        cursor.execute(
            """
            INSERT INTO scans (
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
                errors_count,
                confirmed_count
            )
            VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
            )
            ON CONFLICT(scan_id)
            DO UPDATE SET
                target = excluded.target,
                timestamp = excluded.timestamp,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                fingerprint = excluded.fingerprint,
                findings_count = excluded.findings_count,
                scan_duration = excluded.scan_duration,
                status = excluded.status,
                scan_depth = excluded.scan_depth,
                templates_loaded = excluded.templates_loaded,
                requests_sent = excluded.requests_sent,
                errors_count = excluded.errors_count,
                confirmed_count = excluded.confirmed_count
            """,
            (
                str(scan_id),
                str(target),
                str(end),
                str(start),
                str(end),
                _json(
                    fingerprint or {}
                ),
                findings_count,
                duration,
                kwargs.get(
                    "status",
                    "completed",
                ),
                kwargs.get(
                    "scan_depth",
                    1,
                ),
                kwargs.get(
                    "templates_loaded",
                    0,
                ),
                kwargs.get(
                    "requests_sent",
                    0,
                ),
                kwargs.get(
                    "errors_count",
                    0,
                ),
                confirmed_count,
            ),
        )

        # ====================================================
        # REMOVE OLD FINDINGS
        # ====================================================

        cursor.execute(
            """
            DELETE FROM findings
            WHERE scan_id = ?
            """,
            (
                str(scan_id),
            ),
        )

        # ====================================================
        # INSERT NEW FINDINGS
        # ====================================================

        for finding in normalized:

            cursor.execute(
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
                    ai_explanation,
                    description,
                    category,
                    endpoint,
                    method,
                    http_status,
                    details
                )
                VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    str(scan_id),

                    finding[
                        "template_id"
                    ],

                    finding[
                        "name"
                    ],

                    finding[
                        "severity"
                    ],

                    finding[
                        "impact"
                    ],

                    _json(
                        finding[
                            "chain"
                        ]
                    ),

                    _json(
                        finding[
                            "evidence"
                        ]
                    ),

                    _json(
                        finding[
                            "extracted"
                        ]
                    ),

                    finding[
                        "confirmed"
                    ],

                    finding[
                        "exploit_attempted"
                    ],

                    finding[
                        "exploit_success"
                    ],

                    finding[
                        "confidence"
                    ],

                    finding[
                        "cwe"
                    ],

                    finding[
                        "owasp"
                    ],

                    finding[
                        "remediation"
                    ],

                    str(end),

                    finding[
                        "ai_explanation"
                    ],

                    finding[
                        "description"
                    ],

                    finding[
                        "category"
                    ],

                    finding[
                        "endpoint"
                    ],

                    finding[
                        "method"
                    ],

                    finding[
                        "http_status"
                    ],

                    _json(
                        finding[
                            "details"
                        ]
                    ),
                ),
            )

        connection.commit()

        return str(
            scan_id
        )

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_scans(
    limit=50,
):
    """
    Return recent scans.

    IMPORTANT:
        Uses scans.scan_id, NOT scans.id.
    """

    init_db()

    try:

        limit = int(
            limit
        )

    except (
        TypeError,
        ValueError,
    ):

        limit = 50

    limit = max(
        1,
        min(
            limit,
            1000,
        ),
    )

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
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
                errors_count,
                confirmed_count
            FROM scans
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (
                limit,
            ),
        ).fetchall()

        results = []

        for row in rows:

            results.append(
                {
                    "scan_id": row[
                        "scan_id"
                    ],

                    "target": row[
                        "target"
                    ],

                    "url": row[
                        "target"
                    ],

                    "timestamp": row[
                        "timestamp"
                    ],

                    "start_time": row[
                        "start_time"
                    ],

                    "end_time": row[
                        "end_time"
                    ],

                    "fingerprint": _from_json(
                        row[
                            "fingerprint"
                        ]
                    ),

                    "findings_count": row[
                        "findings_count"
                    ],

                    "confirmed_count": row[
                        "confirmed_count"
                    ],

                    "scan_duration": row[
                        "scan_duration"
                    ],

                    "status": row[
                        "status"
                    ],

                    "scan_depth": row[
                        "scan_depth"
                    ],

                    "templates_loaded": row[
                        "templates_loaded"
                    ],

                    "requests_sent": row[
                        "requests_sent"
                    ],

                    "errors_count": row[
                        "errors_count"
                    ],
                }
            )

        return results

    finally:

        connection.close()


# ============================================================
# GET COMPLETE SCAN
# ============================================================

def get_scan(
    scan_id,
):
    """
    Return a complete scan and all findings.
    """

    init_db()

    if not scan_id:

        return None

    connection = get_connection()

    try:

        scan = connection.execute(
            """
            SELECT
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
                errors_count,
                confirmed_count
            FROM scans
            WHERE scan_id = ?
            """,
            (
                str(scan_id),
            ),
        ).fetchone()

        if scan is None:

            return None

        rows = connection.execute(
            """
            SELECT
                id,
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
                ai_explanation,
                description,
                category,
                endpoint,
                method,
                http_status,
                details
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (
                str(scan_id),
            ),
        ).fetchall()

        findings = []

        for row in rows:

            findings.append(
                {
                    "id": row["id"],

                    "scan_id": row[
                        "scan_id"
                    ],

                    "template_id": row[
                        "template_id"
                    ],

                    "name": row[
                        "name"
                    ],

                    "severity": row[
                        "severity"
                    ],

                    "impact": row[
                        "impact"
                    ],

                    "chain": _from_json(
                        row["chain"]
                    ),

                    "evidence": _from_json(
                        row["evidence"]
                    ),

                    "extracted": _from_json(
                        row["extracted"]
                    ),

                    "confirmed": bool(
                        row["confirmed"]
                    ),

                    "exploit_attempted": bool(
                        row[
                            "exploit_attempted"
                        ]
                    ),

                    "exploit_success": bool(
                        row[
                            "exploit_success"
                        ]
                    ),

                    "confidence": row[
                        "confidence"
                    ],

                    "cwe": row[
                        "cwe"
                    ],

                    "owasp": row[
                        "owasp"
                    ],

                    "remediation": row[
                        "remediation"
                    ],

                    "created_at": row[
                        "created_at"
                    ],

                    "ai_explanation": row[
                        "ai_explanation"
                    ],

                    "description": row[
                        "description"
                    ],

                    "category": row[
                        "category"
                    ],

                    "endpoint": row[
                        "endpoint"
                    ],

                    "method": row[
                        "method"
                    ],

                    "status": row[
                        "http_status"
                    ],

                    "http_status": row[
                        "http_status"
                    ],

                    "details": _from_json(
                        row["details"]
                    ),
                }
            )

        # ====================================================
        # RECALCULATE COUNTS FROM REAL FINDINGS
        # ====================================================

        findings_count = len(
            findings
        )

        confirmed_count = sum(
            1
            for finding in findings
            if finding[
                "confirmed"
            ]
        )

        return {
            "scan_id": scan[
                "scan_id"
            ],

            "target": scan[
                "target"
            ],

            "url": scan[
                "target"
            ],

            "timestamp": scan[
                "timestamp"
            ],

            "start_time": scan[
                "start_time"
            ],

            "end_time": scan[
                "end_time"
            ],

            "fingerprint": _from_json(
                scan[
                    "fingerprint"
                ]
            ),

            "findings_count": findings_count,

            "confirmed_count": confirmed_count,

            "scan_duration": scan[
                "scan_duration"
            ],

            "status": scan[
                "status"
            ],

            "scan_depth": scan[
                "scan_depth"
            ],

            "templates_loaded": scan[
                "templates_loaded"
            ],

            "requests_sent": scan[
                "requests_sent"
            ],

            "errors_count": scan[
                "errors_count"
            ],

            "findings": findings,
        }

    finally:

        connection.close()


# ============================================================
# GET SINGLE FINDING
# ============================================================

def get_finding(
    finding_id,
):
    """
    Return a single finding by findings.id.
    """

    init_db()

    connection = get_connection()

    try:

        row = connection.execute(
            """
            SELECT
                id,
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
                ai_explanation,
                description,
                category,
                endpoint,
                method,
                http_status,
                details
            FROM findings
            WHERE id = ?
            """,
            (
                finding_id,
            ),
        ).fetchone()

        if row is None:

            return None

        return {
            "id": row["id"],
            "scan_id": row["scan_id"],
            "template_id": row["template_id"],
            "name": row["name"],
            "severity": row["severity"],
            "impact": row["impact"],
            "chain": _from_json(
                row["chain"]
            ),
            "evidence": _from_json(
                row["evidence"]
            ),
            "extracted": _from_json(
                row["extracted"]
            ),
            "confirmed": bool(
                row["confirmed"]
            ),
            "exploit_attempted": bool(
                row["exploit_attempted"]
            ),
            "exploit_success": bool(
                row["exploit_success"]
            ),
            "confidence": row[
                "confidence"
            ],
            "cwe": row["cwe"],
            "owasp": row["owasp"],
            "remediation": row[
                "remediation"
            ],
            "created_at": row[
                "created_at"
            ],
            "ai_explanation": row[
                "ai_explanation"
            ],
            "description": row[
                "description"
            ],
            "category": row[
                "category"
            ],
            "endpoint": row[
                "endpoint"
            ],
            "method": row[
                "method"
            ],
            "status": row[
                "http_status"
            ],
            "http_status": row[
                "http_status"
            ],
            "details": _from_json(
                row["details"]
            ),
        }

    finally:

        connection.close()


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_statistics():
    """
    Calculate dashboard statistics directly from SQLite.
    """

    init_db()

    connection = get_connection()

    try:

        scans = connection.execute(
            """
            SELECT COUNT(*)
            FROM scans
            """
        ).fetchone()[0]

        findings = connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            """
        ).fetchone()[0]

        confirmed = connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE confirmed = 1
            """
        ).fetchone()[0]

        critical = connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE UPPER(severity) = 'CRITICAL'
            """
        ).fetchone()[0]

        high = connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE UPPER(severity) = 'HIGH'
            """
        ).fetchone()[0]

        medium = connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE UPPER(severity) = 'MEDIUM'
            """
        ).fetchone()[0]

        low = connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE UPPER(severity) = 'LOW'
            """
        ).fetchone()[0]

        info = connection.execute(
            """
            SELECT COUNT(*)
            FROM findings
            WHERE UPPER(severity) = 'INFO'
            """
        ).fetchone()[0]

        return {
            "scans": scans,
            "findings": findings,
            "confirmed": confirmed,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
            "info": info,
        }

    finally:

        connection.close()


# ============================================================
# SEVERITY COUNTS
# ============================================================

def get_severity_counts():
    """
    Return finding counts grouped by severity.
    """

    init_db()

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                UPPER(severity) AS severity,
                COUNT(*) AS count
            FROM findings
            GROUP BY UPPER(severity)
            ORDER BY count DESC
            """
        ).fetchall()

        return {
            row[
                "severity"
            ]: row[
                "count"
            ]
            for row in rows
        }

    finally:

        connection.close()


# ============================================================
# RECENT FINDINGS
# ============================================================

def get_recent_findings(
    limit=20,
):
    """
    Return recent findings for dashboard/report use.
    """

    init_db()

    try:

        limit = int(
            limit
        )

    except (
        TypeError,
        ValueError,
    ):

        limit = 20

    limit = max(
        1,
        min(
            limit,
            500,
        ),
    )

    connection = get_connection()

    try:

        rows = connection.execute(
            """
            SELECT
                id,
                scan_id,
                name,
                severity,
                confirmed,
                confidence,
                endpoint,
                method,
                http_status,
                created_at
            FROM findings
            ORDER BY id DESC
            LIMIT ?
            """,
            (
                limit,
            ),
        ).fetchall()

        return [
            {
                "id": row[
                    "id"
                ],

                "scan_id": row[
                    "scan_id"
                ],

                "name": row[
                    "name"
                ],

                "severity": row[
                    "severity"
                ],

                "confirmed": bool(
                    row[
                        "confirmed"
                    ]
                ),

                "confidence": row[
                    "confidence"
                ],

                "endpoint": row[
                    "endpoint"
                ],

                "method": row[
                    "method"
                ],

                "status": row[
                    "http_status"
                ],

                "http_status": row[
                    "http_status"
                ],

                "created_at": row[
                    "created_at"
                ],
            }
            for row in rows
        ]

    finally:

        connection.close()


# ============================================================
# DELETE SCAN
# ============================================================

def delete_scan(
    scan_id,
):
    """
    Delete a scan and its findings.
    """

    init_db()

    connection = get_connection()

    try:

        cursor = connection.cursor()

        cursor.execute(
            """
            DELETE FROM findings
            WHERE scan_id = ?
            """,
            (
                str(scan_id),
            ),
        )

        cursor.execute(
            """
            DELETE FROM scans
            WHERE scan_id = ?
            """,
            (
                str(scan_id),
            ),
        )

        deleted = (
            cursor.rowcount > 0
        )

        connection.commit()

        return deleted

    except Exception:

        connection.rollback()

        raise

    finally:

        connection.close()


# ============================================================
# DATABASE HEALTH
# ============================================================

def check_database():
    """
    Verify the database is readable and internally consistent.
    """

    result = {
        "ok": False,
        "path": get_db_path(),
        "scans": 0,
        "findings": 0,
        "error": None,
    }

    try:

        init_db()

        connection = get_connection()

        try:

            result[
                "scans"
            ] = connection.execute(
                """
                SELECT COUNT(*)
                FROM scans
                """
            ).fetchone()[0]

            result[
                "findings"
            ] = connection.execute(
                """
                SELECT COUNT(*)
                FROM findings
                """
            ).fetchone()[0]

            integrity = connection.execute(
                """
                PRAGMA integrity_check
                """
            ).fetchone()[0]

            if integrity != "ok":

                result[
                    "error"
                ] = str(
                    integrity
                )

                return result

            result[
                "ok"
            ] = True

            return result

        finally:

            connection.close()

    except Exception as exc:

        result[
            "error"
        ] = str(
            exc
        )

        return result


# ============================================================
# MAIN DATABASE TEST
# ============================================================

if __name__ == "__main__":

    logging.basicConfig(
        level=logging.INFO
    )

    print(
        "VulnForge Database"
    )

    print(
        "Path:",
        get_db_path()
    )

    init_db()

    health = check_database()

    print(
        json.dumps(
            health,
            indent=2,
        )
    )

    print()
    print(
        "Statistics:"
    )

    print(
        json.dumps(
            get_statistics(),
            indent=2,
        )
    )

