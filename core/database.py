#!/usr/bin/env python3
"""
core/database.py – God‑Level Database Module for VulnForge
Bug‑Bounty Style: production‑ready, schema migration, full error handling, logging.
"""

import sqlite3
import json
import logging
import os
from datetime import datetime
from typing import List, Dict, Any, Optional

# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------
DB_PATH = 'vulnforge.db'
logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Schema Definitions
# ------------------------------------------------------------------
SCHEMA = {
    'scans': '''
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
    ''',
    'findings': '''
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
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        )
    ''',
    'fingerprints': '''
        CREATE TABLE IF NOT EXISTS fingerprints (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            target TEXT NOT NULL,
            server TEXT,
            waf TEXT,
            cdn TEXT,
            tech_stack TEXT,
            frameworks TEXT,
            cms TEXT,
            libraries TEXT,
            databases TEXT,
            os TEXT,
            security_rating TEXT,
            created_at TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(scan_id) ON DELETE CASCADE
        )
    ''',
}

# ------------------------------------------------------------------
# Database Connection
# ------------------------------------------------------------------
def get_connection() -> sqlite3.Connection:
    """Return a connection to the SQLite database with row factory."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

def column_exists(cursor: sqlite3.Cursor, table: str, column: str) -> bool:
    """Check if a column exists in a table."""
    cursor.execute(f"PRAGMA table_info({table})")
    columns = [row[1] for row in cursor.fetchall()]
    return column in columns

def table_exists(cursor: sqlite3.Cursor, table: str) -> bool:
    """Check if a table exists."""
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
        (table,)
    )
    return cursor.fetchone() is not None

# ------------------------------------------------------------------
# Schema Migration
# ------------------------------------------------------------------
def migrate_schema() -> None:
    """Apply schema migrations automatically."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Create tables if not exist
            for name, stmt in SCHEMA.items():
                cursor.execute(stmt)

            # --- Migrate scans table ---
            if table_exists(cursor, 'scans'):
                columns_to_add = [
                    ('scan_duration', 'REAL'),
                    ('status', "TEXT DEFAULT 'completed'"),
                    ('scan_depth', 'INTEGER DEFAULT 1'),
                    ('templates_loaded', 'INTEGER DEFAULT 0'),
                    ('requests_sent', 'INTEGER DEFAULT 0'),
                    ('errors_count', 'INTEGER DEFAULT 0'),
                ]
                for col_name, col_type in columns_to_add:
                    if not column_exists(cursor, 'scans', col_name):
                        cursor.execute(f'ALTER TABLE scans ADD COLUMN {col_name} {col_type}')
                        logger.info(f"Added column '{col_name}' to scans table.")

            # --- Migrate findings table ---
            if table_exists(cursor, 'findings'):
                # Add columns without default for created_at (to avoid SQLite error)
                columns_to_add = [
                    ('confirmed', 'BOOLEAN DEFAULT 0'),
                    ('exploit_attempted', 'BOOLEAN DEFAULT 0'),
                    ('exploit_success', 'BOOLEAN DEFAULT 0'),
                    ('confidence', 'REAL DEFAULT 0.0'),
                    ('cwe', 'TEXT'),
                    ('owasp', 'TEXT'),
                    ('remediation', 'TEXT'),
                    ('created_at', 'TEXT'),  # no default
                ]
                for col_name, col_type in columns_to_add:
                    if not column_exists(cursor, 'findings', col_name):
                        cursor.execute(f'ALTER TABLE findings ADD COLUMN {col_name} {col_type}')
                        logger.info(f"Added column '{col_name}' to findings table.")

            # --- Migrate fingerprints table ---
            if not table_exists(cursor, 'fingerprints'):
                cursor.execute(SCHEMA['fingerprints'])
                logger.info("Created fingerprints table.")
            else:
                if not column_exists(cursor, 'fingerprints', 'created_at'):
                    cursor.execute('ALTER TABLE fingerprints ADD COLUMN created_at TEXT')
                    logger.info("Added column 'created_at' to fingerprints table.")

            conn.commit()
            logger.debug("Schema migration completed successfully.")
    except sqlite3.Error as e:
        logger.error(f"Schema migration failed: {e}")
        raise

# ------------------------------------------------------------------
# Initialization
# ------------------------------------------------------------------
def init_db() -> None:
    """Initialize the database – create tables and migrate schema."""
    try:
        migrate_schema()
        logger.info(f"Database initialized at {DB_PATH}")
    except sqlite3.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def db_exists() -> bool:
    """Check if the database file exists."""
    return os.path.exists(DB_PATH)

def get_db_size() -> int:
    """Get the size of the database file in bytes."""
    if db_exists():
        return os.path.getsize(DB_PATH)
    return 0

# ------------------------------------------------------------------
# Save Scan
# ------------------------------------------------------------------
def save_scan(
    scan_id: str,
    target: str,
    fingerprint: Dict,
    findings: List[Dict],
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    scan_duration: Optional[float] = None,
    status: str = 'completed',
    scan_depth: int = 1,
    templates_loaded: int = 0,
    requests_sent: int = 0,
    errors_count: int = 0,
) -> None:
    """
    Save a scan and its findings to the database.
    """
    if start_time is None:
        start_time = datetime.now().isoformat()
    if end_time is None:
        end_time = datetime.now().isoformat()
    if scan_duration is None:
        try:
            scan_duration = (
                datetime.fromisoformat(end_time) - datetime.fromisoformat(start_time)
            ).total_seconds()
        except:
            scan_duration = 0.0

    timestamp = datetime.now().isoformat()
    now = timestamp

    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Insert or replace the scan record
            cursor.execute('''
                INSERT OR REPLACE INTO scans (
                    scan_id, target, timestamp, start_time, end_time,
                    fingerprint, findings_count, scan_duration, status,
                    scan_depth, templates_loaded, requests_sent, errors_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                scan_id,
                target,
                timestamp,
                start_time,
                end_time,
                json.dumps(fingerprint),
                len(findings),
                scan_duration,
                status,
                scan_depth,
                templates_loaded,
                requests_sent,
                errors_count,
            ))

            # Delete existing findings for this scan
            cursor.execute('DELETE FROM findings WHERE scan_id = ?', (scan_id,))

            # Insert each finding
            for f in findings:
                evidence = f.get('evidence', {})
                extracted = f.get('extracted', {})
                cursor.execute('''
                    INSERT INTO findings (
                        scan_id, template_id, name, severity, impact, chain,
                        evidence, extracted, confirmed, exploit_attempted,
                        exploit_success, confidence, cwe, owasp, remediation,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    f.get('template_id'),
                    f.get('name'),
                    f.get('severity', 'info'),
                    f.get('impact'),
                    f.get('chain'),
                    json.dumps(evidence),
                    json.dumps(extracted),
                    f.get('confirmed', False),
                    f.get('exploit_attempted', False),
                    f.get('exploit_success', False),
                    f.get('confidence', 0.0),
                    f.get('cwe'),
                    f.get('owasp'),
                    f.get('remediation'),
                    now,
                ))

            # Save fingerprint data separately
            if fingerprint:
                cursor.execute('''
                    INSERT OR REPLACE INTO fingerprints (
                        scan_id, target, server, waf, cdn, tech_stack,
                        frameworks, cms, libraries, databases, os, security_rating,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    scan_id,
                    target,
                    fingerprint.get('server'),
                    json.dumps(fingerprint.get('waf', [])),
                    json.dumps(fingerprint.get('cdn', [])),
                    json.dumps(fingerprint.get('tech_stack', [])),
                    json.dumps(fingerprint.get('frameworks', [])),
                    json.dumps(fingerprint.get('cms', [])),
                    json.dumps(fingerprint.get('libraries', [])),
                    json.dumps(fingerprint.get('databases', [])),
                    fingerprint.get('os'),
                    fingerprint.get('security_rating'),
                    now,
                ))

            conn.commit()
            logger.info(f"✅ Saved scan {scan_id} with {len(findings)} findings.")

    except sqlite3.Error as e:
        logger.error(f"❌ Failed to save scan {scan_id}: {e}")
        raise

# ------------------------------------------------------------------
# Retrieve Scans
# ------------------------------------------------------------------
def get_scans(limit: int = 20, offset: int = 0) -> List[Dict]:
    """Retrieve the most recent scans."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT
                    scan_id, target, timestamp, findings_count,
                    scan_duration, status, start_time, end_time,
                    templates_loaded, requests_sent, errors_count
                FROM scans
                ORDER BY timestamp DESC
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            rows = cursor.fetchall()
        return [
            {
                'scan_id': row['scan_id'],
                'target': row['target'],
                'timestamp': row['timestamp'],
                'findings_count': row['findings_count'],
                'scan_duration': row['scan_duration'],
                'status': row['status'],
                'start_time': row['start_time'],
                'end_time': row['end_time'],
                'templates_loaded': row['templates_loaded'],
                'requests_sent': row['requests_sent'],
                'errors_count': row['errors_count'],
            }
            for row in rows
        ]
    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve scan list: {e}")
        return []

def get_scan(scan_id: str) -> Optional[Dict]:
    """Retrieve a specific scan with all its findings and fingerprint."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()

            # Scan metadata
            cursor.execute('''
                SELECT * FROM scans WHERE scan_id = ?
            ''', (scan_id,))
            row = cursor.fetchone()
            if not row:
                logger.warning(f"Scan ID {scan_id} not found.")
                return None

            scan = dict(row)
            scan['fingerprint'] = json.loads(scan.get('fingerprint', '{}'))

            # Fingerprint data
            cursor.execute('''
                SELECT * FROM fingerprints WHERE scan_id = ?
            ''', (scan_id,))
            fp_row = cursor.fetchone()
            if fp_row:
                scan['fingerprint_detail'] = {
                    'server': fp_row['server'],
                    'waf': json.loads(fp_row['waf']) if fp_row['waf'] else [],
                    'cdn': json.loads(fp_row['cdn']) if fp_row['cdn'] else [],
                    'tech_stack': json.loads(fp_row['tech_stack']) if fp_row['tech_stack'] else [],
                    'frameworks': json.loads(fp_row['frameworks']) if fp_row['frameworks'] else [],
                    'cms': json.loads(fp_row['cms']) if fp_row['cms'] else [],
                    'libraries': json.loads(fp_row['libraries']) if fp_row['libraries'] else [],
                    'databases': json.loads(fp_row['databases']) if fp_row['databases'] else [],
                    'os': fp_row['os'],
                    'security_rating': fp_row['security_rating'],
                }

            # Findings
            cursor.execute('''
                SELECT * FROM findings WHERE scan_id = ? ORDER BY severity DESC, created_at DESC
            ''', (scan_id,))
            findings_rows = cursor.fetchall()

            scan['findings'] = []
            for f in findings_rows:
                finding = dict(f)
                finding['evidence'] = json.loads(finding.get('evidence', '{}'))
                finding['extracted'] = json.loads(finding.get('extracted', '{}'))
                scan['findings'].append(finding)

            return scan
    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve scan {scan_id}: {e}")
        return None

# ------------------------------------------------------------------
# Delete / Cleanup
# ------------------------------------------------------------------
def delete_scan(scan_id: str) -> bool:
    """Delete a scan and all associated findings."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM scans WHERE scan_id = ?', (scan_id,))
            if cursor.rowcount == 0:
                logger.warning(f"Scan ID {scan_id} not found for deletion.")
                return False
            conn.commit()
            logger.info(f"🗑️ Deleted scan {scan_id}")
            return True
    except sqlite3.Error as e:
        logger.error(f"Failed to delete scan {scan_id}: {e}")
        return False

def clear_all_scans() -> None:
    """Delete all scans and findings (USE WITH CAUTION)."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM findings')
            cursor.execute('DELETE FROM fingerprints')
            cursor.execute('DELETE FROM scans')
            conn.commit()
            logger.warning("🧹 All scan data cleared.")
    except sqlite3.Error as e:
        logger.error(f"Failed to clear scans: {e}")
        raise

def get_statistics() -> Dict:
    """Get database statistics."""
    try:
        with get_connection() as conn:
            cursor = conn.cursor()
            stats = {}
            cursor.execute('SELECT COUNT(*) FROM scans')
            stats['total_scans'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(*) FROM findings')
            stats['total_findings'] = cursor.fetchone()[0]
            cursor.execute('SELECT COUNT(DISTINCT target) FROM scans')
            stats['unique_targets'] = cursor.fetchone()[0]
            cursor.execute(
                "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
            )
            stats['severity_counts'] = {row[0]: row[1] for row in cursor.fetchall()}
            cursor.execute(
                "SELECT AVG(findings_count) FROM scans WHERE findings_count > 0"
            )
            avg = cursor.fetchone()[0]
            stats['avg_findings_per_scan'] = avg if avg else 0
            stats['db_size'] = get_db_size()
            return stats
    except sqlite3.Error as e:
        logger.error(f"Failed to get statistics: {e}")
        return {}

# ------------------------------------------------------------------
# Export / Import
# ------------------------------------------------------------------
def export_scan(scan_id: str, output_file: str) -> bool:
    """Export a scan to a JSON file."""
    scan = get_scan(scan_id)
    if not scan:
        return False
    try:
        with open(output_file, 'w') as f:
            json.dump(scan, f, indent=2, default=str)
        logger.info(f"📤 Exported scan {scan_id} to {output_file}")
        return True
    except Exception as e:
        logger.error(f"Failed to export scan {scan_id}: {e}")
        return False

def import_scan(input_file: str) -> Optional[str]:
    """Import a scan from a JSON file."""
    try:
        with open(input_file, 'r') as f:
            scan_data = json.load(f)
        scan_id = scan_data.get('scan_id')
        if not scan_id:
            raise ValueError("No scan_id found in imported file.")
        save_scan(
            scan_id=scan_id,
            target=scan_data.get('target', ''),
            fingerprint=scan_data.get('fingerprint', {}),
            findings=scan_data.get('findings', []),
            start_time=scan_data.get('start_time'),
            end_time=scan_data.get('end_time'),
        )
        logger.info(f"📥 Imported scan {scan_id} from {input_file}")
        return scan_id
    except Exception as e:
        logger.error(f"Failed to import scan: {e}")
        return None
