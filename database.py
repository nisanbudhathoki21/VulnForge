import sqlite3
import json
import os
from datetime import datetime
from typing import Dict, List, Optional, Any

def get_db_path() -> str:
    """Resolves active database path from environment or default."""
    return os.environ.get("VULNFORGE_DB_PATH", os.path.abspath("vulnforge.db"))

def set_db_path(path: str):
    """Sets active database path globally."""
    abs_path = os.path.abspath(path)
    os.environ["VULNFORGE_DB_PATH"] = abs_path
    init_db()

def get_db_connection():
    db_path = get_db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=20.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn

def init_db():
    conn = get_db_connection()
    with conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS scans (
            id TEXT PRIMARY KEY,
            target_url TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'pending',
            findings_count INTEGER NOT NULL DEFAULT 0,
            confirmed_count INTEGER NOT NULL DEFAULT 0,
            requests_count INTEGER NOT NULL DEFAULT 0,
            duration_seconds REAL NOT NULL DEFAULT 0.0,
            created_at TEXT NOT NULL,
            options_json TEXT DEFAULT '{}',
            summary_json TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            target_url TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            tested_endpoint TEXT NOT NULL,
            parameter_name TEXT DEFAULT '',
            parameter_location TEXT DEFAULT 'Query',
            payload_used TEXT DEFAULT '',
            payload_type TEXT DEFAULT '',
            vuln_type TEXT NOT NULL,
            title TEXT NOT NULL,
            severity TEXT NOT NULL,
            confidence TEXT NOT NULL DEFAULT 'HIGH',
            is_confirmed INTEGER NOT NULL DEFAULT 0,
            cvss_score REAL DEFAULT 0.0,
            cvss_vector TEXT DEFAULT '',
            cwe_id TEXT DEFAULT '',
            owasp_category TEXT DEFAULT '',
            category TEXT DEFAULT 'Server-Side',
            template_id TEXT DEFAULT '',
            short_description TEXT DEFAULT '',
            description TEXT DEFAULT '',
            technical_impact TEXT DEFAULT '',
            remediation TEXT DEFAULT '',
            request_method TEXT DEFAULT 'GET',
            raw_request TEXT DEFAULT '',
            request_headers_json TEXT DEFAULT '{}',
            request_body TEXT DEFAULT '',
            raw_response TEXT DEFAULT '',
            response_headers_json TEXT DEFAULT '{}',
            response_body TEXT DEFAULT '',
            response_status INTEGER DEFAULT 200,
            response_time_ms REAL DEFAULT 0.0,
            baseline_raw_response TEXT DEFAULT '',
            verification_proof TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS requests_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            status_code INTEGER,
            duration_ms REAL,
            module TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS repeater_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            method TEXT NOT NULL,
            url TEXT NOT NULL,
            raw_request TEXT NOT NULL,
            raw_response TEXT,
            status_code INTEGER,
            duration_ms REAL,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
        CREATE INDEX IF NOT EXISTS idx_findings_confirmed ON findings(is_confirmed);
        """)
    conn.close()

def save_scan(scan_data: Dict[str, Any]):
    conn = get_db_connection()
    with conn:
        conn.execute("""
            INSERT OR REPLACE INTO scans 
            (id, target_url, status, findings_count, confirmed_count, requests_count, duration_seconds, created_at, options_json, summary_json)
            VALUES (:id, :target_url, :status, :findings_count, :confirmed_count, :requests_count, :duration_seconds, :created_at, :options_json, :summary_json)
        """, {
            "id": scan_data["id"],
            "target_url": scan_data["target_url"],
            "status": scan_data.get("status", "pending"),
            "findings_count": scan_data.get("findings_count", 0),
            "confirmed_count": scan_data.get("confirmed_count", 0),
            "requests_count": scan_data.get("requests_count", 0),
            "duration_seconds": scan_data.get("duration_seconds", 0.0),
            "created_at": scan_data.get("created_at", datetime.now().isoformat()),
            "options_json": json.dumps(scan_data.get("options", {})),
            "summary_json": json.dumps(scan_data.get("summary", {}))
        })
    conn.close()

def update_scan_progress(scan_id: str, requests_count: int, findings_count: int, confirmed_count: int, status: Optional[str] = None, duration_seconds: Optional[float] = None):
    conn = get_db_connection()
    with conn:
        updates = ["requests_count = :requests_count", "findings_count = :findings_count", "confirmed_count = :confirmed_count"]
        params = {"scan_id": scan_id, "requests_count": requests_count, "findings_count": findings_count, "confirmed_count": confirmed_count}
        if status:
            updates.append("status = :status")
            params["status"] = status
        if duration_seconds is not None:
            updates.append("duration_seconds = :duration_seconds")
            params["duration_seconds"] = duration_seconds
        conn.execute(f"UPDATE scans SET {', '.join(updates)} WHERE id = :scan_id", params)
    conn.close()

def save_finding(finding: Dict[str, Any]) -> int:
    conn = get_db_connection()
    with conn:
        cursor = conn.execute("""
            INSERT INTO findings 
            (scan_id, target_url, endpoint, tested_endpoint, parameter_name, parameter_location,
             payload_used, payload_type, vuln_type, title, severity, confidence, is_confirmed,
             cvss_score, cvss_vector, cwe_id, owasp_category, category, template_id,
             short_description, description, technical_impact, remediation, request_method,
             raw_request, request_headers_json, request_body, raw_response, response_headers_json,
             response_body, response_status, response_time_ms, baseline_raw_response,
             verification_proof, created_at)
            VALUES 
            (:scan_id, :target_url, :endpoint, :tested_endpoint, :parameter_name, :parameter_location,
             :payload_used, :payload_type, :vuln_type, :title, :severity, :confidence, :is_confirmed,
             :cvss_score, :cvss_vector, :cwe_id, :owasp_category, :category, :template_id,
             :short_description, :description, :technical_impact, :remediation, :request_method,
             :raw_request, :request_headers_json, :request_body, :raw_response, :response_headers_json,
             :response_body, :response_status, :response_time_ms, :baseline_raw_response,
             :verification_proof, :created_at)
        """, {
            "scan_id": finding["scan_id"],
            "target_url": finding["target_url"],
            "endpoint": finding.get("endpoint", finding["target_url"]),
            "tested_endpoint": finding.get("tested_endpoint", finding.get("endpoint", "")),
            "parameter_name": finding.get("parameter_name", "N/A"),
            "parameter_location": finding.get("parameter_location", "Query String / Path"),
            "payload_used": finding.get("payload_used", finding.get("payload", "")),
            "payload_type": finding.get("payload_type", "Active Verification Probe"),
            "vuln_type": finding.get("vuln_type", "Security Weakness"),
            "title": finding["title"],
            "severity": finding.get("severity", "MEDIUM"),
            "confidence": finding.get("confidence", "CONFIRMED"),
            "is_confirmed": 1 if finding.get("is_confirmed", False) else 0,
            "cvss_score": finding.get("cvss_score", 5.0),
            "cvss_vector": finding.get("cvss_vector", ""),
            "cwe_id": finding.get("cwe_id", ""),
            "owasp_category": finding.get("owasp_category", ""),
            "category": finding.get("category", "Server-Side"),
            "template_id": finding.get("template_id", ""),
            "short_description": finding.get("short_description", finding.get("description", "")[:180]),
            "description": finding.get("description", ""),
            "technical_impact": finding.get("technical_impact", finding.get("impact", "")),
            "remediation": finding.get("remediation", ""),
            "request_method": finding.get("request_method", "GET"),
            "raw_request": finding.get("raw_request", ""),
            "request_headers_json": json.dumps(finding.get("request_headers", {})),
            "request_body": finding.get("request_body", ""),
            "raw_response": finding.get("raw_response", ""),
            "response_headers_json": json.dumps(finding.get("response_headers", {})),
            "response_body": finding.get("response_body", ""),
            "response_status": finding.get("response_status", 200),
            "response_time_ms": finding.get("response_time_ms", 0.0),
            "baseline_raw_response": finding.get("baseline_raw_response", ""),
            "verification_proof": finding.get("verification_proof", ""),
            "created_at": finding.get("created_at", datetime.now().isoformat())
        })
        fid = cursor.lastrowid
        conn.execute("""
            UPDATE scans SET 
                findings_count = (SELECT COUNT(*) FROM findings WHERE scan_id = :scan_id),
                confirmed_count = (SELECT COUNT(*) FROM findings WHERE scan_id = :scan_id AND is_confirmed = 1)
            WHERE id = :scan_id
        """, {"scan_id": finding["scan_id"]})
    conn.close()
    return fid

def log_request(scan_id: str, method: str, url: str, status_code: int, duration_ms: float, module: str = ""):
    conn = get_db_connection()
    with conn:
        conn.execute("INSERT INTO requests_log (scan_id, method, url, status_code, duration_ms, module, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (scan_id, method, url, status_code, duration_ms, module, datetime.now().isoformat()))
        conn.execute("UPDATE scans SET requests_count = requests_count + 1 WHERE id = ?", (scan_id,))
    conn.close()

def get_all_scans() -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM scans ORDER BY created_at DESC").fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_scan_by_id(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_findings_for_scan(scan_id: str, confirmed_only: bool = False) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    q = "SELECT * FROM findings WHERE scan_id = ?"
    if confirmed_only:
        q += " AND is_confirmed = 1"
    q += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, id ASC"
    rows = conn.execute(q, (scan_id,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_all_findings(confirmed_only: bool = False, severity: Optional[str] = None, search: Optional[str] = None) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    q = "SELECT * FROM findings WHERE 1=1"
    p = []
    if confirmed_only:
        q += " AND is_confirmed = 1"
    if severity and severity.upper() != "ALL":
        q += " AND UPPER(severity) = ?"
        p.append(severity.upper())
    if search:
        q += " AND (title LIKE ? OR tested_endpoint LIKE ? OR vuln_type LIKE ?)"
        t = f"%{search}%"
        p.extend([t, t, t])
    q += " ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, id DESC"
    rows = conn.execute(q, p).fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_finding_by_id(finding_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
    conn.close()
    return dict(row) if row else None

def get_dashboard_stats() -> Dict[str, Any]:
    conn = get_db_connection()
    total_scans = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    total_findings = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    confirmed_findings = conn.execute("SELECT COUNT(*) FROM findings WHERE is_confirmed = 1").fetchone()[0]
    unique_targets = conn.execute("SELECT COUNT(DISTINCT target_url) FROM scans").fetchone()[0]
    total_requests = conn.execute("SELECT COALESCE(SUM(requests_count), 0) FROM scans").fetchone()[0]
    severity_breakdown = {
        "CRITICAL": conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL'").fetchone()[0],
        "HIGH": conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'HIGH'").fetchone()[0],
        "MEDIUM": conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'MEDIUM'").fetchone()[0],
        "LOW": conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'LOW'").fetchone()[0],
        "INFO": conn.execute("SELECT COUNT(*) FROM findings WHERE severity = 'INFO'").fetchone()[0],
    }
    avg_findings = round(total_findings / max(total_scans, 1), 1)
    conn.close()
    return {
        "active_db": get_db_path(),
        "total_scans": total_scans,
        "total_findings": total_findings,
        "confirmed_findings": confirmed_findings,
        "unique_targets": unique_targets,
        "total_requests": total_requests,
        "avg_findings_per_scan": avg_findings,
        "severity_breakdown": severity_breakdown
    }

def save_repeater_request(data: Dict[str, Any]) -> int:
    conn = get_db_connection()
    with conn:
        cur = conn.execute("INSERT INTO repeater_history (title, method, url, raw_request, raw_response, status_code, duration_ms, created_at) VALUES (:title, :method, :url, :raw_request, :raw_response, :status_code, :duration_ms, :created_at)",
                           {"title": data.get("title", "Repeater Probe"), "method": data["method"], "url": data["url"], "raw_request": data["raw_request"], "raw_response": data.get("raw_response", ""), "status_code": data.get("status_code", 0), "duration_ms": data.get("duration_ms", 0.0), "created_at": datetime.now().isoformat()})
        rep_id = cur.lastrowid
    conn.close()
    return rep_id

def get_repeater_history(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    rows = conn.execute("SELECT * FROM repeater_history ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]
