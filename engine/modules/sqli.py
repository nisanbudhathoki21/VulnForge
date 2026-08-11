import re
from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

SQL_ERROR_PATTERNS = [
    (r"SQLITE_ERROR", "SQLite Database Error"),
    (r"You have an error in your SQL syntax", "MySQL Error-based SQL Injection"),
    (r"Warning:\s*mysql_", "MySQL PHP Driver Error"),
    (r"pg_query\(\):\s*Query failed", "PostgreSQL Error-based SQL Injection"),
    (r"org\.postgresql\.util\.PSQLException", "PostgreSQL Java Error"),
    (r"Unclosed quotation mark before the character string", "Microsoft SQL Server Error"),
    (r"SQLite3::SQLException", "SQLite3 Error-based SQL Injection"),
    (r"sqlite3\.OperationalError:", "SQLite Python Error")
]

SQL_PROBES = [
    {"path": "/rest/products/search", "param": "q", "payload": "apple'))--"},
    {"path": "/rest/products/search", "param": "q", "payload": "test'"},
    {"path": "/", "param": "id", "payload": "1'"}
]

async def run_sqli_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    for probe in SQL_PROBES:
        test_url = f"{base_clean}{probe['path']}?{probe['param']}={probe['payload']}"
        res = await requester.send("GET", test_url, module="sqli_error")
        if baseline.is_similar_to_nonexistent(res):
            continue
        for pattern, desc in SQL_ERROR_PATTERNS:
            if re.search(pattern, res.body, re.IGNORECASE):
                findings.append({
                    "scan_id": scan_id, "target_url": target_url, "endpoint": test_url, "tested_endpoint": test_url,
                    "parameter_name": probe["param"], "parameter_location": "Query Parameter",
                    "payload_used": f"?{probe['param']}={probe['payload']}", "payload_type": "SQL Syntax Error Probe",
                    "vuln_type": "SQL Injection (Error-Based)",
                    "title": f"SQL Injection on {probe['path']} via '{probe['param']}' parameter",
                    "severity": "CRITICAL", "confidence": "CONFIRMED", "is_confirmed": True,
                    "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "cwe_id": "CWE-89", "owasp_category": "A03:2021-Injection",
                    "category": "Server-Side Injection", "template_id": "vf-sqli-error-01",
                    "short_description": f"The application reflected raw database syntax error ({desc}) when tested with quote payload.",
                    "description": f"Database syntax error occurred when testing parameter '{probe['param']}'. Raw error message returned to client.",
                    "technical_impact": "Unrestricted database read/write access, authentication bypass, and data exfiltration.",
                    "remediation": "Use parameterized queries (prepared statements). Never concatenate user input into SQL commands.",
                    "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
                    "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
                    "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
                    "baseline_raw_response": baseline.root_response.raw_response if baseline.root_response else "",
                    "verification_proof": f"Database syntax error detected: Pattern '{pattern}' matched in response body."
                })
                return findings
    return findings
