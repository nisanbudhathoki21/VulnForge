#!/usr/bin/env python3
"""
VulnForge - Advanced Local Dashboard
====================================

Purpose
-------
Generate a professional, self-contained HTML dashboard directly from
vulnforge.db.

Design goals
------------
1. Never hard-code findings.
2. Never fabricate evidence.
3. Correctly interpret evidence stored as:
       - dict
       - JSON string
       - nested JSON string
       - details JSON
       - extracted JSON
3. Keep target URL and exact endpoint separate.
4. Show request and response separately.
5. Show HTTP status from the evidence object.
6. Make technical evidence understandable to beginners.
7. Preserve raw evidence in a collapsible technical section.
8. Generate an index dashboard.
9. Generate a dedicated HTML report for every scan.
10. Avoid giant nested f-strings so CSS/JS braces cannot break Python.
11. Work with the existing VulnForge SQLite schema.
12. Never invent a response when none was recorded.

Usage
-----
    python -m terminal.dashboard

or:

    from terminal.dashboard import generate_dashboard
    generate_dashboard()

Default output
--------------
    vulnforge_dashboard.html

Per-scan reports
----------------
    vulnforge_reports/
        scan_<scan_id>.html

PDF
---
PDF generation is optional. If terminal.pdf_summary exists and works,
a summary PDF is generated. A PDF failure never prevents HTML generation.
"""

from __future__ import annotations

import html
import json
import re
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DB = PROJECT_ROOT / "vulnforge.db"
DEFAULT_DASHBOARD = PROJECT_ROOT / "vulnforge_dashboard.html"
DEFAULT_REPORT_DIR = PROJECT_ROOT / "vulnforge_reports"


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SEVERITY_ORDER = [
    "critical",
    "high",
    "medium",
    "low",
    "info",
]

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#22c55e",
    "info": "#64748b",
}

SEVERITY_SCORE = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}


# ---------------------------------------------------------------------------
# Generic helpers
# ---------------------------------------------------------------------------

def esc(value: Any) -> str:
    """HTML escape anything safely."""
    if value is None:
        return ""

    return html.escape(str(value), quote=True)


def safe_str(value: Any, default: str = "") -> str:
    """Convert a value to string without producing 'None'."""
    if value is None:
        return default

    text = str(value).strip()

    if not text:
        return default

    return text


def json_dumps(value: Any, pretty: bool = True) -> str:
    """Serialize arbitrary values safely."""
    try:
        if pretty:
            return json.dumps(
                value,
                indent=2,
                ensure_ascii=False,
                default=str,
            )

        return json.dumps(
            value,
            ensure_ascii=False,
            default=str,
        )

    except Exception:
        return safe_str(value)


def parse_json(value: Any) -> Any:
    """
    Parse JSON safely.

    Handles:
        dict
        list
        JSON string
        double-encoded JSON
        plain text
    """
    if value is None:
        return None

    if isinstance(value, (dict, list, tuple, int, float, bool)):
        return value

    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="replace")
        except Exception:
            return str(value)

    if not isinstance(value, str):
        return value

    text = value.strip()

    if not text:
        return None

    current: Any = text

    for _ in range(3):
        if not isinstance(current, str):
            return current

        try:
            decoded = json.loads(current)
        except Exception:
            return current

        current = decoded

    return current


def first_nonempty(*values: Any) -> Any:
    """Return the first meaningful value."""
    for value in values:
        if value is None:
            continue

        if isinstance(value, str) and not value.strip():
            continue

        return value

    return None


def normalize_severity(value: Any) -> str:
    sev = safe_str(value, "info").lower()

    aliases = {
        "informational": "info",
        "notice": "info",
        "moderate": "medium",
        "urgent": "critical",
    }

    return aliases.get(sev, sev if sev in SEVERITY_COLORS else "info")


def truncate(text: Any, limit: int = 5000) -> str:
    text = safe_str(text)

    if len(text) <= limit:
        return text

    return text[:limit] + "\n\n...[truncated]..."


def pretty_url(url: Any) -> str:
    return safe_str(url, "Endpoint not recorded")


def method_upper(method: Any) -> str:
    return safe_str(method, "GET").upper()


# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------

def database_path() -> Path:
    """
    Resolve vulnforge.db.

    Priority:
        1. VULNFORGE_DB environment variable
        2. project root / vulnforge.db
    """
    import os

    configured = os.environ.get("VULNFORGE_DB")

    if configured:
        return Path(configured).expanduser().resolve()

    return DEFAULT_DB


def connect_db() -> sqlite3.Connection:
    db = database_path()

    if not db.exists():
        raise FileNotFoundError(
            "VulnForge database not found: {}".format(db)
        )

    conn = sqlite3.connect(str(db))
    conn.row_factory = sqlite3.Row

    return conn


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    row = conn.execute(
        """
        SELECT name
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        """,
        (table,),
    ).fetchone()

    return row is not None


def get_table_columns(
    conn: sqlite3.Connection,
    table: str,
) -> List[str]:
    rows = conn.execute(
        "PRAGMA table_info({})".format(table)
    ).fetchall()

    return [row["name"] for row in rows]


def row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


# ---------------------------------------------------------------------------
# Database loading
# ---------------------------------------------------------------------------

def load_scans(
    conn: sqlite3.Connection,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    if not table_exists(conn, "scans"):
        return []

    columns = get_table_columns(conn, "scans")

    wanted = [
        "scan_id",
        "target",
        "timestamp",
        "start_time",
        "end_time",
        "fingerprint",
        "findings_count",
        "scan_duration",
        "status",
        "scan_depth",
        "templates_loaded",
        "requests_sent",
        "errors_count",
        "confirmed_count",
    ]

    available = [c for c in wanted if c in columns]

    if not available:
        return []

    query_columns = ", ".join(
        '"' + c.replace('"', '""') + '"'
        for c in available
    )

    query = """
        SELECT {columns}
        FROM scans
        ORDER BY
            COALESCE(timestamp, start_time, end_time) DESC
        LIMIT ?
    """.format(columns=query_columns)

    rows = conn.execute(query, (int(limit),)).fetchall()

    return [row_to_dict(row) for row in rows]


def load_scan(
    conn: sqlite3.Connection,
    scan_id: str,
) -> Optional[Dict[str, Any]]:
    if not table_exists(conn, "scans"):
        return None

    row = conn.execute(
        """
        SELECT *
        FROM scans
        WHERE scan_id = ?
        LIMIT 1
        """,
        (scan_id,),
    ).fetchone()

    if row is None:
        return None

    return row_to_dict(row)


def load_findings(
    conn: sqlite3.Connection,
    scan_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    if not table_exists(conn, "findings"):
        return []

    if scan_id is None:
        rows = conn.execute(
            """
            SELECT *
            FROM findings
            ORDER BY id DESC
            """
        ).fetchall()
    else:
        rows = conn.execute(
            """
            SELECT *
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,),
        ).fetchall()

    return [row_to_dict(row) for row in rows]


def load_all_findings(
    conn: sqlite3.Connection,
) -> List[Dict[str, Any]]:
    return load_findings(conn, None)


# ---------------------------------------------------------------------------
# Evidence extraction
# ---------------------------------------------------------------------------

def possible_json_sources(
    finding: Dict[str, Any],
) -> Iterable[Any]:
    """
    Return every field that might contain structured evidence.

    The important part of the dashboard fix is here.

    Old findings may store evidence in different places, so we inspect:
        evidence
        details
        extracted

    We do NOT assume one fixed data path.
    """
    for key in (
        "evidence",
        "details",
        "extracted",
    ):
        if key in finding:
            value = finding.get(key)

            if value not in (None, "", "null", "None"):
                yield value


def flatten_dicts(value: Any) -> Iterable[Dict[str, Any]]:
    """
    Recursively locate dictionaries.

    This handles evidence such as:

        {
            "method": "...",
            "request": {...},
            "response": {...}
        }

    and:

        {
            "evidence": "{...}"
        }
    """
    parsed = parse_json(value)

    if isinstance(parsed, dict):
        yield parsed

        for child in parsed.values():
            yield from flatten_dicts(child)

    elif isinstance(parsed, list):
        for child in parsed:
            yield from flatten_dicts(child)


def evidence_objects(
    finding: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """
    Extract structured evidence dictionaries from all possible locations.
    """
    objects: List[Dict[str, Any]] = []

    seen = set()

    for source in possible_json_sources(finding):
        for obj in flatten_dicts(source):
            marker = repr(sorted(obj.keys()))

            # Keep multiple objects if they have different content.
            content_marker = marker + "|" + json_dumps(obj, False)

            if content_marker in seen:
                continue

            seen.add(content_marker)
            objects.append(obj)

    return objects


def recursive_find(
    value: Any,
    keys: Iterable[str],
) -> Any:
    """
    Find the first value associated with any key recursively.
    """
    wanted = {
        str(k).lower()
        for k in keys
    }

    parsed = parse_json(value)

    if isinstance(parsed, dict):
        for key, child in parsed.items():
            if str(key).lower() in wanted:
                if child not in (None, "", []):
                    return child

        for child in parsed.values():
            result = recursive_find(child, wanted)

            if result not in (None, ""):
                return result

    elif isinstance(parsed, list):
        for child in parsed:
            result = recursive_find(child, wanted)

            if result not in (None, ""):
                return result

    return None


def extract_method(
    finding: Dict[str, Any],
    objects: List[Dict[str, Any]],
) -> str:
    value = first_nonempty(
        recursive_find(objects, ["method", "http_method"]),
        finding.get("method"),
    )

    return method_upper(value)


def extract_request_url(
    finding: Dict[str, Any],
    objects: List[Dict[str, Any]],
) -> str:
    value = first_nonempty(
        recursive_find(
            objects,
            [
                "url",
                "request_url",
                "requestUrl",
                "full_url",
                "fullUrl",
            ],
        ),
        finding.get("endpoint"),
    )

    return pretty_url(value)


def extract_affected_endpoint(
    finding: Dict[str, Any],
    objects: List[Dict[str, Any]],
) -> str:
    """
    Prefer affected_endpoints because it represents the actual endpoint
    identified by the scanner.

    Fall back to evidence URL.

    Finally fall back to finding.endpoint.
    """
    affected = recursive_find(
        objects,
        [
            "affected_endpoints",
            "affected_endpoints",
            "affectedEndpoints",
        ],
    )

    if isinstance(affected, list) and affected:
        for item in affected:
            if safe_str(item):
                return safe_str(item)

    if isinstance(affected, str):
        parsed = parse_json(affected)

        if isinstance(parsed, list) and parsed:
            return safe_str(parsed[0])

        if parsed:
            return safe_str(parsed)

    request_url = extract_request_url(finding, objects)

    if request_url and request_url != "Endpoint not recorded":
        return request_url

    return pretty_url(finding.get("endpoint"))


def extract_target(
    finding: Dict[str, Any],
    scan: Dict[str, Any],
) -> str:
    return pretty_url(
        first_nonempty(
            scan.get("target"),
            finding.get("_target"),
        )
    )


def extract_status(
    finding: Dict[str, Any],
    objects: List[Dict[str, Any]],
) -> Optional[int]:
    candidates = [
        recursive_find(
            objects,
            [
                "status",
                "status_code",
                "statusCode",
                "http_status",
                "httpStatus",
            ]
        ),
        finding.get("http_status"),
    ]

    for value in candidates:
        if value in (None, ""):
            continue

        try:
            return int(value)
        except (ValueError, TypeError):
            continue

    return None


def extract_headers(
    objects: List[Dict[str, Any]],
    names: Iterable[str],
) -> Dict[str, Any]:
    value = recursive_find(objects, names)

    if isinstance(value, dict):
        return value

    parsed = parse_json(value)

    if isinstance(parsed, dict):
        return parsed

    return {}


def extract_request_headers(
    objects: List[Dict[str, Any]],
) -> Dict[str, Any]:
    return extract_headers(
        objects,
        [
            "request_headers",
            "requestHeaders",
            "headers",
        ],
    )


def extract_response_headers(
    objects: List[Dict[str, Any]],
) -> Dict[str, Any]:
    value = recursive_find(
        objects,
        [
            "response_headers",
            "responseHeaders",
        ],
    )

    if isinstance(value, dict):
        return value

    parsed = parse_json(value)

    if isinstance(parsed, dict):
        return parsed

    return {}


def extract_request_body(
    objects: List[Dict[str, Any]],
) -> str:
    value = recursive_find(
        objects,
        [
            "request_body",
            "requestBody",
            "body",
        ],
    )

    if value is None:
        return ""

    if isinstance(value, (dict, list)):
        return json_dumps(value)

    return safe_str(value)


def extract_response_body(
    objects: List[Dict[str, Any]],
) -> str:
    value = recursive_find(
        objects,
        [
            "response_body",
            "responseBody",
            "body",
            "response",
        ],
    )

    if isinstance(value, dict):
        # Avoid accidentally treating a response metadata dictionary
        # as the response body.
        if any(
            key in value
            for key in (
                "status",
                "headers",
                "body",
            )
        ):
            nested = first_nonempty(
                value.get("body"),
                value.get("response_body"),
                value.get("responseBody"),
            )

            if nested is not None:
                return (
                    json_dumps(nested)
                    if isinstance(nested, (dict, list))
                    else safe_str(nested)
                )

        return json_dumps(value)

    if isinstance(value, list):
        return json_dumps(value)

    return safe_str(value)


def extract_payload(
    finding: Dict[str, Any],
    objects: List[Dict[str, Any]],
) -> Any:
    """
    Extract payload without dumping the entire request/response object.

    Priority:
        payload
        payload_used
        test_payload
        input
        parameter
        request body
    """
    payload = recursive_find(
        objects,
        [
            "payload",
            "payload_used",
            "payloadUsed",
            "test_payload",
            "testPayload",
            "input",
            "test_input",
            "testInput",
        ],
    )

    if payload not in (None, ""):
        return payload

    extracted = parse_json(finding.get("extracted"))

    if isinstance(extracted, dict):
        payload = first_nonempty(
            extracted.get("payload"),
            extracted.get("input"),
            extracted.get("value"),
        )

        if payload not in (None, ""):
            return payload

    return ""


def extract_match_information(
    objects: List[Dict[str, Any]],
) -> Dict[str, Any]:
    result: Dict[str, Any] = {}

    for key in (
        "matched_types",
        "matcher_total",
        "occurrences",
        "affected_endpoints",
    ):
        value = recursive_find(objects, [key])

        if value not in (None, ""):
            result[key] = value

    return result


# ---------------------------------------------------------------------------
# Human-friendly interpretation
# ---------------------------------------------------------------------------

def finding_name(finding: Dict[str, Any]) -> str:
    return safe_str(
        finding.get("name"),
        "Security Finding",
    )


def category_for(finding: Dict[str, Any]) -> str:
    category = safe_str(finding.get("category"))

    if category:
        return category

    name = finding_name(finding).lower()

    mappings = [
        ("sql", "SQL Injection"),
        ("nosql", "NoSQL Injection"),
        ("xss", "Cross-Site Scripting"),
        ("command", "OS Command Injection"),
        ("path traversal", "Path Traversal"),
        ("file upload", "File Upload"),
        ("authorization", "Access Control"),
        ("idor", "Access Control"),
        ("bola", "Access Control"),
        ("ssrf", "Server-Side Request Forgery"),
        ("cors", "CORS Misconfiguration"),
        ("csrf", "Cross-Site Request Forgery"),
    ]

    for needle, category_name in mappings:
        if needle in name:
            return category_name

    return "Web Application Security"


def beginner_meaning(
    finding: Dict[str, Any],
) -> str:
    name = finding_name(finding).lower()
    category = category_for(finding).lower()

    if "sql" in name:
        return (
            "VulnForge found signs that user-controlled input may be "
            "reaching a database query without sufficient protection."
        )

    if "nosql" in name:
        return (
            "VulnForge found signs that user-controlled input may be "
            "reaching a NoSQL database operation without sufficient "
            "validation."
        )

    if "xss" in name or "cross-site" in name:
        return (
            "VulnForge found signs that input supplied by a user may be "
            "returned to a browser without sufficient output protection."
        )

    if "command" in name:
        return (
            "VulnForge found signs that user input may be reaching an "
            "operating-system command."
        )

    if "path traversal" in name:
        return (
            "VulnForge found signs that user input may influence a file "
            "path without sufficient path validation."
        )

    if "upload" in name:
        return (
            "The file-upload endpoint may not validate uploaded files "
            "correctly."
        )

    if (
        "authorization" in name
        or "idor" in name
        or "bola" in name
        or "access control" in category
    ):
        return (
            "VulnForge found signs that the server may not properly "
            "check whether a user is allowed to access a requested object."
        )

    if "ssrf" in name:
        return (
            "VulnForge found signs that user-controlled input may influence "
            "where the server makes network requests."
        )

    if "cors" in name:
        return (
            "VulnForge found a cross-origin policy that may allow an "
            "untrusted website to interact with the application."
        )

    return (
        "VulnForge found behaviour that may indicate a security weakness "
        "and recorded supporting evidence for review."
    )


def what_can_go_wrong(
    finding: Dict[str, Any],
) -> List[str]:
    name = finding_name(finding).lower()

    if "sql" in name or "nosql" in name:
        return [
            "Attackers may influence database queries.",
            "Sensitive records may become accessible.",
            "Authentication or application logic may be bypassed.",
        ]

    if "xss" in name:
        return [
            "Untrusted content may execute in another user's browser.",
            "Account actions may be performed using a victim's session.",
            "Sensitive information displayed in the application may be exposed.",
        ]

    if "command" in name:
        return [
            "Unexpected operating-system commands may be processed.",
            "The application account may access files or services it can reach.",
            "The impact can become severe if the process has excessive privileges.",
        ]

    if "upload" in name:
        return [
            "Unwanted files may be stored on the server.",
            "Malicious content may become accessible through the application.",
            "Risk increases if uploaded files can later be executed or interpreted.",
        ]

    if "path traversal" in name:
        return [
            "Files outside the intended directory may become accessible.",
            "Application configuration or sensitive files may be exposed.",
            "The final impact depends on filesystem permissions.",
        ]

    if (
        "idor" in name
        or "bola" in name
        or "authorization" in name
    ):
        return [
            "A user may access another user's object or record.",
            "Private information may be exposed.",
            "The attacker may be able to modify data if the endpoint allows changes.",
        ]

    if "ssrf" in name:
        return [
            "The server may be tricked into making unintended requests.",
            "Internal services may become reachable through the application.",
            "Cloud or internal credentials may be at risk depending on the environment.",
        ]

    return [
        "The weakness may allow behaviour the application did not intend.",
        "The actual impact depends on server configuration and permissions.",
        "A manual security review should confirm the final impact.",
    ]


def real_world_impact(
    finding: Dict[str, Any],
) -> List[str]:
    name = finding_name(finding).lower()
    severity = normalize_severity(finding.get("severity"))

    points: List[str] = []

    if "command" in name:
        points.extend(
            [
                "A vulnerable production endpoint could allow attacker-controlled input to reach the operating system.",
                "This can become a major security issue when the application process has access to sensitive files or services.",
            ]
        )

    elif "upload" in name:
        points.extend(
            [
                "A production application could allow attackers to store files that were never intended to be accepted.",
                "Risk becomes higher when uploaded content is executable or served from an executable location.",
            ]
        )

    elif "xss" in name:
        points.extend(
            [
                "A production application could expose users to attacker-controlled browser content.",
                "The impact can include unauthorized actions or exposure of information available to the victim.",
            ]
        )

    elif "nosql" in name or "sql" in name:
        points.extend(
            [
                "A production application could expose or manipulate database-backed information.",
                "The final impact depends on the database permissions available to the application.",
            ]
        )

    elif (
        "idor" in name
        or "bola" in name
        or "authorization" in name
    ):
        points.extend(
            [
                "A production API could expose another user's records or objects.",
                "The risk is especially important when the affected data contains private or sensitive information.",
            ]
        )

    elif "path traversal" in name:
        points.extend(
            [
                "A production server could expose files outside the application's intended directory.",
                "The impact depends on filesystem permissions and which files are reachable.",
            ]
        )

    else:
        points.extend(
            [
                "The same behaviour on a production system could expose data or functionality to unauthorized users.",
                "The final impact must be confirmed against the application's actual permissions and data.",
            ]
        )

    if severity in ("critical", "high"):
        points.append(
            "Because the finding is rated {} severity, it should be reviewed before relying on the affected endpoint in production.".format(
                severity
            )
        )

    return points


def beginner_test_explanation(
    finding: Dict[str, Any],
    endpoint: str,
    method: str,
) -> str:
    name = finding_name(finding)

    return (
        "VulnForge sent a controlled test to {} {} and examined how "
        "the application responded. The goal was to determine whether "
        "{} behaves in a way that matches the security weakness detected "
        "by the scanner.".format(
            method,
            endpoint,
            name,
        )
    )


def payload_explanation(
    finding: Dict[str, Any],
    payload: Any,
) -> str:
    if payload in (None, "", {}):
        return (
            "No separate payload value was recorded. The scanner still "
            "stored the available request/evidence so the test can be "
            "reviewed."
        )

    name = finding_name(finding).lower()

    if isinstance(payload, (dict, list)):
        compact = json_dumps(payload, False)
    else:
        compact = safe_str(payload)

    compact = truncate(compact, 300)

    if "command" in name:
        return (
            "A controlled input was used to check whether the supplied "
            "value was interpreted as part of an operating-system command. "
            "Technical value: {}".format(compact)
        )

    if "upload" in name:
        return (
            "A controlled file-upload test was used to check whether the "
            "server validates the uploaded file's type and metadata. "
            "Technical value: {}".format(compact)
        )

    if "xss" in name:
        return (
            "A controlled browser-input value was used to check whether "
            "untrusted content is returned without sufficient output "
            "encoding. Technical value: {}".format(compact)
        )

    if "sql" in name or "nosql" in name:
        return (
            "A controlled database-input test was used to check whether "
            "user-controlled input changes database processing. "
            "Technical value: {}".format(compact)
        )

    return (
        "VulnForge used the recorded test value to check the behaviour "
        "associated with this finding. Technical value: {}".format(
            compact
        )
    )


# ---------------------------------------------------------------------------
# Evidence model
# ---------------------------------------------------------------------------

def build_evidence_model(
    finding: Dict[str, Any],
    scan: Dict[str, Any],
) -> Dict[str, Any]:
    objects = evidence_objects(finding)

    method = extract_method(finding, objects)
    endpoint = extract_affected_endpoint(finding, objects)
    request_url = extract_request_url(finding, objects)

    if endpoint == "Endpoint not recorded" and request_url:
        endpoint = request_url

    status = extract_status(finding, objects)

    request_headers = extract_request_headers(objects)
    response_headers = extract_response_headers(objects)

    request_body = extract_request_body(objects)
    response_body = extract_response_body(objects)

    payload = extract_payload(finding, objects)

    target = extract_target(finding, scan)

    confidence_raw = finding.get("confidence", 0)

    try:
        confidence = float(confidence_raw or 0)
    except (ValueError, TypeError):
        confidence = 0.0

    confirmed = bool(
        finding.get("confirmed")
        in (
            True,
            1,
            "1",
            "true",
            "True",
            "yes",
            "Yes",
        )
    )

    attempted = bool(
        finding.get("exploit_attempted")
        in (
            True,
            1,
            "1",
            "true",
            "True",
            "yes",
            "Yes",
        )
    )

    exploit_success = bool(
        finding.get("exploit_success")
        in (
            True,
            1,
            "1",
            "true",
            "True",
            "yes",
            "Yes",
        )
    )

    match_info = extract_match_information(objects)

    return {
        "objects": objects,
        "method": method,
        "endpoint": endpoint,
        "request_url": request_url,
        "target": target,
        "status": status,
        "request_headers": request_headers,
        "response_headers": response_headers,
        "request_body": request_body,
        "response_body": response_body,
        "payload": payload,
        "confidence": confidence,
        "confirmed": confirmed,
        "attempted": attempted,
        "exploit_success": exploit_success,
        "match_info": match_info,
    }


# ---------------------------------------------------------------------------
# HTML components
# ---------------------------------------------------------------------------

def status_badge(status: Optional[int]) -> str:
    if status is None:
        return (
            '<span class="status status-none">Not recorded</span>'
        )

    if 200 <= status < 300:
        cls = "status-good"
    elif 300 <= status < 400:
        cls = "status-redirect"
    elif 400 <= status < 500:
        cls = "status-client"
    else:
        cls = "status-server"

    return (
        '<span class="status {}">{}</span>'.format(
            cls,
            esc(status),
        )
    )


def severity_badge(severity: str) -> str:
    sev = normalize_severity(severity)
    color = SEVERITY_COLORS.get(sev, "#64748b")

    return (
        '<span class="severity-badge" style="--sev:{}">{}</span>'.format(
            color,
            esc(sev.upper()),
        )
    )


def code_block(
    content: Any,
    empty_message: str = "Not recorded",
    max_length: int = 12000,
) -> str:
    text = safe_str(content)

    if not text:
        return (
            '<div class="empty-evidence">{}</div>'.format(
                esc(empty_message)
            )
        )

    return (
        '<pre class="code-block">{}</pre>'.format(
            esc(truncate(text, max_length))
        )
    )


def headers_block(
    headers: Dict[str, Any],
) -> str:
    if not headers:
        return (
            '<div class="empty-evidence">'
            'No headers were recorded.'
            '</div>'
        )

    lines: List[str] = []

    for key in sorted(headers.keys(), key=lambda x: str(x).lower()):
        value = headers[key]

        if isinstance(value, (dict, list)):
            value_text = json_dumps(value, False)
        else:
            value_text = safe_str(value)

        lines.append(
            "{}: {}".format(
                key,
                value_text,
            )
        )

    return code_block(
        "\n".join(lines),
        "No headers were recorded.",
        8000,
    )


def list_points(points: List[str]) -> str:
    if not points:
        return '<p class="muted">No additional information recorded.</p>'

    items = []

    for point in points:
        items.append(
            "<li>{}</li>".format(
                esc(point)
            )
        )

    return "<ul>{}</ul>".format("".join(items))


def classification_grid(
    finding: Dict[str, Any],
) -> str:
    fields = [
        ("CWE", safe_str(finding.get("cwe"), "Not classified")),
        ("OWASP", safe_str(finding.get("owasp"), "Not classified")),
        ("Category", category_for(finding)),
        (
            "Template",
            safe_str(
                finding.get("template_id"),
                "Not recorded",
            ),
        ),
        (
            "Exploit attempted",
            "YES" if finding.get("exploit_attempted") else "NO",
        ),
        (
            "Exploit successful",
            "YES" if finding.get("exploit_success") else "NO",
        ),
    ]

    cards = []

    for label, value in fields:
        cards.append(
            """
            <div class="classification-item">
                <div class="classification-label">{}</div>
                <div class="classification-value">{}</div>
            </div>
            """.format(
                esc(label),
                esc(value),
            )
        )

    return "".join(cards)


def request_response_panel(
    evidence: Dict[str, Any],
) -> str:
    status = evidence["status"]

    request_body = evidence["request_body"]

    if not request_body and evidence["payload"] not in ("", None, {}):
        payload = evidence["payload"]

        if isinstance(payload, (dict, list)):
            request_body = json_dumps(payload)
        else:
            request_body = safe_str(payload)

    request_summary = (
        "{} {}".format(
            evidence["method"],
            evidence["request_url"]
            if evidence["request_url"] != "Endpoint not recorded"
            else evidence["endpoint"],
        )
    )

    response_summary = (
        "HTTP {}".format(status)
        if status is not None
        else "HTTP status not recorded"
    )

    return """
    <div class="request-response">
        <div class="rr-column request-column">
            <div class="rr-header">
                <span>REQUEST</span>
                <small>{}</small>
            </div>

            <div class="rr-summary">{}</div>

            <div class="mini-title">Request headers</div>
            {}

            <div class="mini-title">Request body</div>
            {}

            <div class="mini-title">Payload / test input</div>
            {}

            <div class="interpretation request-meaning">
                <strong>What is this?</strong>
                <p>
                    This is the information VulnForge sent to the application.
                    It shows the HTTP method, endpoint, headers and test input
                    used during the security check.
                </p>
            </div>
        </div>

        <div class="rr-column response-column">
            <div class="rr-header">
                <span>RESPONSE</span>
                <small>{}</small>
            </div>

            <div class="rr-summary">{}</div>

            <div class="mini-title">Response headers</div>
            {}

            <div class="mini-title">Response body</div>
            {}

            <div class="interpretation response-meaning">
                <strong>What is this?</strong>
                <p>
                    This is what the server returned after receiving the
                    request. VulnForge uses this information as evidence
                    when deciding whether the tested behaviour is suspicious.
                </p>
            </div>
        </div>
    </div>
    """.format(
        esc(evidence["method"]),
        esc(request_summary),
        headers_block(evidence["request_headers"]),
        code_block(
            request_body,
            "No request body was recorded.",
        ),
        code_block(
            evidence["payload"],
            "No separate payload was recorded.",
        ),
        status_badge(status),
        esc(response_summary),
        headers_block(evidence["response_headers"]),
        code_block(
            evidence["response_body"],
            "No response body was recorded.",
        ),
    )


def technical_evidence_panel(
    finding: Dict[str, Any],
    evidence: Dict[str, Any],
) -> str:
    raw = {
        "finding": {
            "id": finding.get("id"),
            "name": finding.get("name"),
            "severity": finding.get("severity"),
            "template_id": finding.get("template_id"),
        },
        "request": {
            "method": evidence["method"],
            "url": evidence["request_url"],
            "headers": evidence["request_headers"],
            "body": evidence["request_body"],
        },
        "response": {
            "status": evidence["status"],
            "headers": evidence["response_headers"],
            "body": evidence["response_body"],
        },
        "payload": evidence["payload"],
        "match_information": evidence["match_info"],
    }

    return """
    <details class="technical-details">
        <summary>
            Advanced technical evidence
            <span>For developers and security researchers</span>
        </summary>

        <div class="technical-warning">
            This section contains the raw evidence recorded by VulnForge.
            It is intentionally separated from the beginner-friendly
            explanation above.
        </div>

        <pre class="code-block raw-evidence">{}</pre>
    </details>
    """.format(
        esc(json_dumps(raw))
    )


def finding_card(
    finding: Dict[str, Any],
    scan: Dict[str, Any],
) -> str:
    evidence = build_evidence_model(finding, scan)

    severity = normalize_severity(
        finding.get("severity")
    )

    name = finding_name(finding)

    endpoint = evidence["endpoint"]

    confidence = evidence["confidence"]

    if confidence <= 1:
        confidence_percent = confidence * 100
    else:
        confidence_percent = confidence

    meaning = beginner_meaning(finding)

    wrong = what_can_go_wrong(finding)

    impact = real_world_impact(finding)

    how = beginner_test_explanation(
        finding,
        endpoint,
        evidence["method"],
    )

    payload_text = payload_explanation(
        finding,
        evidence["payload"],
    )

    recommendation = safe_str(
        finding.get("remediation"),
        "Review the affected endpoint, apply the appropriate server-side security control, and retest the endpoint.",
    )

    confirmed_text = (
        "Confirmed"
        if evidence["confirmed"]
        else "Unconfirmed"
    )

    status_text = (
        "HTTP {}".format(evidence["status"])
        if evidence["status"] is not None
        else "HTTP status not recorded"
    )

    scan_id = safe_str(
        scan.get("scan_id"),
        safe_str(finding.get("scan_id"), "unknown"),
    )

    finding_id = safe_str(
        finding.get("id"),
        "Not recorded",
    )

    return """
    <article
        class="finding-card"
        data-severity="{severity}"
        data-confirmed="{confirmed}"
        data-search="{search}"
    >
        <div class="finding-header">
            <div class="finding-main">
                <div class="finding-topline">
                    {severity_badge}
                    <span class="finding-status">{confirmed_text}</span>
                </div>

                <h3>{name}</h3>

                <div class="finding-endpoint">
                    <strong>{method}</strong>
                    <code>{endpoint}</code>
                </div>

                <div class="finding-meta">
                    <span>Scan: <code>{scan_id}</code></span>
                    <span>Finding ID: <code>{finding_id}</code></span>
                    <span>{status_badge}</span>
                    <span>{confidence:.0f}% confidence</span>
                </div>
            </div>

            <div class="finding-score">
                <div>{confidence:.0f}%</div>
                <small>confidence</small>
            </div>
        </div>

        <section class="meaning-section">
            <div class="section-kicker">What does this mean?</div>

            <p class="lead">
                {meaning}
            </p>

            <div class="endpoint-highlight">
                <div>
                    <span class="label">Actual endpoint tested</span>
                    <strong>{method}</strong>
                    <code>{endpoint}</code>
                </div>

                <div>
                    <span class="label">Target</span>
                    <code>{target}</code>
                </div>

                <div>
                    <span class="label">HTTP status</span>
                    {status_badge}
                </div>
            </div>
        </section>

        <section>
            <div class="section-kicker">Test input used</div>

            <p>{payload_explanation}</p>

            <details class="technical-input">
                <summary>Show technical test value</summary>
                {payload_block}
            </details>
        </section>

        <section>
            <div class="section-kicker">
                Request &amp; response
            </div>

            {request_response}
        </section>

        <section class="explanation-section">
            <div class="explanation-grid">
                <div class="explanation-card">
                    <h4>What is this?</h4>
                    <p>
                        The request is what VulnForge sent.
                        The response is what the server returned.
                        Together they form the main evidence for this finding.
                    </p>
                </div>

                <div class="explanation-card warning">
                    <h4>What can go wrong?</h4>
                    {wrong}
                </div>

                <div class="explanation-card">
                    <h4>What did VulnForge test?</h4>
                    <p>{how}</p>
                </div>

                <div class="explanation-card impact">
                    <h4>Real-world impact</h4>
                    {impact}
                </div>
            </div>
        </section>

        <section class="remediation-section">
            <div class="section-kicker">
                Recommended protection
            </div>

            <div class="remediation">
                <p>{recommendation}</p>
            </div>
        </section>

        <section class="classification-section">
            <div class="section-kicker">
                Security classification
            </div>

            <div class="classification-grid">
                {classification}
            </div>
        </section>

        <section class="verification-section">
            <div class="section-kicker">
                Remediation verification
            </div>

            <div class="before-after">
                <div class="before-box">
                    <h4>Before modification</h4>

                    <p>
                        This is the evidence recorded by the current scan.
                        It shows the exact request and response that caused
                        VulnForge to create the finding.
                    </p>

                    <div class="verify-line">
                        <strong>Endpoint</strong>
                        <code>{endpoint}</code>
                    </div>

                    <div class="verify-line">
                        <strong>Payload / test input</strong>
                        <span>{payload_summary}</span>
                    </div>

                    <div class="verify-line">
                        <strong>HTTP status</strong>
                        {status_badge}
                    </div>
                </div>

                <div class="after-box">
                    <h4>After modification</h4>

                    <p>
                        Run VulnForge against the same endpoint again after
                        applying the fix. The new scan should record a new
                        request and response here instead of reusing old
                        evidence.
                    </p>

                    <div class="after-checklist">
                        <div>✓ Send the same controlled security test</div>
                        <div>✓ Record the new HTTP status</div>
                        <div>✓ Record the new response</div>
                        <div>✓ Compare the result with this finding</div>
                        <div>✓ Mark the weakness resolved only when the new evidence supports it</div>
                    </div>

                    <div class="after-note">
                        No after-fix evidence is fabricated by the dashboard.
                        A new scan is required to prove the fix.
                    </div>
                </div>
            </div>
        </section>

        {technical_evidence}
    </article>
    """.format(
        severity=esc(severity),
        confirmed="1" if evidence["confirmed"] else "0",
        search=esc(
            "{} {} {} {}".format(
                name,
                endpoint,
                category_for(finding),
                finding.get("template_id", ""),
            ).lower()
        ),
        severity_badge=severity_badge(severity),
        confirmed_text=esc(confirmed_text),
        name=esc(name),
        method=esc(evidence["method"]),
        endpoint=esc(endpoint),
        scan_id=esc(scan_id),
        finding_id=esc(finding_id),
        status_badge=status_badge(evidence["status"]),
        confidence=confidence_percent,
        meaning=esc(meaning),
        target=esc(evidence["target"]),
        payload_explanation=esc(payload_text),
        payload_block=code_block(
            evidence["payload"],
            "No separate technical payload was recorded.",
        ),
        request_response=request_response_panel(evidence),
        wrong=list_points(wrong),
        how=esc(how),
        impact=list_points(impact),
        recommendation=esc(recommendation),
        classification=classification_grid(finding),
        payload_summary=esc(
            truncate(
                evidence["payload"]
                if evidence["payload"] not in ("", None)
                else "No separate payload recorded",
                400,
            )
        ),
        technical_evidence=technical_evidence_panel(
            finding,
            evidence,
        ),
        status_text=esc(status_text),
    )


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

def calculate_statistics(
    scans: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
) -> Dict[str, Any]:
    total_scans = len(scans)
    total_findings = len(findings)

    targets = set()

    for scan in scans:
        target = safe_str(scan.get("target"))

        if target:
            targets.add(target)

    for finding in findings:
        target = safe_str(finding.get("_target"))

        if target:
            targets.add(target)

    severity_counts = {
        sev: 0
        for sev in SEVERITY_ORDER
    }

    confirmed = 0

    for finding in findings:
        sev = normalize_severity(
            finding.get("severity")
        )

        severity_counts[sev] = (
            severity_counts.get(sev, 0) + 1
        )

        if finding.get("confirmed"):
            confirmed += 1

    durations = []

    for scan in scans:
        try:
            value = float(
                scan.get("scan_duration") or 0
            )

            if value > 0:
                durations.append(value)

        except (ValueError, TypeError):
            pass

    avg_findings = (
        total_findings / total_scans
        if total_scans
        else 0
    )

    return {
        "total_scans": total_scans,
        "total_findings": total_findings,
        "unique_targets": len(targets),
        "confirmed_findings": confirmed,
        "avg_findings_per_scan": avg_findings,
        "severity_counts": severity_counts,
        "avg_duration": (
            sum(durations) / len(durations)
            if durations
            else 0
        ),
    }


def severity_cards(
    counts: Dict[str, int],
) -> str:
    cards = []

    for severity in SEVERITY_ORDER:
        cards.append(
            """
            <button
                type="button"
                class="severity-card severity-{}"
                data-severity-card="{}"
                onclick="filterSeverity('{}')"
                title="Show {} findings"
            >
                <div class="severity-number">{}</div>
                <div class="severity-name">{}</div>
                <div class="severity-click-hint">Click to filter</div>
            </button>
            """.format(
                esc(severity),
                esc(severity),
                esc(severity),
                esc(severity.upper()),
                counts.get(severity, 0),
                esc(severity.upper()),
            )
        )

    return "".join(cards)


# ---------------------------------------------------------------------------
# Scan table
# ---------------------------------------------------------------------------

def scan_rows(
    scans: List[Dict[str, Any]],
) -> str:
    if not scans:
        return """
        <tr>
            <td colspan="8" class="empty-table">
                No scans recorded yet.
            </td>
        </tr>
        """

    rows = []

    for scan in scans:
        scan_id = safe_str(
            scan.get("scan_id"),
            "unknown",
        )

        target = safe_str(
            scan.get("target"),
            "Unknown target",
        )

        status = safe_str(
            scan.get("status"),
            "unknown",
        )

        findings = scan.get("findings_count", 0)

        requests = scan.get("requests_sent", 0)

        try:
            duration = float(
                scan.get("scan_duration") or 0
            )
        except (ValueError, TypeError):
            duration = 0

        timestamp = safe_str(
            scan.get("timestamp"),
            scan.get("start_time"),
        )

        rows.append(
            """
            <tr class="scan-row">
                <td>
                    <code>{}</code>
                </td>

                <td class="target-cell">
                    {}
                </td>

                <td>
                    <span class="scan-status">{}</span>
                </td>

                <td>
                    <strong>{}</strong>
                </td>

                <td>{}</td>

                <td>{:.2f}s</td>

                <td>{}</td>

                <td>
                    <a
                        class="open-report"
                        href="vulnforge_reports/scan_{}.html"
                    >
                        Open report
                    </a>
                </td>
            </tr>
            """.format(
                esc(scan_id),
                esc(target),
                esc(status),
                esc(findings),
                esc(requests),
                duration,
                esc(timestamp),
                esc(re.sub(r"[^A-Za-z0-9_.-]", "_", scan_id)),
            )
        )

    return "".join(rows)


# ---------------------------------------------------------------------------
# Dashboard CSS
# ---------------------------------------------------------------------------

CSS = r"""
:root {
    color-scheme: dark;
    --bg: #080d17;
    --panel: #0f1726;
    --panel-2: #111c2d;
    --border: #223047;
    --text: #e5edf7;
    --muted: #8fa1b8;
    --blue: #38bdf8;
    --green: #22c55e;
    --red: #ef4444;
    --orange: #f97316;
    --yellow: #eab308;
}

* {
    box-sizing: border-box;
}

html {
    scroll-behavior: smooth;
}

body {
    margin: 0;
    background:
        radial-gradient(
            circle at top right,
            rgba(56,189,248,.08),
            transparent 30%
        ),
        var(--bg);
    color: var(--text);
    font-family:
        Inter,
        ui-sans-serif,
        system-ui,
        -apple-system,
        BlinkMacSystemFont,
        "Segoe UI",
        sans-serif;
}

a {
    color: var(--blue);
}

code,
pre {
    font-family:
        "JetBrains Mono",
        "Fira Code",
        Consolas,
        monospace;
}

code {
    background: #09111f;
    border: 1px solid #1b2a40;
    border-radius: 5px;
    padding: 2px 5px;
    word-break: break-all;
}

.container {
    width: min(1500px, calc(100% - 40px));
    margin: 0 auto;
}

.header {
    padding: 34px 0 24px;
}

.header-top {
    display: flex;
    justify-content: space-between;
    gap: 20px;
    align-items: flex-start;
}

.brand {
    display: flex;
    gap: 14px;
    align-items: center;
}

.logo {
    width: 46px;
    height: 46px;
    border-radius: 12px;
    display: grid;
    place-items: center;
    background: linear-gradient(135deg,#38bdf8,#2563eb);
    color: #03101b;
    font-weight: 900;
    box-shadow: 0 0 30px rgba(56,189,248,.18);
}

h1 {
    margin: 0;
    font-size: 29px;
    letter-spacing: -.04em;
}

.subtitle {
    margin-top: 6px;
    color: var(--muted);
    font-size: 13px;
}

.generated {
    color: #6f8198;
    font-size: 12px;
    margin-top: 5px;
}

.header-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 12px;
    flex-wrap: wrap;
}

.pdf-download {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    padding: 10px 15px;
    border-radius: 10px;
    border: 1px solid var(--blue);
    background: rgba(56,189,248,.10);
    color: var(--text);
    text-decoration: none;
    font-weight: 700;
    font-size: 13px;
    transition: transform .18s ease, background .18s ease;
}

.pdf-download:hover {
    background: rgba(56,189,248,.18);
    transform: translateY(-2px);
}

.database-pill {
    border: 1px solid var(--border);
    background: rgba(15,23,38,.75);
    border-radius: 9px;
    padding: 9px 12px;
    color: var(--muted);
    font-size: 12px;
}

.stats {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(180px, 1fr));
    gap: 13px;
    margin-bottom: 24px;
}

.stat {
    background: linear-gradient(180deg,#111c2d,#0c1421);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 18px;
}

.stat-number {
    font-size: 30px;
    font-weight: 800;
    letter-spacing: -.04em;
}

.stat-label {
    color: var(--muted);
    font-size: 12px;
    text-transform: uppercase;
    letter-spacing: .06em;
    margin-top: 4px;
}

.severity-grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(145px, 1fr));
    gap: 10px;
    margin-bottom: 30px;
}

.severity-card {
    appearance: none;
    -webkit-appearance: none;
    position: relative;
    overflow: hidden;
    width: 100%;
    text-align: left;
    cursor: pointer;
    font: inherit;
    color: var(--text);

    border: 1px solid var(--border);
    border-left: 4px solid var(--sev);

    background:
        linear-gradient(
            135deg,
            var(--sev-bg),
            var(--panel)
        );

    transition:
        transform .18s ease,
        border-color .18s ease,
        box-shadow .18s ease;
}

.severity-card:hover {
    transform: translateY(-3px);
    border-color: var(--sev);
    box-shadow:
        0 0 0 1px var(--sev),
        0 10px 30px rgba(0,0,0,.25);
}

.severity-card:focus-visible {
    outline: 2px solid var(--sev);
    outline-offset: 3px;
}

.severity-card .severity-number {
    color: var(--sev);
}

.severity-card .severity-name {
    color: var(--sev);
}

.severity-click-hint {
    margin-top: 8px;
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .08em;
}

/* Severity-specific colors */

.severity-critical {
    --sev: #ef4444;
    --sev-bg: rgba(239, 68, 68, .12);
}

.severity-high {
    --sev: #f97316;
    --sev-bg: rgba(249, 115, 22, .12);
}

.severity-medium {
    --sev: #eab308;
    --sev-bg: rgba(234, 179, 8, .12);
}

.severity-low {
    --sev: #22c55e;
    --sev-bg: rgba(34, 197, 94, .12);
}

.severity-info {
    --sev: #64748b;
    --sev-bg: rgba(100, 116, 139, .12);
}


.severity-card:hover {
    transform: translateY(-3px);
    border-color: var(--sev);
    box-shadow: 0 0 0 1px var(--sev);
}

.severity-card:focus-visible {
    outline: 2px solid var(--blue);
    outline-offset: 3px;
}

.severity-click-hint {
    margin-top: 8px;
    font-size: 11px;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .08em;
}



.severity-card-existing .severity-number {
    color: var(--sev);
}

.severity-card-existing .severity-name {
    color: var(--sev);
}

.severity-card-existing::before {
    content: "";
    position: absolute;
    inset: 0;
    pointer-events: none;
    background:
        linear-gradient(
            135deg,
            color-mix(
                in srgb,
                var(--sev) 7%,
                transparent
            ),
            transparent 55%
        );
}

.severity-card-existing:hover {
    border-color: var(--sev);
    box-shadow:
        0 0 0 1px var(--sev),
        0 10px 30px rgba(0, 0, 0, .25);
}

/* Explicit severity colors */

.severity-critical {
    --sev: #ef4444;
}

.severity-high {
    --sev: #f97316;
}

.severity-medium {
    --sev: #eab308;
}

.severity-low {
    --sev: #22c55e;
}

.severity-info {
    --sev: #64748b;
}

    border: 1px solid var(--border);
    background: var(--panel);
    border-radius: 10px;
    padding: 14px;
    border-left: 4px solid var(--sev);
}

.severity-critical { --sev: #ef4444; }
.severity-high { --sev: #f97316; }
.severity-medium { --sev: #eab308; }
.severity-low { --sev: #22c55e; }
.severity-info { --sev: #64748b; }

.severity-number {
    font-size: 25px;
    font-weight: 800;
}

.severity-name {
    color: var(--muted);
    font-size: 11px;
    letter-spacing: .06em;
    margin-top: 3px;
}

.section {
    margin: 32px 0;
}

.section-title {
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
    gap: 15px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 10px;
    margin-bottom: 14px;
}

.section-title h2 {
    margin: 0;
    font-size: 17px;
}

.section-title p {
    margin: 4px 0 0;
    color: var(--muted);
    font-size: 12px;
}

.scan-table-wrap {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 12px;
}

table {
    width: 100%;
    border-collapse: collapse;
    min-width: 900px;
}

th {
    color: var(--muted);
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .06em;
    padding: 12px;
    border-bottom: 1px solid var(--border);
    background: #0c1524;
}

td {
    padding: 12px;
    border-bottom: 1px solid #18263a;
    font-size: 12px;
}

tr:last-child td {
    border-bottom: 0;
}

.scan-row:hover {
    background: #111d2f;
}

.target-cell {
    max-width: 360px;
    word-break: break-all;
}

.scan-status {
    border: 1px solid #24543a;
    background: #0d2519;
    color: #6ee7a0;
    border-radius: 999px;
    padding: 3px 8px;
    font-size: 10px;
}

.open-report {
    text-decoration: none;
    font-weight: 700;
}

.clear-filter {
    border: 1px solid var(--border);
    background: var(--panel-2);
    color: var(--text);
    padding: 9px 13px;
    border-radius: 9px;
    cursor: pointer;
    font: inherit;
    font-size: 13px;
}

.clear-filter:hover {
    border-color: var(--blue);
}

.controls {
    display: flex;
    gap: 9px;
    flex-wrap: wrap;
    align-items: center;
    margin-bottom: 15px;
}

.controls input,
.controls select {
    background: #0d1727;
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 8px;
    padding: 9px 11px;
    font-size: 12px;
}

.controls input {
    min-width: 280px;
}

.checkbox {
    color: var(--muted);
    font-size: 12px;
    display: flex;
    gap: 7px;
    align-items: center;
}

.findings {
    display: grid;
    gap: 15px;
}

.finding-card {
    background:
        linear-gradient(
            180deg,
            rgba(17,28,45,.98),
            rgba(10,18,30,.98)
        );
    border: 1px solid var(--border);
    border-radius: 14px;
    overflow: hidden;
    box-shadow: 0 8px 30px rgba(0,0,0,.15);
}

.finding-header {
    display: flex;
    justify-content: space-between;
    gap: 18px;
    padding: 20px;
    border-bottom: 1px solid var(--border);
}

.finding-topline {
    display: flex;
    gap: 8px;
    align-items: center;
    margin-bottom: 9px;
}

.severity-badge {
    --sev: #64748b;
    background: var(--sev);
    color: #fff;
    font-weight: 900;
    font-size: 10px;
    letter-spacing: .06em;
    padding: 4px 8px;
    border-radius: 5px;
}

.finding-status {
    color: #94a3b8;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .04em;
}

.finding-main h3 {
    margin: 0 0 10px;
    font-size: 19px;
}

.finding-endpoint {
    display: flex;
    gap: 7px;
    align-items: center;
    flex-wrap: wrap;
}

.finding-endpoint strong {
    color: var(--blue);
    font-size: 12px;
}

.finding-meta {
    display: flex;
    gap: 9px;
    flex-wrap: wrap;
    color: var(--muted);
    font-size: 11px;
    margin-top: 11px;
}

.finding-score {
    min-width: 80px;
    text-align: center;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 10px;
    height: max-content;
    background: #0b1422;
}

.finding-score div {
    font-size: 24px;
    font-weight: 800;
    color: var(--blue);
}

.finding-score small {
    color: var(--muted);
    font-size: 10px;
}

.status {
    display: inline-block;
    border-radius: 5px;
    padding: 3px 7px;
    font-size: 10px;
    font-weight: 800;
}

.status-good {
    color: #86efac;
    background: #0c2618;
    border: 1px solid #1f5a37;
}

.status-redirect {
    color: #fde68a;
    background: #2a220b;
    border: 1px solid #665316;
}

.status-client {
    color: #fdba74;
    background: #2a170b;
    border: 1px solid #6b3213;
}

.status-server {
    color: #fca5a5;
    background: #2b1010;
    border: 1px solid #6b1d1d;
}

.status-none {
    color: #94a3b8;
    background: #111827;
    border: 1px solid var(--border);
}

.meaning-section,
.finding-card > section {
    padding: 20px;
}

.section-kicker {
    color: #7dd3fc;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: .08em;
    text-transform: uppercase;
    margin-bottom: 9px;
}

.lead {
    color: #dbeafe;
    font-size: 15px;
    line-height: 1.65;
    margin: 0 0 16px;
}

.endpoint-highlight {
    display: grid;
    grid-template-columns:
        minmax(0, 2fr)
        minmax(0, 1fr)
        minmax(130px, .5fr);
    gap: 10px;
}

.endpoint-highlight > div {
    background: #0b1422;
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 12px;
}

.endpoint-highlight .label {
    display: block;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: .05em;
    font-size: 9px;
    margin-bottom: 6px;
}

.endpoint-highlight strong {
    color: var(--blue);
    margin-right: 6px;
}

.request-response {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 14px;
}

.rr-column {
    border: 1px solid var(--border);
    border-radius: 11px;
    background: #091321;
    overflow: hidden;
}

.request-column {
    border-top: 3px solid #38bdf8;
}

.response-column {
    border-top: 3px solid #22c55e;
}

.rr-header {
    display: flex;
    justify-content: space-between;
    padding: 12px 14px;
    background: #0d1828;
    border-bottom: 1px solid var(--border);
    font-weight: 900;
    font-size: 11px;
    letter-spacing: .07em;
}

.rr-header small {
    color: var(--muted);
    font-weight: 500;
}

.rr-summary {
    padding: 12px 14px;
    border-bottom: 1px solid #17253a;
    color: #dbeafe;
    font-size: 12px;
    word-break: break-all;
}

.mini-title {
    padding: 10px 14px 5px;
    color: var(--muted);
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: .06em;
}

.code-block {
    margin: 0 14px 14px;
    padding: 12px;
    background: #050a12;
    border: 1px solid #18263a;
    border-radius: 8px;
    white-space: pre-wrap;
    overflow: auto;
    max-height: 350px;
    color: #c9d8ea;
    font-size: 11px;
    line-height: 1.5;
    word-break: break-word;
}

.interpretation {
    margin: 14px;
    border-radius: 8px;
    padding: 12px;
    background: #0c1726;
    border: 1px solid #1c3048;
}

.interpretation strong {
    color: #bae6fd;
    font-size: 12px;
}

.interpretation p {
    margin: 5px 0 0;
    color: var(--muted);
    line-height: 1.5;
    font-size: 12px;
}

.explanation-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
}

.explanation-card {
    background: #0b1422;
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 15px;
}

.explanation-card.warning {
    border-left: 3px solid #f97316;
}

.explanation-card.impact {
    border-left: 3px solid #ef4444;
}

.explanation-card h4 {
    margin: 0 0 7px;
    font-size: 13px;
}

.explanation-card p,
.explanation-card li {
    color: #b8c7da;
    font-size: 12px;
    line-height: 1.55;
}

.explanation-card ul {
    margin: 0;
    padding-left: 18px;
}

.remediation {
    background: #0b1d16;
    border: 1px solid #194c35;
    border-left: 3px solid #22c55e;
    border-radius: 9px;
    padding: 14px;
}

.remediation p {
    margin: 0;
    color: #c7f9d8;
    font-size: 13px;
    line-height: 1.55;
}

.classification-grid {
    display: grid;
    grid-template-columns:
        repeat(auto-fit, minmax(170px, 1fr));
    gap: 9px;
}

.classification-item {
    background: #0b1422;
    border: 1px solid var(--border);
    border-radius: 9px;
    padding: 12px;
}

.classification-label {
    color: var(--muted);
    text-transform: uppercase;
    font-size: 9px;
    letter-spacing: .06em;
}

.classification-value {
    margin-top: 6px;
    font-weight: 700;
    font-size: 12px;
    word-break: break-word;
}

.before-after {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 13px;
}

.before-box,
.after-box {
    border-radius: 10px;
    padding: 16px;
    border: 1px solid var(--border);
    background: #0b1422;
}

.before-box {
    border-top: 3px solid #ef4444;
}

.after-box {
    border-top: 3px solid #22c55e;
}

.before-box h4,
.after-box h4 {
    margin: 0 0 8px;
}

.before-box p,
.after-box p {
    color: var(--muted);
    font-size: 12px;
    line-height: 1.55;
}

.verify-line {
    margin-top: 9px;
    padding: 9px;
    border: 1px solid #1b2a40;
    border-radius: 7px;
    background: #08111e;
    font-size: 11px;
}

.verify-line strong {
    display: block;
    color: #94a3b8;
    margin-bottom: 4px;
}

.after-checklist {
    display: grid;
    gap: 7px;
    color: #bbf7d0;
    font-size: 11px;
}

.after-note {
    margin-top: 13px;
    padding: 10px;
    border-radius: 7px;
    background: #17200d;
    border: 1px solid #3f4f18;
    color: #d9f99d;
    font-size: 11px;
    line-height: 1.5;
}

.technical-details {
    margin: 0 20px 20px;
    border: 1px solid #26374e;
    border-radius: 10px;
    background: #080e17;
}

.technical-details summary {
    cursor: pointer;
    padding: 13px 15px;
    font-weight: 800;
    color: #cbd5e1;
    font-size: 12px;
}

.technical-details summary span {
    color: #64748b;
    font-weight: 500;
    margin-left: 8px;
}

.technical-warning {
    padding: 11px 15px;
    border-top: 1px solid #18263a;
    border-bottom: 1px solid #18263a;
    color: #94a3b8;
    font-size: 11px;
}

.raw-evidence {
    margin: 15px;
    max-height: 500px;
}

.technical-input {
    margin-top: 10px;
}

.technical-input summary {
    color: var(--muted);
    cursor: pointer;
    font-size: 11px;
}

.empty-evidence {
    margin: 0 14px 14px;
    padding: 11px;
    border: 1px dashed #26374e;
    border-radius: 7px;
    color: #64748b;
    font-size: 11px;
}

.muted {
    color: var(--muted);
}

.empty-table {
    text-align: center;
    color: var(--muted);
    padding: 25px;
}

.footer {
    margin: 50px 0 30px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    color: #64748b;
    font-size: 11px;
}

@media (max-width: 900px) {
    .request-response,
    .explanation-grid,
    .before-after {
        grid-template-columns: 1fr;
    }

    .endpoint-highlight {
        grid-template-columns: 1fr;
    }

    .header-top {
        flex-direction: column;
    }
}

@media (max-width: 650px) {
    .container {
        width: min(100% - 20px, 1500px);
    }

    .finding-header {
        flex-direction: column;
    }

    .finding-score {
        width: 100%;
    }

    .controls input {
        width: 100%;
        min-width: 0;
    }
}


/* ============================================================
   VULNFORGE SEVERITY CARD OVERRIDES
   Added safely without replacing existing dashboard CSS.
   ============================================================ */

.severity-grid {
    display: grid !important;
    grid-template-columns: repeat(
        auto-fit,
        minmax(180px, 1fr)
    ) !important;
    gap: 16px !important;
}

.severity-card {
    position: relative !important;
    display: block !important;
    width: 100% !important;
    min-height: 145px !important;

    padding: 20px !important;

    border: 2px solid var(--vf-severity-color) !important;
    border-radius: 16px !important;

    background:
        linear-gradient(
            145deg,
            var(--vf-severity-bg),
            rgba(15, 23, 42, 0.96)
        ) !important;

    color: #ffffff !important;
    text-align: left !important;

    cursor: pointer !important;

    box-shadow:
        0 8px 24px rgba(0, 0, 0, 0.25),
        0 0 12px var(--vf-severity-glow) !important;

    transition:
        transform 0.18s ease,
        box-shadow 0.18s ease,
        border-color 0.18s ease !important;
}

.severity-card:hover {
    transform: translateY(-4px) !important;

    border-color: var(--vf-severity-color) !important;

    box-shadow:
        0 14px 35px rgba(0, 0, 0, 0.35),
        0 0 25px var(--vf-severity-glow) !important;
}

.severity-card:focus {
    outline: 2px solid var(--vf-severity-color) !important;
    outline-offset: 3px !important;
}

.severity-card::before {
    content: "" !important;

    position: absolute !important;
    left: 0 !important;
    top: 0 !important;
    bottom: 0 !important;

    width: 5px !important;

    border-radius: 16px 0 0 16px !important;

    background: var(--vf-severity-color) !important;
}

.severity-card-top {
    display: flex !important;
    align-items: center !important;
    gap: 9px !important;
}

.severity-icon {
    display: inline-flex !important;

    align-items: center !important;
    justify-content: center !important;

    width: 30px !important;
    height: 30px !important;

    border-radius: 8px !important;

    color: var(--vf-severity-color) !important;

    background:
        var(--vf-severity-bg-strong) !important;

    font-size: 14px !important;
    font-weight: 900 !important;
}

.severity-card .severity-name {
    color: var(--vf-severity-color) !important;

    font-size: 13px !important;
    font-weight: 900 !important;

    letter-spacing: 0.08em !important;
}

.severity-card .severity-number {
    margin-top: 13px !important;

    color: #ffffff !important;

    font-size: 38px !important;
    line-height: 1 !important;
    font-weight: 900 !important;
}

.severity-filter-hint {
    margin-top: 13px !important;

    color: #94a3b8 !important;

    font-size: 12px !important;
    font-weight: 600 !important;
}

/* CRITICAL */

.severity-card.severity-critical {
    --vf-severity-color: #ef4444;
    --vf-severity-bg: rgba(239, 68, 68, 0.13);
    --vf-severity-bg-strong: rgba(239, 68, 68, 0.22);
    --vf-severity-glow: rgba(239, 68, 68, 0.30);
}

/* HIGH */

.severity-card.severity-high {
    --vf-severity-color: #f97316;
    --vf-severity-bg: rgba(249, 115, 22, 0.13);
    --vf-severity-bg-strong: rgba(249, 115, 22, 0.22);
    --vf-severity-glow: rgba(249, 115, 22, 0.30);
}

/* MEDIUM */

.severity-card.severity-medium {
    --vf-severity-color: #eab308;
    --vf-severity-bg: rgba(234, 179, 8, 0.13);
    --vf-severity-bg-strong: rgba(234, 179, 8, 0.22);
    --vf-severity-glow: rgba(234, 179, 8, 0.30);
}

/* LOW */

.severity-card.severity-low {
    --vf-severity-color: #22c55e;
    --vf-severity-bg: rgba(34, 197, 94, 0.13);
    --vf-severity-bg-strong: rgba(34, 197, 94, 0.22);
    --vf-severity-glow: rgba(34, 197, 94, 0.30);
}

/* INFO */

.severity-card.severity-info {
    --vf-severity-color: #38bdf8;
    --vf-severity-bg: rgba(56, 189, 248, 0.13);
    --vf-severity-bg-strong: rgba(56, 189, 248, 0.22);
    --vf-severity-glow: rgba(56, 189, 248, 0.30);
}

/* ============================================================
   END SEVERITY OVERRIDES
   ============================================================ */

"""


# ---------------------------------------------------------------------------
# JavaScript
# ---------------------------------------------------------------------------

JAVASCRIPT = r"""
(function () {
    const search = document.getElementById("findingSearch");
    const severity = document.getElementById("severityFilter");
    const confirmed = document.getElementById("confirmedFilter");
    const cards = Array.from(
        document.querySelectorAll(".finding-card")
    );

    function applyFilters() {
        const query = (search.value || "").toLowerCase().trim();
        const selectedSeverity = severity.value;
        const confirmedOnly = confirmed.checked;

        let visible = 0;

        cards.forEach(function (card) {
            const text = (
                card.dataset.search || ""
            ).toLowerCase();

            const cardSeverity =
                card.dataset.severity || "";

            const isConfirmed =
                card.dataset.confirmed === "1";

            const matchesSearch =
                !query || text.includes(query);

            const matchesSeverity =
                !selectedSeverity ||
                cardSeverity === selectedSeverity;

            const matchesConfirmed =
                !confirmedOnly || isConfirmed;

            const show =
                matchesSearch &&
                matchesSeverity &&
                matchesConfirmed;

            card.style.display =
                show ? "" : "none";

            if (show) {
                visible++;
            }
        });

        const counter =
            document.getElementById("visibleCount");

        if (counter) {
            counter.textContent =
                String(visible);
        }
    }

    if (search) {
        search.addEventListener(
            "input",
            applyFilters
        );
    }

    if (severity) {
        severity.addEventListener(
            "change",
            applyFilters
        );
    }

    if (confirmed) {
        confirmed.addEventListener(
            "change",
            applyFilters
        );
    }

    window.filterSeverity = function (selected) {
        if (!severity) {
            return;
        }

        severity.value = selected || "";
        applyFilters();

        const findingsSection =
            document.getElementById("findings");

        if (findingsSection) {
            findingsSection.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });
        }
    };

    window.clearSeverityFilter = function () {
        if (!severity) {
            return;
        }

        severity.value = "";
        applyFilters();
    };

    applyFilters();
})();
"""


# ---------------------------------------------------------------------------
# HTML page generation
# ---------------------------------------------------------------------------

def dashboard_html(
    scans: List[Dict[str, Any]],
    findings: List[Dict[str, Any]],
    stats: Dict[str, Any],
    generated_at: str,
) -> str:
    finding_html = []

    scan_lookup: Dict[str, Dict[str, Any]] = {
        safe_str(scan.get("scan_id")): scan
        for scan in scans
    }

    for finding in findings:
        scan_id = safe_str(
            finding.get("scan_id")
        )

        scan = scan_lookup.get(
            scan_id,
            {
                "scan_id": scan_id,
                "target": finding.get("_target", ""),
            },
        )

        finding_html.append(
            finding_card(
                finding,
                scan,
            )
        )

    findings_content = (
        "".join(finding_html)
        if finding_html
        else """
        <div class="empty-table">
            No findings recorded yet.
        </div>
        """
    )

    db_path = database_path()

    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>VulnForge Security Dashboard</title>
<style>
{css}
</style>
</head>

<body>

<div class="container">

<header class="header">
    <div class="header-top">

        <div class="brand">
            <div class="logo">VF</div>

            <div>
                <h1>VulnForge Security Dashboard</h1>

                <div class="subtitle">
                    Live security findings generated from
                    <strong>vulnforge.db</strong>
                </div>

                <div class="generated">
                    Generated {generated}
                </div>
            </div>
        </div>

        <div class="header-actions">

            <div class="database-pill">
                Database:
                <code>{database}</code>
            </div>

            <a
                class="pdf-download"
                href="vulnforge_summary_report.pdf"
                download
                target="_blank"
                rel="noopener"
            >
                ↓ Download PDF Report
            </a>

        </div>

    </div>
</header>


<section class="stats">

    <div class="stat">
        <div class="stat-number">{total_scans}</div>
        <div class="stat-label">Total Scans</div>
    </div>

    <div class="stat">
        <div class="stat-number">{total_findings}</div>
        <div class="stat-label">Total Findings</div>
    </div>

    <div class="stat">
        <div class="stat-number">{unique_targets}</div>
        <div class="stat-label">Unique Targets</div>
    </div>

    <div class="stat">
        <div class="stat-number">{confirmed}</div>
        <div class="stat-label">Confirmed Findings</div>
    </div>

    <div class="stat">
        <div class="stat-number">{avg_findings:.1f}</div>
        <div class="stat-label">Avg Findings / Scan</div>
    </div>

</section>


<section class="section">

    <div class="section-title">
        <div>
            <h2>Findings by Severity</h2>
            <p>
                Current findings stored in the VulnForge database.
            </p>
        </div>
    </div>

    <div class="severity-grid">
        {severity_cards}
    </div>

</section>


<section class="section">

    <div class="section-title">
        <div>
            <h2>Recent Scans</h2>
            <p>
                Every scan is stored independently in SQLite.
            </p>
        </div>
    </div>

    <div class="scan-table-wrap">

        <table>
            <thead>
                <tr>
                    <th>Scan ID</th>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Findings</th>
                    <th>Requests</th>
                    <th>Duration</th>
                    <th>Timestamp</th>
                    <th>Report</th>
                </tr>
            </thead>

            <tbody>
                {scan_rows}
            </tbody>
        </table>

    </div>

</section>


<section class="section" id="findings">

    <div class="section-title">
        <div>
            <h2>Findings</h2>
            <p>
                Click through the evidence sections to see the exact
                endpoint, payload, request, response and explanation.
            </p>
        </div>

        <div>
            <strong id="visibleCount">{total_findings}</strong>
            <span class="muted">visible</span>
        </div>
    </div>


    <div class="controls">

        <input
            id="findingSearch"
            type="search"
            placeholder="Search finding, endpoint, category..."
            autocomplete="off"
        >

        <select id="severityFilter">
            <option value="">All severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
        </select>

        <label class="checkbox">
            <input
                id="confirmedFilter"
                type="checkbox"
            >
            Confirmed only
        </label>

        <button
            type="button"
            class="clear-filter"
            onclick="clearSeverityFilter()"
        >
            Clear Severity Filter
        </button>

    </div>


    <div class="findings">
        {findings}
    </div>

</section>


<footer class="footer">
    VulnForge local security dashboard ·
    Evidence is displayed exactly when it exists in the database.
    Missing evidence is never fabricated.
</footer>

</div>

<script>
{javascript}
</script>

</body>
</html>
""".format(
        css=CSS,
        javascript=JAVASCRIPT,
        generated=esc(generated_at),
        database=esc(str(db_path)),
        total_scans=stats["total_scans"],
        total_findings=stats["total_findings"],
        unique_targets=stats["unique_targets"],
        confirmed=stats["confirmed_findings"],
        avg_findings=stats["avg_findings_per_scan"],
        severity_cards=severity_cards(
            stats["severity_counts"]
        ),
        scan_rows=scan_rows(scans),
        findings=findings_content,
    )


# ---------------------------------------------------------------------------
# Per-scan report
# ---------------------------------------------------------------------------

def scan_report_html(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
    generated_at: str,
) -> str:
    stats = calculate_statistics(
        [scan],
        findings,
    )

    return dashboard_html(
        [scan],
        findings,
        stats,
        generated_at,
    )


# ---------------------------------------------------------------------------
# File helpers
# ---------------------------------------------------------------------------

def safe_filename(value: Any) -> str:
    text = safe_str(value, "unknown")

    text = re.sub(
        r"[^A-Za-z0-9_.-]+",
        "_",
        text,
    )

    return text[:150]


def write_text(
    path: Path,
    content: str,
) -> None:
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        content,
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

def try_generate_pdf(
    findings: List[Dict[str, Any]],
    output_directory: Path,
) -> Optional[Path]:
    """
    Best-effort PDF generation.

    Dashboard generation never depends on PDF support.
    """
    try:
        from .pdf_summary import build_summary_pdf
    except Exception:
        return None

    pdf_path = (
        output_directory
        / "vulnforge_summary_report.pdf"
    )

    try:
        build_summary_pdf(
            findings,
            str(pdf_path),
            title="VulnForge Summary Report",
        )

        if pdf_path.exists():
            return pdf_path

    except Exception as exc:
        print(
            "[DASHBOARD] PDF warning: {}".format(exc)
        )

    return None


# ---------------------------------------------------------------------------
# Main generator
# ---------------------------------------------------------------------------

def generate_dashboard(
    output_path: str = str(DEFAULT_DASHBOARD),
    scan_limit: int = 100,
) -> str:
    """
    Generate:

        vulnforge_dashboard.html

    and:

        vulnforge_reports/scan_<id>.html

    for every scan currently stored in the database.
    """
    generated_at = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    output = Path(output_path).expanduser().resolve()

    with connect_db() as conn:
        scans = load_scans(
            conn,
            limit=scan_limit,
        )

        all_findings = load_all_findings(conn)

        # Attach target to findings without changing the DB.
        scan_targets = {
            safe_str(scan.get("scan_id")):
                safe_str(scan.get("target"))
            for scan in scans
        }

        for finding in all_findings:
            finding["_target"] = scan_targets.get(
                safe_str(finding.get("scan_id")),
                "",
            )

        stats = calculate_statistics(
            scans,
            all_findings,
        )

        html_document = dashboard_html(
            scans,
            all_findings,
            stats,
            generated_at,
        )

        write_text(
            output,
            html_document,
        )

        # ---------------------------------------------------------------
        # Per-scan HTML reports
        # ---------------------------------------------------------------

        report_dir = output.parent / "vulnforge_reports"

        findings_by_scan: Dict[str, List[Dict[str, Any]]] = {}

        for finding in all_findings:
            scan_id = safe_str(
                finding.get("scan_id")
            )

            findings_by_scan.setdefault(
                scan_id,
                [],
            ).append(finding)

        for scan in scans:
            scan_id = safe_str(
                scan.get("scan_id"),
                "unknown",
            )

            scan_findings = findings_by_scan.get(
                scan_id,
                [],
            )

            filename = (
                "scan_{}.html".format(
                    safe_filename(scan_id)
                )
            )

            scan_html = scan_report_html(
                scan,
                scan_findings,
                generated_at,
            )

            write_text(
                report_dir / filename,
                scan_html,
            )

        # ---------------------------------------------------------------
        # PDF
        # ---------------------------------------------------------------

        pdf_path = try_generate_pdf(
            all_findings,
            output.parent,
        )

    print(
        "[DASHBOARD] Generated: {}".format(output)
    )

    print(
        "[DASHBOARD] Scans: {}".format(
            len(scans)
        )
    )

    print(
        "[DASHBOARD] Findings: {}".format(
            len(all_findings)
        )
    )

    print(
        "[DASHBOARD] Per-scan reports: {}".format(
            report_dir
        )
    )

    if pdf_path:
        print(
            "[DASHBOARD] PDF: {}".format(
                pdf_path
            )
        )

    return str(output)


# ---------------------------------------------------------------------------
# Command line entry point
# ---------------------------------------------------------------------------

def main() -> int:
    try:
        path = generate_dashboard()

        print(
            "[DASHBOARD] Written to {}".format(
                path
            )
        )

        return 0

    except FileNotFoundError as exc:
        print(
            "[DASHBOARD ERROR] {}".format(exc)
        )

        return 1

    except sqlite3.Error as exc:
        print(
            "[DASHBOARD DATABASE ERROR] {}".format(
                exc
            )
        )

        return 1

    except Exception as exc:
        print(
            "[DASHBOARD ERROR] {}".format(
                exc
            )
        )

        return 1


if __name__ == "__main__":
    raise SystemExit(main())
