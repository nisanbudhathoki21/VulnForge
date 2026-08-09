"""
report/scan_report.py

SQLite-only scan report generator for VulnForge.

This module intentionally does NOT use SQLAlchemy.

Database:
    vulnforge.db

Tables used:
    scans
    findings
    fingerprints
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_PATH = Path("vulnforge.db")


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_connection(db_path: Path = DB_PATH) -> sqlite3.Connection:
    """
    Open the VulnForge SQLite database.

    Returns:
        sqlite3.Connection with Row objects enabled.
    """
    if not db_path.exists():
        raise FileNotFoundError(
            f"VulnForge database not found: {db_path.resolve()}"
        )

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def table_exists(conn: sqlite3.Connection, table: str) -> bool:
    """Return True if a SQLite table exists."""
    row = conn.execute(
        """
        SELECT 1
        FROM sqlite_master
        WHERE type = 'table'
          AND name = ?
        LIMIT 1
        """,
        (table,),
    ).fetchone()

    return row is not None


def ensure_database() -> None:
    """
    Validate that the VulnForge SQLite database contains
    the expected tables.
    """
    with get_connection() as conn:
        required_tables = ("scans", "findings", "fingerprints")

        missing = [
            table
            for table in required_tables
            if not table_exists(conn, table)
        ]

        if missing:
            raise RuntimeError(
                "VulnForge database is missing required table(s): "
                + ", ".join(missing)
            )


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def safe_json(value: Any, default: Any = None) -> Any:
    """
    Safely decode JSON stored in SQLite.

    SQLite stores the fingerprint/evidence fields as TEXT.
    """
    if value is None:
        return default

    if isinstance(value, (dict, list)):
        return value

    if not isinstance(value, str):
        return value

    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else value


def format_value(value: Any, default: str = "N/A") -> str:
    """Convert a database value into readable report text."""
    if value is None:
        return default

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (dict, list)):
        return json.dumps(value, indent=2, ensure_ascii=False)

    text = str(value).strip()

    return text if text else default


def severity_rank(severity: Optional[str]) -> int:
    """Return sorting priority for vulnerability severity."""
    ranks = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "info": 1,
        "informational": 1,
    }

    if not severity:
        return 0

    return ranks.get(str(severity).lower(), 0)


def severity_label(severity: Optional[str]) -> str:
    """Normalize severity for report display."""
    if not severity:
        return "INFO"

    return str(severity).upper()


# ---------------------------------------------------------------------------
# Database queries
# ---------------------------------------------------------------------------

def get_scan(
    scan_id: str,
    db_path: Path = DB_PATH,
) -> Optional[Dict[str, Any]]:
    """Retrieve a single scan from the scans table."""

    with get_connection(db_path) as conn:
        row = conn.execute(
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
                errors_count
            FROM scans
            WHERE scan_id = ?
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()

        if row is None:
            return None

        scan = dict(row)

        scan["fingerprint_data"] = safe_json(
            scan.get("fingerprint"),
            {},
        )

        return scan


def get_findings(
    scan_id: str,
    db_path: Path = DB_PATH,
) -> List[Dict[str, Any]]:
    """Retrieve all findings belonging to a scan."""

    with get_connection(db_path) as conn:
        rows = conn.execute(
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
                created_at
            FROM findings
            WHERE scan_id = ?
            ORDER BY id ASC
            """,
            (scan_id,),
        ).fetchall()

        findings: List[Dict[str, Any]] = []

        for row in rows:
            finding = dict(row)

            finding["evidence_data"] = safe_json(
                finding.get("evidence"),
                {},
            )

            finding["extracted_data"] = safe_json(
                finding.get("extracted"),
                {},
            )

            findings.append(finding)

        return findings


def get_fingerprint(
    scan_id: str,
    db_path: Path = DB_PATH,
) -> Optional[Dict[str, Any]]:
    """Retrieve fingerprint information for a scan."""

    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT
                id,
                scan_id,
                target,
                server,
                waf,
                cdn,
                tech_stack,
                frameworks,
                cms,
                libraries,
                databases,
                os,
                security_rating,
                created_at
            FROM fingerprints
            WHERE scan_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()

        if row is None:
            return None

        return dict(row)


# ---------------------------------------------------------------------------
# Finding rendering
# ---------------------------------------------------------------------------

def render_finding(
    finding: Dict[str, Any],
    index: int,
) -> str:
    """Render one finding as Markdown."""

    severity = severity_label(
        finding.get("severity")
    )

    title = format_value(
        finding.get("name"),
        "Unnamed Finding",
    )

    confidence = finding.get("confidence")

    if confidence is not None:
        try:
            confidence_text = f"{float(confidence) * 100:.0f}%"
        except (TypeError, ValueError):
            confidence_text = format_value(confidence)
    else:
        confidence_text = "N/A"

    confirmed = bool(finding.get("confirmed", False))
    exploit_attempted = bool(
        finding.get("exploit_attempted", False)
    )
    exploit_success = bool(
        finding.get("exploit_success", False)
    )

    evidence = finding.get("evidence_data", {})
    extracted = finding.get("extracted_data", {})

    lines: List[str] = []

    lines.append(
        f"## {index}. [{severity}] {title}"
    )
    lines.append("")

    lines.append(
        f"**Template:** `{format_value(finding.get('template_id'))}`"
    )

    lines.append(
        f"**Confidence:** {confidence_text}"
    )

    lines.append(
        f"**Confirmed:** {'Yes' if confirmed else 'No'}"
    )

    lines.append(
        f"**Exploit attempted:** "
        f"{'Yes' if exploit_attempted else 'No'}"
    )

    lines.append(
        f"**Exploit successful:** "
        f"{'Yes' if exploit_success else 'No'}"
    )

    if finding.get("cwe"):
        lines.append(
            f"**CWE:** {finding['cwe']}"
        )

    if finding.get("owasp"):
        lines.append(
            f"**OWASP:** {finding['owasp']}"
        )

    lines.append("")

    if finding.get("impact"):
        lines.append("### Impact")
        lines.append("")
        lines.append(
            str(finding["impact"]).strip()
        )
        lines.append("")

    if finding.get("chain"):
        lines.append("### Attack Chain")
        lines.append("")
        lines.append(
            str(finding["chain"]).strip()
        )
        lines.append("")

    if evidence:
        lines.append("### Evidence")
        lines.append("")
        lines.append("```json")
        lines.append(
            json.dumps(
                evidence,
                indent=2,
                ensure_ascii=False,
            )
        )
        lines.append("```")
        lines.append("")

    if extracted:
        lines.append("### Extracted Data")
        lines.append("")
        lines.append("```json")
        lines.append(
            json.dumps(
                extracted,
                indent=2,
                ensure_ascii=False,
            )
        )
        lines.append("```")
        lines.append("")

    if finding.get("remediation"):
        lines.append("### Remediation")
        lines.append("")
        lines.append(
            str(finding["remediation"]).strip()
        )
        lines.append("")

    if finding.get("created_at"):
        lines.append(
            f"**Detected:** {finding['created_at']}"
        )
        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Fingerprint rendering
# ---------------------------------------------------------------------------

def render_fingerprint(
    fingerprint: Optional[Dict[str, Any]],
    scan: Dict[str, Any],
) -> str:
    """Render target fingerprint information."""

    lines: List[str] = []

    lines.append("## Target Fingerprint")
    lines.append("")

    if fingerprint:
        fields = [
            ("Server", "server"),
            ("WAF", "waf"),
            ("CDN", "cdn"),
            ("Technology Stack", "tech_stack"),
            ("Frameworks", "frameworks"),
            ("CMS", "cms"),
            ("Libraries", "libraries"),
            ("Databases", "databases"),
            ("Operating System", "os"),
            ("Security Rating", "security_rating"),
        ]

        for label, key in fields:
            value = fingerprint.get(key)

            if value is not None and str(value).strip():
                lines.append(
                    f"- **{label}:** {value}"
                )

    else:
        fingerprint_data = scan.get(
            "fingerprint_data",
            {},
        )

        if isinstance(fingerprint_data, dict):
            for key, value in fingerprint_data.items():
                label = str(key).replace("_", " ").title()

                if isinstance(value, (dict, list)):
                    value = json.dumps(
                        value,
                        ensure_ascii=False,
                    )

                lines.append(
                    f"- **{label}:** {format_value(value)}"
                )

    if len(lines) == 2:
        lines.append(
            "No fingerprint information was stored."
        )

    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Scan summary
# ---------------------------------------------------------------------------

def render_summary(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> str:
    """Render high-level scan statistics."""

    severity_counts: Dict[str, int] = {}

    for finding in findings:
        severity = severity_label(
            finding.get("severity")
        )

        severity_counts[severity] = (
            severity_counts.get(severity, 0) + 1
        )

    lines: List[str] = []

    lines.append("## Scan Summary")
    lines.append("")

    lines.append(
        f"- **Target:** {format_value(scan.get('target'))}"
    )

    lines.append(
        f"- **Scan ID:** `{format_value(scan.get('scan_id'))}`"
    )

    lines.append(
        f"- **Status:** {format_value(scan.get('status'))}"
    )

    lines.append(
        f"- **Started:** {format_value(scan.get('start_time'))}"
    )

    lines.append(
        f"- **Finished:** {format_value(scan.get('end_time'))}"
    )

    duration = scan.get("scan_duration")

    if duration is not None:
        try:
            duration_text = f"{float(duration):.2f}s"
        except (TypeError, ValueError):
            duration_text = str(duration)
    else:
        duration_text = "N/A"

    lines.append(
        f"- **Duration:** {duration_text}"
    )

    lines.append(
        f"- **Templates loaded:** "
        f"{format_value(scan.get('templates_loaded'), '0')}"
    )

    lines.append(
        f"- **Requests sent:** "
        f"{format_value(scan.get('requests_sent'), '0')}"
    )

    lines.append(
        f"- **Errors:** "
        f"{format_value(scan.get('errors_count'), '0')}"
    )

    lines.append(
        f"- **Findings:** {len(findings)}"
    )

    lines.append("")

    if severity_counts:
        lines.append("### Severity Breakdown")
        lines.append("")

        order = [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO",
            "INFORMATIONAL",
        ]

        for severity in order:
            count = severity_counts.get(
                severity,
                0,
            )

            if count:
                lines.append(
                    f"- **{severity}:** {count}"
                )

        lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Full report generation
# ---------------------------------------------------------------------------

def generate_scan_report(
    scan_id: str,
    db_path: Path = DB_PATH,
) -> str:
    """
    Generate a complete Markdown report for a scan.

    Args:
        scan_id: VulnForge scan identifier.
        db_path: SQLite database path.

    Returns:
        Markdown report as a string.
    """

    ensure_database()

    scan = get_scan(
        scan_id,
        db_path,
    )

    if scan is None:
        raise ValueError(
            f"Scan not found: {scan_id}"
        )

    findings = get_findings(
        scan_id,
        db_path,
    )

    fingerprint = get_fingerprint(
        scan_id,
        db_path,
    )

    # Sort strongest findings first.
    findings.sort(
        key=lambda item: (
            severity_rank(item.get("severity")),
            float(item.get("confidence") or 0),
        ),
        reverse=True,
    )

    lines: List[str] = []

    lines.append("# VulnForge Scan Report")
    lines.append("")

    lines.append(
        f"> Automated security scan report for "
        f"`{format_value(scan.get('target'))}`."
    )

    lines.append("")

    lines.append(
        render_summary(
            scan,
            findings,
        )
    )

    lines.append(
        render_fingerprint(
            fingerprint,
            scan,
        )
    )

    lines.append("## Findings")
    lines.append("")

    if not findings:
        lines.append(
            "No findings were recorded for this scan."
        )
        lines.append("")
    else:
        for index, finding in enumerate(
            findings,
            start=1,
        ):
            lines.append(
                render_finding(
                    finding,
                    index,
                )
            )

    lines.append("---")
    lines.append("")
    lines.append(
        "*Generated by VulnForge.*"
    )
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Save report
# ---------------------------------------------------------------------------

def save_scan_report(
    scan_id: str,
    output_path: Optional[str] = None,
    db_path: Path = DB_PATH,
) -> Path:
    """
    Generate and save a Markdown scan report.

    If output_path is omitted:
        reports/scan_<scan_id>.md
    """

    report = generate_scan_report(
        scan_id,
        db_path,
    )

    if output_path:
        path = Path(output_path)
    else:
        path = Path("reports") / f"scan_{scan_id}.md"

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    path.write_text(
        report,
        encoding="utf-8",
    )

    return path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def list_scans(
    db_path: Path = DB_PATH,
) -> List[Dict[str, Any]]:
    """Return recent scans from the database."""

    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                scan_id,
                target,
                timestamp,
                findings_count,
                scan_duration,
                status
            FROM scans
            ORDER BY rowid DESC
            """
        ).fetchall()

        return [dict(row) for row in rows]


def main() -> None:
    """Simple command-line interface."""

    import argparse

    parser = argparse.ArgumentParser(
        description="Generate a VulnForge SQLite scan report."
    )

    parser.add_argument(
        "scan_id",
        nargs="?",
        help="Scan ID to generate a report for.",
    )

    parser.add_argument(
        "-o",
        "--output",
        help="Output Markdown file.",
    )

    parser.add_argument(
        "--db",
        default=str(DB_PATH),
        help="SQLite database path.",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available scans.",
    )

    args = parser.parse_args()

    db_path = Path(args.db)

    if args.list:
        scans = list_scans(db_path)

        if not scans:
            print("No scans found.")
            return

        print(
            f"{'SCAN ID':<30} "
            f"{'FINDINGS':<10} "
            f"{'STATUS':<12} "
            f"TARGET"
        )

        print("-" * 100)

        for scan in scans:
            print(
                f"{str(scan.get('scan_id', '')):<30} "
                f"{str(scan.get('findings_count', 0)):<10} "
                f"{str(scan.get('status', '')):<12} "
                f"{scan.get('target', '')}"
            )

        return

    if not args.scan_id:
        parser.error(
            "scan_id is required unless --list is used."
        )

    try:
        output = save_scan_report(
            args.scan_id,
            args.output,
            db_path,
        )

        print(
            f"[+] Report generated: {output}"
        )

    except Exception as exc:
        print(
            f"[!] Failed to generate report: {exc}"
        )
        raise SystemExit(1)


if __name__ == "__main__":
    main()
