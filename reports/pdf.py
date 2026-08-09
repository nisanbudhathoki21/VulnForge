#!/usr/bin/env python3
"""
reports/pdf.py

SQLite-compatible PDF reporting for VulnForge.

Architecture:
    core.database -> SQLite
    reports.pdf   -> ReportLab PDF

This module intentionally does NOT use:
    - SQLAlchemy
    - database.models
    - Session
    - Vulnerability ORM models
    - AIAnalysis ORM models

It reads scan data through core.database.get_scan().
"""

from __future__ import annotations

import html
import logging
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import (
    ParagraphStyle,
    getSampleStyleSheet,
)
from reportlab.lib.units import cm
from reportlab.platypus import (
    KeepTogether,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from core.database import get_scan


logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
    "informational": 1,
    "unknown": 0,
}


def normalize_severity(value: Any) -> str:
    """Normalize a severity value into a display string."""

    if value is None:
        return "INFO"

    severity = str(value).strip().lower()

    aliases = {
        "informational": "INFO",
        "information": "INFO",
        "none": "INFO",
        "": "INFO",
    }

    severity = aliases.get(severity, severity)

    return severity.upper()


def severity_rank(value: Any) -> int:
    """Return sorting priority for vulnerability severity."""

    if value is None:
        return 1

    return SEVERITY_ORDER.get(
        str(value).strip().lower(),
        SEVERITY_ORDER["unknown"],
    )


def severity_badge(value: Any) -> str:
    """Return a human-readable severity label."""

    severity = normalize_severity(value)

    if severity == "CRITICAL":
        return "CRITICAL"
    if severity == "HIGH":
        return "HIGH"
    if severity == "MEDIUM":
        return "MEDIUM"
    if severity == "LOW":
        return "LOW"

    return "INFO"


def severity_color(value: Any):
    """Return a report color for a severity."""

    severity = str(value or "").strip().lower()

    return {
        "critical": colors.HexColor("#B71C1C"),
        "high": colors.HexColor("#D84315"),
        "medium": colors.HexColor("#EF6C00"),
        "low": colors.HexColor("#2E7D32"),
        "info": colors.HexColor("#1565C0"),
        "informational": colors.HexColor("#1565C0"),
    }.get(severity, colors.HexColor("#546E7A"))


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def safe_text(value: Any, default: str = "N/A") -> str:
    """
    Convert arbitrary values into safe PDF text.

    ReportLab Paragraph interprets HTML-like markup, so escaping is important.
    """

    if value is None:
        return default

    if isinstance(value, bool):
        return "Yes" if value else "No"

    if isinstance(value, (dict, list, tuple)):
        text = str(value)
    else:
        text = str(value)

    text = text.strip()

    if not text:
        return default

    return html.escape(text).replace("\n", "<br/>")


def short_text(value: Any, length: int = 180) -> str:
    """Return a compact escaped representation."""

    if value is None:
        return "N/A"

    text = str(value).strip()

    if not text:
        return "N/A"

    if len(text) > length:
        text = text[: length - 3] + "..."

    return safe_text(text)


def format_datetime(value: Any) -> str:
    """Format an ISO timestamp for display."""

    if not value:
        return "N/A"

    text = str(value)

    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return text


def format_duration(value: Any) -> str:
    """Format scan duration."""

    if value is None:
        return "N/A"

    try:
        seconds = float(value)

        if seconds < 1:
            return f"{seconds:.3f} s"

        if seconds < 60:
            return f"{seconds:.2f} s"

        minutes = int(seconds // 60)
        remaining = seconds % 60

        return f"{minutes}m {remaining:.1f}s"

    except (TypeError, ValueError):
        return safe_text(value)


def yes_no(value: Any) -> str:
    """Convert SQLite boolean-like values into readable text."""

    if isinstance(value, str):
        return "Yes" if value.lower() in {
            "1",
            "true",
            "yes",
            "y",
        } else "No"

    return "Yes" if bool(value) else "No"


# ---------------------------------------------------------------------------
# Data helpers
# ---------------------------------------------------------------------------

def parse_json_value(value: Any) -> Any:
    """
    Parse JSON-like values safely.

    core.database.get_scan() already decodes evidence/extracted, but this
    protects the report generator if another caller supplies raw JSON.
    """

    if value is None:
        return None

    if isinstance(value, (dict, list, tuple)):
        return value

    if not isinstance(value, str):
        return value

    text = value.strip()

    if not text:
        return None

    try:
        import json

        return json.loads(text)
    except Exception:
        return value


def render_value(value: Any) -> str:
    """Render dict/list/scalar values for the PDF."""

    value = parse_json_value(value)

    if value is None:
        return "N/A"

    if isinstance(value, dict):
        parts = []

        for key, item in value.items():
            parts.append(
                f"<b>{safe_text(key)}:</b> {safe_text(item)}"
            )

        return "<br/>".join(parts) if parts else "N/A"

    if isinstance(value, list):
        if not value:
            return "N/A"

        return "<br/>".join(
            f"• {safe_text(item)}"
            for item in value
        )

    return safe_text(value)


def get_fingerprint(scan: Dict[str, Any]) -> Dict[str, Any]:
    """Return fingerprint information from the scan."""

    fingerprint = scan.get("fingerprint_detail")

    if isinstance(fingerprint, dict):
        return fingerprint

    fingerprint = scan.get("fingerprint")

    if isinstance(fingerprint, dict):
        return fingerprint

    return {}


def calculate_severity_counts(
    findings: List[Dict[str, Any]],
) -> Dict[str, int]:
    """Calculate severity distribution."""

    counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
    }

    for finding in findings:
        severity = str(
            finding.get("severity", "info")
        ).strip().lower()

        if severity == "informational":
            severity = "info"

        if severity not in counts:
            severity = "info"

        counts[severity] += 1

    return counts


def calculate_risk_score(
    findings: List[Dict[str, Any]],
) -> int:
    """
    Calculate a simple report risk score.

    This is intentionally deterministic and does not pretend to be CVSS.
    """

    weights = {
        "critical": 40,
        "high": 25,
        "medium": 15,
        "low": 5,
        "info": 0,
        "informational": 0,
    }

    score = 0

    for finding in findings:
        severity = str(
            finding.get("severity", "info")
        ).strip().lower()

        score += weights.get(severity, 0)

    return min(score, 100)


# ---------------------------------------------------------------------------
# Report styles
# ---------------------------------------------------------------------------

def build_styles():
    """Create all PDF styles."""

    styles = getSampleStyleSheet()

    styles.add(
        ParagraphStyle(
            name="VFTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=29,
            alignment=TA_CENTER,
            spaceAfter=12,
            textColor=colors.HexColor("#0D47A1"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFSubtitle",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=11,
            leading=15,
            alignment=TA_CENTER,
            textColor=colors.HexColor("#546E7A"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFHeading1",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#0D47A1"),
            spaceBefore=12,
            spaceAfter=10,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFHeading2",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=14,
            leading=18,
            textColor=colors.HexColor("#1565C0"),
            spaceBefore=10,
            spaceAfter=7,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFHeading3",
            parent=styles["Heading3"],
            fontName="Helvetica-Bold",
            fontSize=11,
            leading=14,
            textColor=colors.HexColor("#263238"),
            spaceBefore=8,
            spaceAfter=5,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9.5,
            leading=14,
            textColor=colors.HexColor("#263238"),
            spaceAfter=6,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFSmall",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=8,
            leading=11,
            textColor=colors.HexColor("#455A64"),
            spaceAfter=3,
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFLabel",
            parent=styles["BodyText"],
            fontName="Helvetica-Bold",
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#37474F"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFEvidence",
            parent=styles["BodyText"],
            fontName="Courier",
            fontSize=7.5,
            leading=10,
            textColor=colors.HexColor("#263238"),
        )
    )

    styles.add(
        ParagraphStyle(
            name="VFTable",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=7.5,
            leading=10,
        )
    )

    return styles


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------

def make_table(
    data: List[List[Any]],
    col_widths: Optional[List[float]] = None,
    header: bool = True,
) -> Table:
    """Create a consistently styled report table."""

    converted = []

    for row_index, row in enumerate(data):
        converted_row = []

        for cell in row:
            if isinstance(cell, Paragraph):
                converted_row.append(cell)
            else:
                converted_row.append(
                    Paragraph(
                        safe_text(cell),
                        getSampleStyleSheet()["BodyText"],
                    )
                )

        converted.append(converted_row)

    table = Table(
        converted,
        colWidths=col_widths,
        repeatRows=1 if header else 0,
        hAlign="LEFT",
    )

    commands = [
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "TOP",
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.3,
            colors.HexColor("#CFD8DC"),
        ),
        (
            "LEFTPADDING",
            (0, 0),
            (-1, -1),
            6,
        ),
        (
            "RIGHTPADDING",
            (0, 0),
            (-1, -1),
            6,
        ),
        (
            "TOPPADDING",
            (0, 0),
            (-1, -1),
            5,
        ),
        (
            "BOTTOMPADDING",
            (0, 0),
            (-1, -1),
            5,
        ),
    ]

    if header and data:
        commands.extend(
            [
                (
                    "BACKGROUND",
                    (0, 0),
                    (-1, 0),
                    colors.HexColor("#0D47A1"),
                ),
                (
                    "TEXTCOLOR",
                    (0, 0),
                    (-1, 0),
                    colors.white,
                ),
                (
                    "FONTNAME",
                    (0, 0),
                    (-1, 0),
                    "Helvetica-Bold",
                ),
            ]
        )

    for row_index in range(
        1 if header else 0,
        len(data),
    ):
        if row_index % 2 == 0:
            commands.append(
                (
                    "BACKGROUND",
                    (0, row_index),
                    (-1, row_index),
                    colors.HexColor("#F7F9FA"),
                )
            )

    table.setStyle(TableStyle(commands))

    return table


def make_severity_table(
    findings: List[Dict[str, Any]],
    styles,
) -> Table:
    """Create severity summary table."""

    counts = calculate_severity_counts(findings)

    data = [
        [
            Paragraph("<b>Severity</b>", styles["VFTable"]),
            Paragraph("<b>Count</b>", styles["VFTable"]),
        ],
        [
            Paragraph("Critical", styles["VFTable"]),
            Paragraph(str(counts["critical"]), styles["VFTable"]),
        ],
        [
            Paragraph("High", styles["VFTable"]),
            Paragraph(str(counts["high"]), styles["VFTable"]),
        ],
        [
            Paragraph("Medium", styles["VFTable"]),
            Paragraph(str(counts["medium"]), styles["VFTable"]),
        ],
        [
            Paragraph("Low", styles["VFTable"]),
            Paragraph(str(counts["low"]), styles["VFTable"]),
        ],
        [
            Paragraph("Informational", styles["VFTable"]),
            Paragraph(str(counts["info"]), styles["VFTable"]),
        ],
    ]

    table = Table(
        data,
        colWidths=[5 * cm, 3 * cm],
    )

    commands = [
        (
            "BACKGROUND",
            (0, 0),
            (-1, 0),
            colors.HexColor("#0D47A1"),
        ),
        (
            "TEXTCOLOR",
            (0, 0),
            (-1, 0),
            colors.white,
        ),
        (
            "GRID",
            (0, 0),
            (-1, -1),
            0.3,
            colors.HexColor("#CFD8DC"),
        ),
        (
            "VALIGN",
            (0, 0),
            (-1, -1),
            "MIDDLE",
        ),
    ]

    severity_rows = {
        1: "critical",
        2: "high",
        3: "medium",
        4: "low",
        5: "info",
    }

    for row, severity in severity_rows.items():
        commands.append(
            (
                "TEXTCOLOR",
                (0, row),
                (0, row),
                severity_color(severity),
            )
        )

    table.setStyle(TableStyle(commands))

    return table


# ---------------------------------------------------------------------------
# Page decoration
# ---------------------------------------------------------------------------

def draw_page(canvas, doc):
    """Draw header/footer on every PDF page."""

    canvas.saveState()

    width, height = A4

    # Header
    canvas.setStrokeColor(colors.HexColor("#CFD8DC"))
    canvas.line(
        2 * cm,
        height - 1.25 * cm,
        width - 2 * cm,
        height - 1.25 * cm,
    )

    canvas.setFont("Helvetica-Bold", 8)
    canvas.setFillColor(colors.HexColor("#546E7A"))
    canvas.drawString(
        2 * cm,
        height - 1.0 * cm,
        "VulnForge Security Assessment",
    )

    # Footer
    canvas.setStrokeColor(colors.HexColor("#CFD8DC"))
    canvas.line(
        2 * cm,
        1.25 * cm,
        width - 2 * cm,
        1.25 * cm,
    )

    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(colors.HexColor("#78909C"))

    canvas.drawString(
        2 * cm,
        0.9 * cm,
        "Generated by VulnForge",
    )

    canvas.drawRightString(
        width - 2 * cm,
        0.9 * cm,
        f"Page {doc.page}",
    )

    canvas.restoreState()


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def build_executive_summary(
    scan: Dict[str, Any],
    findings: List[Dict[str, Any]],
) -> str:
    """Generate a deterministic executive summary."""

    target = scan.get("target", "unknown target")
    counts = calculate_severity_counts(findings)

    total = len(findings)

    if total == 0:
        return (
            f"VulnForge completed a security scan of "
            f"{safe_text(target)} and did not record any "
            f"automated findings."
        )

    return (
        f"VulnForge completed a security scan of "
        f"{safe_text(target)} and recorded {total} "
        f"automated finding(s). The scan identified "
        f"{counts['critical']} critical, "
        f"{counts['high']} high, "
        f"{counts['medium']} medium, "
        f"{counts['low']} low, and "
        f"{counts['info']} informational finding(s). "
        f"Automated findings should be manually validated "
        f"before being treated as confirmed vulnerabilities."
    )


# ---------------------------------------------------------------------------
# Finding rendering
# ---------------------------------------------------------------------------

def finding_evidence_text(
    finding: Dict[str, Any],
) -> str:
    """Extract readable evidence from a finding."""

    evidence = finding.get("evidence")

    if evidence:
        return render_value(evidence)

    extracted = finding.get("extracted")

    if extracted:
        return render_value(extracted)

    return "N/A"


def render_finding(
    finding: Dict[str, Any],
    number: int,
    styles,
) -> List[Any]:
    """Render a single finding."""

    name = finding.get(
        "name",
        "Unnamed Finding",
    )

    severity = finding.get(
        "severity",
        "info",
    )

    category = (
        finding.get("category")
        or finding.get("template_id")
        or "Uncategorized"
    )

    story: List[Any] = []

    title = (
        f"{number}. {safe_text(name)} "
        f"[{safe_text(severity_badge(severity))}]"
    )

    story.append(
        Paragraph(
            title,
            styles["VFHeading2"],
        )
    )

    metadata = [
        [
            Paragraph("<b>Severity</b>", styles["VFTable"]),
            Paragraph(
                safe_text(severity_badge(severity)),
                styles["VFTable"],
            ),
            Paragraph("<b>Template</b>", styles["VFTable"]),
            Paragraph(
                safe_text(finding.get("template_id")),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph("<b>Category</b>", styles["VFTable"]),
            Paragraph(
                safe_text(category),
                styles["VFTable"],
            ),
            Paragraph("<b>Confirmed</b>", styles["VFTable"]),
            Paragraph(
                yes_no(finding.get("confirmed")),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph("<b>Confidence</b>", styles["VFTable"]),
            Paragraph(
                safe_text(finding.get("confidence", 0.0)),
                styles["VFTable"],
            ),
            Paragraph(
                "<b>Exploit Attempted</b>",
                styles["VFTable"],
            ),
            Paragraph(
                yes_no(finding.get("exploit_attempted")),
                styles["VFTable"],
            ),
        ],
    ]

    metadata_table = Table(
        metadata,
        colWidths=[
            3 * cm,
            5 * cm,
            3.5 * cm,
            5 * cm,
        ],
    )

    metadata_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.3,
                    colors.HexColor("#CFD8DC"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#ECEFF1"),
                ),
                (
                    "BACKGROUND",
                    (2, 0),
                    (2, -1),
                    colors.HexColor("#ECEFF1"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    5,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    4,
                ),
            ]
        )
    )

    story.append(metadata_table)
    story.append(Spacer(1, 8))

    # URL if available
    if finding.get("url"):
        story.append(
            Paragraph(
                f"<b>URL:</b> {safe_text(finding.get('url'))}",
                styles["VFBody"],
            )
        )

    # Impact
    story.append(
        Paragraph(
            "<b>Impact</b>",
            styles["VFHeading3"],
        )
    )

    story.append(
        Paragraph(
            render_value(finding.get("impact")),
            styles["VFBody"],
        )
    )

    # Evidence
    story.append(
        Paragraph(
            "<b>Evidence</b>",
            styles["VFHeading3"],
        )
    )

    evidence = finding_evidence_text(finding)

    story.append(
        Paragraph(
            evidence,
            styles["VFEvidence"],
        )
    )

    # Chain
    if finding.get("chain"):
        story.append(
            Paragraph(
                "<b>Attack / Detection Chain</b>",
                styles["VFHeading3"],
            )
        )

        story.append(
            Paragraph(
                render_value(finding.get("chain")),
                styles["VFBody"],
            )
        )

    # CWE / OWASP
    if finding.get("cwe") or finding.get("owasp"):
        mapping_data = [
            [
                Paragraph("<b>CWE</b>", styles["VFTable"]),
                Paragraph(
                    safe_text(finding.get("cwe")),
                    styles["VFTable"],
                ),
                Paragraph("<b>OWASP</b>", styles["VFTable"]),
                Paragraph(
                    safe_text(finding.get("owasp")),
                    styles["VFTable"],
                ),
            ]
        ]

        mapping_table = Table(
            mapping_data,
            colWidths=[
                2 * cm,
                5.5 * cm,
                2 * cm,
                5.5 * cm,
            ],
        )

        mapping_table.setStyle(
            TableStyle(
                [
                    (
                        "GRID",
                        (0, 0),
                        (-1, -1),
                        0.3,
                        colors.HexColor("#CFD8DC"),
                    ),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, 0),
                        colors.HexColor("#ECEFF1"),
                    ),
                    (
                        "BACKGROUND",
                        (2, 0),
                        (2, 0),
                        colors.HexColor("#ECEFF1"),
                    ),
                    (
                        "VALIGN",
                        (0, 0),
                        (-1, -1),
                        "TOP",
                    ),
                ]
            )
        )

        story.append(Spacer(1, 5))
        story.append(mapping_table)

    # Remediation
    story.append(
        Paragraph(
            "<b>Remediation</b>",
            styles["VFHeading3"],
        )
    )

    story.append(
        Paragraph(
            render_value(finding.get("remediation")),
            styles["VFBody"],
        )
    )

    # Exploit status
    if finding.get("exploit_attempted"):
        story.append(
            Paragraph(
                "<b>Exploit Status</b>",
                styles["VFHeading3"],
            )
        )

        exploit_success = finding.get(
            "exploit_success"
        )

        story.append(
            Paragraph(
                (
                    "Exploit attempt succeeded."
                    if exploit_success
                    else
                    "Exploit attempt was unsuccessful or "
                    "not conclusively demonstrated."
                ),
                styles["VFBody"],
            )
        )

    story.append(
        Spacer(1, 14)
    )

    return [
        KeepTogether(story)
    ]


# ---------------------------------------------------------------------------
# Main PDF generator
# ---------------------------------------------------------------------------

def generate_pdf_report(
    scan_id: str,
    output_dir: str | Path = "output",
    risk_score: Optional[int] = None,
) -> Path:
    """
    Generate a PDF report from a SQLite VulnForge scan.

    Parameters
    ----------
    scan_id:
        Scan identifier stored in the scans table.

    output_dir:
        Destination directory for the generated PDF.

    risk_score:
        Optional externally calculated risk score.
        If omitted, VulnForge calculates a deterministic report score.

    Returns
    -------
    Path
        Path to the generated PDF.

    Raises
    ------
    ValueError
        If the scan does not exist.
    """

    scan_id = str(scan_id)

    scan = get_scan(scan_id)

    if not scan:
        raise ValueError(
            f"Scan '{scan_id}' was not found in vulnforge.db"
        )

    output_path = Path(output_dir)
    output_path.mkdir(
        parents=True,
        exist_ok=True,
    )

    findings = scan.get("findings") or []

    if not isinstance(findings, list):
        findings = []

    findings = [
        finding
        for finding in findings
        if isinstance(finding, dict)
    ]

    findings.sort(
        key=lambda finding: (
            severity_rank(
                finding.get("severity")
            ),
            str(
                finding.get("name", "")
            ).lower(),
        ),
        reverse=True,
    )

    if risk_score is None:
        risk_score = calculate_risk_score(
            findings
        )

    timestamp = datetime.now().strftime(
        "%Y%m%d_%H%M%S"
    )

    pdf_path = (
        output_path
        / f"VulnForge_Report_{scan_id}_{timestamp}.pdf"
    )

    styles = build_styles()

    document = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        rightMargin=1.8 * cm,
        leftMargin=1.8 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.8 * cm,
        title="VulnForge Security Assessment Report",
        author="VulnForge",
        subject="Automated Web Security Assessment",
    )

    story: List[Any] = []

    target = scan.get(
        "target",
        "Unknown target",
    )

    # ------------------------------------------------------------------
    # Cover
    # ------------------------------------------------------------------

    story.append(
        Spacer(1, 2.0 * cm)
    )

    story.append(
        Paragraph(
            "VulnForge",
            styles["VFTitle"],
        )
    )

    story.append(
        Paragraph(
            "Security Assessment Report",
            styles["VFSubtitle"],
        )
    )

    story.append(
        Spacer(1, 1.2 * cm)
    )

    cover_data = [
        [
            Paragraph(
                "<b>Target</b>",
                styles["VFTable"],
            ),
            Paragraph(
                safe_text(target),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Scan ID</b>",
                styles["VFTable"],
            ),
            Paragraph(
                safe_text(scan_id),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Status</b>",
                styles["VFTable"],
            ),
            Paragraph(
                safe_text(
                    scan.get(
                        "status",
                        "completed",
                    )
                ),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Started</b>",
                styles["VFTable"],
            ),
            Paragraph(
                format_datetime(
                    scan.get("start_time")
                ),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Completed</b>",
                styles["VFTable"],
            ),
            Paragraph(
                format_datetime(
                    scan.get("end_time")
                ),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Duration</b>",
                styles["VFTable"],
            ),
            Paragraph(
                format_duration(
                    scan.get("scan_duration")
                ),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Templates Loaded</b>",
                styles["VFTable"],
            ),
            Paragraph(
                safe_text(
                    scan.get(
                        "templates_loaded",
                        0,
                    )
                ),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Requests Sent</b>",
                styles["VFTable"],
            ),
            Paragraph(
                safe_text(
                    scan.get(
                        "requests_sent",
                        0,
                    )
                ),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Findings</b>",
                styles["VFTable"],
            ),
            Paragraph(
                str(len(findings)),
                styles["VFTable"],
            ),
        ],
        [
            Paragraph(
                "<b>Report Risk Score</b>",
                styles["VFTable"],
            ),
            Paragraph(
                f"{risk_score}/100",
                styles["VFTable"],
            ),
        ],
    ]

    cover_table = Table(
        cover_data,
        colWidths=[
            5 * cm,
            11 * cm,
        ],
    )

    cover_table.setStyle(
        TableStyle(
            [
                (
                    "GRID",
                    (0, 0),
                    (-1, -1),
                    0.35,
                    colors.HexColor("#CFD8DC"),
                ),
                (
                    "BACKGROUND",
                    (0, 0),
                    (0, -1),
                    colors.HexColor("#ECEFF1"),
                ),
                (
                    "VALIGN",
                    (0, 0),
                    (-1, -1),
                    "TOP",
                ),
                (
                    "LEFTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "RIGHTPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "TOPPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
                (
                    "BOTTOMPADDING",
                    (0, 0),
                    (-1, -1),
                    7,
                ),
            ]
        )
    )

    story.append(cover_table)

    story.append(
        Spacer(1, 1.2 * cm)
    )

    story.append(
        Paragraph(
            "Automated scanner output must be manually validated "
            "before being treated as a confirmed security "
            "vulnerability.",
            styles["VFSmall"],
        )
    )

    story.append(PageBreak())

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------

    story.append(
        Paragraph(
            "1. Executive Summary",
            styles["VFHeading1"],
        )
    )

    story.append(
        Paragraph(
            build_executive_summary(
                scan,
                findings,
            ),
            styles["VFBody"],
        )
    )

    # ------------------------------------------------------------------
    # Severity overview
    # ------------------------------------------------------------------

    story.append(
        Paragraph(
            "Severity Overview",
            styles["VFHeading2"],
        )
    )

    severity_table = make_severity_table(
        findings,
        styles,
    )

    story.append(severity_table)

    story.append(
        Spacer(1, 10)
    )

    # ------------------------------------------------------------------
    # Priority findings
    # ------------------------------------------------------------------

    story.append(
        Paragraph(
            "Finding Priority",
            styles["VFHeading2"],
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No automated findings were recorded.",
                styles["VFBody"],
            )
        )
    else:
        priority_data = [
            [
                Paragraph(
                    "<b>#</b>",
                    styles["VFTable"],
                ),
                Paragraph(
                    "<b>Severity</b>",
                    styles["VFTable"],
                ),
                Paragraph(
                    "<b>Finding</b>",
                    styles["VFTable"],
                ),
                Paragraph(
                    "<b>Template</b>",
                    styles["VFTable"],
                ),
                Paragraph(
                    "<b>Confirmed</b>",
                    styles["VFTable"],
                ),
            ]
        ]

        for index, finding in enumerate(
            findings,
            start=1,
        ):
            priority_data.append(
                [
                    Paragraph(
                        str(index),
                        styles["VFTable"],
                    ),
                    Paragraph(
                        severity_badge(
                            finding.get(
                                "severity"
                            )
                        ),
                        styles["VFTable"],
                    ),
                    Paragraph(
                        safe_text(
                            finding.get(
                                "name",
                                "Unnamed",
                            )
                        ),
                        styles["VFTable"],
                    ),
                    Paragraph(
                        safe_text(
                            finding.get(
                                "template_id"
                            )
                        ),
                        styles["VFTable"],
                    ),
                    Paragraph(
                        yes_no(
                            finding.get(
                                "confirmed"
                            )
                        ),
                        styles["VFTable"],
                    ),
                ]
            )

        priority_table = make_table(
            priority_data,
            col_widths=[
                0.8 * cm,
                2.5 * cm,
                6.2 * cm,
                4.0 * cm,
                2.0 * cm,
            ],
        )

        story.append(priority_table)

    # ------------------------------------------------------------------
    # Fingerprint
    # ------------------------------------------------------------------

    fingerprint = get_fingerprint(
        scan
    )

    if fingerprint:
        story.append(
            Paragraph(
                "2. Target Fingerprint",
                styles["VFHeading1"],
            )
        )

        fingerprint_data = [
            [
                Paragraph(
                    "<b>Technology</b>",
                    styles["VFTable"],
                ),
                Paragraph(
                    "<b>Detected</b>",
                    styles["VFTable"],
                ),
            ]
        ]

        fingerprint_fields = [
            ("Server", "server"),
            ("Operating System", "os"),
            ("WAF", "waf"),
            ("CDN", "cdn"),
            ("Tech Stack", "tech_stack"),
            ("Frameworks", "frameworks"),
            ("CMS", "cms"),
            ("Libraries", "libraries"),
            ("Databases", "databases"),
            ("Security Rating", "security_rating"),
        ]

        for label, key in fingerprint_fields:
            value = fingerprint.get(key)

            if value in (
                None,
                "",
                [],
                {},
            ):
                continue

            fingerprint_data.append(
                [
                    Paragraph(
                        safe_text(label),
                        styles["VFTable"],
                    ),
                    Paragraph(
                        render_value(value),
                        styles["VFTable"],
                    ),
                ]
            )

        if len(fingerprint_data) > 1:
            story.append(
                make_table(
                    fingerprint_data,
                    col_widths=[
                        4.5 * cm,
                        11.5 * cm,
                    ],
                )
            )

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "3. Vulnerability Details",
            styles["VFHeading1"],
        )
    )

    if not findings:
        story.append(
            Paragraph(
                "No findings were detected.",
                styles["VFBody"],
            )
        )
    else:
        for index, finding in enumerate(
            findings,
            start=1,
        ):
            story.extend(
                render_finding(
                    finding,
                    index,
                    styles,
                )
            )

    # ------------------------------------------------------------------
    # Conclusion
    # ------------------------------------------------------------------

    story.append(PageBreak())

    story.append(
        Paragraph(
            "4. Conclusion",
            styles["VFHeading1"],
        )
    )

    if findings:
        counts = calculate_severity_counts(
            findings
        )

        conclusion = (
            f"The scan produced {len(findings)} "
            f"automated finding(s), including "
            f"{counts['critical']} critical, "
            f"{counts['high']} high, "
            f"{counts['medium']} medium, "
            f"{counts['low']} low, and "
            f"{counts['info']} informational item(s). "
        )

        if counts["critical"] or counts["high"]:
            conclusion += (
                "High-priority findings should be reviewed "
                "and manually validated first. "
            )
        elif counts["medium"]:
            conclusion += (
                "Medium-severity findings should be reviewed "
                "and manually validated before remediation "
                "planning. "
            )
        else:
            conclusion += (
                "The detected items should still be reviewed "
                "to determine whether they represent "
                "security-relevant conditions. "
            )

        conclusion += (
            "Automated template matches are not equivalent "
            "to confirmed vulnerabilities."
        )
    else:
        conclusion = (
            "No automated findings were recorded during this "
            "scan. This does not prove that the target is free "
            "of vulnerabilities because scanner coverage depends "
            "on the templates executed, target behavior, "
            "authentication state, and available application "
            "context."
        )

    story.append(
        Paragraph(
            safe_text(conclusion),
            styles["VFBody"],
        )
    )

    # ------------------------------------------------------------------
    # Methodology
    # ------------------------------------------------------------------

    story.append(
        Paragraph(
            "5. Methodology and Limitations",
            styles["VFHeading1"],
        )
    )

    methodology = [
        "VulnForge uses YAML-driven security testing templates.",
        "Detection results are recorded as automated findings.",
        "Findings may require manual verification.",
        "Scanner coverage depends on the templates executed.",
        "Unauthenticated scanning cannot evaluate functionality "
        "that requires valid authentication.",
        "A finding does not automatically establish exploitability "
        "or business impact.",
        "Risk score in this report is a deterministic summary "
        "indicator and is not a CVSS score.",
    ]

    for item in methodology:
        story.append(
            Paragraph(
                f"• {safe_text(item)}",
                styles["VFBody"],
            )
        )

    # ------------------------------------------------------------------
    # Build
    # ------------------------------------------------------------------

    document.build(
        story,
        onFirstPage=draw_page,
        onLaterPages=draw_page,
    )

    logger.info(
        "Generated PDF report: %s",
        pdf_path,
    )

    return pdf_path


# ---------------------------------------------------------------------------
# Convenience API
# ---------------------------------------------------------------------------

def generate_report(
    scan_id: str,
    output_dir: str | Path = "output",
) -> Path:
    """
    Backwards-compatible convenience wrapper.
    """

    return generate_pdf_report(
        scan_id=scan_id,
        output_dir=output_dir,
    )


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "Generate a VulnForge PDF report "
            "from a SQLite scan."
        )
    )

    parser.add_argument(
        "scan_id",
        help="VulnForge scan ID",
    )

    parser.add_argument(
        "-o",
        "--output",
        default="output",
        help="Output directory",
    )

    args = parser.parse_args()

    try:
        path = generate_pdf_report(
            scan_id=args.scan_id,
            output_dir=args.output,
        )

        print("PDF generated successfully:")
        print(path)

    except Exception as exc:
        print(
            f"ERROR: {exc}"
        )
        raise SystemExit(1)
