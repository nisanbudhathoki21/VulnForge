"""
VulnForge PDF Report Generator
===============================
Generates professional, HackerOne-bug-report-style PDFs directly from
SQLite (core.database) - never from live terminal output. Supports:

  - Full scan report  (all findings for a scan_id)
  - Single finding report (one specific finding_id)

Both pull exclusively from the `scans` / `findings` / `fingerprints`
tables, so the PDF always matches what's actually stored, not what
a particular terminal run happened to print.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
    HRFlowable,
)

from core.database import get_scan

SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#7f1d1d"),
    "HIGH": colors.HexColor("#b91c1c"),
    "MEDIUM": colors.HexColor("#b45309"),
    "LOW": colors.HexColor("#0369a1"),
    "INFORMATIONAL": colors.HexColor("#374151"),
    "INFO": colors.HexColor("#374151"),
}


def _styles():
    ss = getSampleStyleSheet()
    ss.add(ParagraphStyle(
        name="VFTitle", fontSize=22, leading=26, spaceAfter=6,
        textColor=colors.HexColor("#111827"),
    ))
    ss.add(ParagraphStyle(
        name="VFSubtitle", fontSize=11, leading=14,
        textColor=colors.HexColor("#6b7280"), spaceAfter=20,
    ))
    ss.add(ParagraphStyle(
        name="VFSection", fontSize=14, leading=18, spaceBefore=16,
        spaceAfter=8, textColor=colors.HexColor("#111827"),
    ))
    ss.add(ParagraphStyle(
        name="VFFindingTitle", fontSize=13, leading=16, spaceBefore=4,
        textColor=colors.white,
    ))
    ss.add(ParagraphStyle(
        name="VFBody", fontSize=9.5, leading=14,
        textColor=colors.HexColor("#1f2937"),
    ))
    ss.add(ParagraphStyle(
        name="VFEvidence", fontSize=8.5, leading=12, fontName="Courier",
        textColor=colors.HexColor("#111827"),
    ))
    ss.add(ParagraphStyle(
        name="VFLabel", fontSize=9, leading=12,
        textColor=colors.HexColor("#6b7280"),
    ))
    return ss


def _severity_color(sev: str):
    return SEVERITY_COLORS.get(
        str(sev or "").upper(), colors.HexColor("#374151")
    )


def _truncate(value: str, limit: int = 400) -> str:
    """Truncate long evidence values (e.g. full response bodies) so
    the PDF never embeds an entire raw page dump. Evidence should be
    a short, relevant fragment - not the whole response."""
    text = str(value)
    if len(text) > limit:
        return text[:limit] + f"... [truncated, {len(text)} chars total]"
    return text


# Fields that commonly hold large/raw payloads (full response bodies,
# headers dicts, etc.) and should never be embedded verbatim in a
# PDF - either drop them or aggressively truncate them.
_EVIDENCE_DROP_FIELDS = {
    "response_body", "request_body", "response_headers",
    "request_headers", "raw_response", "body",
}
_EVIDENCE_TRUNCATE_LIMIT = 400


def _fmt_evidence(evidence: Any) -> str:
    if not evidence:
        return "No evidence recorded."
    if isinstance(evidence, dict):
        lines = []
        for k in ("method", "url", "status", "matched_condition",
                   "parameter", "template_id", "response_fragment"):
            if k in evidence and evidence[k] not in (None, ""):
                lines.append(f"{k}: {_truncate(evidence[k], _EVIDENCE_TRUNCATE_LIMIT)}")
        for k, v in evidence.items():
            if k in _EVIDENCE_DROP_FIELDS:
                continue
            if k not in (
                "method", "url", "status", "matched_condition",
                "parameter", "template_id", "response_fragment",
            ) and v not in (None, ""):
                lines.append(f"{k}: {_truncate(v, _EVIDENCE_TRUNCATE_LIMIT)}")
        return "\n".join(lines) if lines else "No evidence recorded."
    return _truncate(evidence, _EVIDENCE_TRUNCATE_LIMIT)


def _cover_page(story, styles, scan: Dict[str, Any], subtitle: str):
    story.append(Spacer(1, 3 * cm))
    story.append(Paragraph("VulnForge Security Assessment", styles["VFTitle"]))
    story.append(Paragraph(_xml_escape(subtitle), styles["VFSubtitle"]))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
    story.append(Spacer(1, 0.6 * cm))

    meta_rows = [
        ["Target", scan.get("target", "N/A")],
        ["Scan ID", scan.get("scan_id", "N/A")],
        ["Scan Date", str(scan.get("timestamp") or scan.get("start_time") or "N/A")],
        ["Status", scan.get("status", "N/A")],
        ["Report Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
    ]
    t = Table(meta_rows, colWidths=[4 * cm, 11 * cm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 9.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("LINEBELOW", (0, 0), (-1, -1), 0.5, colors.HexColor("#e5e7eb")),
    ]))
    story.append(t)
    story.append(PageBreak())


def _finding_block(story, styles, finding: Dict[str, Any]):
    sev = str(finding.get("severity", "Unknown")).upper()
    color = _severity_color(sev)

    header = Table(
        [[Paragraph(
            _xml_escape(f"[{sev}] {finding.get('name', 'Unnamed finding')}"),
            styles["VFFindingTitle"],
        )]],
        colWidths=[17 * cm],
    )
    header.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(header)
    story.append(Spacer(1, 0.3 * cm))

    confirmed = "Confirmed" if finding.get("confirmed") else "Unconfirmed (lead only)"
    confidence = finding.get("confidence", 0.0) or 0.0

    meta_rows = [
        ["Confidence", f"{confidence:.2f}", "Status", confirmed],
        ["CWE", str(finding.get("cwe") or "N/A"), "OWASP", str(finding.get("owasp") or "N/A")],
        ["Template ID", str(finding.get("template_id") or "N/A"), "Finding ID", str(finding.get("id") or "N/A")],
    ]
    t = Table(meta_rows, colWidths=[3 * cm, 5.5 * cm, 3 * cm, 5.5 * cm])
    t.setStyle(TableStyle([
        ("FONTSIZE", (0, 0), (-1, -1), 8.5),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#6b7280")),
        ("TEXTCOLOR", (2, 0), (2, -1), colors.HexColor("#6b7280")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
    ]))
    story.append(t)
    story.append(Spacer(1, 0.4 * cm))

    for label, key in [
        ("Impact", "impact"),
        ("Attack Chain", "chain"),
    ]:
        val = finding.get(key)
        if val:
            story.append(Paragraph(f"<b>{label}</b>", styles["VFLabel"]))
            story.append(Paragraph(_xml_escape(str(val)), styles["VFBody"]))
            story.append(Spacer(1, 0.25 * cm))

    story.append(Paragraph("<b>Evidence</b>", styles["VFLabel"]))
    story.append(Spacer(1, 0.1 * cm))
    evidence_text = _xml_escape(_fmt_evidence(finding.get("evidence")))
    evidence_para = Paragraph(
        evidence_text.replace("\n", "<br/>"),
        styles["VFEvidence"],
    )
    evidence_table = Table([[evidence_para]], colWidths=[17 * cm])
    evidence_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f4f6")),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(evidence_table)
    story.append(Spacer(1, 0.3 * cm))

    remediation = finding.get("remediation")
    if remediation:
        story.append(Paragraph("<b>Remediation</b>", styles["VFLabel"]))
        story.append(Paragraph(_xml_escape(str(remediation)), styles["VFBody"]))

    if not finding.get("confirmed"):
        story.append(Spacer(1, 0.3 * cm))
        story.append(Paragraph(
            "<b>Note:</b> This finding was not independently reproduced "
            "by the verification stage. Treat it as an unconfirmed lead "
            "requiring manual validation before disclosure.",
            styles["VFBody"],
        ))

    story.append(Spacer(1, 0.6 * cm))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#e5e7eb")))
    story.append(Spacer(1, 0.4 * cm))


def generate_full_report_pdf(scan_id: str, output_path: Optional[str] = None) -> str:
    """
    Generate a full-scan PDF (all findings) from SQLite data for the
    given scan_id. Returns the output file path.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise ValueError(f"No scan found in database for scan_id={scan_id!r}")

    findings: List[Dict[str, Any]] = scan.get("findings", []) or []

    if not output_path:
        safe_target = "".join(
            c if c.isalnum() else "_" for c in str(scan.get("target", "target"))
        )[:40]
        output_path = f"VulnForge_Report_{safe_target}_{scan_id}.pdf"

    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
    )
    story = []

    _cover_page(story, styles, scan, "Full Scan Security Report")

    story.append(Paragraph("Executive Summary", styles["VFSection"]))
    sev_counts: Dict[str, int] = {}
    for f in findings:
        s = str(f.get("severity", "Unknown")).upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    if findings:
        summary_rows = [["Severity", "Count"]] + [
            [s, str(c)] for s, c in sorted(
                sev_counts.items(),
                key=lambda kv: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "INFO"].index(kv[0])
                if kv[0] in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "INFO"] else 99,
            )
        ]
        t = Table(summary_rows, colWidths=[6 * cm, 3 * cm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#111827")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTSIZE", (0, 0), (-1, -1), 9.5),
            ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
    else:
        story.append(Paragraph(
            "No verified findings were recorded for this scan.",
            styles["VFBody"],
        ))

    fp = scan.get("fingerprint") or {}
    if fp:
        story.append(Paragraph("Technology Fingerprint", styles["VFSection"]))
        fp_rows = [[_xml_escape(str(k)), _xml_escape(str(v))] for k, v in fp.items() if v not in (None, "")]
        if fp_rows:
            t = Table(fp_rows, colWidths=[4 * cm, 11 * cm])
            t.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#e5e7eb")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)

    story.append(PageBreak())
    story.append(Paragraph("Findings", styles["VFSection"]))
    story.append(Spacer(1, 0.2 * cm))

    if not findings:
        story.append(Paragraph("No findings to report.", styles["VFBody"]))
    else:
        for f in findings:
            _finding_block(story, styles, f)

    doc.build(story)
    return os.path.abspath(output_path)


def generate_finding_pdf(scan_id: str, finding_id: str, output_path: Optional[str] = None) -> str:
    """
    Generate a PDF for ONLY the specified finding_id within scan_id.
    Raises ValueError if the scan or finding isn't found.
    """
    scan = get_scan(scan_id)
    if not scan:
        raise ValueError(f"No scan found in database for scan_id={scan_id!r}")

    findings = scan.get("findings", []) or []
    target_finding = None
    for f in findings:
        if str(f.get("id")) == str(finding_id):
            target_finding = f
            break

    if not target_finding:
        raise ValueError(
            f"No finding with id={finding_id!r} found in scan {scan_id!r}"
        )

    if not output_path:
        date_str = datetime.now().strftime("%Y%m%d")
        output_path = f"VulnForge_Finding_{finding_id}_{date_str}.pdf"

    styles = _styles()
    doc = SimpleDocTemplate(
        output_path, pagesize=A4,
        topMargin=2 * cm, bottomMargin=2 * cm,
        leftMargin=2 * cm, rightMargin=2 * cm,
    )
    story = []

    _cover_page(
        story, styles, scan,
        f"Single Finding Report — {target_finding.get('name', 'Unnamed finding')}",
    )

    story.append(Paragraph("Finding Detail", styles["VFSection"]))
    _finding_block(story, styles, target_finding)

    doc.build(story)
    return os.path.abspath(output_path)
