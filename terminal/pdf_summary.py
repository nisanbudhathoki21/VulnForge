"""
pdf_summary.py
--------------
Generates a compact, HackerOne-style PDF summary directly from the list
of findings the dashboard already has in memory (no separate DB query
needed). Used by terminal/dashboard.py to produce a "Download Full
Report" link right next to the live dashboard.

This is intentionally shorter/denser than report_gen/generate_report.py
(which does one full page per finding) -- this one is a scannable
summary: title, severity, target/endpoint, payload, response, plain-
English impact, and remediation, several findings per page.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable
)

from .explain_engine import explain_finding

SEVERITY_COLORS = {
    "critical": colors.HexColor("#da3633"),
    "high": colors.HexColor("#e0742a"),
    "medium": colors.HexColor("#d29922"),
    "low": colors.HexColor("#3fb950"),
    "info": colors.HexColor("#8b949e"),
}


def _styles():
    s = getSampleStyleSheet()
    s.add(ParagraphStyle(name="Title2", fontSize=20, leading=24, spaceAfter=4,
                          fontName="Helvetica-Bold", textColor=colors.HexColor("#0d1117")))
    s.add(ParagraphStyle(name="Sub2", fontSize=10, textColor=colors.HexColor("#57606a"), spaceAfter=16))
    s.add(ParagraphStyle(name="FTitle", fontSize=12.5, fontName="Helvetica-Bold",
                          textColor=colors.HexColor("#0d1117")))
    s.add(ParagraphStyle(name="Small", fontSize=9, leading=13, textColor=colors.HexColor("#24292f")))
    s.add(ParagraphStyle(name="SmallLabel", fontSize=8, fontName="Helvetica-Bold",
                          textColor=colors.HexColor("#57606a"), spaceBefore=5, spaceAfter=1))
    s.add(ParagraphStyle(name="Mono", fontSize=8, fontName="Courier", leading=11,
                          textColor=colors.HexColor("#b91c1c"), backColor=colors.HexColor("#f6f8fa"),
                          borderPadding=5))
    s.add(ParagraphStyle(name="MonoResp", fontSize=8, fontName="Courier", leading=11,
                          textColor=colors.HexColor("#1f2328"), backColor=colors.HexColor("#f0f7ff"),
                          borderPadding=5))
    return s


def _badge(sev):
    sev = (sev or "info").lower()
    color = SEVERITY_COLORS.get(sev, colors.grey)
    t = Table([[sev.upper()]], colWidths=[0.95 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), color),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def build_summary_pdf(findings: list, out_path: str, title: str = "VulnForge Summary Report") -> int:
    """
    findings: list of finding dicts, each expected to have at minimum
    name/severity/template_id/evidence/_target (or 'scan_target')/confirmed.
    Writes a PDF to out_path. Returns number of findings included.
    """
    styles = _styles()
    story = []

    story.append(Paragraph(title, styles["Title2"]))
    story.append(Paragraph(
        f"Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} &middot; "
        f"{len(findings)} finding(s) &middot; scoped to targets in current dashboard view",
        styles["Sub2"]
    ))
    story.append(HRFlowable(width="100%", color=colors.HexColor("#d0d7de"), thickness=1))
    story.append(Spacer(1, 12))

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(findings, key=lambda f: sev_order.get((f.get("severity") or "info").lower(), 5))

    for i, f in enumerate(ordered, 1):
        expl = explain_finding(f)
        sev = (f.get("severity") or "info").lower()
        target = f.get("_target") or f.get("scan_target") or "—"
        confirmed = "Confirmed" if f.get("confirmed") else "Unconfirmed"

        head = Table(
            [[Paragraph(f"{i}. {f.get('name','')}", styles["FTitle"]), _badge(sev)]],
            colWidths=[5.0 * inch, 1.1 * inch]
        )
        head.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "MIDDLE"), ("ALIGN", (1, 0), (1, 0), "RIGHT")]))
        story.append(head)

        story.append(Paragraph(
            f"<b>Target:</b> {target} &nbsp;&nbsp; <b>Status:</b> {confirmed} &nbsp;&nbsp; "
            f"<b>Confidence:</b> {f.get('confidence', 0) or 0:.2f}",
            styles["Small"]
        ))

        story.append(Paragraph("REQUEST", styles["SmallLabel"]))
        story.append(Paragraph(f"{expl['method']} {expl['full_url']}", styles["Small"]))

        if expl["payload"]:
            story.append(Paragraph("PAYLOAD", styles["SmallLabel"]))
            story.append(Paragraph(expl["payload"].replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"),
                                    styles["Mono"]))

        if expl["response_preview"]:
            status_line = f"HTTP {expl['response_status']} — " if expl["response_status"] else ""
            story.append(Paragraph("RESPONSE", styles["SmallLabel"]))
            resp_escaped = (expl["response_preview"]
                            .replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                            .replace("\\n", "<br/>").replace("\n", "<br/>"))
            story.append(Paragraph(status_line + resp_escaped, styles["MonoResp"]))

        story.append(Paragraph("WHAT THIS MEANS (plain English)", styles["SmallLabel"]))
        story.append(Paragraph(expl["why"], styles["Small"]))

        if f.get("remediation"):
            story.append(Paragraph("FIX", styles["SmallLabel"]))
            story.append(Paragraph(str(f.get("remediation")), styles["Small"]))

        story.append(Spacer(1, 8))
        story.append(HRFlowable(width="100%", color=colors.HexColor("#eaeef2"), thickness=0.5))
        story.append(Spacer(1, 10))

    if not findings:
        story.append(Paragraph("No findings to report.", styles["Small"]))

    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        topMargin=0.55 * inch, bottomMargin=0.55 * inch,
        leftMargin=0.6 * inch, rightMargin=0.6 * inch,
        title=title,
    )
    doc.build(story)
    return len(findings)
