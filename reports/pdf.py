from __future__ import annotations
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from sqlalchemy.orm import Session
from database.models import Scan, Vulnerability, AIAnalysis

def _sec(sev: str) -> str:
    s = (sev or "").lower()
    return {"critical":"CRITICAL","high":"HIGH","medium":"MEDIUM","low":"LOW","info":"INFO"}.get(s, s.upper() or "INFO")

def _mk_table(data: List[List[str]], col_widths=None) -> Table:
    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#0D47A1")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 11),
        ("BOTTOMPADDING", (0,0), (-1,0), 8),
        ("BACKGROUND", (0,1), (-1,-1), colors.HexColor("#F5F5F5")),
        ("GRID", (0,0), (-1,-1), 0.25, colors.grey),
    ]))
    return t

def generate_pdf_report(db: Session, scan_id: int, target_url: str, risk_score: int, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    pdf_path = output_dir / f"VulnForge_Report_scan_{scan_id}_{ts}.pdf"

    scan: Scan = db.get(Scan, scan_id)  # type: ignore
    vulns: List[Vulnerability] = db.query(Vulnerability).filter(Vulnerability.scan_id == scan_id).all()
    ai_rows: List[AIAnalysis] = db.query(AIAnalysis).filter(AIAnalysis.scan_id == scan_id).all()

    # Split executive vs per-finding
    exec_row: Optional[AIAnalysis] = next((r for r in ai_rows if r.vuln_id is None), None)
    per_finding = {r.vuln_id: r for r in ai_rows if r.vuln_id is not None}

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]; h1.textColor = colors.HexColor("#0D47A1")
    h2 = styles["Heading2"]; h2.textColor = colors.HexColor("#1565C0")
    body = styles["BodyText"]
    small = ParagraphStyle("small", parent=body, fontSize=9, leading=12)

    doc = SimpleDocTemplate(str(pdf_path), pagesize=A4, rightMargin=2*cm, leftMargin=2*cm, topMargin=2*cm, bottomMargin=2*cm)
    story: List[Any] = []

    # Cover
    story.append(Paragraph("VulnForge — Security Assessment Report", h1))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: {target_url}", body))
    story.append(Paragraph(f"Scan ID: {scan_id}", body))
    story.append(Paragraph(f"Scan Date (UTC): {scan.started_at.strftime('%Y-%m-%d %H:%M:%S')}", body))
    story.append(Paragraph(f"Templates Executed: {scan.total_templates}", body))
    story.append(Paragraph(f"Findings: {scan.findings_count}", body))
    story.append(Paragraph(f"Overall Risk Score: {risk_score}/100", body))
    story.append(Spacer(1, 12))

    # Executive Summary
    story.append(Paragraph("Executive Summary", h2))
    exec_text = exec_row.summary if exec_row and exec_row.summary else f"Scan of {target_url} identified {scan.findings_count} findings. Prioritize remediation by severity."
    story.append(Paragraph(exec_text, body))
    story.append(Spacer(1, 6))

    # Priority Order (from AI row prevention field stores final_conclusion; priority is in DB only as individual rows; keep concise)
    if vulns:
        pri_data = [["Severity", "Name", "URL"]]
        # Sort by severity
        order = {"critical":5,"high":4,"medium":3,"low":2,"info":1}
        for v in sorted(vulns, key=lambda x: order.get((x.severity or "").lower(), 1), reverse=True):
            pri_data.append([_sec(v.severity), v.name, v.url])
        story.append(_mk_table(pri_data, col_widths=[3*cm, 7*cm, 6*cm]))
        story.append(Spacer(1, 12))

    # Findings details
    story.append(Paragraph("Vulnerability Details", h2))
    if not vulns:
        story.append(Paragraph("No findings detected by the scanner.", body))
    else:
        for i, v in enumerate(vulns, start=1):
            story.append(Paragraph(f"{i}. {v.name} [{_sec(v.severity)}]", styles["Heading3"]))
            story.append(Paragraph(f"Category: {v.category}", small))
            story.append(Paragraph(f"URL: {v.url}", small))
            story.append(Paragraph(f"Status Code: {v.status_code} | Response Time: {v.response_time:.2f}s", small))
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Evidence</b>: " + (v.evidence or "N/A"), body))
            story.append(Spacer(1, 4))
            story.append(Paragraph("<b>Recommendation</b>: " + (v.recommendation or "N/A"), body))

            a: Optional[AIAnalysis] = per_finding.get(v.id)
            if a:
                story.append(Spacer(1, 6))
                story.append(Paragraph("<b>AI Analysis</b>", styles["Heading4"]))
                if a.simple_explanation: story.append(Paragraph(f"- Simple: {a.simple_explanation}", body))
                if a.technical_explanation: story.append(Paragraph(f"- Technical: {a.technical_explanation}", body))
                if a.business_impact: story.append(Paragraph(f"- Business Impact: {a.business_impact}", body))
                if a.suggested_severity: story.append(Paragraph(f"- Suggested Severity: {_sec(a.suggested_severity)}", body))
                if a.confidence is not None: story.append(Paragraph(f"- Confidence: {a.confidence:.2f}", body))
                if a.remediation: story.append(Paragraph(f"- Remediation: {a.remediation}", body))
                if a.prevention: story.append(Paragraph(f"- Prevention Tips: {a.prevention}", body))
            story.append(Spacer(1, 10))
        story.append(PageBreak())

    # Conclusion
    story.append(Paragraph("Conclusion", h2))
    concl = exec_row.prevention if exec_row and exec_row.prevention else "Address higher severity items first and implement systemic prevention controls."
    story.append(Paragraph(concl, body))

    doc.build(story)
    return pdf_path
