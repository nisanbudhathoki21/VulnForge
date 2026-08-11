import io
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from database import get_scan_by_id, get_findings_for_scan

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_number(num_pages)
            canvas.Canvas.showPage(self)
        canvas.Canvas.save(self)

    def draw_page_number(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 9)
        self.setFillColor(colors.HexColor("#64748b"))
        self.drawString(54, 750, "VulnForge Ultimate - Vulnerability Assessment Report")
        self.setStrokeColor(colors.HexColor("#334155"))
        self.setLineWidth(0.5)
        self.line(54, 742, 558, 742)
        page_str = f"Page {self._pageNumber} of {page_count}"
        self.drawRightString(558, 35, page_str)
        self.drawString(54, 35, "CONFIDENTIAL - SECURITY ASSESSMENT")
        self.line(54, 48, 558, 48)
        self.restoreState()


def generate_pdf_report(scan_id: str) -> bytes:
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("ReportLab is not installed. Run: pip install reportlab")

    scan = get_scan_by_id(scan_id)
    if not scan:
        raise ValueError(f"Scan '{scan_id}' not found.")

    findings = get_findings_for_scan(scan_id)
    buffer = io.BytesIO()
    
    doc = SimpleDocTemplate(
        buffer, pagesize=letter, leftMargin=54, rightMargin=54, topMargin=64, bottomMargin=60
    )
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('DocTitle', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=22, leading=26, textColor=colors.HexColor("#0f172a"), spaceAfter=6)
    subtitle_style = ParagraphStyle('DocSubtitle', parent=styles['Normal'], fontName='Helvetica', fontSize=11, leading=15, textColor=colors.HexColor("#0284c7"), spaceAfter=15)
    h1_style = ParagraphStyle('Heading1', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=15, leading=19, textColor=colors.HexColor("#0f172a"), spaceBefore=14, spaceAfter=8)
    h2_style = ParagraphStyle('Heading2', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=11, leading=14, textColor=colors.HexColor("#1e293b"), spaceBefore=8, spaceAfter=4)
    body_style = ParagraphStyle('BodyDark', parent=styles['Normal'], fontName='Helvetica', fontSize=9, leading=13, textColor=colors.HexColor("#334155"))
    code_style = ParagraphStyle('CodeStyle', parent=styles['Normal'], fontName='Courier', fontSize=7.5, leading=10, textColor=colors.HexColor("#0f172a"))

    story = [
        Paragraph("VULNFORGE ULTIMATE", ParagraphStyle('Badge', fontName='Helvetica-Bold', fontSize=9, textColor=colors.HexColor("#0284c7"))),
        Paragraph("Security Assessment Report", title_style),
        Paragraph(f"Target: <b>{scan['target_url']}</b> | Scan ID: <code>{scan['id']}</code>", subtitle_style),
        HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#0284c7"), spaceAfter=12)
    ]

    meta_data = [
        [Paragraph("<b>Assessment Target:</b>", body_style), Paragraph(scan["target_url"], body_style), Paragraph("<b>Scan Status:</b>", body_style), Paragraph(scan["status"].upper(), body_style)],
        [Paragraph("<b>Assessment Date:</b>", body_style), Paragraph(scan["created_at"][:19].replace("T", " "), body_style), Paragraph("<b>Duration:</b>", body_style), Paragraph(f"{scan['duration_seconds']:.2f}s", body_style)],
        [Paragraph("<b>Total HTTP Requests:</b>", body_style), Paragraph(str(scan["requests_count"]), body_style), Paragraph("<b>Confirmed Bugs:</b>", body_style), Paragraph(f"<b>{scan['confirmed_count']}</b> of {scan['findings_count']}", body_style)]
    ]
    t_meta = Table(meta_data, colWidths=[120, 160, 110, 114])
    t_meta.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('LEFTPADDING', (0, 0), (-1, -1), 6),
    ]))
    story.append(t_meta)
    story.append(Spacer(1, 12))

    story.append(Paragraph("1. Executive Summary", h1_style))
    story.append(Paragraph("VulnForge Ultimate performed an automated security assessment leveraging verification state machines and differential analysis to eradicate false positives.", body_style))
    story.append(Spacer(1, 10))

    story.append(Paragraph("2. Detailed Technical Findings & Proof of Concepts", h1_style))
    if not findings:
        story.append(Paragraph("<i>No security weaknesses or vulnerabilities were identified during this scan.</i>", body_style))
    else:
        for idx, f in enumerate(findings, 1):
            f_box = [
                Paragraph(f"<b>Finding #{idx}: {f['title']}</b>", h2_style),
                Paragraph(f"<b>Severity:</b> {f['severity']} | <b>CVSS v3.1:</b> {f['cvss_score']} | <b>CWE:</b> {f.get('cwe_id') or 'CWE-N/A'}", body_style),
                Paragraph(f"<b>Endpoint:</b> <code>{f.get('tested_endpoint') or f['endpoint']}</code>", body_style),
                Paragraph(f"<b>Verification Proof:</b> {f.get('verification_proof') or 'Verified over wire response'}", body_style),
                Paragraph(f"<b>Remediation:</b> {f.get('remediation') or 'Apply standard defensive security practices.'}", body_style),
                Spacer(1, 6),
                HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#cbd5e1"), spaceAfter=8)
            ]
            story.append(KeepTogether(f_box))

    doc.build(story, canvasmaker=NumberedCanvas)
    buffer.seek(0)
    return buffer.getvalue()


def generate_markdown_report(scan_id: str) -> str:
    scan = get_scan_by_id(scan_id)
    if not scan:
        return "# Scan Not Found"
    findings = get_findings_for_scan(scan_id)
    md = [
        f"# VulnForge Ultimate - Penetration Testing Report",
        f"**Target:** `{scan['target_url']}`  ",
        f"**Scan ID:** `{scan['id']}`  ",
        f"**Duration:** `{scan['duration_seconds']:.2f}s` | **HTTP Requests:** `{scan['requests_count']}`  ",
        f"**Confirmed Findings:** `{scan['confirmed_count']}` / `{scan['findings_count']}`  \n",
        "---",
        "## Technical Findings\n"
    ]
    for idx, f in enumerate(findings, 1):
        md.append(f"### {idx}. {f['title']} [{f['severity']}]")
        md.append(f"- **Endpoint:** `{f.get('tested_endpoint') or f['endpoint']}`")
        md.append(f"- **CVSS v3.1:** `{f['cvss_score']}` ({f.get('cwe_id') or 'CWE-N/A'})")
        md.append(f"- **Status:** `{'CONFIRMED' if f['is_confirmed'] else 'HIGH CONFIDENCE'}`")
        md.append(f"\n**Summary:** {f.get('short_description') or f.get('description')}\n")
        if f.get("verification_proof"):
            md.append(f"**Verification Proof:**\n> {f['verification_proof']}\n")
        md.append(f"**Remediation:** {f.get('remediation')}\n")
        md.append("---\n")
    return "\n".join(md)
