from __future__ import annotations
from datetime import datetime
from urllib.parse import urlparse
from database.session import SessionLocal
from database.models import DBFinding, DBInvestigationPath


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc or url
    except Exception:
        return url


def _render_finding_report(f: DBFinding, index: int) -> str:
    """Renders a single finding in HackerOne-style report format."""
    lines = []

    lines.append(f"## {index}. {f.title}")
    lines.append("")
    lines.append(f"**Severity:** {f.severity}  ")
    lines.append(f"**Kind:** {f.kind}  ")
    lines.append(f"**Category:** {f.category}")
    lines.append("")

    lines.append("### Executive Summary")
    lines.append("")
    lines.append(
        f"Testing against `{_domain(f.url)}` identified a **{f.title}** issue "
        f"classified under **{f.category}**. This finding is currently rated "
        f"**{f.kind}** and requires manual verification before being submitted "
        f"as a confirmed vulnerability."
    )
    lines.append("")

    lines.append("### Affected Asset")
    lines.append("")
    lines.append(f"- **Domain:** {_domain(f.url)}")
    lines.append(f"- **Endpoint:** `{f.url}`")
    lines.append(f"- **Environment:** Production")
    lines.append("")

    lines.append("### Observed Behavior")
    lines.append("")
    lines.append(f"{f.evidence}")
    lines.append("")

    lines.append("### Steps to Reproduce")
    lines.append("")
    lines.append(f"1. Send a request to the affected endpoint:")
    lines.append(f"   ```")
    lines.append(f"   {f.poc}")
    lines.append(f"   ```")
    lines.append(f"2. Inspect the response headers/body for the evidence described above.")
    lines.append("")

    lines.append("### Proof of Concept (PoC)")
    lines.append("")
    lines.append("```bash")
    lines.append(f"{f.poc}")
    lines.append("```")
    lines.append("")

    lines.append("### Impact")
    lines.append("")
    if f.kind == "Verified":
        lines.append(
            "This behavior was directly observed and confirmed against the live target."
        )
    else:
        lines.append(
            "This is a **potential** issue based on automated detection. It has not "
            "been manually verified and should not be reported as a confirmed "
            "vulnerability until validated by a human researcher."
        )
    lines.append("")

    if f.investigation:
        lines.append("### Related Investigation Path")
        lines.append("")
        lines.append(
            f"This finding is part of a broader investigation lead: "
            f"**{f.investigation.title}** — {f.investigation.reasoning}"
        )
        lines.append("")

    lines.append("---")
    lines.append("")

    return "\n".join(lines)


def generate_markdown_report(scan_id: str) -> str:
    """Builds a full HackerOne-style Markdown report for a given scan_id."""
    db = SessionLocal()
    try:
        findings = db.query(DBFinding).filter(DBFinding.scan_id == scan_id).all()
        paths = db.query(DBInvestigationPath).filter(DBInvestigationPath.scan_id == scan_id).all()

        if not findings:
            return f"# VulnForge Report\n\nNo findings recorded for scan ID `{scan_id}`.\n"

        target = findings[0].url
        generated = datetime.now().strftime("%B %d, %Y")

        lines = []
        lines.append(f"# Security Research Report — {_domain(target)}")
        lines.append("")
        lines.append(f"**Scan ID:** `{scan_id}`  ")
        lines.append(f"**Date:** {generated}  ")
        lines.append(f"**Total Findings:** {len(findings)}")
        lines.append("")
        lines.append("---")
        lines.append("")

        for i, f in enumerate(findings, start=1):
            lines.append(_render_finding_report(f, i))

        if paths:
            lines.append("## Investigation Recommendations")
            lines.append("")
            for p in paths:
                lines.append(f"### 🎯 {p.title}")
                lines.append("")
                lines.append(f"- **Estimated Time:** {p.estimated_time}")
                lines.append(f"- **Confidence:** {p.confidence:.0%}")
                lines.append(f"- **Reasoning:** {p.reasoning}")
                lines.append("")

        lines.append(
            "_Findings labeled `Possible` or `Investigation` require manual "
            "verification before being reported as confirmed vulnerabilities._"
        )
        lines.append("")

        return "\n".join(lines)
    finally:
        db.close()
