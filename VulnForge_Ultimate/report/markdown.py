from __future__ import annotations
from typing import List
from workspace.models import Finding
from risk.engine import score
def to_markdown(ws_name: str, findings: List[Finding]) -> str:
    lines = [f"# VulnForge Report: {ws_name}"]
    lines.append("")
    lines.append(f"**Total Findings:** {len(findings)}")
    lines.append("")
    critical = [f for f in findings if f.severity == "Critical"]
    high = [f for f in findings if f.severity == "High"]
    medium = [f for f in findings if f.severity == "Medium"]
    low = [f for f in findings if f.severity == "Low"]
    lines.append("## Summary")
    lines.append(f"- 🔴 Critical: {len(critical)}")
    lines.append(f"- 🟠 High: {len(high)}")
    lines.append(f"- 🟡 Medium: {len(medium)}")
    lines.append(f"- 🟢 Low: {len(low)}")
    lines.append("")
    lines.append("## Findings")
    for f in sorted(findings, key=lambda x: score(x)["priority"], reverse=True):
        s = score(f)
        lines.append(f"### {s['band']} {f.title}")
        lines.append(f"**Severity:** {f.severity}")
        lines.append(f"**Confidence:** {f.confidence:.0%}")
        lines.append(f"**Kind:** {f.kind}")
        lines.append(f"**Priority:** {s['priority']}")
        if f.context:
            lines.append("**Context:**")
            for k, v in f.context.items():
                lines.append(f"  - {k}: {v}")
        if f.references:
            lines.append("**References:**")
            for ref in f.references:
                lines.append(f"  - {ref}")
        lines.append("")
    return "\n".join(lines)
