#!/usr/bin/env python3
"""
terminal/dashboard.py - VulnForge Dashboard Generator

Builds a single self-contained HTML dashboard from the SQLite database
in core/database.py. No hardcoded/sample data: every number here comes
from a live query against vulnforge.db.

Usage:
    from terminal.dashboard import generate_dashboard
    path = generate_dashboard()
"""

from __future__ import annotations

import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from core.database import get_scan, get_scans, get_statistics, init_db

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "informational"]

SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#15803d",
    "info": "#334155",
    "informational": "#334155",
}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _severity_badge(sev: str) -> str:
    sev_l = (sev or "info").lower()
    color = SEVERITY_COLORS.get(sev_l, "#334155")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;'
        f'border-radius:4px;font-size:12px;font-weight:600;text-transform:'
        f'uppercase;">{_esc(sev_l)}</span>'
    )


def _collect_findings(scans_detail: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings = []
    for scan in scans_detail:
        for f in scan.get("findings", []):
            enriched = dict(f)
            enriched["_scan_id"] = scan.get("scan_id")
            enriched["_target"] = scan.get("target")
            findings.append(enriched)
    return findings


def generate_dashboard(
    output_path: str = "vulnforge_dashboard.html",
    scan_limit: int = 50,
) -> str:
    """
    Generate the dashboard HTML file and return its path. Reads
    exclusively from core.database - no hardcoded sample data.
    """
    init_db()

    stats = get_statistics() or {}
    scans = get_scans(limit=scan_limit)

    # Pull full detail (including findings) for each recent scan so
    # the dashboard can offer per-finding drilldown without a backend.
    scans_detail = []
    for s in scans:
        full = get_scan(s.get("scan_id"))
        if full:
            scans_detail.append(full)

    all_findings = _collect_findings(scans_detail)

    severity_counts = stats.get("severity_counts", {}) or {}
    ordered_sev = [
        (sev, severity_counts.get(sev, severity_counts.get(sev.capitalize(), 0)))
        for sev in ["critical", "high", "medium", "low", "info"]
    ]
    # Catch any severities not in the standard list (e.g. custom labels)
    known = {s.lower() for s, _ in ordered_sev}
    extra_sev = [
        (k, v) for k, v in severity_counts.items() if k.lower() not in known
    ]

    summary_cards = "".join(
        f'''<div class="card">
            <div class="card-value">{v}</div>
            <div class="card-label">{_esc(k.capitalize())}</div>
        </div>'''
        for k, v in (ordered_sev + extra_sev)
    )

    scan_rows = []
    for s in scans:
        scan_rows.append(f'''
        <tr class="scan-row" data-scan="{_esc(s.get('scan_id'))}">
            <td><code>{_esc(s.get('scan_id'))}</code></td>
            <td>{_esc(s.get('target'))}</td>
            <td>{_esc(s.get('status'))}</td>
            <td>{_esc(s.get('findings_count'))}</td>
            <td>{_esc(s.get('requests_sent'))}</td>
            <td>{_esc(round(s.get('scan_duration') or 0, 2))}s</td>
            <td>{_esc(s.get('timestamp'))}</td>
        </tr>''')

    finding_rows = []
    for f in all_findings:
        evidence = f.get("evidence") or {}
        endpoint = evidence.get("url", "") if isinstance(evidence, dict) else ""
        occurrences = (
            evidence.get("occurrences", 1) if isinstance(evidence, dict) else 1
        )
        confirmed = "Yes" if f.get("confirmed") else "No"
        confidence = f.get("confidence", 0.0) or 0.0
        finding_rows.append(f'''
        <tr class="finding-row" data-scan="{_esc(f.get('_scan_id'))}">
            <td>{_severity_badge(f.get('severity'))}</td>
            <td>{_esc(f.get('name'))}</td>
            <td>{_esc(f.get('_target'))}</td>
            <td><code style="font-size:11px;">{_esc(endpoint)[:60]}</code></td>
            <td>{confidence:.2f}</td>
            <td>{_esc(confirmed)}</td>
            <td>{_esc(occurrences)}</td>
            <td><code>{_esc(f.get('_scan_id'))}</code></td>
        </tr>''')

    findings_json = json.dumps(all_findings, default=str)

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnForge Dashboard</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 24px;
    background: #0b1120; color: #e2e8f0;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  }}
  h1 {{ font-size: 22px; margin: 0 0 4px 0; }}
  .subtitle {{ color: #94a3b8; font-size: 13px; margin-bottom: 24px; }}
  .cards {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 12px; margin-bottom: 28px;
  }}
  .card {{
    background: #111827; border: 1px solid #1f2937; border-radius: 10px;
    padding: 16px; text-align: center;
  }}
  .card-value {{ font-size: 26px; font-weight: 700; }}
  .card-label {{ font-size: 12px; color: #94a3b8; margin-top: 4px; }}
  .top-stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat-box {{
    background: #111827; border: 1px solid #1f2937; border-radius: 10px;
    padding: 14px 20px; min-width: 140px;
  }}
  .stat-box .n {{ font-size: 22px; font-weight: 700; color: #38bdf8; }}
  .stat-box .l {{ font-size: 12px; color: #94a3b8; }}
  section {{ margin-bottom: 32px; }}
  h2 {{ font-size: 15px; text-transform: uppercase; letter-spacing: .05em;
        color: #94a3b8; border-bottom: 1px solid #1f2937; padding-bottom: 8px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 10px; color: #94a3b8; font-weight: 600;
        border-bottom: 1px solid #1f2937; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid #16202f; vertical-align: top; }}
  tr.scan-row {{ cursor: pointer; }}
  tr.scan-row:hover {{ background: #131c2e; }}
  code {{ background: #0f172a; padding: 1px 5px; border-radius: 4px; }}
  .empty {{ color: #64748b; font-style: italic; padding: 12px 0; }}
  .hidden {{ display: none; }}
</style>
</head>
<body>

<h1>VulnForge Dashboard</h1>
<div class="subtitle">Live from vulnforge.db &middot; generated {_esc(generated_at)}</div>

<div class="top-stats">
  <div class="stat-box"><div class="n">{stats.get('total_scans', 0)}</div><div class="l">Total Scans</div></div>
  <div class="stat-box"><div class="n">{stats.get('total_findings', 0)}</div><div class="l">Total Findings</div></div>
  <div class="stat-box"><div class="n">{stats.get('unique_targets', 0)}</div><div class="l">Unique Targets</div></div>
  <div class="stat-box"><div class="n">{round(stats.get('avg_findings_per_scan', 0) or 0, 1)}</div><div class="l">Avg Findings / Scan</div></div>
</div>

<section>
  <h2>Findings by Severity</h2>
  <div class="cards">
    {summary_cards if summary_cards else '<div class="empty">No findings recorded yet.</div>'}
  </div>
</section>

<section>
  <h2>Recent Scans</h2>
  <table>
    <thead>
      <tr><th>Scan ID</th><th>Target</th><th>Status</th><th>Findings</th><th>Requests</th><th>Duration</th><th>Timestamp</th></tr>
    </thead>
    <tbody>
      {''.join(scan_rows) if scan_rows else '<tr><td colspan="7" class="empty">No scans recorded yet.</td></tr>'}
    </tbody>
  </table>
</section>

<section>
  <h2>Findings (click a scan row above to filter)</h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Name</th><th>Target</th><th>Endpoint</th><th>Confidence</th><th>Confirmed</th><th>Occurrences</th><th>Scan ID</th></tr>
    </thead>
    <tbody id="findings-body">
      {''.join(finding_rows) if finding_rows else '<tr><td colspan="8" class="empty">No findings recorded yet.</td></tr>'}
    </tbody>
  </table>
</section>

<script>
  const allFindingRows = Array.from(document.querySelectorAll('.finding-row'));
  document.querySelectorAll('.scan-row').forEach(row => {{
    row.addEventListener('click', () => {{
      const scanId = row.dataset.scan;
      allFindingRows.forEach(fr => {{
        fr.classList.toggle('hidden', fr.dataset.scan !== scanId);
      }});
    }});
  }});
</script>

</body>
</html>"""

    out = Path(output_path)
    out.write_text(html_doc, encoding="utf-8")
    return str(out.resolve())


if __name__ == "__main__":
    path = generate_dashboard()
    print(f"[DASHBOARD] Written to {path}")
