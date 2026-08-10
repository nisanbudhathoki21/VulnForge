#!/usr/bin/env python3
"""
terminal/dashboard.py - VulnForge Dashboard Generator (v2)

Builds a single self-contained HTML dashboard from the SQLite database
in core/database.py. No hardcoded/sample data: every number here comes
from a live query against vulnforge.db.

v2 additions:
  - Every finding row is expandable: click it to reveal exact payload,
    exact endpoint, and a plain-English what/how/why explanation
    (via explain_engine.py), so non-technical readers understand it.
  - Search box + severity filter + "confirmed only" toggle.
  - Cleaner card/table visual design.

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
from .explain_engine import explain_finding
from .pdf_summary import build_summary_pdf

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "informational"]

SEVERITY_COLORS = {
    "critical": "#dc2626",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    "info": "#475569",
    "informational": "#475569",
}


def _esc(value: Any) -> str:
    return html.escape(str(value if value is not None else ""))


def _severity_badge(sev: str) -> str:
    sev_l = (sev or "info").lower()
    color = SEVERITY_COLORS.get(sev_l, "#475569")
    return (
        f'<span class="badge" style="background:{color};">{_esc(sev_l)}</span>'
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
    known = {s.lower() for s, _ in ordered_sev}
    extra_sev = [
        (k, v) for k, v in severity_counts.items() if k.lower() not in known
    ]

    summary_cards = "".join(
        f'''<div class="card sev-card" data-sev="{_esc(k.lower())}"
             style="border-top:3px solid {SEVERITY_COLORS.get(k.lower(),"#475569")}"
             onclick="filterBySeverity('{_esc(k.lower())}')">
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

    finding_blocks = []
    for i, f in enumerate(all_findings):
        expl = explain_finding(f)
        sev = (f.get("severity") or "info").lower()
        confirmed = "Yes" if f.get("confirmed") else "No"
        confidence = f.get("confidence", 0.0) or 0.0
        row_id = f"finding-{i}"

        payload_html = (
            f'<code class="payload">{_esc(expl["payload"])}</code>'
            if expl["payload"] else '<span class="muted">No distinct payload recorded</span>'
        )

        if expl["response_preview"]:
            status_prefix = f'HTTP {_esc(expl["response_status"])} — ' if expl["response_status"] else ""
            resp_display = _esc(expl["response_preview"]).replace("\\n", "<br>").replace(chr(10), "<br>")
            response_html = f'<code class="response">{status_prefix}{resp_display}</code>'
        else:
            response_html = '<span class="muted">No response body recorded</span>'

        finding_blocks.append(f'''
        <tr class="finding-row" data-scan="{_esc(f.get('_scan_id'))}"
            data-sev="{_esc(sev)}" data-confirmed="{1 if f.get('confirmed') else 0}"
            data-search="{_esc((f.get('name','') + ' ' + expl['endpoint'] + ' ' + str(expl['payload'] or '')).lower())}"
            onclick="document.getElementById('{row_id}').classList.toggle('hidden'); this.classList.toggle('open');">
            <td>{_severity_badge(sev)}</td>
            <td>{_esc(f.get('name'))}</td>
            <td>{_esc(f.get('_target'))}</td>
            <td><code class="endpoint">{_esc(expl['method'])} {_esc(expl['endpoint'])[:50]}</code></td>
            <td>{confidence:.2f}</td>
            <td>{_esc(confirmed)}</td>
            <td class="chev">&#9656;</td>
        </tr>
        <tr id="{row_id}" class="detail-row hidden" data-scan="{_esc(f.get('_scan_id'))}"
            data-sev="{_esc(sev)}" data-confirmed="{1 if f.get('confirmed') else 0}">
            <td colspan="7">
              <div class="detail-panel">
                <div class="detail-title">{_esc(expl['what'])}</div>
                <div class="detail-grid">
                  <div>
                    <div class="dl">Endpoint hit</div>
                    <code class="block">{_esc(expl['method'])} {_esc(expl['full_url'])}</code>
                  </div>
                  <div>
                    <div class="dl">Payload used</div>
                    <div class="block">{payload_html}</div>
                  </div>
                </div>
                <div class="detail-grid">
                  <div>
                    <div class="dl">Server response</div>
                    <div class="block resp-block">{response_html}</div>
                  </div>
                  <div>
                    <div class="dl">Confidence / status</div>
                    <div class="block">{confidence:.2f} confidence &middot; {'Confirmed' if f.get('confirmed') else 'Unconfirmed'}</div>
                  </div>
                </div>
                <div class="explain-grid">
                  <div><div class="dl">What was tested</div><p>{_esc(expl['how'])}</p></div>
                  <div><div class="dl">Why it matters</div><p>{_esc(expl['why'])}</p></div>
                </div>
              </div>
            </td>
        </tr>''')

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Generate a HackerOne-style PDF summary right next to the dashboard,
    # and link to it -- so "download report" is a real, working link,
    # not a placeholder. Best-effort: a PDF failure should never break
    # dashboard generation.
    out_dir = Path(output_path).resolve().parent
    pdf_filename = "vulnforge_summary_report.pdf"
    pdf_path = out_dir / pdf_filename
    pdf_ready = False
    try:
        build_summary_pdf(all_findings, str(pdf_path), title="VulnForge Summary Report")
        pdf_ready = True
    except Exception as exc:  # noqa: BLE001 - best-effort, never block the dashboard
        print(f"[DASHBOARD] Warning: could not generate PDF summary: {exc}")

    download_button = (
        f'<a class="pdf-btn" href="{pdf_filename}" download>&#8681; Download Full Report (PDF)</a>'
        if pdf_ready else
        '<span class="pdf-btn disabled">PDF generation unavailable (see terminal output)</span>'
    )

    html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnForge Dashboard</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 28px 32px 60px;
    background: #0b1120; color: #e2e8f0;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
  }}
  h1 {{ font-size: 24px; margin: 0 0 4px 0; letter-spacing: -0.02em; }}
  .subtitle {{ color: #94a3b8; font-size: 13px; margin-bottom: 24px; }}
  .cards {{
    display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
    gap: 12px; margin-bottom: 28px;
  }}
  .card {{
    background: #111827; border: 1px solid #1f2937; border-radius: 10px;
    padding: 16px; text-align: center;
  }}
  .card-value {{ font-size: 28px; font-weight: 700; }}
  .card-label {{ font-size: 12px; color: #94a3b8; margin-top: 4px; text-transform: uppercase; letter-spacing: .04em; }}
  .top-stats {{ display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }}
  .stat-box {{
    background: linear-gradient(180deg,#111827,#0f1725); border: 1px solid #1f2937; border-radius: 10px;
    padding: 14px 20px; min-width: 140px;
  }}
  .stat-box .n {{ font-size: 24px; font-weight: 700; color: #38bdf8; }}
  .stat-box .l {{ font-size: 12px; color: #94a3b8; }}
  section {{ margin-bottom: 32px; }}
  h2 {{ font-size: 14px; text-transform: uppercase; letter-spacing: .06em;
        color: #94a3b8; border-bottom: 1px solid #1f2937; padding-bottom: 8px;
        display:flex; justify-content:space-between; align-items:center; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; padding: 8px 10px; color: #94a3b8; font-weight: 600;
        border-bottom: 1px solid #1f2937; }}
  td {{ padding: 9px 10px; border-bottom: 1px solid #16202f; vertical-align: top; }}
  tr.scan-row {{ cursor: pointer; }}
  tr.scan-row:hover {{ background: #131c2e; }}
  tr.finding-row {{ cursor: pointer; }}
  tr.finding-row:hover {{ background: #131c2e; }}
  tr.finding-row.open {{ background: #131c2e; }}
  .chev {{ text-align:right; color:#475569; transition: transform .15s; }}
  tr.finding-row.open .chev {{ transform: rotate(90deg); color:#38bdf8; }}
  tr.detail-row td {{ padding: 0; border-bottom: 1px solid #1f2937; }}
  tr.detail-row.hidden {{ display: none; }}
  .detail-panel {{ background:#0d1524; padding:16px 20px; border-left:3px solid #38bdf8; }}
  .detail-title {{ font-weight:700; font-size:14px; color:#38bdf8; margin-bottom:10px; }}
  .detail-grid, .explain-grid {{ display:grid; grid-template-columns: 1fr 1fr; gap:16px; margin-bottom:12px; }}
  .dl {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#64748b; margin-bottom:4px; }}
  .block {{ background:#111827; border:1px solid #1f2937; border-radius:6px; padding:8px 10px;
            font-family: Consolas, Menlo, monospace; font-size:12px; word-break:break-all; }}
  code.payload {{ font-family: Consolas, Menlo, monospace; font-size:12px; color:#fca5a5; }}
  code.endpoint {{ background:#0f172a; padding:1px 5px; border-radius:4px; font-size:11px; }}
  p {{ margin: 0; font-size: 13px; line-height: 1.5; color:#cbd5e1; }}
  .muted {{ color:#64748b; font-style: italic; }}
  code {{ background: #0f172a; padding: 1px 5px; border-radius: 4px; }}
  .badge {{ color:#fff; padding:2px 9px; border-radius:5px; font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:.03em; }}
  .empty {{ color: #64748b; font-style: italic; padding: 12px 0; }}
  .hidden {{ display: none; }}
  .controls {{ display:flex; gap:10px; flex-wrap:wrap; align-items:center; }}
  .controls input[type=text] {{
    background:#111827; border:1px solid #1f2937; color:#e2e8f0; border-radius:6px;
    padding:6px 10px; font-size:12px; width:220px;
  }}
  .controls select {{
    background:#111827; border:1px solid #1f2937; color:#e2e8f0; border-radius:6px;
    padding:6px 8px; font-size:12px;
  }}
  .controls label {{ font-size:12px; color:#94a3b8; display:flex; align-items:center; gap:4px; }}
  .header-row {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:24px; flex-wrap:wrap; gap:12px; }}
  .pdf-btn {{
    background:#38bdf8; color:#04141f; font-weight:700; font-size:13px;
    padding:10px 18px; border-radius:8px; text-decoration:none; white-space:nowrap;
    box-shadow: 0 1px 0 rgba(0,0,0,.2); transition: filter .15s;
  }}
  .pdf-btn:hover {{ filter: brightness(1.08); }}
  .pdf-btn.disabled {{ background:#1f2937; color:#64748b; cursor:default; padding:10px 18px; border-radius:8px; font-size:12px; }}
  .sev-card {{ cursor:pointer; transition: transform .1s, background .15s; }}
  .sev-card:hover {{ background:#151f31; transform: translateY(-1px); }}
  .sev-card.active-filter {{ outline: 2px solid #38bdf8; }}
  code.response {{ font-family: Consolas, Menlo, monospace; font-size:12px; color:#93c5fd; white-space:pre-wrap; word-break:break-all; }}
  .resp-block {{ max-height:140px; overflow-y:auto; }}
</style>
</head>
<body>

<div class="header-row">
  <div>
    <h1>VulnForge Dashboard</h1>
    <div class="subtitle">Live from vulnforge.db &middot; generated {_esc(generated_at)}</div>
  </div>
  {download_button}
</div>

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
  <h2>
    <span>Findings &mdash; click a row to see the exact payload &amp; plain-English explanation</span>
    <span class="controls">
      <input type="text" id="searchBox" placeholder="Search name / endpoint / payload...">
      <select id="sevFilter">
        <option value="">All severities</option>
        <option value="critical">Critical</option>
        <option value="high">High</option>
        <option value="medium">Medium</option>
        <option value="low">Low</option>
        <option value="info">Info</option>
      </select>
      <label><input type="checkbox" id="confirmedOnly"> Confirmed only</label>
    </span>
  </h2>
  <table>
    <thead>
      <tr><th>Severity</th><th>Name</th><th>Target</th><th>Endpoint</th><th>Confidence</th><th>Confirmed</th><th></th></tr>
    </thead>
    <tbody id="findings-body">
      {''.join(finding_blocks) if finding_blocks else '<tr><td colspan="7" class="empty">No findings recorded yet.</td></tr>'}
    </tbody>
  </table>
</section>

<script>
  const findingRows = Array.from(document.querySelectorAll('.finding-row'));
  const detailRows = Array.from(document.querySelectorAll('.detail-row'));

  document.querySelectorAll('.scan-row').forEach(row => {{
    row.addEventListener('click', () => {{
      const scanId = row.dataset.scan;
      findingRows.forEach(fr => {{
        const match = fr.dataset.scan === scanId;
        fr.classList.toggle('hidden', !match);
      }});
      detailRows.forEach(dr => {{
        if (dr.dataset.scan !== scanId) dr.classList.add('hidden');
      }});
      applyFilters();
    }});
  }});

  function applyFilters() {{
    const q = document.getElementById('searchBox').value.toLowerCase();
    const sev = document.getElementById('sevFilter').value;
    const confirmedOnly = document.getElementById('confirmedOnly').checked;

    findingRows.forEach((fr, idx) => {{
      const detail = detailRows[idx];
      let visible = true;
      if (q && !fr.dataset.search.includes(q)) visible = false;
      if (sev && fr.dataset.sev !== sev) visible = false;
      if (confirmedOnly && fr.dataset.confirmed !== '1') visible = false;
      fr.style.display = visible ? '' : 'none';
      if (!visible) detail.classList.add('hidden');
      detail.style.display = visible ? '' : 'none';
    }});
  }}

  document.getElementById('searchBox').addEventListener('input', applyFilters);
  document.getElementById('sevFilter').addEventListener('change', applyFilters);
  document.getElementById('confirmedOnly').addEventListener('change', applyFilters);

  function filterBySeverity(sev) {{
    const select = document.getElementById('sevFilter');
    const cards = document.querySelectorAll('.sev-card');
    if (select.value === sev) {{
      // clicking the same card again clears the filter
      select.value = '';
      cards.forEach(c => c.classList.remove('active-filter'));
    }} else {{
      select.value = sev;
      cards.forEach(c => c.classList.toggle('active-filter', c.dataset.sev === sev));
    }}
    applyFilters();
    document.getElementById('findings-body').scrollIntoView({{ behavior: 'smooth', block: 'start' }});
  }}
</script>

</body>
</html>"""

    out = Path(output_path)
    out.write_text(html_doc, encoding="utf-8")
    return str(out.resolve())


if __name__ == "__main__":
    path = generate_dashboard()
    print(f"[DASHBOARD] Written to {path}")
