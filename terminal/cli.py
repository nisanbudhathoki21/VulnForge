from __future__ import annotations
import argparse
import asyncio
import json
import os
import uuid
from datetime import datetime
from dataclasses import asdict

from correlation.engine import CorrelationEngine
from workspace.models import Finding
from httpclient.client import HttpClient
from scanner.engine import Scanner
from templates.loader import TemplateLoader
from terminal.ui import StartupBanner, LogPrinter, LogStyleReporter
from database.session import init_db, SessionLocal
from database.repo import FindingRepository
from database.models import DBFinding
from report.scan_report import generate_markdown_report


def parse_args():
    parser = argparse.ArgumentParser(prog="VulnForge", description="VulnForge Security Research Platform")
    parser.add_argument("-u", "--url", help="Target URL to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    parser.add_argument("--history", action="store_true", help="Show past scan findings from the local database")
    parser.add_argument("--scan-id", help="Filter --history results to a specific scan ID")
    parser.add_argument("--report", metavar="SCAN_ID", help="Generate a Markdown report for a past scan ID")
    return parser.parse_args()


async def run_scan(target: str, reporter):
    loader = TemplateLoader()
    templates = sorted(loader.load_all(), key=lambda t: t.category)

    if reporter:
        reporter.phase("Recon")
        reporter.running(f"Loaded {len(templates)} templates. Scanning {target}")

    all_findings = []
    total_requests = 0

    http = HttpClient()
    try:
        scanner = Scanner(http)
        current_category = None

        for tpl in templates:
            if reporter and tpl.category != current_category:
                current_category = tpl.category
                reporter.phase(current_category)

            result = await scanner.run_template(ws=None, base_url=target, tpl=tpl)
            all_findings.extend(result.findings)
            total_requests += result.request_count

            if reporter:
                for _ in range(result.request_count):
                    reporter.register_request()

                if result.findings:
                    for f in result.findings:
                        reporter.finding(
                            title=f.title,
                            severity=f.severity,
                            endpoint=f.context.get("url", "unknown"),
                            evidence=f.context.get("evidence", ""),
                        )
                else:
                    reporter.passed(f"No issues found ({tpl.name})")
    finally:
        await http.close()

    return all_findings, total_requests


def show_history(scan_id_filter, json_mode):
    init_db()
    db = SessionLocal()
    try:
        query = db.query(DBFinding)
        if scan_id_filter:
            query = query.filter(DBFinding.scan_id == scan_id_filter)
        rows = query.order_by(DBFinding.timestamp.desc()).all()

        if json_mode:
            output = [
                {
                    "id": r.id,
                    "finding_uuid": r.finding_uuid,
                    "scan_id": r.scan_id,
                    "title": r.title,
                    "severity": r.severity,
                    "kind": r.kind,
                    "category": r.category,
                    "url": r.url,
                    "evidence": r.evidence,
                    "poc": r.poc,
                    "investigation_id": r.investigation_id,
                    "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                }
                for r in rows
            ]
            print(json.dumps(output, indent=2))
        else:
            if not rows:
                print("[INFO] No historical findings in the database.")
                return
            print(f"[INFO] {len(rows)} historical finding(s):\n")
            for r in rows:
                print(f"[{r.severity.upper()}] {r.title} ({r.kind})")
                print(f"    Scan ID  : {r.scan_id}")
                print(f"    URL      : {r.url}")
                print(f"    Evidence : {r.evidence}")
                print(f"    When     : {r.timestamp}")
                print()
    finally:
        db.close()


def run_report(scan_id):
    init_db()
    report_text = generate_markdown_report(scan_id)

    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "output")
    output_dir = os.path.abspath(output_dir)
    os.makedirs(output_dir, exist_ok=True)

    filename = os.path.join(output_dir, f"vulnforge_report_{scan_id[:8]}.md")
    with open(filename, "w") as f:
        f.write(report_text)
    print(f"[INFO] Report written to {filename}")


def main():
    args = parse_args()

    if args.report:
        run_report(args.report)
        return

    if args.history:
        show_history(args.scan_id, args.json)
        return

    if not args.url:
        print("[ERROR] -u/--url is required unless using --history or --report")
        return

    target = args.url if args.url.startswith("http") else f"https://{args.url}"

    init_db()
    scan_id = str(uuid.uuid4())

    reporter = None
    if not args.json:
        StartupBanner.show()
        LogPrinter.info(f"Target: {target}")
        LogPrinter.info(f"Scan ID: {scan_id}")
        LogPrinter.info(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        reporter = LogStyleReporter()

    all_findings, total_requests = asyncio.run(run_scan(target, reporter))

    engine = CorrelationEngine(all_findings)
    investigation_paths = engine.correlate()

    FindingRepository.save_scan(scan_id, all_findings, investigation_paths)

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in all_findings:
        sev = str(f.severity).capitalize()
        if sev in severity_counts:
            severity_counts[sev] += 1

    if args.json:
        output = {
            "target": target,
            "scan_id": scan_id,
            "request_count": total_requests,
            "severity_summary": severity_counts,
            "findings": [asdict(f) for f in all_findings],
            "investigation_paths": [asdict(p) for p in investigation_paths],
        }
        print(json.dumps(output, indent=2, default=str))
    else:
        reporter.summary_bar()

        if investigation_paths:
            reporter.phase("Investigation Recommendations")
            for path in investigation_paths:
                print(f" ok {path.title} ({path.estimated_time})")
                print(f"    Reasoning: {path.reasoning}")

        print(f"\n[INFO] Scan ID: {scan_id}")
        print(f"[INFO] Generate a report with: VulnForge --report {scan_id}")


if __name__ == "__main__":
    main()
