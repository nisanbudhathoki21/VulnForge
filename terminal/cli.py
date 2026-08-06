from __future__ import annotations
import argparse
import asyncio
import json
from datetime import datetime
from dataclasses import asdict

from correlation.engine import CorrelationEngine
from workspace.models import Finding
from httpclient.client import HttpClient
from scanner.engine import Scanner
from templates.loader import TemplateLoader
from terminal.ui import StartupBanner, LogPrinter, LogStyleReporter


def parse_args():
    parser = argparse.ArgumentParser(prog="VulnForge", description="VulnForge Security Research Platform")
    parser.add_argument("-u", "--url", required=True, help="Target URL to scan")
    parser.add_argument("--json", action="store_true", help="Output results as JSON")
    return parser.parse_args()


async def run_scan(target: str, reporter: LogStyleReporter | None) -> tuple[list[Finding], int]:
    loader = TemplateLoader()
    templates = loader.load_all()

    if reporter:
        reporter.phase("Recon")
        reporter.running(f"Loaded {len(templates)} templates. Scanning {target}")

    all_findings: list[Finding] = []
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


def main():
    args = parse_args()
    target = args.url if args.url.startswith("http") else f"https://{args.url}"

    reporter = None
    if not args.json:
        StartupBanner.show()
        LogPrinter.info(f"Target: {target}")
        LogPrinter.info(f"Scan Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        reporter = LogStyleReporter()

    all_findings, total_requests = asyncio.run(run_scan(target, reporter))

    engine = CorrelationEngine(all_findings)
    investigation_paths = engine.correlate()

    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Informational": 0}
    for f in all_findings:
        sev = str(f.severity).capitalize()
        if sev in severity_counts:
            severity_counts[sev] += 1

    if args.json:
        output = {
            "target": target,
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
                print(f" 🎯 {path.title} ({path.estimated_time})")
                print(f"    Reasoning: {path.reasoning}")


if __name__ == "__main__":
    main()
