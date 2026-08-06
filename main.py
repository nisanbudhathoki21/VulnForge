#!/usr/bin/env python3
from utils.console import console, print_banner
from utils.fs import ensure_project_dirs
from utils.cli import parse_args
from utils.logger import setup_logging
from utils.url import normalize_url, is_valid_url
from config.settings import Settings
from scanner.loader import load_templates
from scanner.engine import run_scan, print_findings_table
from database.session import init_db, SessionLocal
from database.repo import get_or_create_target, create_scan, finalize_scan, add_vulnerability, add_report
from ai.analyzer import run_ai_for_scan
from reports.pdf import generate_pdf_report

def main() -> None:
    print_banner()
    args = parse_args()
    logger = setup_logging(args.verbose)

    target = normalize_url(args.url)
    if not is_valid_url(target):
        console.print("[red]Invalid target. Provide a domain or URL.[/red]")
        raise SystemExit(2)

    settings = Settings()
    ensure_project_dirs(settings)
    init_db()

    templates = load_templates(settings.TEMPLATES_DIR)
    logger.info(f"[bold cyan]Target:[/bold cyan] {target}")
    console.print(f"[cyan]Loaded templates:[/cyan] {len(templates)}")

    with SessionLocal() as db:
        tgt = get_or_create_target(db, target)
        scan = create_scan(db, tgt.id, total_templates=len(templates))
        console.print(f"[cyan]Scan ID:[/cyan] {scan.id}")

        findings = run_scan(target, templates, verbose=args.verbose)
        console.print(f"[magenta]Findings:[/magenta] {len(findings)}")
        vulns_saved = []
        if findings:
            print_findings_table(findings)
            for f in findings:
                v = add_vulnerability(db, scan.id, f)
                vulns_saved.append(v)

        sev_weights = {"info": 5, "low": 10, "medium": 25, "high": 40, "critical": 60}
        risk = sum(sev_weights.get(f["severity"].lower(), 10) for f in findings)
        risk = max(0, min(100, risk))
        finalize_scan(db, scan.id, findings_count=len(findings), risk_score=risk)
        console.print(f"[cyan]Saved to DB:[/cyan] {settings.DB_PATH} | [cyan]Risk Score:[/cyan] {risk}")

        # AI analysis (heuristic by default)
        overall = run_ai_for_scan(db, scan.id, target, findings, vulns_saved, risk)
        console.print("[bold cyan]Executive Summary:[/bold cyan] " + overall["executive_summary"])
        console.print("[bold cyan]Overall Risk Score:[/bold cyan] " + str(overall["overall_risk_score"]))

        # PDF report
        pdf_path = generate_pdf_report(db, scan.id, target, risk, settings.OUTPUT_DIR)
        add_report(db, scan.id, str(pdf_path))
        console.print(f"[bold green]PDF report saved:[/bold green] {pdf_path}")

    console.print("[bold green]Phase 7 (PDF Report) ready.[/bold green]")

if __name__ == "__main__":
    main()
