#!/usr/bin/env python3
"""
VulnForge Ultimate v3.3 - CLI Scanner
Zero False-Positive Engine • Multi-Stage Verification • Safe Rate Limiting
"""

import argparse
import asyncio
import sys
import os
import uuid
from datetime import datetime

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from database import init_db, get_scan_by_id, get_findings_for_scan
from engine.core import execute_security_scan
from engine.reporter import generate_pdf_report, generate_markdown_report

BANNER = r"""
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝

VulnForge Ultimate v3.3 — Automated Penetration Testing Suite
Zero False-Positive Engine • Multi-Stage Verifications • Wire-Level Burp Evidence
"""

async def main_async(args):
    target = args.url.strip()
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + str(uuid.uuid4())[:3]
    
    print(f"[*] Target      : {target}")
    print(f"[*] Concurrency : {args.threads}")
    print(f"[*] Rate Limit  : {args.rate_limit} req/sec (Safe Mode)")
    print(f"[*] Timeout     : {args.timeout}s")
    print(f"[*] Scan ID     : {scan_id}")
    print(f"[*] Database    : SQLite (Active)")
    print("-" * 65)

    options = {
        "profile": "God-Level Pentest",
        "concurrency": args.threads,
        "rate_limit": args.rate_limit,
        "timeout": args.timeout,
        "whitelist": args.whitelist
    }

    try:
        result = await execute_security_scan(scan_id, target, options)
        scan = get_scan_by_id(scan_id)
        findings = get_findings_for_scan(scan_id)

        print("\n" + "=" * 65)
        print("               VULNFORGE SCAN SUMMARY")
        print("=" * 65)
        print(f"  Target                 : {scan['target_url']}")
        print(f"  Scan Status            : {scan['status'].upper()}")
        print(f"  Duration               : {scan['duration_seconds']:.2f}s")
        print(f"  Total HTTP Requests    : {scan['requests_count']}")
        print(f"  Total Findings         : {scan['findings_count']}")
        print(f"  100% Confirmed Bugs    : {scan['confirmed_count']}")
        print("-" * 65)

        if findings:
            print("\n[+] DETAILED VERIFIED FINDINGS:")
            for idx, f in enumerate(findings, 1):
                confirmed_str = "[100% CONFIRMED]" if f["is_confirmed"] else "[HIGH CONFIDENCE]"
                print(f"\n  [{f['severity']}] {idx}. {f['title']}")
                print(f"      Status       : {confirmed_str}")
                print(f"      Endpoint     : {f['tested_endpoint'] or f['endpoint']}")
                print(f"      Parameter    : {f['parameter_name'] or 'N/A'}")
                if f.get("payload_used"):
                    print(f"      Payload      : {f['payload_used']}")
                print(f"      CVSS v3.1    : {f['cvss_score']} ({f['cwe_id'] or 'CWE-N/A'})")
                print(f"      Proof        : {f['verification_proof'][:160]}")
        else:
            print("\n[+] No vulnerabilities detected on this target.")

        # Export PDF Report
        if args.pdf:
            pdf_path = args.pdf if args.pdf.endswith(".pdf") else f"{args.pdf}.pdf"
            try:
                pdf_data = generate_pdf_report(scan_id)
                with open(pdf_path, "wb") as f:
                    f.write(pdf_data)
                print(f"\n[+] PDF Security Report saved: {pdf_path}")
            except Exception as e:
                print(f"\n[!] Note: PDF generation requires reportlab: {e}")

        # Export Markdown Report
        if args.markdown:
            md_path = args.markdown if args.markdown.endswith(".md") else f"{args.markdown}.md"
            md_data = generate_markdown_report(scan_id)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_data)
            print(f"[+] Markdown Report saved: {md_path}")

        print("\n✓ VulnForge assessment finished successfully.\n")

    except Exception as e:
        print(f"\n[-] Error during scan execution: {str(e)}")
        sys.exit(1)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="VulnForge Ultimate v3.3 - Automated Penetration Testing Suite")
    parser.add_argument("--db", type=str, default=None, help="Custom SQLite database file path (e.g. --db client_audit.db)")
    parser.add_argument("-u", "--url", required=True, help="Target URL to assess (e.g. http://127.0.0.1:3000)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrency workers (default: 10)")
    parser.add_argument("--rate-limit", type=float, default=8.0, help="Max requests per second (safe mode default: 8.0)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5.0)")
    parser.add_argument("--whitelist", nargs="*", default=None, help="Additional allowed subdomains in scope")
    parser.add_argument("--pdf", type=str, default=None, help="Output path for PDF Penetration Testing Report")
    parser.add_argument("--markdown", type=str, default=None, help="Output path for Markdown Report")

    args = parser.parse_args()
    if args.db:
        from database import set_db_path
        set_db_path(args.db)
    init_db()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
