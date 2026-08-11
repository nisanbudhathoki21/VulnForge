#!/usr/bin/env python3
"""
VulnForge Ultimate v3.3 - Evidence-First Dual-Track CLI Scanner
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

# ================= ANSI COLOR CODES =================
RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

# Specific Requested Colors
COLOR_CRITICAL = "\033[1;31m"      # Bright Red
COLOR_HIGH = "\033[1;91m"          # Light Red / Coral
COLOR_MEDIUM = "\033[1;33m"        # Yellow / Amber
COLOR_LOW = "\033[1;32m"           # Green
COLOR_INFO = "\033[1;90m"          # Grey / Muted
COLOR_CYAN = "\033[1;36m"
COLOR_WHITE = "\033[1;37m"
COLOR_AMBER = "\033[38;5;214m"

# Badges
BADGE_CONFIRMED = f"\033[1;42;30m ✓ 100% CONFIRMED {RESET}"
BADGE_UNCONFIRMED = f"\033[1;43;30m ⚠ UNCONFIRMED LEAD {RESET}"
BADGE_HARDENING = f"\033[1;44;37m 🛡️ HARDENING {RESET}"

BANNER = f"""{COLOR_CYAN}
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝{RESET}

{BOLD}VulnForge Ultimate v3.3 — Evidence-First Penetration Testing Suite{RESET}
{DIM}Zero False-Positive Engine • Dual-Track Verification • Real-World Wire Telemetry{RESET}
"""

def get_severity_colored_tag(severity: str) -> str:
    sev_upper = severity.upper().strip()
    if sev_upper == "CRITICAL":
        return f"{COLOR_CRITICAL}[CRITICAL]{RESET}"
    elif sev_upper == "HIGH":
        return f"{COLOR_HIGH}[HIGH]{RESET}"
    elif sev_upper == "MEDIUM":
        return f"{COLOR_MEDIUM}[MEDIUM]{RESET}"
    elif sev_upper == "LOW":
        return f"{COLOR_LOW}[LOW]{RESET}"
    else:
        return f"{COLOR_INFO}[INFO]{RESET}"

def get_severity_color(severity: str) -> str:
    sev_upper = severity.upper().strip()
    if sev_upper == "CRITICAL":
        return COLOR_CRITICAL
    elif sev_upper == "HIGH":
        return COLOR_HIGH
    elif sev_upper == "MEDIUM":
        return COLOR_MEDIUM
    elif sev_upper == "LOW":
        return COLOR_LOW
    else:
        return COLOR_INFO

def correlate_attack_chains(findings):
    chains = []
    has_mass = any("mass assignment" in f["title"].lower() for f in findings if f.get("is_confirmed"))
    has_sqli = any("sql injection" in f["title"].lower() for f in findings if f.get("is_confirmed"))
    has_cors = any("cors" in f["title"].lower() for f in findings if f.get("is_confirmed"))
    
    if has_mass:
        chains.append({
            "name": "Mass Assignment → Privilege Escalation → Full Account Takeover",
            "severity": "CRITICAL (P1)",
            "impact": "Unauthenticated attackers can provision administrative accounts and take over application state."
        })
    if has_sqli:
        chains.append({
            "name": "SQL Injection → Authentication Bypass → Database Exfiltration",
            "severity": "CRITICAL (P1)",
            "impact": "Direct extraction of user tables, password hashes, and sensitive business data via raw SQL syntax injection."
        })
    if has_cors and has_mass:
        chains.append({
            "name": "CORS Misconfiguration + Mass Assignment → Cross-Origin State Alteration",
            "severity": "HIGH (P2)",
            "impact": "Malicious websites can issue authenticated cross-origin requests to alter user roles."
        })
    return chains


async def main_async(args):
    target = args.url.strip()
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + str(uuid.uuid4())[:3]
    
    print(f"{BOLD}[*] Target      :{RESET} {COLOR_CYAN}{target}{RESET}")
    print(f"{BOLD}[*] Concurrency :{RESET} {args.threads} workers")
    print(f"{BOLD}[*] Rate Limit  :{RESET} {args.rate_limit} req/sec (Safe Mode)")
    print(f"{BOLD}[*] Timeout     :{RESET} {args.timeout}s")
    print(f"{BOLD}[*] Scan ID     :{RESET} {scan_id}")
    print(f"{BOLD}[*] Database    :{RESET} SQLite (Active)")
    print(f"{DIM}{'-' * 65}{RESET}")

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

        # 4-Tier Categorization
        confirmed_exploits = [
            f for f in findings 
            if f["is_confirmed"] and f["severity"] in ["CRITICAL", "HIGH", "MEDIUM"] 
            and "hardening" not in f["title"].lower() and "missing" not in f["title"].lower()
        ]
        
        unconfirmed_leads = [
            f for f in findings 
            if not f["is_confirmed"] and "hardening" not in f["title"].lower() and "missing" not in f["title"].lower()
        ]
        
        hardening_items = [
            f for f in findings 
            if "hardening" in f["title"].lower() or "missing" in f["title"].lower() or f["severity"] in ["LOW", "INFO"]
        ]

        print("\n" + "=" * 65)
        print(f"               {BOLD}VULNFORGE SCAN SUMMARY{RESET}")
        print("=" * 65)
        print(f"  Target                     : {BOLD}{scan['target_url']}{RESET}")
        print(f"  Scan Status                : {COLOR_LOW}{scan['status'].upper()}{RESET}")
        print(f"  Duration                   : {scan['duration_seconds']:.2f}s")
        print(f"  Total HTTP Requests        : {COLOR_CYAN}{scan['requests_count']}{RESET}")
        print(f"  100% Confirmed Exploitable : {COLOR_CRITICAL if len(confirmed_exploits) > 0 else COLOR_LOW}{len(confirmed_exploits)}{RESET}")
        print(f"  Unconfirmed Leads          : {COLOR_MEDIUM if len(unconfirmed_leads) > 0 else DIM}{len(unconfirmed_leads)}{RESET}")
        print(f"  Defensive Hardening Items  : {COLOR_INFO}{len(hardening_items)}{RESET}")
        print(f"{DIM}{'-' * 65}{RESET}")

        # -------------------------------------------------------------
        # TIER 1: 100% CONFIRMED EXPLOITABLE VULNERABILITIES
        # -------------------------------------------------------------
        if confirmed_exploits:
            print(f"\n{COLOR_CRITICAL}[!] 🚨 100% CONFIRMED EXPLOITABLE VULNERABILITIES:{RESET}")
            for idx, f in enumerate(confirmed_exploits, 1):
                sev_tag = get_severity_colored_tag(f["severity"])
                sev_col = get_severity_color(f["severity"])
                
                print(f"\n  {sev_tag} {BOLD}{idx}. {f['title']}{RESET}")
                print(f"      Status       : {BADGE_CONFIRMED}")
                print(f"      Endpoint     : {COLOR_CYAN}{f['tested_endpoint'] or f['endpoint']}{RESET}")
                print(f"      Parameter    : {sev_col}{f['parameter_name'] or 'N/A'}{RESET}")
                if f.get("payload_used"):
                    print(f"      Payload      : {BOLD}{f['payload_used']}{RESET}")
                print(f"      CVSS v3.1    : {sev_col}{f['cvss_score']} ({f['cwe_id'] or 'CWE-N/A'}){RESET}")
                print(f"      Proof        : {COLOR_WHITE}{f['verification_proof']}{RESET}")
        else:
            print(f"\n{COLOR_LOW}[+] No confirmed exploitable vulnerabilities found on this target.{RESET}")

        # -------------------------------------------------------------
        # TIER 2: CORRELATED ATTACK CHAINS
        # -------------------------------------------------------------
        chains = correlate_attack_chains(confirmed_exploits)
        if chains:
            print("\n" + "=" * 65)
            print(f"         {COLOR_CRITICAL}⚡ CORRELATED ATTACK CHAINS (EXPLOIT PATHS){RESET}")
            print("=" * 65)
            for c_idx, ch in enumerate(chains, 1):
                print(f"\n  {COLOR_CRITICAL}[{ch['severity']}]{RESET} {BOLD}Chain #{c_idx}: {ch['name']}{RESET}")
                print(f"      Impact       : {ch['impact']}")

        # -------------------------------------------------------------
        # TIER 3: UNCONFIRMED LEADS & SUSPICIOUS ANOMALIES
        # -------------------------------------------------------------
        if unconfirmed_leads:
            print(f"\n{COLOR_MEDIUM}[?] ⚠️  UNCONFIRMED LEADS (TREAT AS LEAD - MANUAL REPEAT REQUIRED):{RESET}")
            for u_idx, uf in enumerate(unconfirmed_leads, 1):
                sev_tag = get_severity_colored_tag(uf["severity"])
                print(f"\n  {sev_tag} {BOLD}{u_idx}. {uf['title']}{RESET}")
                print(f"      Status       : {BADGE_UNCONFIRMED}")
                print(f"      Endpoint     : {COLOR_CYAN}{uf['tested_endpoint'] or uf['endpoint']}{RESET}")
                print(f"      Reason       : {COLOR_AMBER}{uf.get('verification_proof') or 'Anomaly observed but execution/data change not proven.'}{RESET}")
                print(f"      Action       : {DIM}Send to Live Repeater (http://localhost:8000) for manual validation.{RESET}")

        # -------------------------------------------------------------
        # TIER 4: DEFENSIVE HARDENING / CONFIGURATION BASELINES
        # -------------------------------------------------------------
        if hardening_items:
            print(f"\n{DIM}{'-' * 65}{RESET}")
            print(f"{COLOR_INFO}[*] 🛡️  DEFENSIVE HARDENING / CONFIGURATION BASELINES:{RESET}")
            for h_idx, hf in enumerate(hardening_items, 1):
                sev_tag = get_severity_colored_tag(hf["severity"])
                print(f"  {sev_tag} {h_idx}. {COLOR_INFO}{hf['title']}{RESET} ({COLOR_CYAN}{hf.get('tested_endpoint') or hf['endpoint']}{RESET})")
                print(f"     {DIM}Proof: {hf['verification_proof']}{RESET}")

        # Export Reports
        if args.pdf:
            pdf_path = args.pdf if args.pdf.endswith(".pdf") else f"{args.pdf}.pdf"
            try:
                pdf_data = generate_pdf_report(scan_id)
                with open(pdf_path, "wb") as f:
                    f.write(pdf_data)
                print(f"\n{COLOR_LOW}[+] PDF Security Report saved:{RESET} {pdf_path}")
            except Exception as e:
                print(f"\n{DIM}[!] Note: PDF report generation: {e}{RESET}")

        if args.markdown:
            md_path = args.markdown if args.markdown.endswith(".md") else f"{args.markdown}.md"
            md_data = generate_markdown_report(scan_id)
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_data)
            print(f"{COLOR_LOW}[+] Markdown Report saved:{RESET} {md_path}")

        print(f"\n{COLOR_LOW}✓ VulnForge assessment finished successfully.{RESET}\n")

    except Exception as e:
        print(f"\n{COLOR_CRITICAL}[-] Error during scan execution: {str(e)}{RESET}")
        sys.exit(1)


def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="VulnForge Ultimate v3.3 - Evidence-First Automated Security Scanner")
    parser.add_argument("--db", type=str, default=None, help="Custom SQLite database file path (e.g. --db client.db)")
    parser.add_argument("-u", "--url", required=True, help="Target URL to assess")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Concurrency workers (default: 10)")
    parser.add_argument("--rate-limit", type=float, default=8.0, help="Max requests per second (safe mode default: 8.0)")
    parser.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds (default: 5.0)")
    parser.add_argument("--whitelist", nargs="*", default=None, help="Additional allowed subdomains in scope")
    parser.add_argument("--pdf", type=str, default=None, help="Output path for PDF Report")
    parser.add_argument("--markdown", type=str, default=None, help="Output path for Markdown Report")

    args = parser.parse_args()
    if args.db:
        from database import set_db_path
        set_db_path(args.db)
    init_db()
    asyncio.run(main_async(args))


if __name__ == "__main__":
    main()
