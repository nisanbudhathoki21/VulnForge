#!/usr/bin/env python3
"""
VulnForge CLI – Full control, aggressive by default, with all flags.
"""

import argparse
import sys
import os
import json
import time
import csv
import itertools
import threading
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    class Fore: RED=''; GREEN=''; YELLOW=''; BLUE=''; MAGENTA=''; CYAN=''; WHITE=''; RESET=''
    class Style: BRIGHT=''; DIM=''; NORMAL=''; RESET_ALL=''

try:
    from core.fingerprint import fingerprint_target
except ImportError:
    def fingerprint_target(url, quiet=False): return {}

try:
    from engine.scanner import scan_target
except ImportError:
    def scan_target(*args, **kwargs):
        print(f"{Fore.RED}[ERROR] Scanner engine not found.{Style.RESET_ALL}")
        return {'url': kwargs.get('url', ''), 'findings': [], 'scan_id': 'N/A'}

try:
    from core.database import init_db, save_scan, get_scans, get_scan
except ImportError:
    def init_db(): pass
    def save_scan(*args, **kwargs): pass
    def get_scans(*args, **kwargs): return []
    def get_scan(*args, **kwargs): return None

# ------------------------------------------------------------------
# BANNER
# ------------------------------------------------------------------
BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.MAGENTA}⚡ VulnForge v1.0 – Aggressive by Default ⚡{Style.RESET_ALL}
{Fore.YELLOW}🔍 Full request/response • Impact • Chain • Database • Reports{Style.RESET_ALL}
{Fore.GREEN}💻 One Engine. Every Website Vulnerabilities.{Style.RESET_ALL}
"""

# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def load_targets(file_path):
    try:
        with open(file_path) as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        sys.exit(1)

def generate_hackerone_report(finding, fingerprint):
    sev = finding['severity'].upper()
    cwe_map = {'critical':'CWE-94','high':'CWE-639','medium':'CWE-352','low':'CWE-200'}
    cwe = cwe_map.get(finding['severity'], 'CWE-Unknown')
    ev = finding['evidence']
    lines = []
    lines.append("## Vulnerability Report\n")
    lines.append(f"**Title:** {finding['name']}\n")
    lines.append(f"**CWE:** {cwe}\n")
    lines.append(f"**Severity:** {sev}\n")
    lines.append("### Summary\n")
    lines.append(f"{finding.get('impact', 'No impact description provided.')}\n")
    lines.append("### Steps to Reproduce\n")
    lines.append("1. Send the following request:\n")
    lines.append(f"```\n{ev['method']} {ev['url']}\n```\n")
    lines.append(f"2. Observe the response (status {ev.get('status', 'N/A')}).\n")
    lines.append("### Request\n")
    lines.append(f"```\n{ev['method']} {ev['url']}\n")
    lines.append(f"{json.dumps(ev.get('request_headers', {}), indent=2)}\n")
    lines.append(f"{ev.get('request_body', '')}\n```\n")
    lines.append("### Response\n")
    lines.append(f"```\nStatus: {ev.get('status', 'N/A')}\n")
    lines.append(f"{json.dumps(ev.get('response_headers', {}), indent=2)}\n")
    lines.append(f"{ev.get('response_body', '')[:1000]}\n```\n")
    lines.append("### Exploitation\n")
    if finding.get('exploit'):
        ex = finding['exploit']
        lines.append("```\n")
        lines.append(f"EXPLOIT {'SUCCESS' if ex['success'] else 'FAILED'}\n")
        lines.append(f"Request:\n{ex['request']['method']} {ex['request']['url']}\n")
        lines.append(f"Headers: {json.dumps(ex['request']['headers'], indent=2)}\n")
        lines.append(f"Body: {ex['request']['body']}\n")
        lines.append(f"Response:\nStatus: {ex['response']['status']}\n")
        lines.append(f"Body: {ex['response']['body'][:1000]}\n")
        lines.append(f"Output: {ex['output']}\n")
        lines.append("```\n")
    else:
        lines.append("No exploitation attempted.\n")
    lines.append("### Remediation\n")
    lines.append("- Implement proper authorization checks.\n")
    lines.append("- Validate and sanitize user input.\n")
    lines.append("### Tools Used\n")
    tools = ', '.join(fingerprint.get('security_tools', ['N/A']))
    lines.append(f"- VulnForge v1.0\n- {tools}\n")
    lines.append("### Impact\n")
    lines.append(f"{finding.get('impact', 'No impact')}\n")
    lines.append("### Chain\n")
    lines.append(f"{finding.get('chain', 'No chaining')}\n")
    return ''.join(lines)

def save_report(results, output_file, format='json'):
    os.makedirs(os.path.dirname(output_file) or '.', exist_ok=True)
    if format == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2, default=str)
    elif format == 'csv':
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['Target', 'Finding', 'Severity', 'Endpoint', 'Status', 'Exploitable'])
            for entry in results:
                for finding in entry.get('findings', []):
                    writer.writerow([
                        entry.get('url', ''),
                        finding.get('name', ''),
                        finding.get('severity', ''),
                        finding.get('evidence', {}).get('url', ''),
                        finding.get('evidence', {}).get('status', ''),
                        finding.get('exploit', {}).get('success', False)
                    ])
    else:
        print(f"{Fore.RED}Unsupported format.{Style.RESET_ALL}")
        sys.exit(1)
    print(f"{Fore.GREEN}[SAVED] Report saved to {output_file}{Style.RESET_ALL}")

def spinner_task(stop_event, message="Scanning"):
    chars = itertools.cycle(['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'])
    while not stop_event.is_set():
        sys.stdout.write(f'\r{Fore.YELLOW}{next(chars)} {message}...{Style.RESET_ALL}')
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\r' + ' ' * 40 + '\r')

def scan_single_target(target, args, progress_callback=None):
    result = {
        'url': target,
        'scan_id': None,
        'findings': [],
        'fingerprint': {},
        'error': None,
        'timestamp': datetime.now().isoformat(),
    }
    try:
        if not args.no_fingerprint:
            fp = fingerprint_target(target, quiet=args.quiet)
            result['fingerprint'] = fp

        scanner_quiet = not args.debug
        use_aggressive = not getattr(args, 'no_aggressive', False)

        scan_result = scan_target(
            target,
            quiet=scanner_quiet,
            template_dir=args.templates,
            max_workers=args.threads,
            proxy_file=args.proxy_file if not args.no_proxy else None,
            country=args.country if use_aggressive else None,
            rate_limit=args.rate_limit if args.rate_limit is not None else (10 if use_aggressive else 0),
            delay=args.delay if args.delay is not None else (0.5 if use_aggressive else 2),
            jitter=args.jitter if args.jitter is not None else (0.3 if use_aggressive else 0.5),
            exploit=args.exploit if args.exploit is not None else (True if use_aggressive else False),
            full=args.full if args.full is not None else (True if use_aggressive else False),
            username=args.username,
            password=args.password,
            timeout=args.timeout,
            skip_priv=args.no_priv,
            skip_auth=args.no_auth,
        )
        result['scan_id'] = scan_result.get('scan_id')
        result['findings'] = scan_result.get('findings', [])

        if args.db:
            init_db()
            save_scan(result['scan_id'], target, result['fingerprint'], result['findings'])

    except Exception as e:
        result['error'] = str(e)
    if progress_callback:
        progress_callback()
    return result

# ------------------------------------------------------------------
# Main
# ------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="VulnForge – Aggressive by Default")
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument('-u', '--url', help='Single target URL')
    target_group.add_argument('-l', '--list', help='File with URLs')
    parser.add_argument('-t', '--threads', type=int, default=10)
    parser.add_argument('-T', '--templates', default='templates/', help='Template file or directory')
    parser.add_argument('--proxy-file', help='Proxy file (proxies.txt) – loaded if exists')
    parser.add_argument('--country', help='Preferred proxy country (e.g., US)')
    parser.add_argument('--rate-limit', type=int, help='Requests per second (default aggressive: 10)')
    parser.add_argument('--delay', type=float, help='Base delay in seconds (default aggressive: 0.5)')
    parser.add_argument('--jitter', type=float, help='Jitter in seconds (default aggressive: 0.3)')
    parser.add_argument('--timeout', type=int, default=10, help='Request timeout in seconds (default: 10)')
    parser.add_argument('--exploit', action='store_true', help='Enable exploitation (default aggressive: ON)')
    parser.add_argument('--no-exploit', action='store_true', help='Disable exploitation')
    parser.add_argument('--full', action='store_true', help='Show full request/response (default aggressive: ON)')
    parser.add_argument('--no-full', action='store_true', help='Disable full request/response')
    parser.add_argument('--no-proxy', action='store_true', help='Disable proxy rotation')
    parser.add_argument('--no-aggressive', action='store_true', help='Turn off aggressive defaults (use conservative settings)')
    parser.add_argument('--no-priv', action='store_true', help='Skip privilege escalation tests')
    parser.add_argument('--no-auth', action='store_true', help='Skip authentication (register/login)')
    parser.add_argument('--report', action='store_true', help='Generate a HackerOne-style report for each finding')
    parser.add_argument('--db', action='store_true', help='Store results in SQLite')
    parser.add_argument('--history', action='store_true', help='Show scan history')
    parser.add_argument('--scan-id', help='Show details of a specific scan')
    parser.add_argument('-q', '--quiet', action='store_true', help='Suppress all output except findings')
    parser.add_argument('--debug', action='store_true', help='Show debug output (loading, etc.)')
    parser.add_argument('--no-fingerprint', action='store_true')
    parser.add_argument('-o', '--output', help='Output file (JSON)')
    parser.add_argument('--json', action='store_true', help='Output JSON to stdout')
    parser.add_argument('--username', help='Manual username for authentication')
    parser.add_argument('--password', help='Manual password for authentication')

    args = parser.parse_args()

    if args.history:
        init_db()
        scans = get_scans(20)
        print(f"{Fore.CYAN}Scan History:{Style.RESET_ALL}")
        for s in scans:
            print(f"  {s['scan_id']}: {s['target']} ({s['findings_count']} findings)")
        sys.exit(0)

    if args.scan_id:
        init_db()
        scan = get_scan(args.scan_id)
        print(json.dumps(scan, indent=2, default=str))
        sys.exit(0)

    if not args.quiet:
        print(BANNER)

    targets = [args.url] if args.url else load_targets(args.list)
    if not targets:
        print(f"{Fore.RED}No targets.{Style.RESET_ALL}")
        sys.exit(1)

    if args.proxy_file and not os.path.exists(args.proxy_file):
        if not args.quiet:
            print(f"{Fore.YELLOW}[WARN] Proxy file '{args.proxy_file}' not found. Proceeding without proxies.{Style.RESET_ALL}")
        args.proxy_file = None

    if args.no_exploit:
        args.exploit = False
    elif args.exploit is None:
        args.exploit = True
    if args.no_full:
        args.full = False
    elif args.full is None:
        args.full = True

    results = []
    start = time.time()

    stop_spinner = threading.Event()
    spinner_thread = None
    if len(targets) == 1 and not args.quiet and not args.debug:
        spinner_thread = threading.Thread(target=spinner_task, args=(stop_spinner, "Scanning"))
        spinner_thread.daemon = True
        spinner_thread.start()

    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = {executor.submit(scan_single_target, t, args): t for t in targets}
        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as e:
                print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")

    if spinner_thread:
        stop_spinner.set()
        spinner_thread.join()
        sys.stdout.write('\r' + ' ' * 40 + '\r')

    elapsed = time.time() - start
    total = sum(len(r.get('findings', [])) for r in results)

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2, default=str)
        print(f"{Fore.GREEN}[SAVED] Report saved to {args.output}{Style.RESET_ALL}")

    if not args.quiet:
        print(f"\n{Fore.CYAN}[+] Scan completed in {elapsed:.2f}s, {total} findings{Style.RESET_ALL}")

    for r in results:
        if r.get('error'):
            print(f"{Fore.RED}  ❌ {r['url']} → ERROR: {r['error']}{Style.RESET_ALL}")
            continue
        if not r.get('findings'):
            print(f"{Fore.GREEN}  ✅ {r['url']} → No vulnerabilities{Style.RESET_ALL}")
            continue

        print(f"\n{Fore.YELLOW}Target: {r['url']}{Style.RESET_ALL}")
        for idx, f in enumerate(r['findings'], 1):
            sev = f['severity'].upper()
            color = Fore.RED if sev in ['CRITICAL','HIGH'] else Fore.YELLOW if sev=='MEDIUM' else Fore.WHITE
            print(f"  {color}[{sev}]{Style.RESET_ALL} {idx}. {f['name']}")
            ev = f['evidence']
            print(f"    Endpoint: {ev['method']} {ev['url']}")
            print(f"    Status: {ev.get('status', 'N/A')}")
            if args.full:
                print("    Request Headers:")
                for k, v in ev.get('request_headers', {}).items():
                    print(f"      {k}: {v}")
                if ev.get('request_body'):
                    print(f"    Request Body:\n{ev['request_body'][:1000]}")
                print("    Response Headers:")
                for k, v in ev.get('response_headers', {}).items():
                    print(f"      {k}: {v}")
                print(f"    Response Body:\n{ev.get('response_body', '')[:1000]}")
            if args.exploit and f.get('exploit'):
                ex = f['exploit']
                print(f"    Exploitation: {'✅ SUCCESS' if ex['success'] else '❌ FAILED'}")
                print(f"      Request: {ex['request']['method']} {ex['request']['url']}")
                print(f"      Response Status: {ex['response']['status']}")
                if ex['output']:
                    print(f"      Output:\n{ex['output'][:500]}")
            if args.report:
                print(generate_hackerone_report(f, r.get('fingerprint', {})))
            print("")

    if args.db and not args.quiet:
        print(f"{Fore.GREEN}[DB] Results stored in vulnforge.db{Style.RESET_ALL}")

if __name__ == '__main__':
    main()
