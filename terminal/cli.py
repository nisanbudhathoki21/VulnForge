#!/usr/bin/env python3

"""
VulnForge CLI
Stable demonstration CLI for vulnerability scanning.

Features:
- Single URL / URL list
- Fingerprinting
- Template scanning
- SQLite persistence
- Scan history
- Scan details
- HTML/PDF/Markdown reporting
- Optional Ollama AI reporting
- Clean Ctrl+C handling
- Per-scan timeout
- No hanging ThreadPoolExecutor shutdown
"""

import argparse
import csv
import json
import os
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime


# ============================================================
# OPTIONAL COLOR SUPPORT
# ============================================================

try:
    from colorama import init, Fore, Style

    init(autoreset=True)

except ImportError:

    class Fore:
        RED = ""
        GREEN = ""
        YELLOW = ""
        BLUE = ""
        MAGENTA = ""
        CYAN = ""
        WHITE = ""
        RESET = ""

    class Style:
        BRIGHT = ""
        DIM = ""
        NORMAL = ""
        RESET_ALL = ""


# ============================================================
# IMPORTS
# ============================================================

try:
    from core.fingerprint import fingerprint_target
except ImportError:

    def fingerprint_target(url, quiet=False):
        return {}


try:
    from engine.scanner import scan_target
except ImportError:

    def scan_target(*args, **kwargs):
        return {
            "url": kwargs.get("url", ""),
            "findings": [],
            "scan_id": None,
        }


try:
    from core.database import (
        init_db,
        save_scan,
        get_scans,
        get_scan,
    )
except ImportError:

    def init_db():
        pass

    def save_scan(*args, **kwargs):
        pass

    def get_scans(*args, **kwargs):
        return []

    def get_scan(*args, **kwargs):
        return None


# ============================================================
# GLOBAL CONTROL
# ============================================================

STOP_EVENT = threading.Event()


def handle_sigint(signum, frame):
    """
    First Ctrl+C:
        Stop scheduling / processing more work.

    Second Ctrl+C:
        Immediate exit.
    """

    if STOP_EVENT.is_set():
        print("\n\n[!] Forced exit.")
        os._exit(130)

    STOP_EVENT.set()

    print()
    print(
        f"{Fore.YELLOW}"
        "[!] Ctrl+C received. Stopping safely..."
        f"{Style.RESET_ALL}"
    )


signal.signal(signal.SIGINT, handle_sigint)


# ============================================================
# BANNER
# ============================================================

BANNER = f"""
{Fore.CYAN}{Style.BRIGHT}
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ ██████╗  ██████╗ ███████╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
██║   ██║██║   ██║██║     ██╔██╗ ██║█████╗  ██║   ██║██████╔╝██║  ███╗█████╗
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.MAGENTA}{Style.BRIGHT}VulnForge v1.0{Style.RESET_ALL}
{Fore.CYAN}Web Vulnerability Scanner{Style.RESET_ALL}
{Fore.GREEN}Templates • Fingerprinting • Verification • SQLite • Reports{Style.RESET_ALL}
"""


# ============================================================
# HELPERS
# ============================================================

def now():
    return datetime.now().isoformat(timespec="seconds")


def load_targets(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return [
                line.strip()
                for line in f
                if line.strip() and not line.lstrip().startswith("#")
            ]

    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")
        sys.exit(1)


def safe_count(value):
    try:
        return len(value)
    except Exception:
        return 0


def severity_color(severity):
    severity = str(severity).upper()

    if severity == "CRITICAL":
        return Fore.RED + Style.BRIGHT

    if severity == "HIGH":
        return Fore.RED

    if severity == "MEDIUM":
        return Fore.YELLOW

    if severity == "LOW":
        return Fore.CYAN

    return Fore.WHITE


# ============================================================
# DATABASE
# ============================================================

def persist_scan(result):

    scan_id = result.get("scan_id")

    if not scan_id:
        return False

    try:
        init_db()

        save_scan(
            scan_id,
            result["url"],
            result.get("fingerprint", {}),
            result.get("findings", []),
            start_time=result.get("start_time"),
            end_time=result.get("end_time"),
        )

        return True

    except Exception as e:
        result["database_error"] = str(e)
        return False


# ============================================================
# SINGLE TARGET
# ============================================================

def scan_single_target(target, args):

    result = {
        "url": target,
        "scan_id": None,
        "findings": [],
        "fingerprint": {},
        "error": None,
        "database_error": None,
        "timestamp": now(),
        "start_time": now(),
        "end_time": None,
    }

    try:

        if STOP_EVENT.is_set():
            result["error"] = "Scan cancelled"
            return result

        # ----------------------------------------------------
        # FINGERPRINT
        # ----------------------------------------------------

        if not args.no_fingerprint:

            if not args.quiet:
                print(
                    f"{Fore.BLUE}[FINGERPRINT]{Style.RESET_ALL} "
                    f"{target}"
                )

            try:
                result["fingerprint"] = fingerprint_target(
                    target,
                    quiet=True,
                ) or {}

            except Exception as e:
                result["fingerprint"] = {
                    "error": str(e)
                }

        # ----------------------------------------------------
        # SCANNER
        # ----------------------------------------------------

        if STOP_EVENT.is_set():
            result["error"] = "Scan cancelled"
            return result

        scan_result = scan_target(
            target,

            quiet=True,

            template_dir=args.templates,

            max_workers=max(1, min(args.threads, 10)),

            proxy_file=(
                args.proxy_file
                if args.proxy_file and not args.no_proxy
                else None
            ),

            country=args.country,

            rate_limit=args.rate_limit,

            delay=args.delay,

            jitter=args.jitter,

            exploit=args.exploit,

            full=args.full,

            username=args.username,

            password=args.password,

            timeout=args.timeout,

            skip_priv=args.no_priv,

            skip_auth=args.no_auth,
        )

        if not isinstance(scan_result, dict):
            scan_result = {}

        result["scan_id"] = scan_result.get("scan_id")

        result["findings"] = (
            scan_result.get("findings", [])
            or []
        )

        result["end_time"] = now()

        # ----------------------------------------------------
        # SQLITE
        # ----------------------------------------------------

        saved = persist_scan(result)

        result["database_saved"] = saved

    except KeyboardInterrupt:

        result["error"] = "Interrupted by user"

    except Exception as e:

        result["error"] = str(e)

    finally:

        if not result["end_time"]:
            result["end_time"] = now()

    return result


# ============================================================
# OUTPUT
# ============================================================

def print_fingerprint(fp):

    if not fp:
        return

    print(f"\n{Fore.CYAN}Fingerprint{Style.RESET_ALL}")

    server = fp.get("server", "Unknown")
    os_name = fp.get("os", "Unknown")
    rating = fp.get("security_rating", "N/A")

    print(f"  Server : {server}")
    print(f"  OS     : {os_name}")
    print(f"  Rating : {rating}")

    libraries = fp.get("libraries")

    if libraries:

        if isinstance(libraries, list):
            libraries = ", ".join(map(str, libraries))

        print(f"  Libraries : {libraries}")


def print_findings(findings):

    if not findings:

        print(
            f"\n{Fore.GREEN}"
            "✓ No verified findings"
            f"{Style.RESET_ALL}"
        )

        return

    print(
        f"\n{Fore.YELLOW}"
        f"Findings: {len(findings)}"
        f"{Style.RESET_ALL}"
    )

    for index, finding in enumerate(findings, 1):

        severity = str(
            finding.get("severity", "unknown")
        ).upper()

        color = severity_color(severity)

        name = finding.get(
            "name",
            "Unnamed finding"
        )

        evidence = finding.get(
            "evidence",
            {}
        ) or {}

        print(
            f"\n  {color}"
            f"[{severity}]"
            f"{Style.RESET_ALL} "
            f"{index}. {name}"
        )

        method = evidence.get(
            "method",
            "?"
        )

        url = evidence.get(
            "url",
            ""
        )

        status = evidence.get(
            "status",
            "N/A"
        )

        print(
            f"      {method} {url}"
        )

        print(
            f"      Status: {status}"
        )


def print_summary(result, elapsed):

    findings = result.get(
        "findings",
        []
    )

    print(
        f"\n{Fore.CYAN}"
        "╭──────────────────────────────────────────────╮"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        "│              VULNFORGE SCAN                 │"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        "╰──────────────────────────────────────────────╯"
        f"{Style.RESET_ALL}"
    )

    print(f"Target      : {result['url']}")
    print(f"Duration    : {elapsed:.2f}s")
    print(f"Findings    : {len(findings)}")

    if result.get("scan_id"):
        print(
            f"Scan ID     : "
            f"{result['scan_id']}"
        )

    if result.get("database_saved"):
        print(
            f"{Fore.GREEN}"
            "Database    : SAVED"
            f"{Style.RESET_ALL}"
        )

    elif result.get("scan_id"):
        print(
            f"{Fore.YELLOW}"
            "Database    : NOT SAVED"
            f"{Style.RESET_ALL}"
        )

    if result.get("error"):
        print(
            f"{Fore.RED}"
            f"Error       : {result['error']}"
            f"{Style.RESET_ALL}"
        )

    print()


# ============================================================
# HISTORY
# ============================================================

def show_history():

    init_db()

    scans = get_scans(20)

    print(
        f"\n{Fore.CYAN}"
        "VulnForge Scan History"
        f"{Style.RESET_ALL}\n"
    )

    if not scans:

        print(
            f"{Fore.YELLOW}"
            "No scans found."
            f"{Style.RESET_ALL}"
        )

        return

    for scan in scans:

        print(
            f"{Fore.GREEN}"
            f"{scan.get('scan_id', 'N/A')}"
            f"{Style.RESET_ALL}"
        )

        print(
            f"  Target   : "
            f"{scan.get('target', 'N/A')}"
        )

        print(
            f"  Findings : "
            f"{scan.get('findings_count', 0)}"
        )

        print(
            f"  Time     : "
            f"{scan.get('timestamp', 'N/A')}"
        )

        print()


# ============================================================
# SCAN DETAILS
# ============================================================

def show_scan(scan_id):

    init_db()

    scan = get_scan(scan_id)

    if not scan:

        print(
            f"{Fore.RED}"
            f"Scan '{scan_id}' not found."
            f"{Style.RESET_ALL}"
        )

        return

    print(
        json.dumps(
            scan,
            indent=2,
            default=str
        )
    )


# ============================================================
# JSON / CSV OUTPUT
# ============================================================

def save_json(results, path):

    with open(
        path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=2,
            default=str
        )

    print(
        f"{Fore.GREEN}"
        f"[SAVED] {path}"
        f"{Style.RESET_ALL}"
    )


def save_csv(results, path):

    with open(
        path,
        "w",
        newline="",
        encoding="utf-8"
    ) as f:

        writer = csv.writer(f)

        writer.writerow([
            "Target",
            "Finding",
            "Severity",
            "Endpoint",
            "Status",
            "Scan ID",
        ])

        for result in results:

            for finding in result.get(
                "findings",
                []
            ):

                evidence = finding.get(
                    "evidence",
                    {}
                ) or {}

                writer.writerow([
                    result.get("url", ""),
                    finding.get("name", ""),
                    finding.get("severity", ""),
                    evidence.get("url", ""),
                    evidence.get("status", ""),
                    result.get("scan_id", ""),
                ])

    print(
        f"{Fore.GREEN}"
        f"[SAVED] {path}"
        f"{Style.RESET_ALL}"
    )


# ============================================================
# ARGUMENTS
# ============================================================

def build_parser():

    parser = argparse.ArgumentParser(
        description="VulnForge Web Vulnerability Scanner"
    )

    # --------------------------------------------------------
    # TARGET
    # --------------------------------------------------------

    target = parser.add_mutually_exclusive_group()

    target.add_argument(
        "-u",
        "--url",
        help="Target URL"
    )

    target.add_argument(
        "-l",
        "--list",
        help="File containing target URLs"
    )

    # --------------------------------------------------------
    # SCANNER
    # --------------------------------------------------------

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        help="Worker threads (default: 5)"
    )

    parser.add_argument(
        "-T",
        "--templates",
        default="templates/",
        help="Template directory"
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout (default: 10)"
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=2,
        help="Requests per second"
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests"
    )

    parser.add_argument(
        "--jitter",
        type=float,
        default=0.2,
        help="Request jitter"
    )

    # --------------------------------------------------------
    # OPTIONAL DEEP TESTING
    # --------------------------------------------------------

    parser.add_argument(
        "--exploit",
        action="store_true",
        help="Enable exploit verification"
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Show full request/response details"
    )

    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable proxy"
    )

    parser.add_argument(
        "--proxy-file",
        help="Proxy file"
    )

    parser.add_argument(
        "--country",
        help="Proxy country"
    )

    parser.add_argument(
        "--no-priv",
        action="store_true",
        help="Skip privilege tests"
    )

    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Skip authentication tests"
    )

    parser.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Skip fingerprinting"
    )

    parser.add_argument(
        "--username"
    )

    parser.add_argument(
        "--password"
    )

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    parser.add_argument(
        "--history",
        action="store_true",
        help="Show scan history"
    )

    parser.add_argument(
        "--scan-id",
        help="Show saved scan"
    )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    parser.add_argument(
        "-o",
        "--output",
        help="Output JSON/CSV file"
    )

    parser.add_argument(
        "--csv",
        help="Save CSV output"
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON output"
    )

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable Ollama AI reporting"
    )

    parser.add_argument(
        "--ai-model",
        default="llama2",
        help="Ollama model"
    )

    parser.add_argument(
        "--ai-url",
        default="http://localhost:11434",
        help="Ollama URL"
    )

    # --------------------------------------------------------
    # UI
    # --------------------------------------------------------

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true"
    )

    parser.add_argument(
        "--debug",
        action="store_true"
    )

    return parser


# ============================================================
# MAIN
# ============================================================

def main():

    parser = build_parser()

    args = parser.parse_args()

    # --------------------------------------------------------
    # DATABASE COMMANDS
    # --------------------------------------------------------

    if args.history:

        show_history()
        return

    if args.scan_id:

        show_scan(args.scan_id)
        return

    # --------------------------------------------------------
    # TARGET REQUIRED
    # --------------------------------------------------------

    if not args.url and not args.list:

        parser.print_help()
        return

    # --------------------------------------------------------
    # BANNER
    # --------------------------------------------------------

    if not args.quiet:
        print(BANNER)

    # --------------------------------------------------------
    # TARGETS
    # --------------------------------------------------------

    if args.url:

        targets = [args.url]

    else:

        targets = load_targets(
            args.list
        )

    if not targets:

        print(
            f"{Fore.RED}"
            "No targets supplied."
            f"{Style.RESET_ALL}"
        )

        return

    # --------------------------------------------------------
    # PROXY VALIDATION
    # --------------------------------------------------------

    if (
        args.proxy_file
        and not os.path.isfile(args.proxy_file)
    ):

        print(
            f"{Fore.YELLOW}"
            f"[WARN] Proxy file not found: "
            f"{args.proxy_file}"
            f"{Style.RESET_ALL}"
        )

        args.proxy_file = None

    # --------------------------------------------------------
    # SCAN
    # --------------------------------------------------------

    results = []

    start_time = time.time()

    if not args.quiet:

        print(
            f"{Fore.CYAN}"
            f"[*] Targets : {len(targets)}"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.CYAN}"
            f"[*] Threads : {args.threads}"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.CYAN}"
            f"[*] Timeout : {args.timeout}s"
            f"{Style.RESET_ALL}"
        )

        print()

    # --------------------------------------------------------
    # ONE TARGET
    # --------------------------------------------------------

    if len(targets) == 1:

        result = scan_single_target(
            targets[0],
            args
        )

        results.append(result)

    # --------------------------------------------------------
    # MULTIPLE TARGETS
    # --------------------------------------------------------

    else:

        workers = max(
            1,
            min(args.threads, len(targets))
        )

        executor = ThreadPoolExecutor(
            max_workers=workers
        )

        futures = []

        try:

            for target_url in targets:

                if STOP_EVENT.is_set():
                    break

                futures.append(
                    executor.submit(
                        scan_single_target,
                        target_url,
                        args
                    )
                )

            for future in as_completed(futures):

                if STOP_EVENT.is_set():

                    for pending in futures:

                        pending.cancel()

                    break

                try:

                    result = future.result(
                        timeout=args.timeout + 15
                    )

                    results.append(result)

                except Exception as e:

                    results.append({
                        "url": "unknown",
                        "findings": [],
                        "error": str(e),
                        "timestamp": now(),
                    })

        finally:

            # IMPORTANT:
            # Do not wait forever after Ctrl+C.

            executor.shutdown(
                wait=False,
                cancel_futures=True
            )

    # --------------------------------------------------------
    # STOPPED
    # --------------------------------------------------------

    if STOP_EVENT.is_set():

        print(
            f"\n{Fore.YELLOW}"
            "[!] Scan stopped by user."
            f"{Style.RESET_ALL}"
        )

    # --------------------------------------------------------
    # RESULTS
    # --------------------------------------------------------

    elapsed = time.time() - start_time

    total_findings = sum(
        len(
            r.get(
                "findings",
                []
            )
        )
        for r in results
    )

    for result in results:

        if not args.quiet:

            print_fingerprint(
                result.get(
                    "fingerprint",
                    {}
                )
            )

            print_findings(
                result.get(
                    "findings",
                    []
                )
            )

            if result.get("error"):

                print(
                    f"{Fore.RED}"
                    f"Error: {result['error']}"
                    f"{Style.RESET_ALL}"
                )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    print(
        f"\n{Fore.CYAN}"
        "╭──────────────────────────────────────────────╮"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        "│                 SUMMARY                      │"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        "╰──────────────────────────────────────────────╯"
        f"{Style.RESET_ALL}"
    )

    print(
        f"Targets     : {len(results)}"
    )

    print(
        f"Findings    : {total_findings}"
    )

    print(
        f"Duration    : {elapsed:.2f}s"
    )

    saved_count = sum(
        1
        for r in results
        if r.get("database_saved")
    )

    print(
        f"DB Saved    : {saved_count}/{len(results)}"
    )

    # --------------------------------------------------------
    # OUTPUT
    # --------------------------------------------------------

    if args.output:

        save_json(
            results,
            args.output
        )

    if args.csv:

        save_csv(
            results,
            args.csv
        )

    # --------------------------------------------------------
    # JSON STDOUT
    # --------------------------------------------------------

    if args.json:

        print(
            json.dumps(
                results,
                indent=2,
                default=str
            )
        )

    print(
        f"\n{Fore.GREEN}"
        "✓ VulnForge finished."
        f"{Style.RESET_ALL}"
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
