#!/usr/bin/env python3

"""
VulnForge Command-Line Interface

Responsibilities:
1. Parse CLI arguments
2. Load target URLs
3. Fingerprint targets
4. Run the VulnForge scanner
5. Persist results into SQLite
6. Display findings
7. Export JSON / CSV
8. Generate dashboard
9. Generate PDF reports
10. Show scan history/details

Architecture:

    Target
       |
       v
    Fingerprint
       |
       v
    Scanner
       |
       v
    Scan Result
       |
       +----> Terminal
       |
       +----> SQLite
       |
       +----> Dashboard
       |
       +----> JSON / CSV / PDF
"""

# ============================================================
# STANDARD LIBRARY
# ============================================================

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
    from colorama import Fore, Style, init

    init(autoreset=True)

except ImportError:

    class Fore:
        BLACK = ""
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
# VULNFORGE IMPORTS
# ============================================================

# Fingerprinting
try:
    from core.fingerprint import fingerprint_target
except ImportError:
    fingerprint_target = None


# Scanner
try:
    from engine.scanner import scan_target
except ImportError:
    scan_target = None


# Database
try:
    from core.database import (
        init_db,
        save_scan,
        get_scans,
        get_scan,
    )
except ImportError:
    init_db = None
    save_scan = None
    get_scans = None
    get_scan = None


# ============================================================
# GLOBAL STATE
# ============================================================

STOP_EVENT = threading.Event()


# ============================================================
# SIGNAL HANDLING
# ============================================================

def handle_sigint(signum, frame):
    """
    Handle Ctrl+C.

    First Ctrl+C:
        Stop safely.

    Second Ctrl+C:
        Force exit.
    """

    if STOP_EVENT.is_set():
        print(
            f"\n{Fore.RED}"
            "[!] Forced exit."
            f"{Style.RESET_ALL}"
        )

        os._exit(130)

    STOP_EVENT.set()

    print(
        f"\n{Fore.YELLOW}"
        "[!] Ctrl+C received."
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.YELLOW}"
        "[!] Stopping safely..."
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
# GENERAL HELPERS
# ============================================================

def now():
    """Return current local time in ISO format."""

    return datetime.now().isoformat(timespec="seconds")


def normalize_target(url):
    """
    Normalize target URL.

    Example:

        example.com
            ->
        https://example.com
    """

    if not url:
        return ""

    url = str(url).strip()

    if not url:
        return ""

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    return url.rstrip("/")


def load_targets(path):
    """
    Load targets from a text file.

    Empty lines and comments are ignored.
    """

    if not path:
        return []

    if not os.path.isfile(path):
        print(
            f"{Fore.RED}"
            f"[ERROR] Target file not found: {path}"
            f"{Style.RESET_ALL}"
        )
        return []

    targets = []

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
        ) as handle:

            for line in handle:

                line = line.strip()

                if not line:
                    continue

                if line.startswith("#"):
                    continue

                target = normalize_target(line)

                if target:
                    targets.append(target)

    except OSError as exc:

        print(
            f"{Fore.RED}"
            f"[ERROR] Could not read target file: {exc}"
            f"{Style.RESET_ALL}"
        )

        return []

    return list(dict.fromkeys(targets))


def severity_color(severity):
    """Return terminal color for severity."""

    severity = str(
        severity or "UNKNOWN"
    ).upper()

    if severity == "CRITICAL":
        return Fore.RED + Style.BRIGHT

    if severity == "HIGH":
        return Fore.RED

    if severity == "MEDIUM":
        return Fore.YELLOW

    if severity == "LOW":
        return Fore.CYAN

    if severity == "INFO":
        return Fore.BLUE

    return Fore.WHITE


def safe_float(value, default=0.0):
    """Safely convert value to float."""

    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def safe_int(value, default=0):
    """Safely convert value to integer."""

    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ============================================================
# DATABASE
# ============================================================

def initialize_database():
    """
    Initialize VulnForge SQLite database.
    """

    if init_db is None:
        raise RuntimeError(
            "core.database could not be imported."
        )

    init_db()


def persist_scan(result):
    """
    Persist one completed scan.

    The same findings shown in the terminal are sent to SQLite.
    """

    if save_scan is None:

        result["database_error"] = (
            "core.database.save_scan is unavailable."
        )

        return False

    scan_id = result.get("scan_id")

    if not scan_id:

        result["database_error"] = (
            "Scanner did not return a scan_id."
        )

        return False

    try:

        initialize_database()

        save_scan(
            scan_id,
            result.get("url", ""),
            result.get("fingerprint", {}) or {},
            result.get("findings", []) or [],
            start_time=result.get("start_time"),
            end_time=result.get("end_time"),
        )

        result["database_saved"] = True
        result["database_error"] = None

        return True

    except Exception as exc:

        result["database_saved"] = False
        result["database_error"] = str(exc)

        return False


# ============================================================
# FINGERPRINT
# ============================================================

def run_fingerprint(target, quiet=False):
    """Run target fingerprinting."""

    if fingerprint_target is None:

        return {
            "error": "Fingerprint module unavailable."
        }

    try:

        fingerprint = fingerprint_target(
            target,
            quiet=True,
        )

        if not isinstance(fingerprint, dict):
            return {}

        return fingerprint

    except Exception as exc:

        if not quiet:

            print(
                f"{Fore.YELLOW}"
                f"[WARN] Fingerprinting failed: {exc}"
                f"{Style.RESET_ALL}"
            )

        return {
            "error": str(exc)
        }


# ============================================================
# SCANNER
# ============================================================

def run_scanner(target, args):
    """
    Execute VulnForge scanner.

    Scanner-specific arguments are kept here.
    """

    if scan_target is None:

        raise RuntimeError(
            "engine.scanner.scan_target could not be imported."
        )

    proxy_file = None

    if args.proxy_file and not args.no_proxy:

        if os.path.isfile(args.proxy_file):
            proxy_file = args.proxy_file

        else:

            print(
                f"{Fore.YELLOW}"
                f"[WARN] Proxy file not found: "
                f"{args.proxy_file}"
                f"{Style.RESET_ALL}"
            )

    worker_count = max(
        1,
        min(args.threads, 10),
    )

    result = scan_target(
        target,
        quiet=True,
        template_dir=args.templates,
        max_workers=worker_count,
        proxy_file=proxy_file,
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

    if not isinstance(result, dict):

        raise RuntimeError(
            "Scanner returned an invalid result."
        )

    return result


# ============================================================
# SINGLE TARGET SCAN
# ============================================================

def scan_single_target(target, args):
    """
    Scan one target and persist the result.
    """

    target = normalize_target(target)

    start_time = now()

    result = {
        "url": target,
        "scan_id": None,
        "findings": [],
        "fingerprint": {},
        "error": None,
        "database_error": None,
        "database_saved": False,
        "timestamp": start_time,
        "start_time": start_time,
        "end_time": None,
        "request_count": 0,
        "requests_sent": 0,
        "templates_loaded": 0,
        "errors_count": 0,
        "confirmed_count": 0,
    }

    if STOP_EVENT.is_set():

        result["error"] = "Scan cancelled."
        result["end_time"] = now()

        return result

    try:

        # ----------------------------------------------------
        # FINGERPRINT
        # ----------------------------------------------------

        if not args.no_fingerprint:

            if not args.quiet:

                print(
                    f"{Fore.BLUE}"
                    f"[FINGERPRINT]"
                    f"{Style.RESET_ALL} "
                    f"{target}"
                )

            result["fingerprint"] = run_fingerprint(
                target,
                quiet=args.quiet,
            )

        # ----------------------------------------------------
        # STOP CHECK
        # ----------------------------------------------------

        if STOP_EVENT.is_set():

            result["error"] = "Scan cancelled."
            result["end_time"] = now()

            return result

        # ----------------------------------------------------
        # SCAN
        # ----------------------------------------------------

        if not args.quiet:

            print(
                f"{Fore.CYAN}"
                f"[SCAN]"
                f"{Style.RESET_ALL} "
                f"{target}"
            )

        scan_result = run_scanner(
            target,
            args,
        )

        # ----------------------------------------------------
        # SCAN ID
        # ----------------------------------------------------

        scanner_scan_id = scan_result.get(
            "scan_id"
        )

        if scanner_scan_id:
            result["scan_id"] = scanner_scan_id

        # ----------------------------------------------------
        # FINDINGS
        # ----------------------------------------------------

        scanner_findings = scan_result.get(
            "findings",
            [],
        )

        if isinstance(
            scanner_findings,
            list,
        ):
            result["findings"] = scanner_findings

        # ----------------------------------------------------
        # FINGERPRINT
        # ----------------------------------------------------

        scanner_fingerprint = scan_result.get(
            "fingerprint"
        )

        if scanner_fingerprint:

            result["fingerprint"] = (
                scanner_fingerprint
            )

        # ----------------------------------------------------
        # ERROR
        # ----------------------------------------------------

        scanner_error = scan_result.get(
            "error"
        )

        if scanner_error:
            result["error"] = scanner_error

        # ----------------------------------------------------
        # ACCOUNTING
        # ----------------------------------------------------

        request_count = scan_result.get(
            "request_count",
            0,
        )

        requests_sent = scan_result.get(
            "requests_sent",
            request_count,
        )

        templates_loaded = scan_result.get(
            "templates_loaded",
            scan_result.get(
                "total_templates",
                0,
            ),
        )

        errors_count = scan_result.get(
            "errors_count",
            0,
        )

        confirmed_count = scan_result.get(
            "confirmed_count"
        )

        result["request_count"] = safe_int(
            request_count
        )

        result["requests_sent"] = safe_int(
            requests_sent,
            result["request_count"],
        )

        result["templates_loaded"] = safe_int(
            templates_loaded
        )

        result["errors_count"] = safe_int(
            errors_count
        )

        if confirmed_count is None:

            confirmed_count = sum(
                1
                for finding in result["findings"]
                if (
                    isinstance(finding, dict)
                    and bool(
                        finding.get(
                            "confirmed",
                            False,
                        )
                    )
                )
            )

        result["confirmed_count"] = safe_int(
            confirmed_count
        )

        # ----------------------------------------------------
        # END TIME
        # ----------------------------------------------------

        result["end_time"] = now()

        # ----------------------------------------------------
        # DATABASE
        # ----------------------------------------------------

        persist_scan(result)

    except KeyboardInterrupt:

        result["error"] = (
            "Interrupted by user."
        )

        result["end_time"] = now()

    except Exception as exc:

        result["error"] = str(exc)
        result["end_time"] = now()

    finally:

        if not result.get("end_time"):
            result["end_time"] = now()

    return result


# ============================================================
# FINDING HELPERS
# ============================================================

def finding_status(finding):
    """Determine finding display status."""

    if bool(
        finding.get(
            "confirmed",
            False,
        )
    ):
        return "CONFIRMED"

    return "UNCONFIRMED"


def finding_evidence(finding):
    """Return normalized evidence dictionary."""

    evidence = finding.get(
        "evidence",
        {},
    )

    if isinstance(
        evidence,
        dict,
    ):
        return evidence

    return {}


# ============================================================
# PRINT FINGERPRINT
# ============================================================

def print_fingerprint(fingerprint):
    """Display fingerprint information."""

    if not fingerprint:
        return

    if fingerprint.get("error"):

        print(
            f"{Fore.YELLOW}"
            f"Fingerprint warning: "
            f"{fingerprint['error']}"
            f"{Style.RESET_ALL}"
        )

    print(
        f"\n{Fore.CYAN}"
        f"Fingerprint"
        f"{Style.RESET_ALL}"
    )

    print(
        f"  Server : "
        f"{fingerprint.get('server', 'Unknown')}"
    )

    print(
        f"  OS     : "
        f"{fingerprint.get('os', 'Unknown')}"
    )

    print(
        f"  Rating : "
        f"{fingerprint.get('security_rating', 'N/A')}"
    )

    libraries = fingerprint.get(
        "libraries"
    )

    if libraries:

        if isinstance(
            libraries,
            list,
        ):

            libraries = ", ".join(
                str(item)
                for item in libraries
            )

        print(
            f"  Libraries : {libraries}"
        )


# ============================================================
# PRINT FINDINGS
# ============================================================

def print_findings(findings):
    """Display findings clearly."""

    if not findings:

        print(
            f"\n{Fore.GREEN}"
            "✓ No findings returned by scanner."
            f"{Style.RESET_ALL}"
        )

        return

    print(
        f"\n{Fore.YELLOW}"
        f"Findings: {len(findings)}"
        f"{Style.RESET_ALL}"
    )

    for index, finding in enumerate(
        findings,
        start=1,
    ):

        if not isinstance(
            finding,
            dict,
        ):
            continue

        severity = str(
            finding.get(
                "severity",
                "UNKNOWN",
            )
        ).upper()

        name = finding.get(
            "name",
            "Unnamed finding",
        )

        confidence = safe_float(
            finding.get(
                "confidence",
                0.0,
            )
        )

        confirmed = bool(
            finding.get(
                "confirmed",
                False,
            )
        )

        evidence = finding_evidence(
            finding
        )

        method = evidence.get(
            "method",
            "?",
        )

        evidence_url = evidence.get(
            "url",
            "",
        )

        http_status = evidence.get(
            "status",
            "N/A",
        )

        color = severity_color(
            severity
        )

        if confirmed:

            status_display = (
                f"{Fore.GREEN}"
                f"CONFIRMED"
                f"{Style.RESET_ALL}"
            )

        else:

            status_display = (
                f"{Fore.YELLOW}"
                f"UNCONFIRMED"
                f"{Style.RESET_ALL}"
            )

        print(
            f"\n  {color}"
            f"[{severity}]"
            f"{Style.RESET_ALL} "
            f"{index}. {name}"
        )

        print(
            f"      Status     : "
            f"{status_display}"
        )

        print(
            f"      Confidence : "
            f"{confidence:.2f}"
        )

        print(
            f"      Request    : "
            f"{method} {evidence_url}"
        )

        print(
            f"      HTTP Status: "
            f"{http_status}"
        )

        if not confirmed:

            print(
                f"      {Fore.YELLOW}"
                f"⚠ This finding is not independently "
                f"confirmed. Treat it as a lead."
                f"{Style.RESET_ALL}"
            )


# ============================================================
# RESULT SUMMARY
# ============================================================

def print_result_summary(
    result,
    elapsed=None,
):
    """Print summary for one target."""

    if elapsed is None:

        try:

            start = datetime.fromisoformat(
                result.get("start_time")
            )

            end = datetime.fromisoformat(
                result.get("end_time")
            )

            elapsed = (
                end - start
            ).total_seconds()

        except Exception:

            elapsed = 0.0

    findings = result.get(
        "findings",
        [],
    ) or []

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

    print(
        f"Target      : "
        f"{result.get('url', 'N/A')}"
    )

    print(
        f"Duration    : "
        f"{elapsed:.2f}s"
    )

    print(
        f"Findings    : "
        f"{len(findings)}"
    )

    print(
        f"Requests    : "
        f"{result.get('requests_sent', 0)}"
    )

    print(
        f"Templates   : "
        f"{result.get('templates_loaded', 0)}"
    )

    if result.get("scan_id"):

        print(
            f"Scan ID     : "
            f"{result['scan_id']}"
        )

    if result.get("database_saved"):

        print(
            f"{Fore.GREEN}"
            f"Database    : SAVED"
            f"{Style.RESET_ALL}"
        )

    else:

        print(
            f"{Fore.RED}"
            f"Database    : NOT SAVED"
            f"{Style.RESET_ALL}"
        )

        if result.get("database_error"):

            print(
                f"{Fore.RED}"
                f"DB Error    : "
                f"{result['database_error']}"
                f"{Style.RESET_ALL}"
            )

    if result.get("error"):

        print(
            f"{Fore.RED}"
            f"Error       : "
            f"{result['error']}"
            f"{Style.RESET_ALL}"
        )

    print()


# ============================================================
# HISTORY
# ============================================================

def show_history(limit=20):
    """Display saved scan history."""

    try:

        initialize_database()

        if get_scans is None:
            raise RuntimeError(
                "core.database.get_scans unavailable."
            )

        scans = get_scans(limit)

    except Exception as exc:

        print(
            f"{Fore.RED}"
            f"[DATABASE ERROR] {exc}"
            f"{Style.RESET_ALL}"
        )

        return

    print(
        f"\n{Fore.CYAN}"
        f"VulnForge Scan History"
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

        if not isinstance(
            scan,
            dict,
        ):
            continue

        scan_id = scan.get(
            "scan_id",
            "N/A",
        )

        target = scan.get(
            "target",
            scan.get(
                "url",
                "N/A",
            ),
        )

        findings_count = scan.get(
            "findings_count",
            scan.get(
                "finding_count",
                0,
            ),
        )

        timestamp = scan.get(
            "timestamp",
            scan.get(
                "start_time",
                "N/A",
            ),
        )

        print(
            f"{Fore.GREEN}"
            f"{scan_id}"
            f"{Style.RESET_ALL}"
        )

        print(
            f"  Target   : {target}"
        )

        print(
            f"  Findings : {findings_count}"
        )

        print(
            f"  Time     : {timestamp}"
        )

        print()


# ============================================================
# SCAN DETAILS
# ============================================================

def show_scan(scan_id):
    """Display a saved scan."""

    try:

        initialize_database()

        if get_scan is None:
            raise RuntimeError(
                "core.database.get_scan unavailable."
            )

        scan = get_scan(scan_id)

    except Exception as exc:

        print(
            f"{Fore.RED}"
            f"[DATABASE ERROR] {exc}"
            f"{Style.RESET_ALL}"
        )

        return

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
            default=str,
        )
    )


# ============================================================
# JSON OUTPUT
# ============================================================

def save_json(results, path):
    """Save results as JSON."""

    try:

        with open(
            path,
            "w",
            encoding="utf-8",
        ) as handle:

            json.dump(
                results,
                handle,
                indent=2,
                default=str,
            )

        print(
            f"{Fore.GREEN}"
            f"[SAVED] JSON: {path}"
            f"{Style.RESET_ALL}"
        )

    except OSError as exc:

        print(
            f"{Fore.RED}"
            f"[JSON ERROR] {exc}"
            f"{Style.RESET_ALL}"
        )


# ============================================================
# CSV OUTPUT
# ============================================================

def save_csv(results, path):
    """Save findings as CSV."""

    try:

        with open(
            path,
            "w",
            newline="",
            encoding="utf-8",
        ) as handle:

            writer = csv.writer(handle)

            writer.writerow(
                [
                    "Target",
                    "Scan ID",
                    "Finding",
                    "Severity",
                    "Confirmed",
                    "Confidence",
                    "Method",
                    "Endpoint",
                    "HTTP Status",
                ]
            )

            for result in results:

                findings = result.get(
                    "findings",
                    [],
                ) or []

                for finding in findings:

                    if not isinstance(
                        finding,
                        dict,
                    ):
                        continue

                    evidence = finding_evidence(
                        finding
                    )

                    writer.writerow(
                        [
                            result.get(
                                "url",
                                "",
                            ),
                            result.get(
                                "scan_id",
                                "",
                            ),
                            finding.get(
                                "name",
                                "",
                            ),
                            finding.get(
                                "severity",
                                "",
                            ),
                            finding.get(
                                "confirmed",
                                False,
                            ),
                            finding.get(
                                "confidence",
                                0,
                            ),
                            evidence.get(
                                "method",
                                "",
                            ),
                            evidence.get(
                                "url",
                                "",
                            ),
                            evidence.get(
                                "status",
                                "",
                            ),
                        ]
                    )

        print(
            f"{Fore.GREEN}"
            f"[SAVED] CSV: {path}"
            f"{Style.RESET_ALL}"
        )

    except OSError as exc:

        print(
            f"{Fore.RED}"
            f"[CSV ERROR] {exc}"
            f"{Style.RESET_ALL}"
        )


# ============================================================
# DASHBOARD
# ============================================================

def refresh_dashboard(output_path):
    """
    Refresh dashboard from SQLite.

    Dashboard generation happens after scan persistence.
    """

    try:

        from terminal.dashboard import (
            generate_dashboard
        )

    except ImportError as exc:

        return False, (
            f"Dashboard module unavailable: {exc}"
        )

    try:

        path = generate_dashboard(
            output_path
        )

        return True, path

    except Exception as exc:

        return False, str(exc)


# ============================================================
# PDF REPORT
# ============================================================

def generate_pdf_report(args):
    """Generate PDF report from saved database data."""

    try:

        from report.pdf_report import (
            generate_full_report_pdf,
            generate_finding_pdf,
        )

    except ImportError as exc:

        print(
            f"{Fore.RED}"
            f"[PDF ERROR] PDF module unavailable: {exc}"
            f"{Style.RESET_ALL}"
        )

        return

    try:

        if args.finding_id:

            path = generate_finding_pdf(
                args.scan_id,
                args.finding_id,
                args.pdf_output,
            )

        else:

            path = generate_full_report_pdf(
                args.scan_id,
                args.pdf_output,
            )

        print(
            f"{Fore.GREEN}"
            f"[PDF] Report written to {path}"
            f"{Style.RESET_ALL}"
        )

    except ValueError as exc:

        print(
            f"{Fore.RED}"
            f"[PDF ERROR] {exc}"
            f"{Style.RESET_ALL}"
        )

    except Exception as exc:

        print(
            f"{Fore.RED}"
            f"[PDF ERROR] Report generation failed: "
            f"{exc}"
            f"{Style.RESET_ALL}"
        )


# ============================================================
# ARGUMENT PARSER
# ============================================================

def build_parser():
    """Create VulnForge CLI argument parser."""

    parser = argparse.ArgumentParser(
        prog="VulnForge",
        description=(
            "VulnForge Web Vulnerability Scanner"
        ),
    )

    # ========================================================
    # TARGET
    # ========================================================

    target_group = (
        parser.add_mutually_exclusive_group()
    )

    target_group.add_argument(
        "-u",
        "--url",
        help="Target URL or domain",
    )

    target_group.add_argument(
        "-l",
        "--list",
        dest="list",
        help="File containing target URLs",
    )

    # ========================================================
    # SCANNER
    # ========================================================

    parser.add_argument(
        "-t",
        "--threads",
        type=int,
        default=5,
        help="Worker threads (default: 5)",
    )

    parser.add_argument(
        "-T",
        "--templates",
        default="templates/",
        help="Template directory",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="HTTP timeout in seconds",
    )

    parser.add_argument(
        "--rate-limit",
        type=float,
        default=2.0,
        help="Requests per second",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests",
    )

    parser.add_argument(
        "--jitter",
        type=float,
        default=0.2,
        help="Random request jitter",
    )

    # ========================================================
    # VERIFICATION
    # ========================================================

    parser.add_argument(
        "--exploit",
        action="store_true",
        help="Enable exploit verification",
    )

    parser.add_argument(
        "--full",
        action="store_true",
        help="Show full request/response details",
    )

    parser.add_argument(
        "--no-priv",
        action="store_true",
        help="Skip privilege-related tests",
    )

    parser.add_argument(
        "--no-auth",
        action="store_true",
        help="Skip authentication tests",
    )

    parser.add_argument(
        "--no-fingerprint",
        action="store_true",
        help="Skip target fingerprinting",
    )

    # ========================================================
    # PROXY
    # ========================================================

    parser.add_argument(
        "--no-proxy",
        action="store_true",
        help="Disable proxy",
    )

    parser.add_argument(
        "--proxy-file",
        help="Proxy file",
    )

    parser.add_argument(
        "--country",
        help="Proxy country",
    )

    # ========================================================
    # AUTHENTICATION
    # ========================================================

    parser.add_argument(
        "--username",
        help="Username for authenticated testing",
    )

    parser.add_argument(
        "--password",
        help="Password for authenticated testing",
    )

    # ========================================================
    # DATABASE
    # ========================================================

    parser.add_argument(
        "--history",
        action="store_true",
        help="Show scan history",
    )

    parser.add_argument(
        "--scan-id",
        help="Show a saved scan",
    )

    # ========================================================
    # DASHBOARD
    # ========================================================

    parser.add_argument(
        "--dashboard",
        action="store_true",
        help="Generate dashboard from SQLite data",
    )

    parser.add_argument(
        "--dashboard-output",
        default="vulnforge_dashboard.html",
        help=(
            "Dashboard output path "
            "(default: vulnforge_dashboard.html)"
        ),
    )

    parser.add_argument(
        "--no-auto-dashboard",
        action="store_true",
        help="Do not refresh dashboard after scanning",
    )

    # ========================================================
    # PDF
    # ========================================================

    parser.add_argument(
        "--pdf",
        action="store_true",
        help="Generate PDF report from saved scan",
    )

    parser.add_argument(
        "--finding-id",
        help=(
            "Generate PDF for one finding "
            "(requires --scan-id)"
        ),
    )

    parser.add_argument(
        "--pdf-output",
        help="PDF output path",
    )

    # ========================================================
    # OUTPUT
    # ========================================================

    parser.add_argument(
        "-o",
        "--output",
        help="Save JSON results to this file",
    )

    parser.add_argument(
        "--csv",
        help="Save CSV results to this file",
    )

    parser.add_argument(
        "--json",
        action="store_true",
        help="Print JSON results",
    )

    # ========================================================
    # AI
    # ========================================================

    parser.add_argument(
        "--ai",
        action="store_true",
        help="Enable AI reporting",
    )

    parser.add_argument(
        "--ai-model",
        default="qwen3:8b",
        help="Ollama model",
    )

    parser.add_argument(
        "--ai-url",
        default="http://localhost:11434",
        help="Ollama server URL",
    )

    # ========================================================
    # UI / DEBUG
    # ========================================================

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Reduce terminal output",
    )

    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug output",
    )

    # ========================================================
    # BUG BOUNTY PRO - NEW PROFESSIONAL MODE
    # ========================================================

    bb_group = parser.add_argument_group("Bug Bounty Pro (advanced correlation)")

    bb_group.add_argument(
        "--bugbounty",
        action="store_true",
        help="Enable Bug Bounty Pro mode: scope enforcement + attack chain correlation + HackerOne report (P1-P4)",
    )

    bb_group.add_argument(
        "--scope",
        nargs="+",
        default=[],
        help="In-scope patterns like HackerOne: *.target.com example.com (supports wildcard)",
    )

    bb_group.add_argument(
        "--out-scope",
        nargs="+",
        default=[],
        dest="out_scope",
        help="Out-of-scope patterns: admin.target.com *.out.target.com",
    )

    bb_group.add_argument(
        "--stealth",
        action="store_true",
        help="Stealth mode for BBP: delay 0.5s, jitter, UA rotation, strict scope",
    )

    bb_group.add_argument(
        "--severity",
        nargs="+",
        default=["critical","high","medium","low","info"],
        help="Severity filter like nuclei: --severity critical high",
    )

    bb_group.add_argument(
        "--tags",
        nargs="+",
        default=[],
        help="Tags filter like nuclei: sqli,xss,ssrf,idor",
    )

    bb_group.add_argument(
        "--hackerone-report",
        help="Generate HackerOne-ready markdown report path: --hackerone-report reports/hackerone.md",
    )

    return parser


# ============================================================
# VALIDATION
# ============================================================

def validate_args(args):
    """Validate CLI arguments."""

    if args.threads < 1:

        print(
            f"{Fore.RED}"
            "[ERROR] --threads must be >= 1."
            f"{Style.RESET_ALL}"
        )

        return False

    if args.timeout < 1:

        print(
            f"{Fore.RED}"
            "[ERROR] --timeout must be >= 1."
            f"{Style.RESET_ALL}"
        )

        return False

    if args.rate_limit < 0:

        print(
            f"{Fore.RED}"
            "[ERROR] --rate-limit cannot be negative."
            f"{Style.RESET_ALL}"
        )

        return False

    if args.delay < 0:

        print(
            f"{Fore.RED}"
            "[ERROR] --delay cannot be negative."
            f"{Style.RESET_ALL}"
        )

        return False

    if args.jitter < 0:

        print(
            f"{Fore.RED}"
            "[ERROR] --jitter cannot be negative."
            f"{Style.RESET_ALL}"
        )

        return False

    if args.finding_id and not args.scan_id:

        print(
            f"{Fore.RED}"
            "[ERROR] --finding-id requires --scan-id."
            f"{Style.RESET_ALL}"
        )

        return False

    if args.pdf and not args.scan_id:

        print(
            f"{Fore.RED}"
            "[ERROR] --pdf requires --scan-id."
            f"{Style.RESET_ALL}"
        )

        return False

    return True


# ============================================================
# SCAN CONFIGURATION
# ============================================================

def print_scan_configuration(
    args,
    targets,
):
    """Display scan configuration."""

    print(
        f"{Fore.CYAN}"
        f"[*] Targets  : {len(targets)}"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        f"[*] Threads  : {args.threads}"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        f"[*] Timeout  : {args.timeout}s"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        f"[*] Templates: {args.templates}"
        f"{Style.RESET_ALL}"
    )

    print(
        f"{Fore.CYAN}"
        f"[*] Database : SQLite"
        f"{Style.RESET_ALL}"
    )

    print()


# ============================================================
# MULTIPLE TARGET SCANNING
# ============================================================

def scan_multiple_targets(
    targets,
    args,
):
    """
    Scan multiple targets.
    """

    results = []

    workers = max(
        1,
        min(
            args.threads,
            len(targets),
        ),
    )

    executor = ThreadPoolExecutor(
        max_workers=workers
    )

    futures = {}

    try:

        for target in targets:

            if STOP_EVENT.is_set():
                break

            future = executor.submit(
                scan_single_target,
                target,
                args,
            )

            futures[future] = target

        for future in as_completed(
            futures
        ):

            target = futures[future]

            try:

                result = future.result()

            except Exception as exc:

                result = {
                    "url": target,
                    "scan_id": None,
                    "findings": [],
                    "fingerprint": {},
                    "error": str(exc),
                    "database_error": None,
                    "database_saved": False,
                    "timestamp": now(),
                    "start_time": now(),
                    "end_time": now(),
                }

            results.append(result)

    finally:

        executor.shutdown(
            wait=False,
            cancel_futures=True,
        )

    return results


# ============================================================
# DISPLAY RESULTS
# ============================================================

def display_results(
    results,
    quiet=False,
):
    """Display scan results."""

    if quiet:
        return

    for result in results:

        print_fingerprint(
            result.get(
                "fingerprint",
                {},
            )
        )

        print_findings(
            result.get(
                "findings",
                [],
            )
        )

        if result.get("error"):

            print(
                f"{Fore.RED}"
                f"Error: {result['error']}"
                f"{Style.RESET_ALL}"
            )

        print_result_summary(
            result
        )


# ============================================================
# GLOBAL SUMMARY
# ============================================================

def print_global_summary(
    results,
    elapsed,
):
    """Print final scan summary."""

    total_targets = len(results)

    total_findings = sum(
        len(
            result.get(
                "findings",
                [],
            ) or []
        )
        for result in results
    )

    confirmed_findings = 0

    for result in results:

        for finding in (
            result.get(
                "findings",
                [],
            ) or []
        ):

            if (
                isinstance(
                    finding,
                    dict,
                )
                and finding.get(
                    "confirmed",
                    False,
                )
            ):

                confirmed_findings += 1

    database_saved = sum(
        1
        for result in results
        if result.get(
            "database_saved"
        )
    )

    failed = sum(
        1
        for result in results
        if result.get(
            "error"
        )
    )

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
        f"Targets           : "
        f"{total_targets}"
    )

    print(
        f"Findings          : "
        f"{total_findings}"
    )

    print(
        f"Confirmed         : "
        f"{confirmed_findings}"
    )

    print(
        f"Database saved    : "
        f"{database_saved}/{total_targets}"
    )

    print(
        f"Scan errors       : "
        f"{failed}"
    )

    print(
        f"Duration          : "
        f"{elapsed:.2f}s"
    )


# ============================================================
# MAIN
# ============================================================

def main():
    """Main VulnForge CLI entry point."""

    parser = build_parser()

    args = parser.parse_args()

    # --------------------------------------------------------
    # VALIDATE
    # --------------------------------------------------------

    if not validate_args(args):
        return 2

    # --------------------------------------------------------
    # HISTORY
    # --------------------------------------------------------

    if args.history:

        show_history()

        return 0

    # --------------------------------------------------------
    # PDF
    # --------------------------------------------------------

    if args.pdf:

        generate_pdf_report(args)

        return 0

    # --------------------------------------------------------
    # SAVED SCAN
    # --------------------------------------------------------

    if args.scan_id:

        show_scan(
            args.scan_id
        )

        return 0

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    if args.dashboard:

        try:

            initialize_database()

        except Exception as exc:

            print(
                f"{Fore.RED}"
                f"[DATABASE ERROR] {exc}"
                f"{Style.RESET_ALL}"
            )

            return 1

        success, message = (
            refresh_dashboard(
                args.dashboard_output
            )
        )

        if success:

            print(
                f"{Fore.GREEN}"
                f"[DASHBOARD] Written to {message}"
                f"{Style.RESET_ALL}"
            )

            return 0

        print(
            f"{Fore.RED}"
            f"[DASHBOARD ERROR] {message}"
            f"{Style.RESET_ALL}"
        )

        return 1

    # --------------------------------------------------------
    # TARGET REQUIRED
    # --------------------------------------------------------

    if not args.url and not args.list:

        parser.print_help()

        return 0

    # --------------------------------------------------------
    # DATABASE
    # --------------------------------------------------------

    try:

        initialize_database()

    except Exception as exc:

        print(
            f"{Fore.RED}"
            "[DATABASE ERROR] "
            f"Could not initialize SQLite:"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.RED}"
            f"{exc}"
            f"{Style.RESET_ALL}"
        )

        return 1

    # --------------------------------------------------------
    # BANNER
    # --------------------------------------------------------

    if not args.quiet:
        print(BANNER)

    # --------------------------------------------------------
    # TARGETS
    # --------------------------------------------------------

    if args.url:

        targets = [
            normalize_target(
                args.url
            )
        ]

    else:

        targets = load_targets(
            args.list
        )

    targets = [
        target
        for target in targets
        if target
    ]

    targets = list(
        dict.fromkeys(targets)
    )

    if not targets:

        print(
            f"{Fore.RED}"
            "No valid targets supplied."
            f"{Style.RESET_ALL}"
        )

        return 1

    # --------------------------------------------------------
    # CONFIGURATION
    # --------------------------------------------------------

    if not args.quiet:

        print_scan_configuration(
            args,
            targets,
        )

    # --------------------------------------------------------
    # START
    # --------------------------------------------------------

    global_start = time.time()

    if len(targets) == 1:

        results = [
            scan_single_target(
                targets[0],
                args,
            )
        ]

    else:

        results = scan_multiple_targets(
            targets,
            args,
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
    # DISPLAY
    # --------------------------------------------------------

    display_results(
        results,
        quiet=args.quiet,
    )

    # --------------------------------------------------------
    # SUMMARY
    # --------------------------------------------------------

    elapsed = (
        time.time()
        - global_start
    )

    print_global_summary(
        results,
        elapsed,
    )

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    if not args.no_auto_dashboard:

        success, message = (
            refresh_dashboard(
                args.dashboard_output
            )
        )

        if success:

            print(
                f"{Fore.GREEN}"
                f"\n[DASHBOARD] Refreshed: "
                f"{message}"
                f"{Style.RESET_ALL}"
            )

        else:

            print(
                f"{Fore.YELLOW}"
                f"\n[DASHBOARD] Not refreshed: "
                f"{message}"
                f"{Style.RESET_ALL}"
            )

    # --------------------------------------------------------
    # JSON
    # --------------------------------------------------------

    if args.output:

        save_json(
            results,
            args.output,
        )

    # --------------------------------------------------------
    # CSV
    # --------------------------------------------------------

    if args.csv:

        save_csv(
            results,
            args.csv,
        )

    # --------------------------------------------------------
    # JSON STDOUT
    # --------------------------------------------------------

    if args.json:

        print(
            json.dumps(
                results,
                indent=2,
                default=str,
            )
        )

    # --------------------------------------------------------
    # AI
    # --------------------------------------------------------

    if args.ai:

        print(
            f"{Fore.CYAN}"
            "\n[AI] AI reporting requested."
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.CYAN}"
            f"[AI] Model : {args.ai_model}"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.CYAN}"
            f"[AI] URL   : {args.ai_url}"
            f"{Style.RESET_ALL}"
        )

        print(
            f"{Fore.YELLOW}"
            "[AI] AI generation is handled by the "
            "reporting layer."
            f"{Style.RESET_ALL}"
        )

    # --------------------------------------------------------
    # BUG BOUNTY PRO - ADVANCED CORRELATION
    # --------------------------------------------------------

    if getattr(args, "bugbounty", False):
        print(
            f"\n{Fore.CYAN}{Style.BRIGHT}"
            "=== BUG BOUNTY PRO MODE ==="
            f"{Style.RESET_ALL}"
        )
        try:
            from correlation.advanced_chain import AdvancedCorrelationEngine
            from report.hackerone_report import HackerOneReportGenerator
            from core.scope import BugBountyScope
            from engine.pipeline import ScanConfig
            import sys
            sys.path.insert(0, str(__import__('pathlib').Path(__file__).resolve().parents[1] / "report"))
            
            # Gather all findings across all targets
            all_findings = []
            for res in results:
                all_findings.extend(res.get("findings", []))

            print(
                f"{Fore.CYAN}[CHAIN] Correlating {len(all_findings)} findings into attack chains..."
                f"{Style.RESET_ALL}"
            )

            # Scope enforcement display
            scope_obj = None
            if getattr(args, "scope", None):
                try:
                    from core.scope import BugBountyScope
                    scope_obj = BugBountyScope(in_scope=args.scope, out_of_scope=getattr(args, "out_scope", []))
                    print(
                        f"{Fore.GREEN}[SCOPE] In-scope: {args.scope} | Out: {getattr(args, 'out_scope', [])}"
                        f"{Style.RESET_ALL}"
                    )
                except Exception as e:
                    print(f"[SCOPE WARN] {e}")

            engine = AdvancedCorrelationEngine(all_findings)
            chains = engine.correlate()

            p1_chains = [c for c in chains if c.severity == "P1"]
            print(
                f"{Fore.MAGENTA}{Style.BRIGHT}[CHAINS] Found {len(chains)} chains, {len(p1_chains)} P1 (Account Takeover/RCE)"
                f"{Style.RESET_ALL}"
            )
            for chain in chains:
                color = Fore.RED + Style.BRIGHT if chain.severity == "P1" else Fore.YELLOW
                print(
                    f"  {color}[{chain.severity}] {chain.title} -> {chain.estimated_bounty} (conf {chain.confidence}){Style.RESET_ALL}"
                )
                print(f"      Impact: {chain.impact[:100]}...")

            # Generate HackerOne report if requested
            # Build PipelineResult-like object for report generator
            if getattr(args, "hackerone_report", None):
                from dataclasses import dataclass
                from datetime import datetime
                # Minimal result wrapper
                @dataclass
                class MiniResult:
                    scan_id: str
                    target: str
                    duration: float
                    professional_findings: list
                    attack_chains: list
                    metrics: dict
                    fingerprint: dict
                    scope: object

                # Convert raw findings to professional format for report reuse
                # Use existing report generator if available
                try:
                    from engine.pipeline import BugBountyPipeline, ScanConfig
                    from core.evidence import Finding, HttpEvidence
                    
                    # Build professional findings quickly
                    pro_findings = []
                    for idx, rf in enumerate(all_findings):
                        ev = rf.get("evidence") or {}
                        http_ev = HttpEvidence(
                            method=ev.get("method","GET"),
                            url=ev.get("url",""),
                            request_headers=ev.get("request_headers",{}),
                            request_body=ev.get("request_body",""),
                            response_status=ev.get("status",200),
                            response_headers=ev.get("response_headers",{}),
                            response_body=ev.get("response_body","")[:2000],
                            duration=ev.get("duration",0.0)
                        )
                        pro_findings.append(Finding(
                            id=f"VF-{idx}",
                            template_id=rf.get("template_id","unknown"),
                            name=rf.get("name","Unnamed"),
                            severity=(rf.get("severity") or "info").lower(),
                            confidence=rf.get("confidence",0.5),
                            category=rf.get("category",""),
                            endpoint=http_ev.url,
                            method=http_ev.method,
                            evidence=http_ev,
                            impact=rf.get("impact",""),
                            remediation=rf.get("remediation",""),
                            cwe=rf.get("cwe",""),
                            owasp=rf.get("owasp",""),
                            tags=rf.get("matched_types",[]),
                            occurrences=rf.get("occurrences",1),
                            affected_endpoints=rf.get("affected_endpoints",[http_ev.url]),
                            verified=rf.get("confirmed",False),
                        ))
                    
                    # Metrics
                    metrics = {
                        "discovered_endpoints": len(targets),
                        "in_scope_endpoints": len(targets),
                        "raw_findings": len(all_findings),
                        "deduped_findings": len(all_findings),
                        "professional_findings": len(pro_findings),
                        "attack_chains": len(chains),
                        "p1_chains": len(p1_chains),
                        "total_requests": sum(r.get("requests_sent",0) for r in results),
                        "duration": elapsed,
                    }

                    class ScopeWrapper:
                        def __init__(self, in_s, out_s):
                            self.in_scope_raw = in_s
                            self.out_scope_raw = out_s
                        def get_root_domains(self):
                            return set()

                    mini = MiniResult(
                        scan_id=results[0].get("scan_id","") if results else "unknown",
                        target=targets[0] if targets else "unknown",
                        duration=elapsed,
                        professional_findings=pro_findings,
                        attack_chains=chains,
                        metrics=metrics,
                        fingerprint=results[0].get("fingerprint",{}) if results else {},
                        scope=ScopeWrapper(getattr(args,"scope",[]), getattr(args,"out_scope",[]))
                    )

                    # Need PipelineResult shape - create simple wrapper that report generator accepts
                    from report.hackerone_report import HackerOneReportGenerator
                    # HackerOneReportGenerator expects PipelineResult, but we can adapt: it uses .scan_id, .target, .duration, .professional_findings, .attack_chains, .metrics, .fingerprint, .scope
                    # MiniResult has same attrs
                    gen = HackerOneReportGenerator(mini)
                    saved = gen.save(args.hackerone_report)
                    print(
                        f"{Fore.GREEN}[REPORT] HackerOne report saved: {saved}"
                        f"{Style.RESET_ALL}"
                    )
                except Exception as e:
                    print(
                        f"{Fore.RED}[REPORT ERROR] Could not generate HackerOne report: {e}"
                        f"{Style.RESET_ALL}"
                    )
                    import traceback
                    traceback.print_exc()

            # Save chains JSON
            if p1_chains:
                print(
                    f"\n{Fore.RED}{Style.BRIGHT}[!] {len(p1_chains)} P1 CHAINS FOUND - HIGH BOUNTY POTENTIAL! Check report.{Style.RESET_ALL}"
                )

        except ImportError as e:
            print(
                f"{Fore.RED}[CHAIN ERROR] Advanced correlation module missing: {e}"
                f"{Style.RESET_ALL}"
            )
            print(f"{Fore.YELLOW}Make sure core/scope.py, correlation/advanced_chain.py, report/hackerone_report.py exist.{Style.RESET_ALL}")
        except Exception as e:
            print(
                f"{Fore.RED}[CHAIN ERROR] {e}"
                f"{Style.RESET_ALL}"
            )
            import traceback
            traceback.print_exc()

    # --------------------------------------------------------
    # FINISHED
    # --------------------------------------------------------

    print(
        f"\n{Fore.GREEN}"
        "✓ VulnForge finished."
        f"{Style.RESET_ALL}"
    )

    return 0


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    sys.exit(main())
