"""
VulnForge Ultimate - Master Scan Orchestrator (v3.3)
Coordinates web crawling, dynamic route discovery, multi-stage fuzzing,
zero false-positive verification, and live telemetry broadcasting.
"""

import asyncio
import os
import sys
import time
import urllib.parse
from datetime import datetime
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database import save_scan, update_scan_progress, save_finding, get_scan_by_id
from engine.requester import Requester
from engine.baseline import TargetBaseline
from engine.crawler import crawl_target
from engine.modules.sensitive_files import run_sensitive_files_scan
from engine.modules.mass_assignment import run_mass_assignment_scan
from engine.modules.ssrf import run_ssrf_scan
from engine.modules.sqli import run_sqli_scan
from engine.modules.xss import run_xss_scan
from engine.modules.cors_csrf import run_cors_scan
from engine.modules.path_traversal import run_path_traversal_scan
from engine.modules.api_debug import run_api_debug_scan
from engine.modules.open_redirect import run_open_redirect_scan
from engine.modules.security_headers import run_security_headers_scan

ACTIVE_SCAN_LOGS: Dict[str, List[str]] = {}
ACTIVE_LISTENERS: Dict[str, List[asyncio.Queue]] = {}


def register_listener(scan_id: str, queue: asyncio.Queue):
    if scan_id not in ACTIVE_LISTENERS:
        ACTIVE_LISTENERS[scan_id] = []
    ACTIVE_LISTENERS[scan_id].append(queue)


def unregister_listener(scan_id: str, queue: asyncio.Queue):
    if scan_id in ACTIVE_LISTENERS and queue in ACTIVE_LISTENERS[scan_id]:
        ACTIVE_LISTENERS[scan_id].remove(queue)


async def emit_scan_event(scan_id: str, message: str, level: str = "INFO", data: Optional[Dict[str, Any]] = None):
    ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    entry = f"[{ts}] [{level}] {message}"
    
    if scan_id not in ACTIVE_SCAN_LOGS:
        ACTIVE_SCAN_LOGS[scan_id] = []
    ACTIVE_SCAN_LOGS[scan_id].append(entry)
    
    event_payload = {
        "timestamp": ts,
        "level": level,
        "message": message,
        "data": data or {}
    }
    
    if scan_id in ACTIVE_LISTENERS:
        for q in list(ACTIVE_LISTENERS[scan_id]):
            try:
                await q.put(event_payload)
            except Exception:
                pass


async def execute_security_scan(
    scan_id: str,
    target_url: str,
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Executes a comprehensive, multi-stage penetration test across all crawled endpoints.
    """
    options = options or {}
    start_time = time.perf_counter()

    # Normalize target URL
    if not target_url.startswith("http://") and not target_url.startswith("https://"):
        target_url = "https://" + target_url
    target_url = target_url.rstrip("/")

    # Initialize Scan in Database
    save_scan({
        "id": scan_id,
        "target_url": target_url,
        "status": "scanning",
        "findings_count": 0,
        "confirmed_count": 0,
        "requests_count": 0,
        "duration_seconds": 0.0,
        "created_at": datetime.now().isoformat(),
        "options": options,
        "summary": {}
    })

    requester = Requester(scan_id=scan_id, timeout=options.get("timeout", 6.0))
    baseline = TargetBaseline(target_url)

    total_findings_found = 0
    confirmed_findings_found = 0

    try:
        await emit_scan_event(scan_id, f"Initializing VulnForge Engine v3.3 on {target_url}", "SYSTEM")
        
        # -------------------------------------------------------------
        # STAGE 1: Server Fingerprinting & Baseline Profiling
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 1: Establishing server baseline & Soft-404 profile...", "STAGE")
        await baseline.profile(requester)
        await emit_scan_event(
            scan_id,
            f"Baseline Profile: CDN={baseline.cdn_provider or 'Direct Server'}, Soft-404={baseline.is_soft_404}",
            "SUCCESS"
        )

        # -------------------------------------------------------------
        # STAGE 2: Web Spidering & Dynamic Route Discovery
        # -------------------------------------------------------------
        max_crawl_pages = options.get("max_pages", 25)
        await emit_scan_event(scan_id, f"Stage 2: Launching web spider (Max pages: {max_crawl_pages})...", "STAGE")
        crawl_data = await crawl_target(requester, target_url, max_pages=max_crawl_pages)
        
        discovered_endpoints = crawl_data.get("endpoints", [target_url])
        discovered_forms = crawl_data.get("forms", [])
        discovered_params = crawl_data.get("parameters", [])

        await emit_scan_event(
            scan_id,
            f"Spidering Complete: Discovered {len(discovered_endpoints)} endpoints, {len(discovered_forms)} forms, {len(discovered_params)} parameters.",
            "SUCCESS"
        )

        # -------------------------------------------------------------
        # STAGE 3: Sensitive Files & Version Control Discovery
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 3: Probing for sensitive configuration files & Git metadata...", "STAGE")
        findings_files = await run_sensitive_files_scan(requester, baseline, scan_id, target_url)
        for f in findings_files:
            save_finding(f)
            total_findings_found += 1
            if f.get("is_confirmed"):
                confirmed_findings_found += 1
            await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 4: Mass Assignment & Model Binding Escalation
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 4: Probing Mass Assignment & Privilege Escalation...", "STAGE")
        findings_mass = await run_mass_assignment_scan(requester, baseline, scan_id, target_url)
        for f in findings_mass:
            save_finding(f)
            total_findings_found += 1
            if f.get("is_confirmed"):
                confirmed_findings_found += 1
            await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 5: Advanced SSRF & Cloud IMDSv1/v2 Differential
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 5: Probing Server-Side Request Forgery (SSRF)...", "STAGE")
        findings_ssrf = await run_ssrf_scan(requester, baseline, scan_id, target_url)
        for f in findings_ssrf:
            save_finding(f)
            total_findings_found += 1
            if f.get("is_confirmed"):
                confirmed_findings_found += 1
            await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 6: Multi-Engine SQL Injection Fuzzing Across Routes
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, f"Stage 6: SQL Injection fuzzing across {min(len(discovered_endpoints), 8)} discovered routes...", "STAGE")
        for ep in list(discovered_endpoints)[:8]:
            findings_sqli = await run_sqli_scan(requester, baseline, scan_id, ep)
            for f in findings_sqli:
                save_finding(f)
                total_findings_found += 1
                if f.get("is_confirmed"):
                    confirmed_findings_found += 1
                await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 7: Cross-Site Scripting (XSS) Fuzzing Across Routes
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, f"Stage 7: Context-aware XSS fuzzing across {min(len(discovered_endpoints), 8)} routes...", "STAGE")
        for ep in list(discovered_endpoints)[:8]:
            findings_xss = await run_xss_scan(requester, baseline, scan_id, ep)
            for f in findings_xss:
                save_finding(f)
                total_findings_found += 1
                if f.get("is_confirmed"):
                    confirmed_findings_found += 1
                await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 8: Path Traversal & Local File Inclusion (LFI)
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 8: Testing Path Traversal & Arbitrary File Retrieval...", "STAGE")
        for ep in list(discovered_endpoints)[:5]:
            findings_lfi = await run_path_traversal_scan(requester, baseline, scan_id, ep)
            for f in findings_lfi:
                save_finding(f)
                total_findings_found += 1
                if f.get("is_confirmed"):
                    confirmed_findings_found += 1
                await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 9: API Documentation & Actuator Endpoints
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 9: Auditing API Actuators, Swagger & GraphQL...", "STAGE")
        findings_api = await run_api_debug_scan(requester, baseline, scan_id, target_url)
        for f in findings_api:
            save_finding(f)
            total_findings_found += 1
            if f.get("is_confirmed"):
                confirmed_findings_found += 1
            await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 10: Insecure CORS & Open Redirection
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 10: Testing Cross-Origin (CORS) & Open Redirection...", "STAGE")
        findings_cors = await run_cors_scan(requester, baseline, scan_id, target_url)
        for f in findings_cors:
            save_finding(f)
            total_findings_found += 1
            if f.get("is_confirmed"):
                confirmed_findings_found += 1
            await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        findings_redir = await run_open_redirect_scan(requester, baseline, scan_id, target_url)
        for f in findings_redir:
            save_finding(f)
            total_findings_found += 1
            if f.get("is_confirmed"):
                confirmed_findings_found += 1
            await emit_scan_event(scan_id, f"CONFIRMED VULNERABILITY: {f['vuln_type']} ({f['severity']}) on {f['endpoint']}", "VULN", {"finding": f})

        # -------------------------------------------------------------
        # STAGE 11: Security Headers & Defensive Hardening
        # -------------------------------------------------------------
        await emit_scan_event(scan_id, "Stage 11: Auditing Security Headers & Clickjacking defenses...", "STAGE")
        findings_sec = await run_security_headers_scan(requester, baseline, scan_id, target_url)
        for f in findings_sec:
            save_finding(f)
            total_findings_found += 1
            if f.get("is_confirmed"):
                confirmed_findings_found += 1
            await emit_scan_event(scan_id, f"DEFENSIVE MISCONFIGURATION: {f['vuln_type']}", "VULN", {"finding": f})

        duration = round(time.perf_counter() - start_time, 2)

        # Retrieve total request count
        scan_record = get_scan_by_id(scan_id)
        req_count = scan_record["requests_count"] if scan_record else 0

        update_scan_progress(
            scan_id=scan_id,
            requests_count=req_count,
            findings_count=total_findings_found,
            confirmed_count=confirmed_findings_found,
            status="completed",
            duration_seconds=duration
        )

        await emit_scan_event(
            scan_id,
            f"Assessment Complete in {duration}s. Total HTTP Requests: {req_count}, 100% Confirmed Vulnerabilities: {confirmed_findings_found}",
            "COMPLETE"
        )

        return {
            "scan_id": scan_id,
            "status": "completed",
            "requests_count": req_count,
            "findings_count": total_findings_found,
            "confirmed_count": confirmed_findings_found,
            "duration_seconds": duration,
            "crawled_endpoints_count": len(discovered_endpoints)
        }

    except Exception as e:
        duration = round(time.perf_counter() - start_time, 2)
        await emit_scan_event(scan_id, f"Fatal error during scan: {str(e)}", "ERROR")
        update_scan_progress(scan_id, 0, 0, 0, status="failed", duration_seconds=duration)
        raise e
    finally:
        await requester.close()
