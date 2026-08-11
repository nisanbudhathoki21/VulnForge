import urllib.parse
from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

async def run_security_headers_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    
    # 1. Fetch root page
    res = await requester.send("GET", f"{base_clean}/", module="headers_check")

    # 2. If response is a canonical redirect (e.g. airbnb.com -> www.airbnb.com), follow it to inspect actual landing page
    if res.status_code in [301, 302, 307, 308]:
        headers_lower = {k.lower(): v for k, v in res.headers.items()}
        location = headers_lower.get("location", "")
        if location:
            target_final = urllib.parse.urljoin(f"{base_clean}/", location)
            res = await requester.send("GET", target_final, module="headers_check_followed")

    headers_lower = {k.lower(): v for k, v in res.headers.items()}

    # Check 1: Clickjacking / X-Frame-Options
    if "x-frame-options" not in headers_lower and "content-security-policy" not in headers_lower:
        findings.append({
            "scan_id": scan_id, "target_url": target_url, "endpoint": res.url, "tested_endpoint": res.url,
            "parameter_name": "X-Frame-Options / CSP", "parameter_location": "Response Headers",
            "payload_used": "GET / HTTP/1.1", "payload_type": "Defensive Header Audit Probe",
            "vuln_type": "Missing Clickjacking Protection (X-Frame-Options / CSP frame-ancestors)",
            "title": "Missing Clickjacking Protection on Root Endpoint", "severity": "MEDIUM",
            "confidence": "CONFIRMED", "is_confirmed": True, "cvss_score": 4.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "cwe_id": "CWE-1021",
            "owasp_category": "A05:2021-Security Misconfiguration", "category": "Defensive Misconfiguration",
            "template_id": "vf-med-clickjacking-missing-xfo",
            "short_description": "The server does not specify an X-Frame-Options header or Content-Security-Policy with frame-ancestors on the rendered page.",
            "description": "The server does not specify an X-Frame-Options header or Content-Security-Policy with 'frame-ancestors', allowing the target page to be framed inside hostile iframes.",
            "technical_impact": "Attackers can superimpose invisible UI layers over authenticated pages to trick victims into triggering unintended clicks (Clickjacking).",
            "remediation": "Add header 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self';' to HTTP response headers.",
            "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
            "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
            "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
            "baseline_raw_response": res.raw_response, "verification_proof": "Rendered response headers lack X-Frame-Options and Content-Security-Policy frame-ancestors directives."
        })

    # Check 2: Content-Security-Policy
    if "content-security-policy" not in headers_lower:
        findings.append({
            "scan_id": scan_id, "target_url": target_url, "endpoint": res.url, "tested_endpoint": res.url,
            "parameter_name": "Content-Security-Policy", "parameter_location": "Response Headers",
            "payload_used": "GET / HTTP/1.1", "payload_type": "Defensive Header Audit Probe",
            "vuln_type": "Missing Content Security Policy (CSP)", "title": "Missing Content-Security-Policy Header",
            "severity": "LOW", "confidence": "CONFIRMED", "is_confirmed": True, "cvss_score": 3.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "cwe_id": "CWE-1021",
            "owasp_category": "A05:2021-Security Misconfiguration", "category": "Defensive Misconfiguration",
            "template_id": "vf-low-missing-csp",
            "short_description": "The web application does not implement a Content Security Policy (CSP) header on the rendered landing page.",
            "description": "The web application does not implement a Content Security Policy (CSP) header, increasing the severity of any potential Cross-Site Scripting (XSS) or data exfiltration attacks.",
            "technical_impact": "Lacks defense-in-depth mitigation against code injection and unauthorized external resource loading.",
            "remediation": "Define and enforce a strict Content Security Policy restricting script execution to authorized domains/nonces.",
            "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
            "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
            "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
            "baseline_raw_response": res.raw_response, "verification_proof": "Rendered landing page headers verified missing Content-Security-Policy header."
        })

    return findings
