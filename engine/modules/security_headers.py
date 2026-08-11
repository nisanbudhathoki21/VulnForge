import urllib.parse
from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

async def run_security_headers_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    
    # Follow redirects up to 5 hops to find the true rendered page
    current_url = f"{base_clean}/"
    res = None
    
    for _ in range(5):
        res = await requester.send("GET", current_url, module="headers_check")
        if res.status_code in [301, 302, 303, 307, 308]:
            loc = res.headers.get("location", "").strip()
            if loc:
                current_url = urllib.parse.urljoin(current_url, loc)
                continue
        break

    if not res:
        return findings

    headers_lower = {k.lower(): v for k, v in res.headers.items()}

    # Check 1: Clickjacking / X-Frame-Options on rendered page
    if "x-frame-options" not in headers_lower and "content-security-policy" not in headers_lower:
        findings.append({
            "scan_id": scan_id, "target_url": target_url, "endpoint": res.url, "tested_endpoint": res.url,
            "parameter_name": "X-Frame-Options / CSP", "parameter_location": "Response Headers",
            "payload_used": "GET / HTTP/1.1", "payload_type": "Defensive Header Audit Probe",
            "vuln_type": "Defensive Hardening: Missing Clickjacking Protection (X-Frame-Options / CSP)",
            "title": "Missing Clickjacking Defense on Landing Page",
            "severity": "INFO", "finding_tier": "HARDENING",
            "confidence": "CONFIRMED", "is_confirmed": True, "cvss_score": 4.3,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "cwe_id": "CWE-1021",
            "owasp_category": "A05:2021-Security Misconfiguration", "category": "Defensive Hardening",
            "template_id": "vf-info-clickjacking-xfo",
            "short_description": "The final rendered landing page does not specify X-Frame-Options or CSP frame-ancestors headers.",
            "description": "The server does not specify an X-Frame-Options header or Content-Security-Policy with 'frame-ancestors' on the final landing page.",
            "technical_impact": "Allows the landing page to be rendered inside hostile third-party iframes (UI Redressing risk).",
            "remediation": "Add 'X-Frame-Options: SAMEORIGIN' or 'Content-Security-Policy: frame-ancestors 'self';' to all HTTP response headers.",
            "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
            "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
            "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
            "baseline_raw_response": res.raw_response, "verification_proof": f"Rendered page ({res.url}) headers lack X-Frame-Options and CSP frame-ancestors directives."
        })

    # Check 2: Content-Security-Policy on rendered page
    if "content-security-policy" not in headers_lower:
        findings.append({
            "scan_id": scan_id, "target_url": target_url, "endpoint": res.url, "tested_endpoint": res.url,
            "parameter_name": "Content-Security-Policy", "parameter_location": "Response Headers",
            "payload_used": "GET / HTTP/1.1", "payload_type": "Defensive Header Audit Probe",
            "vuln_type": "Defensive Hardening: Missing Content Security Policy (CSP)",
            "title": "Missing Content-Security-Policy (CSP) Header",
            "severity": "INFO", "finding_tier": "HARDENING",
            "confidence": "CONFIRMED", "is_confirmed": True, "cvss_score": 3.7,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N", "cwe_id": "CWE-1021",
            "owasp_category": "A05:2021-Security Misconfiguration", "category": "Defensive Hardening",
            "template_id": "vf-info-missing-csp",
            "short_description": "The final rendered landing page does not enforce a Content Security Policy (CSP).",
            "description": "The web application does not implement a Content Security Policy (CSP) header on the final rendered landing page.",
            "technical_impact": "Lacks defense-in-depth mitigation against code injection and unauthorized resource loading.",
            "remediation": "Define and enforce a strict Content Security Policy restricting script execution to authorized domains/nonces.",
            "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
            "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
            "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
            "baseline_raw_response": res.raw_response, "verification_proof": f"Rendered landing page ({res.url}) headers verified missing Content-Security-Policy header."
        })

    return findings
