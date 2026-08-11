import urllib.parse
from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

XSS_CANARY = "vf7821\"'><script>alert('VulnForge_XSS')</script>"
PARAMS = ["q", "search", "query", "s", "keyword", "redirect", "msg", "name"]

async def run_xss_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    for param in PARAMS[:3]:
        encoded = urllib.parse.quote(XSS_CANARY)
        test_url = f"{base_clean}/?{param}={encoded}"
        res = await requester.send("GET", test_url, module="xss_reflection")
        if "<script>alert('VulnForge_XSS')</script>" in res.body:
            findings.append({
                "scan_id": scan_id, "target_url": target_url, "endpoint": test_url, "tested_endpoint": test_url,
                "parameter_name": param, "parameter_location": "Query Parameter",
                "payload_used": XSS_CANARY, "payload_type": "HTML Script Tag Reflection Probe",
                "vuln_type": "Reflected Cross-Site Scripting (XSS)",
                "title": f"Reflected XSS via '{param}' parameter",
                "severity": "HIGH", "confidence": "CONFIRMED", "is_confirmed": True,
                "cvss_score": 7.5, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cwe_id": "CWE-79", "owasp_category": "A03:2021-Injection",
                "category": "Client-Side Injection", "template_id": "vf-xss-reflected-01",
                "short_description": f"The '{param}' query parameter reflects unsanitized user input directly into HTML without output encoding.",
                "description": f"Unescaped script tags reflected in HTML body when testing parameter '{param}'.",
                "technical_impact": "Session hijacking, credential theft via phishing DOM overlays, and unauthorized actions in victim context.",
                "remediation": "Apply contextual output encoding (HTML entity encoding) before rendering dynamic inputs. Enforce a strict CSP.",
                "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
                "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
                "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
                "baseline_raw_response": baseline.root_response.raw_response if baseline.root_response else "",
                "verification_proof": "Confirmed reflection of unencoded <script> tag payload in HTML body response."
            })
            break
    return findings
