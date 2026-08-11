from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

REDIRECT_PARAMS = ["redirect", "url", "next", "return", "dest", "target", "r", "goto"]
ATTACKER_URL = "https://evil-attacker.example.com"

async def run_open_redirect_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    for param in REDIRECT_PARAMS[:3]:
        test_url = f"{base_clean}/?{param}={ATTACKER_URL}"
        res = await requester.send("GET", test_url, module="open_redirect")
        h = {k.lower(): v for k, v in res.headers.items()}
        location = h.get("location", "")
        if res.status_code in [301, 302, 303, 307, 308] and (location.startswith(ATTACKER_URL) or "evil-attacker.example.com" in location):
            findings.append({
                "scan_id": scan_id, "target_url": target_url, "endpoint": test_url, "tested_endpoint": test_url,
                "parameter_name": param, "parameter_location": "Query Parameter",
                "payload_used": f"?{param}={ATTACKER_URL}", "payload_type": "Arbitrary Domain Redirection Probe",
                "vuln_type": "Open URL Redirection",
                "title": f"Unvalidated Open Redirect via '{param}' parameter",
                "severity": "MEDIUM", "confidence": "CONFIRMED", "is_confirmed": True,
                "cvss_score": 6.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                "cwe_id": "CWE-601", "owasp_category": "A01:2021-Broken Access Control",
                "category": "Client-Side Redirect", "template_id": "vf-med-open-redirect",
                "short_description": f"The application redirects users to arbitrary external domains specified in parameter '{param}'.",
                "description": f"Unvalidated target destination accepted in query parameter '{param}'.",
                "technical_impact": "Can be utilized in phishing campaigns and OAuth authorization code theft.",
                "remediation": "Validate target redirection destinations against a server-side whitelist.",
                "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
                "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
                "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
                "baseline_raw_response": baseline.root_response.raw_response if baseline.root_response else "",
                "verification_proof": f"HTTP {res.status_code} redirection returned Location: {location}"
            })
            break
    return findings
