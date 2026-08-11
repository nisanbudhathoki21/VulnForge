from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

async def run_cors_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    attacker_origin = "https://evil-attacker.domain"
    res = await requester.send("GET", f"{base_clean}/", headers={"Origin": attacker_origin}, module="cors_probe")
    h = {k.lower(): v for k, v in res.headers.items()}
    allow_origin = h.get("access-control-allow-origin", "")
    allow_cred = h.get("access-control-allow-credentials", "").lower()
    if allow_origin == attacker_origin and allow_cred == "true":
        findings.append({
            "scan_id": scan_id, "target_url": target_url, "endpoint": f"{base_clean}/", "tested_endpoint": f"{base_clean}/",
            "parameter_name": "Origin Header", "parameter_location": "Request Headers",
            "payload_used": f"Origin: {attacker_origin}", "payload_type": "Arbitrary Origin Reflection Probe",
            "vuln_type": "CORS Misconfiguration (Arbitrary Origin with Credentials)",
            "title": "Insecure Cross-Origin Resource Sharing (CORS) Configuration",
            "severity": "HIGH", "confidence": "CONFIRMED", "is_confirmed": True,
            "cvss_score": 8.1, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
            "cwe_id": "CWE-942", "owasp_category": "A05:2021-Security Misconfiguration",
            "category": "Misconfiguration", "template_id": "vf-cors-arbitrary-creds",
            "short_description": "The server reflects arbitrary untrusted Origin headers while enabling credentials access.",
            "description": "Server dynamically reflects Origin header and returns Access-Control-Allow-Credentials: true.",
            "technical_impact": "Hostile third-party sites can issue authenticated cross-origin requests and read sensitive personal user data.",
            "remediation": "Do not dynamically reflect Origin. Maintain a strict whitelist of trusted partner origins.",
            "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
            "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
            "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
            "baseline_raw_response": baseline.root_response.raw_response if baseline.root_response else "",
            "verification_proof": f"Server reflected Access-Control-Allow-Origin: {allow_origin} with Access-Control-Allow-Credentials: true"
        })
    return findings
