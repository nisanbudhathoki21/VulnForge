from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline

API_PROBES = [
    {
        "path": "/actuator/env", "method": "GET", "expected_sub": "activeProfiles",
        "vuln_type": "Spring Boot Actuator Environment Exposure (/actuator/env)",
        "severity": "HIGH", "cvss_score": 7.5, "cwe_id": "CWE-200", "owasp_category": "A05:2021-Security Misconfiguration",
        "short_description": "Spring Boot Actuator env endpoint is accessible, leaking server configuration and environment variables.",
        "description": "Exposed Spring Boot Actuator env endpoint revealing server configuration and environment variables.",
        "impact": "Information disclosure of system variables, application properties, and configuration settings.",
        "remediation": "Disable management endpoints in application.properties (`management.endpoints.web.exposure.exclude=env`)."
    },
    {
        "path": "/swagger-ui.html", "method": "GET", "expected_sub": "swagger-ui",
        "vuln_type": "Swagger / OpenAPI Documentation Interface Exposed",
        "severity": "MEDIUM", "cvss_score": 5.3, "cwe_id": "CWE-200", "owasp_category": "A05:2021-Security Misconfiguration",
        "short_description": "Interactive API documentation console (Swagger UI) is publicly accessible.",
        "description": "Interactive API documentation console (Swagger UI) is publicly accessible without authentication.",
        "impact": "Provides attackers with complete documentation of all internal API routes, schemas, and parameters.",
        "remediation": "Disable Swagger UI in production environments or place behind authentication."
    }
]

async def run_api_debug_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    base_clean = target_url.rstrip("/")
    for probe in API_PROBES:
        url = f"{base_clean}{probe['path']}"
        res = await requester.send(probe["method"], url, module="api_debug")
        if res.status_code == 200:
            if baseline.is_similar_to_nonexistent(res):
                continue
            if probe["expected_sub"] in res.body:
                findings.append({
                    "scan_id": scan_id, "target_url": target_url, "endpoint": url, "tested_endpoint": url,
                    "parameter_name": probe["path"], "parameter_location": "URI Path",
                    "payload_used": probe["path"], "payload_type": "API Documentation & Debug Probe",
                    "vuln_type": probe["vuln_type"], "title": probe["vuln_type"], "severity": probe["severity"],
                    "confidence": "CONFIRMED", "is_confirmed": True, "cvss_score": probe["cvss_score"],
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "cwe_id": probe["cwe_id"],
                    "owasp_category": probe["owasp_category"], "category": "API Security",
                    "template_id": f"vf-api-{probe['path'].strip('/').replace('/', '-')}",
                    "short_description": probe["short_description"], "description": probe["description"],
                    "technical_impact": probe["impact"], "remediation": probe["remediation"],
                    "request_method": probe["method"], "raw_request": res.raw_request, "request_headers": res.request_headers,
                    "request_body": res.request_body, "raw_response": res.raw_response, "response_headers": res.headers,
                    "response_body": res.body[:50000], "response_status": res.status_code, "response_time_ms": res.duration_ms,
                    "baseline_raw_response": baseline.root_response.raw_response if baseline.root_response else "",
                    "verification_proof": f"Endpoint responded HTTP 200 containing signature '{probe['expected_sub']}'."
                })
    return findings
