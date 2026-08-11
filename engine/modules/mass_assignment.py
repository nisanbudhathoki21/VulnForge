from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline
from engine.verifier_engine import VerificationStateMachine

async def run_mass_assignment_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    verdict = await VerificationStateMachine.verify_mass_assignment(
        requester=requester,
        base_url=target_url,
        endpoint_path="/api/Users",
        privileged_field="role",
        privileged_value="admin"
    )

    if verdict.is_confirmed:
        endpoint_url = f"{target_url.rstrip('/')}/api/Users"
        findings.append({
            "scan_id": scan_id, "target_url": target_url, "endpoint": endpoint_url, "tested_endpoint": endpoint_url,
            "parameter_name": "role", "parameter_location": "JSON Request Body",
            "payload_used": '{"role": "admin"}', "payload_type": "Privilege Escalation JSON Parameter Probe",
            "vuln_type": "Mass Assignment / Insecure Parameter Binding",
            "title": "Mass Assignment Privilege Escalation on User Registration (/api/Users)",
            "severity": "CRITICAL", "confidence": "CONFIRMED", "is_confirmed": True,
            "cvss_score": 9.8, "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe_id": "CWE-915", "owasp_category": "A01:2021-Broken Access Control",
            "category": "API Security & Access Control", "template_id": "vf-crit-mass-assignment-role",
            "short_description": "The user registration endpoint accepts client-supplied 'role' parameters, allowing unauthenticated users to create administrator accounts.",
            "description": "The application automatically binds incoming JSON fields to the internal User model without an allowlist. Submitting 'role': 'admin' provisions administrative accounts.",
            "technical_impact": "Unrestricted privilege escalation leading to complete administrative takeover of the application.",
            "remediation": "Use Data Transfer Objects (DTOs) with strict property whitelisting. Never bind HTTP request bodies directly to database entities.",
            "request_method": "POST", "raw_request": verdict.mutation_request,
            "raw_response": verdict.mutation_response,
            "baseline_raw_response": verdict.control_response,
            "verification_proof": verdict.differential_proof or verdict.verdict_reason
        })
    return findings
