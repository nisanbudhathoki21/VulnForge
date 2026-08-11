from typing import List, Dict, Any
from engine.requester import Requester
from engine.baseline import TargetBaseline
from engine.verifier_engine import VerificationStateMachine

SENSITIVE_TARGETS = [
    {
        "path": "/.env",
        "vuln_type": "Environment Configuration Disclosure (.env)",
        "severity": "CRITICAL",
        "cwe_id": "CWE-552",
        "owasp_category": "A01:2021-Broken Access Control",
        "cvss_score": 9.1,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "template_id": "vf-crit-env-disclosure",
        "signature_regex": r"(?:DB_PASSWORD|DB_HOST|APP_KEY|AWS_SECRET|DATABASE_URL|REDIS_PASSWORD|SECRET_KEY)\s*=",
        "short_description": "The application's environment configuration file (.env) is publicly accessible, exposing database credentials, API keys, and secret tokens.",
        "description": "The environment configuration file (.env) is directly accessible over HTTP. Attackers can extract production secrets, database credentials, and cryptographic signing keys.",
        "impact": "Complete unauthorized access to database servers, third-party cloud APIs, and application infrastructure.",
        "remediation": "Block access to all hidden files in web server rules (e.g. `location ~ /\\. { deny all; }` in Nginx). Move .env outside the web root."
    },
    {
        "path": "/.git/HEAD",
        "vuln_type": "Git Repository HEAD Disclosure",
        "severity": "HIGH",
        "cwe_id": "CWE-538",
        "owasp_category": "A05:2021-Security Misconfiguration",
        "cvss_score": 7.5,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "template_id": "vf-high-git-head",
        "signature_regex": r"^ref:\s+refs/(?:heads|tags)/[a-zA-Z0-9_\-\./]+|^[0-9a-f]{40}$",
        "short_description": "The Git version control repository HEAD file is publicly exposed in the document root.",
        "description": "The Git metadata file (/.git/HEAD) is publicly accessible over HTTP, allowing automated extraction of complete source code trees and commit histories.",
        "impact": "Full source code disclosure, hardcoded secrets extraction, and discovery of unpatched vulnerabilities.",
        "remediation": "Restrict web server access to `.git` directories or exclude version control files from production deployment pipelines."
    }
]

async def run_sensitive_files_scan(requester: Requester, baseline: TargetBaseline, scan_id: str, target_url: str) -> List[Dict[str, Any]]:
    findings = []
    for item in SENSITIVE_TARGETS:
        # Run through Verification State Machine
        verdict = await VerificationStateMachine.verify_sensitive_file(
            requester=requester,
            base_url=target_url,
            file_path=item["path"],
            signature_regex=item["signature_regex"]
        )

        # Only create finding if verified
        if verdict.is_confirmed:
            target_endpoint = f"{target_url.rstrip('/')}{item['path']}"
            findings.append({
                "scan_id": scan_id, "target_url": target_url, "endpoint": target_endpoint, "tested_endpoint": target_endpoint,
                "parameter_name": item["path"], "parameter_location": "URI Path",
                "payload_used": f"GET {item['path']} HTTP/1.1", "payload_type": "Sensitive Path Disclosure Probe",
                "vuln_type": item["vuln_type"], "title": item["vuln_type"], "severity": item["severity"],
                "confidence": "CONFIRMED", "is_confirmed": True, "cvss_score": item["cvss_score"],
                "cvss_vector": item["cvss_vector"], "cwe_id": item["cwe_id"], "owasp_category": item["owasp_category"],
                "category": "Information Disclosure", "template_id": item["template_id"],
                "short_description": item["short_description"], "description": item["description"],
                "technical_impact": item["impact"], "remediation": item["remediation"],
                "request_method": "GET", "raw_request": verdict.mutation_request,
                "raw_response": verdict.mutation_response,
                "baseline_raw_response": verdict.control_response,
                "verification_proof": verdict.differential_proof or verdict.verdict_reason
            })
    return findings
