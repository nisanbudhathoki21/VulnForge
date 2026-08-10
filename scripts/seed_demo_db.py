#!/usr/bin/env python3

"""
Create a local VulnForge demonstration database.

This script uses VulnForge's real database layer rather than
creating a separate schema.

The generated data is intentionally synthetic and is only for
demonstration/testing.
"""

from datetime import datetime, timedelta, timezone

from core.database import (
    init_db,
    save_scan,
    save_finding,
)


def seed():
    print("[VulnForge] Initializing database...")
    init_db()

    now = datetime.now(timezone.utc)

    scans = [
        {
            "scan_id": "demo-001",
            "target": "http://127.0.0.1:5001",
            "findings": 5,
            "duration": 4.82,
            "requests": 86,
        },
        {
            "scan_id": "demo-002",
            "target": "http://localhost:5002",
            "findings": 3,
            "duration": 3.41,
            "requests": 64,
        },
        {
            "scan_id": "demo-003",
            "target": "https://demo.example.test",
            "findings": 2,
            "duration": 6.17,
            "requests": 119,
        },
        {
            "scan_id": "demo-004",
            "target": "http://127.0.0.1:5003",
            "findings": 4,
            "duration": 5.36,
            "requests": 97,
        },
    ]

    for index, scan in enumerate(scans):
        timestamp = (
            now - timedelta(hours=index * 3)
        ).isoformat()

        save_scan(
            scan_id=scan["scan_id"],
            target=scan["target"],
            timestamp=timestamp,
            start_time=timestamp,
            status="completed",
            end_time=(
                now - timedelta(hours=index * 3)
            ).isoformat(),
            findings_count=scan["findings"],
            scan_duration=scan["duration"],
            scan_depth=2,
            templates_loaded=42,
            requests_sent=scan["requests"],
            errors_count=0,
            fingerprint="Demo application fingerprint",
        )

    findings = [
        {
            "scan_id": "demo-001",
            "name": "SQL Injection",
            "severity": "critical",
            "template_id": "critical/injection/sql-injection",
            "impact": "An attacker may manipulate database queries and access unauthorized data.",
            "chain": "User input → SQL query → database",
            "evidence": "Controlled input produced a database-related response difference.",
            "extracted": "Demo SQL error response",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.98,
            "cwe": "CWE-89",
            "owasp": "A03:2021 Injection",
            "remediation": "Use parameterized queries and server-side input validation.",
            "ai_explanation": "The scanner identified behavior consistent with SQL injection in the synthetic demo application.",
        },
        {
            "scan_id": "demo-001",
            "name": "Broken Object Level Authorization",
            "severity": "high",
            "template_id": "authorization/bola-numeric",
            "impact": "An unauthorized user may access another user's object.",
            "chain": "Object ID → API request → authorization check",
            "evidence": "Changing the object identifier returned another synthetic user's record.",
            "extracted": "Demo object identifier",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.95,
            "cwe": "CWE-639",
            "owasp": "API1:2023 Broken Object Level Authorization",
            "remediation": "Perform server-side authorization checks for every object access.",
            "ai_explanation": "The application failed to enforce object-level authorization in the demonstration environment.",
        },
        {
            "scan_id": "demo-001",
            "name": "Reflected XSS",
            "severity": "high",
            "template_id": "high/xss/reflected-xss",
            "impact": "Injected browser-side script may execute in a victim's browser.",
            "chain": "User input → HTTP response → browser",
            "evidence": "Synthetic input was reflected into an HTML response without adequate encoding.",
            "extracted": "Demo reflected parameter",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.93,
            "cwe": "CWE-79",
            "owasp": "A03:2021 Injection",
            "remediation": "Apply context-aware output encoding and validate untrusted input.",
            "ai_explanation": "The scanner detected reflected user-controlled content in the demonstration application.",
        },
        {
            "scan_id": "demo-001",
            "name": "Missing Security Headers",
            "severity": "medium",
            "template_id": "low/headers/security-headers",
            "impact": "Missing browser security controls can increase exposure to client-side attacks.",
            "chain": "HTTP response → browser security policy",
            "evidence": "One or more expected security headers were absent.",
            "extracted": "Demo HTTP response headers",
            "confirmed": 1,
            "exploit_attempted": 0,
            "exploit_success": 0,
            "confidence": 0.88,
            "cwe": "CWE-693",
            "owasp": "A05:2021 Security Misconfiguration",
            "remediation": "Configure appropriate security headers at the application or reverse-proxy layer.",
            "ai_explanation": "The demonstration server does not provide several recommended security headers.",
        },
        {
            "scan_id": "demo-001",
            "name": "Information Disclosure",
            "severity": "low",
            "template_id": "low/exposure/server-disclosure",
            "impact": "Server metadata may help attackers fingerprint the application.",
            "chain": "HTTP response → server metadata",
            "evidence": "Synthetic server information was exposed in the response.",
            "extracted": "Demo server header",
            "confirmed": 1,
            "exploit_attempted": 0,
            "exploit_success": 0,
            "confidence": 0.84,
            "cwe": "CWE-200",
            "owasp": "A05:2021 Security Misconfiguration",
            "remediation": "Remove unnecessary server-identifying information from responses.",
            "ai_explanation": "The demonstration application exposes unnecessary server metadata.",
        },
        {
            "scan_id": "demo-002",
            "name": "Server-Side Request Forgery",
            "severity": "critical",
            "template_id": "critical/server-side/ssrf",
            "impact": "A vulnerable server may be abused to make unintended internal requests.",
            "chain": "User-controlled URL → server request → internal resource",
            "evidence": "Synthetic internal request behavior was observed.",
            "extracted": "Demo URL parameter",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.96,
            "cwe": "CWE-918",
            "owasp": "A10:2021 SSRF",
            "remediation": "Restrict outbound destinations and validate URLs server-side.",
            "ai_explanation": "The demonstration endpoint accepted a user-controlled destination for server-side requests.",
        },
        {
            "scan_id": "demo-002",
            "name": "CSRF",
            "severity": "medium",
            "template_id": "medium/authentication/csrf",
            "impact": "A victim may be induced to perform an unintended state-changing action.",
            "chain": "Authenticated session → cross-site request → state change",
            "evidence": "Synthetic state-changing request lacked an expected CSRF protection mechanism.",
            "extracted": "Demo request",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.91,
            "cwe": "CWE-352",
            "owasp": "A01:2021 Broken Access Control",
            "remediation": "Use anti-CSRF tokens and appropriate SameSite cookie protections.",
            "ai_explanation": "The demonstration endpoint does not adequately protect a state-changing request against cross-site requests.",
        },
        {
            "scan_id": "demo-002",
            "name": "Open Redirect",
            "severity": "medium",
            "template_id": "medium/redirect/open-redirect",
            "impact": "An attacker may abuse the application to redirect users to an external destination.",
            "chain": "User-controlled redirect parameter → HTTP redirect",
            "evidence": "Synthetic redirect parameter accepted an external destination.",
            "extracted": "Demo redirect parameter",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.90,
            "cwe": "CWE-601",
            "owasp": "A01:2021 Broken Access Control",
            "remediation": "Allow only trusted redirect destinations or use server-side destination identifiers.",
            "ai_explanation": "The demonstration endpoint redirects based on user-controlled input.",
        },
        {
            "scan_id": "demo-003",
            "name": "CORS Misconfiguration",
            "severity": "medium",
            "template_id": "medium/misconfiguration/cors-check",
            "impact": "Improper cross-origin policy may allow unintended origins to interact with sensitive resources.",
            "chain": "Origin header → CORS policy → browser",
            "evidence": "Synthetic response returned an overly permissive cross-origin policy.",
            "extracted": "Demo Access-Control-Allow-Origin header",
            "confirmed": 1,
            "exploit_attempted": 0,
            "exploit_success": 0,
            "confidence": 0.89,
            "cwe": "CWE-942",
            "owasp": "A05:2021 Security Misconfiguration",
            "remediation": "Allow only explicitly trusted origins and avoid wildcard policies for sensitive resources.",
            "ai_explanation": "The demonstration server uses an overly permissive CORS configuration.",
        },
        {
            "scan_id": "demo-003",
            "name": "Git Repository Exposure",
            "severity": "low",
            "template_id": "low/exposure/git-exposure",
            "impact": "Exposed repository metadata may reveal source code or internal information.",
            "chain": "HTTP request → exposed repository resource",
            "evidence": "Synthetic repository metadata was accessible.",
            "extracted": "Demo repository response",
            "confirmed": 1,
            "exploit_attempted": 0,
            "exploit_success": 0,
            "confidence": 0.87,
            "cwe": "CWE-538",
            "owasp": "A05:2021 Security Misconfiguration",
            "remediation": "Prevent repository metadata and development artifacts from being publicly served.",
            "ai_explanation": "The demonstration server exposes a development artifact that should not be public.",
        },
        {
            "scan_id": "demo-004",
            "name": "NoSQL Injection",
            "severity": "high",
            "template_id": "critical/injection/nosql-injection",
            "impact": "Manipulated query operators may alter application database behavior.",
            "chain": "User input → NoSQL query → database",
            "evidence": "Synthetic input changed the application's database query behavior.",
            "extracted": "Demo query parameter",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.94,
            "cwe": "CWE-943",
            "owasp": "A03:2021 Injection",
            "remediation": "Validate input types and construct database queries using safe APIs.",
            "ai_explanation": "The demonstration application showed behavior consistent with NoSQL query manipulation.",
        },
        {
            "scan_id": "demo-004",
            "name": "Path Traversal",
            "severity": "high",
            "template_id": "critical/server-side/path-traversal",
            "impact": "An attacker may access files outside the intended application directory.",
            "chain": "User-controlled path → filesystem operation",
            "evidence": "Synthetic traversal input accessed a file outside the expected directory.",
            "extracted": "Demo file path",
            "confirmed": 1,
            "exploit_attempted": 1,
            "exploit_success": 1,
            "confidence": 0.95,
            "cwe": "CWE-22",
            "owasp": "A01:2021 Broken Access Control",
            "remediation": "Canonicalize paths and enforce a strict allowed-directory boundary.",
            "ai_explanation": "The demonstration endpoint failed to constrain file paths to the intended directory.",
        },
        {
            "scan_id": "demo-004",
            "name": "JWT Misconfiguration",
            "severity": "medium",
            "template_id": "medium/authentication/jwt-misconfiguration",
            "impact": "Weak token configuration can undermine authentication and authorization.",
            "chain": "JWT → verification configuration → authorization",
            "evidence": "Synthetic JWT configuration did not meet the expected security policy.",
            "extracted": "Demo JWT metadata",
            "confirmed": 0,
            "exploit_attempted": 0,
            "exploit_success": 0,
            "confidence": 0.78,
            "cwe": "CWE-287",
            "owasp": "A07:2021 Identification and Authentication Failures",
            "remediation": "Use strong signing algorithms, validate claims, and enforce secure verification configuration.",
            "ai_explanation": "The scanner detected a potentially insecure JWT configuration, but the finding is not fully confirmed.",
        },
    ]

    for finding in findings:
        save_finding(
            scan_id=finding["scan_id"],
            name=finding["name"],
            severity=finding["severity"],
            template_id=finding["template_id"],
            impact=finding["impact"],
            chain=finding["chain"],
            evidence=finding["evidence"],
            extracted=finding["extracted"],
            confirmed=finding["confirmed"],
            exploit_attempted=finding["exploit_attempted"],
            exploit_success=finding["exploit_success"],
            confidence=finding["confidence"],
            cwe=finding["cwe"],
            owasp=finding["owasp"],
            remediation=finding["remediation"],
            ai_explanation=finding["ai_explanation"],
            created_at=now.isoformat(),
        )

    print("[VulnForge] Demo database created successfully.")
    print("[VulnForge] Database: vulnforge.db")
    print(f"[VulnForge] Scans: {len(scans)}")
    print(f"[VulnForge] Findings: {len(findings)}")
    print()
    print("NOTE: All targets and findings in this seed database are synthetic demo data.")


if __name__ == "__main__":
    seed()
