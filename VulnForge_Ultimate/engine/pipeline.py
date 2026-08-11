"""
Professional Bug Bounty Pipeline - Structured Engineering
Orchestrates: Scope -> Recon -> Discovery -> Active Scan -> Verification -> Correlation -> Reporting
Like nuclei's workflow but structured for bug bounty hunting efficiency.
"""
from __future__ import annotations
import time
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from datetime import datetime
import logging

# Import our professional modules
from core.scope import BugBountyScope
from core.evidence import Finding, HttpEvidence
from correlation.advanced_chain import AdvancedCorrelationEngine, AttackChain

# Reuse existing fixed scanner
import sys
from pathlib import Path
# Add VulnForge_Patched to path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "VulnForge_Patched"))
try:
    from engine.scanner import Scanner, scan_target
    from engine.discovery import DiscoveryEngine
    from engine.nikto_fingerprint import fingerprint_headers
except ImportError:
    # Fallback to original
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "VulnForge"))
    from engine.scanner import Scanner, scan_target
    from engine.discovery import DiscoveryEngine
    fingerprint_headers = lambda h: {}

@dataclass
class ScanConfig:
    """Professional scan config for bug bounty"""
    target: str
    in_scope: List[str] = field(default_factory=list)
    out_scope: List[str] = field(default_factory=list)
    threads: int = 20
    timeout: int = 15
    delay: float = 0.0
    rate_limit: float = 0.0
    verify_ssl: bool = False
    follow_redirects: bool = True
    user_agent: str = "VulnForge-BugBounty/1.0"
    max_depth: int = 2
    max_urls: int = 200
    enable_crawler: bool = True
    enable_nikto_checks: bool = True
    enable_interactsh: bool = True
    bugbounty_mode: bool = True
    severity_filter: List[str] = field(default_factory=lambda: ["critical","high","medium","low","info"])
    tags_filter: List[str] = field(default_factory=list)

@dataclass
class PipelineResult:
    scan_id: str
    target: str
    start_time: str
    end_time: str
    duration: float
    scope: BugBountyScope
    discovered_endpoints: List[str]
    raw_findings: List[Dict[str, Any]]
    professional_findings: List[Finding]
    attack_chains: List[AttackChain]
    fingerprint: Dict[str, Any]
    metrics: Dict[str, Any]

class BugBountyPipeline:
    """
    Structured Professional Pipeline for Bug Bounty Hunting
    Steps:
    1. Scope validation
    2. Fingerprinting (nikto-style)
    3. Discovery (crawler + JS linkfinder)
    4. Active scanning (nuclei-style templates + differential)
    5. Verification (reproducibility)
    6. Correlation (attack chains P1-P4)
    7. Reporting (HackerOne ready)
    """
    def __init__(self, config: ScanConfig):
        self.config = config
        self.scope = BugBountyScope(
            in_scope=config.in_scope or [config.target],
            out_of_scope=config.out_scope
        )
        self.logger = logging.getLogger("VulnForge.Pro")
        self.scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_%f")[:-3]

    def _log(self, msg: str, level: str = "info"):
        print(f"[{level.upper()}] {msg}")
        if level == "info":
            self.logger.info(msg)
        elif level == "warn":
            self.logger.warning(msg)
        elif level == "error":
            self.logger.error(msg)

    def run_fingerprint(self, target: str) -> Dict[str, Any]:
        self._log(f"Fingerprinting {target}")
        # Simplified fingerprint - in real would make HTTP request
        # Using existing discovery engine would do
        try:
            import requests
            resp = requests.get(target, timeout=self.config.timeout, verify=False)
            fp = fingerprint_headers(dict(resp.headers))
            fp["status"] = resp.status_code
            fp["final_url"] = str(resp.url)
            return fp
        except Exception as e:
            return {"error": str(e), "server": "Unknown"}

    def run_discovery(self, target: str) -> List[str]:
        if not self.config.enable_crawler:
            return [target]
        
        self._log(f"Discovery crawling {target} (depth={self.config.max_depth})")
        try:
            import requests
            sess = requests.Session()
            sess.headers.update({"User-Agent": self.config.user_agent})
            # Use existing DiscoveryEngine if available
            disc = DiscoveryEngine(
                session=sess,
                base_url=target,
                max_depth=self.config.max_depth,
                max_urls=self.config.max_urls,
                quiet=True
            )
            endpoints = disc.run()  # Returns dict of endpoints
            urls = [ep.url for ep in disc.endpoints.values()] if hasattr(disc, 'endpoints') else [target]
            # Filter by scope
            in_scope_urls = self.scope.filter_urls(urls)
            self._log(f"Discovered {len(urls)} endpoints, {len(in_scope_urls)} in-scope")
            return in_scope_urls or [target]
        except Exception as e:
            self._log(f"Discovery failed: {e}", "warn")
            return [target]

    def run_active_scan(self, target: str) -> Dict[str, Any]:
        self._log(f"Active scanning {target} with {self.config.threads} threads")
        start = time.time()
        result = scan_target(
            url=target,
            quiet=False,
            template_dir="templates/",  # Use fixed templates
            max_workers=self.config.threads,
            rate_limit=self.config.rate_limit,
            delay=self.config.delay,
            timeout=self.config.timeout,
            skip_auth=False,
        )
        elapsed = time.time() - start
        self._log(f"Scan finished in {elapsed:.2f}s, {len(result.get('findings',[]))} findings, {result.get('requests_sent',0)} requests")
        return result

    def convert_to_professional_findings(self, raw_findings: List[Dict]) -> List[Finding]:
        pro_findings = []
        for idx, rf in enumerate(raw_findings):
            ev = rf.get("evidence") or {}
            http_ev = HttpEvidence(
                method=ev.get("method","GET"),
                url=ev.get("url", self.config.target),
                request_headers=ev.get("request_headers", {}),
                request_body=ev.get("request_body",""),
                response_status=ev.get("status", 200),
                response_headers=ev.get("response_headers", {}),
                response_body=ev.get("response_body","")[:2000],
                duration=ev.get("duration", 0.0)
            )
            # Determine bug bounty value
            sev = (rf.get("severity") or "info").lower()
            bounty_map = {
                "critical": "$2000-$10000 (P1 - Account Takeover/RCE)",
                "high": "$1000-$3000 (P2 - High impact leak)",
                "medium": "$500-$1000 (P3)",
                "low": "$100-$500 (P4)",
                "info": "Informational - try to chain",
            }
            finding = Finding(
                id=f"VF-{self.scan_id}-{idx}",
                template_id=rf.get("template_id","unknown"),
                name=rf.get("name","Unnamed"),
                severity=sev,
                confidence=rf.get("confidence", 0.5),
                category=rf.get("category",""),
                endpoint=http_ev.url,
                method=http_ev.method,
                evidence=http_ev,
                impact=rf.get("impact",""),
                remediation=rf.get("remediation",""),
                cwe=rf.get("cwe",""),
                owasp=rf.get("owasp",""),
                tags=rf.get("matched_types",[]),
                occurrences=rf.get("occurrences",1),
                affected_endpoints=rf.get("affected_endpoints",[http_ev.url]),
                verified=rf.get("confirmed", False),
                verification_method=rf.get("evidence",{}).get("differential_reason","") or "regex/word match",
                bugbounty_value=bounty_map.get(sev, "")
            )
            # Severity filter
            if sev in self.config.severity_filter or not self.config.severity_filter:
                pro_findings.append(finding)
        return pro_findings

    def run_correlation(self, raw_findings: List[Dict]) -> List[AttackChain]:
        self._log(f"Correlating {len(raw_findings)} findings into attack chains")
        engine = AdvancedCorrelationEngine(raw_findings)
        chains = engine.correlate()
        for chain in chains:
            self._log(f"CHAIN {chain.severity}: {chain.title} -> {chain.estimated_bounty} (conf {chain.confidence})", "info")
        return chains

    def run(self) -> PipelineResult:
        start_time = datetime.now()
        start_ts = time.time()
        
        self._log(f"=== VulnForge Bug Bounty Pro Pipeline ===")
        self._log(f"Target: {self.config.target}")
        self._log(f"Scope in: {self.config.in_scope} out: {self.config.out_scope}")
        self._log(f"Scan ID: {self.scan_id}")

        # 1. Scope check
        if not self.scope.is_in_scope(self.config.target):
            raise ValueError(f"Target {self.config.target} is out of scope! Check scope rules.")

        # 2. Fingerprint
        fingerprint = self.run_fingerprint(self.config.target)

        # 3. Discovery
        endpoints = self.run_discovery(self.config.target)

        # 4. Active scan (scan each discovered endpoint + main target)
        all_raw_findings = []
        total_requests = 0
        for ep in endpoints[:10]:  # Limit for demo, in prod scan all in-scope
            if not self.scope.is_in_scope(ep):
                continue
            res = self.run_active_scan(ep)
            all_raw_findings.extend(res.get("findings", []))
            total_requests += res.get("requests_sent", 0)

        # Deduplicate raw findings by template+endpoint
        seen = set()
        deduped_raw = []
        for f in all_raw_findings:
            key = (f.get("template_id"), (f.get("evidence") or {}).get("url"))
            if key not in seen:
                seen.add(key)
                deduped_raw.append(f)
        
        # 5. Convert to professional findings
        pro_findings = self.convert_to_professional_findings(deduped_raw)

        # 6. Correlation to attack chains
        chains = self.run_correlation(deduped_raw)

        end_time = datetime.now()
        duration = time.time() - start_ts

        metrics = {
            "discovered_endpoints": len(endpoints),
            "in_scope_endpoints": len([u for u in endpoints if self.scope.is_in_scope(u)]),
            "raw_findings": len(all_raw_findings),
            "deduped_findings": len(deduped_raw),
            "professional_findings": len(pro_findings),
            "attack_chains": len(chains),
            "p1_chains": len([c for c in chains if c.severity == "P1"]),
            "total_requests": total_requests,
            "duration": duration,
        }

        result = PipelineResult(
            scan_id=self.scan_id,
            target=self.config.target,
            start_time=start_time.isoformat(),
            end_time=end_time.isoformat(),
            duration=duration,
            scope=self.scope,
            discovered_endpoints=endpoints,
            raw_findings=deduped_raw,
            professional_findings=pro_findings,
            attack_chains=chains,
            fingerprint=fingerprint,
            metrics=metrics
        )

        self._log(f"=== Pipeline finished: {metrics} ===")
        return result

# CLI helper
if __name__ == "__main__":
    config = ScanConfig(
        target="https://example.com",
        in_scope=["*.example.com"],
        out_scope=["admin.example.com"],
        threads=10,
        bugbounty_mode=True
    )
    pipeline = BugBountyPipeline(config)
    # result = pipeline.run()
    # print(result)
