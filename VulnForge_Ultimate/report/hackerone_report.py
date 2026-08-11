"""
HackerOne / Bugcrowd Professional Report Generator
Generates markdown report ready to submit, with:
- Executive summary
- Attack chains (P1-P4)
- Individual findings with curl POC
- Impact and remediation
- Professional formatting that gets higher bounties
"""
from __future__ import annotations
from typing import List, Dict, Any
from datetime import datetime
from pathlib import Path
import json

from correlation.advanced_chain import AttackChain
from core.evidence import Finding
from engine.pipeline import PipelineResult

class HackerOneReportGenerator:
    def __init__(self, result: PipelineResult):
        self.result = result

    def generate_executive_summary(self) -> str:
        p1_count = len([c for c in self.result.attack_chains if c.severity == "P1"])
        total_chains = len(self.result.attack_chains)
        total_findings = len(self.result.professional_findings)
        critical = len([f for f in self.result.professional_findings if f.severity == "critical"])
        high = len([f for f in self.result.professional_findings if f.severity == "high"])

        return f"""## Executive Summary

**Target:** {self.result.target}
**Scan ID:** {self.result.scan_id}
**Duration:** {self.result.duration:.2f}s
**Discovered Endpoints:** {self.result.metrics['discovered_endpoints']} ({self.result.metrics['in_scope_endpoints']} in-scope)
**Total Requests:** {self.result.metrics['total_requests']}

**Findings:** {total_findings} (Critical: {critical}, High: {high})
**Attack Chains:** {total_chains} (P1: {p1_count})

### Key Risks
This scan identified **{p1_count} P1 chains** that demonstrate Account Takeover or Remote Code Execution potential when chained. 
Individual findings alone may be low severity, but chained they become critical - this is what bug bounty programs pay high bounties for.

### Fingerprint
- Server: {self.result.fingerprint.get('server','Unknown')}
- Tech Stack: {', '.join(self.result.fingerprint.get('tech_stack',[])) or 'Unknown'}
- WAF: {', '.join(self.result.fingerprint.get('waf',[])) or 'None detected'}
- Missing Headers: {', '.join(self.result.fingerprint.get('missing_headers',[])) or 'None'}
"""

    def generate_chains_section(self) -> str:
        if not self.result.attack_chains:
            return "\n## Attack Chains\nNo high-impact chains detected. Individual findings below may still be exploitable.\n"
        
        md = "\n## 🔗 Attack Chains (Chained Exploits - Higher Bounty)\n\nThese are **not** single vulnerabilities, but chains that escalate impact. Report these as P1.\n\n"
        for idx, chain in enumerate(self.result.attack_chains, 1):
            md += f"""
### {idx}. [{chain.severity}] {chain.title}

**Estimated Bounty:** {chain.estimated_bounty}
**Confidence:** {chain.confidence*100:.0f}%
**Findings in Chain:** {len(chain.findings)}

**Impact:**
{chain.impact}

**Why this gets high bounty:**
{chain.bugbounty_reason}

**Steps to Reproduce:**
{chr(10).join(chain.steps)}

**Remediation:**
{chain.remediation}

**Chain Type:** `{chain.chain_type}`

---
"""
        return md

    def generate_findings_section(self) -> str:
        if not self.result.professional_findings:
            return "\n## Findings\nNo findings.\n"
        
        # Sort by severity critical first
        order = {"critical":0, "high":1, "medium":2, "low":3, "info":4}
        sorted_findings = sorted(self.result.professional_findings, key=lambda f: order.get(f.severity.lower(),5))
        
        md = "\n## 🔍 Individual Findings (Detailed)\n\n"
        for idx, finding in enumerate(sorted_findings, 1):
            md += f"\n### {idx}. {finding.to_hackerone_markdown()}\n\n---\n"
        return md

    def generate_metrics_section(self) -> str:
        m = self.result.metrics
        return f"""
## 📊 Scan Metrics

| Metric | Value |
|--------|-------|
| Duration | {m['duration']:.2f}s |
| Discovered Endpoints | {m['discovered_endpoints']} |
| In-Scope | {m['in_scope_endpoints']} |
| Raw Signals | {m['raw_findings']} |
| Deduped | {m['deduped_findings']} |
| Professional Findings | {m['professional_findings']} |
| Attack Chains | {m['attack_chains']} |
| P1 Chains | {m['p1_chains']} |
| Total Requests | {m['total_requests']} |
| Scope | {self.result.scope.in_scope_raw} |
| Out-of-Scope | {self.result.scope.out_scope_raw} |

## 🛡️ Scope Enforcement
All tested URLs were validated against scope:
- In-scope patterns: {self.result.scope.in_scope_raw}
- Out-of-scope patterns: {self.result.scope.out_scope_raw}
- Root domains: {self.result.scope.get_root_domains()}
"""

    def generate_full_report(self) -> str:
        report = f"""# VulnForge Bug Bounty Pro Report

{self.generate_executive_summary()}

{self.generate_chains_section()}

{self.generate_findings_section()}

{self.generate_metrics_section()}

---

## 📝 Notes for HackerOne Submission

1. **Always verify manually** before submitting - scanner findings are leads, not confirmed vulns
2. **Chain low findings** - a P4 info disclosure + P3 IDOR = P1 Account Takeover, report as chain
3. **Include curl POC** - every finding above has curl command ready to copy
4. **Impact first** - bug bounty triagers look at impact, not just technical details
5. **Remediation** - include to show professionalism

Generated by VulnForge Bug Bounty Pro v1.0 - Advanced correlation engine beats nuclei/nikto for bug bounty hunting.

Scan ID: {self.result.scan_id}
Date: {datetime.now().isoformat()}
Target: {self.result.target}
"""
        return report

    def save(self, output_path: str = None) -> str:
        if not output_path:
            output_path = f"reports/bugbounty_{self.result.scan_id}.md"
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        content = self.generate_full_report()
        Path(output_path).write_text(content, encoding="utf-8")
        # Also save JSON
        json_path = output_path.replace(".md",".json")
        data = {
            "scan_id": self.result.scan_id,
            "target": self.result.target,
            "metrics": self.result.metrics,
            "chains": [
                {
                    "title": c.title,
                    "severity": c.severity,
                    "impact": c.impact,
                    "bounty": c.estimated_bounty,
                    "confidence": c.confidence,
                    "findings": c.findings,
                } for c in self.result.attack_chains
            ],
            "findings": [f.to_dict() for f in self.result.professional_findings]
        }
        Path(json_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        return output_path

# Example
if __name__ == "__main__":
    # Demo with dummy data
    pass
