from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Dict, Any, Tuple, Set
from workspace.models import Finding, FindingKind

@dataclass
class InvestigationPath:
    title: str
    reasoning: str
    estimated_time: str
    nodes: List[str] # List of Finding IDs
    confidence: float

class CorrelationEngine:
    """The brain of VulnForge. Links findings into actionable attack chains."""
    
    def __init__(self, findings: List[Finding]):
        self.findings = {f.id: f for f in findings}
        self.graph: Dict[str, Set[str]] = {f.id: set() for f in findings}
        self.paths: List[InvestigationPath] = []

    def correlate(self) -> List[InvestigationPath]:
        """Orchestrates the correlation logic and generates paths."""
        self._link_by_endpoint()
        self._link_by_risk_amplification()
        self._link_auth_dependencies()
        
        return self._generate_investigation_paths()

    def _link_by_endpoint(self):
        """Rule: Findings on the same endpoint are automatically related."""
        endpoints: Dict[str, List[str]] = {}
        for f_id, f in self.findings.items():
            url = f.context.get("url", "unknown")
            endpoints.setdefault(url, []).append(f_id)
            
        for f_ids in endpoints.values():
            for i in f_ids:
                for j in f_ids:
                    if i != j: self.graph[i].add(j)

    def _link_by_risk_amplification(self):
        """Rule: Foundational weaknesses (headers/tls) amplify active vulnerabilities."""
        foundationals = [f for f in self.findings.values() if "headers" in f.title.lower()]
        vulnerabilities = [f for f in self.findings.values() if f.severity in ["High", "Critical"]]

        for f in foundationals:
            for v in vulnerabilities:
                self.graph[f.id].add(v.id)

    def _link_auth_dependencies(self):
        """Rule: Auth findings link to all findings requiring authentication."""
        auth_issues = [f for f in self.findings.values() if f.category == "Authentication"]
        api_findings = [f for f in self.findings.values() if "/api/" in str(f.context.get("url"))]

        for a in auth_issues:
            for api in api_findings:
                self.graph[a.id].add(api.id)

    def _generate_investigation_paths(self) -> List[InvestigationPath]:
        """Transmutes the graph into human-readable research directions."""
        paths = []
        
        # Pattern 1: The 'Insecure API' Path
        api_chain = [f_id for f_id, f in self.findings.items() if "/api/" in str(f.context.get("url"))]
        if len(api_chain) > 1:
            paths.append(InvestigationPath(
                title="API Security Deep-Dive",
                reasoning=f"Found {len(api_chain)} related signals across API endpoints. Potential for Broken Object Level Authorization (BOLA).",
                estimated_time="45 mins",
                nodes=api_chain,
                confidence=0.85
            ))

        # Pattern 2: Foundation Chaining
        header_issues = [f_id for f_id, f in self.findings.items() if "headers" in f.title.lower()]
        high_sev = [f_id for f_id, f in self.findings.items() if self.findings[f_id].severity in ["High", "Critical"]]
        
        if header_issues and high_sev:
            paths.append(InvestigationPath(
                title="Exploit Chain: Foundation Weakness",
                reasoning="Missing security headers may allow bypasses or amplification of the High-severity issues discovered.",
                estimated_time="30 mins",
                nodes=header_issues + high_sev,
                confidence=0.70
            ))

        return paths

