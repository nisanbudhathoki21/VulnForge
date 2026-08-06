from __future__ import annotations
from typing import List, Dict, Any, Tuple
from workspace.models import Finding
class Correlated:
    def __init__(self, findings: List[Finding]) -> None:
        self.findings = findings
        self.edges: List[Tuple[str, str, str]] = []
        self.summaries: Dict[str, Any] = {}
    def correlate(self) -> None:
        by_url: Dict[str, List[Finding]] = {}
        for f in self.findings:
            url = f.context.get("url","")
            by_url.setdefault(url, []).append(f)
        for url, fs in by_url.items():
            ids = [f.id for f in fs]
            for i in range(len(ids)-1):
                self.edges.append((ids[i], ids[i+1], f"Same endpoint {url}"))
        for f in self.findings:
            if "security headers" in f.title.lower():
                for g in self.findings:
                    if g.id != f.id and g.severity in ("High","Critical"):
                        self.edges.append((f.id, g.id, "Weak headers may amplify risk"))
