"""
Professional Evidence Collector for Bug Bounty
Collects request/response, generates curl POC, HTTP raw, impact analysis.
More advanced than nuclei's evidence (which is just matched snippet).
"""
from __future__ import annotations
import json
import base64
import textwrap
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from datetime import datetime
import urllib.parse

@dataclass
class HttpEvidence:
    method: str
    url: str
    request_headers: Dict[str, str]
    request_body: str
    response_status: int
    response_headers: Dict[str, str]
    response_body: str
    duration: float
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_curl(self) -> str:
        """Generate curl POC command for HackerOne report"""
        headers_str = " ".join([f"-H '{k}: {v}'" for k,v in self.request_headers.items() 
                               if k.lower() not in ('content-length','host')])
        data_part = f" --data-raw '{self.request_body}'" if self.request_body else ""
        return f"curl -i -s -k -X {self.method} '{self.url}' {headers_str}{data_part}"

    def to_raw_request(self) -> str:
        """Generate raw HTTP request"""
        parsed = urllib.parse.urlparse(self.url)
        path = parsed.path or "/"
        if parsed.query:
            path += f"?{parsed.query}"
        lines = [f"{self.method} {path} HTTP/1.1", f"Host: {parsed.netloc}"]
        for k,v in self.request_headers.items():
            if k.lower() != 'host':
                lines.append(f"{k}: {v}")
        lines.append("")
        if self.request_body:
            lines.append(self.request_body)
        return "\n".join(lines)

    def to_markdown(self) -> str:
        return f"""### Evidence
**URL:** `{self.url}`
**Method:** `{self.method}`
**Status:** `{self.response_status}`
**Duration:** `{self.duration:.2f}s`

**Request:**
```http
{self.to_raw_request()[:2000]}
```

**Curl POC:**
```bash
{self.to_curl()}
```

**Response Snippet (first 1000 chars):**
```
{self.response_body[:1000]}
```
"""

@dataclass
class Finding:
    """Professional Bug Bounty Finding"""
    id: str
    template_id: str
    name: str
    severity: str  # critical/high/medium/low/info
    confidence: float  # 0.0-1.0
    category: str
    endpoint: str
    method: str
    evidence: HttpEvidence
    impact: str
    remediation: str
    cwe: str = ""
    owasp: str = ""
    cvss: float = 0.0
    tags: List[str] = field(default_factory=list)
    occurrences: int = 1
    affected_endpoints: List[str] = field(default_factory=list)
    verified: bool = False
    verification_method: str = ""  # e.g., "boolean_differential", "time_repro"
    chain: List[str] = field(default_factory=list)  # For chained exploits
    bugbounty_value: str = ""  # Estimated bounty impact

    def to_hackerone_markdown(self) -> str:
        """Generate HackerOne/Bugcrowd ready report"""
        severity_emoji = {
            "critical": "🔴 CRITICAL",
            "high": "🟠 HIGH",
            "medium": "🟡 MEDIUM",
            "low": "🔵 LOW",
            "info": "⚪ INFO"
        }
        sev_label = severity_emoji.get(self.severity.lower(), self.severity.upper())
        
        return f"""## {sev_label} - {self.name}

**Severity:** {self.severity.upper()}
**Confidence:** {self.confidence*100:.0f}%
**Endpoint:** `{self.method} {self.endpoint}`
**Category:** {self.category}
**CWE:** {self.cwe} | **OWASP:** {self.owasp} | **CVSS:** {self.cvss}

### Summary
{self.impact}

### Impact for Bug Bounty
{self.bugbounty_value or self.impact}

### Steps to Reproduce
1. {self.evidence.to_curl()}
2. Observe response returns {self.evidence.response_status}
3. Verification: {self.verification_method or "Matched via " + ", ".join(self.evidence.request_headers.keys())}

{self.evidence.to_markdown()}

### Affected Endpoints ({len(self.affected_endpoints) or self.occurrences} found)
{chr(10).join([f"- `{ep}`" for ep in self.affected_endpoints[:10]])}

### Remediation
{self.remediation}

### Tags
{", ".join(self.tags)}
"""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "template_id": self.template_id,
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "category": self.category,
            "endpoint": self.endpoint,
            "method": self.method,
            "evidence": {
                "url": self.evidence.url,
                "method": self.evidence.method,
                "status": self.evidence.response_status,
                "curl": self.evidence.to_curl(),
                "duration": self.evidence.duration,
            },
            "impact": self.impact,
            "cwe": self.cwe,
            "verified": self.verified,
            "occurrences": self.occurrences,
            "affected_endpoints": self.affected_endpoints,
        }
