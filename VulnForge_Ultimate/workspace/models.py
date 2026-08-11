from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Literal, Optional

FindingKind = Literal["Verified", "Possible", "Related", "Investigation"]
Severity = Literal["Critical", "High", "Medium", "Low", "Informational"]

@dataclass
class Evidence:
    id: str
    request_raw: str
    response_raw: str
    extracted_data: Dict[str, Any]
    timestamp: datetime = field(default_factory=datetime.utcnow)

@dataclass
class Finding:
    id: str
    title: str
    kind: FindingKind
    severity: Severity
    confidence: float
    evidence: List[Evidence] = field(default_factory=list)
    category: str = "General"
    context: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None

@dataclass
class Target:
    url: str
    notes: str = ""
    tags: List[str] = field(default_factory=list)

@dataclass
class Workspace:
    name: str
    targets: List[Target] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.utcnow)
