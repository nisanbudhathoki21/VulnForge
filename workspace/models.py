from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Any
from datetime import datetime
import uuid
@dataclass
class Target:
    url: str
    tags: List[str]=field(default_factory=list)
@dataclass
class Evidence:
    id: str
    type: str
    data: Any
    created_at: str
@dataclass
class Finding:
    id: str
    title: str
    category: str
    kind: str
    severity: str
    confidence: float
    context: Dict[str, Any]
    references: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")
@dataclass
class Workspace:
    id: str
    name: str
    targets: List[Target] = field(default_factory=list)
    notes: Dict[str, str] = field(default_factory=dict)
    history: List[Dict[str, Any]] = field(default_factory=list)
    templates_used: List[str] = field(default_factory=list)
    reports: List[str] = field(default_factory=list)
    evidence: Dict[str, Evidence] = field(default_factory=dict)
    screenshots: Dict[str, str] = field(default_factory=dict)
    bookmarks: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    ai_context: Dict[str, Any] = field(default_factory=dict)
    @staticmethod
    def new(name: str) -> "Workspace":
        return Workspace(id=str(uuid.uuid4()), name=name)
    def to_json(self) -> Dict[str, Any]:
        return asdict(self)
