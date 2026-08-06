from __future__ import annotations
from typing import Any, Dict, List, Optional
from dataclasses import dataclass
@dataclass
class RequestDef:
    id: str
    method: str
    path: str = "/"
    headers: Dict[str, str] = None
    body: Optional[str] = None
    matchers: Dict[str, Any] = None
    def __post_init__(self):
        if self.headers is None:
            self.headers = {}
        if self.matchers is None:
            self.matchers = {}
@dataclass
class Template:
    vft: str
    id: str
    name: str
    severity: str
    confidence: str
    category: str
    metadata: Dict[str, Any]
    variables: Dict[str, str]
    requests: List[RequestDef]
    extractors: List[Dict[str, Any]]
    classification: Dict[str, Any]
    remediation: Dict[str, Any]
