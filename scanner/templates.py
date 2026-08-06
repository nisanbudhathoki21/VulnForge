from dataclasses import dataclass, field
from typing import Dict, List, Optional

@dataclass(frozen=True)
class Matcher:
    type: str               # e.g., "header_contains", "body_regex", "missing_headers"
    value: str | List[str]  # string or list depending on the matcher

@dataclass(frozen=True)
class Extractor:
    type: str               # e.g., "header", "regex"
    name: str               # key name to store extracted value
    value: str              # header name or regex pattern

@dataclass(frozen=True)
class VFTemplate:
    id: str
    name: str
    description: str
    severity: str           # info/low/medium/high/critical
    category: str           # e.g., "misconfiguration", "injection"
    method: str             # GET/POST/HEAD/OPTIONS
    path: str               # relative or absolute path to request
    headers: Dict[str, str] = field(default_factory=dict)
    payload: Optional[str] = None
    matchers: List[Matcher] = field(default_factory=list)
    extractors: List[Extractor] = field(default_factory=list)
    recommendation: str = ""

    def normalized_method(self) -> str:
        return self.method.upper()
