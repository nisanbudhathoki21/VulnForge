from __future__ import annotations
from typing import Protocol, Dict, Any
class AIProvider(Protocol):
    name: str
    def summarize(self, finding: Dict[str, Any]) -> str: ...
    def guidance(self, finding: Dict[str, Any]) -> str: ...
class NullAI:
    name = "null"
    def summarize(self, finding: Dict[str, Any]) -> str:
        return "AI disabled. No summary."
    def guidance(self, finding: Dict[str, Any]) -> str:
        return "AI disabled. No guidance."
