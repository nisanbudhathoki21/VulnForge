from __future__ import annotations
from typing import List, Dict, Any
import json
from workspace.models import Finding
from risk.engine import score
def to_json(workspace_id: str, findings: List[Finding]) -> str:
    data: List[Dict[str, Any]] = []
    for f in findings:
        s = score(f)
        data.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "kind": f.kind,
            "confidence": f.confidence,
            "context": f.context,
            "priority": s["priority"],
            "band": s["band"],
            "references": f.references
        })
    return json.dumps({"workspace": workspace_id, "findings": data}, indent=2)
