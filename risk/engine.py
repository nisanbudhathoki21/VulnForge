from __future__ import annotations
from typing import Dict
from workspace.models import Finding
def score(f: Finding) -> Dict[str, float | str]:
    sev_w = {"Critical": 1.0, "High": 0.8, "Medium": 0.5, "Low": 0.3, "Informational": 0.1}.get(f.severity, 0.3)
    conf = max(0.0, min(1.0, f.confidence))
    exposure = 0.7 if "/login" not in f.context.get("url", "") else 0.5
    chain = 0.2 if f.kind == "Related" else 0.5 if f.kind == "Possible" else 0.7
    novelty = 0.4 if "template_id" in f.context else 0.6
    exploit = 0.5
    priority = 100 * (0.35 * sev_w + 0.25 * conf + 0.15 * exposure + 0.15 * chain + 0.10 * novelty)
    band = (
        "🔴 Critical" if priority >= 85 else
        "🟠 High" if priority >= 70 else
        "🟡 Medium" if priority >= 50 else
        "🟢 Low" if priority >= 30 else
        "💔 Informational"
    )
    return {"priority": round(priority, 2), "band": band, "exploitability": exploit}
