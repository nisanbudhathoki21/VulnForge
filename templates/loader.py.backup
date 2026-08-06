from __future__ import annotations
import yaml, os
from .schema import Template, RequestDef

class TemplateLoader:
    def __init__(self, base_dir: str="templates"):
        self.base = os.path.abspath(base_dir)

    def load_all(self):
        tpls = []
        seen_ids = set()
        if not os.path.exists(self.base): return tpls
        
        for root, _, files in os.walk(self.base):
            for fn in files:
                if fn.endswith(".yaml") and not fn.startswith("."):
                    path = os.path.join(root, fn)
                    try:
                        with open(path, "r") as f:
                            raw = yaml.safe_load(f)
                        if not raw or "id" not in raw: continue
                        
                        # Check for duplicates across the whole library
                        if raw["id"] in seen_ids: continue
                        seen_ids.add(raw["id"])

                        r_list = raw.get("requests", [])
                        if isinstance(r_list, dict): r_list = [r_list]
                        
                        reqs = [RequestDef(
                            id=str(r.get("id", "req")),
                            method=str(r.get("method", "GET")),
                            path=str(r.get("path", "/")),
                            headers=r.get("headers", {}),
                            matchers=r.get("matchers", {})
                        ) for r in r_list]
                        
                        tpls.append(Template(
                            vft="1.0", id=raw["id"], name=raw.get("name", fn),
                            severity=raw.get("severity", "Low"),
                            confidence="High", category=raw.get("category", "General"),
                            metadata={}, variables={}, requests=reqs,
                            extractors=[], classification={}, remediation={}
                        ))
                    except: continue
        return tpls
