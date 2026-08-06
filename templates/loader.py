from __future__ import annotations
from typing import List
import yaml, os
from .schema import Template, RequestDef
class TemplateLoader:
    def __init__(self, base_dir: str="templates") -> None:
        self.base = base_dir
    def load_all(self) -> List[Template]:
        tpls: List[Template] = []
        if not os.path.exists(self.base):
            return tpls
        for root, _, files in os.walk(self.base):
            for fn in files:
                if fn.endswith(".vft.yaml"):
                    try:
                        with open(os.path.join(root, fn), "r", encoding="utf-8") as f:
                            raw = yaml.safe_load(f)
                        reqs = []
                        for r in raw.get("requests", []):
                            reqs.append(RequestDef(
                                id=str(r["id"]),
                                method=str(r["method"]),
                                path=str(r.get("path","/")),
                                headers=r.get("headers", {}) or {},
                                body=r.get("body"),
                                matchers=r.get("matchers", {}) or {}
                            ))
                        tpls.append(Template(
                            vft=str(raw["vft"]),
                            id=str(raw["id"]),
                            name=str(raw["name"]),
                            severity=str(raw["severity"]),
                            confidence=str(raw["confidence"]),
                            category=str(raw["category"]),
                            metadata=raw.get("metadata", {}) or {},
                            variables=raw.get("variables", {}) or {},
                            requests=reqs,
                            extractors=raw.get("extractors", []) or [],
                            classification=raw.get("classification", {}) or {},
                            remediation=raw.get("remediation", {}) or {}
                        ))
                    except Exception as e:
                        print(f"Warning: failed to load {fn}: {e}")
        return tpls
