from __future__ import annotations

import os
import yaml

from .schema import Template, RequestDef


class TemplateLoader:
    def __init__(self, base_dir: str = "templates"):
        self.base = os.path.abspath(base_dir)

    def load_all(self):
        tpls = []
        seen_ids = set()

        if not os.path.exists(self.base):
            return tpls

        for root, _, files in os.walk(self.base):
            for fn in files:

                if not fn.endswith(".yaml") or fn.startswith("."):
                    continue

                path = os.path.join(root, fn)

                try:
                    print(f"[LOADING] {path}")

                    with open(path, "r", encoding="utf-8") as f:
                        raw = yaml.safe_load(f)

                    if raw is None:
                        print("  -> Empty YAML")
                        continue

                    if "id" not in raw:
                        print("  -> Missing id")
                        continue

                    if raw["id"] in seen_ids:
                        print(f"  -> Duplicate id: {raw['id']}")
                        continue

                    seen_ids.add(raw["id"])

                    requests = raw.get("requests", [])

                    if isinstance(requests, dict):
                        requests = [requests]

                    reqs = []

                    for r in requests:
                        reqs.append(
                            RequestDef(
                                id=str(r.get("id", "req")),
                                method=str(r.get("method", "GET")),
                                path=str(r.get("path", "/")),
                                headers=r.get("headers", {}),
                                body=r.get("body"),
                                matchers=r.get("matchers", {}),
                            )
                        )

                    tpl = Template(
                        vft=str(raw.get("vft", "1.0")),
                        id=str(raw["id"]),
                        name=str(raw.get("name", fn)),
                        severity=str(raw.get("severity", "Low")),
                        confidence=str(raw.get("confidence", "High")),
                        category=str(raw.get("category", "General")),
                        metadata=raw.get("metadata", {}),
                        variables=raw.get("variables", {}),
                        requests=reqs,
                        extractors=raw.get("extractors", []),
                        classification=raw.get("classification", {}),
                        remediation=raw.get("remediation", {}),
                    )

                    tpls.append(tpl)

                    print(f"  -> Loaded: {tpl.id}")

                except Exception as e:
                    print(f"[FAILED] {path}")
                    print(f"Reason: {e}")

        print(f"\n[+] Loaded {len(tpls)} templates")

        return tpls
