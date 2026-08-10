from __future__ import annotations

import os
from pathlib import Path
from typing import List

import yaml

from .schema import Template, RequestDef


_DEFAULT_TEMPLATES_DIR = str(Path(__file__).resolve().parents[1] / "templates")

class TemplateLoader:
    def __init__(self, base_dir: str = None):
        self.base = os.path.abspath(base_dir or _DEFAULT_TEMPLATES_DIR)

    def _is_disabled_path(self, path: str) -> bool:
        """
        Return True when the template is inside a disabled directory.

        Example:
            templates/_disabled/foo.yaml
            templates/_disabled/starbucks-jp/test.yaml

        Both are ignored.
        """
        parts = os.path.normpath(path).split(os.sep)
        return "_disabled" in parts

    def load_all(self) -> List[Template]:
        tpls: List[Template] = []
        seen_ids = set()

        if not os.path.exists(self.base):
            return tpls

        for root, dirs, files in os.walk(self.base):
            # Do not descend into disabled template directories.
            dirs[:] = [
                d for d in dirs
                if d != "_disabled"
            ]

            for fn in files:

                if not fn.endswith((".yaml", ".yml")):
                    continue

                if fn.startswith("."):
                    continue

                path = os.path.join(root, fn)

                # Defensive check in case this function is called
                # with a path that somehow contains _disabled.
                if self._is_disabled_path(path):
                    continue

                try:
                    print(f"[LOADING] {path}")

                    with open(
                        path,
                        "r",
                        encoding="utf-8",
                    ) as f:
                        raw = yaml.safe_load(f)

                    if raw is None:
                        print("  -> Empty YAML")
                        continue

                    if not isinstance(raw, dict):
                        print("  -> Invalid YAML structure")
                        continue

                    if "id" not in raw:
                        print("  -> Missing id")
                        continue

                    template_id = str(raw["id"])

                    if template_id in seen_ids:
                        print(
                            f"  -> Duplicate id: "
                            f"{template_id}"
                        )
                        continue

                    seen_ids.add(template_id)

                    requests = raw.get("requests", [])

                    if isinstance(requests, dict):
                        requests = [requests]

                    if not isinstance(requests, list):
                        print("  -> Invalid requests")
                        continue

                    reqs = []

                    for r in requests:

                        if not isinstance(r, dict):
                            continue

                        reqs.append(
                            RequestDef(
                                id=str(
                                    r.get("id", "req")
                                ),
                                method=str(
                                    r.get("method", "GET")
                                ),
                                path=r.get(
                                    "path",
                                    "/",
                                ),
                                headers=r.get(
                                    "headers",
                                    {},
                                ),
                                body=r.get("body"),
                                matchers=r.get(
                                    "matchers",
                                    {},
                                ),
                            )
                        )

                    tpl = Template(
                        vft=str(
                            raw.get("vft", "1.0")
                        ),
                        id=template_id,
                        name=str(
                            raw.get("name", fn)
                        ),
                        severity=str(
                            raw.get(
                                "severity",
                                "Low",
                            )
                        ),
                        confidence=str(
                            raw.get(
                                "confidence",
                                "High",
                            )
                        ),
                        category=str(
                            raw.get(
                                "category",
                                "General",
                            )
                        ),
                        metadata=raw.get(
                            "metadata",
                            {},
                        ),
                        variables=raw.get(
                            "variables",
                            {},
                        ),
                        requests=reqs,
                        extractors=raw.get(
                            "extractors",
                            [],
                        ),
                        classification=raw.get(
                            "classification",
                            {},
                        ),
                        remediation=raw.get(
                            "remediation",
                            {},
                        ),
                    )

                    tpls.append(tpl)

                    print(
                        f"  -> Loaded: "
                        f"{tpl.id}"
                    )

                except Exception as e:
                    print(f"[FAILED] {path}")
                    print(f"Reason: {e}")

        print(
            f"\n[+] Loaded "
            f"{len(tpls)} templates"
        )

        return tpls
