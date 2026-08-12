from __future__ import annotations
import os
import re
import yaml
from pathlib import Path
from typing import List, Dict

from .schema import Template, RequestDef

_DEFAULT_TEMPLATES_DIR = str(Path(__file__).resolve().parents[1] / "templates")

# Cache for compiled regex (perf)
_REGEX_CACHE = {}

class TemplateLoader:
    """
    Fixed & Enhanced Template Loader
    - Supports both legacy VulnForge schema (id, requests, matchers list)
    - And new VFT/nuclei-like schema (vft, requests with logic/rules)
    - Deduplicates by id
    - Pre-validates required fields (like nuclei -t validation)
    - Skips _disabled and validates YAML
    """
    def __init__(self, base_dir: str = None):
        self.base = os.path.abspath(base_dir or _DEFAULT_TEMPLATES_DIR)

    def _is_disabled_path(self, path: str) -> bool:
        parts = os.path.normpath(path).split(os.sep)
        return "_disabled" in parts or any(p.startswith("_disabled") for p in parts)

    def _validate_template(self, raw: dict, path: str) -> bool:
        # Basic nuclei-like validation: must have info or id+name, and requests/http/flow
        if not isinstance(raw, dict):
            return False
        if "id" not in raw and "vft" not in raw:
            # allow if has requests anyway? original did require id
            if "requests" not in raw:
                return False
        reqs = raw.get("requests")
        if reqs is None:
            # allow single request as dict?
            if "path" in raw or "method" in raw:
                return True
            return False
        if isinstance(reqs, dict):
            reqs = [reqs]
        if not isinstance(reqs, list) or len(reqs)==0:
            return False
        return True

    def load_all(self) -> List[Template]:
        tpls: List[Template] = []
        seen_ids = set()
        if not os.path.exists(self.base):
            print(f"[WARN] Template dir not found: {self.base}")
            return tpls
        for root, dirs, files in os.walk(self.base):
            # Prune disabled directories early
            dirs[:] = [d for d in dirs if d != "_disabled" and not d.startswith(".") and d != "__pycache__"]
            for fn in sorted(files):
                if not fn.endswith((".yaml",".yml")):
                    continue
                if fn.startswith("."):
                    continue
                if fn.lower().endswith(".disabled"):
                    continue
                path = os.path.join(root, fn)
                if self._is_disabled_path(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        raw = yaml.safe_load(f)
                    if raw is None:
                        continue
                    if not isinstance(raw, dict):
                        print(f"[WARN] Invalid YAML structure: {path}")
                        continue
                    if not self._validate_template(raw, path):
                        print(f"[WARN] Skipping invalid template (missing id/requests): {path}")
                        continue
                    template_id = str(raw.get("id", Path(path).stem))
                    if template_id in seen_ids:
                        print(f"[WARN] Duplicate id {template_id} in {path} - skipping")
                        continue
                    seen_ids.add(template_id)

                    requests_raw = raw.get("requests", [])
                    if isinstance(requests_raw, dict):
                        requests_raw=[requests_raw]
                    if not isinstance(requests_raw, list):
                        requests_raw=[]

                    reqs=[]
                    for r in requests_raw:
                        if not isinstance(r, dict):
                            continue
                        # Normalize path: can be str or list
                        reqs.append(
                            RequestDef(
                                id=str(r.get("id", "req")),
                                method=str(r.get("method","GET")),
                                path=r.get("path","/"),
                                headers=r.get("headers",{}),
                                body=r.get("body"),
                                matchers=r.get("matchers",{}),
                            )
                        )
                    tpl=Template(
                        vft=str(raw.get("vft","1.0")),
                        id=template_id,
                        name=str(raw.get("name", fn)),
                        severity=str(raw.get("severity","Low")),
                        confidence=str(raw.get("confidence","High")),
                        category=str(raw.get("category","General")),
                        metadata=raw.get("metadata",{}),
                        variables=raw.get("variables",{}),
                        requests=reqs,
                        extractors=raw.get("extractors",[]),
                        classification=raw.get("classification",{}),
                        remediation=raw.get("remediation",{}),
                    )
                    tpls.append(tpl)
                except yaml.YAMLError as e:
                    print(f"[FAILED YAML] {path}: {e}")
                except Exception as e:
                    print(f"[FAILED] {path}: {e}")

        print(f"\n[+] Loaded {len(tpls)} templates from {self.base}")
        return tpls

    # Additional method for scanner to load raw dicts directly (faster, no schema conversion)
    def load_raw(self) -> List[Dict]:
        """Load templates as raw dicts, like Scanner.load_templates does but with validation"""
        raw_templates=[]
        seen=set()
        if not os.path.exists(self.base):
            return raw_templates
        for root, dirs, files in os.walk(self.base):
            dirs[:] = [d for d in dirs if d not in ("_disabled",".git","__pycache__")]
            for fn in sorted(files):
                if not fn.lower().endswith((".yaml",".yml")):
                    continue
                if fn.lower().endswith(".disabled"):
                    continue
                path=os.path.join(root, fn)
                if self._is_disabled_path(path):
                    continue
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        data=yaml.safe_load(f)
                    if not isinstance(data, dict):
                        continue
                    if "id" not in data and "vft" not in data:
                        if "requests" not in data:
                            continue
                        data["id"]=Path(path).stem
                    if "requests" not in data or not isinstance(data["requests"], list):
                        continue
                    tid=str(data["id"])
                    if tid in seen:
                        continue
                    seen.add(tid)
                    data["_file"]=path
                    raw_templates.append(data)
                except Exception:
                    continue
        return raw_templates
