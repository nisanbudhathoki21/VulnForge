from __future__ import annotations
from typing import Any, Dict, List
import re, json
try:
    from lxml import etree
except ImportError:
    etree = None
class ExtractCtx:
    def __init__(self, response) -> None:
        self.response = response
def extract(ctx: ExtractCtx, extractors: List[Dict[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for ex in extractors or []:
        typ = ex.get("type")
        name = ex.get("name","value")
        if typ == "regex":
            m = re.search(ex["pattern"], ctx.response.text, re.I|re.M|re.S)
            if m:
                out[name] = m.group(1) if m.groups() else m.group(0)
        elif typ == "json":
            try:
                out[name] = ctx.response.json()
            except json.JSONDecodeError:
                pass
        elif typ == "xpath" and etree is not None:
            try:
                root = etree.HTML(ctx.response.text)
                res = root.xpath(ex["expr"])
                out[name] = res
            except Exception:
                pass
    return out
