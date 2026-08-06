from __future__ import annotations
from typing import Any, Dict, List
import re
class MatchContext:
    def __init__(self, response) -> None:
        self.response = response
def _header_absent(ctx: MatchContext, key: str) -> bool:
    return key.lower() not in {k.lower(): v for k,v in ctx.response.headers.items()}
def _status(ctx: MatchContext, code: int) -> bool:
    return ctx.response.status_code == code
def _regex(ctx: MatchContext, pattern: str, flags: str="ims") -> bool:
    fl = 0
    fl |= re.I if "i" in flags else 0
    fl |= re.M if "m" in flags else 0
    fl |= re.S if "s" in flags else 0
    rx = re.compile(pattern, fl)
    return bool(rx.search(ctx.response.text))
def apply_matchers(ctx: MatchContext, matchers: Dict[str, Any]) -> bool:
    logic = (matchers or {}).get("logic", "AND")
    rules: List[Dict[str, Any]] = (matchers or {}).get("rules", [])
    if not rules:
        return False
    results: List[bool] = []
    for r in rules:
        t = r.get("type")
        if t == "header_absent":
            results.append(_header_absent(ctx, r["key"]))
        elif t == "status":
            results.append(_status(ctx, int(r["code"])))
        elif t == "regex":
            results.append(_regex(ctx, r["pattern"], r.get("flags","ims")))
        else:
            results.append(False)
    if logic == "AND":
        return all(results)
    if logic == "OR":
        return any(results)
    if logic == "NOT":
        return not any(results)
    return False
