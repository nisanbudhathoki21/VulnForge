from __future__ import annotations
from typing import Any, Dict, List
import re, json, threading

try:
    from lxml import etree
except ImportError:
    etree = None

try:
    import jsonpath_ng
except ImportError:
    jsonpath_ng = None

_REGEX_CACHE = {}
_LOCK = threading.Lock()

def _compile(pat):
    with _LOCK:
        if pat in _REGEX_CACHE:
            return _REGEX_CACHE[pat]
    try:
        c = re.compile(pat, re.I|re.S)
        with _LOCK:
            _REGEX_CACHE[pat]=c
        return c
    except re.error:
        return None

class ExtractCtx:
    def __init__(self, response) -> None:
        self.response = response
        self.text = ""
        try:
            self.text = response.text or ""
        except:
            try:
                self.text = response.content.decode(errors="ignore") if hasattr(response, "content") else ""
            except:
                self.text = ""
        self.headers = getattr(response, "headers", {}) or {}

def extract(ctx: ExtractCtx, extractors: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Enhanced extractor supporting:
    - regex with group, part (body/header/all)
    - json with jsonpath
    - kval (header key extraction)
    - xpath
    - raw
    - regex caching
    """
    out: Dict[str, Any] = {}
    for ex in extractors or []:
        if not isinstance(ex, dict):
            continue
        typ = str(ex.get("type","")).lower()
        name = ex.get("name","value")
        if not name:
            continue

        part = str(ex.get("part","body")).lower()
        if part == "body":
            data = ctx.text
        elif part in ("header","headers"):
            data = str(ctx.headers)
        elif part == "all":
            data = str(ctx.headers) + "\n" + ctx.text
        else:
            data = ctx.text

        # REGEX
        if typ == "regex":
            # support keys: pattern, regex, pattern list
            patterns = ex.get("pattern") or ex.get("regex") or []
            if isinstance(patterns, str):
                patterns=[patterns]
            group = ex.get("group", 1)  # default 1 for first group like nuclei
            # allow group as string "0"
            try:
                group_idx = int(group)
            except:
                group_idx = 0
            for pat in patterns:
                try:
                    comp = _compile(pat)
                    m = comp.search(data) if comp else re.search(pat, data, re.I|re.S)
                    if m:
                        if m.groups():
                            # try requested group, fallback to 0
                            try:
                                out[name] = m.group(group_idx) if group_idx <= len(m.groups()) else m.group(1)
                            except IndexError:
                                out[name] = m.group(1) if m.groups() else m.group(0)
                        else:
                            out[name] = m.group(0)
                        break
                except re.error:
                    continue
                except Exception:
                    continue

        # JSON
        elif typ == "json":
            try:
                jdata = ctx.response.json() if hasattr(ctx.response, "json") else json.loads(ctx.text)
                jpath = ex.get("path") or ex.get("json") or ex.get("query") or ""
                # If jsonpath available
                if jpath and jsonpath_ng:
                    try:
                        expr = jsonpath_ng.parse(jpath)
                        matches = [m.value for m in expr.find(jdata)]
                        if matches:
                            out[name] = matches[0] if len(matches)==1 else matches
                    except Exception:
                        pass
                else:
                    # Simple dot path $.a.b or a.b
                    cur=jdata
                    path = str(jpath).lstrip("$.").split(".") if jpath else []
                    for p in path:
                        if not p:
                            continue
                        if isinstance(cur, dict):
                            cur=cur.get(p)
                        elif isinstance(cur, list):
                            try:
                                cur=cur[int(p)]
                            except:
                                cur=None
                                break
                        else:
                            cur=None
                            break
                    if cur is not None:
                        out[name]=cur
                    elif not jpath:
                        out[name]=jdata
            except Exception:
                pass

        # KVAL - header key value
        elif typ in ("kval","key_value","header"):
            kval = ex.get("kval") or ex.get("key") or []
            if isinstance(kval, str):
                kval=[kval]
            for k in kval:
                for hk,hv in ctx.headers.items():
                    if hk.lower()==str(k).lower():
                        out[name]=hv
                        break
                if name in out:
                    break

        # XPATH
        elif typ == "xpath" and etree is not None:
            try:
                root = etree.HTML(ctx.text)
                expr = ex.get("expr") or ex.get("xpath") or ex.get("query") or ""
                if expr:
                    res = root.xpath(expr)
                    out[name]=res
            except Exception:
                pass

        # RAW
        elif typ == "raw":
            out[name] = ex.get("value","")

        # DSL extractor? e.g., extract via regex from DSL? simple support
        elif typ == "dsl":
            # Evaluate dsl expression that returns string
            try:
                # Example: dsl: "md5(body)"
                # We'll support minimal: keep as empty for now, rely on scanner extractor
                pass
            except:
                pass

    return out
