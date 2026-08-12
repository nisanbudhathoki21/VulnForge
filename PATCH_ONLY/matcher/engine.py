from __future__ import annotations
from typing import Any, Dict, Tuple, List
import re
import time
import threading

_REGEX_CACHE: Dict[str, re.Pattern] = {}
_LOCK = threading.Lock()

def _compile(pat: str):
    with _LOCK:
        if pat in _REGEX_CACHE:
            return _REGEX_CACHE[pat]
    try:
        c=re.compile(pat, re.I)
        with _LOCK:
            _REGEX_CACHE[pat]=c
        return c
    except re.error:
        return None

class MatchContext:
    def __init__(self, response):
        self.response = response
        # Unified duration handling (supports all attr names)
        dur = getattr(response, "vulnforge_duration", None)
        if dur is None:
            dur = getattr(response, "vf_duration", None)
        if dur is None:
            dur = getattr(response, "vulnforge_elapsed", 0)
            try:
                # requests elapsed
                if hasattr(response, "elapsed"):
                    dur = response.elapsed.total_seconds()
            except:
                pass
        self.duration = float(dur or 0)
        self.body = getattr(response, "text", "") or ""
        try:
            # decode if needed, fallback
            if not self.body and hasattr(response, "content"):
               self.body = response.content.decode(errors="ignore")
        except:
            pass
        self.headers = getattr(response, "headers", {}) or {}
        self.status = getattr(response, "status_code", 0)

def apply_matchers(ctx: MatchContext, matchers: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Enhanced nuclei-compatible matcher engine.
    Supports:
    - time_delay / time / delay with seconds/min/max
    - header_absent / header_present / header
    - status with list support
    - status_not
    - word with part support
    - regex with part support
    - size/length
    - dsl
    - binary (best effort)
    """
    if not matchers:
        return False, ""

    logic = str(matchers.get("logic", "OR")).upper()
    rules = matchers.get("rules", [])
    if isinstance(rules, dict):
        rules=[rules]

    results: List[bool] = []
    evidence: List[str] = []

    for r in rules:
        if not isinstance(r, dict):
            results.append(False)
            continue
        rtype = str(r.get("type","")).lower()
        negative = bool(r.get("negative", False))

        def finalize(found: bool):
            return (not found) if negative else found

        # TIME DELAY
        if rtype in ("time_delay","time","delay"):
            try:
                # Support seconds or min/max
                sec = float(r.get("seconds", r.get("min", 0)) or 0)
                max_s = float(r.get("max", 9999))
                if max_s is None:
                    max_s=9999
                # If only seconds key, interpret as >= seconds
                if "seconds" in r and "max" not in r:
                    if ctx.duration >= sec:
                        results.append(finalize(True))
                        evidence.append(f"Time {ctx.duration:.2f}s >= {sec}s")
                    else:
                        results.append(finalize(False))
                else:
                    if sec <= ctx.duration <= max_s:
                        results.append(finalize(True))
                        evidence.append(f"Time {ctx.duration:.2f}s in [{sec},{max_s}]")
                    else:
                        results.append(finalize(False))
            except Exception:
                results.append(False)

        # HEADER ABSENT
        elif rtype in ("header_absent","missing_header"):
            key=str(r.get("key","")).lower()
            if not key:
                results.append(False)
                continue
            present = any(k.lower()==key for k in ctx.headers.keys())
            found = not present
            if finalize(found):
                results.append(True)
                evidence.append(f"Missing: {key}")
            else:
                results.append(False)

        # HEADER PRESENT
        elif rtype in ("header_present","present_header"):
            key=str(r.get("key","")).lower()
            exp_val=r.get("value")
            actual=None
            for hk,hv in ctx.headers.items():
                if hk.lower()==key:
                    actual=hv
                    break
            if actual is not None and (exp_val is None or str(exp_val).lower() in str(actual).lower()):
                if finalize(True):
                    results.append(True)
                    evidence.append(f"Present: {key}={actual}")
                else:
                    results.append(False)
            else:
                results.append(finalize(False))

        # HEADER (generic with name/value/regex)
        elif rtype=="header":
            name=r.get("name") or r.get("key") or ""
            if not name:
                results.append(False)
                continue
            actual=""
            for hk,hv in ctx.headers.items():
                if hk.lower()==str(name).lower():
                    actual=hv
                    break
            if "value" in r:
                found=str(r["value"]).lower() in actual.lower() if actual else False
            elif "regex" in r or "pattern" in r:
                pat=r.get("regex") or r.get("pattern")
                try:
                    found=bool(re.search(pat, actual, re.I)) if actual else False
                except:
                    found=False
            else:
                found=bool(actual)
            if finalize(found):
                results.append(True)
                evidence.append(f"Header {name}: {actual[:50]}")
            else:
                results.append(False)

        # STATUS
        elif rtype=="status":
            expected = r.get("code")
            if expected is None:
                expected = r.get("status",200)
            if isinstance(expected, list):
                codes=[int(x) for x in expected]
            elif isinstance(expected, str) and "," in expected:
                codes=[int(x.strip()) for x in expected.split(",")]
            else:
                try:
                    codes=[int(expected)]
                except:
                    codes=[200]
            found = ctx.status in codes
            if finalize(found):
                results.append(True)
                evidence.append(f"Status: {ctx.status}")
            else:
                results.append(False)

        # STATUS_NOT
        elif rtype in ("status_not","not_status"):
            expected = r.get("code") or r.get("status") or 200
            if isinstance(expected, list):
                codes=[int(x) for x in expected]
            else:
                try:
                    codes=[int(expected)]
                except:
                    codes=[200]
            found = ctx.status not in codes
            # negative double handling simplified
            results.append(found)
            if found:
                evidence.append(f"Status not {codes}: got {ctx.status}")

        # WORD
        elif rtype=="word":
            words=r.get("words") or r.get("word") or []
            if isinstance(words, str):
                words=[words]
            part=str(r.get("part","body")).lower()
            if part=="body":
                data=ctx.body
            elif part in ("header","headers"):
                data=str(ctx.headers)
            else:
                data=ctx.body+"\n"+str(ctx.headers)
            found=any(str(w).lower() in data.lower() for w in words)
            if finalize(found):
                results.append(True)
                evidence.append(f"Word match: {words[:2]}")
            else:
                results.append(False)

        # REGEX
        elif rtype in ("regex","pattern"):
            pattern=str(r.get("pattern") or r.get("regex") or "")
            if not pattern and "words" in r:
                # sometimes word list under regex? fallback
                pattern=str(r["words"][0]) if isinstance(r["words"], list) else str(r["words"])
            part=str(r.get("part","body")).lower()
            if part=="body":
                data=ctx.body
            elif part in ("header","headers"):
                data=str(ctx.headers)
            else:
                data=str(ctx.headers)+"\n"+ctx.body
            try:
                comp=_compile(pattern)
                if comp:
                    found=bool(comp.search(data))
                else:
                    found=bool(re.search(pattern, data, re.I|re.M))
            except re.error:
                found=False
            if finalize(found):
                results.append(True)
                evidence.append(f"Regex: {pattern[:40]}")
            else:
                results.append(False)

        # SIZE / LENGTH
        elif rtype in ("size","length","content_length"):
            exp = r.get("size") or r.get("length") or 0
            try:
                if isinstance(exp, str) and "-" in exp:
                    a,b=exp.split("-",1)
                    found = int(a) <= len(ctx.body) <= int(b)
                else:
                    found = len(ctx.body) == int(exp)
            except:
                # operator handling > < etc if string
                try:
                    op=str(exp)
                    llen=len(ctx.body)
                    if op.startswith(">="):
                        found=llen>=int(op[2:])
                    elif op.startswith("<="):
                        found=llen<=int(op[2:])
                    elif op.startswith(">"):
                        found=llen>int(op[1:])
                    elif op.startswith("<"):
                        found=llen<int(op[1:])
                    else:
                        found=False
                except:
                    found=False
            if finalize(found):
                results.append(True)
                evidence.append(f"Size {len(ctx.body)} matches {exp}")
            else:
                results.append(False)

        # DSL - simple eval
        elif rtype=="dsl":
            exprs=r.get("dsl") or []
            if isinstance(exprs, str):
                exprs=[exprs]
            ok=True
            for expr in exprs:
                # reuse simple evaluator from scanner - quick implementation
                try:
                    # Very limited: support contains, status_code, body
                    def contains(a,b): return str(b).lower() in str(a).lower()
                    def regex(p,t):
                        try: return bool(re.search(p, str(t), re.I))
                        except: return False
                    local = {"status_code": ctx.status, "body": ctx.body, "content_length": len(ctx.body),
                             "duration": ctx.duration, "contains": contains, "regex": regex, "headers": str(ctx.headers)}
                    py_expr = expr.replace("&&"," and ").replace("||"," or ")
                    if not eval(py_expr, {"__builtins__":{}}, local):
                        ok=False
                        break
                except Exception:
                    ok=False
                    break
            if finalize(ok):
                results.append(True)
                evidence.append(f"DSL {exprs[0][:50] if exprs else ''}")
            else:
                results.append(False)

        else:
            results.append(False)

    success = all(results) if logic=="AND" else any(results)
    return success, " | ".join(evidence) if success else ""
