from __future__ import annotations
from typing import Any, Dict, Tuple
import re


class MatchContext:
    def __init__(self, response):
        self.response = response
        self.duration = getattr(response, "vulnforge_duration", 0)


def apply_matchers(ctx: MatchContext, matchers: Dict[str, Any]) -> Tuple[bool, str]:
    if not matchers:
        return False, ""

    logic = matchers.get("logic", "OR").upper()
    rules = matchers.get("rules", [])
    results, evidence = [], []

    for r in rules:
        rtype = r.get("type")

        # 1. Time Delay Matcher (blind detection)
        if rtype == "time_delay":
            seconds = float(r.get("seconds", 0))
            if ctx.duration >= seconds:
                results.append(True)
                evidence.append(f"Time Delay: {ctx.duration:.2f}s (Threshold: {seconds}s)")
            else:
                results.append(False)

        # 2. Header Absence
        elif rtype == "header_absent":
            key = str(r.get("key", "")).lower()
            if key not in [k.lower() for k in ctx.response.headers.keys()]:
                results.append(True)
                evidence.append(f"Missing: {key}")
            else:
                results.append(False)

        # 3. Header Present (with optional value check)
        elif rtype == "header_present":
            key = str(r.get("key", "")).lower()
            expected_value = r.get("value")
            actual = None
            for hk, hv in ctx.response.headers.items():
                if hk.lower() == key:
                    actual = hv
                    break
            if actual is not None and (expected_value is None or expected_value.lower() in actual.lower()):
                results.append(True)
                evidence.append(f"Present: {key}={actual}")
            else:
                results.append(False)

        # 4. Status Code
        elif rtype == "status":
            expected = int(r.get("code", 200))
            if ctx.response.status_code == expected:
                results.append(True)
                evidence.append(f"Status: {ctx.response.status_code}")
            else:
                results.append(False)

        # 5. Regex against headers + body
        elif rtype == "regex":
            pattern = str(r.get("pattern", ""))
            content = f"{ctx.response.headers}\n{ctx.response.text}"
            if re.search(pattern, content, re.I | re.M):
                results.append(True)
                evidence.append(f"Matched: {pattern[:40]}")
            else:
                results.append(False)

        else:
            # Unknown rule type: do not silently pass it — record as failed
            # so unsupported matcher types can't accidentally satisfy AND logic.
            results.append(False)

    success = all(results) if logic == "AND" else any(results)
    return success, " | ".join(evidence) if success else ""
