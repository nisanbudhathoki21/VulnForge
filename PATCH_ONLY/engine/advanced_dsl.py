"""
Advanced DSL engine (nuclei-compatible) for matchers
Supports expressions like:
- status_code == 200
- body contains 'admin'
- regex('(?i)root:.*:0:0', body)
- toupper, tolower, len, etc
- && || ! operators
- Binary ops for content_length, duration

This is an improvement over scanner's inline _eval_dsl, reusable across modules.
"""
import re
from typing import Any, Dict

class DSLEngine:
    def __init__(self):
        pass

    def evaluate(self, expr: str, context: Dict[str, Any]) -> bool:
        """
        context keys: status_code, body, headers, duration, content_length, etc
        """
        try:
            # helper funcs
            def contains(haystack, needle):
                return str(needle).lower() in str(haystack).lower()
            def regex(pat, text):
                try:
                    return bool(re.search(pat, str(text), re.I))
                except:
                    return False
            def bcontains(data, substr):
                # binary contains
                if isinstance(data, bytes):
                    return substr.encode() in data
                return str(substr) in str(data)

            # Prepare locals with helpers
            local = {
                "status_code": context.get("status_code", 0),
                "body": context.get("body",""),
                "headers": context.get("headers",""),
                "all_headers": context.get("headers",""),
                "duration": context.get("duration",0),
                "content_length": context.get("content_length",0),
                "contains": contains,
                "regex": regex,
                "bcontains": bcontains,
                "len": len,
                "toupper": lambda s: str(s).upper(),
                "tolower": lambda s: str(s).lower(),
            }
            # Translate nuclei DSL operators
            py_expr = expr.replace("&&"," and ").replace("||"," or ")
            # Handle ! prefix that is not !=
            py_expr = re.sub(r'(?<![=!])!\s*\(', 'not (', py_expr)
            py_expr = re.sub(r'!\s*contains', 'not contains', py_expr)
            py_expr = re.sub(r'!\s*regex', 'not regex', py_expr)
            # Eval safely
            result = eval(py_expr, {"__builtins__":{}}, local)
            return bool(result)
        except Exception as e:
            # print(f"DSL eval error {e} for {expr}")
            return False

    def evaluate_all(self, exprs, context):
        if isinstance(exprs, str):
            exprs=[exprs]
        for ex in exprs:
            if not self.evaluate(ex, context):
                return False
        return True
