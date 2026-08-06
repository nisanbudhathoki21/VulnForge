from __future__ import annotations
import sys
import uuid
from typing import List, Dict, Any
from httpclient.client import HttpClient
from matcher.engine import MatchContext, apply_matchers
from workspace.models import Finding


class ScanResult:
    def __init__(self):
        self.findings: List[Finding] = []
        self.request_count: int = 0


class Scanner:
    def __init__(self, http: HttpClient):
        self.http = http
        self.memory: Dict[str, str] = {}

    def _resolve_kind(self, tpl, matchers: Dict[str, Any]) -> str:
        """Determine the finding's kind from the template's own classification,
        falling back to a conservative default rather than guessing from matcher type."""
        classification = getattr(tpl, "classification", None) or {}
        declared = classification.get("kind")
        if declared in ("Verified", "Possible", "Related", "Investigation"):
            return declared

        # Fallback: time-delay based matchers are treated as Verified since
        # timing behavior is directly observed, not inferred.
        if "time_delay" in str(matchers):
            return "Verified"

        return "Possible"

    async def run_template(self, ws, base_url: str, tpl) -> ScanResult:
        result = ScanResult()
        base = base_url.rstrip("/")

        for r in tpl.requests:
            result.request_count += 1

            # Variable substitution
            path = r.path
            for var, val in self.memory.items():
                path = path.replace(f"{{{{{var}}}}}", str(val))

            url = base + (path if path.startswith("/") else "/" + path)

            try:
                resp = await self.http.request(r.method, url, headers=r.headers)

                matched, evidence = apply_matchers(MatchContext(resp), r.matchers)
                if matched:
                    result.findings.append(Finding(
                        id=str(uuid.uuid4()),
                        title=tpl.name,
                        category=tpl.category,
                        kind=self._resolve_kind(tpl, r.matchers),
                        severity=tpl.severity,
                        confidence=1.0,
                        context={
                            "url": url,
                            "evidence": evidence,
                            "duration": getattr(resp, "vulnforge_duration", 0),
                        },
                    ))
            except Exception as e:
                print(f"[DEBUG] Template {tpl.id} failed: {e}", file=sys.stderr)

        return result
