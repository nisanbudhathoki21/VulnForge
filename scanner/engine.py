from __future__ import annotations
from typing import List
import asyncio, logging, urllib.parse, uuid, datetime
from httpclient.client import HttpClient
from templates.schema import Template
from matcher.engine import MatchContext, apply_matchers
from extractor.engine import ExtractCtx, extract
from workspace.models import Workspace, Finding, Evidence
log = logging.getLogger("vulnforge.scanner")
class ScanResult:
    def __init__(self) -> None:
        self.findings: List[Finding] = []
        self.evidence: List[Evidence] = []
class Scanner:
    def __init__(self, http: HttpClient) -> None:
        self.http = http
    async def run_template(self, ws: Workspace, base_url: str, tpl: Template) -> ScanResult:
        res = ScanResult()
        for r in tpl.requests:
            url = urllib.parse.urljoin(base_url, r.path)
            try:
                resp = await self.http.request(r.method, url, headers=r.headers, content=r.body)
            except Exception as e:
                log.warning("Request error %s -> %s", url, e)
                continue
            mctx = MatchContext(resp)
            ex_ctx = ExtractCtx(resp)
            matched = apply_matchers(mctx, r.matchers)
            data = extract(ex_ctx, tpl.extractors)
            ev = Evidence(
                id=str(uuid.uuid4()),
                type="http",
                data={
                    "template_id": tpl.id,
                    "request_id": r.id,
                    "url": url,
                    "status": resp.status_code,
                    "headers": dict(resp.headers),
                    "body_preview": resp.text[:2048],
                    "extracted": data
                },
                created_at=datetime.datetime.utcnow().isoformat() + "Z"
            )
            res.evidence.append(ev)
            if matched:
                kind = tpl.classification.get("kind","Possible")
                f = Finding(
                    id=str(uuid.uuid4()),
                    title=tpl.name,
                    category=tpl.category,
                    kind=kind,
                    severity=tpl.severity,
                    confidence={"Low":0.3,"Medium":0.6,"High":0.85,"Certain":0.98}.get(tpl.confidence,0.5),
                    context={"template_id": tpl.id, "request_id": r.id, "url": url},
                    references=tpl.metadata.get("references", []),
                    evidence_ids=[ev.id]
                )
                res.findings.append(f)
        return res
    async def scan(self, ws: Workspace, targets: List[str], templates: List[Template]) -> ScanResult:
        agg = ScanResult()
        for base in targets:
            for tpl in templates:
                r = await self.run_template(ws, base, tpl)
                agg.findings.extend(r.findings)
                agg.evidence.extend(r.evidence)
        return agg
