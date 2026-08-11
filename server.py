import asyncio
import base64
import hashlib
import json
import os
import sys
import urllib.parse
import uuid
from datetime import datetime
from typing import Dict, Any, Optional, List

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

from fastapi import FastAPI, BackgroundTasks, HTTPException, Query, Response
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from database import (
    init_db, get_dashboard_stats, get_all_scans, get_scan_by_id,
    get_findings_for_scan, get_all_findings, get_finding_by_id,
    get_repeater_history, save_scan
)
from engine.core import execute_security_scan, register_listener, unregister_listener, ACTIVE_SCAN_LOGS
from engine.repeater import execute_repeater_request
from engine.reporter import generate_pdf_report, generate_markdown_report

app = FastAPI(title="VulnForge Ultimate Security Suite", version="3.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

init_db()

STATIC_DIR = os.path.join(CURRENT_DIR, "static")
os.makedirs(STATIC_DIR, exist_ok=True)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

class ScanRequest(BaseModel):
    target_url: str
    profile: Optional[str] = "God-Level Pentest"
    timeout: Optional[float] = 6.0
    concurrency: Optional[int] = 10
    rate_limit: Optional[float] = 8.0

class RepeaterRequest(BaseModel):
    raw_request: str
    timeout: Optional[float] = 8.0
    title: Optional[str] = "Manual Probe"

class UtilityRequest(BaseModel):
    text: str
    operation: str

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        with open(index_file, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse("<h1>VulnForge Ultimate Backend is Running</h1>")

@app.get("/api/stats")
async def api_get_stats():
    return get_dashboard_stats()

@app.get("/api/scans")
async def api_get_scans():
    return get_all_scans()

@app.get("/api/scans/{scan_id}")
async def api_get_scan(scan_id: str):
    scan = get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings = get_findings_for_scan(scan_id)
    return {"scan": scan, "findings": findings}

@app.post("/api/scans/start")
async def api_start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    target = req.target_url.strip()
    if not target:
        raise HTTPException(status_code=400, detail="Target URL cannot be empty.")
    scan_id = datetime.now().strftime("%Y%m%d_%H%M%S_") + str(uuid.uuid4())[:3]
    options = {
        "profile": req.profile,
        "timeout": req.timeout,
        "concurrency": req.concurrency,
        "rate_limit": req.rate_limit
    }
    background_tasks.add_task(execute_security_scan, scan_id, target, options)
    return {"status": "started", "scan_id": scan_id, "target_url": target, "created_at": datetime.now().isoformat()}

@app.get("/api/findings")
async def api_get_findings(confirmed_only: bool = Query(False), severity: Optional[str] = Query(None), search: Optional[str] = Query(None)):
    return get_all_findings(confirmed_only=confirmed_only, severity=severity, search=search)

@app.get("/api/findings/{finding_id}")
async def api_get_finding(finding_id: int):
    f = get_finding_by_id(finding_id)
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return f

@app.post("/api/repeater/send")
async def api_repeater_send(req: RepeaterRequest):
    if not req.raw_request.strip():
        raise HTTPException(status_code=400, detail="Raw request cannot be empty.")
    try:
        return await execute_repeater_request(req.raw_request, timeout=req.timeout or 8.0, title=req.title or "Manual Probe")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Request failed: {str(e)}")

@app.get("/api/repeater/history")
async def api_repeater_history():
    return get_repeater_history()

@app.get("/api/logs/stream/{scan_id}")
async def api_stream_logs(scan_id: str):
    async def event_generator():
        existing = ACTIVE_SCAN_LOGS.get(scan_id, [])
        for log in existing:
            yield f"data: {json.dumps({'message': log, 'timestamp': datetime.now().strftime('%H:%M:%S')})}\n\n"
        queue = asyncio.Queue()
        register_listener(scan_id, queue)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=1.0)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("level") in ["COMPLETE", "ERROR"]:
                        break
                except asyncio.TimeoutError:
                    yield ": ping\n\n"
                    scan = get_scan_by_id(scan_id)
                    if scan and scan["status"] in ["completed", "failed"]:
                        break
        finally:
            unregister_listener(scan_id, queue)
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/reports/pdf/{scan_id}")
async def api_download_pdf(scan_id: str):
    try:
        pdf_bytes = generate_pdf_report(scan_id)
        return Response(content=pdf_bytes, media_type="application/pdf", headers={"Content-Disposition": f'attachment; filename="VulnForge_Report_{scan_id}.pdf"'})
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/markdown/{scan_id}")
async def api_download_markdown(scan_id: str):
    md = generate_markdown_report(scan_id)
    return Response(content=md, media_type="text/markdown", headers={"Content-Disposition": f'attachment; filename="VulnForge_Report_{scan_id}.md"'})

@app.post("/api/tools/encode-decode")
async def api_encode_decode(req: UtilityRequest):
    text, op = req.text, req.operation
    try:
        if op == "url_encode": res = urllib.parse.quote(text)
        elif op == "url_decode": res = urllib.parse.unquote(text)
        elif op == "b64_encode": res = base64.b64encode(text.encode()).decode()
        elif op == "b64_decode": res = base64.b64decode(text.encode()).decode(errors='replace')
        elif op == "md5": res = hashlib.md5(text.encode()).hexdigest()
        elif op == "sha256": res = hashlib.sha256(text.encode()).hexdigest()
        else: res = text
    except Exception as e:
        res = f"Error: {str(e)}"
    return {"result": res, "operation": op}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    print(f"[*] Starting VulnForge Ultimate Live Dashboard on http://{host}:{port}")
    uvicorn.run("server:app", host=host, port=port, reload=False)
