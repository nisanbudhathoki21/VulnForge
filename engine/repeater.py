import time
import httpx
import re
import os
import sys
from typing import Dict, Any, Tuple

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database import save_repeater_request
from engine.requester import format_raw_request, format_raw_response, DEFAULT_USER_AGENT

def parse_raw_http_request(raw_text: str, default_scheme: str = "https") -> Tuple[str, str, Dict[str, str], str]:
    raw_text = raw_text.replace("\r\n", "\n")
    parts = raw_text.split("\n\n", 1)
    header_part = parts[0]
    body_part = parts[1] if len(parts) > 1 else ""
    lines = header_part.split("\n")
    req_line = lines[0].strip()
    match = re.match(r"^([A-Z]+)\s+([^\s]+)", req_line)
    if not match:
        raise ValueError(f"Invalid HTTP request line: {req_line}")
    method = match.group(1).upper()
    path = match.group(2)
    headers = {}
    host = ""
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
            if k.strip().lower() == "host":
                host = v.strip()
    if not host:
        host = "localhost"
    if path.startswith("http://") or path.startswith("https://"):
        full_url = path
    else:
        scheme = "http" if ("localhost" in host or "127.0.0.1" in host) else default_scheme
        full_url = f"{scheme}://{host}{path}"
    return method, full_url, headers, body_part

async def execute_repeater_request(raw_request_text: str, timeout: float = 8.0, title: str = "Manual Probe") -> Dict[str, Any]:
    method, url, headers, body = parse_raw_http_request(raw_request_text)
    if "User-Agent" not in headers:
        headers["User-Agent"] = DEFAULT_USER_AGENT
    t0 = time.perf_counter()
    async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=False) as client:
        resp = await client.request(method=method, url=url, headers=headers, content=body.encode('utf-8') if body else None)
        elapsed = round((time.perf_counter() - t0) * 1000, 2)
        raw_resp = format_raw_response(resp.status_code, "OK", dict(resp.headers), resp.text)
        rep_id = save_repeater_request({"title": title, "method": method, "url": url, "raw_request": raw_request_text, "raw_response": raw_resp, "status_code": resp.status_code, "duration_ms": elapsed})
        return {"id": rep_id, "method": method, "url": url, "status_code": resp.status_code, "duration_ms": elapsed, "headers": dict(resp.headers), "body": resp.text, "raw_request": raw_request_text, "raw_response": raw_resp}
