import time
import httpx
import urllib.parse
from typing import Dict, Any, Optional
from database import log_request

DEFAULT_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 (VulnForge/3.2 Professional)"

class HTTPResponseResult:
    def __init__(self, status_code: int, headers: Dict[str, str], body: str, raw_request: str, raw_response: str, duration_ms: float, url: str, method: str, request_headers: Dict[str, str], request_body: str = ""):
        self.status_code = status_code
        self.headers = headers
        self.body = body
        self.raw_request = raw_request
        self.raw_response = raw_response
        self.duration_ms = duration_ms
        self.url = url
        self.method = method
        self.request_headers = request_headers
        self.request_body = request_body

def format_raw_request(method: str, url: str, headers: Dict[str, str], body: str = "") -> str:
    parsed = urllib.parse.urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path += f"?{parsed.query}"
    host = parsed.netloc
    normalized = {"Host": host}
    for k, v in headers.items():
        if k.lower() != "host":
            normalized[k] = v
    if body and "Content-Length" not in normalized:
        normalized["Content-Length"] = str(len(body.encode('utf-8')))
    lines = [f"{method.upper()} {path} HTTP/1.1"]
    for k, v in normalized.items():
        lines.append(f"{k}: {v}")
    req = "\r\n".join(lines) + "\r\n\r\n"
    if body:
        req += body
    return req

def format_raw_response(status_code: int, reason_phrase: str, headers: Dict[str, str], body: str) -> str:
    lines = [f"HTTP/1.1 {status_code} {reason_phrase}"]
    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    return "\r\n".join(lines) + "\r\n\r\n" + body

class Requester:
    def __init__(self, scan_id: Optional[str] = None, timeout: float = 8.0):
        self.scan_id = scan_id
        self.timeout = timeout
        self.client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(timeout, connect=3.0),
            follow_redirects=False,
            limits=httpx.Limits(max_keepalive_connections=30, max_connections=60)
        )

    async def close(self):
        await self.client.aclose()

    async def send(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, data: Optional[Any] = None, json_data: Optional[Any] = None, follow_redirects: bool = False, module: str = "") -> HTTPResponseResult:
        req_headers = {
            "User-Agent": DEFAULT_USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Connection": "keep-alive"
        }
        if headers:
            req_headers.update(headers)
        body_str = ""
        if data:
            if isinstance(data, dict):
                body_str = urllib.parse.urlencode(data)
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
            else:
                body_str = str(data)
        elif json_data is not None:
            import json
            body_str = json.dumps(json_data)
            req_headers["Content-Type"] = "application/json"

        raw_req = format_raw_request(method, url, req_headers, body_str)
        t0 = time.perf_counter()
        status_code = 0
        resp_headers = {}
        resp_body = ""
        reason = "OK"
        try:
            resp = await self.client.request(method=method.upper(), url=url, headers=req_headers, content=body_str.encode('utf-8') if body_str else None, follow_redirects=follow_redirects)
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            status_code = resp.status_code
            reason = resp.extensions.get("reason_phrase", b"OK").decode("latin-1", errors="ignore") or "OK"
            resp_headers = dict(resp.headers)
            try:
                resp_body = resp.text
            except Exception:
                resp_body = resp.content.decode("latin-1", errors="replace")
        except Exception as e:
            elapsed = round((time.perf_counter() - t0) * 1000, 2)
            status_code = 502
            reason = "Connection Failed"
            resp_body = f"[VulnForge Error: {str(e)}]"

        raw_resp = format_raw_response(status_code, reason, resp_headers, resp_body)
        if self.scan_id:
            try:
                log_request(self.scan_id, method.upper(), url, status_code, elapsed, module)
            except Exception:
                pass
        return HTTPResponseResult(status_code, resp_headers, resp_body, raw_req, raw_resp, elapsed, url, method.upper(), req_headers, body_str)
