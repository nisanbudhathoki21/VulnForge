from typing import Dict, Any, Tuple
from urllib.parse import urljoin
import requests

DEFAULT_UA = "VulnForge-MVP/0.1 (+https://example.edu/bca)"

def send_request(base_url: str, method: str, path: str, headers: Dict[str, str] | None = None, payload: str | None = None, timeout: int = 10) -> Tuple[int, Dict[str, str], str, float, str]:
    url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    h = {"User-Agent": DEFAULT_UA}
    if headers:
        h.update(headers)
    try:
        resp = requests.request(method=method.upper(), url=url, headers=h, data=payload, timeout=timeout, allow_redirects=True)
        status = resp.status_code
        # Normalize headers to plain dict[str, str]
        hdrs = {k: v for k, v in resp.headers.items()}
        text = resp.text if hasattr(resp, "text") else ""
        elapsed = resp.elapsed.total_seconds() if resp.elapsed else 0.0
        final_url = str(resp.url)
        return status, hdrs, text, elapsed, final_url
    except requests.RequestException as e:
        return 0, {}, f"REQUEST_ERROR: {e}", 0.0, url
