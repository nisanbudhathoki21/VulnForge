from __future__ import annotations
import httpx, time
from typing import Any

class HttpClient:
    def __init__(self, timeout: float = 20.0):
        self._client = httpx.AsyncClient(
            timeout=timeout,
            verify=False,
            follow_redirects=True,
            headers={"User-Agent": "VulnForge-Research/1.0"}
        )

    async def request(self, method: str, url: str, **kwargs: Any):
        # Precise high-resolution timer
        start = time.perf_counter()
        resp = await self._client.request(method, url, **kwargs)
        # Store duration directly on the response object
        resp.vf_duration = time.perf_counter() - start
        return resp

    async def close(self) -> None:
        await self._client.aclose()
