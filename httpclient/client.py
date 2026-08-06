from __future__ import annotations
from typing import Dict, Optional, Any
import httpx, asyncio
class HttpClient:
    def __init__(self, timeout: float=10.0, rate_limit_per_host: int=8, proxies: Optional[Dict[str,str]]=None) -> None:
        limits = httpx.Limits(max_keepalive_connections=32, max_connections=128)
        self._client = httpx.AsyncClient(timeout=timeout, limits=limits, http2=True, proxies=proxies)
        self._sem: Dict[str, asyncio.Semaphore] = {}
        self._rate_limit_per_host = rate_limit_per_host
    async def _host_sem(self, host: str) -> asyncio.Semaphore:
        if host not in self._sem:
            self._sem[host] = asyncio.Semaphore(self._rate_limit_per_host)
        return self._sem[host]
    async def request(self, method: str, url: str, **kwargs: Any) -> httpx.Response:
        host = httpx.URL(url).host or "default"
        sem = await self._host_sem(host)
        async with sem:
            return await self._client.request(method, url, **kwargs)
    async def close(self) -> None:
        await self._client.aclose()
