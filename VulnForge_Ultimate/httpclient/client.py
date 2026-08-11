from __future__ import annotations
import httpx
import time
import random
import threading
from typing import Any, Optional

# Thread-safe httpx client with duration attrs compatibility

class HttpClient:
    """
    Fixed & Enhanced HttpClient
    - Supports both async and sync-style usage (via httpx.AsyncClient + sync wrapper optional)
    - Adds unified duration attrs: vulnforge_duration, vf_duration, duration
    - UA rotation
    - OOB / Interactsh placeholder
    - Keep-alive pooling (like nuclei)
    """

    def __init__(self, timeout: float = 20.0, headers: dict | None = None, proxy: str | None = None, random_ua: bool = True):
        self.timeout = timeout
        self._user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "VulnForge-Research/1.0",
        ]
        default_headers = {"User-Agent": random.choice(self._user_agents)} if random_ua else {"User-Agent": "VulnForge-Research/1.0"}
        if headers:
            default_headers.update(headers)

        client_kwargs = {
            "timeout": timeout,
            "verify": False,
            "follow_redirects": True,
            "headers": default_headers,
            "http2": True,
            "limits": httpx.Limits(max_keepalive_connections=20, max_connections=100),
        }
        if proxy:
            client_kwargs["proxy"] = proxy

        self._client = httpx.AsyncClient(**client_kwargs)
        self._sync_client = httpx.Client(**{**client_kwargs, "http2": False})  # sync fallback for scanner

    async def request(self, method: str, url: str, **kwargs: Any):
        start = time.perf_counter()
        resp = await self._client.request(method, url, **kwargs)
        elapsed = time.perf_counter() - start
        # Attach all compatible attrs
        resp.vf_duration = elapsed
        resp.vulnforge_duration = elapsed
        resp.vulnforge_elapsed = elapsed
        setattr(resp, "duration", elapsed)
        # Also store as custom for matcher/engine
        return resp

    def request_sync(self, method: str, url: str, **kwargs: Any):
        """
        Synchronous request for use in threaded scanner (avoid asyncio overhead)
        Still provides same duration attrs for compatibility
        """
        start = time.perf_counter()
        resp = self._sync_client.request(method, url, **kwargs)
        elapsed = time.perf_counter() - start
        resp.vf_duration = elapsed
        resp.vulnforge_duration = elapsed
        resp.vulnforge_elapsed = elapsed
        setattr(resp, "duration", elapsed)
        return resp

    async def close(self) -> None:
        try:
            await self._client.aclose()
        except Exception:
            pass
        try:
            self._sync_client.close()
        except Exception:
            pass

    def close_sync(self):
        try:
            self._sync_client.close()
        except Exception:
            pass

# Convenience sync wrapper for scanner if needed
class SyncHttpClient:
    def __init__(self, timeout: float = 20.0):
        self._client = httpx.Client(timeout=timeout, verify=False, follow_redirects=True, headers={"User-Agent": "VulnForge-Research/1.0"})
    
    def request(self, method: str, url: str, **kwargs):
        start=time.perf_counter()
        r=self._client.request(method, url, **kwargs)
        elapsed=time.perf_counter()-start
        r.vf_duration=elapsed
        r.vulnforge_duration=elapsed
        r.duration=elapsed
        return r
    
    def close(self):
        self._client.close()
