import difflib
import hashlib
from typing import Optional
from engine.requester import Requester, HTTPResponseResult

class TargetBaseline:
    def __init__(self, target_url: str):
        self.target_url = target_url.rstrip("/")
        self.root_response: Optional[HTTPResponseResult] = None
        self.nonexistent_response: Optional[HTTPResponseResult] = None
        self.is_soft_404: bool = False
        self.cdn_provider: str = ""
        self.nonexistent_body_len: int = 0

    async def profile(self, requester: Requester):
        self.root_response = await requester.send("GET", f"{self.target_url}/", module="baseline_root")
        h = {k.lower(): v for k, v in self.root_response.headers.items()}
        if "cf-ray" in h or "cloudflare" in h.get("server", "").lower():
            self.cdn_provider = "Cloudflare"
        canary = "vf_probe_soft404_canary_83910"
        self.nonexistent_response = await requester.send("GET", f"{self.target_url}/{canary}", module="baseline_404")
        self.nonexistent_body_len = len(self.nonexistent_response.body)
        if self.nonexistent_response.status_code == 200:
            self.is_soft_404 = True

    def is_similar_to_nonexistent(self, response: HTTPResponseResult) -> bool:
        if not self.nonexistent_response:
            return False
        if response.status_code == self.nonexistent_response.status_code and response.status_code == 200:
            if abs(len(response.body) - self.nonexistent_body_len) < 60:
                return True
            s = difflib.SequenceMatcher(None, response.body[:1500], self.nonexistent_response.body[:1500])
            if s.quick_ratio() > 0.85:
                return True
        return False
