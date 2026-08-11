"""
Interactsh-like OOB helper - Competitive with nuclei's interactsh
Provides:
- Unique OOB domain generation
- Simple polling (stub, can integrate with actual interactsh server or dnslog)
- Placeholders for SSRF, XXE, Log4Shell etc.
For local labs, uses oob.vulnforge.com as dummy (like original). In production, point to your interactsh server.
"""
import random
import string
import time
import threading
from typing import Dict, List
import requests

class InteractshClient:
    def __init__(self, server_url: str = "https://oob.vulnforge.com", token: str = None, poll_interval: float = 2.0):
        self.server_url = server_url.rstrip("/")
        self.token = token or "".join(random.choices(string.ascii_letters+string.digits, k=20))
        self.poll_interval = poll_interval
        self._interactions: Dict[str, List[Dict]] = {}
        self._lock = threading.Lock()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "VulnForge-Interactsh/1.0"})

    def generate_url(self, subdomain_prefix: str = None) -> str:
        rand = "".join(random.choices(string.ascii_lowercase+string.digits, k=10))
        prefix = subdomain_prefix or rand
        # If using real interactsh server, format is <rand>.<token>.server
        # For placeholder, just <rand>.oob.vulnforge.com
        if "vulnforge.com" in self.server_url:
            return f"{prefix}.oob.vulnforge.com"
        return f"{prefix}.{self.token}.{self.server_url.replace('https://','').replace('http://','')}"

    def generate_payload(self, template: str = "http") -> str:
        url = self.generate_url()
        if template == "http":
            return f"http://{url}"
        if template == "dns":
            return url
        if template == "ldap":
            return f"ldap://{url}/a"
        return url

    def poll(self, correlation_id: str = None, timeout: float = 10.0) -> List[Dict]:
        # Stub polling - in real client would hit /poll endpoint
        # Here we simulate empty for local dev
        with self._lock:
            return self._interactions.get(correlation_id or "default", [])

    def register_interaction(self, correlation_id: str, interaction: Dict):
        with self._lock:
            self._interactions.setdefault(correlation_id, []).append(interaction)

    def close(self):
        try:
            self.session.close()
        except:
            pass

# Global singleton
_client = None
_client_lock = threading.Lock()

def get_interactsh_client() -> InteractshClient:
    global _client
    with _client_lock:
        if _client is None:
            _client = InteractshClient()
        return _client
