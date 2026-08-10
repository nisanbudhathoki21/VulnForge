import asyncio, re, time, hashlib
from dataclasses import dataclass, field
from collections import deque, defaultdict
from urllib.parse import urljoin, urlparse, urlunparse, parse_qsl, urlencode
import httpx
from aiolimiter import AsyncLimiter
from bs4 import BeautifulSoup
import tldextract

SAFE_WORDLIST = [
    "/.well-known/security.txt", "/.well-known/change-password",
    "/admin", "/administrator", "/login", "/signup", "/account", "/user",
    "/api", "/api/v1", "/graphql",
    "/dashboard", "/cp", "/manage",
    "/uploads", "/static", "/assets",
    "/.git/", "/.env", "/backup", "/old", "/test", "/staging"
]

DROP_PARAMS = re.compile(r"^(utm_|fbclid|gclid|ref$|_ga$)", re.I)

SEC_HEADER_MIN = [
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
    "permissions-policy"
]

def canonicalize(url: str) -> str:
    p = urlparse(url)
    scheme = p.scheme.lower()
    host = p.hostname.lower() if p.hostname else ""
    port = f":{p.port}" if p.port and not ((scheme == "http" and p.port == 80) or (scheme == "https" and p.port == 443)) else ""
    path = p.path or "/"
    # remove dot segments lightly
    path = re.sub(r"/{2,}", "/", path)
    # sort and filter params
    q = []
    for k, v in parse_qsl(p.query, keep_blank_values=False):
        if DROP_PARAMS.match(k): continue
        q.append((k, v))
    q = q[:3]
    query = urlencode(q, doseq=True)
    frag = ""  # ignore fragments
    return urlunparse((scheme, host + port, path, "", query, frag))

@dataclass
class Config:
    start_urls: list
    include_hosts: set
    allow_subdomains: bool = False
    max_depth: int = 2
    max_pages_per_host: int = 500
    max_pages_total: int = 1500
    time_budget_s: int = 900
    concurrency_per_host: int = 3
    rps_per_host: float = 2.0
    wordlist_probe: bool = True
    wordlist_rps: float = 0.5
    user_agent: str = "VulnForgePassive/1.0 (+contact: you@example.com)"
    timeout_connect: float = 10.0
    timeout_read: float = 20.0
    follow_sitemap: bool = True

@dataclass
class State:
    queued: deque = field(default_factory=deque)
    seen: set = field(default_factory=set)
    by_host_count: defaultdict = field(default_factory=lambda: defaultdict(int))
    findings: list = field(default_factory=list)
    start_time: float = field(default_factory=time.time)
    stop: bool = False

class VulnForgePassive:
    def init(self, cfg: Config):
        self.cfg = cfg
        self.state = State()
        self.limiters = {}
        self.clients = {}
def in_scope(self, url: str) -> bool:
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"): return False
        host = p.hostname or ""
        root = tldextract.extract(host)
        domain = f"{root.domain}.{root.suffix}" if root.suffix else host
        if self.cfg.allow_subdomains:
            return any(host == h or host.endswith(f".{h}") for h in self.cfg.include_hosts)
        return host in self.cfg.include_hosts or domain in self.cfg.include_hosts
    except Exception:
        return False

def host_key(self, url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.hostname or ''}"

async def get_client(self, host_key: str) -> httpx.AsyncClient:
    if host_key in self.clients: return self.clients[host_key]
    limits = httpx.Limits(max_connections=self.cfg.concurrency_per_host, max_keepalive_connections=self.cfg.concurrency_per_host)
    client = httpx.AsyncClient(
        http2=True,
        timeout=httpx.Timeout(self.cfg.timeout_read, connect=self.cfg.timeout_connect),
        headers={"User-Agent": self.cfg.user_agent, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"},
        limits=limits,
        follow_redirects=True,
        verify=True,
    )
    self.clients[host_key] = client
    return client

def get_limiter(self, host_key: str) -> AsyncLimiter:
    if host_key not in self.limiters:
        self.limiters[host_key] = AsyncLimiter(self.cfg.rps_per_host, time_period=1)
    return self.limiters[host_key]

async def head(self, url: str) -> httpx.Response | None:
    if not self.in_scope(url): return None
    hk = self.host_key(url)
    async with self.get_limiter(hk):
        client = await self.get_client(hk)
        try:
            return await client.head(url, headers={"User-Agent": self.cfg.user_agent})
        except Exception:
            return None

async def get(self, url: str) -> httpx.Response | None:
    if not self.in_scope(url): return None
    hk = self.host_key(url)
    async with self.get_limiter(hk):
        client = await self.get_client(hk)
        try:
            return await client.get(url)
        except Exception:
            return None

def enqueue(self, url: str, depth: int, reason: str):
    if self.state.stop: return
    if depth > self.cfg.max_depth: return
    cu = canonicalize(url)
    if not self.in_scope(cu): return
    if cu in self.state.seen:
        return
    host = urlparse(cu).hostname or ""
    if self.state.by_host_count[host] >= self.cfg.max_pages_per_host:
        return
    self.state.seen.add(cu)
    self.state.queued.append((cu, depth, reason))

def record(self, url: str, kind: str, detail: str):
    self.state.findings.append({"url": url, "type": kind, "detail": detail})

async def parse_robots_sitemaps(self, base: str):
    # robots.txt
    robots_url = urljoin(base, "/robots.txt")
    r = await self.get(robots_url)
    if r and r.status_code == 200 and "sitemap" in r.text.lower() and self.cfg.follow_sitemap:
        for line in r.text.splitlines():
            if line.lower().startswith("sitemap:"):
                sm = line.split(":", 1)[1].strip()
                self.enqueue(sm, 0, "sitemap_hint")
    # default sitemap
    if self.cfg.follow_sitemap:
        for sm in ["/sitemap.xml", "/sitemap_index.xml"]:
            self.enqueue(urljoin(base, sm), 0, "sitemap_guess")

def extract_links(self, base_url: str, html: str) -> set:
    out = set()
    soup = BeautifulSoup(html, "html.parser")
    for tag, attr in [("a", "href"), ("link", "href"), ("script", "src"), ("img", "src")]:
        for el in soup.find_all(tag):
            href = el.get(attr)
            if not href: continue
            absu = urljoin(base_url, href)
            out.add(absu)
    return out

def check_headers(self, url: str, r: httpx.Response):
    hs = {k.lower(): v for k, v in r.headers.items()}
    missing = [h for h in SEC_HEADER_MIN if h not in hs]
    if missing:
        self.record(url, "missing_security_headers", ", ".join(missing))
    server = hs.get("server", "")
    if server:
        self.record(url, "server_header_exposed", server)
    cc = hs.get("cache-control", "")
    if ("no-store" not in cc.lower()) and urlparse(url).path.startswith(("/login", "/account", "/user")):
        self.record(url, "weak_cache_control", cc or "none")
    if hs.get("access-control-allow-origin") == "*" and "credentials" in hs.get("access-control-allow-credentials", "").lower():
        self.record(url, "cors_misconfig_suspected", "ACAOrigin=* with credentials")

def check_cookies(self, url: str, r: httpx.Response):
    for c in r.cookies.jar:
        name = getattr(c, "name", "")
        secure = getattr(c, "secure", False)
        httponly = "httponly" in (getattr(c, "rest", {}) or {}).get("HttpOnly", "httponly").lower() or "httponly" in str(c).lower()
        samesite = (getattr(c, "rest", {}) or {}).get("SameSite", "") or ""
        if name and not secure and urlparse(url).scheme == "https":
            self.record(url, "cookie_missing_secure", name)
        if name and not httponly:
            self.record(url, "cookie_missing_httponly", name)
        if name and samesite.strip().lower() not in ("lax", "strict"):
            self.record(url, "cookie_samesite_none_or_missing", f"{name}={samesite or 'missing'}")

def detect_directory_listing(self, url: str, r: httpx.Response):
    if r.status_code == 200 and r.headers.get("content-type", "").startswith("text/html"):
        txt = r.text[:1000].lower()
        if "index of /" in txt or "directory listing for" in txt:
            self.record(url, "directory_listing_enabled", "html index detected")

def detect_tech(self, url: str, r: httpx.Response):
    # weak fingerprinting from headers for awareness
    hs = {k.lower(): v for k, v in r.headers.items()}
    for k in ["x-powered-by", "via", "x-aspnet-version"]:
        if k in hs:
            self.record(url, "tech_disclosure_header", f"{k}: {hs[k]}")

async def probe_wordlist(self, base: str):
    if not self.cfg.wordlist_probe: return
    host_key = self.host_key(base)
    wl_limiter = AsyncLimiter(self.cfg.wordlist_rps, time_period=1)
    base_root = f"{urlparse(base).scheme}://{urlparse(base).netloc}"
    async with (await self.get_client(host_key)):
        for path in SAFE_WORDLIST:
            url = base_root + path
            if not self.in_scope(url): continue
            async with wl_limiter:
                r = await self.head(url)
            if not r: continue
            if r.status_code in (200, 204):
                self.record(url, "interesting_path_accessible", f"status={r.status_code}")
            if r.status_code in (401, 403):
                self.record(url, "restricted_area_detected", f"status={r.status_code}")

async def crawl(self):
    # seed
    for u in self.cfg.start_urls:
        if self.in_scope(u): self.enqueue(u, 0, "seed")
    # per-host robots/sitemap and wordlist
    bases = set(self.host_key(u) for u in self.cfg.start_urls if self.in_scope(u))
    await asyncio.gather(*(self.parse_robots_sitemaps(b + "/") for b in bases))
    await asyncio.gather(*(self.probe_wordlist(b + "/") for b in bases))

    while self.state.queued and not self.state.stop:
        if (time.time() - self.state.start_time) > self.cfg.time_budget_s: break
        url, depth, reason = self.state.queued.popleft()
        host = urlparse(url).hostname or ""
        if self.state.by_host_count[host] >= self.cfg.max_pages_per_host: continue
        if len(self.state.seen) >= self.cfg.max_pages_total: break

        r = await self.get(url)
        if not r: continue
        self.state.by_host_count[host] += 1

        self.check_headers(url, r)
        self.check_cookies(url, r)
        self.detect_directory_listing(url, r)
        self.detect_tech(url, r)

        ctype = r.headers.get("content-type", "").lower()
        if "xml" in ctype and "sitemap" in (url.lower() + ctype):
            # parse basic sitemap URLs
            for m in re.findall(r">\s*(https?://[^<\s]+)\s*<", r.text):
                self.enqueue(m, depth + 1, "sitemap_url")
        elif "text/html" in ctype:
            for link in self.extract_links(url, r.text):
                self.enqueue(link, depth + 1, "html_link")

    # close clients
    await asyncio.gather(*(c.aclose() for c in self.clients.values()))
    return self.state.findings
async def main():
    target = "https://example.com/"
    cfg = Config(
        start_urls=[target],
        include_hosts={urlparse(target).hostname or "example.com"},
        allow_subdomains=False,
        max_depth=2,
        max_pages_per_host=400,
        time_budget_s=900,
        wordlist_probe=True
    )
    vf = VulnForgePassive(cfg)
    findings = await vf.crawl()
    # minimal output
    for f in findings:
        print(f"[{f['type']}] {f['url']} :: {f['detail']}")

if name == "main":
asyncio.run(main())
