"""
VulnForge Ultimate - High-Performance Web Spider & DOM Crawler
Recursively extracts endpoints from <a href>, <form action>, <script src>,
inline API routes, query parameters, and HTML forms.
"""

import re
import urllib.parse
from html.parser import HTMLParser
from typing import Set, List, Dict, Any
from engine.requester import Requester

STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".webp", ".bmp",
    ".css", ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".mp4", ".mp3", ".wav", ".avi", ".mov", ".webm"
)

class HTMLEndpointParser(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.links: Set[str] = set()
        self.forms: List[Dict[str, Any]] = []
        self._current_form: Dict[str, Any] = None

    def handle_starttag(self, tag: str, attrs: list):
        attr_dict = {k.lower(): v for k, v in attrs if v is not None}
        tag = tag.lower()

        # 1. Standard navigation links
        if tag in ["a", "link", "area"] and "href" in attr_dict:
            href = attr_dict["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urllib.parse.urljoin(self.base_url, href)
                self.links.add(full_url)

        # 2. Scripts and JavaScript bundles
        elif tag == "script" and "src" in attr_dict:
            src = attr_dict["src"].strip()
            if src:
                full_url = urllib.parse.urljoin(self.base_url, src)
                self.links.add(full_url)

        # 3. Forms (Actions and Methods)
        elif tag == "form":
            action = attr_dict.get("action", "").strip()
            method = attr_dict.get("method", "GET").upper()
            full_action = urllib.parse.urljoin(self.base_url, action) if action else self.base_url
            self._current_form = {
                "action": full_action,
                "method": method,
                "inputs": []
            }

        # 4. Form input fields & parameters
        elif tag in ["input", "textarea", "select"] and self._current_form is not None:
            name = attr_dict.get("name")
            val = attr_dict.get("value", "")
            inp_type = attr_dict.get("type", "text")
            if name:
                self._current_form["inputs"].append({
                    "name": name,
                    "type": inp_type,
                    "default_value": val
                })

    def handle_endtag(self, tag: str):
        if tag.lower() == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def extract_js_endpoints(js_text: str, base_url: str) -> Set[str]:
    """Extracts internal API routes and path literals from JavaScript bundles."""
    endpoints = set()
    pattern = r"""['"`](/(?:api|v[0-9]+|rest|graphql|user|auth|admin|oauth)[a-zA-Z0-9_\-\./\?=&]*)['"`]"""
    matches = re.findall(pattern, js_text)
    for m in matches:
        if len(m) > 2 and not m.endswith(STATIC_EXTENSIONS):
            full = urllib.parse.urljoin(base_url, m)
            endpoints.add(full)
    return endpoints


async def crawl_target(
    requester: Requester,
    start_url: str,
    max_pages: int = 30
) -> Dict[str, Any]:
    """
    Crawls target domain, discovers internal endpoints, parses forms,
    and extracts query parameters for fuzzing.
    """
    parsed_start = urllib.parse.urlsplit(start_url)
    target_host = parsed_start.netloc

    visited: Set[str] = set()
    to_visit: List[str] = [start_url]
    discovered_endpoints: Set[str] = {start_url}
    discovered_forms: List[Dict[str, Any]] = []
    discovered_params: Set[str] = set()

    if parsed_start.query:
        for qk in urllib.parse.parse_qs(parsed_start.query).keys():
            discovered_params.add(qk)

    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        clean_url = urllib.parse.urldefrag(current_url).url
        if clean_url in visited:
            continue

        visited.add(clean_url)
        res = await requester.send("GET", clean_url, module="crawler")
        content_type = res.headers.get("content-type", "").lower()

        # Parse HTML responses
        if res.status_code == 200 and "text/html" in content_type:
            parser = HTMLEndpointParser(clean_url)
            try:
                parser.feed(res.body)
                for link in parser.links:
                    parsed_link = urllib.parse.urlsplit(link)
                    if parsed_link.netloc == target_host and not parsed_link.path.lower().endswith(STATIC_EXTENSIONS):
                        clean_link = urllib.parse.urldefrag(link).url
                        discovered_endpoints.add(clean_link)
                        
                        if parsed_link.query:
                            for qk in urllib.parse.parse_qs(parsed_link.query).keys():
                                discovered_params.add(qk)
                                
                        if clean_link not in visited and clean_link not in to_visit:
                            to_visit.append(clean_link)

                for form in parser.forms:
                    discovered_forms.append(form)
                    for inp in form.get("inputs", []):
                        if inp.get("name"):
                            discovered_params.add(inp["name"])

            except Exception:
                pass

        # Parse JS scripts for hidden API endpoints
        elif res.status_code == 200 and ("javascript" in content_type or clean_url.endswith(".js")):
            js_routes = extract_js_endpoints(res.body, clean_url)
            for route in js_routes:
                parsed_route = urllib.parse.urlsplit(route)
                if parsed_route.netloc == target_host:
                    discovered_endpoints.add(route)

    return {
        "endpoints": list(discovered_endpoints),
        "forms": discovered_forms,
        "parameters": list(discovered_params),
        "total_crawled": len(visited)
    }
