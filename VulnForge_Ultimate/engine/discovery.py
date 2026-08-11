"""
VulnForge Web Discovery Engine

Designed for authorized security testing.

Features:
- Same-origin crawling
- HTML link discovery
- Form discovery
- Query parameter discovery
- JavaScript URL discovery
- robots.txt
- sitemap.xml
- API endpoint identification
- Scope enforcement
- Depth and URL limits
- Response-size limits
- Rate limiting
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
from typing import Optional
from urllib.parse import (
    parse_qsl,
    urlencode,
    urljoin,
    urlparse,
    urlunparse,
)


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    source: str = "crawler"
    depth: int = 0
    parameters: tuple = ()
    is_api: bool = False
    content_type: str = ""

    def as_dict(self):
        data = asdict(self)
        data["parameters"] = list(self.parameters)
        return data


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__(
            convert_charrefs=True
        )

        self.links = []
        self.forms = []
        self.scripts = []

        self._form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)

        tag = tag.lower()

        if tag == "a":
            href = attrs.get("href")

            if href:
                self.links.append(href)

        elif tag == "script":
            src = attrs.get("src")

            if src:
                self.scripts.append(src)

        elif tag == "form":
            self._form = {
                "action": attrs.get("action", ""),
                "method": attrs.get(
                    "method",
                    "GET",
                ).upper(),
                "inputs": [],
            }

        elif self._form is not None and tag in (
            "input",
            "textarea",
            "select",
        ):
            name = attrs.get("name")

            if name:
                self._form["inputs"].append(
                    name
                )

    def handle_endtag(self, tag):
        if (
            tag.lower() == "form"
            and self._form is not None
        ):
            self.forms.append(
                self._form
            )

            self._form = None


class DiscoveryEngine:
    def __init__(
        self,
        session,
        base_url,
        max_depth=2,
        max_urls=200,
        timeout=10,
        delay=0.25,
        max_body_size=2_000_000,
        quiet=False,
    ):
        self.session = session

        parsed = urlparse(
            base_url
        )

        self.scheme = parsed.scheme.lower()
        self.host = parsed.hostname.lower()

        self.base_url = (
            f"{self.scheme}://"
            f"{parsed.netloc}"
        )

        self.max_depth = max_depth
        self.max_urls = max_urls
        self.timeout = timeout
        self.delay = max(
            0,
            delay,
        )
        self.max_body_size = (
            max_body_size
        )
        self.quiet = quiet

        self.queue = deque()
        self.visited = set()
        self.endpoints = {}

        self.requests = 0
        self.errors = 0

    # --------------------------------------------------
    # SCOPE
    # --------------------------------------------------

    def in_scope(self, url):
        try:
            parsed = urlparse(url)

            if parsed.scheme not in (
                "http",
                "https",
            ):
                return False

            hostname = (
                parsed.hostname or ""
            ).lower()

            return hostname == self.host

        except Exception:
            return False

    # --------------------------------------------------
    # NORMALIZATION
    # --------------------------------------------------

    def normalize_url(self, url):
        try:
            parsed = urlparse(url)

            if not parsed.scheme:
                return None

            if not self.in_scope(url):
                return None

            path = parsed.path or "/"

            query_pairs = parse_qsl(
                parsed.query,
                keep_blank_values=True,
            )

            query_pairs.sort()

            query = urlencode(
                query_pairs,
                doseq=True,
            )

            normalized = urlunparse(
                (
                    parsed.scheme.lower(),
                    parsed.netloc.lower(),
                    path,
                    "",
                    query,
                    "",
                )
            )

            return normalized.rstrip("#")

        except Exception:
            return None

    # --------------------------------------------------
    # ADD ENDPOINT
    # --------------------------------------------------

    def add_endpoint(
        self,
        url,
        method="GET",
        source="crawler",
        depth=0,
        parameters=None,
        content_type="",
    ):
        normalized = self.normalize_url(
            url
        )

        if not normalized:
            return

        parsed = urlparse(
            normalized
        )

        params = sorted(
            {
                name
                for name, _ in parse_qsl(
                    parsed.query,
                    keep_blank_values=True,
                )
            }
        )

        if parameters:
            params.extend(
                parameters
            )

        params = tuple(
            sorted(set(params))
        )

        api = (
            parsed.path.startswith(
                "/api/"
            )
            or "/api/" in parsed.path
            or parsed.path.startswith(
                "/graphql"
            )
            or parsed.path.endswith(
                ".json"
            )
        )

        key = (
            method.upper(),
            normalized,
        )

        if key not in self.endpoints:
            self.endpoints[key] = Endpoint(
                url=normalized,
                method=method.upper(),
                source=source,
                depth=depth,
                parameters=params,
                is_api=api,
                content_type=content_type,
            )

    # --------------------------------------------------
    # JAVASCRIPT EXTRACTION
    # --------------------------------------------------

    def extract_js_urls(
        self,
        body,
    ):
        results = set()

        patterns = [
            r"""["']((?:/|\./|\.\./)[^"'<> ]+)["']""",
            r"""fetch\(\s*["']([^"']+)["']""",
            r"""axios\.[a-z]+\(\s*["']([^"']+)["']""",
            r"""url\s*:\s*["']([^"']+)["']""",
            r"""endpoint\s*:\s*["']([^"']+)["']""",
        ]

        for pattern in patterns:
            try:
                matches = re.findall(
                    pattern,
                    body,
                    flags=re.I,
                )

                results.update(
                    matches
                )

            except re.error:
                continue

        return results

    # --------------------------------------------------
    # FETCH
    # --------------------------------------------------

    def fetch(self, url):
        if self.delay:
            time.sleep(
                self.delay
            )

        try:
            self.requests += 1

            response = (
                self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=True,
                    stream=True,
                )
            )

            chunks = []
            size = 0

            for chunk in response.iter_content(
                chunk_size=16384
            ):
                if not chunk:
                    continue

                size += len(chunk)

                if size > self.max_body_size:
                    break

                chunks.append(chunk)

            raw = b"".join(
                chunks
            )

            encoding = (
                response.encoding
                or "utf-8"
            )

            body = raw.decode(
                encoding,
                errors="replace",
            )

            return response, body

        except Exception as exc:
            self.errors += 1

            if not self.quiet:
                print(
                    f"[DISCOVERY ERROR] "
                    f"{url}: {exc}"
                )

            return None, ""

    # --------------------------------------------------
    # HTML
    # --------------------------------------------------

    def process_html(
        self,
        url,
        body,
        depth,
    ):
        parser = PageParser()

        try:
            parser.feed(
                body
            )
        except Exception:
            return

        for href in parser.links:
            absolute = urljoin(
                url,
                href,
            )

            if self.in_scope(
                absolute
            ):
                self.add_endpoint(
                    absolute,
                    source="html",
                    depth=depth,
                )

                if depth < self.max_depth:
                    normalized = (
                        self.normalize_url(
                            absolute
                        )
                    )

                    if normalized:
                        self.queue.append(
                            (
                                normalized,
                                depth + 1,
                            )
                        )

        for form in parser.forms:
            action = form.get(
                "action"
            ) or url

            absolute = urljoin(
                url,
                action,
            )

            self.add_endpoint(
                absolute,
                method=form.get(
                    "method",
                    "GET",
                ),
                source="form",
                depth=depth,
                parameters=form.get(
                    "inputs",
                    [],
                ),
            )

        for script in parser.scripts:
            absolute = urljoin(
                url,
                script,
            )

            if not self.in_scope(
                absolute
            ):
                continue

            self.add_endpoint(
                absolute,
                source="javascript",
                depth=depth,
            )

            script_response, script_body = (
                self.fetch(
                    absolute
                )
            )

            if not script_response:
                continue

            for discovered in (
                self.extract_js_urls(
                    script_body
                )
            ):
                endpoint = urljoin(
                    absolute,
                    discovered,
                )

                if self.in_scope(
                    endpoint
                ):
                    self.add_endpoint(
                        endpoint,
                        source="javascript",
                        depth=depth,
                    )

                    if depth < self.max_depth:
                        normalized = (
                            self.normalize_url(
                                endpoint
                            )
                        )

                        if normalized:
                            self.queue.append(
                                (
                                    normalized,
                                    depth + 1,
                                )
                            )

    # --------------------------------------------------
    # ROBOTS
    # --------------------------------------------------

    def discover_robots(self):
        url = (
            self.base_url
            + "/robots.txt"
        )

        response, body = self.fetch(
            url
        )

        if not response:
            return

        for line in body.splitlines():
            line = line.strip()

            if not line.lower().startswith(
                "disallow:"
            ):
                continue

            path = line.split(
                ":",
                1,
            )[1].strip()

            if not path:
                continue

            endpoint = urljoin(
                self.base_url,
                path,
            )

            self.add_endpoint(
                endpoint,
                source="robots",
            )

    # --------------------------------------------------
    # SITEMAP
    # --------------------------------------------------

    def discover_sitemap(self):
        url = (
            self.base_url
            + "/sitemap.xml"
        )

        response, body = self.fetch(
            url
        )

        if not response:
            return

        locations = re.findall(
            r"<loc>\s*(.*?)\s*</loc>",
            body,
            flags=re.I,
        )

        for location in locations:
            location = location.strip()

            if self.in_scope(
                location
            ):
                self.add_endpoint(
                    location,
                    source="sitemap",
                )

                if len(
                    self.endpoints
                ) >= self.max_urls:
                    break

    # --------------------------------------------------
    # RUN
    # --------------------------------------------------

    def run(self):
        self.add_endpoint(
            self.base_url,
            source="seed",
            depth=0,
        )

        self.queue.append(
            (
                self.base_url,
                0,
            )
        )

        self.discover_robots()

        if len(
            self.endpoints
        ) < self.max_urls:
            self.discover_sitemap()

        while (
            self.queue
            and len(
                self.visited
            )
            < self.max_urls
        ):
            url, depth = (
                self.queue.popleft()
            )

            if url in self.visited:
                continue

            if not self.in_scope(
                url
            ):
                continue

            self.visited.add(
                url
            )

            if not self.quiet:
                print(
                    "[DISCOVER]",
                    url,
                )

            response, body = (
                self.fetch(
                    url
                )
            )

            if not response:
                continue

            content_type = (
                response.headers.get(
                    "Content-Type",
                    "",
                )
            )

            self.add_endpoint(
                url,
                source="crawler",
                depth=depth,
                content_type=content_type,
            )

            if (
                "text/html"
                in content_type.lower()
            ):
                self.process_html(
                    url,
                    body,
                    depth,
                )

            if len(
                self.endpoints
            ) >= self.max_urls:
                break

        return {
            "endpoints": [
                endpoint.as_dict()
                for endpoint
                in self.endpoints.values()
            ],
            "visited": len(
                self.visited
            ),
            "requests": self.requests,
            "errors": self.errors,
        }
