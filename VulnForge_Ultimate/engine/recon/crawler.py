from collections import deque
from urllib.parse import urlparse

import requests

from .models import Endpoint
from .parser import (
    extract_forms,
    extract_links,
    extract_query_parameters,
)
from .scope import ScopeManager


class ReconCrawler:
    """
    VulnForge web reconnaissance crawler.

    Responsibilities:
    - Crawl pages within the configured scope
    - Discover links
    - Discover HTML forms
    - Extract query parameters
    - Track crawl depth
    - Deduplicate endpoints
    - Respect page/depth limits
    - Report request errors
    """

    def __init__(
        self,
        target,
        max_depth=2,
        max_pages=100,
        timeout=10,
        user_agent="VulnForge/1.0",
    ):
        self.target = target.rstrip("/")
        self.max_depth = max_depth
        self.max_pages = max_pages
        self.timeout = timeout

        self.scope = ScopeManager(target)

        self.session = requests.Session()

        self.session.headers.update(
            {
                "User-Agent": user_agent,
                "Accept": (
                    "text/html,application/xhtml+xml,"
                    "application/xml;q=0.9,*/*;q=0.8"
                ),
            }
        )

        # URLs that have already been requested.
        self.visited = set()

        # Raw endpoints discovered during crawling.
        self.endpoints = []

        # Basic statistics useful for the dashboard later.
        self.stats = {
            "requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "pages": 0,
            "links": 0,
            "forms": 0,
        }

    def _same_origin(self, url):
        """
        Keep crawling on the same hostname.

        ScopeManager provides the actual scope decision.
        This additional origin check prevents the crawler from
        accidentally following external links.
        """

        try:
            target_host = urlparse(self.target).hostname
            url_host = urlparse(url).hostname

            if not target_host or not url_host:
                return False

            return target_host.lower() == url_host.lower()

        except Exception:
            return False

    def _add_endpoint(
        self,
        url,
        method="GET",
        parameters=None,
        source="crawler",
        depth=0,
        content_type=None,
    ):
        """
        Add an endpoint to the collection.

        Deduplication is based on:
        method + URL + parameter names
        """

        if parameters is None:
            parameters = []

        parameters = sorted(set(parameters))

        endpoint = Endpoint(
            url=url,
            method=method.upper(),
            parameters=parameters,
            source=source,
            depth=depth,
            content_type=content_type,
        )

        self.endpoints.append(endpoint)

    def _deduplicate_endpoints(self):
        """
        Remove duplicate endpoint definitions.
        """

        unique = {}

        for endpoint in self.endpoints:
            key = (
                endpoint.method.upper(),
                endpoint.url,
                tuple(sorted(endpoint.parameters)),
            )

            if key not in unique:
                unique[key] = endpoint

        return list(unique.values())

    def _fetch(self, url):
        """
        Fetch a URL and return the response.

        Errors are reported instead of being silently ignored.
        """

        try:
            self.stats["requests"] += 1

            response = self.session.get(
                url,
                timeout=self.timeout,
                allow_redirects=True,
            )

            self.stats["successful_requests"] += 1

            return response

        except requests.RequestException as exc:
            self.stats["failed_requests"] += 1

            print(
                f"[RECON ERROR] "
                f"{url} -> {exc}"
            )

            return None

    def crawl(self):
        """
        Start crawling from the configured target.

        Returns:
            list[Endpoint]: deduplicated discovered endpoints.
        """

        queue = deque()

        queue.append(
            (
                self.target,
                0,
            )
        )

        while queue:

            if len(self.visited) >= self.max_pages:
                break

            url, depth = queue.popleft()

            # Already requested.
            if url in self.visited:
                continue

            # Scope protection.
            if not self.scope.in_scope(url):
                continue

            # Same-origin protection.
            if not self._same_origin(url):
                continue

            self.visited.add(url)

            print(
                f"[RECON] "
                f"GET {url} "
                f"(depth={depth})"
            )

            response = self._fetch(url)

            if response is None:
                continue

            self.stats["pages"] += 1

            final_url = response.url

            # Record the page itself.
            self._add_endpoint(
                url=final_url,
                method="GET",
                parameters=extract_query_parameters(
                    final_url
                ),
                source="crawler",
                depth=depth,
                content_type=response.headers.get(
                    "Content-Type"
                ),
            )

            content_type = response.headers.get(
                "Content-Type",
                "",
            ).lower()

            # We only parse HTML documents.
            if "text/html" not in content_type:
                continue

            html = response.text

            # -------------------------------------------------
            # LINK DISCOVERY
            # -------------------------------------------------

            try:
                links = extract_links(
                    final_url,
                    html,
                )
            except Exception as exc:
                print(
                    f"[RECON PARSER] "
                    f"Link extraction failed for "
                    f"{final_url}: {exc}"
                )
                links = set()

            for link in links:

                if not self.scope.in_scope(link):
                    continue

                if not self._same_origin(link):
                    continue

                self.stats["links"] += 1

                if link not in self.visited:
                    queue.append(
                        (
                            link,
                            depth + 1,
                        )
                    )

            # -------------------------------------------------
            # FORM DISCOVERY
            # -------------------------------------------------

            try:
                forms = extract_forms(
                    final_url,
                    html,
                )
            except Exception as exc:
                print(
                    f"[RECON PARSER] "
                    f"Form extraction failed for "
                    f"{final_url}: {exc}"
                )
                forms = []

            for form in forms:

                form_url = form.get("url")

                if not form_url:
                    continue

                if not self.scope.in_scope(form_url):
                    continue

                if not self._same_origin(form_url):
                    continue

                method = (
                    form.get("method")
                    or "GET"
                ).upper()

                parameters = form.get(
                    "parameters",
                    [],
                )

                self.stats["forms"] += 1

                self._add_endpoint(
                    url=form_url,
                    method=method,
                    parameters=parameters,
                    source="form",
                    depth=depth,
                    content_type=content_type,
                )

            # -------------------------------------------------
            # DEPTH LIMIT
            # -------------------------------------------------

            if depth >= self.max_depth:
                continue

        # Remove duplicate endpoints before returning.
        self.endpoints = self._deduplicate_endpoints()

        return self.endpoints

    def get_stats(self):
        """
        Return a copy of crawler statistics.
        """

        return dict(self.stats)

    def get_visited_urls(self):
        """
        Return URLs that were actually requested.
        """

        return sorted(self.visited)
