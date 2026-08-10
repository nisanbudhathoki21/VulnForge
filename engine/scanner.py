#!/usr/bin/env python3
"""
VulnForge Scanner Engine

Features:
- YAML template loading
- TemplateRuntime integration
- Variable/filter rendering
- Recursive rendering of strings/lists/dicts
- HTTP request execution
- Matchers
- Extractors
- Authentication helpers
- Proxy support
- Rate limiting / delay / jitter
- Response decoding
- Evidence collection
- Optional exploitation
- Concurrent template execution

The scanner delegates template expression rendering to
engine.template_runtime.TemplateRuntime.
"""

import os
import re
import yaml
import json
import time
import requests
import traceback
import zlib
import random
import string
import itertools

from urllib.parse import urljoin, urlparse
from datetime import datetime
from typing import Any, Dict, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from engine.template_runtime import TemplateRuntime


# ==============================================================
# OPTIONAL DEPENDENCIES
# ==============================================================

try:
    import brotli
except ImportError:
    brotli = None

try:
    import jsonpath_ng
except ImportError:
    jsonpath_ng = None


# ==============================================================
# WAF / PROXY HELPER
# ==============================================================

class WAFBypass:
    def __init__(self, proxy_file=None, user_agent_list=None):
        self.proxies = []

        self.user_agents = user_agent_list or [
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (X11; Linux x86_64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) "
                "Gecko/20100101 Firefox/119.0"
            ),
            (
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) "
                "AppleWebKit/605.1.15 (KHTML, like Gecko) "
                "Version/17.0 Mobile/15E148 Safari/604.1"
            ),
        ]

        self.current_index = 0

        if proxy_file and os.path.isfile(proxy_file):
            try:
                with open(proxy_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()

                        if not line or line.startswith("#"):
                            continue

                        parts = line.split()

                        proxy_url = parts[0]
                        country = (
                            parts[1]
                            if len(parts) > 1
                            else "XX"
                        )

                        self.proxies.append(
                            (proxy_url, country)
                        )
            except OSError:
                pass

    def get_proxy(self, preferred_country=None):
        if not self.proxies:
            return None

        if preferred_country:
            country_proxies = [
                proxy
                for proxy in self.proxies
                if proxy[1].upper()
                == preferred_country.upper()
            ]

            if country_proxies:
                proxy_url = random.choice(
                    country_proxies
                )[0]

                return {
                    "http": proxy_url,
                    "https": proxy_url,
                }

        self.current_index = (
            self.current_index + 1
        ) % len(self.proxies)

        proxy_url = self.proxies[
            self.current_index
        ][0]

        return {
            "http": proxy_url,
            "https": proxy_url,
        }

    def get_headers(self):
        fake_ip = (
            f"{random.randint(1, 255)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(1, 255)}"
        )

        return {
            "Accept": (
                "text/html,application/xhtml+xml,"
                "application/xml;q=0.9,*/*;q=0.8"
            ),
            "Accept-Language": random.choice(
                [
                    "en-US,en;q=0.9",
                    "en-GB,en;q=0.8",
                    "fr-FR,fr;q=0.9",
                ]
            ),
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",

            # Kept for compatibility with the original engine.
            "X-Forwarded-For": fake_ip,
            "X-Real-IP": fake_ip,
            "X-Originating-IP": fake_ip,
            "CF-Connecting-IP": fake_ip,
            "True-Client-IP": fake_ip,
        }

    def get_user_agent(self):
        return random.choice(self.user_agents)

    def get_delay(self, base_delay, jitter=0.5):
        if base_delay <= 0:
            return 0

        return (
            base_delay
            + random.uniform(0, max(0, jitter))
        )


# ==============================================================
# AUTHENTICATION
# ==============================================================

class AuthManager:
    def __init__(
        self,
        session,
        base_url,
        quiet=False,
    ):
        self.session = session
        self.base_url = base_url
        self.quiet = quiet
        self.authenticated = False

        self.auth_data = {
            "jwt": None,
            "cookies": {},
            "headers": {},
            "username": None,
            "password": None,
            "user_id": None,
        }

        parsed = urlparse(self.base_url)

        self.domain = parsed.netloc

        if self.domain.startswith("www."):
            self.domain = self.domain[4:]

    def generate_email(self, prefix="scanner"):
        rand = "".join(
            random.choices(
                string.ascii_lowercase
                + string.digits,
                k=6,
            )
        )

        return (
            f"{prefix}_{rand}@{self.domain}"
        )

    def generate_password(
        self,
        base="VulnForge2024!",
    ):
        if "." in self.domain:
            domain_part = self.domain.split(".")[0]
        else:
            domain_part = self.domain

        return (
            f"{base}"
            f"{domain_part.capitalize()}"
            f"{random.randint(10, 99)}!"
        )

    def register(
        self,
        email=None,
        password=None,
    ):
        if not email:
            email = self.generate_email()

        if not password:
            password = self.generate_password()

        endpoints = [
            "/api/Users",
            "/api/users",
            "/register",
            "/signup",
            "/auth/register",
            "/rest/register",
            "/json/register",
        ]

        for endpoint in endpoints:
            url = urljoin(
                self.base_url,
                endpoint,
            )

            data = {
                "email": email,
                "password": password,
                "passwordRepeat": password,
            }

            try:
                response = self.session.post(
                    url,
                    json=data,
                    timeout=10,
                )

                if response.status_code in (
                    200,
                    201,
                ):
                    self.auth_data["username"] = email
                    self.auth_data["password"] = password
                    return True

                response = self.session.post(
                    url,
                    data=data,
                    timeout=10,
                )

                if response.status_code in (
                    200,
                    201,
                    302,
                ):
                    self.auth_data["username"] = email
                    self.auth_data["password"] = password
                    return True

            except requests.RequestException:
                continue

        return False

    def login(
        self,
        username=None,
        password=None,
    ):
        if username is None:
            username = self.auth_data.get(
                "username"
            )

        if password is None:
            password = self.auth_data.get(
                "password"
            )

        if not username or not password:
            return False

        endpoints = [
            "/rest/user/login",
            "/api/login",
            "/auth/login",
            "/login",
            "/signin",
            "/json/login",
        ]

        for endpoint in endpoints:
            url = urljoin(
                self.base_url,
                endpoint,
            )

            try:
                response = self.session.post(
                    url,
                    json={
                        "email": username,
                        "password": password,
                    },
                    timeout=10,
                )

                if response.status_code == 200:
                    try:
                        data = response.json()

                        if isinstance(data, dict):
                            if "token" in data:
                                token = data["token"]

                                self.auth_data["jwt"] = token

                                self.session.headers[
                                    "Authorization"
                                ] = f"Bearer {token}"

                                self.auth_data[
                                    "headers"
                                ]["Authorization"] = (
                                    f"Bearer {token}"
                                )

                                self.authenticated = True

                                return True

                            authentication = data.get(
                                "authentication"
                            )

                            if (
                                isinstance(
                                    authentication,
                                    dict,
                                )
                                and "token"
                                in authentication
                            ):
                                token = authentication[
                                    "token"
                                ]

                                self.auth_data[
                                    "jwt"
                                ] = token

                                self.session.headers[
                                    "Authorization"
                                ] = f"Bearer {token}"

                                self.auth_data[
                                    "headers"
                                ]["Authorization"] = (
                                    f"Bearer {token}"
                                )

                                self.authenticated = True

                                return True

                    except (
                        ValueError,
                        requests.RequestException,
                    ):
                        pass

                response = self.session.post(
                    url,
                    data={
                        "username": username,
                        "password": password,
                    },
                    timeout=10,
                )

                if response.status_code in (
                    200,
                    302,
                ):
                    if self.session.cookies.get_dict():
                        self.authenticated = True

                        self.auth_data[
                            "cookies"
                        ] = self.session.cookies.get_dict()

                        return True

            except requests.RequestException:
                continue

        return False

    def authenticate(
        self,
        username=None,
        password=None,
    ):
        if not username:
            if self.register():
                return self.login()

        self.auth_data["username"] = username
        self.auth_data["password"] = password

        return self.login()


# ==============================================================
# SCANNER
# ==============================================================

class Scanner:
    def __init__(
        self,
        url,
        quiet=False,
        template_dir="templates/",
        max_workers=10,
        proxy_file=None,
        country=None,
        rate_limit=0,
        delay=2,
        jitter=0.5,
        exploit=False,
        username=None,
        password=None,
        timeout=10,
        skip_priv=False,
        skip_auth=False,
    ):
        self.raw_url = url.rstrip("/")

        if not self.raw_url.startswith(
            ("http://", "https://")
        ):
            self.raw_url = (
                "https://" + self.raw_url
            )

        parsed = urlparse(self.raw_url)

        self.base_url = (
            f"{parsed.scheme}://{parsed.netloc}"
        )

        self.quiet = quiet
        self.template_dir = template_dir
        self.max_workers = max_workers
        self.proxy_file = proxy_file
        self.preferred_country = country
        self.rate_limit = rate_limit
        self.base_delay = delay
        self.jitter = jitter
        self.exploit_enabled = exploit
        self.timeout = timeout
        self.skip_priv = skip_priv
        self.skip_auth = skip_auth

        self.last_request_time = 0

        self.waf = WAFBypass(
            proxy_file=self.proxy_file
        )

        self.session = self._get_session()

        self.auth = AuthManager(
            self.session,
            self.base_url,
            self.quiet,
        )

        self.username = username
        self.password = password

        self.context = {
            "BaseURL": self.base_url,
            "interactsh-url": "oob.vulnforge.com",
        }

        self.templates = []
        self.findings = []

        self.scan_id = datetime.now().strftime(
            "%Y%m%d_%H%M%S_%f"
        )[:-3]

        self.block_patterns = [
            "cf-challenge",
            "one moment, please",
            "checking your browser",
            "captcha",
            "cloudflare",
            "ddos protection",
            "please wait",
            "access denied",
            "cf-ray",
            "shutdown",
            "site is down",
            "offline",
            "maintenance mode",
            "under maintenance",
        ]

    # ==========================================================
    # SESSION
    # ==========================================================

    def _get_session(self):
        session = requests.Session()

        session.headers.update(
            self.waf.get_headers()
        )

        session.headers[
            "User-Agent"
        ] = self.waf.get_user_agent()

        proxy = self.waf.get_proxy(
            self.preferred_country
        )

        if proxy:
            session.proxies = proxy

        return session

    # ==========================================================
    # THROTTLING
    # ==========================================================

    def _throttle(self, retry=False):
        if self.rate_limit > 0:
            interval = (
                1.0 / self.rate_limit
            )

            elapsed = (
                time.time()
                - self.last_request_time
            )

            if elapsed < interval:
                sleep_time = (
                    interval - elapsed
                )

                if retry:
                    sleep_time *= 2

                time.sleep(sleep_time)

        if self.base_delay > 0:
            delay = self.waf.get_delay(
                self.base_delay,
                self.jitter,
            )

            time.sleep(delay)

        self.last_request_time = time.time()

    # ==========================================================
    # RESPONSE DECODER
    # ==========================================================

    def _decode_response_body(self, response):
        content_encoding = (
            response.headers
            .get(
                "Content-Encoding",
                "",
            )
            .lower()
        )

        raw_content = response.content

        if (
            content_encoding == "br"
            and brotli is not None
        ):
            try:
                raw_content = brotli.decompress(
                    raw_content
                )
            except Exception:
                pass

        elif content_encoding in (
            "gzip",
            "deflate",
        ):
            try:
                if content_encoding == "gzip":
                    raw_content = zlib.decompress(
                        raw_content,
                        16 + zlib.MAX_WBITS,
                    )
                else:
                    raw_content = zlib.decompress(
                        raw_content
                    )
            except Exception:
                pass

        try:
            return raw_content.decode(
                "utf-8"
            )
        except UnicodeDecodeError:
            try:
                return raw_content.decode(
                    "latin-1"
                )
            except Exception:
                return raw_content.decode(
                    "utf-8",
                    errors="ignore",
                )

    # ==========================================================
    # TEMPLATE LOADING
    # ==========================================================

    def load_templates(self):
        self.templates = []

        if os.path.isfile(
            self.template_dir
        ):
            self._load_template_file(
                self.template_dir
            )
            return

        if not os.path.isdir(
            self.template_dir
        ):
            return

        for root, _, files in os.walk(
            self.template_dir
        ):
            for filename in sorted(files):
                if filename.endswith(
                    (".yaml", ".yml")
                ):
                    path = os.path.join(
                        root,
                        filename,
                    )

                    self._load_template_file(
                        path
                    )

    def _load_template_file(self, path):
        try:
            with open(
                path,
                "r",
                encoding="utf-8",
            ) as file:
                data = yaml.safe_load(file)

            if not isinstance(data, dict):
                return

            if "id" not in data:
                return

            if (
                "requests" not in data
                or not isinstance(
                    data["requests"],
                    list,
                )
            ):
                return

            data["_file"] = path

            self.templates.append(data)

            if not self.quiet:
                print(
                    f"[LOADING] {path} -> "
                    f"{data.get('id', 'unknown')}"
                )

        except Exception:
            if not self.quiet:
                print(
                    f"[WARN] Failed to load template: "
                    f"{path}"
                )

    # ==========================================================
    # CONTEXT
    # ==========================================================

    def _build_context(
        self,
        extra_context=None,
    ):
        """
        Build the complete template context.

        Priority:

        scanner context
            <
        authentication context
            <
        request-specific context
        """

        context = {}

        if isinstance(
            self.context,
            dict,
        ):
            context.update(
                self.context
            )

        try:
            auth_data = self.auth.auth_data

            if isinstance(
                auth_data,
                dict,
            ):
                context.update(
                    auth_data
                )

        except Exception:
            pass

        if isinstance(
            extra_context,
            dict,
        ):
            context.update(
                extra_context
            )

        return context

    # ==========================================================
    # TEMPLATE RUNTIME BRIDGE
    # ==========================================================

    def _substitute(
        self,
        value,
        extra_context=None,
    ):
        """
        Render a template value through TemplateRuntime.

        Supported examples:

            {{own_id}}

            {{own_id|int}}

            {{own_id|int+1}}

            {{own_id|int-1}}

            {{own_id|str}}

            {{own_id|hex}}

            {{own_id|base64}}

        Rendering is recursive for:

            strings
            lists
            dictionaries
        """

        context = self._build_context(
            extra_context
        )

        runtime = TemplateRuntime()

        runtime.set_variables(
            context
        )

        # ------------------------------------------------------
        # STRING
        # ------------------------------------------------------

        if isinstance(
            value,
            str,
        ):
            try:
                return runtime.render(
                    value
                )
            except Exception:
                # Template errors should not crash
                # the entire scan.
                return value

        # ------------------------------------------------------
        # LIST
        # ------------------------------------------------------

        if isinstance(
            value,
            list,
        ):
            return [
                self._substitute(
                    item,
                    context,
                )
                for item in value
            ]

        # ------------------------------------------------------
        # DICTIONARY
        # ------------------------------------------------------

        if isinstance(
            value,
            dict,
        ):
            return {
                key: self._substitute(
                    item,
                    context,
                )
                for key, item in value.items()
            }

        # ------------------------------------------------------
        # OTHER TYPES
        # ------------------------------------------------------

        return value

    # ==========================================================
    # HTTP REQUEST
    # ==========================================================

    def _make_request(
        self,
        method,
        url,
        headers,
        body,
        stage,
        retries=3,
    ):
        for attempt in range(
            retries + 1
        ):
            try:
                self.session = (
                    self._get_session()
                )

                all_headers = (
                    self.session.headers.copy()
                )

                if isinstance(
                    headers,
                    dict,
                ):
                    all_headers.update(
                        headers
                    )

                if (
                    body
                    and "Content-Type"
                    not in all_headers
                ):
                    all_headers[
                        "Content-Type"
                    ] = "application/json"

                timeout = stage.get(
                    "timeout",
                    self.timeout,
                )

                self._throttle(
                    retry=attempt > 0
                )

                response = self.session.request(
                    method,
                    url,
                    headers=all_headers,
                    data=body,
                    timeout=timeout,
                    allow_redirects=True,
                )

                if (
                    response.status_code
                    in (429, 503)
                    and attempt < retries
                ):
                    time.sleep(
                        2 ** attempt
                    )
                    continue

                return response

            except (
                requests.exceptions.Timeout,
                requests.exceptions.ConnectionError,
            ):
                if attempt < retries:
                    time.sleep(
                        2 ** attempt
                    )
                    continue

                return None

            except requests.RequestException:
                return None

        return None

    # ==========================================================
    # MATCHING
    # ==========================================================

    def _match_stage(
        self,
        response,
        stage,
        context,
    ):
        matchers = stage.get(
            "matchers",
            [],
        )

        # Templates may express a single matcher as either a list of
        # dicts (documented form) or a bare dict (also seen across
        # many existing templates, e.g. SQLi/SSRF/XSS/IDOR/upload/CORS
        # templates). Both are valid single-matcher shorthand; without
        # this normalization the dict form silently iterates over its
        # own keys as "matchers" and never fires.
        if isinstance(matchers, dict):
            matchers = [matchers]

        if not matchers:
            return True, [], 0

        valid = [
            matcher
            for matcher in matchers
            if isinstance(
                matcher,
                dict,
            )
        ]

        if not valid:
            return False, [], 0

        body_text = (
            self._decode_response_body(
                response
            )
        )

        body_lower = body_text.lower()

        if any(
            pattern.lower()
            in body_lower
            for pattern in self.block_patterns
        ):
            return False, [], len(valid)

        condition = stage.get(
            "matchers-condition",
            "and",
        ).lower()

        results = []
        matched_types = []

        for matcher in valid:
            outcome = self._evaluate_matcher(
                response,
                matcher,
                context,
            )
            results.append(outcome)
            if outcome:
                matched_types.append(
                    str(matcher.get("type", "")).lower()
                )

        success = any(results) if condition == "or" else all(results)

        return success, (matched_types if success else []), len(valid)

    def _evaluate_matcher(
        self,
        response,
        matcher,
        context,
    ):
        matcher_type = (
            matcher.get(
                "type",
                "",
            )
            .lower()
        )

        # ------------------------------------------------------
        # STATUS
        # ------------------------------------------------------

        if matcher_type == "status":
            expected = matcher.get(
                "status",
                [],
            )

            if isinstance(
                expected,
                int,
            ):
                expected = [
                    expected
                ]

            return (
                response.status_code
                in expected
            )

        # ------------------------------------------------------
        # WORD
        # ------------------------------------------------------

        if matcher_type == "word":
            words = matcher.get(
                "words",
                [],
            )

            if isinstance(
                words,
                str,
            ):
                words = [words]

            part = matcher.get(
                "part",
                "body",
            ).lower()

            if part == "body":
                data = (
                    self._decode_response_body(
                        response
                    )
                )
            elif part == "header":
                data = str(
                    response.headers
                )
            elif part == "all":
                data = (
                    self._decode_response_body(
                        response
                    )
                    + "\n"
                    + str(
                        response.headers
                    )
                )
            else:
                data = (
                    self._decode_response_body(
                        response
                    )
                )

            negative = matcher.get(
                "negative",
                False,
            )

            found = any(
                str(word) in data
                for word in words
            )

            return (
                not found
                if negative
                else found
            )

        # ------------------------------------------------------
        # REGEX
        # ------------------------------------------------------

        if matcher_type == "regex":
            patterns = matcher.get(
                "regex",
                [],
            )

            if isinstance(
                patterns,
                str,
            ):
                patterns = [
                    patterns
                ]

            part = matcher.get(
                "part",
                "body",
            ).lower()

            if part == "body":
                data = (
                    self._decode_response_body(
                        response
                    )
                )
            elif part in (
                "header",
                "headers",
            ):
                data = str(
                    response.headers
                )
            else:
                data = (
                    self._decode_response_body(
                        response
                    )
                )

            negative = matcher.get(
                "negative",
                False,
            )

            found = False

            for pattern in patterns:
                try:
                    if re.search(
                        pattern,
                        data,
                        re.I,
                    ):
                        found = True
                        break
                except re.error:
                    continue

            return (
                not found
                if negative
                else found
            )

        # ------------------------------------------------------
        # HEADER
        # ------------------------------------------------------

        if matcher_type == "header":
            header_name = matcher.get(
                "name"
            )

            if not header_name:
                return False

            actual = ""

            for key, value in (
                response.headers.items()
            ):
                if (
                    key.lower()
                    == str(
                        header_name
                    ).lower()
                ):
                    actual = value
                    break

            if "value" in matcher:
                expected = str(
                    matcher["value"]
                )

                return (
                    expected.lower()
                    in actual.lower()
                )

            if "regex" in matcher:
                try:
                    return bool(
                        re.search(
                            matcher["regex"],
                            actual,
                            re.I,
                        )
                    )
                except re.error:
                    return False

            return bool(actual)

        # ------------------------------------------------------
        # SIZE
        # ------------------------------------------------------

        if matcher_type in (
            "size",
            "length",
        ):
            expected = matcher.get(
                "size",
                matcher.get(
                    "length"
                ),
            )

            if expected is None:
                return False

            try:
                return len(
                    response.content
                ) == int(expected)
            except (
                TypeError,
                ValueError,
            ):
                return False

        # ------------------------------------------------------
        # STATUS NOT
        # ------------------------------------------------------

        if matcher_type in (
            "status_not",
            "not_status",
        ):
            expected = matcher.get(
                "status",
                [],
            )

            if isinstance(
                expected,
                int,
            ):
                expected = [
                    expected
                ]

            return (
                response.status_code
                not in expected
            )

        return False

    # ==========================================================
    # EXTRACTORS
    # ==========================================================

    def _extract_from_response(
        self,
        response,
        extractors,
        context,
    ):
        extracted = {}

        if not extractors:
            return extracted

        if isinstance(
            extractors,
            dict,
        ):
            extractors = [
                extractors
            ]

        for extractor in extractors:
            if not isinstance(
                extractor,
                dict,
            ):
                continue

            extractor_type = extractor.get(
                "type",
                "",
            ).lower()

            name = extractor.get(
                "name"
            )

            if not name:
                continue

            # --------------------------------------------------
            # JSON
            # --------------------------------------------------

            if extractor_type == "json":
                try:
                    data = response.json()

                    paths = extractor.get(
                        "json",
                        extractor.get(
                            "path",
                            [],
                        ),
                    )

                    if isinstance(
                        paths,
                        str,
                    ):
                        paths = [
                            paths
                        ]

                    if jsonpath_ng:
                        for json_path in paths:
                            expression = (
                                jsonpath_ng
                                .parse(
                                    json_path
                                )
                            )

                            matches = (
                                expression.find(
                                    data
                                )
                            )

                            if matches:
                                values = [
                                    match.value
                                    for match
                                    in matches
                                ]

                                value = (
                                    values[0]
                                    if len(
                                        values
                                    ) == 1
                                    else values
                                )

                                context[
                                    name
                                ] = value

                                extracted[
                                    name
                                ] = value

                                break

                except Exception:
                    pass

            # --------------------------------------------------
            # REGEX
            # --------------------------------------------------

            elif extractor_type == "regex":
                part = extractor.get(
                    "part",
                    "body",
                ).lower()

                if part == "body":
                    data = (
                        self._decode_response_body(
                            response
                        )
                    )
                else:
                    data = str(
                        response.headers
                    )

                patterns = extractor.get(
                    "regex",
                    extractor.get(
                        "pattern",
                        [],
                    ),
                )

                if isinstance(
                    patterns,
                    str,
                ):
                    patterns = [
                        patterns
                    ]

                for pattern in patterns:
                    try:
                        matches = re.findall(
                            pattern,
                            data,
                        )
                    except re.error:
                        continue

                    if matches:
                        value = (
                            matches[0]
                            if len(
                                matches
                            ) == 1
                            else matches
                        )

                        context[
                            name
                        ] = value

                        extracted[
                            name
                        ] = value

                        break

            # --------------------------------------------------
            # RAW
            # --------------------------------------------------

            elif extractor_type == "raw":
                value = extractor.get(
                    "value",
                    "",
                )

                context[
                    name
                ] = value

                extracted[
                    name
                ] = value

        return extracted

    # ==========================================================
    # EVIDENCE
    # ==========================================================

    def _build_evidence(
        self,
        method,
        url,
        request_headers,
        request_body,
        response,
    ):
        body = (
            self._decode_response_body(
                response
            )
        )

        return {
            "method": method,
            "url": url,
            "request_headers": dict(
                request_headers or {}
            ),
            "request_body": request_body,
            "status": response.status_code,
            "response_headers": dict(
                response.headers
            ),
            "response_body": body,
            "response_length": len(
                response.content
            ),
        }

    # ==========================================================
    # CONFIDENCE SCORING
    # ==========================================================

    # Weight per matcher type: more specific/harder-to-fake signals
    # get more weight. A bare "status" or "size" match alone is weak
    # evidence (lots of pages return 200), while a specific regex/word
    # match on response content, or an absent/present security header,
    # is much stronger evidence for that particular vulnerability class.
    _MATCHER_WEIGHTS = {
        "regex": 0.40,
        "word": 0.35,
        "header": 0.30,
        "status_not": 0.15,
        "not_status": 0.15,
        "size": 0.15,
        "length": 0.15,
        "status": 0.10,
    }

    def _score_confidence(
        self,
        matched_types,
        matcher_total,
        verified=False,
    ):
        """
        Compute a 0.0-1.0 confidence score from which matcher types
        actually fired for a finding, plus whether an independent
        verification stage also confirmed it.

        Rules of thumb (see project spec section 5):
          - a single generic indicator (e.g. only "status")  -> low
          - one specific indicator (word/regex/header)        -> medium
          - multiple independent indicator types               -> high
          - verification stage independently reproduces it     -> very high
        """
        unique_types = set(t for t in matched_types if t)

        if not unique_types:
            return 0.0

        score = sum(
            self._MATCHER_WEIGHTS.get(t, 0.10)
            for t in unique_types
        )

        # A single weak/generic matcher (status/size only) should never
        # look like strong evidence on its own.
        if unique_types <= {"status", "status_not", "not_status", "size", "length"}:
            score = min(score, 0.25)

        # Reward genuinely independent corroborating signals rather
        # than just summing weights unboundedly.
        if len(unique_types) >= 2:
            score = min(score + 0.10, 0.80)

        if verified:
            score = min(score + 0.20, 1.0)

        return round(min(max(score, 0.0), 1.0), 2)

    def _run_verification(self, template, context):
        """
        Execute the template's optional `verification` stage(s), if
        present, as an independent re-check of the finding. Returns
        True only if verification requests were defined AND matched.
        Never raises; verification failures just mean "not confirmed".
        """
        verification_stages = template.get("verification")

        if not verification_stages:
            return False

        if isinstance(verification_stages, dict):
            verification_stages = [verification_stages]

        if not isinstance(verification_stages, list):
            return False

        for v_stage in verification_stages:
            if not isinstance(v_stage, dict):
                continue
            try:
                response, evidence, _ctx = self._execute_request(
                    v_stage,
                    context,
                )
            except Exception:
                continue

            if response is not None and evidence is not None:
                return True

        return False

    # ==========================================================
    # REQUEST EXECUTION
    # ==========================================================

    def _execute_request(
        self,
        stage,
        extra_context=None,
    ):
        if not isinstance(
            stage,
            dict,
        ):
            return (
                None,
                None,
                None,
            )

        context = self._build_context(
            extra_context
        )

        method = stage.get(
            "method",
            "GET",
        ).upper()

        # ------------------------------------------------------
        # RENDER PATH
        # ------------------------------------------------------

        paths = self._substitute(
            stage.get(
                "path",
                [],
            ),
            context,
        )

        if isinstance(
            paths,
            str,
        ):
            paths = [
                paths
            ]

        if not isinstance(
            paths,
            list,
        ):
            return (
                None,
                None,
                None,
            )

        # ------------------------------------------------------
        # RENDER HEADERS / BODY
        # ------------------------------------------------------

        headers = self._substitute(
            stage.get(
                "headers",
                {},
            ),
            context,
        )

        body = self._substitute(
            stage.get(
                "body",
                "",
            ),
            context,
        )

        raw_body = self._substitute(
            stage.get(
                "raw_body",
                "",
            ),
            context,
        )

        request_body = (
            raw_body
            if raw_body
            else body
        )

        if isinstance(
            request_body,
            (dict, list),
        ):
            request_body = json.dumps(
                request_body
            )

        # ------------------------------------------------------
        # PAYLOADS
        # ------------------------------------------------------

        payloads = stage.get(
            "payloads",
            {},
        )

        if payloads:
            payload_keys = list(
                payloads.keys()
            )

            payload_values = []

            for key in payload_keys:
                value = self._substitute(
                    payloads[key],
                    context,
                )

                if not isinstance(
                    value,
                    list,
                ):
                    value = [
                        value
                    ]

                payload_values.append(
                    value
                )

            for combination in itertools.product(
                *payload_values
            ):
                payload_context = dict(
                    zip(
                        payload_keys,
                        combination,
                    )
                )

                request_context = {
                    **context,
                    **payload_context,
                }

                for path_template in paths:
                    full_path = (
                        self._substitute(
                            path_template,
                            request_context,
                        )
                    )

                    full_url = urljoin(
                        self.base_url,
                        full_path,
                    )

                    response = (
                        self._make_request(
                            method,
                            full_url,
                            headers,
                            request_body,
                            stage,
                        )
                    )

                    match_ok, matched_types, matcher_total = (
                        self._match_stage(
                            response,
                            stage,
                            request_context,
                        )
                        if response
                        else (False, [], 0)
                    )

                    if match_ok:
                        evidence = (
                            self._build_evidence(
                                method,
                                full_url,
                                headers,
                                request_body,
                                response,
                            )
                        )
                        evidence["matched_types"] = matched_types
                        evidence["matcher_total"] = matcher_total

                        return (
                            response,
                            evidence,
                            request_context,
                        )

            return (
                None,
                None,
                None,
            )

        # ------------------------------------------------------
        # NORMAL REQUESTS
        # ------------------------------------------------------

        for path_template in paths:
            full_path = self._substitute(
                path_template,
                context,
            )

            full_url = urljoin(
                self.base_url,
                full_path,
            )

            response = self._make_request(
                method,
                full_url,
                headers,
                request_body,
                stage,
            )

            match_ok, matched_types, matcher_total = (
                self._match_stage(
                    response,
                    stage,
                    context,
                )
                if response
                else (False, [], 0)
            )

            if match_ok:
                evidence = (
                    self._build_evidence(
                        method,
                        full_url,
                        headers,
                        request_body,
                        response,
                    )
                )
                evidence["matched_types"] = matched_types
                evidence["matcher_total"] = matcher_total

                return (
                    response,
                    evidence,
                    context,
                )

        return (
            None,
            None,
            None,
        )

    # ==========================================================
    # EXPLOITATION
    # ==========================================================

    def _attempt_exploitation(
        self,
        finding,
        template,
    ):
        if not self.exploit_enabled:
            return None

        exploit_section = template.get(
            "exploitation"
        )

        if not isinstance(
            exploit_section,
            dict,
        ):
            return None

        method = exploit_section.get(
            "method",
            "GET",
        ).upper()

        path_template = exploit_section.get(
            "path",
            "",
        )

        headers_template = (
            exploit_section.get(
                "headers",
                {},
            )
        )

        body_template = exploit_section.get(
            "body",
            "",
        )

        extractor = exploit_section.get(
            "extract"
        )

        context = self._build_context(
            finding.get(
                "extracted",
                {},
            )
        )

        path = self._substitute(
            path_template,
            context,
        )

        url = urljoin(
            self.base_url,
            path,
        )

        body = self._substitute(
            body_template,
            context,
        )

        headers = self._substitute(
            headers_template,
            context,
        )

        try:
            self._throttle()

            response = self.session.request(
                method,
                url,
                headers=headers,
                data=body,
                timeout=self.timeout,
                allow_redirects=True,
            )

            success = False
            output = ""

            if isinstance(
                extractor,
                dict,
            ):
                extractor_type = extractor.get(
                    "type",
                    "",
                ).lower()

                if extractor_type == "regex":
                    pattern = extractor.get(
                        "pattern",
                        "",
                    )

                    try:
                        match = re.search(
                            pattern,
                            response.text,
                        )

                        if match:
                            output = (
                                match.group(1)
                                if match.groups()
                                else match.group(0)
                            )

                            success = True

                    except re.error:
                        pass

                elif extractor_type == "json":
                    try:
                        data = response.json()

                        json_path = (
                            extractor.get(
                                "path"
                            )
                        )

                        if (
                            json_path
                            and jsonpath_ng
                        ):
                            expression = (
                                jsonpath_ng
                                .parse(
                                    json_path
                                )
                            )

                            matches = (
                                expression.find(
                                    data
                                )
                            )

                            if matches:
                                output = [
                                    match.value
                                    for match
                                    in matches
                                ]

                                success = True

                    except Exception:
                        pass

                elif extractor_type == "status":
                    expected = extractor.get(
                        "expected",
                        200,
                    )

                    if (
                        response.status_code
                        == expected
                    ):
                        success = True
                        output = (
                            f"Status "
                            f"{response.status_code}"
                        )

            else:
                if response.status_code == 200:
                    success = True
                    output = response.text[
                        :500
                    ]

            return {
                "success": success,
                "request": {
                    "method": method,
                    "url": url,
                    "headers": dict(
                        headers or {}
                    ),
                    "body": body,
                },
                "response": {
                    "status": response.status_code,
                    "headers": dict(
                        response.headers
                    ),
                    "body": response.text,
                },
                "output": output,
            }

        except requests.RequestException:
            return None

    # ==========================================================
    # TEMPLATE EXECUTION
    # ==========================================================

    def _execute_template(
        self,
        template,
    ):
        template_id = template.get(
            "id",
            "unknown",
        )

        template_name = template.get(
            "name",
            template_id,
        )

        severity = template.get(
            "severity",
            "info",
        )

        impact = template.get(
            "impact",
            "No impact description provided.",
        )

        chain = template.get(
            "chain",
            "No chaining information provided.",
        )

        stages = template.get(
            "requests",
            [],
        )

        if not isinstance(
            stages,
            list,
        ):
            return

        local_context = self._build_context()

        stage_variables = {}

        # Import differential helpers
        from core.differential import (
            ResponseFingerprint,
            compare_boolean_responses,
            compare_timing_responses,
        )

        # We'll collect paired stages (true/false, probe/confirm)
        pending_pairs = {}  # base_id -> {"true": (resp, ev), "false": (resp, ev), ...}

        for index, stage in enumerate(
            stages
        ):
            if not isinstance(
                stage,
                dict,
            ):
                continue

            request_context = {
                **local_context,
                **stage_variables,
            }

            stage_id = str(stage.get("id", ""))
            is_boolean_pair = stage_id.endswith(("-true", "-false"))
            is_timing_pair = stage_id.endswith(("-probe", "-confirm"))

            (
                response,
                evidence,
                updated_context,
            ) = self._execute_request(
                stage,
                request_context,
            )

            if is_boolean_pair or is_timing_pair:
                # Determine role
                if stage_id.endswith("-true"):
                    role = "true"
                elif stage_id.endswith("-false"):
                    role = "false"
                elif stage_id.endswith("-probe"):
                    role = "probe"
                else:
                    role = "confirm"
                base_id = stage_id[: -len("-" + role)]

                pending_pairs.setdefault(base_id, {})[role] = (response, evidence)

                # Check if we have both halves
                have_pair = (
                    (is_boolean_pair and "true" in pending_pairs[base_id] and "false" in pending_pairs[base_id])
                    or
                    (is_timing_pair and "probe" in pending_pairs[base_id] and "confirm" in pending_pairs[base_id])
                )

                if not have_pair:
                    # Wait for the paired stage
                    continue

                # ---- We have both halves - run differential ----
                if is_boolean_pair:
                    true_resp, true_ev = pending_pairs[base_id]["true"]
                    false_resp, false_ev = pending_pairs[base_id]["false"]
                    if true_resp is None or false_resp is None:
                        # Remove pair to avoid re-processing
                        del pending_pairs[base_id]
                        continue

                    baseline_fp = ResponseFingerprint(
                        200, len(true_resp.text), true_resp.text, 0.0
                    )
                    true_fp = ResponseFingerprint(
                        true_resp.status_code, len(true_resp.text), true_resp.text, 0.0
                    )
                    false_fp = ResponseFingerprint(
                        false_resp.status_code, len(false_resp.text), false_resp.text, 0.0
                    )
                    diff = compare_boolean_responses(baseline_fp, true_fp, false_fp)
                    if not diff.is_significant:
                        if not self.quiet:
                            print(f"[SKIP] {template_id}:{base_id} — {diff.reason}")
                        del pending_pairs[base_id]
                        continue

                    # Use the true response as the finding evidence
                    response, evidence = true_resp, true_ev
                    if evidence is not None:
                        evidence["matched_types"] = list(
                            set((evidence.get("matched_types") or []) + ["boolean_differential"])
                        )
                        evidence["differential_reason"] = diff.reason

                else:  # timing pair
                    probe_resp, probe_ev = pending_pairs[base_id]["probe"]
                    confirm_resp, confirm_ev = pending_pairs[base_id]["confirm"]
                    if probe_resp is None or confirm_resp is None:
                        del pending_pairs[base_id]
                        continue

                    baseline_fp = ResponseFingerprint(200, 0, "", 0.3)
                    probe_fp = ResponseFingerprint(
                        probe_resp.status_code, 0, "", probe_resp.elapsed.total_seconds()
                    )
                    confirm_fp = ResponseFingerprint(
                        confirm_resp.status_code, 0, "", confirm_resp.elapsed.total_seconds()
                    )
                    timing = compare_timing_responses(baseline_fp, probe_fp, confirm_fp)
                    if not timing.is_significant:
                        if not self.quiet:
                            print(f"[SKIP] {template_id}:{base_id} — {timing.reason}")
                        del pending_pairs[base_id]
                        continue

                    response, evidence = probe_resp, probe_ev
                    if evidence is not None:
                        evidence["matched_types"] = list(
                            set((evidence.get("matched_types") or []) + ["time_differential"])
                        )
                        evidence["differential_reason"] = timing.reason

                # Remove the pair so we don't re-process
                del pending_pairs[base_id]

                # Now response and evidence are set, fall through to finding creation
                # (if we didn't skip due to insignificant diff)
            else:
                # Single-stage (non-pair): normal matching
                if response is None:
                    continue
                # We need to evaluate matchers here; _execute_request already did matching
                # but we need to get the match result. Actually _execute_request already
                # returns evidence only if matched. So if evidence is None, no match.
                # But we need to check if the stage matched; _execute_request returns evidence only if match_ok.
                # However we already have evidence from _execute_request; if it's None, no match.
                # So we just check if evidence is not None.
                if evidence is None:
                    continue

            # ---- Now we have a matched finding (either from single stage or pair) ----

            # Extract variables (done inside _execute_request already, but updated_context may contain more)
            # We already have response and evidence.
            # Do we need to run verification? Let's keep existing verification logic.
            # We'll compute confidence and lifecycle stage.

            matched_types = evidence.get("matched_types", []) if evidence else []
            matcher_total = evidence.get("matcher_total", 0) if evidence else 0

            # Verification (optional)
            confirmed = self._run_verification(
                template,
                {**local_context, **stage_variables},
            )

            confidence = self._score_confidence(
                matched_types,
                matcher_total,
                verified=confirmed,
            )

            if confidence < 0.30:
                lifecycle_stage = "signal"
            elif confidence < 0.60:
                lifecycle_stage = "possible"
            elif confirmed:
                lifecycle_stage = "verified"
            else:
                lifecycle_stage = "possible"

            finding = {
                "template_id": template_id,
                "name": template_name,
                "severity": severity,
                "impact": impact,
                "chain": chain,
                "evidence": evidence,
                "extracted": {},   # Could be filled from stage_variables
                "exploit": None,
                "stage_index": index,
                "template_file": template.get("_file"),
                "confidence": confidence,
                "confirmed": confirmed,
                "lifecycle_stage": lifecycle_stage,
                "matched_types": matched_types,
            }

            # Optional exploitation
            if self.exploit_enabled:
                exploit_result = self._attempt_exploitation(finding, template)
                if exploit_result:
                    finding["exploit"] = exploit_result
                    if not self.quiet:
                        status = "SUCCESS" if exploit_result["success"] else "FAILED"
                        print(f"[EXPLOIT] {template_id} - {status}")

            self.findings.append(finding)

            if not self.quiet:
                print(f"[VULN] {str(severity).upper()}: {template_name} at {evidence['url']}")

            # After producing a finding, break the stage loop (stop processing further stages)
            # But careful: for paired stages we already consumed both; we should break after finding.
            break

        # If we finished loop without finding, nothing added.

    def _endpoint_shape(self, url):
        """
        Collapse a URL to its path shape (scheme+host+path, no query
        string) so that the same vulnerable endpoint hit with 20
        different payload permutations fingerprints as one place, not
        20 unrelated ones.
        """
        try:
            parsed = urlparse(url)
            return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        except Exception:
            return url

    def _fingerprint(self, finding):
        evidence = finding.get("evidence") or {}
        url = evidence.get("url", "")
        param_hint = ",".join(sorted(finding.get("matched_types", [])))
        return (
            finding.get("template_id"),
            self._endpoint_shape(url),
            param_hint,
        )

    def _deduplicate_findings(self, findings):
        """
        Correlate findings that share (template_id, endpoint shape,
        matcher signature) into a single record with an occurrence
        count and the list of distinct affected endpoints, keeping the
        highest-confidence/most-confirmed instance as the representative
        evidence. See spec section 8.
        """
        groups: Dict[Any, List[Dict[str, Any]]] = {}

        for finding in findings:
            key = self._fingerprint(finding)
            groups.setdefault(key, []).append(finding)

        deduped = []

        for key, group in groups.items():
            group.sort(
                key=lambda f: (
                    f.get("confirmed", False),
                    f.get("confidence", 0.0),
                ),
                reverse=True,
            )

            best = dict(group[0])

            affected_endpoints = sorted(set(
                self._endpoint_shape(
                    (f.get("evidence") or {}).get("url", "")
                )
                for f in group
            ))

            best["occurrences"] = len(group)
            best["affected_endpoints"] = affected_endpoints
            best["affected_endpoint_count"] = len(affected_endpoints)

            # Persist correlation metadata inside the evidence blob too,
            # since core.database.save_scan() only writes a fixed set of
            # top-level finding columns - this keeps it in the DB and
            # available to history/dashboard/PDF without a schema change.
            if isinstance(best.get("evidence"), dict):
                best["evidence"] = dict(best["evidence"])
                best["evidence"]["occurrences"] = len(group)
                best["evidence"]["affected_endpoints"] = affected_endpoints

            # Multiple independent occurrences of the same real issue
            # is itself corroborating evidence — nudge confidence up
            # slightly, capped, rather than letting 20 duplicate rows
            # each individually claim the same confidence.
            if len(group) > 1:
                best["confidence"] = round(
                    min(best.get("confidence", 0.0) + 0.05, 1.0), 2
                )

            deduped.append(best)

        return deduped

    # ==========================================================
    # SCAN
    # ==========================================================

    def run(self):
        # ------------------------------------------------------
        # AUTHENTICATION
        # ------------------------------------------------------

        if not self.skip_auth:
            if not self.quiet:
                print(
                    "[AUTH] Attempting to authenticate..."
                )

            authenticated = (
                self.auth.authenticate(
                    self.username,
                    self.password,
                )
            )

            if authenticated:
                if not self.quiet:
                    print(
                        "[AUTH] Authentication successful."
                    )
            else:
                if not self.quiet:
                    print(
                        "[AUTH] Auto-authentication "
                        "failed. Continuing without auth."
                    )

        else:
            if not self.quiet:
                print(
                    "[AUTH] Skipped (--no-auth)."
                )

        # ------------------------------------------------------
        # LOAD TEMPLATES
        # ------------------------------------------------------

        self.load_templates()

        if not self.templates:
            if not self.quiet:
                print(
                    "[WARN] No templates loaded. "
                    "Nothing to scan."
                )

            return {
                "url": self.raw_url,
                "base_url": self.base_url,
                "scan_id": self.scan_id,
                "findings": self.findings,
                "total_templates": 0,
            }

        if not self.quiet:
            print(
                f"[SCANNER] Running "
                f"{len(self.templates)} templates "
                f"against {self.base_url}..."
            )

        # ------------------------------------------------------
        # CONCURRENT EXECUTION
        # ------------------------------------------------------

        with ThreadPoolExecutor(
            max_workers=self.max_workers
        ) as executor:

            futures = {
                executor.submit(
                    self._execute_template,
                    template,
                ): template
                for template in self.templates
            }

            for future in as_completed(
                futures
            ):
                template = futures[
                    future
                ]

                try:
                    future.result()

                except Exception as exc:
                    if not self.quiet:
                        print(
                            f"[ERROR] Template failed: "
                            f"{template.get('id', 'unknown')}"
                        )

                        print(
                            f"[ERROR] {exc}"
                        )

                        traceback.print_exc()

        # ------------------------------------------------------
        # RESULT
        # ------------------------------------------------------

        deduped_findings = self._deduplicate_findings(
            self.findings
        )

        if not self.quiet and len(deduped_findings) != len(self.findings):
            print(
                f"[CORRELATE] {len(self.findings)} raw signal(s) "
                f"correlated into {len(deduped_findings)} "
                f"distinct finding(s)."
            )

        return {
            "url": self.raw_url,
            "base_url": self.base_url,
            "scan_id": self.scan_id,
            "findings": deduped_findings,
            "raw_signal_count": len(self.findings),
            "total_templates": len(
                self.templates
            ),
        }


# ==============================================================
# CONVENIENCE FUNCTION
# ==============================================================

def scan_target(
    url,
    quiet=False,
    template_dir="templates/",
    **kwargs,
):
    scanner = Scanner(
        url=url,
        quiet=quiet,
        template_dir=template_dir,

        max_workers=kwargs.get(
            "max_workers",
            10,
        ),

        proxy_file=kwargs.get(
            "proxy_file"
        ),

        country=kwargs.get(
            "country"
        ),

        rate_limit=kwargs.get(
            "rate_limit",
            0,
        ),

        delay=kwargs.get(
            "delay",
            2,
        ),

        jitter=kwargs.get(
            "jitter",
            0.5,
        ),

        exploit=kwargs.get(
            "exploit",
            False,
        ),

        username=kwargs.get(
            "username"
        ),

        password=kwargs.get(
            "password"
        ),

        timeout=kwargs.get(
            "timeout",
            10,
        ),

        skip_priv=kwargs.get(
            "skip_priv",
            False,
        ),

        skip_auth=kwargs.get(
            "skip_auth",
            False,
        ),
    )

    return scanner.run()
