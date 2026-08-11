# engine/endpoint_pipeline.py

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import (
    parse_qsl,
    urlencode,
    urlparse,
    urlunparse,
)


# ==========================================================
# DATA MODEL
# ==========================================================

@dataclass
class Endpoint:
    method: str
    url: str

    normalized_url: str = ""
    path: str = ""

    parameters: list[str] = field(
        default_factory=list
    )

    parameter_values: dict[str, list[str]] = field(
        default_factory=dict
    )

    source: str = "unknown"

    endpoint_type: str = "web"
    is_api: bool = False
    is_static: bool = False

    technology_hints: list[str] = field(
        default_factory=list
    )

    test_categories: list[str] = field(
        default_factory=list
    )

    def to_dict(self):
        return {
            "method": self.method,
            "url": self.url,
            "normalized_url": self.normalized_url,
            "path": self.path,
            "parameters": list(self.parameters),
            "parameter_values": dict(
                self.parameter_values
            ),
            "source": self.source,
            "endpoint_type": self.endpoint_type,
            "is_api": self.is_api,
            "is_static": self.is_static,
            "technology_hints": list(
                self.technology_hints
            ),
            "test_categories": list(
                self.test_categories
            ),
        }


# ==========================================================
# CONSTANTS
# ==========================================================

STATIC_EXTENSIONS = {
    ".css",
    ".js",
    ".jpg",
    ".jpeg",
    ".png",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".mp4",
    ".mp3",
    ".pdf",
    ".zip",
    ".tar",
    ".gz",
    ".apk",
    ".map",
}

STATIC_PATH_MARKERS = {
    "/assets/",
    "/asset/",
    "/static/",
    "/images/",
    "/image/",
    "/css/",
    "/fonts/",
    "/js/",
    "/vendor/",
    "/node_modules/",
}

IGNORED_PATH_MARKERS = {
    "/jquery/",
    "/bootstrap/",
    "/isotope/",
    "/fancybox/",
}

PARAM_CATEGORY_MAP = {
    "id": "identifier",
    "user_id": "identifier",
    "userid": "identifier",
    "uid": "identifier",
    "account": "identifier",
    "account_id": "identifier",
    "course_id": "identifier",
    "post_id": "identifier",

    "q": "search",
    "query": "search",
    "search": "search",
    "keyword": "search",
    "term": "search",

    "page": "pagination",
    "offset": "pagination",
    "limit": "pagination",
    "start": "pagination",

    "sort": "sorting",
    "order": "sorting",
    "order_by": "sorting",

    "url": "url",
    "uri": "url",
    "link": "url",

    "redirect": "redirect",
    "redirect_url": "redirect",

    "file": "file",
    "filename": "file",
    "path": "file",
    "filepath": "file",
    "document": "file",

    "callback": "callback",

    "next": "navigation",
    "return": "navigation",
    "return_url": "navigation",
}


# ==========================================================
# URL NORMALIZATION
# ==========================================================

def normalize_url(url: str) -> str:
    """
    Normalize a discovered URL.

    This function does not perform network requests.
    """

    if not isinstance(url, str):
        return ""

    url = url.strip()

    if not url:
        return ""

    # Remove common crawler/parser artifacts.
    url = url.rstrip(
        " \t\r\n,;"
    )

    # Remove accidental Markdown brackets.
    url = url.replace("[", "")
    url = url.replace("]", "")

    try:
        parsed = urlparse(url)
    except Exception:
        return ""

    if parsed.scheme.lower() not in {
        "http",
        "https",
    }:
        return ""

    if not parsed.netloc:
        return ""

    scheme = parsed.scheme.lower()
    netloc = parsed.netloc.lower()

    path = parsed.path or "/"

    # Normalize duplicate trailing slash only for root.
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    query_pairs = parse_qsl(
        parsed.query,
        keep_blank_values=True,
    )

    # Stable parameter ordering.
    query_pairs.sort(
        key=lambda item: (
            item[0],
            item[1],
        )
    )

    query = urlencode(
        query_pairs,
        doseq=True,
    )

    return urlunparse(
        (
            scheme,
            netloc,
            path,
            "",
            query,
            "",
        )
    )


# ==========================================================
# PARAMETER CLASSIFICATION
# ==========================================================

def classify_parameter(
    parameter: str,
) -> str:

    if not isinstance(
        parameter,
        str,
    ):
        return "generic"

    normalized = parameter.strip().lower()

    if not normalized:
        return "generic"

    if normalized in PARAM_CATEGORY_MAP:
        return PARAM_CATEGORY_MAP[
            normalized
        ]

    # Useful heuristic handling.
    if normalized.endswith("_id"):
        return "identifier"

    if normalized.endswith("id"):
        return "identifier"

    if (
        "redirect" in normalized
        or normalized.startswith("return")
    ):
        return "redirect"

    if (
        "url" in normalized
        or normalized.endswith("uri")
    ):
        return "url"

    if (
        "file" in normalized
        or "path" in normalized
    ):
        return "file"

    if (
        "search" in normalized
        or "query" in normalized
        or normalized in {
            "q",
            "keyword",
        }
    ):
        return "search"

    return "generic"


# ==========================================================
# ENDPOINT TYPE
# ==========================================================

def determine_endpoint_type(
    normalized_url: str,
) -> str:

    parsed = urlparse(
        normalized_url
    )

    path_lower = (
        parsed.path or "/"
    ).lower()

    extension = ""

    if "." in path_lower.rsplit(
        "/",
        1,
    )[-1]:
        extension = (
            "."
            + path_lower.rsplit(
                ".",
                1,
            )[-1]
        )

    if extension in STATIC_EXTENSIONS:
        return "static"

    for marker in STATIC_PATH_MARKERS:
        if marker in path_lower:
            return "static"

    return "web"


# ==========================================================
# API DETECTION
# ==========================================================

def detect_api(
    normalized_url: str,
) -> bool:

    parsed = urlparse(
        normalized_url
    )

    path = (
        parsed.path or ""
    ).lower()

    if (
        path.startswith("/api/")
        or "/api/" in path
    ):
        return True

    if path.startswith(
        "/graphql"
    ):
        return True

    if path.endswith(
        ".json"
    ):
        return True

    if "/rest/" in path:
        return True

    return False


# ==========================================================
# TECHNOLOGY HINTS
# ==========================================================

def technology_hints(
    normalized_url: str,
) -> list[str]:

    parsed = urlparse(
        normalized_url
    )

    path = (
        parsed.path or ""
    ).lower()

    hints = []

    if (
        ".php" in path
        or path.endswith(".php")
    ):
        hints.append("PHP")

    if (
        ".asp" in path
        or ".aspx" in path
    ):
        hints.append("ASP.NET")

    if ".jsp" in path:
        hints.append("JSP")

    if (
        "/api/" in path
        or path.startswith("/api")
    ):
        hints.append("API")

    if path.startswith(
        "/graphql"
    ):
        hints.append("GraphQL")

    return sorted(
        set(hints)
    )


# ==========================================================
# TEST CATEGORY GENERATION
# ==========================================================

def tests_for_category(
    category: str,
) -> list[str]:

    mapping = {
        "identifier": [
            "baseline",
            "identifier_consistency",
        ],

        "search": [
            "baseline",
            "reflection_check",
        ],

        "redirect": [
            "baseline",
            "redirect_validation",
        ],

        "url": [
            "baseline",
            "url_parameter_analysis",
        ],

        "file": [
            "baseline",
            "file_parameter_analysis",
        ],

        "pagination": [
            "baseline",
            "pagination_consistency",
        ],

        "sorting": [
            "baseline",
            "sorting_consistency",
        ],

        "callback": [
            "baseline",
            "callback_analysis",
        ],

        "navigation": [
            "baseline",
            "navigation_parameter_analysis",
        ],

        "generic": [
            "baseline",
            "reflection_check",
        ],
    }

    return list(
        mapping.get(
            category,
            ["baseline"],
        )
    )


# ==========================================================
# BUILD ENDPOINT
# ==========================================================

def build_endpoint(
    raw: dict,
) -> Endpoint | None:

    if not isinstance(
        raw,
        dict,
    ):
        return None

    raw_url = raw.get(
        "url",
        "",
    )

    normalized = normalize_url(
        raw_url
    )

    if not normalized:
        return None

    parsed = urlparse(
        normalized
    )

    method = str(
        raw.get(
            "method",
            "GET",
        )
    ).upper()

    if not method:
        method = "GET"

    endpoint_type = determine_endpoint_type(
        normalized
    )

    is_api = bool(
        raw.get(
            "is_api",
            False,
        )
    ) or detect_api(
        normalized
    )

    # Query parameters discovered by crawler.
    query_parameters = []

    parameter_values = {}

    for name, value in parse_qsl(
        parsed.query,
        keep_blank_values=True,
    ):
        if not name:
            continue

        query_parameters.append(
            name
        )

        parameter_values.setdefault(
            name,
            [],
        )

        if value not in parameter_values[
            name
        ]:
            parameter_values[
                name
            ].append(value)

    # Parameters discovered from HTML forms.
    form_parameters = raw.get(
        "parameters",
        [],
    )

    if isinstance(
        form_parameters,
        str,
    ):
        form_parameters = [
            form_parameters
        ]

    if not isinstance(
        form_parameters,
        (list, tuple, set),
    ):
        form_parameters = []

    parameters = sorted(
        set(
            query_parameters
            + [
                str(item)
                for item in form_parameters
                if item
            ]
        )
    )

    categories = sorted(
        set(
            classify_parameter(
                parameter
            )
            for parameter in parameters
        )
    )

    return Endpoint(
        method=method,
        url=raw_url,
        normalized_url=normalized,
        path=parsed.path or "/",
        parameters=parameters,
        parameter_values=dict(
            parameter_values
        ),
        source=raw.get(
            "source",
            "unknown",
        ),
        endpoint_type=endpoint_type,
        is_api=is_api,
        is_static=(
            endpoint_type == "static"
        ),
        technology_hints=technology_hints(
            normalized
        ),
        test_categories=categories,
    )


# ==========================================================
# DEDUPLICATION
# ==========================================================

def deduplicate_endpoints(
    raw_endpoints: list[dict],
) -> list[Endpoint]:

    groups = {}

    for raw in raw_endpoints:

        endpoint = build_endpoint(
            raw
        )

        if endpoint is None:
            continue

        key = (
            endpoint.method,
            endpoint.normalized_url,
        )

        if key not in groups:
            groups[key] = endpoint
            continue

        existing = groups[key]

        # Merge parameter names.
        existing.parameters = sorted(
            set(
                existing.parameters
                + endpoint.parameters
            )
        )

        # Merge parameter values.
        for parameter, values in (
            endpoint.parameter_values.items()
        ):
            existing.parameter_values.setdefault(
                parameter,
                [],
            )

            for value in values:
                if value not in (
                    existing.parameter_values[
                        parameter
                    ]
                ):
                    existing.parameter_values[
                        parameter
                    ].append(value)

        # Preserve useful metadata.
        if (
            existing.source == "unknown"
            and endpoint.source != "unknown"
        ):
            existing.source = endpoint.source

        existing.is_api = (
            existing.is_api
            or endpoint.is_api
        )

        if not existing.technology_hints:
            existing.technology_hints = list(
                endpoint.technology_hints
            )
        else:
            existing.technology_hints = sorted(
                set(
                    existing.technology_hints
                    + endpoint.technology_hints
                )
            )

    # Recalculate categories after merging.
    for endpoint in groups.values():

        endpoint.test_categories = sorted(
            set(
                classify_parameter(
                    parameter
                )
                for parameter
                in endpoint.parameters
            )
        )

    return list(
        groups.values()
    )


# ==========================================================
# TEST PLAN
# ==========================================================

def build_test_plan(
    endpoints: list[Endpoint],
    include_static: bool = False,
) -> list[dict]:

    plan = []

    for endpoint in endpoints:

        if (
            endpoint.is_static
            and not include_static
        ):
            continue

        # --------------------------------------------------
        # PARAMETERIZED ENDPOINT
        # --------------------------------------------------

        for parameter in endpoint.parameters:

            category = classify_parameter(
                parameter
            )

            plan.append(
                {
                    "method": endpoint.method,
                    "url": endpoint.url,
                    "endpoint": endpoint.normalized_url,
                    "path": endpoint.path,
                    "parameter": parameter,
                    "parameter_category": category,
                    "endpoint_type": endpoint.endpoint_type,
                    "is_api": endpoint.is_api,
                    "technology": list(
                        endpoint.technology_hints
                    ),
                    "source": endpoint.source,
                    "tests": tests_for_category(
                        category
                    ),
                }
            )

        # --------------------------------------------------
        # NO PARAMETER
        # --------------------------------------------------

        if not endpoint.parameters:

            plan.append(
                {
                    "method": endpoint.method,
                    "url": endpoint.url,
                    "endpoint": endpoint.normalized_url,
                    "path": endpoint.path,
                    "parameter": None,
                    "parameter_category": "none",
                    "endpoint_type": endpoint.endpoint_type,
                    "is_api": endpoint.is_api,
                    "technology": list(
                        endpoint.technology_hints
                    ),
                    "source": endpoint.source,
                    "tests": [
                        "baseline",
                        "security_headers",
                    ],
                }
            )

    return plan


# ==========================================================
# PUBLIC PIPELINE
# ==========================================================

def prepare_endpoints(
    raw_endpoints: list[dict],
    include_static: bool = False,
) -> dict:

    endpoints = deduplicate_endpoints(
        raw_endpoints
    )

    test_plan = build_test_plan(
        endpoints,
        include_static=include_static,
    )

    return {
        "endpoints": endpoints,
        "test_plan": test_plan,
        "endpoint_count": len(
            endpoints
        ),
        "test_count": len(
            test_plan
        ),
    }


# ==========================================================
# SERIALIZATION HELPER
# ==========================================================

def pipeline_to_dict(
    pipeline: dict,
) -> dict:

    return {
        "endpoints": [
            endpoint.to_dict()
            if isinstance(
                endpoint,
                Endpoint,
            )
            else endpoint
            for endpoint in pipeline.get(
                "endpoints",
                [],
            )
        ],
        "test_plan": pipeline.get(
            "test_plan",
            [],
        ),
        "endpoint_count": pipeline.get(
            "endpoint_count",
            0,
        ),
        "test_count": pipeline.get(
            "test_count",
            0,
        ),
    }
