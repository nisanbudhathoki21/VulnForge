#!/usr/bin/env python3

import argparse
import sys
from urllib.parse import urlparse

import requests

from engine.discovery import DiscoveryEngine
from engine.endpoint_pipeline import prepare_endpoints


def validate_url(url):
    """Validate and normalize the target URL."""

    if not url:
        raise ValueError("Target URL cannot be empty.")

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.hostname:
        raise ValueError(f"Invalid target URL: {url}")

    return url.rstrip("/")


def parse_args():
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="VulnForge Endpoint Discovery + Pipeline Test"
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL, for example https://example.com",
    )

    parser.add_argument(
        "--max-depth",
        type=int,
        default=2,
        help="Maximum discovery depth (default: 2)",
    )

    parser.add_argument(
        "--max-urls",
        type=int,
        default=100,
        help="Maximum URLs to discover (default: 100)",
    )

    parser.add_argument(
        "--timeout",
        type=float,
        default=10,
        help="HTTP timeout in seconds (default: 10)",
    )

    parser.add_argument(
        "--delay",
        type=float,
        default=0.5,
        help="Delay between requests (default: 0.5)",
    )

    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Reduce discovery output",
    )

    return parser.parse_args()


def print_header(title):
    """Print a formatted section header."""

    print()
    print("=" * 70)
    print(title)
    print("=" * 70)


def main():
    args = parse_args()

    try:
        target = validate_url(args.url)
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        return 2

    if args.max_depth < 0:
        print("[ERROR] --max-depth cannot be negative.")
        return 2

    if args.max_urls <= 0:
        print("[ERROR] --max-urls must be greater than zero.")
        return 2

    if args.timeout <= 0:
        print("[ERROR] --timeout must be greater than zero.")
        return 2

    if args.delay < 0:
        print("[ERROR] --delay cannot be negative.")
        return 2

    print_header("VULNFORGE ENDPOINT PIPELINE TEST")

    print(f"Target       : {target}")
    print(f"Max depth    : {args.max_depth}")
    print(f"Max URLs     : {args.max_urls}")
    print(f"Timeout      : {args.timeout}s")
    print(f"Request delay: {args.delay}s")

    session = requests.Session()

    session.headers.update(
        {
            "User-Agent": "VulnForge-Pipeline-Test/1.0"
        }
    )

    try:
        print_header("DISCOVERY")

        engine = DiscoveryEngine(
            session=session,
            base_url=target,
            max_depth=args.max_depth,
            max_urls=args.max_urls,
            timeout=args.timeout,
            delay=args.delay,
            quiet=args.quiet,
        )

        result = engine.run()

    except KeyboardInterrupt:
        print("\n[!] Discovery interrupted by user.")
        return 130

    except Exception as exc:
        print(f"\n[ERROR] Discovery failed: {exc}")
        return 1

    if not isinstance(result, dict):
        print("[ERROR] Discovery returned an invalid result.")
        return 1

    discovered_endpoints = result.get("endpoints", [])

    print_header("DISCOVERY RESULT")

    print(f"Target      : {target}")
    print(f"Discovered  : {len(discovered_endpoints)}")

    if not discovered_endpoints:
        print()
        print("[!] No endpoints were discovered.")
        print()
        print("Possible reasons:")
        print("  - Target is unreachable")
        print("  - Target blocks automated requests")
        print("  - Discovery depth is too low")
        print("  - Target contains few crawlable endpoints")
        print()
        return 0

    try:
        pipeline = prepare_endpoints(
            discovered_endpoints
        )
    except Exception as exc:
        print(f"[ERROR] Endpoint pipeline failed: {exc}")
        return 1

    if not isinstance(pipeline, dict):
        print("[ERROR] Endpoint pipeline returned invalid data.")
        return 1

    endpoints = pipeline.get("endpoints", [])
    test_plan = pipeline.get("test_plan", [])

    endpoint_count = pipeline.get(
        "endpoint_count",
        len(endpoints),
    )

    test_count = pipeline.get(
        "test_count",
        len(test_plan),
    )

    print_header("PIPELINE RESULT")

    print(f"Discovered endpoints : {len(discovered_endpoints)}")
    print(f"Normalized endpoints : {endpoint_count}")
    print(f"Generated test cases : {test_count}")

    print_header("ENDPOINTS")

    if not endpoints:
        print("[!] No normalized endpoints.")
    else:
        for index, endpoint in enumerate(
            endpoints,
            start=1,
        ):
            print(
                f"[{index:03}] "
                f"{endpoint.method} "
                f"{endpoint.normalized_url}"
            )

            print(
                f"      Type   : {endpoint.endpoint_type}"
            )

            print(
                f"      Params : {endpoint.parameters}"
            )

            print(
                f"      Tests  : {endpoint.test_categories}"
            )

    print_header("TEST PLAN")

    if not test_plan:
        print("[!] No test cases generated.")
    else:
        for index, test in enumerate(
            test_plan,
            start=1,
        ):
            print(
                f"[{index:03}] "
                f"{test.get('method')} "
                f"{test.get('endpoint')}"
            )

            print(
                f"      Parameter : "
                f"{test.get('parameter')}"
            )

            print(
                f"      Category  : "
                f"{test.get('parameter_category')}"
            )

            print(
                f"      Tests     : "
                f"{test.get('tests')}"
            )

    print_header("PIPELINE TEST COMPLETE")

    print(f"Target     : {target}")
    print(f"Endpoints  : {endpoint_count}")
    print(f"Test cases : {test_count}")
    print("Status     : SUCCESS")

    return 0


if __name__ == "__main__":
    sys.exit(main())
