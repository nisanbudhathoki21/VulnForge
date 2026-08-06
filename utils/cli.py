import argparse

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="VulnForge",
        description="AI-assisted vulnerability scanner (MVP) — CLI"
    )
    parser.add_argument("-u", "--url", dest="url", required=True, help="Target URL or domain")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    return parser

def parse_args() -> argparse.Namespace:
    return build_parser().parse_args()
