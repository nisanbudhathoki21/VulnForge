from urllib.parse import urlparse


class ScopeManager:
    def __init__(self, target):
        parsed = urlparse(target)

        if parsed.scheme not in ("http", "https"):
            raise ValueError("Target must use http:// or https://")

        if not parsed.hostname:
            raise ValueError("Target hostname could not be determined")

        self.target_host = parsed.hostname.lower()

    def in_scope(self, url):
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            return False

        if not parsed.hostname:
            return False

        host = parsed.hostname.lower()

        return host == self.target_host
