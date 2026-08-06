from urllib.parse import urlparse

def normalize_url(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith(("http://", "https://")):
        return raw
    return f"https://{raw}"

def is_valid_url(url: str) -> bool:
    p = urlparse(url)
    return bool(p.scheme) and bool(p.netloc)
