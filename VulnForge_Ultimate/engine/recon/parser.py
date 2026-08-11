from urllib.parse import urljoin, urldefrag, urlparse, parse_qs

from bs4 import BeautifulSoup


def normalize_url(base_url, discovered_url):
    if not discovered_url:
        return None

    discovered_url = discovered_url.strip()

    if discovered_url.startswith(("#", "mailto:", "javascript:", "tel:")):
        return None

    absolute = urljoin(base_url, discovered_url)
    absolute, _ = urldefrag(absolute)

    parsed = urlparse(absolute)

    if parsed.scheme not in ("http", "https"):
        return None

    return absolute


def extract_links(base_url, html):
    soup = BeautifulSoup(html, "html.parser")

    results = set()

    for tag in soup.find_all("a", href=True):
        url = normalize_url(base_url, tag["href"])

        if url:
            results.add(url)

    return results


def extract_forms(base_url, html):
    soup = BeautifulSoup(html, "html.parser")

    forms = []

    for form in soup.find_all("form"):
        action = normalize_url(
            base_url,
            form.get("action") or base_url,
        )

        method = (form.get("method") or "GET").upper()

        parameters = []

        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")

            if name:
                parameters.append(name)

        forms.append(
            {
                "url": action,
                "method": method,
                "parameters": sorted(set(parameters)),
            }
        )

    return forms


def extract_query_parameters(url):
    parsed = urlparse(url)

    params = parse_qs(
        parsed.query,
        keep_blank_values=True,
    )

    return sorted(params.keys())
