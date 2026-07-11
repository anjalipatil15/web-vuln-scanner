from urllib.parse import urljoin, urlparse, parse_qs
from collections import deque

import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings()


DEFAULT_MAX_PAGES = 50
DEFAULT_TIMEOUT = 5  # seconds per request


def _same_domain(base_url: str, candidate_url: str) -> bool:
    return urlparse(base_url).netloc == urlparse(candidate_url).netloc


def _extract_forms(soup: BeautifulSoup, page_url: str) -> list[dict]:
    forms = []
    for form in soup.find_all("form"):
        action = form.get("action") or page_url
        method = (form.get("method") or "GET").upper()
        full_action = urljoin(page_url, action)

        inputs = []
        for field in form.find_all(["input", "textarea", "select"]):
            name = field.get("name")
            if name:
                inputs.append(name)

        forms.append({
            "action": full_action,
            "method": method,
            "inputs": inputs,
        })
    return forms


def crawl(start_url: str, max_pages: int = DEFAULT_MAX_PAGES, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """
    Crawl start_url and everything same-domain reachable from it.
    Returns pages visited, forms found, and any errors.
    """
    visited = set()
    queue = deque([start_url])

    pages = []
    forms = []
    errors = []

    session = requests.Session()
    session.headers.update({"User-Agent": "SimpleVulnScanner/0.1 (authorized-testing)"})

    while queue and len(visited) < max_pages:
        url = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        try:
            response = session.get(
    url,
    timeout=timeout,
    allow_redirects=True,
    verify=False
)
        except requests.RequestException as exc:
            errors.append({"url": url, "error": str(exc)})
            continue

        query_params = list(parse_qs(urlparse(url).query).keys())
        pages.append({
            "url": url,
            "status_code": response.status_code,
            "query_params": query_params,
        })

        content_type = response.headers.get("Content-Type", "")
        if "text/html" not in content_type:
            continue

        soup = BeautifulSoup(response.text, "html.parser")
        forms.extend(_extract_forms(soup, url))

        for anchor in soup.find_all("a", href=True):
            next_url = urljoin(url, anchor["href"])
            next_url = next_url.split("#")[0]
            if _same_domain(start_url, next_url) and next_url not in visited:
                queue.append(next_url)

    return {"pages": pages, "forms": forms, "errors": errors}


if __name__ == "__main__":
    import json
    result = crawl("http://testphp.vulnweb.com/")
    print(json.dumps(result, indent=2))