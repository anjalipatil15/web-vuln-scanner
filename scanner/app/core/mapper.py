"""
Attack Surface Mapper — converts raw crawler output (pages + forms) into
a clean list of testable targets: (endpoint, parameter, method) tuples.

Example:
  Crawler finds: /search?q=test
  Mapper produces: {endpoint: "/search", parameter: "q", method: "GET"}

  Crawler finds a form with action=/login, method=POST, inputs=[username, password]
  Mapper produces two targets:
    {endpoint: "/login", parameter: "username", method: "POST"}
    {endpoint: "/login", parameter: "password", method: "POST"}
"""

from urllib.parse import urlparse, parse_qs


def map_attack_surface(crawl_result: dict) -> list[dict]:
    """
    Takes the dict returned by crawler.crawl() and returns a deduplicated
    list of attack targets, each: {"url": ..., "method": ..., "parameter": ...}
    """
    targets = []
    seen = set()

    def add_target(url: str, method: str, parameter: str):
        key = (url, method, parameter)
        if key not in seen:
            seen.add(key)
            targets.append({"url": url, "method": method, "parameter": parameter})

    # 1. Targets from query-string parameters on crawled pages (GET params)
    for page in crawl_result.get("pages", []):
        url = page["url"]
        base_url = url.split("?")[0]
        query_params = parse_qs(urlparse(url).query)
        for param_name in query_params:
            add_target(base_url, "GET", param_name)

    # 2. Targets from forms (GET or POST, depending on the form's method)
    for form in crawl_result.get("forms", []):
        action = form["action"]
        method = form["method"]
        for input_name in form["inputs"]:
            add_target(action, method, input_name)

    return targets


def targets_to_asset_rows(targets: list[dict]) -> list[dict]:
    """
    Groups targets by (url, method) and combines their parameters into
    a single comma-separated string, matching the Asset model's shape:
    {url, method, parameters}
    """
    grouped = {}
    for t in targets:
        key = (t["url"], t["method"])
        grouped.setdefault(key, []).append(t["parameter"])

    return [
        {"url": url, "method": method, "parameters": ",".join(params)}
        for (url, method), params in grouped.items()
    ]


if __name__ == "__main__":
    import json
    from app.core.crawler import crawl

    result = crawl("http://127.0.0.1:5000/")
    targets = map_attack_surface(result)
    assets = targets_to_asset_rows(targets)

    print("--- Individual test targets ---")
    print(json.dumps(targets, indent=2))
    print("\n--- Grouped into Asset rows ---")
    print(json.dumps(assets, indent=2))