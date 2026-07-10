"""
Cookie Security Module — inspects cookies set by the target site for
missing security flags: Secure, HttpOnly, and SameSite.

Missing flags matter because:
- Secure: without it, the cookie can be sent over plain HTTP, exposing
  it to interception on the network.
- HttpOnly: without it, JavaScript can read the cookie, meaning an XSS
  bug can be used to steal it (e.g. session hijacking).
- SameSite: without it (or set to "None"), the cookie may be sent on
  cross-site requests, making CSRF-style attacks easier.
"""

import requests

DEFAULT_TIMEOUT = 5


def run(urls: list[str], timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """
    Takes a list of unique URLs, checks any cookies set by each response
    for missing security flags, and returns a list of finding dicts.
    """
    findings = []
    session = requests.Session()
    session.headers.update({"User-Agent": "SimpleVulnScanner/0.1 (authorized-testing)"})

    checked_urls = set()

    for url in urls:
        if url in checked_urls:
            continue
        checked_urls.add(url)

        try:
            response = session.get(url, timeout=timeout, allow_redirects=True)
        except requests.RequestException:
            continue

        # Raw Set-Cookie headers give us access to flags that the
        # simplified requests.cookies jar doesn't expose directly.
        set_cookie_headers = response.raw.headers.get_all("Set-Cookie") \
            if hasattr(response.raw.headers, "get_all") else []

        # Fallback for environments where get_all isn't available.
        if not set_cookie_headers:
            raw_header = response.headers.get("Set-Cookie")
            set_cookie_headers = [raw_header] if raw_header else []

        for cookie_header in set_cookie_headers:
            cookie_name = cookie_header.split("=")[0].strip()
            lowered = cookie_header.lower()

            missing_flags = []
            if "secure" not in lowered:
                missing_flags.append("Secure")
            if "httponly" not in lowered:
                missing_flags.append("HttpOnly")
            if "samesite" not in lowered:
                missing_flags.append("SameSite")

            if missing_flags:
                findings.append({
                    "vulnerability_name": f"Cookie '{cookie_name}' missing security flags",
                    "severity": "medium" if "HttpOnly" in missing_flags else "low",
                    "evidence": f"Set-Cookie header missing: {', '.join(missing_flags)}",
                    "endpoint": url,
                    "recommendation": (
                        "Set the Secure, HttpOnly, and SameSite attributes on all "
                        "cookies, especially session identifiers, to reduce exposure "
                        "to interception, XSS-based theft, and CSRF."
                    ),
                    "module": "cookies",
                })

    return findings


if __name__ == "__main__":
    import json
    findings = run(["http://127.0.0.1:5000/", "http://127.0.0.1:5000/login"])
    print(json.dumps(findings, indent=2))