"""
Security Header Module — checks each discovered endpoint for missing
or misconfigured security-related HTTP response headers.

This module needs no injected payloads; it just inspects the headers
already returned by a normal GET request.
"""

import requests

DEFAULT_TIMEOUT = 5

# Each entry: header name -> (severity, recommendation)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "medium",
        "Set a Content-Security-Policy header to restrict which sources "
        "scripts, styles, and other resources can be loaded from, reducing "
        "the impact of XSS if it occurs.",
    ),
    "Strict-Transport-Security": (
        "medium",
        "Set Strict-Transport-Security (HSTS) to force browsers to only "
        "connect over HTTPS, preventing downgrade/SSL-stripping attacks.",
    ),
    "X-Frame-Options": (
        "low",
        "Set X-Frame-Options (e.g. DENY or SAMEORIGIN) to prevent the "
        "site from being embedded in a malicious iframe (clickjacking).",
    ),
    "X-Content-Type-Options": (
        "low",
        "Set X-Content-Type-Options: nosniff to stop browsers from "
        "MIME-sniffing responses into an unintended, potentially "
        "executable content type.",
    ),
    "Referrer-Policy": (
        "info",
        "Set a Referrer-Policy header to control how much URL "
        "information is leaked to other sites via the Referer header.",
    ),
}


def run(urls: list[str], timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """
    Takes a list of unique URLs (endpoints), checks each for missing
    security headers, and returns a list of finding dicts:
    {vulnerability_name, severity, evidence, endpoint, recommendation, module}
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
            response = session.get(url, timeout=timeout, verify=False)
        except requests.RequestException as exc:
            continue  # unreachable endpoint, skip — crawler already logged this

        for header_name, (severity, recommendation) in SECURITY_HEADERS.items():
            if header_name not in response.headers:
                findings.append({
                    "vulnerability_name": f"Missing {header_name} header",
                    "severity": severity,
                    "evidence": f"Response headers did not include '{header_name}'",
                    "endpoint": url,
                    "recommendation": recommendation,
                    "module": "headers",
                })

    return findings


if __name__ == "__main__":
    import json
    findings = run(["http://127.0.0.1:5000/", "http://127.0.0.1:5000/login"])
    print(json.dumps(findings, indent=2))