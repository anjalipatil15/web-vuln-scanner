"""
Cookie Security Module

Checks cookies for security attributes:
- Secure flag
- HttpOnly flag
- SameSite attribute
"""

import requests

DEFAULT_TIMEOUT = 5


def run(urls: list[str], timeout: int = DEFAULT_TIMEOUT) -> list[dict]:

    findings = []

    session = requests.Session()

    session.headers.update({
        "User-Agent": "SimpleVulnScanner/0.1 (authorized-testing)"
    })


    checked_urls = set()


    for url in urls:

        if url in checked_urls:
            continue

        checked_urls.add(url)


        try:
            response = session.get(
    url,
    timeout=timeout,
    allow_redirects=False
)

        except requests.RequestException:
            continue


        cookies = response.cookies
        print("COOKIE FOUND:", response.cookies)


        for cookie in cookies:


            # Secure flag check
            if not cookie.secure:

                findings.append({
                    "vulnerability_name": "Cookie Missing Secure Flag",
                    "severity": "medium",
                    "evidence": f"Cookie '{cookie.name}' does not have Secure flag",
                    "endpoint": url,
                    "recommendation": 
                        "Set the Secure attribute so cookies are only sent over HTTPS.",
                    "module": "cookies"
                })


            # HttpOnly check
            if "httponly" not in cookie._rest:

                findings.append({
                    "vulnerability_name": "Cookie Missing HttpOnly Flag",
                    "severity": "medium",
                    "evidence": f"Cookie '{cookie.name}' does not have HttpOnly flag",
                    "endpoint": url,
                    "recommendation":
                        "Set HttpOnly attribute to prevent JavaScript access to sensitive cookies.",
                    "module": "cookies"
                })


            # SameSite check
            samesite = cookie._rest.get("SameSite")


            if not samesite:

                findings.append({
                    "vulnerability_name": "Cookie Missing SameSite Attribute",
                    "severity": "low",
                    "evidence": f"Cookie '{cookie.name}' does not define SameSite",
                    "endpoint": url,
                    "recommendation":
                        "Set SameSite attribute to reduce CSRF attack risk.",
                    "module": "cookies"
                })


    return findings