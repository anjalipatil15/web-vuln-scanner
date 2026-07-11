"""
Reflected XSS Detection Module

Checks whether user-controlled parameters are reflected
directly in HTTP responses.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

DEFAULT_TIMEOUT = 5

XSS_PAYLOAD = "<script>alert(1)</script>"


def inject_payload(url: str, parameter: str) -> str:
    """
    Replace parameter value with XSS payload.
    """

    parsed = urlparse(url)

    params = parse_qs(parsed.query)

    params[parameter] = [XSS_PAYLOAD]

    new_query = urlencode(params, doseq=True)

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        )
    )


def run(urls: list[str], timeout: int = DEFAULT_TIMEOUT) -> list[dict]:

    findings = []

    session = requests.Session()

    session.headers.update({
        "User-Agent": "SimpleVulnScanner/0.1"
    })


    for url in urls:

        parsed = urlparse(url)

        parameters = parse_qs(parsed.query)


        if not parameters:
            continue


        for parameter in parameters:


            test_url = inject_payload(
                url,
                parameter
            )


            try:

                response = session.get(
                    test_url,
                    timeout=timeout
                )

            except requests.RequestException:
                continue


            if XSS_PAYLOAD in response.text:

                findings.append({

                    "vulnerability_name":
                        "Reflected Cross-Site Scripting (XSS)",

                    "severity":
                        "high",

                    "evidence":
                        f"Payload reflected in response parameter '{parameter}'",

                    "endpoint":
                        test_url,

                    "recommendation":
                        "Implement proper input validation and output encoding.",

                    "module":
                        "xss"
                })


    return findings