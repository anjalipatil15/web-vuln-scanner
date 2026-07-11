"""
Reflected XSS Detection Module

Checks whether user-controlled parameters (from query strings, GET forms,
and POST forms) are reflected directly in HTTP responses.
"""

import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

DEFAULT_TIMEOUT = 5

XSS_PAYLOAD = "<script>alert(1)</script>"


def _build_param_values(parameter: str, payload: str, all_parameters: list[str] | None) -> dict:
    """
    Builds the full set of form/query values for a request: the target
    parameter gets the payload, every other known field gets a harmless
    placeholder so the request behaves like a normal submission.
    """
    params = list(all_parameters) if all_parameters else [parameter]
    if parameter not in params:
        params.append(parameter)
    return {p: (payload if p == parameter else "test") for p in params}


def _send(session, target: dict, timeout: int):
    """
    Sends a request against a target dict {url, method, parameter,
    all_parameters} with the XSS payload injected into `parameter`.
    Returns (response, display_url) where display_url is used for
    reporting (includes POST data since there's no query string to show).
    """
    method = target.get("method", "GET").upper()
    url = target["url"]
    parameter = target["parameter"]
    all_parameters = target.get("all_parameters")

    values = _build_param_values(parameter, XSS_PAYLOAD, all_parameters)

    if method == "POST":
        response = session.post(
            url,
            data=values,
            timeout=timeout,
            verify=False
        )
        display_url = f"{url} [POST data: {values}]"
    else:
        parsed = urlparse(url)
        existing = parse_qs(parsed.query)
        for key, value in values.items():
            existing[key] = [value]
        new_query = urlencode(existing, doseq=True)
        full_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        response = session.get(
            full_url,
            timeout=timeout,
            verify=False
        )
        display_url = full_url

    return response, display_url


def run(targets: list[dict], timeout: int = DEFAULT_TIMEOUT) -> list[dict]:
    """
    targets: list of dicts {url, method, parameter, all_parameters}
    as produced by app.core.mapper.map_attack_surface()
    """
    findings = []

    session = requests.Session()

    session.headers.update({
        "User-Agent": "SimpleVulnScanner/0.1"
    })

    checked = set()

    for target in targets:

        key = (target["url"], target.get("method", "GET").upper(), target["parameter"])

        if key in checked:
            continue

        checked.add(key)

        try:

            response, display_url = _send(session, target, timeout)

        except requests.RequestException:
            continue

        if XSS_PAYLOAD in response.text:

            findings.append({

                "vulnerability_name":
                    "Reflected Cross-Site Scripting (XSS)",

                "severity":
                    "high",

                "evidence":
                    f"Payload reflected in response parameter '{target['parameter']}' "
                    f"({target.get('method', 'GET').upper()})",

                "endpoint":
                    display_url,

                "recommendation":
                    "Implement proper input validation and output encoding.",

                "module":
                    "xss"
            })

    return findings