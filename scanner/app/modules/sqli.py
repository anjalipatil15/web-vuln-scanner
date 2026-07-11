"""
Advanced SQL Injection Detection Module

Detection methods:
1. Error-based SQL Injection
2. Boolean-based SQL Injection
3. Time-based SQL Injection

Works against both GET query parameters and GET/POST form fields
(as produced by app.core.mapper.map_attack_surface()).

This module only detects possible vulnerabilities.
It does not exploit or extract data.
"""

import requests
import time

from urllib.parse import (
    urlparse,
    parse_qs,
    urlencode,
    urlunparse
)


DEFAULT_TIMEOUT = 7


# Payload categories

ERROR_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "') OR ('1'='1"
]


BOOLEAN_TRUE_PAYLOADS = [
    "' AND 1=1--",
    "\" AND 1=1--",
    "1 AND 1=1"
]


BOOLEAN_FALSE_PAYLOADS = [
    "' AND 1=2--",
    "\" AND 1=2--",
    "1 AND 1=2"
]


TIME_PAYLOADS = [
    "1' AND SLEEP(3)--",
    "1\" AND SLEEP(3)--",
    "1'; SELECT pg_sleep(3)--"
]


SQL_ERROR_PATTERNS = [
    "sql syntax",
    "mysql",
    "mysqli",
    "sqlite",
    "postgresql",
    "postgres",
    "oracle",
    "syntax error",
    "unclosed quotation",
    "quoted string not properly terminated",
    "database error"
]


# -------------------------------
# Request Building
# -------------------------------


def _build_param_values(parameter: str, payload: str, all_parameters: list[str] | None) -> dict:
    """
    Builds the full set of form/query values for a request: the target
    parameter gets the payload, every other known field gets a harmless
    placeholder so the request behaves like a normal submission.
    """
    params = list(all_parameters) if all_parameters else [parameter]
    if parameter not in params:
        params.append(parameter)
    return {p: (payload if p == parameter else "1") for p in params}


def _send(session, target: dict, payload: str, timeout: int):
    """
    Sends a request against a target dict {url, method, parameter,
    all_parameters} with `payload` injected into `parameter`.
    Returns (response, display_url).
    """
    method = target.get("method", "GET").upper()
    url = target["url"]
    parameter = target["parameter"]
    all_parameters = target.get("all_parameters")

    values = _build_param_values(parameter, payload, all_parameters)

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


def _send_baseline(session, target: dict, timeout: int):
    """
    Sends a normal (non-payload) request, used to measure baseline
    response length/time for boolean- and time-based checks.
    """
    method = target.get("method", "GET").upper()
    url = target["url"]

    if method == "POST":

        values = _build_param_values(target["parameter"], "1", target.get("all_parameters"))

        return session.post(
            url,
            data=values,
            timeout=timeout,
            verify=False
        )

    return session.get(
        url,
        timeout=timeout,
        verify=False
    )


# -------------------------------
# Error Based Detection
# -------------------------------


def check_error_based(
        session,
        target,
        timeout
):

    for payload in ERROR_PAYLOADS:

        try:

            response, display_url = _send(
                session,
                target,
                payload,
                timeout
            )

        except requests.RequestException:
            continue


        body = response.text.lower()


        for error in SQL_ERROR_PATTERNS:

            if error in body:

                return {
                    "type": "error",
                    "url": display_url,
                    "evidence":
                        f"Database error pattern '{error}' detected"
                }


    return None



# -------------------------------
# Boolean Based Detection
# -------------------------------


def check_boolean_based(
        session,
        target,
        timeout
):

    baseline_response = None


    try:

        baseline_response = _send_baseline(
            session,
            target,
            timeout
        )

    except requests.RequestException:

        return None



    baseline_length = len(
        baseline_response.text
    )


    for true_payload, false_payload in zip(
        BOOLEAN_TRUE_PAYLOADS,
        BOOLEAN_FALSE_PAYLOADS
    ):

        try:

            true_response, true_display_url = _send(
                session,
                target,
                true_payload,
                timeout
            )


            false_response, _ = _send(
                session,
                target,
                false_payload,
                timeout
            )


        except requests.RequestException:

            continue



        true_length = len(
            true_response.text
        )


        false_length = len(
            false_response.text
        )


        difference = abs(
            true_length - false_length
        )


        # Significant response difference

        if difference > (baseline_length * 0.3):

            return {

                "type": "boolean",

                "url": true_display_url,

                "evidence":
                    "Boolean payloads caused significant response difference"

            }


    return None



# -------------------------------
# Time Based Detection
# -------------------------------


def check_time_based(
        session,
        target,
        timeout
):


    try:

        start = time.time()

        _send_baseline(
            session,
            target,
            timeout
        )

        normal_time = time.time() - start


    except requests.RequestException:

        return None



    for payload in TIME_PAYLOADS:

        try:

            start = time.time()


            response, display_url = _send(
                session,
                target,
                payload,
                timeout
            )


            response_time = time.time() - start



            if response_time - normal_time > 2:


                return {

                    "type": "time",

                    "url": display_url,

                    "evidence":
                        f"Response delayed by {round(response_time-normal_time,2)} seconds"

                }


        except requests.RequestException:

            continue


    return None



# -------------------------------
# Main Runner
# -------------------------------


def run(
        targets: list[dict],
        timeout: int = DEFAULT_TIMEOUT
):
    """
    targets: list of dicts {url, method, parameter, all_parameters}
    as produced by app.core.mapper.map_attack_surface()
    """

    findings = []

    session = requests.Session()


    session.headers.update({

        "User-Agent":
            "AdvancedVulnerabilityScanner/1.0"

    })


    checked = set()



    for target in targets:

        key = (
            target["url"],
            target.get("method", "GET").upper(),
            target["parameter"]
        )

        if key in checked:
            continue

        checked.add(key)


        result = None


        # Try error based

        result = check_error_based(
            session,
            target,
            timeout
        )


        # Try boolean based

        if not result:

            result = check_boolean_based(
                session,
                target,
                timeout
            )


        # Try time based

        if not result:

            result = check_time_based(
                session,
                target,
                timeout
            )



        if result:


            findings.append({

                "vulnerability_name":
                    "SQL Injection",


                "severity":
                    "high",


                "evidence":
                    result["evidence"],


                "endpoint":
                    result["url"],


                "recommendation":
                    "Use prepared statements, parameterized queries, and secure ORM practices.",


                "module":
                    "sqli"

            })



    return findings