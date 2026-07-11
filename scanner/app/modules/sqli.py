"""
Advanced SQL Injection Detection Module

Detection methods:
1. Error-based SQL Injection
2. Boolean-based SQL Injection
3. Time-based SQL Injection

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
# URL Payload Injection
# -------------------------------


def inject_payload(url: str, parameter: str, payload: str):

    parsed = urlparse(url)

    params = parse_qs(parsed.query)

    params[parameter] = [payload]

    new_query = urlencode(
        params,
        doseq=True
    )

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


# -------------------------------
# Error Based Detection
# -------------------------------


def check_error_based(
        session,
        url,
        parameter,
        timeout
):

    for payload in ERROR_PAYLOADS:

        test_url = inject_payload(
            url,
            parameter,
            payload
        )

        try:

            response = session.get(
                test_url,
                timeout=timeout
            )

        except requests.RequestException:
            continue


        body = response.text.lower()


        for error in SQL_ERROR_PATTERNS:

            if error in body:

                return {
                    "type": "error",
                    "url": test_url,
                    "evidence":
                        f"Database error pattern '{error}' detected"
                }


    return None



# -------------------------------
# Boolean Based Detection
# -------------------------------


def check_boolean_based(
        session,
        url,
        parameter,
        timeout
):

    baseline_response = None


    try:

        baseline_response = session.get(
            url,
            timeout=timeout
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


        true_url = inject_payload(
            url,
            parameter,
            true_payload
        )


        false_url = inject_payload(
            url,
            parameter,
            false_payload
        )


        try:

            true_response = session.get(
                true_url,
                timeout=timeout
            )


            false_response = session.get(
                false_url,
                timeout=timeout
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

                "url": true_url,

                "evidence":
                    "Boolean payloads caused significant response difference"

            }


    return None



# -------------------------------
# Time Based Detection
# -------------------------------


def check_time_based(
        session,
        url,
        parameter,
        timeout
):


    try:

        start = time.time()

        session.get(
            url,
            timeout=timeout
        )

        normal_time = time.time() - start


    except requests.RequestException:

        return None



    for payload in TIME_PAYLOADS:


        test_url = inject_payload(
            url,
            parameter,
            payload
        )


        try:

            start = time.time()


            session.get(
                test_url,
                timeout=timeout
            )


            response_time = time.time() - start



            if response_time - normal_time > 2:


                return {

                    "type": "time",

                    "url": test_url,

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
        urls: list[str],
        timeout: int = DEFAULT_TIMEOUT
):

    findings = []

    session = requests.Session()


    session.headers.update({

        "User-Agent":
            "AdvancedVulnerabilityScanner/1.0"

    })


    checked = set()



    for url in urls:


        if url in checked:
            continue


        checked.add(url)


        parsed = urlparse(url)


        parameters = parse_qs(
            parsed.query
        )


        if not parameters:
            continue



        for parameter in parameters:


            result = None



            # Try error based

            result = check_error_based(
                session,
                url,
                parameter,
                timeout
            )


            # Try boolean based

            if not result:

                result = check_boolean_based(
                    session,
                    url,
                    parameter,
                    timeout
                )


            # Try time based

            if not result:

                result = check_time_based(
                    session,
                    url,
                    parameter,
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