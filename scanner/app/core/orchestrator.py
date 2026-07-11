from app.core.crawler import crawl
from app.modules.headers import run as run_header_scan
from app.modules.cookies import run as run_cookie_checks
from app.modules.xss import run as run_xss_checks
from app.modules.sqli import run as run_sqli_checks


class CrawlFailedError(Exception):
    """Raised when the crawler couldn't successfully reach the target."""
    pass


def run_scan(scan_id: int, target: str):

    print(f"[+] Starting scan: {target}")

    # Crawl website
    crawl_result = crawl(target)

    pages = crawl_result["pages"]
    errors = crawl_result["errors"]

    print("CRAWL RESULT PAGES:", pages)
    if errors:
        print("CRAWL ERRORS:", errors)

    # If we got nothing back AND there were errors, this wasn't a clean
    # "0 findings" scan - the crawler actually failed to reach the target.
    # Don't let this masquerade as a completed scan with an empty report.
    if not pages and errors:
        error_summary = "; ".join(f"{e['url']} -> {e['error']}" for e in errors)
        raise CrawlFailedError(
            f"Crawl failed to reach '{target}': {error_summary}"
        )

    # Extract URLs for security modules
    urls = [
        page["url"]
        for page in pages
    ]

    # Run header scanner
    findings = run_header_scan(urls)
    print("HEADER FINDINGS:", findings)

    # Run cookie scanner
    cookie_findings = run_cookie_checks(urls)
    findings.extend(cookie_findings)

    # Run XSS scanner
    xss_findings = run_xss_checks(urls)
    findings.extend(xss_findings)

    # Run SQLi scanner (only against URLs that actually have query params)
    sqli_urls = [
        page["url"]
        for page in pages
        if page.get("query_params")
    ]

    print("[+] SQLi Targets:", sqli_urls)

    sqli_findings = run_sqli_checks(sqli_urls)
    findings.extend(sqli_findings)

    return {
        "scan_id": scan_id,
        "assets": pages,
        "findings": findings,
        "errors": errors,
    }