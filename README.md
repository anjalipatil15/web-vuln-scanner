# web-vuln-scanner
# VulnScan

A lightweight web application vulnerability scanner. Point it at a target URL and it crawls the site, then checks for missing security headers, insecure cookies, reflected XSS, and SQL injection — producing a report you can view in the browser or export as a PDF.

## Features

- **Crawler** — discovers pages, links, and forms within a target domain
- **Header & cookie checks** — flags missing security headers and insecure cookie flags
- **XSS detection** — tests for reflected Cross-Site Scripting
- **SQL injection detection** — error-based, boolean-based, and time-based checks
- **Risk scoring** — each scan gets an overall risk score/level based on finding severity
- **Reports** — in-browser report with severity filtering, plus one-click PDF export
- **OWASP Top 10 reference** — findings link to the relevant 2025 OWASP category

## Tech Stack

- **Backend:** FastAPI, SQLAlchemy
- **Frontend:** Jinja2 templates, vanilla JS, custom CSS
- **PDF generation:** ReportLab
- **Crawling/requests:** `requests`, BeautifulSoup

## Getting Started

```bash
# install dependencies
pip install -r requirements.txt

# run the app
uvicorn main:app --reload
```

Then open `http://127.0.0.1:8000` in your browser.

## Project Structure

```
app/
├── api/              # route handlers (scans, assets, findings, reports)
├── core/             # crawler, orchestrator, mapper, risk engine
├── modules/          # scanning modules (headers, cookies, xss, sqli)
├── services/         # PDF report generation
├── models/            # SQLAlchemy models
├── schemas/           # Pydantic schemas
├── templates/         # dashboard, report, OWASP pages
└── static/            # stylesheet
main.py                 # FastAPI app entrypoint
test.py                #test vulnerable website
```

## Usage

1. Paste a target URL on the dashboard and click **Start scan**.
2. Wait for the scan to complete — you'll be redirected to the report automatically.
3. Filter findings by severity, review the risk score, and download a PDF if needed.
4. Check the **OWASP Top 10** page for background on any finding's category.

## Known Limitations

- XSS detection is reflection-based only; it doesn't confirm the payload actually executes in a browser.
- Designed for small-to-medium sites; large sites may take a while to crawl and scan.