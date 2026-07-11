from fastapi import FastAPI, Request, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from sqlalchemy.orm import Session
from sqlalchemy import inspect

from app.database.database import Base, engine, get_db

from app.models.scan import Scan
from app.models.finding import Finding
from app.models.asset import Asset

from app.api.scans import router as scan_router
from app.api import assets, findings, reports

app = FastAPI(
    title="Advanced Web Application Vulnerability Scanner"
)

templates = Jinja2Templates(directory="app/templates")

# API ROUTES

app.include_router(scan_router)
app.include_router(assets.router)
app.include_router(findings.router)
app.include_router(reports.router)

# STATIC FILES

app.mount(
    "/static",
    StaticFiles(directory="app/static"),
    name="static"
)

# DATABASE STARTUP

@app.on_event("startup")
def on_startup():

    Base.metadata.create_all(bind=engine)

    print("DB URL:", engine.url)
    print("Registered Models:", Base.metadata.tables.keys())

    inspector = inspect(engine)
    print("Tables in DB:", inspector.get_table_names())


# =====================================================
# OWASP TOP 10 -> scanner module mapping
# =====================================================
# Maps each scanning module to the OWASP Top 10:2025 category
# its findings belong to, so report findings can link to the
# reference page.

OWASP_MODULE_MAP = {
    "headers": ("A02", "Security Misconfiguration"),
    "cookies": ("A02", "Security Misconfiguration"),
    "xss": ("A05", "Injection"),
    "sqli": ("A05", "Injection"),
}


# =====================================================
# DASHBOARD
# =====================================================

@app.get("/")
def dashboard(
    request: Request,
    db: Session = Depends(get_db)
):

    scans = (
        db.query(Scan)
        .order_by(Scan.id.desc())
        .all()
    )

    return templates.TemplateResponse(
        request=request,
        name="dashboard.html",
        context={
            "scans": scans,
            "active": "dashboard"
        }
    )


# =====================================================
# OWASP TOP 10 REFERENCE PAGE
# =====================================================

@app.get("/owasp-top-10")
def owasp_top_10(request: Request):

    return templates.TemplateResponse(
        request=request,
        name="owasp.html",
        context={
            "active": "owasp"
        }
    )


# =====================================================
# REPORT PAGE
# =====================================================

@app.get("/report/{scan_id}")
def report_page(
    scan_id: int,
    request: Request,
    db: Session = Depends(get_db)
):

    scan = (
        db.query(Scan)
        .filter(Scan.id == scan_id)
        .first()
    )

    findings = (
        db.query(Finding)
        .filter(Finding.scan_id == scan_id)
        .all()
    )

    assets = (
        db.query(Asset)
        .filter(Asset.scan_id == scan_id)
        .all()
    )

    severity_summary = {}

    for finding in findings:
        severity_summary[finding.severity] = (
            severity_summary.get(finding.severity, 0) + 1
        )

        # Attach OWASP category info for the template to link to.
        # This is a transient attribute (not persisted, not a DB column).
        owasp = OWASP_MODULE_MAP.get(finding.module)
        finding.owasp_id = owasp[0] if owasp else None
        finding.owasp_title = owasp[1] if owasp else None

    return templates.TemplateResponse(
        request=request,
        name="report.html",
        context={
            "scan": scan,
            "findings": findings,
            "assets": assets,
            "severity_summary": severity_summary,
            "active": None
        }
    )