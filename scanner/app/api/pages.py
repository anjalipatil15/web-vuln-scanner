from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from fastapi import Depends

from app.database.database import get_db

from app.models.scan import Scan
from app.models.finding import Finding
from app.models.asset import Asset

router = APIRouter()

templates = Jinja2Templates(directory="app/templates")


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request):

    return templates.TemplateResponse(
        "index.html",
        {
            "request": request
        }
    )

@router.get(
    "/scan/{scan_id}",
    response_class=HTMLResponse
)
def scan_report(
        scan_id: int,
        request: Request,
        db: Session = Depends(get_db)
):

    scan = (
        db.query(Scan)
        .filter(
            Scan.id == scan_id
        )
        .first()
    )

    findings = (
        db.query(Finding)
        .filter(
            Finding.scan_id == scan_id
        )
        .all()
    )

    assets = (
        db.query(Asset)
        .filter(
            Asset.scan_id == scan_id
        )
        .all()
    )

    return templates.TemplateResponse(
        "report.html",
        {
            "request": request,
            "scan": scan,
            "findings": findings,
            "assets": assets
        }
    )