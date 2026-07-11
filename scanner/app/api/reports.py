import os
import tempfile

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.core.risk_engine import calculate_risk
from app.models.scan import Scan
from app.models.asset import Asset
from app.models.finding import Finding

from app.schemas.report import ReportResponse
from fastapi.responses import FileResponse
from app.services.report_generator import generate_pdf_report

router = APIRouter(
    prefix="/reports",
    tags=["Reports"]
)


@router.get("/{scan_id}", response_model=ReportResponse)
def generate_report(
    scan_id: int,
    db: Session = Depends(get_db)
):

    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )


    assets = db.query(Asset).filter(
        Asset.scan_id == scan_id
    ).all()


    findings = db.query(Finding).filter(
        Finding.scan_id == scan_id
    ).all()


    severity_summary = {}

    for finding in findings:
        severity = finding.severity

        if severity in severity_summary:
            severity_summary[severity] += 1
        else:
            severity_summary[severity] = 1

    risk = calculate_risk(findings)


    return {
        "scan_id": scan.id,
        "target": scan.target,
        "status": scan.status,

        "total_assets": len(assets),
        "total_findings": len(findings),

        "severity_summary": severity_summary,
        "risk_score": risk["score"],
        "risk_level": risk["level"],

        "assets": [
            {
                "url": asset.url,
                "method": asset.method,
                "parameters": asset.parameters
            }
            for asset in assets
        ],

        "findings": [
            {
                "vulnerability_name": finding.vulnerability_name,
                "severity": finding.severity,
                "endpoint": finding.endpoint,
                "evidence": finding.evidence,
                "recommendation": finding.recommendation,
                "module": finding.module
            }
            for finding in findings
        ]
    }

@router.get("/{scan_id}/download")
def download_report(
    scan_id: int,
    db: Session = Depends(get_db)
):

    scan = db.query(Scan).filter(
        Scan.id == scan_id
    ).first()

    if not scan:
        raise HTTPException(
            status_code=404,
            detail="Scan not found"
        )

    filename = f"scan_report_{scan_id}.pdf"
    output_path = os.path.join(tempfile.gettempdir(), filename)

    generate_pdf_report(
        scan_id,
        db,
        output_path
    )

    return FileResponse(
        output_path,
        media_type="application/pdf",
        filename=filename
    )