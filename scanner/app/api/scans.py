from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db

from app.models.scan import Scan
from app.models.asset import Asset
from app.models.finding import Finding

from app.schemas.scan import ScanCreate, ScanResponse

from app.core.orchestrator import run_scan, CrawlFailedError


router = APIRouter(
    prefix="/scans",
    tags=["Scans"]
)


@router.get("/", response_model=List[ScanResponse])
def get_scans(db: Session = Depends(get_db)):
    return db.query(Scan).all()



@router.post("/", response_model=ScanResponse)
def create_scan(
    scan: ScanCreate,
    db: Session = Depends(get_db)
):

    # 1. Create scan entry
    new_scan = Scan(
        target=scan.target,
        status="running"
    )

    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)


    # 2. Run scanner workflow
    try:
        result = run_scan(
            new_scan.id,
            new_scan.target
        )
    except CrawlFailedError as exc:
        print(f"[!] Scan {new_scan.id} failed: {exc}")
        new_scan.status = "failed"
        db.commit()
        db.refresh(new_scan)
        return new_scan


    # 3. Save discovered assets
    for page in result["assets"]:

        asset = Asset(
            scan_id=new_scan.id,
            url=page["url"],
            method="GET",
            parameters=",".join(page["query_params"])
            if page["query_params"]
            else None
        )

        db.add(asset)


    # 4. Save findings
    for item in result["findings"]:

        finding = Finding(
            scan_id=new_scan.id,
            vulnerability_name=item["vulnerability_name"],
            severity=item["severity"],
            evidence=item["evidence"],
            endpoint=item["endpoint"],
            recommendation=item["recommendation"],
            module=item["module"]
        )

        db.add(finding)


    # 5. Mark scan complete
    new_scan.status = "completed"

    db.commit()
    db.refresh(new_scan)


    return new_scan