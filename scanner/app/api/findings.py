from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.finding import Finding
from app.schemas.finding import FindingResponse


router = APIRouter(
    prefix="/findings",
    tags=["Findings"]
)


@router.get("/", response_model=List[FindingResponse])
def get_findings(db: Session = Depends(get_db)):
    return db.query(Finding).all()


@router.get("/{finding_id}", response_model=FindingResponse)
def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    return db.query(Finding).filter(
        Finding.id == finding_id
    ).first()