from typing import List

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.database import get_db
from app.models.asset import Asset
from app.schemas.asset import AssetResponse


router = APIRouter(
    prefix="/assets",
    tags=["Assets"]
)


@router.get("/", response_model=List[AssetResponse])
def get_assets(db: Session = Depends(get_db)):
    return db.query(Asset).all()


@router.get("/{asset_id}", response_model=AssetResponse)
def get_asset(
    asset_id: int,
    db: Session = Depends(get_db)
):
    return db.query(Asset).filter(
        Asset.id == asset_id
    ).first()