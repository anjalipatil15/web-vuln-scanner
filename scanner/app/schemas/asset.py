from pydantic import BaseModel
from datetime import datetime


class AssetResponse(BaseModel):
    id: int
    scan_id: int
    url: str
    method: str
    parameters: str | None = None
    forms_found: bool
    discovered_at: datetime

    class Config:
        from_attributes = True