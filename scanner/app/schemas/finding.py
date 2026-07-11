from pydantic import BaseModel


class FindingResponse(BaseModel):
    id: int
    scan_id: int
    vulnerability_name: str
    severity: str
    evidence: str | None = None
    endpoint: str | None = None
    recommendation: str | None = None
    module: str | None = None

    class Config:
        from_attributes = True