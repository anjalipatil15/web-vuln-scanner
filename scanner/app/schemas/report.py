from pydantic import BaseModel
from typing import List


class ReportFinding(BaseModel):
    vulnerability_name: str
    severity: str
    endpoint: str | None = None
    evidence: str | None = None
    recommendation: str | None = None
    module: str | None = None


class ReportAsset(BaseModel):
    url: str
    method: str
    parameters: str | None = None


class ReportResponse(BaseModel):
    scan_id: int
    target: str
    status: str

    total_assets: int
    total_findings: int

    severity_summary: dict
    risk_score: int
    risk_level: str

    assets: List[ReportAsset]
    findings: List[ReportFinding]

    class Config:
        from_attributes = True