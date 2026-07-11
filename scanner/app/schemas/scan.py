from pydantic import BaseModel


class ScanCreate(BaseModel):
    target: str


class ScanResponse(BaseModel):
    id: int
    target: str
    status: str

    class Config:
        from_attributes = True