from fastapi import FastAPI
from app.database.database import Base, engine
from app.models import scan, finding, asset  # noqa: F401

app = FastAPI(title="Advanced Web Application Vulnerability Scanner")

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Vulnerability scanner API is running"}