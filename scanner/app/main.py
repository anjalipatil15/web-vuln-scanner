from fastapi import FastAPI
from app.database.database import Base, engine
from app.models import scan, finding, asset  # noqa: F401
from sqlalchemy import inspect

app = FastAPI(title="Advanced Web Application Vulnerability Scanner")

@app.on_event("startup")

@app.on_event("startup")
def on_startup():
    Base.metadata.create_all(bind=engine)

    print("DB URL:", engine.url)
    print("Registered Models:", Base.metadata.tables.keys())

    inspector = inspect(engine)
    print("Tables in DB:", inspector.get_table_names())

@app.get("/")
def read_root():
    return {"status": "ok", "message": "Vulnerability scanner API is running"}