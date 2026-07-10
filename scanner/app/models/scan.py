from sqlalchemy import Column, Integer, String, DateTime, Float
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String, nullable=False)
    status = Column(String, default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)
    risk_score = Column(Float, default=0.0)

    # One scan has many findings and many discovered assets.
    findings = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    assets = relationship(
        "Asset", back_populates="scan", cascade="all, delete-orphan"
    )