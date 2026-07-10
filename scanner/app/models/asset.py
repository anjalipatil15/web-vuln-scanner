from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime

from app.database.database import Base


class Asset(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)

    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    url = Column(String, nullable=False)

    method = Column(String, default="GET")

    parameters = Column(String, nullable=True)

    forms_found = Column(Boolean, default=False)

    discovered_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="assets")