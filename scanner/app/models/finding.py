from sqlalchemy import Column, Integer, String, ForeignKey, Text
from sqlalchemy.orm import relationship

from app.database.database import Base


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)

    vulnerability_name = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # info, low, medium, high, critical
    evidence = Column(Text, nullable=True)
    endpoint = Column(String, nullable=True)
    recommendation = Column(Text, nullable=True)
    module = Column(String, nullable=True)  # which module produced this finding

    scan = relationship("Scan", back_populates="findings")