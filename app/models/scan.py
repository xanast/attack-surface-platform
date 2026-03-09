from sqlalchemy import Column, Integer, String, DateTime, ForeignKey
from datetime import datetime

from app.db.database import Base


class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True)

    target_id = Column(Integer, ForeignKey("targets.id"))

    headers_score = Column(Integer)
    risk_score = Column(Integer)
    risk_level = Column(String)

    tls_version = Column(String)

    findings = Column(String)
    ports = Column(String)
    tech = Column(String)
    subdomains = Column(String)

    created_at = Column(DateTime, default=datetime.utcnow)