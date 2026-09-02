import datetime

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.database.session import Base


class VulnerabilityMatch(Base):
    """A CVE correlation produced from a software indicator in case evidence."""

    __tablename__ = "vulnerability_matches"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    cve_id = Column(String(30), nullable=False, index=True)
    product = Column(String(200), nullable=False)
    version = Column(String(80), nullable=True)
    cpe_uri = Column(String(500), nullable=True)
    severity = Column(String(20), nullable=False, default="info")
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    is_kev = Column(Boolean, nullable=False, default=False)
    risk_score = Column(Integer, nullable=False, default=0)
    description = Column(Text, nullable=False, default="")
    references = Column(JSON, nullable=False, default=list)
    source_data = Column(JSON, nullable=False, default=dict)
    matched_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case = relationship("Case", back_populates="vulnerability_matches")
    evidence = relationship("Evidence")


class ThreatIntelIndicator(Base):
    """Observed IOC with its provider-backed or local enrichment result."""

    __tablename__ = "threat_intel_indicators"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator_type = Column(String(30), nullable=False)
    value = Column(String(500), nullable=False, index=True)
    provider = Column(String(100), nullable=False, default="local extraction")
    verdict = Column(String(30), nullable=False, default="unknown")
    confidence = Column(Float, nullable=False, default=0.0)
    details = Column(JSON, nullable=False, default=dict)
    last_checked = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case = relationship("Case", back_populates="threat_intel_indicators")
    evidence = relationship("Evidence")
