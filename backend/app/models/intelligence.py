import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class VulnerabilityMatch(Base):
    """A CVE correlation produced from a software indicator in case evidence."""

    __tablename__ = "vulnerability_matches"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    cve_id: Mapped[str] = mapped_column(String(30), nullable=False, index=True)
    product: Mapped[str] = mapped_column(String(200), nullable=False)
    version: Mapped[str | None] = mapped_column(String(80), nullable=True)
    cpe_uri: Mapped[str | None] = mapped_column(String(500), nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    cvss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    references: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=list)
    source_data: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    matched_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case: Mapped["Case"] = relationship("Case", back_populates="vulnerability_matches")
    evidence: Mapped["Evidence"] = relationship("Evidence")


class ThreatIntelIndicator(Base):
    """Observed IOC with its provider-backed or local enrichment result."""

    __tablename__ = "threat_intel_indicators"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    indicator_type: Mapped[str] = mapped_column(String(30), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    provider: Mapped[str] = mapped_column(String(100), nullable=False, default="local extraction")
    verdict: Mapped[str] = mapped_column(String(30), nullable=False, default="unknown")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    last_checked: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case: Mapped["Case"] = relationship("Case", back_populates="threat_intel_indicators")
    evidence: Mapped["Evidence"] = relationship("Evidence")
