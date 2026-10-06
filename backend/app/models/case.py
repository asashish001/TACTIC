import datetime

from sqlalchemy import Date, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Case(Base):
    __tablename__ = "cases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_number: Mapped[str] = mapped_column(String(80), unique=True, index=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    incident_date: Mapped[datetime.date] = mapped_column(Date, nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False, default="open")
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    
    created_by_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    created_by: Mapped["User"] = relationship("User", back_populates="cases")
    evidence_items: Mapped[list["Evidence"]] = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    reports: Mapped[list["Report"]] = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    forensic_jobs: Mapped[list["ForensicJob"]] = relationship("ForensicJob", back_populates="case", cascade="all, delete-orphan")
    correlations: Mapped[list["ArtifactCorrelation"]] = relationship("ArtifactCorrelation", back_populates="case", cascade="all, delete-orphan")
    extracted_artifacts: Mapped[list["ExtractedArtifact"]] = relationship("ExtractedArtifact", back_populates="case", cascade="all, delete-orphan")
    browser_artifacts: Mapped[list["BrowserArtifact"]] = relationship("BrowserArtifact", back_populates="case", cascade="all, delete-orphan")
    network_artifacts: Mapped[list["NetworkArtifact"]] = relationship("NetworkArtifact", back_populates="case", cascade="all, delete-orphan")
    chain_of_custody: Mapped["ChainOfCustody"] = relationship("ChainOfCustody", back_populates="case", cascade="all, delete-orphan")
    timeline_events: Mapped[list["TimelineEvent"]] = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    audit_logs: Mapped[list["AuditLog"]] = relationship("AuditLog", back_populates="case", passive_deletes=True)
    vulnerability_matches: Mapped[list["VulnerabilityMatch"]] = relationship("VulnerabilityMatch", back_populates="case", cascade="all, delete-orphan")
    threat_intel_indicators: Mapped[list["ThreatIntelIndicator"]] = relationship("ThreatIntelIndicator", back_populates="case", cascade="all, delete-orphan")
