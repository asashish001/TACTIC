import datetime
from sqlalchemy import Column, Integer, String, Text, Date, DateTime, ForeignKey
from sqlalchemy.orm import relationship
from app.database.session import Base

class Case(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, index=True)
    case_number = Column(String(80), unique=True, index=True, nullable=False)
    name = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    incident_date = Column(Date, nullable=False)
    status = Column(String(30), nullable=False, default="open") # open, active, closed
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)

    created_by = relationship("User", back_populates="cases")
    evidence_items = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="case", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="case", cascade="all, delete-orphan")
    forensic_jobs = relationship("ForensicJob", back_populates="case", cascade="all, delete-orphan")
    correlations = relationship("ArtifactCorrelation", back_populates="case", cascade="all, delete-orphan")
    extracted_artifacts = relationship("ExtractedArtifact", back_populates="case", cascade="all, delete-orphan")
    browser_artifacts = relationship("BrowserArtifact", back_populates="case", cascade="all, delete-orphan")
    network_artifacts = relationship("NetworkArtifact", back_populates="case", cascade="all, delete-orphan")
    chain_of_custody = relationship("ChainOfCustody", back_populates="case", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="case", passive_deletes=True)
    vulnerability_matches = relationship("VulnerabilityMatch", back_populates="case", cascade="all, delete-orphan")
    threat_intel_indicators = relationship("ThreatIntelIndicator", back_populates="case", cascade="all, delete-orphan")
