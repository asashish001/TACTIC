import datetime
from sqlalchemy import Column, Integer, String, BigInteger, DateTime, ForeignKey, JSON, UniqueConstraint
from sqlalchemy.orm import relationship
from app.database.session import Base

class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("case_id", "sha256", name="uq_evidence_case_sha256"),)

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    filename = Column(String(255), nullable=False)
    stored_path = Column(String(500), nullable=False, unique=True)
    file_size = Column(BigInteger, nullable=False)
    extension = Column(String(20), nullable=False, default="")
    md5 = Column(String(32), nullable=False)
    sha1 = Column(String(40), nullable=True, index=True)
    sha256 = Column(String(64), nullable=False, index=True)
    detected_mime = Column(String(100), nullable=False, default="application/octet-stream")
    extracted_metadata = Column(JSON, nullable=False, default=dict)
    ingested_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    preservation_status = Column(String(30), nullable=False, default="preserved")
    # Updated before every analysis attempt; the original file is never changed.
    # Valid values: VERIFIED, TAMPERED, MISSING, PROCESSING_FAILED
    integrity_status = Column(String(20), nullable=False, default="VERIFIED")

    case = relationship("Case", back_populates="evidence_items")
    findings = relationship("Finding", back_populates="evidence", cascade="all, delete-orphan")
    hashes = relationship("EvidenceHash", back_populates="evidence", cascade="all, delete-orphan")
    browser_artifacts = relationship("BrowserArtifact", back_populates="evidence", cascade="all, delete-orphan")
    network_artifacts = relationship("NetworkArtifact", back_populates="evidence", cascade="all, delete-orphan")
    extracted_artifacts = relationship("ExtractedArtifact", back_populates="evidence", cascade="all, delete-orphan")
