import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    ForeignKey,
    Integer,
    String,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Evidence(Base):
    __tablename__ = "evidence"
    __table_args__ = (UniqueConstraint("case_id", "sha256", name="uq_evidence_case_sha256"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    filename: Mapped[str] = mapped_column(String(255), nullable=False)
    stored_path: Mapped[str] = mapped_column(String(500), nullable=False, unique=True)
    file_size: Mapped[int] = mapped_column(BigInteger, nullable=False)
    extension: Mapped[str] = mapped_column(String(20), nullable=False, default="")
    md5: Mapped[str] = mapped_column(String(32), nullable=False)
    sha1: Mapped[str | None] = mapped_column(String(40), nullable=True, index=True)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    detected_mime: Mapped[str] = mapped_column(String(100), nullable=False, default="application/octet-stream")
    extracted_metadata: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    ingested_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    preservation_status: Mapped[str] = mapped_column(String(30), nullable=False, default="preserved")
    integrity_status: Mapped[str] = mapped_column(String(20), nullable=False, default="VERIFIED")

    case: Mapped["Case"] = relationship("Case", back_populates="evidence_items")
    findings: Mapped[list["Finding"]] = relationship("Finding", back_populates="evidence", cascade="all, delete-orphan")
    hashes: Mapped[list["EvidenceHash"]] = relationship("EvidenceHash", back_populates="evidence", cascade="all, delete-orphan")
    browser_artifacts: Mapped[list["BrowserArtifact"]] = relationship("BrowserArtifact", back_populates="evidence", cascade="all, delete-orphan")
    network_artifacts: Mapped[list["NetworkArtifact"]] = relationship("NetworkArtifact", back_populates="evidence", cascade="all, delete-orphan")
    extracted_artifacts: Mapped[list["ExtractedArtifact"]] = relationship("ExtractedArtifact", back_populates="evidence", cascade="all, delete-orphan")
