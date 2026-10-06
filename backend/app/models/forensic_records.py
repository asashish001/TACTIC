"""Persistent forensic-integrity, audit, and timeline records."""
import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class EvidenceHash(Base):
    __tablename__ = "evidence_hashes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    evidence_id: Mapped[int] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    algorithm: Mapped[str] = mapped_column(String(16), nullable=False)
    digest: Mapped[str] = mapped_column(String(128), nullable=False, index=True)
    calculated_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    evidence: Mapped["Evidence"] = relationship("Evidence", back_populates="hashes")


class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    hash_snapshot: Mapped[str | None] = mapped_column(String(64), nullable=True)
    occurred_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)

    case: Mapped["Case"] = relationship("Case", back_populates="chain_of_custody")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    case_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    occurred_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)

    case: Mapped["Case"] = relationship("Case", back_populates="audit_logs")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    event: Mapped[str] = mapped_column(Text, nullable=False)
    timestamp: Mapped[str] = mapped_column(String(80), nullable=False, index=True)
    evidence_source: Mapped[str] = mapped_column(String(255), nullable=False)
    priority: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    event_type: Mapped[str] = mapped_column(String(60), nullable=False, default="derived")
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    generated_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    case: Mapped["Case"] = relationship("Case", back_populates="timeline_events")
