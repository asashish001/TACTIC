"""Persistent forensic-integrity, audit, and timeline records."""
import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.database.session import Base


def utcnow():
    return datetime.datetime.now(datetime.timezone.utc)


class EvidenceHash(Base):
    __tablename__ = "evidence_hashes"

    id = Column(Integer, primary_key=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    algorithm = Column(String(16), nullable=False)
    digest = Column(String(128), nullable=False, index=True)
    calculated_at = Column(DateTime, default=utcnow, nullable=False)

    evidence = relationship("Evidence", back_populates="hashes")


class ChainOfCustody(Base):
    __tablename__ = "chain_of_custody"

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    actor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(80), nullable=False)
    description = Column(Text, nullable=False)
    hash_snapshot = Column(String(64), nullable=True)
    occurred_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    details = Column(JSON, nullable=False, default=dict)

    case = relationship("Case", back_populates="chain_of_custody")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True)
    actor_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="SET NULL"), nullable=True, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    description = Column(Text, nullable=False)
    occurred_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    details = Column(JSON, nullable=False, default=dict)

    case = relationship("Case", back_populates="audit_logs")


class TimelineEvent(Base):
    __tablename__ = "timeline_events"

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="SET NULL"), nullable=True, index=True)
    event = Column(Text, nullable=False)
    timestamp = Column(String(80), nullable=False, index=True)
    evidence_source = Column(String(255), nullable=False)
    priority = Column(String(20), nullable=False, default="info")
    event_type = Column(String(60), nullable=False, default="derived")
    details = Column(JSON, nullable=False, default=dict)
    generated_at = Column(DateTime, default=utcnow, nullable=False)

    case = relationship("Case", back_populates="timeline_events")
