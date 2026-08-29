import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False, default="info") # critical, high, medium, low, info
    confidence = Column(Float, nullable=False, default=1.0)
    risk_score = Column(Integer, nullable=False, default=0) # 0 to 100
    threat_category = Column(String(100), nullable=False, default="General Analysis")
    reason = Column(Text, nullable=False)
    recommendation = Column(Text, nullable=False)
    details = Column(JSON, nullable=False, default=dict)
    # Human-in-the-loop review fields
    review_status = Column(String(20), nullable=False, default="pending")  # pending, approved, rejected, escalated
    reviewed_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at = Column(DateTime, nullable=True)
    review_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case = relationship("Case", back_populates="findings")
    evidence = relationship("Evidence", back_populates="findings")
    reviewed_by = relationship("User", foreign_keys=[reviewed_by_id])
