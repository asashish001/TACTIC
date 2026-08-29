import datetime
from sqlalchemy import Column, DateTime, Float, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.database.session import Base


class ExtractedArtifact(Base):
    """A forensic artifact extracted via Hugging Face Transformers or rule-based fallback."""
    __tablename__ = "extracted_artifacts"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    source_evidence_id = Column(Integer, nullable=False, index=True)
    artifact_type = Column(String(50), nullable=False, index=True)
    value = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False, default=1.0)
    extractor = Column(String(50), nullable=False, default="regex-fallback")
    context_snippet = Column(Text, nullable=True)
    start_char = Column(Integer, nullable=True)
    end_char = Column(Integer, nullable=True)
    details = Column(JSON, nullable=False, default=dict)
    extracted_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    evidence = relationship("Evidence", back_populates="extracted_artifacts")
