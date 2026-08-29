import datetime

from sqlalchemy import Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship

from app.database.session import Base


class BrowserArtifact(Base):
    """A privacy-preserving browser artifact extracted from submitted evidence."""
    __tablename__ = "browser_artifacts"

    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    browser = Column(String(40), nullable=False)
    artifact_type = Column(String(40), nullable=False, index=True)
    url = Column(Text, nullable=True)
    domain = Column(String(255), nullable=True, index=True)
    title = Column(Text, nullable=True)
    timestamp = Column(String(80), nullable=True, index=True)
    details = Column(JSON, nullable=False, default=dict)
    extracted_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    evidence = relationship("Evidence", back_populates="browser_artifacts")
