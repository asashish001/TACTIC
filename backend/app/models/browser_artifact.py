import datetime

from sqlalchemy import JSON, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class BrowserArtifact(Base):
    """A privacy-preserving browser artifact extracted from submitted evidence."""
    __tablename__ = "browser_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    browser: Mapped[str] = mapped_column(String(40), nullable=False)
    artifact_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    domain: Mapped[str | None] = mapped_column(String(255), nullable=True, index=True)
    title: Mapped[str | None] = mapped_column(Text, nullable=True)
    timestamp: Mapped[str | None] = mapped_column(String(80), nullable=True, index=True)
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    extracted_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    evidence: Mapped["Evidence"] = relationship("Evidence", back_populates="browser_artifacts")
    case: Mapped["Case"] = relationship("Case", back_populates="browser_artifacts")
