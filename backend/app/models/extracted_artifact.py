import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.case import Case
    from app.models.evidence import Evidence
from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class ExtractedArtifact(Base):
    """A forensic artifact extracted via Hugging Face Transformers or rule-based fallback."""
    __tablename__ = "extracted_artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=False, index=True)
    source_evidence_id: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    artifact_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    value: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    extractor: Mapped[str] = mapped_column(String(50), nullable=False, default="regex-fallback")
    context_snippet: Mapped[str | None] = mapped_column(Text, nullable=True)
    start_char: Mapped[int | None] = mapped_column(Integer, nullable=True)
    end_char: Mapped[int | None] = mapped_column(Integer, nullable=True)
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    extracted_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    evidence: Mapped["Evidence"] = relationship("Evidence", back_populates="extracted_artifacts")
    case: Mapped["Case"] = relationship("Case", back_populates="extracted_artifacts")

    @property
    def evidence_filename(self) -> str | None:
        return self.evidence.filename if self.evidence else None
