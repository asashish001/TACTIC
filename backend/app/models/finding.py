import datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.case import Case
    from app.models.evidence import Evidence
    from app.models.user import User
from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="info")
    confidence: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)
    risk_score: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    threat_category: Mapped[str] = mapped_column(String(100), nullable=False, default="General Analysis")
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, nullable=False)
    details: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    review_status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    reviewed_by_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    reviewed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case: Mapped["Case"] = relationship("Case", back_populates="findings")
    evidence: Mapped["Evidence"] = relationship("Evidence", back_populates="findings")
    reviewed_by: Mapped["User"] = relationship("User", foreign_keys=[reviewed_by_id])

    @property
    def evidence_filename(self) -> str | None:
        return self.evidence.filename if self.evidence else None
