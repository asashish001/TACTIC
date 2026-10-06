import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class ArtifactCorrelation(Base):
    """Stores cross-evidence artifact relationship correlations with normalized scores and explainable reasons."""
    __tablename__ = "artifact_correlations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    artifact_a_type: Mapped[str] = mapped_column(String(50), nullable=False)
    artifact_a_id: Mapped[str] = mapped_column(String(100), nullable=False)
    artifact_a_label: Mapped[str] = mapped_column(String(255), nullable=False)

    artifact_b_type: Mapped[str] = mapped_column(String(50), nullable=False)
    artifact_b_id: Mapped[str] = mapped_column(String(100), nullable=False)
    artifact_b_label: Mapped[str] = mapped_column(String(255), nullable=False)

    correlation_type: Mapped[str] = mapped_column(String(50), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    strength_category: Mapped[str] = mapped_column(String(20), nullable=False, default="Weak") # Weak (0.0-0.39), Moderate (0.40-0.69), Strong (0.70-1.00)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    components: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    
    timestamp: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case: Mapped["Case"] = relationship("Case", back_populates="correlations")
