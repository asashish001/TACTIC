import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base
from app.database.types import UUID


class ForensicJob(Base):
    """Tracks asynchronous background forensic analysis jobs, stage progress, errors, and status."""
    __tablename__ = "forensic_jobs"

    id: Mapped[str] = mapped_column(UUID(), primary_key=True, default=UUID.create_default())
    case_id: Mapped[int] = mapped_column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    
    job_type: Mapped[str] = mapped_column(String(50), nullable=False, default="ANALYSIS_PIPELINE")
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="QUEUED", index=True)
    current_stage: Mapped[str] = mapped_column(String(50), nullable=False, default="upload")
    progress_percent: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    stage_message: Mapped[str] = mapped_column(Text, nullable=False, default="Job queued for processing.")
    
    error_info: Mapped[dict | list | None] = mapped_column(JSON, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    started_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)

    case: Mapped["Case"] = relationship("Case", back_populates="forensic_jobs")
    evidence: Mapped["Evidence"] = relationship("Evidence", backref="forensic_jobs")
