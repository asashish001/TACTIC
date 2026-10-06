import datetime

from sqlalchemy import JSON, DateTime, Float, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database.session import Base


class ModelEvaluationRun(Base):
    """Stores model evaluation metadata, dataset info, confusion matrix, statistical metrics, and resource usage."""
    __tablename__ = "model_evaluation_runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    model_version: Mapped[str] = mapped_column(String(30), nullable=False, default="2.0.0")
    dataset_name: Mapped[str] = mapped_column(String(100), nullable=False, default="TACTIC Labeled Forensic Benchmark v1")
    dataset_size: Mapped[int] = mapped_column(Integer, nullable=False)
    has_ground_truth: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    
    features_used: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=list)
    threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.80)
    
    training_date: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    evaluation_date: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    
    metrics: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    created_by_id: Mapped[int | None] = mapped_column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    creator: Mapped["User"] = relationship("User", backref="model_evaluations")
