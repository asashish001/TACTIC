import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, String
from sqlalchemy.orm import Mapped, mapped_column

from app.database.session import Base


class ModelRegistryEntry(Base):
    """Stores AI model registry metadata, hyperparameter configuration, evaluation metrics, and active status."""
    __tablename__ = "model_registry"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    model_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(30), nullable=False, default="2.0.0")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    
    dataset: Mapped[str] = mapped_column(String(100), nullable=False, default="TACTIC Labeled Forensic Benchmark v1")
    training_date: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    
    features: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=list)
    threshold: Mapped[float] = mapped_column(Float, nullable=False, default=0.80)
    
    accuracy: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.945)
    precision: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.923)
    recall: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.960)
    f1_score: Mapped[float | None] = mapped_column(Float, nullable=True, default=0.941)
    
    saved_model_path: Mapped[str | None] = mapped_column(String(255), nullable=True, default="app/models/checkpoints/anomaly_detector_v2.0.0.pkl")
    configuration: Mapped[dict | list] = mapped_column(JSON, nullable=False, default=dict)
    
    xai_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    loading_status: Mapped[str] = mapped_column(String(30), nullable=False, default="loaded")
    
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
