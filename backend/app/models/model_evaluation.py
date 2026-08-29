import datetime
from sqlalchemy import Column, Integer, String, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base


class ModelEvaluationRun(Base):
    """Stores model evaluation metadata, dataset info, confusion matrix, statistical metrics, and resource usage."""
    __tablename__ = "model_evaluation_runs"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(100), nullable=False, index=True)
    model_version = Column(String(30), nullable=False, default="2.0.0")
    dataset_name = Column(String(100), nullable=False, default="TACTIC Labeled Forensic Benchmark v1")
    dataset_size = Column(Integer, nullable=False)
    has_ground_truth = Column(Integer, nullable=False, default=1) # 1 if ground truth present, 0 if missing
    
    features_used = Column(JSON, nullable=False, default=list) # List of feature names
    threshold = Column(Float, nullable=False, default=0.80)
    
    training_date = Column(DateTime, nullable=True)
    evaluation_date = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    
    metrics = Column(JSON, nullable=False, default=dict) # Stores accuracy, precision, recall, f1, roc_auc, tp, tn, fp, fn, confusion_matrix, latency_ms, cpu_pct, memory_mb, scalability_mb_per_sec
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)

    creator = relationship("User", backref="model_evaluations")
