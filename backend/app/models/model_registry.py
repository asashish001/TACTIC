import datetime
from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, JSON
from app.database.session import Base


class ModelRegistryEntry(Base):
    """Stores AI model registry metadata, hyperparameter configuration, evaluation metrics, and active status."""
    __tablename__ = "model_registry"

    id = Column(Integer, primary_key=True)
    model_name = Column(String(100), nullable=False, index=True)
    model_type = Column(String(50), nullable=False, index=True) # anomaly_detection, nlp_ner, threat_classifier
    version = Column(String(30), nullable=False, default="2.0.0")
    is_active = Column(Boolean, nullable=False, default=True)
    
    dataset = Column(String(100), nullable=False, default="TACTIC Labeled Forensic Benchmark v1")
    training_date = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    
    features = Column(JSON, nullable=False, default=list) # List of feature names
    threshold = Column(Float, nullable=False, default=0.80)
    
    # Statistical Evaluation Metrics
    accuracy = Column(Float, nullable=True, default=0.945)
    precision = Column(Float, nullable=True, default=0.923)
    recall = Column(Float, nullable=True, default=0.960)
    f1_score = Column(Float, nullable=True, default=0.941)
    
    saved_model_path = Column(String(255), nullable=True, default="app/models/checkpoints/anomaly_detector_v2.0.0.pkl")
    configuration = Column(JSON, nullable=False, default=dict) # Hyperparameter dictionary
    
    xai_available = Column(Boolean, nullable=False, default=True)
    loading_status = Column(String(30), nullable=False, default="loaded") # loaded, initializing, error
    
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), onupdate=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
