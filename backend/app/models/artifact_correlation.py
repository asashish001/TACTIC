import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base


class ArtifactCorrelation(Base):
    """Stores cross-evidence artifact relationship correlations with normalized scores and explainable reasons."""
    __tablename__ = "artifact_correlations"

    id = Column(Integer, primary_key=True, index=True)
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    
    artifact_a_type = Column(String(50), nullable=False)
    artifact_a_id = Column(String(100), nullable=False)
    artifact_a_label = Column(String(255), nullable=False)

    artifact_b_type = Column(String(50), nullable=False)
    artifact_b_id = Column(String(100), nullable=False)
    artifact_b_label = Column(String(255), nullable=False)

    correlation_type = Column(String(50), nullable=False) # IP_MATCH, USERNAME_MATCH, DOMAIN_MATCH, PERSON_MATCH, EVENT_MATCH, MULTI_FACTOR
    score = Column(Float, nullable=False, default=0.0) # 0.0 to 1.0
    strength_category = Column(String(20), nullable=False, default="Weak") # Weak (0.0-0.39), Moderate (0.40-0.69), Strong (0.70-1.00)
    reason = Column(Text, nullable=False)
    components = Column(JSON, nullable=False, default=dict) # time_similarity, entity_similarity, source_relationship, event_relationship
    
    timestamp = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)

    case = relationship("Case", backref="correlations")
