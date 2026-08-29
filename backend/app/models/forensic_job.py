import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, JSON
from sqlalchemy.orm import relationship
from app.database.session import Base
from app.database.types import UUID


class ForensicJob(Base):
    """Tracks asynchronous background forensic analysis jobs, stage progress, errors, and status."""
    __tablename__ = "forensic_jobs"

    id = Column(UUID(), primary_key=True, default=UUID.create_default())
    case_id = Column(Integer, ForeignKey("cases.id", ondelete="CASCADE"), nullable=False, index=True)
    evidence_id = Column(Integer, ForeignKey("evidence.id", ondelete="CASCADE"), nullable=True, index=True)
    
    job_type = Column(String(50), nullable=False, default="ANALYSIS_PIPELINE")
    status = Column(String(20), nullable=False, default="QUEUED", index=True) # QUEUED, PROCESSING, COMPLETED, FAILED, PARTIAL
    current_stage = Column(String(50), nullable=False, default="upload") # upload, hashing, preprocessing, artifact extraction, anomaly detection, correlation, timeline, report
    progress_percent = Column(Float, nullable=False, default=0.0) # 0.0 to 100.0
    stage_message = Column(Text, nullable=False, default="Job queued for processing.")
    
    error_info = Column(JSON, nullable=True) # Traceback / error details
    retry_count = Column(Integer, nullable=False, default=0)

    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc), nullable=False)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    case = relationship("Case", backref="forensic_jobs")
    evidence = relationship("Evidence", backref="forensic_jobs")
