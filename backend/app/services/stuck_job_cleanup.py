"""Service for cleaning up stuck forensic jobs and evidence records.

When background tasks crash or timeout, jobs can be left in a PROCESSING
state indefinitely. This module provides utilities to detect and clean up
such stuck records.
"""
import datetime
import logging
from datetime import timedelta, timezone

from sqlalchemy.orm import Session

from app.models.evidence import Evidence
from app.models.forensic_job import ForensicJob
from app.services.forensic_audit import record_audit

logger = logging.getLogger("tactic.cleanup")

STUCK_JOB_THRESHOLD_MINUTES = 30


def find_stuck_jobs(db: Session, threshold_minutes: int = STUCK_JOB_THRESHOLD_MINUTES) -> list[ForensicJob]:
    """Find forensic jobs stuck in PROCESSING state for too long.
    
    Args:
        db: Database session
        threshold_minutes: Minutes after which a PROCESSING job is considered stuck
        
    Returns:
        List of stuck ForensicJob records
    """
    cutoff_time = datetime.datetime.now(timezone.utc) - timedelta(minutes=threshold_minutes)
    
    stuck_jobs = db.query(ForensicJob).filter(
        ForensicJob.status == "PROCESSING",
        ForensicJob.started_at < cutoff_time
    ).all()
    
    return stuck_jobs


def cleanup_stuck_job(db: Session, job: ForensicJob, actor_id: int | None = None) -> ForensicJob:
    """Mark a stuck job as FAILED and clean up associated evidence state.
    
    Args:
        db: Database session
        job: The stuck ForensicJob to clean up
        actor_id: Optional user ID for audit logging
        
    Returns:
        Updated ForensicJob
    """
    job.status = "FAILED"
    job.stage_message = (
        f"Job timed out while processing at stage '{job.current_stage}'. "
        f"This may indicate a system resource issue or a processing error that "
        f"was not properly caught."
    )
    job.error_info = {
        "error": "Job stuck in PROCESSING state - likely due to process crash or timeout",
        "stage_at_timeout": job.current_stage,
        "progress_at_timeout": job.progress_percent,
        "cleanup_action": "auto_reset_to_failed"
    }
    job.completed_at = datetime.datetime.now(timezone.utc)
    
    if job.evidence_id:
        evidence = db.query(Evidence).filter(Evidence.id == job.evidence_id).first()
        if evidence:
            evidence.integrity_status = "PROCESSING_FAILED"
            record_audit(
                db,
                "EVIDENCE_PROCESSING_FAILED",
                f"Evidence '{evidence.filename}' marked as failed due to stuck job cleanup.",
                actor_id=actor_id,
                case_id=job.case_id,
                evidence_id=evidence.id,
                details={"job_id": str(job.id), "stage_at_failure": job.current_stage}
            )
    
    record_audit(
        db,
        "STUCK_JOB_CLEANUP",
        f"Job {job.id} cleaned up from stuck PROCESSING state at stage '{job.current_stage}'.",
        actor_id=actor_id,
        case_id=job.case_id,
        details={
            "job_id": str(job.id),
            "stage_at_cleanup": job.current_stage,
            "progress_at_cleanup": job.progress_percent,
            "evidence_id": job.evidence_id
        }
    )
    
    db.commit()
    logger.warning("Cleaned up stuck job %s at stage '%s'", job.id, job.current_stage)
    
    return job


def cleanup_all_stuck_jobs(db: Session, actor_id: int | None = None) -> list[ForensicJob]:
    """Find and clean up all stuck jobs.
    
    Args:
        db: Database session
        actor_id: Optional user ID for audit logging
        
    Returns:
        List of cleaned up ForensicJob records
    """
    stuck_jobs = find_stuck_jobs(db)
    cleaned_jobs = []
    
    for job in stuck_jobs:
        try:
            cleaned_job = cleanup_stuck_job(db, job, actor_id=actor_id)
            cleaned_jobs.append(cleaned_job)
        except Exception as exc:
            logger.error("Failed to clean up stuck job %s: %s", job.id, exc)
            db.rollback()
    
    if cleaned_jobs:
        logger.info("Cleaned up %s stuck jobs", len(cleaned_jobs))
    
    return cleaned_jobs


def get_stuck_jobs_summary(db: Session) -> dict:
    """Get a summary of stuck jobs for monitoring.
    
    Returns:
        Dictionary with stuck job statistics
    """
    stuck_jobs = find_stuck_jobs(db)
    
    stages = {}
    for job in stuck_jobs:
        stage = job.current_stage
        if stage not in stages:
            stages[stage] = 0
        stages[stage] += 1
    
    return {
        "total_stuck": len(stuck_jobs),
        "by_stage": stages,
        "oldest_stuck": min(
            (job.started_at for job in stuck_jobs if job.started_at),
            default=None
        )
    }
