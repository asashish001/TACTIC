"""TACTIC Asynchronous Forensic Job Runner Service."""
import datetime
import logging
import traceback
import uuid as _uuid
from typing import Any
from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.models.forensic_job import ForensicJob
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.services.integrity_verification import (
    VERIFIED,
    evidence_disk_path,
    verify_case_evidence_integrity,
)
from app.services.settings_service import get_correlation_config

logger = logging.getLogger("tactic.job_runner")

STAGES = [
    ("upload", 10.0, "Evidence uploaded & job queued for background analysis."),
    ("hashing", 20.0, "Executing cryptographic hash verification (MD5/SHA256) & audit trail logging..."),
    ("preprocessing", 35.0, "Preprocessing file metadata and structural content..."),
    ("artifact extraction", 50.0, "Running Hugging Face Transformers & rule-based entity extraction..."),
    ("anomaly detection", 65.0, "Executing Isolation Forest anomaly classifier & XAI feature attribution..."),
    ("correlation", 80.0, "Compiling multi-factor cross-evidence correlation graph..."),
    ("timeline", 90.0, "Reconstructing multi-source forensic timeline stream..."),
    ("report", 100.0, "Compiling formal PDF forensic audit report...")
]


def create_job(
    db: Session,
    case_id: int,
    evidence_id: int | None = None,
    job_type: str = "ANALYSIS_PIPELINE"
) -> ForensicJob:
    """Create and persist a new ForensicJob in QUEUED status."""
    job = ForensicJob(
        case_id=case_id,
        evidence_id=evidence_id,
        job_type=job_type,
        status="QUEUED",
        current_stage="upload",
        progress_percent=10.0,
        stage_message="Job queued for processing.",
        retry_count=0
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def _update_job_stage(
    db: Session,
    job_id: str | _uuid.UUID,
    stage: str,
    progress: float,
    message: str,
    status: str = "PROCESSING"
):
    """Helper to update job progress in database immediately."""
    job = db.query(ForensicJob).filter(ForensicJob.id == job_id).first()
    if job:
        job.status = status
        job.current_stage = stage
        job.progress_percent = progress
        job.stage_message = message
        if status == "PROCESSING" and not job.started_at:
            job.started_at = datetime.datetime.now(datetime.timezone.utc)
        elif status in ("COMPLETED", "FAILED", "PARTIAL"):
            job.completed_at = datetime.datetime.now(datetime.timezone.utc)
        db.commit()


def execute_job_pipeline(job_id: str | _uuid.UUID, actor_id: int | None = None, db: Session | None = None):
    """Execute complete 8-stage forensic pipeline asynchronously in background worker thread."""
    should_close_db = False
    if db is None:
        db = SessionLocal()
        should_close_db = True

    try:
        job = db.query(ForensicJob).filter(ForensicJob.id == job_id).first()
        if not job:
            logger.error("Job ID %s not found in database.", job_id)
            return

        evidence_id = job.evidence_id
        case_id = job.case_id

        # Stage 1: upload (10%)
        _update_job_stage(db, job_id, "upload", 10.0, "Job initialized.")

        # Stage 2: hashing (20%)
        _update_job_stage(db, job_id, "hashing", 20.0, "Executing cryptographic hash verification & audit logging...")
        if evidence_id:
            evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
            if not evidence:
                raise ValueError(f"Target Evidence ID {evidence_id} not found.")
            case_evidence = [evidence]
        else:
            case_evidence = db.query(Evidence).filter(Evidence.case_id == case_id).all()

        if case_evidence:
            integrity_report = verify_case_evidence_integrity(db, case_evidence, actor_id=actor_id)
            integrity_report.record_report(db, actor_id=actor_id)
            if not integrity_report.all_passed:
                failed_details = ", ".join(
                    f"'{item.filename}' ({res.status})"
                    for item, res in integrity_report.failed_items
                )
                raise ValueError(
                    f"Integrity verification failed for {integrity_report.failed_count} evidence file(s): {failed_details}"
                )

        # Stage 3: preprocessing (35%)
        _update_job_stage(db, job_id, "preprocessing", 35.0, "Preprocessing evidence metadata and text content...")
        
        # Stage 4: artifact extraction (50%)
        _update_job_stage(db, job_id, "artifact extraction", 50.0, "Running Hugging Face Transformers & rule-based entity extraction...")
        from app.services.artifact_extraction import extract_and_store_artifacts
        for ev in case_evidence:
            try:
                extract_and_store_artifacts(ev, db)
            except Exception as exc:
                logger.warning("Artifact extraction partial warning for Evidence %s: %s", ev.id, exc)

        # Stage 5: anomaly detection (65%)
        _update_job_stage(db, job_id, "anomaly detection", 65.0, "Executing Isolation Forest anomaly classifier & XAI feature attribution...")
        from app.ai.risk_analyzer import run_risk_analysis
        for ev in case_evidence:
            file_abs_path = evidence_disk_path(ev)
            db.query(Finding).filter(Finding.evidence_id == ev.id).delete()
            findings = run_risk_analysis(ev, file_abs_path, db=db)
            for f in findings:
                db.add(f)
        db.commit()

        # Stage 6: correlation (80%)
        _update_job_stage(db, job_id, "correlation", 80.0, "Compiling multi-factor cross-evidence correlation graph...")
        from app.services.correlation_engine import correlate_case_artifacts
        cfg = get_correlation_config(db)
        correlate_case_artifacts(case_id, db, weights=cfg["weights"], time_window_seconds=cfg["time_window_seconds"])

        # Stage 7: timeline (90%)
        _update_job_stage(db, job_id, "timeline", 90.0, "Reconstructing multi-source forensic timeline stream...")
        from app.services.timeline_builder import build_forensic_timeline
        build_forensic_timeline(case_id, db, target_timezone="UTC")

        # Stage 8: report (100%)
        _update_job_stage(db, job_id, "report", 95.0, "Compiling formal PDF forensic audit report...")
        try:
            from app.services.report_service import generate_report
            generate_report(case_id=case_id, fmt="pdf", db=db, actor_id=actor_id)
        except Exception as rep_exc:
            logger.warning("Report generation partial warning for Case %s: %s", case_id, rep_exc)

        # Complete
        _update_job_stage(db, job_id, "report", 100.0, "All forensic analysis stages completed successfully.", status="COMPLETED")
        logger.info("Job ID %s finished execution successfully.", job_id)

    except Exception as exc:
        err_detail = {
            "error": str(exc),
            "traceback": traceback.format_exc(),
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat()
        }
        logger.error("Job ID %s failed: %s\n%s", job_id, exc, traceback.format_exc())
        
        db_job = db.query(ForensicJob).filter(ForensicJob.id == job_id).first()
        if db_job:
            db_job.status = "FAILED"
            db_job.stage_message = f"Job failed at stage '{db_job.current_stage}': {str(exc)}"
            db_job.error_info = err_detail
            db_job.completed_at = datetime.datetime.now(datetime.timezone.utc)
            db.commit()
    finally:
        if should_close_db:
            db.close()


def retry_job(db: Session, job_id: str | _uuid.UUID) -> ForensicJob:
    """Reset a failed or partial job to QUEUED and increment retry count."""
    job = db.query(ForensicJob).filter(ForensicJob.id == job_id).first()
    if not job:
        raise ValueError("Job not found.")

    job.status = "QUEUED"
    job.current_stage = "upload"
    job.progress_percent = 10.0
    job.stage_message = "Job queued for retry."
    job.error_info = None
    job.retry_count += 1
    job.started_at = None
    job.completed_at = None
    db.commit()
    db.refresh(job)
    return job
