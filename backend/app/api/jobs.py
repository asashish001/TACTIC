import uuid as _uuid
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from typing import Any

from app.database.session import get_db
from app.models.case import Case
from app.models.forensic_job import ForensicJob
from app.models.user import User
from app.auth.security import get_current_user, require_case_access, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_HEAVY
from app.services.job_runner import execute_job_pipeline, retry_job

router = APIRouter(prefix="/api/jobs", tags=["Forensic Background Jobs"])


class JobStatusResponse(BaseModel):
    id: str | _uuid.UUID
    case_id: int
    evidence_id: int | None = None
    job_type: str
    status: str
    current_stage: str
    progress_percent: float
    stage_message: str
    error_info: dict[str, Any] | None = None
    retry_count: int
    created_at: Any
    started_at: Any | None = None
    completed_at: Any | None = None


@router.get("/case/{case_id}", response_model=list[JobStatusResponse])
@limiter.limit(RATE_LIMIT_READ)
def get_case_jobs(request: Request, 
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all background jobs for a case file."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    
    jobs = db.query(ForensicJob).filter(ForensicJob.case_id == case_id).order_by(ForensicJob.created_at.desc()).all()
    return jobs


@router.get("/{job_id}", response_model=JobStatusResponse)
@limiter.limit(RATE_LIMIT_READ)
def get_job_status(request: Request, 
    job_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Query real-time status and progress of an asynchronous forensic job."""
    job = db.query(ForensicJob).filter(ForensicJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    require_case_access(job.case, current_user)
    return job


@router.post("/{job_id}/retry", response_model=JobStatusResponse)
@limiter.limit(RATE_LIMIT_HEAVY)
def trigger_retry_job(request: Request, 
    job_id: str,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Safely retry a failed or partial forensic job."""
    job = db.query(ForensicJob).filter(ForensicJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    require_case_access(job.case, current_user)

    try:
        updated_job = retry_job(db, job_id)
        background_tasks.add_task(execute_job_pipeline, job_id, current_user.id)
        return updated_job
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
