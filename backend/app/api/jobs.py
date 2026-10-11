import uuid as _uuid
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.security import RoleChecker, get_current_user, require_case_access
from app.config import RATE_LIMIT_HEAVY, RATE_LIMIT_READ, limiter
from app.database.session import get_db
from app.models.case import Case
from app.models.forensic_job import ForensicJob
from app.models.user import User
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
    
    latest_jobs = {}
    for job in jobs:
        if job.evidence_id not in latest_jobs:
            latest_jobs[job.evidence_id] = job
            
    return list(latest_jobs.values())


@router.get("/case/{case_id}/stream")
@limiter.limit(RATE_LIMIT_READ)
def get_case_jobs_stream(request: Request, 
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Stream real-time background jobs status for a case file."""
    import asyncio
    import json
    from fastapi.responses import StreamingResponse

    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    async def event_generator():
        # First ping immediately
        padding = " " * 1024
        yield f": {padding}\n\n"
        await asyncio.sleep(0.1)

        while True:
            # Check if client disconnected
            if await request.is_disconnected():
                break

            # Need to clear session to get fresh DB data
            db.expire_all()
            
            jobs = db.query(ForensicJob).filter(ForensicJob.case_id == case_id).order_by(ForensicJob.created_at.desc()).all()
            
            latest_jobs = {}
            for job in jobs:
                if job.evidence_id not in latest_jobs:
                    latest_jobs[job.evidence_id] = job
            
            job_dicts = []
            for job in latest_jobs.values():
                job_dicts.append({
                    "id": str(job.id),
                    "case_id": job.case_id,
                    "evidence_id": job.evidence_id,
                    "job_type": job.job_type,
                    "status": job.status,
                    "current_stage": job.current_stage,
                    "progress_percent": job.progress_percent,
                    "stage_message": job.stage_message
                })
                
            yield f"data: {json.dumps(job_dicts)}\n\n"
            
            # Polling delay
            await asyncio.sleep(2)

    return StreamingResponse(event_generator(), media_type="text/event-stream")



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
