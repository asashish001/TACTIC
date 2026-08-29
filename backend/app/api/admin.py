import math
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.report import Report
from app.schemas.user import UserResponse
from sqlalchemy import func
from app.auth.security import RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_WRITE
from app.services.stuck_job_cleanup import cleanup_all_stuck_jobs, get_stuck_jobs_summary

router = APIRouter(prefix="/api/admin", tags=["Admin Console"])

# Require admin role for all admin operations
admin_checker = Depends(RoleChecker(["admin"]))

class PaginatedUserResponse(BaseModel):
    items: list[UserResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

@router.get("/users", response_model=PaginatedUserResponse)
@limiter.limit(RATE_LIMIT_READ)
def list_users(request: Request, 
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_admin: User = admin_checker
):
    """Retrieve registered accounts with pagination (Admin privilege only)."""
    page_size = min(max(page_size, 1), 200)
    total = db.query(User).count()
    total_pages = max(1, math.ceil(total / page_size))
    items = db.query(User).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedUserResponse(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)

@router.delete("/users/{user_id}", status_code=status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_WRITE)
def delete_user(request: Request, 
    user_id: int,
    db: Session = Depends(get_db),
    current_admin: User = admin_checker
):
    """Delete a user account by ID (Admin privilege only)."""
    if user_id == current_admin.id:
        raise HTTPException(status_code=400, detail="An administrator cannot delete their own active account.")
        
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")
        
    db.delete(user)
    db.commit()
    return {"message": "User account deleted successfully."}

@router.get("/stats")
@limiter.limit(RATE_LIMIT_READ)
def get_system_stats(request: Request, 
    db: Session = Depends(get_db),
    current_admin: User = admin_checker
):
    """Generate global system health metrics, storage calculations, and model execution tallies (Admin privilege only)."""
    total_users = db.query(User).count()
    total_cases = db.query(Case).count()
    total_evidence = db.query(Evidence).count()
    total_findings = db.query(Finding).count()
    total_reports = db.query(Report).count()
    
    # Calculate storage footprint using SQL aggregation (not loading all rows into memory)
    total_bytes = db.query(func.sum(Evidence.file_size)).scalar() or 0
    
    # Count findings by severity
    severity_breakdown = {
        "critical": db.query(Finding).filter(Finding.severity == "critical").count(),
        "high": db.query(Finding).filter(Finding.severity == "high").count(),
        "medium": db.query(Finding).filter(Finding.severity == "medium").count(),
        "low": db.query(Finding).filter(Finding.severity == "low").count(),
        "info": db.query(Finding).filter(Finding.severity == "info").count()
    }
    
    return {
        "metrics": {
            "total_users": total_users,
            "total_cases": total_cases,
            "total_evidence": total_evidence,
            "total_findings": total_findings,
            "total_reports": total_reports,
            "storage_used_bytes": total_bytes
        },
        "findings_by_severity": severity_breakdown
    }


@router.get("/stuck-jobs")
@limiter.limit(RATE_LIMIT_READ)
def get_stuck_jobs(request: Request, 
    db: Session = Depends(get_db),
    current_admin: User = admin_checker
):
    """Get summary of stuck forensic jobs (Admin privilege only)."""
    return get_stuck_jobs_summary(db)


@router.post("/cleanup-stuck-jobs", status_code=status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_WRITE)
def trigger_cleanup_stuck_jobs(request: Request, 
    db: Session = Depends(get_db),
    current_admin: User = admin_checker
):
    """Clean up stuck forensic jobs that are stuck in PROCESSING state (Admin privilege only)."""
    cleaned_jobs = cleanup_all_stuck_jobs(db, actor_id=current_admin.id)
    return {
        "message": f"Cleaned up {len(cleaned_jobs)} stuck job(s).",
        "cleaned_count": len(cleaned_jobs),
        "job_ids": [str(job.id) for job in cleaned_jobs]
    }
