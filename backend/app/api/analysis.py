from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.user import User
from app.schemas.finding import FindingResponse, FindingReviewRequest
from app.auth.security import get_current_user, require_case_access, RoleChecker
from app.config import limiter, RATE_LIMIT_HEAVY, RATE_LIMIT_READ, RATE_LIMIT_WRITE
from app.services.integrity_verification import (
    VERIFIED,
    evidence_disk_path,
    verify_case_evidence_integrity,
)
from app.services.job_runner import create_job, execute_job_pipeline

router = APIRouter(prefix="/api/analyze", tags=["AI Analysis Engine"])


class AnalysisRequest(BaseModel):
    evidence_id: int = Field(...)
    sync: bool = Field(default=False) # Set sync=True for synchronous blocking execution (e.g., tests)


class JobQueuedResponse(BaseModel):
    job_id: str
    status: str = "QUEUED"
    message: str = "Forensic analysis job queued in background."
    current_stage: str = "upload"
    progress_percent: float = 10.0


@router.post("", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit(RATE_LIMIT_HEAVY)
def trigger_analysis(request: Request, 
    payload: AnalysisRequest,
    background_tasks: BackgroundTasks,
    response: Response,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Trigger non-blocking asynchronous background forensic analysis job, returning immediately with job_id."""
    evidence = db.query(Evidence).filter(Evidence.id == payload.evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    require_case_access(evidence.case, current_user)

    # 1. If payload.sync is True, execute synchronously for compatibility with tests / CLI
    if payload.sync:
        response.status_code = status.HTTP_201_CREATED
        case_evidence = db.query(Evidence).filter(Evidence.case_id == evidence.case_id).all()
        integrity_report = verify_case_evidence_integrity(db, case_evidence, actor_id=current_user.id)
        integrity_report.record_report(db, actor_id=current_user.id)
        db.commit()
        if not integrity_report.all_passed:
            failed_details = ", ".join(
                f"'{item.filename}' ({res.status})"
                for item, res in integrity_report.failed_items
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Integrity verification failed for {integrity_report.failed_count} evidence file(s): {failed_details}."
            )
        file_absolute_path = evidence_disk_path(evidence)
        db.query(Finding).filter(Finding.evidence_id == evidence.id).delete()

        try:
            from app.ai.risk_analyzer import run_risk_analysis
            from app.services.artifact_extraction import extract_and_store_artifacts
            findings = run_risk_analysis(evidence, file_absolute_path, db=db)
            for finding in findings:
                db.add(finding)
            extract_and_store_artifacts(evidence, db)
            db.commit()
            for f in findings:
                db.refresh(f)
            return [FindingResponse.model_validate(f) for f in findings]
        except Exception as e:
            db.rollback()
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Analysis engine execution failed: {str(e)}"
            )

    # 2. Default: Create job and launch background pipeline asynchronously
    job = create_job(db, case_id=evidence.case_id, evidence_id=evidence.id, job_type="ANALYSIS_PIPELINE")
    background_tasks.add_task(execute_job_pipeline, job.id, current_user.id)

    return JobQueuedResponse(
        job_id=job.id,
        status="QUEUED",
        message="Forensic analysis job queued in background.",
        current_stage="upload",
        progress_percent=10.0
    )

# ── Human-in-the-Loop: Finding Review Endpoints ──

@router.get("/findings/{case_id}", response_model=list[FindingResponse])
@limiter.limit(RATE_LIMIT_READ)
def list_findings_for_review(request: Request,
    case_id: int,
    review_status: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List all findings for a case, optionally filtered by review status."""
    query = db.query(Finding).filter(Finding.case_id == case_id)
    if review_status:
        query = query.filter(Finding.review_status == review_status)
    return query.order_by(Finding.risk_score.desc()).all()


@router.put("/findings/{finding_id}/review", response_model=FindingResponse)
@limiter.limit(RATE_LIMIT_WRITE)
def review_finding(request: Request,
    finding_id: int,
    payload: FindingReviewRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Review a finding: approve, reject, or escalate. Records reviewer identity and timestamp."""
    import datetime
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found.")
    
    finding.review_status = payload.review_status
    finding.reviewed_by_id = current_user.id
    finding.reviewed_at = datetime.datetime.now(datetime.timezone.utc)
    finding.review_notes = payload.review_notes
    
    # Record audit trail
    from app.services.forensic_audit import record_audit
    record_audit(
        db, 
        "finding_reviewed", 
        f"Finding '{finding.title}' {payload.review_status} by {current_user.username}.",
        actor_id=current_user.id,
        case_id=finding.case_id,
        details={"finding_id": finding_id, "review_status": payload.review_status, "notes": payload.review_notes}
    )
    
    db.commit()
    db.refresh(finding)
    return finding


@router.post("/findings/{case_id}/bulk-review", response_model=list[FindingResponse])
@limiter.limit(RATE_LIMIT_WRITE)
def bulk_review_findings(request: Request,
    case_id: int,
    review_status: str,
    finding_ids: list[int] | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Bulk approve or reject multiple findings at once."""
    import datetime
    query = db.query(Finding).filter(Finding.case_id == case_id if finding_ids is None else Finding.id.in_(finding_ids))
    findings = query.all()
    
    now = datetime.datetime.now(datetime.timezone.utc)
    for f in findings:
        f.review_status = review_status
        f.reviewed_by_id = current_user.id
        f.reviewed_at = now
    
    db.commit()
    for f in findings:
        db.refresh(f)
    return findings


@router.get("/findings/{case_id}/review-summary")
@limiter.limit(RATE_LIMIT_READ)
def get_review_summary(request: Request,
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get review status summary for a case: counts by status."""
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    summary = {
        "total": len(findings),
        "pending": sum(1 for f in findings if f.review_status == "pending"),
        "approved": sum(1 for f in findings if f.review_status == "approved"),
        "rejected": sum(1 for f in findings if f.review_status == "rejected"),
        "escalated": sum(1 for f in findings if f.review_status == "escalated"),
        "all_reviewed": all(f.review_status != "pending" for f in findings) if findings else True,
        "review_ready_for_report": sum(1 for f in findings if f.review_status == "approved"),
    }
    return summary
