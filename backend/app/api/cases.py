import shutil
from pathlib import Path
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import or_

from app.database.session import get_db
from app.models.case import Case
from app.models.intelligence import ThreatIntelIndicator, VulnerabilityMatch
from app.models.user import User
from app.schemas.case import CaseCreate, CaseUpdate, CaseResponse
from app.auth.security import get_current_user, require_case_access, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_WRITE
from app.services.forensic_audit import record_audit, record_custody

def _sanitize_like(value: str) -> str:
    """Escape SQL LIKE wildcards to prevent pattern injection in search queries."""
    bs = chr(92)
    return value.replace(bs, bs + bs).replace(chr(37), bs + chr(37)).replace(chr(95), bs + chr(95))

router = APIRouter(prefix="/api/cases", tags=["Cases"])

class CaseListResponse(BaseModel):
    """Paginated case list with metadata."""
    items: list[CaseResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=CaseListResponse)
@limiter.limit(RATE_LIMIT_READ)
def list_cases(request: Request, 
    q: str | None = None,
    status_filter: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve cases with pagination and optional search/filter.

    The database performs all filtering and pagination — no Python-side
    loading of the full result set.
    """
    # Clamp page_size to a sane range
    page_size = max(1, min(page_size, 200))
    page = max(1, page)

    query = db.query(Case)
    if current_user.role not in ("admin", "viewer"):
        query = query.filter(Case.created_by_id == current_user.id)
    if status_filter:
        query = query.filter(Case.status == status_filter)
    if q:
        query = query.filter(
            or_(
                Case.case_number.ilike(f"%{_sanitize_like(q)}%"),
                Case.name.ilike(f"%{_sanitize_like(q)}%"),
                Case.description.ilike(f"%{_sanitize_like(q)}%")
            )
        )

    total = query.count()
    total_pages = max(1, -(-total // page_size))

    items = (
        query
        .order_by(Case.created_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return CaseListResponse(
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )

@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_WRITE)
def create_case(request: Request, 
    case_in: CaseCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Create a new case instance owned by the current authorized user."""
    existing_case = db.query(Case).filter(Case.case_number == case_in.case_number).first()
    if existing_case:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Case number already exists."
        )
    
    case = Case(
        case_number=case_in.case_number,
        name=case_in.name,
        description=case_in.description,
        incident_date=case_in.incident_date,
        created_by_id=current_user.id
    )
    db.add(case)
    db.flush()
    record_audit(db, "case_created", f"Created case '{case.case_number}'.", actor_id=current_user.id, case_id=case.id)
    record_custody(db, "case_opened", f"Case '{case.case_number}' opened.", actor_id=current_user.id, case_id=case.id)
    db.commit()
    db.refresh(case)
    return case

@router.get("/{case_id}", response_model=CaseResponse)
@limiter.limit(RATE_LIMIT_READ)
def get_case(request: Request, 
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get detailed case information by Case ID."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    return case

@router.put("/{case_id}", response_model=CaseResponse)
@limiter.limit(RATE_LIMIT_WRITE)
def update_case(request: Request, 
    case_id: int,
    case_update: CaseUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Update case metadata fields (name, description, incident date, status)."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    
    update_data = case_update.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(case, field, value)
    record_audit(db, "case_updated", f"Updated case '{case.case_number}'.", actor_id=current_user.id,
                 case_id=case.id, details={"updated_fields": sorted(update_data)})
    db.commit()
    db.refresh(case)
    return case

@router.delete("/{case_id}", status_code=status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_WRITE)
def delete_case(request: Request,
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Delete a case, its database findings, evidence items, and clear its folders."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    
    # 1. Delete database records FIRST so a file deletion failure doesn't
    #    leave orphaned DB rows. Model cascade deletes all child records cleanly.
    db.delete(case)
    db.commit()
    
    # 2. Remove files from disk AFTER the database is updated.
    #    If this fails the case is already gone from the DB; orphaned files
    #    can be cleaned up manually or by a background job.
    base_dir = Path(__file__).resolve().parent.parent.parent
    upload_dir = base_dir / "app" / "uploads" / f"case_{case_id}"
    report_dir = base_dir / "app" / "reports" / f"case_{case_id}"
    
    try:
        if upload_dir.exists():
            shutil.rmtree(upload_dir)
        if report_dir.exists():
            shutil.rmtree(report_dir)
    except Exception as e:
        # Log warning but continue — database is already consistent
        import logging
        logging.getLogger(__name__).warning(f"Failed to delete folders for case {case_id}: {e}")
    
    return {"message": "Case and all associated records deleted successfully."}
