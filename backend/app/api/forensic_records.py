"""Read-only accountability endpoints for case owners and administrators."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.security import get_current_user, require_case_access
from app.config import RATE_LIMIT_READ, limiter
from app.database.session import get_db
from app.models.case import Case
from app.models.forensic_records import AuditLog, ChainOfCustody
from app.models.user import User

router = APIRouter(prefix="/api/forensic-records", tags=["Forensic Integrity"])


def _case_or_404(case_id: int, db: Session, current_user: User) -> Case:
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    return case


@router.get("/cases/{case_id}/chain-of-custody")
@limiter.limit(RATE_LIMIT_READ)
def list_chain_of_custody(request: Request, case_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _case_or_404(case_id, db, current_user)
    records = db.query(ChainOfCustody).filter(ChainOfCustody.case_id == case_id).order_by(ChainOfCustody.occurred_at.asc()).all()
    return [{
        "id": item.id, "action": item.action, "description": item.description,
        "evidence_id": item.evidence_id, "actor_id": item.actor_id,
        "hash_snapshot": item.hash_snapshot, "occurred_at": item.occurred_at,
        "details": item.details,
    } for item in records]


@router.get("/cases/{case_id}/audit-log")
@limiter.limit(RATE_LIMIT_READ)
def list_audit_log(request: Request, case_id: int, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    _case_or_404(case_id, db, current_user)
    records = db.query(AuditLog).filter(AuditLog.case_id == case_id).order_by(AuditLog.occurred_at.desc()).all()
    return [{
        "id": item.id, "action": item.action, "description": item.description,
        "evidence_id": item.evidence_id, "actor_id": item.actor_id,
        "occurred_at": item.occurred_at, "details": item.details,
    } for item in records]
