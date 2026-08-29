from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.case import Case
from app.models.user import User
from app.auth.security import get_current_user, require_case_access
from app.config import limiter, RATE_LIMIT_READ
from app.services.timeline_builder import build_forensic_timeline
from app.services.timezone_service import resolve_timezone
import logging


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/timeline", tags=["Forensic Timeline Engine"])


def _resolve_target_tz(tz: str | None, current_user: User) -> str:
    target_tz = tz or getattr(current_user, "timezone", "UTC") or "UTC"
    try:
        resolve_timezone(target_tz)
    except Exception as exc:
        target_tz = "UTC"
    return target_tz


@router.get("/{case_id}")
@limiter.limit(RATE_LIMIT_READ)
def get_timeline(request: Request, 
    case_id: int,
    tz: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve complete multi-source forensic timeline formatted in investigator target timezone."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    
    target_tz = _resolve_target_tz(tz, current_user)
    return build_forensic_timeline(case_id, db, target_timezone=target_tz)


@router.get("/session/{case_id}")
@limiter.limit(RATE_LIMIT_READ)
def get_session_timeline(request: Request, 
    case_id: int,
    tz: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve stable forensic timeline schema for case session."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case session not found.")
    require_case_access(case, current_user)
    
    target_tz = _resolve_target_tz(tz, current_user)
    return build_forensic_timeline(case_id, db, target_timezone=target_tz)
