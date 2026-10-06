from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.security import RoleChecker, get_current_user, require_case_access
from app.config import RATE_LIMIT_READ, RATE_LIMIT_WRITE, limiter
from app.database.session import get_db
from app.models.case import Case
from app.models.user import User
from app.services.correlation import build_correlation_graph
from app.services.correlation_engine import correlate_case_artifacts
from app.services.settings_service import get_correlation_config

router = APIRouter(prefix="/api/correlation", tags=["Evidence Correlation"])

@router.get("/{case_id}")
@limiter.limit(RATE_LIMIT_READ)
def get_correlation(request: Request, 
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Generate a node-link network graph of related IP addresses, emails, usernames, hashes, and files."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    
    graph = build_correlation_graph(case_id, db)
    return {"case_id": case_id, "nodes": graph["nodes"], "edges": graph["edges"]}


@router.post("/{case_id}/rebuild")
@limiter.limit(RATE_LIMIT_WRITE)
def rebuild_correlation(request: Request, 
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Recompute all cross-evidence correlation scores using persisted system formula weights & time window."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    cfg = get_correlation_config(db)
    records = correlate_case_artifacts(case_id, db, weights=cfg["weights"], time_window_seconds=cfg["time_window_seconds"])

    graph = build_correlation_graph(case_id, db)
    return {
        "case_id": case_id,
        "correlations_compiled": len(records),
        "nodes": graph["nodes"],
        "edges": graph["edges"]
    }
