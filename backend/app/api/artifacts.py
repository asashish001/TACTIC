from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.extracted_artifact import ExtractedArtifact
from app.models.user import User
from app.schemas.artifact import (
    ArtifactExtractionResponse,
    ExtractedArtifactResponse,
    ModelStatusResponse,
)
from app.auth.security import get_current_user, require_case_access, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_HEAVY
from app.ai.registry import get_nlp_extractor
from app.services.artifact_extraction import extract_and_store_artifacts


router = APIRouter(prefix="/api/artifacts", tags=["Artifact Extraction Pipeline"])


@router.get("/model/status", response_model=ModelStatusResponse)
@limiter.limit(RATE_LIMIT_READ)
def get_model_status(request: Request):
    """Retrieve Transformer model loading status, version, and error state."""
    return get_nlp_extractor().get_status()


@router.post("/evidence/{evidence_id}/extract", response_model=ArtifactExtractionResponse)
@limiter.limit(RATE_LIMIT_HEAVY)
def trigger_evidence_artifact_extraction(request: Request, 
    evidence_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Run NLP Transformer + Deterministic extraction on a specific evidence file."""
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    require_case_access(evidence.case, current_user)

    artifacts = extract_and_store_artifacts(evidence, db)
    return {
        "message": f"Extracted {len(artifacts)} forensic artifacts from evidence '{evidence.filename}'.",
        "evidence_id": evidence.id,
        "artifacts_extracted": len(artifacts),
        "artifacts": artifacts
    }


@router.post("/cases/{case_id}/extract", response_model=dict)
@limiter.limit(RATE_LIMIT_HEAVY)
def trigger_case_artifact_extraction(request: Request, 
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Run artifact extraction pipeline for all evidence ingested under a case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    total_extracted = 0
    for evidence in evidence_items:
        artifacts = extract_and_store_artifacts(evidence, db)
        total_extracted += len(artifacts)

    return {
        "message": f"Extracted {total_extracted} total forensic artifacts across {len(evidence_items)} evidence files.",
        "case_id": case_id,
        "evidence_count": len(evidence_items),
        "total_artifacts_extracted": total_extracted
    }


@router.get("/evidence/{evidence_id}", response_model=list[ExtractedArtifactResponse])
@limiter.limit(RATE_LIMIT_READ)
def list_evidence_artifacts(request: Request, 
    evidence_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all extracted forensic artifacts for a specific evidence item."""
    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found.")
    require_case_access(evidence.case, current_user)

    return db.query(ExtractedArtifact).filter(ExtractedArtifact.evidence_id == evidence_id).all()


@router.get("/cases/{case_id}", response_model=list[ExtractedArtifactResponse])
@limiter.limit(RATE_LIMIT_READ)
def list_case_artifacts(request: Request, 
    case_id: int,
    artifact_type: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve all extracted forensic artifacts for an investigation case."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    query = db.query(ExtractedArtifact).filter(ExtractedArtifact.case_id == case_id)
    if artifact_type:
        query = query.filter(ExtractedArtifact.artifact_type == artifact_type)

    return query.order_by(ExtractedArtifact.confidence.desc()).all()

# ── Artifact Table with 12 Filters ──

@router.get("/cases/{case_id}/filtered")
@limiter.limit(RATE_LIMIT_READ)
def list_artifacts_filtered(request: Request,
    case_id: int,
    artifact_type: str | None = None,
    source: str | None = None,
    value_contains: str | None = None,
    extractor: str | None = None,
    min_confidence: float | None = None,
    max_confidence: float | None = None,
    username: str | None = None,
    ip_address: str | None = None,
    is_suspicious: bool | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve artifacts with 12 filter parameters for the Artifact Table view."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    query = db.query(ExtractedArtifact).filter(ExtractedArtifact.case_id == case_id)

    # Apply filters
    if artifact_type:
        query = query.filter(ExtractedArtifact.artifact_type == artifact_type)
    if source:
        query = query.filter(ExtractedArtifact.evidence_id == source)
    if value_contains:
        query = query.filter(ExtractedArtifact.value.ilike(f"%{value_contains}%"))
    if extractor:
        query = query.filter(ExtractedArtifact.extractor == extractor)
    if min_confidence is not None:
        query = query.filter(ExtractedArtifact.confidence >= min_confidence)
    if max_confidence is not None:
        query = query.filter(ExtractedArtifact.confidence <= max_confidence)
    if username:
        query = query.filter(ExtractedArtifact.value.ilike(f"%{username}%"))
    if ip_address:
        query = query.filter(ExtractedArtifact.value.ilike(f"%{ip_address}%"))
    if is_suspicious is not None:
        query = query.filter(ExtractedArtifact.details["is_suspicious"].as_string() == str(is_suspicious).lower())
    if date_from:
        query = query.filter(ExtractedArtifact.extracted_at >= date_from)
    if date_to:
        query = query.filter(ExtractedArtifact.extracted_at <= date_to)

    total = query.count()
    page_size = max(1, min(page_size, 200))
    page = max(1, page)
    total_pages = max(1, -(-total // page_size))

    items = query.order_by(ExtractedArtifact.confidence.desc()).offset((page - 1) * page_size).limit(page_size).all()

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "total_pages": total_pages,
        "filters_applied": {
            "artifact_type": artifact_type,
            "source": source,
            "value_contains": value_contains,
            "extractor": extractor,
            "min_confidence": min_confidence,
            "max_confidence": max_confidence,
            "username": username,
            "ip_address": ip_address,
            "is_suspicious": is_suspicious,
            "date_from": date_from,
            "date_to": date_to
        }
    }


@router.get("/cases/{case_id}/types")
@limiter.limit(RATE_LIMIT_READ)
def list_artifact_types(request: Request,
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get distinct artifact types for a case (for filter dropdowns)."""
    from sqlalchemy import distinct
    types = db.query(distinct(ExtractedArtifact.artifact_type)).filter(ExtractedArtifact.case_id == case_id).all()
    return [t[0] for t in types]


@router.get("/cases/{case_id}/extractors")
@limiter.limit(RATE_LIMIT_READ)
def list_artifact_extractors(request: Request,
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get distinct extractors for a case (for filter dropdowns)."""
    from sqlalchemy import distinct
    extractors = db.query(distinct(ExtractedArtifact.extractor)).filter(ExtractedArtifact.case_id == case_id).all()
    return [e[0] for e in extractors]
