"""System-level endpoints: health check and model status."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.health_service import check_system_health
from app.services.model_registry_service import get_model_status_summary, seed_default_model_registry

router = APIRouter(tags=["System"])


@router.get("/api/health")
@router.get("/api/health/details")
def health_check(db: Session = Depends(get_db)):
    """Comprehensive system health check: DB latency, NLP/ML model status,
    storage usage, and uptime."""
    return check_system_health(db)


@router.get("/model/status")
def get_global_model_status(db: Session = Depends(get_db)):
    """Active models, versions, loading status, evaluation metrics,
    and XAI availability."""
    seed_default_model_registry(db)
    active = get_model_status_summary(db)
    return {
        "loaded": True,
        "model_name": "TACTIC AI Model Suite (v2.0.0)",
        "error_state": None,
        "active_models": active,
    }
