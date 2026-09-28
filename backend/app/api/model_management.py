from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session
from typing import Any

from app.database.session import get_db
from app.models.model_registry import ModelRegistryEntry
from app.models.user import User
from app.auth.security import get_current_user, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_WRITE
from app.services.model_registry_service import get_model_status_summary, seed_default_model_registry

router = APIRouter(prefix="/api/model", tags=["Model Management Module"])


class ModelRegisterRequest(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_name: str = Field(..., min_length=2, max_length=100)
    model_type: str = Field(..., description="anomaly_detection, nlp_ner, threat_classifier")
    version: str = Field(default="2.0.0")
    is_active: bool = Field(default=True)
    dataset: str = Field(default="TACTIC Labeled Forensic Benchmark v1")
    features: list[str] = Field(default_factory=list)
    threshold: float = Field(default=0.80)
    accuracy: float | None = Field(default=None)
    precision: float | None = Field(default=None)
    recall: float | None = Field(default=None)
    f1_score: float | None = Field(default=None)
    saved_model_path: str | None = Field(default=None)
    configuration: dict[str, Any] = Field(default_factory=dict)
    xai_available: bool = Field(default=True)
    loading_status: str = Field(default="loaded")


class ModelStatusResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    model_id: int
    model_name: str
    model_type: str
    version: str
    is_active: bool
    loading_status: str
    xai_available: bool
    threshold: float
    dataset: str
    training_date: Any | None = None
    saved_model_path: str | None = None
    features: list[str]
    configuration: dict[str, Any]
    evaluation_metrics: dict[str, Any]


class ModelRegistryResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: int
    model_name: str
    model_type: str
    version: str
    is_active: bool
    dataset: str
    training_date: Any
    features: list[str]
    threshold: float
    accuracy: float | None = None
    precision: float | None = None
    recall: float | None = None
    f1_score: float | None = None
    saved_model_path: str | None = None
    configuration: dict[str, Any]
    xai_available: bool
    loading_status: str
    created_at: Any


@router.get("/status", response_model=list[ModelStatusResponse])
@limiter.limit(RATE_LIMIT_READ)
def get_active_model_statuses(request: Request, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve currently active models, version, loading status, evaluation metrics, and XAI availability."""
    seed_default_model_registry(db)
    return get_model_status_summary(db)


@router.get("/registry", response_model=list[ModelRegistryResponse])
@limiter.limit(RATE_LIMIT_READ)
def list_model_registry(request: Request, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve complete database model registry history and metadata."""
    seed_default_model_registry(db)
    return db.query(ModelRegistryEntry).order_by(ModelRegistryEntry.id.desc()).all()


@router.get("/registry/{model_id}", response_model=ModelRegistryResponse)
@limiter.limit(RATE_LIMIT_READ)
def get_model_registry_detail(request: Request, 
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve metadata for a specific registered model ID."""
    entry = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == model_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Model registry entry not found.")
    return entry


@router.post("/register", response_model=ModelRegistryResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_WRITE)
def register_new_model(request: Request, 
    payload: ModelRegisterRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin"]))
):
    """Register a new AI model in the database model registry."""
    if payload.is_active:
        # Deactivate other active models of the same type
        db.query(ModelRegistryEntry).filter(ModelRegistryEntry.model_type == payload.model_type).update({"is_active": False})

    entry = ModelRegistryEntry(
        model_name=payload.model_name,
        model_type=payload.model_type,
        version=payload.version,
        is_active=payload.is_active,
        dataset=payload.dataset,
        features=payload.features,
        threshold=payload.threshold,
        accuracy=payload.accuracy,
        precision=payload.precision,
        recall=payload.recall,
        f1_score=payload.f1_score,
        saved_model_path=payload.saved_model_path,
        configuration=payload.configuration,
        xai_available=payload.xai_available,
        loading_status=payload.loading_status
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


@router.put("/{model_id}/activate", response_model=ModelRegistryResponse)
@limiter.limit(RATE_LIMIT_WRITE)
def activate_model_version(request: Request, 
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin"]))
):
    """Activate a specific model version and deactivate other entries of the same type."""
    entry = db.query(ModelRegistryEntry).filter(ModelRegistryEntry.id == model_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="Model registry entry not found.")

    db.query(ModelRegistryEntry).filter(ModelRegistryEntry.model_type == entry.model_type).update({"is_active": False})
    entry.is_active = True
    db.commit()
    db.refresh(entry)
    return entry
