from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session
from typing import Any

from app.database.session import get_db
from app.models.model_evaluation import ModelEvaluationRun
from app.models.user import User
from app.auth.security import get_current_user, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_HEAVY
from app.services.model_evaluator import evaluate_anomaly_detector, evaluate_nlp_extractor

router = APIRouter(prefix="/api/evaluation", tags=["Model Evaluation Module"])


class RunEvaluationRequest(BaseModel):
    target_model: str = Field(default="anomaly_detector") # "anomaly_detector" or "nlp_extractor"
    threshold: float | None = Field(default=None)
    custom_dataset: dict[str, Any] | None = Field(default=None)


class ModelEvaluationResponse(BaseModel):
    model_config = ConfigDict(protected_namespaces=())
    id: int
    model_name: str
    model_version: str
    dataset_name: str
    dataset_size: int
    has_ground_truth: int
    features_used: list[str]
    threshold: float
    training_date: Any | None = None
    evaluation_date: Any
    metrics: dict[str, Any]


@router.post("/run", response_model=ModelEvaluationResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_HEAVY)
def trigger_model_evaluation(request: Request, 
    payload: RunEvaluationRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Run model evaluation pipeline, compute confusion matrix & metrics, and persist run metadata."""
    model_key = payload.target_model.lower()
    
    if model_key in ("anomaly_detector", "isolation_forest"):
        run = evaluate_anomaly_detector(db, dataset=payload.custom_dataset, threshold=payload.threshold, creator_id=current_user.id)
    elif model_key in ("nlp_extractor", "bert", "ner"):
        run = evaluate_nlp_extractor(db, dataset=payload.custom_dataset, creator_id=current_user.id)
    else:
        raise HTTPException(status_code=400, detail="Invalid target_model. Expected 'anomaly_detector' or 'nlp_extractor'.")

    return run


@router.get("/runs", response_model=list[ModelEvaluationResponse])
@limiter.limit(RATE_LIMIT_READ)
def list_evaluation_runs(request: Request, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve history of model evaluation runs."""
    return db.query(ModelEvaluationRun).order_by(ModelEvaluationRun.evaluation_date.desc()).all()


@router.get("/runs/{run_id}", response_model=ModelEvaluationResponse)
@limiter.limit(RATE_LIMIT_READ)
def get_evaluation_run_detail(request: Request, 
    run_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve detailed metrics and confusion matrix for a single evaluation run."""
    run = db.query(ModelEvaluationRun).filter(ModelEvaluationRun.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Evaluation run not found.")
    return run
