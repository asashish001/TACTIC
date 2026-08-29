from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.user import User
from app.auth.security import get_current_user, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_WRITE
from app.services.settings_service import (
    get_system_settings,
    update_system_settings,
)

router = APIRouter(prefix="/api/settings", tags=["System Settings & Threshold Config"])


class SystemSettingsResponse(BaseModel):
    anomaly_threshold: float
    anomaly_threshold_default: float = 0.80
    anomaly_threshold_label: str = "Configurable Default (0.80)"
    default_timezone: str = "UTC"
    correlation_weights: dict[str, float] = Field(default_factory=lambda: {"time": 0.30, "entity": 0.35, "source": 0.15, "event": 0.20})
    correlation_time_window_seconds: int = 3600


class SystemSettingsUpdateRequest(BaseModel):
    anomaly_threshold: float | None = Field(default=None, ge=0.0, le=1.0)
    default_timezone: str | None = None
    correlation_weights: dict[str, float] | None = None
    correlation_time_window_seconds: int | None = Field(default=None, gt=0)


@router.get("", response_model=SystemSettingsResponse)
@limiter.limit(RATE_LIMIT_READ)
def read_system_settings(request: Request, 
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve current system configuration including persisted anomaly threshold."""
    return get_system_settings(db)


@router.put("", response_model=SystemSettingsResponse)
@limiter.limit(RATE_LIMIT_WRITE)
def update_settings(request: Request, 
    payload: SystemSettingsUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Update persisted system settings, validating anomaly threshold (0.0 to 1.0) and logging audit trail."""
    try:
        updated = update_system_settings(
            db=db,
            payload=payload.model_dump(exclude_unset=True),
            actor_id=current_user.id
        )
        return updated
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc)
        )
