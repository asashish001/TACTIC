from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.auth.security import get_current_user, verify_password, get_password_hash, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_WRITE
from app.models.user import User
from app.schemas.user import UserResponse, UserSettingsUpdate
from app.services.timezone_service import resolve_timezone
import logging


logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/users", tags=["Users & Settings"])

@router.get("/me", response_model=UserResponse)
@limiter.limit(RATE_LIMIT_READ)
def get_me(request: Request, current_user: User = Depends(get_current_user)):
    """Return the profile data of the currently logged-in investigator."""
    return current_user


@router.get("/me/settings")
@limiter.limit(RATE_LIMIT_READ)
def get_user_settings(request: Request, current_user: User = Depends(get_current_user)):
    """Return the timezone and profile preferences of the logged-in investigator."""
    return {
        "username": current_user.username,
        "full_name": current_user.full_name,
        "role": current_user.role,
        "timezone": current_user.timezone or "UTC"
    }


@router.put("/me/settings", response_model=UserResponse)
@limiter.limit(RATE_LIMIT_WRITE)
def update_user_settings(request: Request, 
    payload: UserSettingsUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update preferred investigator timezone and profile settings."""
    if payload.timezone:
        # Validate timezone string
        try:
            resolve_timezone(payload.timezone)
        except Exception as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid timezone identifier '{payload.timezone}'."
            )
        current_user.timezone = payload.timezone.strip()

    if payload.full_name:
        current_user.full_name = payload.full_name.strip()

    db.commit()
    db.refresh(current_user)
    return current_user


from app.schemas.user import _PASSWORD_COMPLEXITY_RE, _PASSWORD_HINT


class PasswordChangeRequest(BaseModel):
    current_password: str = Field(...)
    new_password: str = Field(..., min_length=8)

    @field_validator("new_password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not _PASSWORD_COMPLEXITY_RE.match(v):
            raise ValueError(_PASSWORD_HINT)
        return v


@router.post("/me/change-password")
@limiter.limit(RATE_LIMIT_WRITE)
def change_password(request: Request, 
    payload: PasswordChangeRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Change the authenticated user's password."""
    if not verify_password(payload.current_password, current_user.password_hash):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")
    current_user.password_hash = get_password_hash(payload.new_password)
    current_user.token_version = (current_user.token_version or 0) + 1
    current_user.refresh_token_jtis = '[]'
    db.commit()
    return {"message": "Password changed successfully."}


class PromoteUserRequest(BaseModel):
    user_id: int = Field(...)
    role: str = Field(..., pattern="^(admin|investigator|student|viewer)$")


@router.post("/promote", response_model=UserResponse)
@limiter.limit(RATE_LIMIT_WRITE)
def promote_user(request: Request, 
    payload: PromoteUserRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin"]))
):
    """Admin-only endpoint to change a user's role. Prevents self-promotion."""
    if payload.user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Administrators cannot change their own role."
        )
    target_user = db.query(User).filter(User.id == payload.user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found.")
    old_role = target_user.role
    target_user.role = payload.role
    db.commit()
    db.refresh(target_user)
    logger.info("Admin '%s' promoted user '%s' from '%s' to '%s'.", current_user.username, target_user.username, old_role, payload.role)
    return target_user
