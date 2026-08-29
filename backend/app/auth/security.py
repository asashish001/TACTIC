import logging
import os
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated
import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from app.database.session import get_db
from app.models.user import User
from app.schemas.auth import TokenData

logger = logging.getLogger(__name__)

load_dotenv()

# ── Secret key validation ──
# The hardcoded fallback is INSECURE and must never be used in production.
_INSECURE_DEFAULTS = {
    "prod-only-secure-key-11223344",
    "development-only-change-this-secret",
    "changeme",
}
_secret = os.getenv("JWT_SECRET_KEY") or os.getenv("SECRET_KEY", "")
if not _secret or _secret in _INSECURE_DEFAULTS:
    # Auto-generate a ephemeral key for this process so the server can still
    # start in development, but invalidate all existing tokens on restart.
    _secret = secrets.token_hex(32)
    logger.warning(
        "No secure JWT_SECRET_KEY configured. A random key was generated "
        "for this session. All tokens will be invalidated on restart. "
        "Set JWT_SECRET_KEY in backend/.env for persistent tokens."
    )

SECRET_KEY = _secret
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours
REFRESH_TOKEN_EXPIRE_DAYS = 7  # 7 days for refresh tokens

security_bearer = HTTPBearer()

def get_password_hash(password: str) -> str:
    """Create a bcrypt password hash without passlib/bcrypt version coupling."""
    password_bytes = password.encode("utf-8")
    if len(password_bytes) > 72:
        raise ValueError("Passwords must be 72 bytes or fewer when encoded as UTF-8.")
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, TypeError):
        return False

def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access", "ver": data.get("token_version", 0)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict, *, jti: str | None = None) -> str:
    """Create a long-lived refresh token with a unique jti for rotation.

    If *jti* is not supplied a fresh UUID is generated.
    """
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({
        "exp": expire,
        "type": "refresh",
        "jti": jti or str(uuid.uuid4()),
        "ver": data.get("token_version", 0),
    })
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str, expected_type: str = "access") -> dict:
    """Decode and validate a JWT, raising HTTPException on any failure."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != expected_type:
            raise credentials_exception
        if payload.get("sub") is None or payload.get("user_id") is None:
            raise credentials_exception
        return payload
    except JWTError:
        raise credentials_exception

def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(security_bearer)],
    db: Session = Depends(get_db)
) -> User:
    payload = decode_token(credentials.credentials, expected_type="access")
    user = db.query(User).filter(User.id == payload.get("user_id")).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Invalidate tokens issued before a password change or admin revocation
    if payload.get("ver", 0) != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


def require_case_access(case, current_user: User) -> None:
    """Allow administrators, viewers, or the case owner to access a case-scoped record."""
    if current_user.role not in ("admin", "viewer") and case.created_by_id != current_user.id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not have access to this case.")

class RoleChecker:
    def __init__(self, allowed_roles: list[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: Annotated[User, Depends(get_current_user)]):
        if current_user.role not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Action requires one of these roles: {self.allowed_roles}"
            )
        return current_user
