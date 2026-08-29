import json
import uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.models.user import User
from app.schemas.user import UserCreate, UserResponse
from app.schemas.auth import LoginRequest, Token
from app.auth.security import (
    get_password_hash, verify_password,
    create_access_token, create_refresh_token, decode_token,
)
from app.config import limiter

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

# Max valid refresh tokens per user (handles concurrent sessions & retries)
_MAX_VALID_JTIS = 5


def _get_refresh_jtis(user: User) -> set[str]:
    """Return the set of currently valid refresh token JTIs for a user."""
    try:
        return set(json.loads(user.refresh_token_jtis or "[]"))
    except (json.JSONDecodeError, TypeError):
        return set()


def _add_refresh_jti(user: User, jti: str) -> None:
    """Add a JTI to the user's valid set, capping at _MAX_VALID_JTIS."""
    jtis = _get_refresh_jtis(user)
    jtis.add(jti)
    # Evict oldest entries if over limit (set is unordered; just trim)
    while len(jtis) > _MAX_VALID_JTIS:
        jtis.pop()
    user.refresh_token_jtis = json.dumps(list(jtis))


def _remove_refresh_jti(user: User, jti: str) -> None:
    """Remove a single JTI from the user's valid set."""
    jtis = _get_refresh_jtis(user)
    jtis.discard(jti)
    user.refresh_token_jtis = json.dumps(list(jtis))

@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit("5/minute")
def register(request: Request, user_in: UserCreate, db: Session = Depends(get_db)):
    """Create an investigator account; privileged roles are seeded or admin-managed."""
    existing_user = db.query(User).filter(User.username == user_in.username).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered."
        )
    
    hashed_pwd = get_password_hash(user_in.password)
    user = User(
        username=user_in.username,
        full_name=user_in.full_name,
        password_hash=hashed_pwd,
        role="investigator"  # Registration always assigns investigator; admin role is managed separately
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user

@router.post("/login", response_model=Token)
@limiter.limit("10/minute")
def login(request: Request, login_in: LoginRequest, db: Session = Depends(get_db)):
    """Authenticate username and password to return a signed JWT token."""
    user = db.query(User).filter(User.username == login_in.username).first()
    if not user or not verify_password(login_in.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password."
        )
    
    # Issue a new refresh token and store its jti on the user
    jti = str(uuid.uuid4())
    _add_refresh_jti(user, jti)
    db.commit()

    token_claims = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "token_version": user.token_version,
    }
    access_token = create_access_token(data=token_claims)
    refresh_token = create_refresh_token(data=token_claims, jti=jti)
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=Token)
@limiter.limit("30/minute")
def refresh_token(request: Request, body: RefreshRequest, db: Session = Depends(get_db)):
    """Exchange a valid refresh token for a fresh access + refresh token pair.

    Implements refresh token rotation: the old token is invalidated immediately,
    so a stolen refresh token can only be used once before it stops working.
    """
    payload = decode_token(body.refresh_token, expected_type="refresh")
    user = db.query(User).filter(User.id == payload.get("user_id")).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found.")

    # Validate token_version hasn't been revoked (e.g. password change)
    if payload.get("ver", 0) != user.token_version:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked. Please log in again.",
        )

    # Validate jti matches the set of valid JTIs on the user (rotation check)
    incoming_jti = payload.get("jti")
    valid_jtis = _get_refresh_jtis(user)
    if not incoming_jti or incoming_jti not in valid_jtis:
        # Possible token theft: this jti was already used or never issued.
        # Invalidate ALL refresh tokens for this user.
        user.refresh_token_jtis = "[]"
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token has already been used or is invalid. Please log in again.",
        )

    # Rotate: issue new refresh token, remove old jti from valid set
    new_jti = str(uuid.uuid4())
    _remove_refresh_jti(user, incoming_jti)
    _add_refresh_jti(user, new_jti)
    db.commit()

    token_claims = {
        "sub": user.username,
        "user_id": user.id,
        "role": user.role,
        "token_version": user.token_version,
    }
    return {
        "access_token": create_access_token(data=token_claims),
        "refresh_token": create_refresh_token(data=token_claims, jti=new_jti),
        "token_type": "bearer"
    }
