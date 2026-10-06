import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator

# ── Password complexity rules ──────────────────────────────────
_MIN_PWD_LEN = 8
_PASSWORD_COMPLEXITY_RE = re.compile(
    r"^"
    r"(?=.*[a-z])"      # at least one lowercase
    r"(?=.*[A-Z])"      # at least one uppercase
    r"(?=.*\d)"         # at least one digit
    r"(?=.*[^a-zA-Z0-9])"  # at least one special character
    r"."
    r"{%d,}$" % _MIN_PWD_LEN
)
_PASSWORD_HINT = (
    f"Password must be at least {_MIN_PWD_LEN} characters and include "
    "at least one uppercase letter, one lowercase letter, one digit, and one special character."
)


class UserBase(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    full_name: str = Field(..., min_length=2, max_length=100)
    timezone: str = Field("UTC")

class UserCreate(UserBase):
    password: str = Field(..., min_length=_MIN_PWD_LEN)
    role: str = Field("investigator", pattern="^(admin|investigator|student|viewer)$")

    @field_validator("password")
    @classmethod
    def validate_password_complexity(cls, v: str) -> str:
        if not _PASSWORD_COMPLEXITY_RE.match(v):
            raise ValueError(_PASSWORD_HINT)
        return v

class UserResponse(UserBase):
    id: int
    role: str
    timezone: str
    created_at: datetime
    
    model_config = ConfigDict(from_attributes=True)

class UserSettingsUpdate(BaseModel):
    timezone: str = Field("UTC")
    full_name: str | None = None
