from pydantic import BaseModel, Field


class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str
    mfa_required: bool = False

class TokenData(BaseModel):
    username: str | None = None
    user_id: int | None = None
    role: str | None = None

class LoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)
    totp_code: str | None = Field(None, description="6-digit TOTP code if MFA is enabled")

class TotpSetupResponse(BaseModel):
    secret: str
    otpauth_uri: str

class TotpVerifyRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6)

class TotpDisableRequest(BaseModel):
    password: str = Field(...)

