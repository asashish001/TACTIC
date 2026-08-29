from pydantic import BaseModel, Field

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class TokenData(BaseModel):
    username: str | None = None
    user_id: int | None = None
    role: str | None = None

class LoginRequest(BaseModel):
    username: str = Field(...)
    password: str = Field(...)
