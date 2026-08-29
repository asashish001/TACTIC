from pydantic import BaseModel, Field, ConfigDict
from datetime import date, datetime

class CaseBase(BaseModel):
    case_number: str = Field(..., min_length=1, max_length=80)
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(...)
    incident_date: date = Field(...)

class CaseCreate(CaseBase):
    pass

class CaseUpdate(BaseModel):
    name: str | None = Field(None, max_length=200)
    description: str | None = None
    incident_date: date | None = None
    status: str | None = Field(None, pattern="^(open|active|closed)$")

class CaseResponse(CaseBase):
    id: int
    status: str
    created_by_id: int
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)
