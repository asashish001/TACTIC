from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ReportBase(BaseModel):
    filename: str = Field(..., max_length=255)
    format: str = Field(..., pattern="^(pdf|docx)$")

class ReportCreate(BaseModel):
    case_id: int
    format: str = Field(..., pattern="^(pdf|docx)$")

class ReportResponse(ReportBase):
    id: int
    case_id: int
    generated_at: datetime

    model_config = ConfigDict(from_attributes=True)
