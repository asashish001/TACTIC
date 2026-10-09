from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class FindingBase(BaseModel):
    title: str = Field(..., max_length=200)
    description: str = Field(...)
    severity: str = Field("info", pattern="^(critical|high|medium|low|info)$")
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    risk_score: int = Field(0, ge=0, le=100)
    threat_category: str = Field("General Analysis", max_length=100)
    reason: str = Field(...)
    recommendation: str = Field(...)

class FindingCreate(FindingBase):
    case_id: int
    evidence_id: int | None = None
    details: dict = Field(default_factory=dict)

class FindingResponse(FindingBase):
    id: int
    case_id: int
    evidence_id: int | None
    evidence_filename: str | None = None
    details: dict
    review_status: str = "pending"
    reviewed_by_id: int | None = None
    reviewed_at: datetime | None = None
    review_notes: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class FindingReviewRequest(BaseModel):
    review_status: str = Field(..., pattern="^(approved|rejected|escalated)$")
    review_notes: str | None = Field(default=None, max_length=500)
