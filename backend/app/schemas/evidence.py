from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class EvidenceBase(BaseModel):
    filename: str = Field(..., max_length=255)
    file_size: int = Field(...)
    extension: str = Field(..., max_length=20)
    md5: str = Field(..., min_length=32, max_length=32)
    sha1: str | None = Field(default=None, min_length=40, max_length=40)
    sha256: str = Field(..., min_length=64, max_length=64)
    detected_mime: str = Field(..., max_length=100)

class EvidenceCreate(EvidenceBase):
    case_id: int
    stored_path: str
    extracted_metadata: dict = Field(default_factory=dict)

class EvidenceResponse(EvidenceBase):
    id: int
    case_id: int
    extracted_metadata: dict
    ingested_at: datetime
    preservation_status: str
    integrity_status: str

    model_config = ConfigDict(from_attributes=True)
