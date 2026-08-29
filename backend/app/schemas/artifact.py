from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class ExtractedArtifactResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int
    source_evidence_id: int
    artifact_type: str
    value: str
    confidence: float
    extractor: str
    context_snippet: str | None = None
    start_char: int | None = None
    end_char: int | None = None
    details: dict = Field(default_factory=dict)
    extracted_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ModelStatusResponse(BaseModel):
    model_name: str
    version: str
    loaded: bool
    error_state: str | None = None


class ArtifactExtractionResponse(BaseModel):
    message: str
    evidence_id: int
    artifacts_extracted: int
    artifacts: list[ExtractedArtifactResponse]
