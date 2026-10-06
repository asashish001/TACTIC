from datetime import datetime

from pydantic import BaseModel, ConfigDict


class BrowserArtifactResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int
    browser: str
    artifact_type: str
    url: str | None
    domain: str | None
    title: str | None
    timestamp: str | None
    details: dict
    extracted_at: datetime

    model_config = ConfigDict(from_attributes=True)


class BrowserAnalysisResponse(BaseModel):
    case_id: int
    evidence_files_scanned: int
    artifacts_extracted: int
    suspicious_artifacts: int
    warnings: list[str]
