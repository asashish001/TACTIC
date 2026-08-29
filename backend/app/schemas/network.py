from datetime import datetime
from pydantic import BaseModel, ConfigDict


class NetworkArtifactResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int
    artifact_type: str
    timestamp: str | None
    source_ip: str | None
    destination_ip: str | None
    source_port: int | None
    destination_port: int | None
    protocol: str | None
    value: str | None
    details: dict
    extracted_at: datetime

    model_config = ConfigDict(from_attributes=True)


class NetworkAnalysisResponse(BaseModel):
    case_id: int
    evidence_files_scanned: int
    artifacts_extracted: int
    suspicious_artifacts: int
    warnings: list[str]
