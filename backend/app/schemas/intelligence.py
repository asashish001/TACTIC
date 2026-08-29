from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class IntelligenceAnalysisResponse(BaseModel):
    case_id: int
    software_identified: int
    vulnerabilities_found: int
    indicators_found: int
    remote_lookups_enabled: bool
    warnings: list[str] = Field(default_factory=list)


class VulnerabilityMatchResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int | None
    cve_id: str
    product: str
    version: str | None
    cpe_uri: str | None
    severity: str
    cvss_score: float | None
    epss_score: float | None
    is_kev: bool
    risk_score: int
    description: str
    references: list
    matched_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ThreatIndicatorResponse(BaseModel):
    id: int
    case_id: int
    evidence_id: int | None
    indicator_type: str
    value: str
    provider: str
    verdict: str
    confidence: float
    details: dict
    last_checked: datetime

    model_config = ConfigDict(from_attributes=True)
