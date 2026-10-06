from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.security import RoleChecker, get_current_user, require_case_access
from app.config import RATE_LIMIT_HEAVY, RATE_LIMIT_READ, limiter
from app.database.session import get_db
from app.models.browser_artifact import BrowserArtifact
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.user import User
from app.schemas.browser import BrowserAnalysisResponse, BrowserArtifactResponse
from app.services.browser_forensics import (
    extract_browser_artifacts,
    is_suspicious_browser_artifact,
)
from app.services.forensic_audit import record_audit, record_custody

router = APIRouter(prefix="/api/browser", tags=["Browser Forensics"])


@router.post("/cases/{case_id}/analyze", response_model=BrowserAnalysisResponse)
@limiter.limit(RATE_LIMIT_HEAVY)
def analyze_browser_evidence(request: Request, case_id: int, db: Session = Depends(get_db), current_user: User = Depends(RoleChecker(["admin", "investigator"]))):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id, Evidence.extension.in_(["db", "sqlite", "json"])).all()
    db.query(BrowserArtifact).filter(BrowserArtifact.case_id == case_id).delete()
    db.query(Finding).filter(Finding.case_id == case_id, Finding.details["source"].as_string() == "browser_forensics").delete(synchronize_session=False)
    base_dir = Path(__file__).resolve().parent.parent.parent / "app" / "uploads"
    warnings: list[str] = []
    artifact_count = suspicious_count = 0

    for evidence in evidence_items:
        file_path = (base_dir / evidence.stored_path).resolve()
        if base_dir not in file_path.parents or not file_path.is_file():
            warnings.append(f"{evidence.filename}: preserved file is unavailable.")
            continue
        artifacts, extraction_warnings = extract_browser_artifacts(file_path, evidence.filename)
        warnings.extend(extraction_warnings)
        for artifact in artifacts:
            db.add(BrowserArtifact(case_id=case_id, evidence_id=evidence.id, **artifact))
            artifact_count += 1
            if is_suspicious_browser_artifact(artifact):
                suspicious_count += 1
                db.add(Finding(
                    case_id=case_id, evidence_id=evidence.id,
                    title=f"Browser indicator requires review: {artifact['domain'] or artifact['artifact_type']}",
                    description="A browser artifact matches a conservative phishing, anonymity-network, or executable-download indicator.",
                    severity="medium", confidence=0.7, risk_score=55,
                    threat_category="Browser Forensics",
                    reason=f"Observed {artifact['artifact_type']} artifact: {artifact.get('url') or artifact.get('details', {}).get('target_path', 'unknown')}",
                    recommendation="Validate the destination, download, and related endpoint activity before drawing a conclusion.",
                    details={"source": "browser_forensics", "artifact_type": artifact["artifact_type"], "url": artifact.get("url")},
                ))

    record_audit(db, "browser_forensics_completed", "Analyzed submitted browser evidence.", actor_id=current_user.id,
                 case_id=case_id, details={"evidence_files": len(evidence_items), "artifacts": artifact_count, "suspicious": suspicious_count})
    record_custody(db, "browser_artifacts_extracted", "Browser artifacts extracted from preserved evidence.", actor_id=current_user.id,
                   case_id=case_id, details={"artifacts": artifact_count})
    db.commit()
    return BrowserAnalysisResponse(case_id=case_id, evidence_files_scanned=len(evidence_items), artifacts_extracted=artifact_count, suspicious_artifacts=suspicious_count, warnings=warnings)


@router.get("/cases/{case_id}/artifacts", response_model=list[BrowserArtifactResponse])
@limiter.limit(RATE_LIMIT_READ)
def list_browser_artifacts(request: Request, case_id: int, artifact_type: str | None = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    query = db.query(BrowserArtifact).filter(BrowserArtifact.case_id == case_id)
    if artifact_type:
        query = query.filter(BrowserArtifact.artifact_type == artifact_type)
    return query.order_by(BrowserArtifact.timestamp.desc().nullslast(), BrowserArtifact.id.desc()).all()
