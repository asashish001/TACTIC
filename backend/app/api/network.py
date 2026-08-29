from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.security import RoleChecker, get_current_user, require_case_access
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_HEAVY
from app.database.session import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.network_artifact import NetworkArtifact
from app.models.user import User
from app.schemas.network import NetworkAnalysisResponse, NetworkArtifactResponse
from app.services.forensic_audit import record_audit, record_custody
from app.services.network_forensics import (
    extract_network_log_artifacts,
    extract_pcap_artifacts,
    is_suspicious_network_artifact,
    stream_pcap_artifact_chunks,
)
from app.services.settings_service import get_forensic_chunk_size
from app.utils.memory_logger import log_memory_usage

router = APIRouter(prefix="/api/network", tags=["Network Forensics"])


@router.post("/cases/{case_id}/analyze", response_model=NetworkAnalysisResponse)
@limiter.limit(RATE_LIMIT_HEAVY)
def analyze_network_evidence(request: Request, 
    case_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    db.query(NetworkArtifact).filter(NetworkArtifact.case_id == case_id).delete()
    db.query(Finding).filter(Finding.case_id == case_id, Finding.details["source"].as_string() == "network_forensics").delete(synchronize_session=False)

    upload_root = (Path(__file__).resolve().parent.parent.parent / "app" / "uploads").resolve()
    warnings: list[str] = []
    artifacts_count = suspicious_count = scanned = 0
    chunk_size = get_forensic_chunk_size(db)

    log_memory_usage(f"Start Network Evidence Analysis (Case {case_id})")

    for evidence in evidence_items:
        if evidence.extension not in {"pcap", "pcapng", "log", "txt", "csv"}:
            continue
        scanned += 1
        file_path = (upload_root / evidence.stored_path).resolve()
        if upload_root not in file_path.parents or not file_path.is_file():
            warnings.append(f"{evidence.filename}: preserved file is unavailable.")
            continue

        if evidence.extension in {"pcap", "pcapng"}:
            # Memory-safe incremental streaming & database batch persistence
            for artifact_chunk in stream_pcap_artifact_chunks(file_path, chunk_size=chunk_size):
                for artifact in artifact_chunk:
                    db.add(NetworkArtifact(case_id=case_id, evidence_id=evidence.id, **artifact))
                    artifacts_count += 1
                    if is_suspicious_network_artifact(artifact):
                        suspicious_count += 1
                        target = artifact.get("value") or artifact.get("destination_ip") or "network event"
                        db.add(Finding(
                            case_id=case_id, evidence_id=evidence.id,
                            title=f"Network indicator requires review: {target}",
                            description="A captured flow or firewall record matches a conservative high-risk network indicator.",
                            severity="medium", confidence=0.7, risk_score=55,
                            threat_category="Network Forensics",
                            reason=f"Observed {artifact['artifact_type']} from {artifact.get('source_ip') or 'unknown'} to {artifact.get('destination_ip') or 'unknown'}.",
                            recommendation="Validate the endpoint, process owner, and related DNS or authentication activity before containment.",
                            details={"source": "network_forensics", "artifact_type": artifact["artifact_type"], "value": artifact.get("value")},
                        ))
                # Batch commit to flush database buffer and keep RAM usage bounded
                db.commit()
                log_memory_usage(f"Persisted batch chunk ({len(artifact_chunk)} items)")
        else:
            artifacts, extraction_warnings = extract_network_log_artifacts(file_path)
            warnings.extend(extraction_warnings)
            for artifact in artifacts:
                db.add(NetworkArtifact(case_id=case_id, evidence_id=evidence.id, **artifact))
                artifacts_count += 1
                if is_suspicious_network_artifact(artifact):
                    suspicious_count += 1
                    target = artifact.get("value") or artifact.get("destination_ip") or "network event"
                    db.add(Finding(
                        case_id=case_id, evidence_id=evidence.id,
                        title=f"Network indicator requires review: {target}",
                        description="A captured flow or firewall record matches a conservative high-risk network indicator.",
                        severity="medium", confidence=0.7, risk_score=55,
                        threat_category="Network Forensics",
                        reason=f"Observed {artifact['artifact_type']} from {artifact.get('source_ip') or 'unknown'} to {artifact.get('destination_ip') or 'unknown'}.",
                        recommendation="Validate the endpoint, process owner, and related DNS or authentication activity before containment.",
                        details={"source": "network_forensics", "artifact_type": artifact["artifact_type"], "value": artifact.get("value")},
                    ))
            db.commit()

    record_audit(
        db, "network_forensics_completed", "Analyzed submitted network evidence.",
        actor_id=current_user.id, case_id=case_id,
        details={"evidence_files": scanned, "artifacts": artifacts_count, "suspicious": suspicious_count}
    )
    record_custody(
        db, "network_artifacts_extracted", "Network artifacts extracted from preserved evidence.",
        actor_id=current_user.id, case_id=case_id,
        details={"artifacts": artifacts_count}
    )
    db.commit()
    log_memory_usage(f"Completed Network Analysis (Total Artifacts: {artifacts_count})")

    return NetworkAnalysisResponse(
        case_id=case_id,
        evidence_files_scanned=scanned,
        artifacts_extracted=artifacts_count,
        suspicious_artifacts=suspicious_count,
        warnings=warnings
    )


@router.get("/cases/{case_id}/artifacts", response_model=list[NetworkArtifactResponse])
@limiter.limit(RATE_LIMIT_READ)
def list_network_artifacts(request: Request, 
    case_id: int,
    artifact_type: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    query = db.query(NetworkArtifact).filter(NetworkArtifact.case_id == case_id)
    if artifact_type:
        query = query.filter(NetworkArtifact.artifact_type == artifact_type)
    return query.order_by(NetworkArtifact.id.desc()).all()
