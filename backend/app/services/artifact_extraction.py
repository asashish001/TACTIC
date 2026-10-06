"""NLP artifact extraction service.

Contains the pure business logic for running the NLP extractor on evidence
and persisting results.  Previously lived inside ``app.api.artifacts`` which
caused the service layer (``job_runner``, ``analysis``) to import from the
API layer — a layering violation.
"""
import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.ai.registry import get_nlp_extractor
from app.models.evidence import Evidence
from app.models.extracted_artifact import ExtractedArtifact
from app.services.integrity_verification import evidence_disk_path

logger = logging.getLogger(__name__)


def extract_text_content(evidence: Evidence, file_path: Path) -> str:
    """Extract raw text representations from evidence file or metadata
    for NLP analysis."""
    text_chunks = [
        (f"Filename: {evidence.filename} "
        f"Extension: {evidence.extension} "
        f"MIME: {evidence.detected_mime}")
    ]

    meta = evidence.extracted_metadata or {}
    if isinstance(meta, dict):
        text_chunks.append(json.dumps(meta, default=str))

    if file_path.is_file():
        try:
            with file_path.open("rb") as f:
                raw = f.read(100_000)
            decoded = raw.decode("utf-8", errors="replace")
            text_chunks.append(decoded)
        except Exception as exc:
            logger.debug("Failed reading evidence file for text extraction: %s", exc)

    return "\n".join(text_chunks)


def extract_and_store_artifacts(evidence: Evidence, db: Session) -> list[ExtractedArtifact]:
    """Run NLP artifact extractor on an evidence item and store results
    in the database.

    This is the canonical service function used by:
    - ``app.api.artifacts`` (manual trigger endpoints)
    - ``app.api.analysis`` (synchronous analysis path)
    - ``app.services.job_runner`` (async pipeline)
    """
    file_path = evidence_disk_path(evidence)
    evidence_text = extract_text_content(evidence, file_path)

    raw_artifacts = get_nlp_extractor().extract_artifacts(
        text=evidence_text,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
    )

    db.query(ExtractedArtifact).filter(
        ExtractedArtifact.evidence_id == evidence.id
    ).delete()

    db_artifacts = []
    for item in raw_artifacts:
        artifact = ExtractedArtifact(
            case_id=item["case_id"],
            evidence_id=item["evidence_id"],
            source_evidence_id=item["source_evidence_id"],
            artifact_type=item["artifact_type"],
            value=item["value"],
            confidence=item["confidence"],
            extractor=item["extractor"],
            context_snippet=item.get("context_snippet"),
            start_char=item.get("start_char"),
            end_char=item.get("end_char"),
            details=item.get("details", {}),
        )
        db.add(artifact)
        db_artifacts.append(artifact)

    db.commit()
    for art in db_artifacts:
        db.refresh(art)

    return db_artifacts
