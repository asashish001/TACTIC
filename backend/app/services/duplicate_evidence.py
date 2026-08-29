"""Duplicate evidence lookup helpers for ingestion workflows."""
from app.models.evidence import Evidence
from sqlalchemy import func


def find_duplicate_evidence(db, case_id: int, sha256_digest: str):
    """Return the already-ingested item with this digest in the same case, if any."""
    return (
        db.query(Evidence)
        .filter(Evidence.case_id == case_id, func.lower(Evidence.sha256) == sha256_digest.lower())
        .first()
    )
