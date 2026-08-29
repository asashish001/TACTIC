"""Helpers that append durable forensic accountability records."""
from app.models.forensic_records import AuditLog, ChainOfCustody, EvidenceHash, TimelineEvent
from app.services.timeline_builder import extract_timeline_events


def record_audit(db, action: str, description: str, *, actor_id: int | None = None,
                 case_id: int | None = None, evidence_id: int | None = None, details: dict | None = None) -> None:
    db.add(AuditLog(
        actor_id=actor_id, case_id=case_id, evidence_id=evidence_id,
        action=action, description=description, details=details or {},
    ))


def record_custody(db, action: str, description: str, *, actor_id: int | None,
                   case_id: int, evidence_id: int | None = None,
                   hash_snapshot: str | None = None, details: dict | None = None) -> None:
    db.add(ChainOfCustody(
        actor_id=actor_id, case_id=case_id, evidence_id=evidence_id,
        action=action, description=description, hash_snapshot=hash_snapshot,
        details=details or {},
    ))


def store_evidence_hashes(db, evidence, hashes: dict[str, str]) -> None:
    for algorithm, digest in hashes.items():
        db.add(EvidenceHash(evidence_id=evidence.id, algorithm=algorithm.upper(), digest=digest))


def rebuild_stored_timeline(case_id: int, db) -> list[TimelineEvent]:
    """Persist a reproducible timeline snapshot for reports and later review."""
    db.query(TimelineEvent).filter(TimelineEvent.case_id == case_id).delete()
    records = []
    for item in extract_timeline_events(case_id, db):
        record = TimelineEvent(
            case_id=case_id,
            event=item["event"],
            timestamp=item["timestamp"],
            evidence_source=item["evidence_source"],
            priority=item["priority"],
            event_type="derived",
            details={},
        )
        db.add(record)
        records.append(record)
    db.flush()
    return records
