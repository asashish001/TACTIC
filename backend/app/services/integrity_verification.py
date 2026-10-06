"""Evidence integrity checks used before forensic processing."""
from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
from typing import Any

from app.services.forensic_audit import record_audit

VERIFIED = "VERIFIED"
TAMPERED = "TAMPERED"
MISSING = "MISSING"
PROCESSING_FAILED = "PROCESSING_FAILED"


@dataclass(frozen=True)
class IntegrityCheckResult:
    status: str
    actual_sha256: str | None = None


@dataclass
class IntegrityCheckReport:
    """Structured report of integrity verification across all evidence items.

    Captures every result so callers have full visibility into what was
    checked, what passed, and what failed — not just the first failure.
    """
    case_id: int
    items: list[tuple[Any, IntegrityCheckResult]] = field(default_factory=list)

    # ── Aggregate statistics ────────────────────────────────────────────
    @property
    def total(self) -> int:
        return len(self.items)

    @property
    def verified_count(self) -> int:
        return sum(1 for _, r in self.items if r.status == VERIFIED)

    @property
    def failed_count(self) -> int:
        return sum(1 for _, r in self.items if r.status != VERIFIED)

    @property
    def all_passed(self) -> bool:
        return self.failed_count == 0

    @property
    def failed_items(self) -> list[tuple[Any, IntegrityCheckResult]]:
        return [(item, res) for item, res in self.items if res.status != VERIFIED]

    @property
    def missing_items(self) -> list[tuple[Any, IntegrityCheckResult]]:
        return [(item, res) for item, res in self.items if res.status == MISSING]

    @property
    def tampered_items(self) -> list[tuple[Any, IntegrityCheckResult]]:
        return [(item, res) for item, res in self.items if res.status == TAMPERED]

    def summary(self) -> dict[str, Any]:
        """Return a machine-readable summary of the check."""
        return {
            "case_id": self.case_id,
            "total_checked": self.total,
            "verified": self.verified_count,
            "failed": self.failed_count,
            "all_passed": self.all_passed,
            "by_status": {
                VERIFIED: self.verified_count,
                TAMPERED: sum(1 for _, r in self.items if r.status == TAMPERED),
                MISSING: sum(1 for _, r in self.items if r.status == MISSING),
                PROCESSING_FAILED: sum(1 for _, r in self.items if r.status == PROCESSING_FAILED),
            },
            "failed_details": [
                {
                    "evidence_id": item.id,
                    "filename": item.filename,
                    "status": res.status,
                    "actual_sha256": res.actual_sha256,
                }
                for item, res in self.failed_items
            ],
        }

    def record_report(self, db, *, actor_id: int | None = None) -> None:
        """Write a single audit event summarising the entire integrity check."""
        summary = self.summary()
        action = "INTEGRITY_CHECK_PASSED" if self.all_passed else "INTEGRITY_CHECK_FAILED"
        description = (
            f"Integrity check completed: {self.verified_count}/{self.total} evidence files verified."
            if self.all_passed
            else (
                f"Integrity check completed: {self.failed_count}/{self.total} evidence files failed. "
                f"Failed: {[item.filename for item, _ in self.failed_items]}"
            )
        )
        record_audit(
            db, action, description, actor_id=actor_id, case_id=self.case_id,
            details=summary,
        )


def calculate_sha256(file_path: Path, chunk_size: int = 1024 * 1024) -> str:
    """Hash a file incrementally without modifying or loading it into memory."""
    digest = sha256()
    with file_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def evidence_disk_path(evidence) -> Path:
    """Resolve an evidence path and reject database path escapes."""
    uploads_dir = (Path(__file__).resolve().parent.parent / "uploads").resolve()
    path = (uploads_dir / evidence.stored_path).resolve()
    if uploads_dir not in path.parents:
        raise ValueError("Evidence stored path escapes the uploads directory.")
    return path


def verify_evidence_integrity(db, evidence, *, actor_id: int | None = None) -> IntegrityCheckResult:
    """Compare the on-disk SHA-256 with the immutable digest captured at ingestion.

    The caller owns the transaction so a failure status and audit event can be
    committed before analysis is stopped.
    """
    try:
        path = evidence_disk_path(evidence)
    except ValueError:
        path = None

    if path is None or not path.is_file():
        result = IntegrityCheckResult(MISSING)
    else:
        try:
            actual_sha256 = calculate_sha256(path)
            result = IntegrityCheckResult(
                VERIFIED if actual_sha256.lower() == evidence.sha256.lower() else TAMPERED,
                actual_sha256,
            )
        except OSError as exc:
            import logging
            logging.getLogger(__name__).error(f"Failed to read {path} for integrity check: {exc}")
            result = IntegrityCheckResult(MISSING)

    evidence.integrity_status = result.status
    action = "HASH_VERIFIED" if result.status == VERIFIED else "INTEGRITY_FAILURE"
    description = (
        f"SHA-256 integrity verified for evidence '{evidence.filename}'."
        if result.status == VERIFIED
        else f"Integrity verification failed for evidence '{evidence.filename}': {result.status.lower()}."
    )
    record_audit(
        db, action, description, actor_id=actor_id, case_id=evidence.case_id,
        evidence_id=evidence.id,
        details={"expected_sha256": evidence.sha256, "actual_sha256": result.actual_sha256, "status": result.status},
    )
    return result


def verify_case_evidence_integrity(db, evidence_items, *, actor_id: int | None = None) -> IntegrityCheckReport:
    """Verify each evidence item and return a structured report.

    The report records every result (not just the first failure) and can
    produce a summary audit event via ``report.record_report()``.
    """
    case_id = evidence_items[0].case_id if evidence_items else 0
    report = IntegrityCheckReport(case_id=case_id)
    for item in evidence_items:
        result = verify_evidence_integrity(db, item, actor_id=actor_id)
        report.items.append((item, result))
    return report
