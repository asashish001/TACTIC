"""Tests for forensic_audit.py — audit trail and chain-of-custody recording."""
import pytest

from app.services.forensic_audit import record_audit, record_custody


class FakeSession:
    """Minimal SQLAlchemy session mock that captures added objects."""

    def __init__(self):
        self.added = []
        self.committed = False

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.committed = True


class TestRecordAudit:
    """Tests for the audit log recording helper."""

    def test_creates_audit_record(self):
        db = FakeSession()
        record_audit(db, "evidence_uploaded", "Uploaded file", actor_id=1, case_id=5)
        assert len(db.added) == 1
        audit = db.added[0]
        assert audit.action == "evidence_uploaded"
        assert audit.description == "Uploaded file"
        assert audit.actor_id == 1
        assert audit.case_id == 5

    def test_includes_evidence_id(self):
        db = FakeSession()
        record_audit(db, "hash_verified", "Hash OK", actor_id=1, case_id=5, evidence_id=10)
        audit = db.added[0]
        assert audit.evidence_id == 10

    def test_includes_details_dict(self):
        db = FakeSession()
        record_audit(db, "case_created", "New case", actor_id=1, case_id=5, details={"key": "value"})
        audit = db.added[0]
        assert audit.details == {"key": "value"}

    def test_records_added(self):
        db = FakeSession()
        record_audit(db, "test", "test", actor_id=1, case_id=5)
        assert len(db.added) == 1


class TestRecordCustody:
    """Tests for the chain-of-custody recording helper."""

    def test_creates_custody_record(self):
        db = FakeSession()
        record_custody(db, "evidence_ingested", "File preserved", actor_id=1, case_id=5)
        assert len(db.added) == 1
        custody = db.added[0]
        assert custody.action == "evidence_ingested"
        assert custody.description == "File preserved"
        assert custody.actor_id == 1
        assert custody.case_id == 5

    def test_includes_hash_snapshot(self):
        db = FakeSession()
        record_custody(
            db, "evidence_verified", "Hash verified",
            actor_id=1, case_id=5, evidence_id=10,
            hash_snapshot="abc123"
        )
        custody = db.added[0]
        assert custody.hash_snapshot == "abc123"
        assert custody.evidence_id == 10

    def test_includes_details(self):
        db = FakeSession()
        record_custody(
            db, "browser_extracted", "Artifacts extracted",
            actor_id=1, case_id=5,
            details={"artifacts": 42}
        )
        custody = db.added[0]
        assert custody.details == {"artifacts": 42}

    def test_records_added(self):
        db = FakeSession()
        record_custody(db, "test", "test", actor_id=1, case_id=5)
        assert len(db.added) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
