from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest

from app.services.integrity_verification import (
    MISSING,
    TAMPERED,
    VERIFIED,
    IntegrityCheckReport,
    IntegrityCheckResult,
    calculate_sha256,
    verify_case_evidence_integrity,
    verify_evidence_integrity,
)


class FakeDatabase:
    def __init__(self):
        self.records = []

    def add(self, record):
        self.records.append(record)


class IntegrityVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.uploads_dir = Path(__file__).resolve().parents[1] / "app" / "uploads"
        self.case_dir = self.uploads_dir / "integrity_unit_test"
        self.case_dir.mkdir(exist_ok=True)
        self.path = self.case_dir / "artifact.log"
        self.path.write_bytes(b"original forensic evidence")
        self.db = FakeDatabase()

    def tearDown(self):
        if self.path.exists():
            self.path.unlink()
        self.case_dir.rmdir()
        self.temp_dir.cleanup()

    def evidence(self):
        return SimpleNamespace(
            id=1, case_id=7, filename="artifact.log",
            stored_path="integrity_unit_test/artifact.log",
            sha256=calculate_sha256(self.path), integrity_status=None,
        )

    def test_valid_hash_is_verified(self):
        evidence = self.evidence()
        result = verify_evidence_integrity(self.db, evidence, actor_id=2)
        self.assertEqual(VERIFIED, result.status)
        self.assertEqual(VERIFIED, evidence.integrity_status)
        self.assertEqual("HASH_VERIFIED", self.db.records[-1].action)

    def test_modified_file_is_tampered(self):
        evidence = self.evidence()
        self.path.write_bytes(b"modified forensic evidence")
        result = verify_evidence_integrity(self.db, evidence)
        self.assertEqual(TAMPERED, result.status)
        self.assertEqual("INTEGRITY_FAILURE", self.db.records[-1].action)

    def test_missing_file_is_marked_missing(self):
        evidence = self.evidence()
        self.path.unlink()
        result = verify_evidence_integrity(self.db, evidence)
        self.assertEqual(MISSING, result.status)
        self.assertEqual(MISSING, evidence.integrity_status)

    def test_corrupted_file_is_tampered(self):
        evidence = self.evidence()
        self.path.write_bytes(b"\x00\xff\x00corrupted\x80")
        result = verify_evidence_integrity(self.db, evidence)
        self.assertEqual(TAMPERED, result.status)
        self.assertNotEqual(evidence.sha256, result.actual_sha256)


class IntegrityCheckReportTests(unittest.TestCase):
    """Tests for the IntegrityCheckReport class."""

    def setUp(self):
        self.temp_dir = TemporaryDirectory()
        self.uploads_dir = Path(__file__).resolve().parents[1] / "app" / "uploads"
        self.case_dir = self.uploads_dir / "report_unit_test"
        self.case_dir.mkdir(exist_ok=True)
        self.path1 = self.case_dir / "good.log"
        self.path1.write_bytes(b"good evidence data")
        self.path2 = self.case_dir / "bad.log"
        self.path2.write_bytes(b"bad evidence data")
        self.db = FakeDatabase()

    def tearDown(self):
        for p in (self.path1, self.path2):
            if p.exists():
                p.unlink()
        self.case_dir.rmdir()
        self.temp_dir.cleanup()

    def _evidence(self, id_=1, filename="good.log"):
        path = self.path1 if filename == "good.log" else self.path2
        return SimpleNamespace(
            id=id_, case_id=7, filename=filename,
            stored_path=f"report_unit_test/{filename}",
            sha256=calculate_sha256(path), integrity_status=None,
        )

    def test_report_all_verified(self):
        evidence = self._evidence()
        report = verify_case_evidence_integrity(self.db, [evidence], actor_id=2)
        self.assertIsInstance(report, IntegrityCheckReport)
        self.assertTrue(report.all_passed)
        self.assertEqual(1, report.total)
        self.assertEqual(1, report.verified_count)
        self.assertEqual(0, report.failed_count)

    def test_report_captures_failed_items(self):
        evidence1 = self._evidence(id_=1, filename="good.log")
        evidence2 = self._evidence(id_=2, filename="bad.log")
        # Tamper the second file after evidence2 was created
        self.path2.write_bytes(b"TAMPERED data")
        report = verify_case_evidence_integrity(self.db, [evidence1, evidence2], actor_id=2)
        self.assertFalse(report.all_passed)
        self.assertEqual(2, report.total)
        self.assertEqual(1, report.verified_count)
        self.assertEqual(1, report.failed_count)
        self.assertEqual(1, len(report.tampered_items))
        self.assertEqual("bad.log", report.tampered_items[0][0].filename)

    def test_report_summary(self):
        evidence = self._evidence()
        report = verify_case_evidence_integrity(self.db, [evidence])
        summary = report.summary()
        self.assertEqual(7, summary["case_id"])
        self.assertEqual(1, summary["total_checked"])
        self.assertEqual(1, summary["verified"])
        self.assertTrue(summary["all_passed"])
        self.assertEqual([], summary["failed_details"])

    def test_report_record_report(self):
        evidence = self._evidence()
        report = verify_case_evidence_integrity(self.db, [evidence])
        report.record_report(self.db, actor_id=2)
        audit = self.db.records[-1]
        self.assertEqual("INTEGRITY_CHECK_PASSED", audit.action)
        self.assertIn("1/1", audit.description)

    def test_report_record_report_with_failures(self):
        evidence1 = self._evidence(id_=1, filename="good.log")
        evidence2 = self._evidence(id_=2, filename="bad.log")
        self.path2.write_bytes(b"TAMPERED data")
        report = verify_case_evidence_integrity(self.db, [evidence1, evidence2])
        report.record_report(self.db, actor_id=2)
        audit = self.db.records[-1]
        self.assertEqual("INTEGRITY_CHECK_FAILED", audit.action)
        self.assertIn("1/2", audit.description)
        self.assertIn("bad.log", audit.description)

    def test_empty_report(self):
        report = IntegrityCheckReport(case_id=7)
        self.assertTrue(report.all_passed)
        self.assertEqual(0, report.total)
        self.assertEqual([], report.failed_items)
        self.assertEqual([], report.missing_items)
        self.assertEqual([], report.tampered_items)


if __name__ == "__main__":
    unittest.main()
