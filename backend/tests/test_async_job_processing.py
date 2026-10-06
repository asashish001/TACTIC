import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.user import User
from app.services.job_runner import create_job, execute_job_pipeline, retry_job


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_job_lifecycle_and_stage_tracking():
    """Verify ForensicJob creation, 8-stage progress tracking, and COMPLETED status."""
    db = setup_in_memory_db()

    user = User(id=1, username="job_inv", full_name="Job Investigator", password_hash="hash", role="investigator")
    db.add(user)
    db.commit()

    case = Case(id=1, case_number="CASE-JOB-01", name="Job Test Case", description="Testing async job runner", incident_date=datetime.date.today(), created_by_id=1)
    db.add(case)
    db.commit()

    content = b"Sample security log content for async job test"
    import hashlib
    sha256 = hashlib.sha256(content).hexdigest()
    md5 = hashlib.md5(content).hexdigest()

    uploads_dir = Path(__file__).resolve().parent.parent / "app" / "uploads"
    uploads_dir.mkdir(parents=True, exist_ok=True)
    real_file = uploads_dir / "CASE-JOB-01_security_alert.log"
    real_file.write_bytes(content)

    ev = Evidence(id=10, case_id=1, filename="security_alert.log", stored_path="CASE-JOB-01_security_alert.log", file_size=len(content), extension="log", md5=md5, sha256=sha256, detected_mime="text/plain")
    db.add(ev)
    db.commit()

    job = create_job(db, case_id=1, evidence_id=10, job_type="ANALYSIS_PIPELINE")
    assert job.status == "QUEUED"
    assert job.current_stage == "upload"
    assert job.progress_percent == 10.0

    execute_job_pipeline(job.id, actor_id=1, db=db)

    db.refresh(job)
    assert job.status == "COMPLETED"
    assert job.progress_percent == 100.0
    assert job.current_stage == "report"
    assert job.started_at is not None
    assert job.completed_at is not None


def test_failed_job_and_retry_mechanism():
    """Verify exception handling records useful error_info and retry_job resets state."""
    db = setup_in_memory_db()

    user = User(id=1, username="job_inv2", full_name="Job Investigator 2", password_hash="hash", role="investigator")
    db.add(user)
    db.commit()

    case = Case(id=2, case_number="CASE-JOB-02", name="Failed Job Case", description="Testing job failure & retry", incident_date=datetime.date.today(), created_by_id=1)
    db.add(case)
    db.commit()

    job = create_job(db, case_id=2, evidence_id=9999, job_type="ANALYSIS_PIPELINE")
    assert job.status == "QUEUED"

    execute_job_pipeline(job.id, actor_id=1, db=db)

    db.refresh(job)
    assert job.status == "FAILED"
    assert "failed at stage" in job.stage_message
    assert job.error_info is not None
    assert "error" in job.error_info
    assert "9999" in job.error_info["error"]

    retried_job = retry_job(db, job.id)
    assert retried_job.status == "QUEUED"
    assert retried_job.progress_percent == 10.0
    assert retried_job.retry_count == 1
    assert retried_job.error_info is None


if __name__ == "__main__":
    print("Running Asynchronous Background Job Runner Unit Tests...")
    test_job_lifecycle_and_stage_tracking()
    print("  [PASS] test_job_lifecycle_and_stage_tracking")
    test_failed_job_and_retry_mechanism()
    print("  [PASS] test_failed_job_and_retry_mechanism")
    print("ALL ASYNCHRONOUS JOB PROCESSING UNIT TESTS PASSED!")
