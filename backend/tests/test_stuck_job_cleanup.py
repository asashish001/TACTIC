"""Tests for stuck job cleanup functionality."""
import datetime
import uuid as _uuid
from datetime import timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.database.session import Base
from app.models.evidence import Evidence
from app.models.forensic_job import ForensicJob
from app.services.stuck_job_cleanup import (
    STUCK_JOB_THRESHOLD_MINUTES,
    cleanup_all_stuck_jobs,
    cleanup_stuck_job,
    find_stuck_jobs,
    get_stuck_jobs_summary,
)


@pytest.fixture
def db_session():
    """Create an in-memory database session for testing."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    with Session(engine) as session:
        yield session


def test_find_stuck_jobs_returns_empty_when_no_stuck_jobs(db_session):
    """Should return empty list when no jobs are stuck."""
    stuck = find_stuck_jobs(db_session)
    assert stuck == []


def test_find_stuck_jobs_finds_old_processing_jobs(db_session):
    """Should find jobs stuck in PROCESSING for longer than threshold."""
    old_time = datetime.datetime.now(timezone.utc) - timedelta(minutes=STUCK_JOB_THRESHOLD_MINUTES + 10)
    
    job = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        status="PROCESSING",
        current_stage="hashing",
        progress_percent=25.0,
        started_at=old_time
    )
    db_session.add(job)
    db_session.commit()
    
    stuck = find_stuck_jobs(db_session)
    assert len(stuck) == 1
    assert stuck[0].id == job.id


def test_find_stuck_jobs_ignores_recent_jobs(db_session):
    """Should not flag recently started processing jobs."""
    recent_time = datetime.datetime.now(timezone.utc) - timedelta(minutes=5)
    
    job = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        status="PROCESSING",
        current_stage="hashing",
        progress_percent=25.0,
        started_at=recent_time
    )
    db_session.add(job)
    db_session.commit()
    
    stuck = find_stuck_jobs(db_session)
    assert len(stuck) == 0


def test_find_stuck_jobs_ignores_non_processing_status(db_session):
    """Should not flag completed or failed jobs."""
    old_time = datetime.datetime.now(timezone.utc) - timedelta(hours=1)
    
    job = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        status="COMPLETED",
        current_stage="report",
        progress_percent=100.0,
        started_at=old_time
    )
    db_session.add(job)
    db_session.commit()
    
    stuck = find_stuck_jobs(db_session)
    assert len(stuck) == 0


def test_cleanup_stuck_job_marks_as_failed(db_session):
    """Should mark stuck job as FAILED with explanatory message."""
    old_time = datetime.datetime.now(timezone.utc) - timedelta(minutes=STUCK_JOB_THRESHOLD_MINUTES + 5)
    
    job = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        status="PROCESSING",
        current_stage="artifact extraction",
        progress_percent=50.0,
        started_at=old_time
    )
    db_session.add(job)
    db_session.commit()
    
    cleaned = cleanup_stuck_job(db_session, job, actor_id=1)
    
    assert cleaned.status == "FAILED"
    assert "timed out" in cleaned.stage_message.lower() or "stuck" in cleaned.stage_message.lower()
    assert cleaned.error_info is not None
    assert cleaned.completed_at is not None


def test_cleanup_stuck_job_updates_evidence_status(db_session):
    """Should mark associated evidence as PROCESSING_FAILED."""
    old_time = datetime.datetime.now(timezone.utc) - timedelta(minutes=STUCK_JOB_THRESHOLD_MINUTES + 5)
    
    evidence = Evidence(
        case_id=1,
        filename="test.txt",
        stored_path="case_1/test.txt",
        file_size=100,
        extension="txt",
        md5="d41d8cd98f00b204e9800998ecf8427e",
        sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        detected_mime="text/plain"
    )
    db_session.add(evidence)
    db_session.flush()  # Get the auto-generated ID
    
    job = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        evidence_id=evidence.id,
        status="PROCESSING",
        current_stage="anomaly detection",
        progress_percent=65.0,
        started_at=old_time
    )
    db_session.add(job)
    db_session.commit()
    
    cleanup_stuck_job(db_session, job, actor_id=1)
    
    db_session.refresh(evidence)
    assert evidence.integrity_status == "PROCESSING_FAILED"


def test_cleanup_all_stuck_jobs_returns_cleaned_jobs(db_session):
    """Should clean up all stuck jobs and return them."""
    old_time = datetime.datetime.now(timezone.utc) - timedelta(minutes=STUCK_JOB_THRESHOLD_MINUTES + 10)
    
    job1 = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        status="PROCESSING",
        current_stage="upload",
        progress_percent=10.0,
        started_at=old_time
    )
    job2 = ForensicJob(
        id=_uuid.uuid4(),
        case_id=2,
        status="PROCESSING",
        current_stage="hashing",
        progress_percent=20.0,
        started_at=old_time
    )
    db_session.add_all([job1, job2])
    db_session.commit()
    
    cleaned = cleanup_all_stuck_jobs(db_session, actor_id=1)
    
    assert len(cleaned) == 2
    assert all(job.status == "FAILED" for job in cleaned)


def test_get_stuck_jobs_summary_returns_statistics(db_session):
    """Should return summary statistics of stuck jobs."""
    old_time = datetime.datetime.now(timezone.utc) - timedelta(minutes=STUCK_JOB_THRESHOLD_MINUTES + 10)
    
    job1 = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        status="PROCESSING",
        current_stage="hashing",
        progress_percent=20.0,
        started_at=old_time
    )
    job2 = ForensicJob(
        id=_uuid.uuid4(),
        case_id=1,
        status="PROCESSING",
        current_stage="hashing",
        progress_percent=25.0,
        started_at=old_time
    )
    job3 = ForensicJob(
        id=_uuid.uuid4(),
        case_id=2,
        status="PROCESSING",
        current_stage="anomaly detection",
        progress_percent=60.0,
        started_at=old_time
    )
    db_session.add_all([job1, job2, job3])
    db_session.commit()
    
    summary = get_stuck_jobs_summary(db_session)
    
    assert summary["total_stuck"] == 3
    assert summary["by_stage"]["hashing"] == 2
    assert summary["by_stage"]["anomaly detection"] == 1
    assert summary["oldest_stuck"] is not None
