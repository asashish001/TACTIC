"""
Shared pytest fixtures for the AIDFA backend test suite.

Provides:
  - In-memory SQLite database with all models
  - FastAPI TestClient wired to the in-memory DB
  - Pre-seeded admin user and auth headers
  - Helper to create cases and upload evidence

Every test gets a clean database state via transaction rollback.
Crash-safe: cleanup runs even if the test raises an exception.
"""
import os
import shutil
import sys
from pathlib import Path
from typing import Generator

# Ensure tests run with offline model fallback and no hanging downloads
os.environ.setdefault("NLP_MODEL_NAME", "fallback")
os.environ.setdefault("TRANSFORMERS_OFFLINE", "1")
os.environ.setdefault("HF_HUB_OFFLINE", "1")

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.engine import Connection

# Ensure the backend package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import limiter  # Import the global limiter
from app.database.session import Base, get_db
from app.models.user import User
from app.models.case import Case
from app.models.finding import Finding  # noqa: F401 - register before create_all
from app.auth.security import get_password_hash, create_access_token

# Disable rate limiting during tests
limiter.enabled = False

# Uploads directory used by tests
_UPLOADS_DIR = Path(__file__).resolve().parent.parent / "app" / "uploads"
_REPORTS_DIR = Path(__file__).resolve().parent.parent / "app" / "reports"


# ── In-memory database ──────────────────────────────────────────

@pytest.fixture(scope="session")
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=eng)
    return eng


@pytest.fixture()
def db(engine) -> Generator[Session, None, None]:
    """Yield a fresh database session per test.

    Uses a savepoint so that even if the test commits, all changes are
    rolled back on teardown — crash-safe via try/finally.
    """
    connection: Connection = engine.connect()
    transaction = connection.begin()
    session = sessionmaker(bind=connection)()

    # Start a nested savepoint so test commits don't leak
    nested = connection.begin_nested()
    session.info["savepoint_token"] = nested

    try:
        yield session
    finally:
        # Rollback everything, even if the test committed
        try:
            session.close()
        except Exception:
            pass
        try:
            if transaction.is_active:
                transaction.rollback()
        except Exception:
            pass
        try:
            connection.close()
        except Exception:
            pass


# ── FastAPI TestClient ──────────────────────────────────────────

@pytest.fixture()
def client(db, engine):
    """TestClient that uses the test database session."""
    def override_get_db():
        try:
            yield db
        finally:
            pass

    # Import app AFTER path is set
    from app.main import app
    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as c:
        yield c

    app.dependency_overrides.clear()


@pytest.fixture(autouse=True)
def _cleanup_test_files():
    """Auto-cleanup: remove any test-created upload/report directories."""
    # Snapshot existing directories before the test
    pre_uploads = set(_UPLOADS_DIR.iterdir()) if _UPLOADS_DIR.exists() else set()
    pre_reports = set(_REPORTS_DIR.iterdir()) if _REPORTS_DIR.exists() else set()

    yield

    # Remove only directories that were created during the test
    for d in (_UPLOADS_DIR, _REPORTS_DIR):
        if not d.exists():
            continue
        pre = pre_uploads if d == _UPLOADS_DIR else pre_reports
        for entry in d.iterdir():
            if entry.is_dir() and entry not in pre:
                shutil.rmtree(entry, ignore_errors=True)


# ── Seed users ──────────────────────────────────────────────────

@pytest.fixture()
def admin_user(db):
    """Create and return an admin user in the test database."""
    user = User(
        username="testadmin",
        full_name="Test Admin",
        password_hash=get_password_hash("AdminPass123!"),
        role="admin",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def investigator_user(db):
    """Create and return an investigator user."""
    user = User(
        username="testinv",
        full_name="Test Investigator",
        password_hash=get_password_hash("InvPass123!"),
        role="investigator",
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture()
def admin_token(admin_user):
    """Return a valid JWT access token for the admin user."""
    return create_access_token({
        "sub": admin_user.username,
        "user_id": admin_user.id,
        "role": admin_user.role,
        "token_version": admin_user.token_version,
    })


@pytest.fixture()
def investigator_token(investigator_user):
    """Return a valid JWT access token for the investigator user."""
    return create_access_token({
        "sub": investigator_user.username,
        "user_id": investigator_user.id,
        "role": investigator_user.role,
        "token_version": investigator_user.token_version,
    })


@pytest.fixture()
def admin_headers(admin_token):
    """Return Authorization headers dict for the admin user."""
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture()
def investigator_headers(investigator_token):
    """Return Authorization headers dict for the investigator user."""
    return {"Authorization": f"Bearer {investigator_token}"}


# ── Helper: create a case ──────────────────────────────────────

@pytest.fixture()
def sample_case(db, admin_user):
    """Create and return a sample case owned by the admin user."""
    import datetime
    case = Case(
        case_number="CASE-TEST-001",
        name="Unit Test Case",
        description="Automated test case for pytest suite",
        incident_date=datetime.date.today(),
        created_by_id=admin_user.id,
    )
    db.add(case)
    db.commit()
    db.refresh(case)
    return case


# ── Helper: build multipart body ────────────────────────────────

def build_multipart(case_id: int, filename: str, content: bytes,
                     content_type: str = "text/plain",
                     boundary: str = "TestBoundary") -> tuple[bytes, dict]:
    """Build a raw multipart/form-data body for evidence upload."""
    parts = []
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="case_id"\r\n\r\n'
        f"{case_id}\r\n".encode()
    )
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        f"Content-Type: {content_type}\r\n\r\n".encode()
    )
    parts.append(content)
    parts.append(f"\r\n--{boundary}--\r\n".encode())
    raw = b"".join(parts)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    return raw, headers
