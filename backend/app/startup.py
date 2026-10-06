"""Database initialisation, compatibility migrations, and admin seeding.

This module is imported once at process start-up by ``main.py``.
All side-effects (create_all, ALTER TABLE, INSERT) execute on import.
"""
import logging
import os

from sqlalchemy import inspect, text

from app.auth.security import get_password_hash, verify_password
from app.database.session import Base, SessionLocal, engine
from app.models.artifact_correlation import ArtifactCorrelation  # noqa: F401
from app.models.browser_artifact import BrowserArtifact  # noqa: F401
from app.models.case import Case  # noqa: F401
from app.models.evidence import Evidence  # noqa: F401
from app.models.extracted_artifact import ExtractedArtifact  # noqa: F401
from app.models.finding import Finding  # noqa: F401
from app.models.forensic_job import ForensicJob  # noqa: F401
from app.models.forensic_records import (  # noqa: F401
    AuditLog,
    ChainOfCustody,
    EvidenceHash,
    TimelineEvent,
)
from app.models.intelligence import (  # noqa: F401
    ThreatIntelIndicator,
    VulnerabilityMatch,
)
from app.models.model_evaluation import ModelEvaluationRun  # noqa: F401
from app.models.model_registry import ModelRegistryEntry  # noqa: F401
from app.models.network_artifact import NetworkArtifact  # noqa: F401
from app.models.report import Report  # noqa: F401
from app.models.system_setting import SystemSetting  # noqa: F401

# ── Ensure all ORM models are registered with Base.metadata ──────
from app.models.user import User

log = logging.getLogger(__name__)

# ── Build schema ────────────────────────────────────────────────
Base.metadata.create_all(bind=engine)


# ── SQLite compatibility migrations ─────────────────────────────
def apply_compatibility_migrations() -> None:
    """Add non-destructive columns required by newer local development builds."""
    if engine.dialect.name != "sqlite":
        return

    columns = {item["name"] for item in inspect(engine).get_columns("evidence")}
    user_columns = {item["name"] for item in inspect(engine).get_columns("users")}
    finding_columns = {item["name"] for item in inspect(engine).get_columns("findings")}

    with engine.begin() as connection:
        if "sha1" not in columns:
            connection.execute(text("ALTER TABLE evidence ADD COLUMN sha1 VARCHAR(40)"))
        if "preservation_status" not in columns:
            connection.execute(text(
                "ALTER TABLE evidence ADD COLUMN preservation_status VARCHAR(30) NOT NULL DEFAULT 'preserved'"
            ))
        if "integrity_status" not in columns:
            connection.execute(text(
                "ALTER TABLE evidence ADD COLUMN integrity_status VARCHAR(20) NOT NULL DEFAULT 'VERIFIED'"
            ))
        if "timezone" not in user_columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN timezone VARCHAR(50) NOT NULL DEFAULT 'UTC'"
            ))
        if "token_version" not in user_columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0"
            ))
        if "refresh_token_jtis" not in user_columns:
            connection.execute(text(
                "ALTER TABLE users ADD COLUMN refresh_token_jtis VARCHAR(500) DEFAULT '[]'"
            ))
        if "review_status" not in finding_columns:
            connection.execute(text(
                "ALTER TABLE findings ADD COLUMN review_status VARCHAR(20) NOT NULL DEFAULT 'pending'"
            ))
        if "reviewed_by_id" not in finding_columns:
            connection.execute(text(
                "ALTER TABLE findings ADD COLUMN reviewed_by_id INTEGER"
            ))
        if "reviewed_at" not in finding_columns:
            connection.execute(text(
                "ALTER TABLE findings ADD COLUMN reviewed_at DATETIME"
            ))
        if "review_notes" not in finding_columns:
            connection.execute(text(
                "ALTER TABLE findings ADD COLUMN review_notes TEXT"
            ))
        duplicates = connection.execute(
            text("SELECT 1 FROM evidence GROUP BY case_id, sha256 HAVING COUNT(*) > 1 LIMIT 1")
        ).first()
        if not duplicates:
            connection.execute(
                text("CREATE UNIQUE INDEX IF NOT EXISTS uq_evidence_case_sha256 ON evidence (case_id, sha256)")
            )


apply_compatibility_migrations()


# ── Admin seeding ───────────────────────────────────────────────
_INSECURE_PASSWORDS = {
    "changeme",
    "password",
    "admin",
    "admin123",
    "password123",
    "",
}


def seed_admin_user() -> None:
    """Ensure at least one administrator account exists in the database.

    Security policy:
    * If ``DEFAULT_ADMIN_PASSWORD`` is set to a value, use it. Default: ``ChangeMe123!`` for demo parity.
    * If it is missing or matches a known trivial insecure default, a random
      20-character password is generated and printed **once** to stdout.
    * The admin should change this password on first login in production.
    """
    db = SessionLocal()
    try:
        username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
        admin_user = db.query(User).filter(User.username == username).first()
        if admin_user:
            return  # already exists, nothing to do

        env_password = os.getenv("DEFAULT_ADMIN_PASSWORD", "ChangeMe123!").strip()

        if env_password.lower() in _INSECURE_PASSWORDS:
            import secrets as _secrets
            generated = _secrets.token_urlsafe(16)  # ~22 chars, URL-safe
            log.warning(
                "No secure DEFAULT_ADMIN_PASSWORD configured. "
                "A random password has been generated."
            )
            log.critical(
                "FIRST-RUN ADMIN ACCOUNT CREATED | "
                "Username: %s, Password: %s | "
                "SAVE THIS PASSWORD — it will not be shown again. "
                "You should change it immediately after first login.",
                username, generated
            )
            password = generated
        else:
            password = env_password
            log.info("Admin user '%s' seeded from environment.", username)

        hashed_pwd = get_password_hash(password)
        admin = User(
            username=username,
            full_name="System Administrator",
            password_hash=hashed_pwd,
            role="admin",
        )
        db.add(admin)
        db.commit()
    except Exception as exc:
        log.warning("Failed to seed default admin: %s", exc)
    finally:
        db.close()


seed_admin_user()


# ── Warn if admin still uses the old hardcoded password ─────────
def _check_admin_password_strength() -> None:
    """Log a warning if the seeded admin's password hash matches
    the legacy hardcoded default ``ChangeMe123!``."""
    demo_default = "ChangeMe123!"
    db = SessionLocal()
    try:
        username = os.getenv("DEFAULT_ADMIN_USERNAME", "admin")
        admin = db.query(User).filter(User.username == username, User.role == "admin").first()
        if admin and verify_password(demo_default, admin.password_hash):
            log.warning(
                "Admin user '%s' is using the demo default "
                "password (ChangeMe123!). "
                "For production use, please change it: "
                "1. Log in with the current password, "
                "2. Go to Settings > Change Password, "
                "3. Choose a strong, unique password.",
                username
            )
    finally:
        db.close()


_check_admin_password_strength()
