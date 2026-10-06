import logging
import os
from pathlib import Path

from dotenv import load_dotenv
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

load_dotenv()

logger = logging.getLogger("tactic.database")

BASE_DIR = Path(__file__).resolve().parent.parent.parent

# ── Database URL ────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    db_dir = BASE_DIR / "app" / "database"
    db_dir.mkdir(parents=True, exist_ok=True)
    DATABASE_URL = f"sqlite:///{(db_dir / 'forensics.db').as_posix()}"

if DATABASE_URL.startswith("sqlite:///") and not DATABASE_URL.startswith("sqlite:////"):
    configured_path = DATABASE_URL.removeprefix("sqlite:///")
    if configured_path and configured_path != ":memory:":
        database_path = Path(configured_path)
        if not database_path.is_absolute():
            database_path = (BASE_DIR / database_path).resolve()
            database_path.parent.mkdir(parents=True, exist_ok=True)
            DATABASE_URL = f"sqlite:///{database_path.as_posix()}"

# ── Pool configuration ──────────────────────────────────────────
is_sqlite = DATABASE_URL.startswith("sqlite")

def _int(env_var: str, default: int) -> int:
    """Read an integer from the environment, falling back to *default*."""
    try:
        return int(os.getenv(env_var, str(default)))
    except (ValueError, TypeError):
        return default

POOL_SIZE: int = _int("DB_POOL_SIZE", 5)

MAX_OVERFLOW: int = _int("DB_MAX_OVERFLOW", 10)

POOL_TIMEOUT: int = _int("DB_POOL_TIMEOUT", 30)

POOL_RECYCLE: int = _int("DB_POOL_RECYCLE", 1800)

POOL_PRE_PING: bool = os.getenv("DB_POOL_PRE_PING", "true").lower() in ("1", "true", "yes")

# ── Engine creation ─────────────────────────────────────────────
engine_kwargs: dict = {"echo": False}

if is_sqlite:
    engine_kwargs["connect_args"] = {"check_same_thread": False, "timeout": 15}
    from sqlalchemy.pool import QueuePool
    engine_kwargs["poolclass"] = QueuePool
else:
    engine_kwargs.update({
        "pool_size": POOL_SIZE,
        "max_overflow": MAX_OVERFLOW,
        "pool_timeout": POOL_TIMEOUT,
        "pool_recycle": POOL_RECYCLE,
        "pool_pre_ping": POOL_PRE_PING,
    })

engine = create_engine(DATABASE_URL, **engine_kwargs)

if is_sqlite:
    @event.listens_for(engine, "connect")
    def _set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=30000;")
        cursor.close()

# ── Connection event hooks ──────────────────────────────────────
if POOL_PRE_PING and not is_sqlite:
    @event.listens_for(engine, "checkout")
    def _on_checkout(dbapi_conn, connection_rec, connection_proxy):
        """Log when a stale connection is detected and recycled."""
        if connection_rec._connected_time:
            import time
            age = time.time() - connection_rec._connected_time
            if age > POOL_RECYCLE:
                logger.debug("Recycling stale connection (age=%.0fs)", age)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass

logger.info(
    "Database pool configured: engine=%s pool_size=%d max_overflow=%d "
    "timeout=%ds recycle=%ds pre_ping=%s",
    "sqlite" if is_sqlite else "async",
    POOL_SIZE if not is_sqlite else 1,
    MAX_OVERFLOW if not is_sqlite else 0,
    POOL_TIMEOUT,
    POOL_RECYCLE,
    POOL_PRE_PING,
)

def get_db():
    """Dependency injection generator to provide database session per request."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
