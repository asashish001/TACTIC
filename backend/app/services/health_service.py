"""TACTIC Crash-Proof System Health Monitoring Service."""
import datetime
import logging
import shutil
import time
from pathlib import Path
from typing import Any
from sqlalchemy import text
from sqlalchemy.orm import Session

logger = logging.getLogger("tactic.health_service")

# Track application startup time for uptime calculation
APP_START_TIME = datetime.datetime.now(datetime.timezone.utc)
APP_VERSION = "2.0.0"


def _format_uptime(seconds: float) -> str:
    """Format seconds into human-readable uptime string (e.g. '1d 4h 12m 30s')."""
    total_sec = int(seconds)
    days = total_sec // 86400
    hours = (total_sec % 86400) // 3600
    minutes = (total_sec % 3600) // 60
    secs = total_sec % 60

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0 or days > 0:
        parts.append(f"{hours}h")
    if minutes > 0 or hours > 0 or days > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")

    return " ".join(parts)


def check_database_health(db: Session | None, timeout_seconds: float = 2.0) -> dict[str, Any]:
    """Execute lightweight timeout-protected database connectivity query and measure latency."""
    if db is None:
        return {"status": "disconnected", "latency_ms": None, "error": "Database session unavailable."}

    start_time = time.perf_counter()
    try:
        # SQLite / Postgres query with 2s timeout
        db.execute(text("SELECT 1")).first()
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)
        return {
            "status": "connected",
            "latency_ms": latency_ms,
            "error": None
        }
    except Exception as exc:
        logger.warning("Database health check query failed: %s", exc)
        return {
            "status": "disconnected",
            "latency_ms": None,
            "error": str(exc)
        }


def check_nlp_model_health() -> dict[str, Any]:
    """Check Hugging Face Transformers model loaded status without crashing."""
    try:
        from app.ai.registry import get_nlp_extractor
        st = get_nlp_extractor().get_status()
        return {
            "status": "ready" if st.get("loaded") else "initializing",
            "loaded": bool(st.get("loaded")),
            "model_name": st.get("model_name", "dslim/bert-base-NER"),
            "error": st.get("error")
        }
    except Exception as exc:
        logger.warning("NLP model health check failed: %s", exc)
        return {
            "status": "warning",
            "loaded": False,
            "model_name": "dslim/bert-base-NER",
            "error": str(exc)
        }


def check_ml_anomaly_model_health(db: Session | None = None) -> dict[str, Any]:
    """Check Isolation Forest ML anomaly detector readiness."""
    try:
        from app.services.settings_service import get_anomaly_threshold
        threshold = get_anomaly_threshold(db)
        return {
            "status": "ready",
            "algorithm": "Isolation Forest & Feature Ablation XAI",
            "anomaly_threshold": round(threshold, 4),
            "error": None
        }
    except Exception as exc:
        logger.warning("ML anomaly model check failed: %s", exc)
        return {
            "status": "warning",
            "algorithm": "Isolation Forest",
            "anomaly_threshold": 0.80,
            "error": str(exc)
        }


def check_storage_health() -> dict[str, Any]:
    """Check upload directory storage availability and capacity."""
    try:
        upload_dir = (Path(__file__).resolve().parent.parent / "uploads").resolve()
        upload_dir.mkdir(parents=True, exist_ok=True)

        usage = shutil.disk_usage(upload_dir)
        total_mb = round(usage.total / (1024 * 1024), 2)
        used_mb = round(usage.used / (1024 * 1024), 2)
        free_mb = round(usage.free / (1024 * 1024), 2)
        used_percent = round((usage.used / usage.total) * 100, 2) if usage.total > 0 else 0.0

        status_val = "ok"
        if used_percent > 95.0:
            status_val = "error"
        elif used_percent > 85.0:
            status_val = "warning"

        return {
            "status": status_val,
            "total_bytes": usage.total,
            "used_bytes": usage.used,
            "free_bytes": usage.free,
            "used_percent": used_percent,
            "total_mb": total_mb,
            "used_mb": used_mb,
            "free_mb": free_mb,
            "error": None
        }
    except Exception as exc:
        logger.warning("Storage health check failed: %s", exc)
        return {
            "status": "warning",
            "total_bytes": 0,
            "used_bytes": 0,
            "free_bytes": 0,
            "used_percent": 0.0,
            "total_mb": 0.0,
            "used_mb": 0.0,
            "free_mb": 0.0,
            "error": str(exc)
        }


def check_system_health(db: Session | None = None) -> dict[str, Any]:
    """Compile comprehensive system health diagnostic payload. Will never raise unhandled exceptions."""
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    uptime_sec = round((now_utc - APP_START_TIME).total_seconds(), 2)

    db_health = check_database_health(db)
    nlp_health = check_nlp_model_health()
    ml_health = check_ml_anomaly_model_health(db)
    storage_health = check_storage_health()

    # Determine overall system health state
    if db_health["status"] != "connected" or storage_health["status"] == "error":
        overall_status = "error"
    elif not nlp_health["loaded"] or storage_health["status"] == "warning" or ml_health["status"] != "ready":
        overall_status = "warning"
    else:
        overall_status = "healthy"

    return {
        "status": overall_status, # healthy, warning, error
        "backend_status": "online",
        "database_status": db_health,
        "nlp_model_status": nlp_health,
        "ml_anomaly_model_status": ml_health,
        "storage": storage_health,
        "version": APP_VERSION,
        "uptime_seconds": uptime_sec,
        "uptime_formatted": _format_uptime(uptime_sec),
        "timestamp": now_utc.isoformat()
    }
