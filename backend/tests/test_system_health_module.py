import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.services.health_service import (
    check_system_health,
)


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_system_health_payload_and_crash_safety():
    """Verify system health diagnostic payload structure and crash-proof behavior."""
    db = setup_in_memory_db()

    health = check_system_health(db)

    assert "status" in health
    assert health["backend_status"] == "online"
    assert health["version"] == "2.0.0"
    assert "uptime_seconds" in health
    assert "uptime_formatted" in health

    assert health["database_status"]["status"] == "connected"
    assert health["database_status"]["latency_ms"] >= 0.0

    assert "loaded" in health["nlp_model_status"]
    assert health["ml_anomaly_model_status"]["status"] == "ready"

    assert health["storage"]["status"] in ("ok", "warning", "error")
    assert health["storage"]["free_mb"] >= 0.0

    health_none_db = check_system_health(db=None)
    assert health_none_db["status"] in ("warning", "error")
    assert health_none_db["database_status"]["status"] == "disconnected"
    assert health_none_db["database_status"]["error"] is not None


if __name__ == "__main__":
    print("Running System Health Monitoring Module Unit Tests...")
    test_system_health_payload_and_crash_safety()
    print("  [PASS] test_system_health_payload_and_crash_safety")
    print("ALL SYSTEM HEALTH MONITORING UNIT TESTS PASSED!")
