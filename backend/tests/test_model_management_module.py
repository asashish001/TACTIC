import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.ai.anomaly_detector import LogAnomalyDetector
from app.database.session import Base
from app.services.model_registry_service import (
    get_model_status_summary,
    seed_default_model_registry,
)


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_model_registry_seeding_and_status():
    """Verify model registry database seeding and status summary endpoint output."""
    db = setup_in_memory_db()

    seed_default_model_registry(db)
    summary = get_model_status_summary(db)

    assert len(summary) >= 3, "Should have seeded 3 default active models"

    anomaly_entry = next((m for m in summary if m["model_type"] == "anomaly_detection"), None)
    assert anomaly_entry is not None
    assert anomaly_entry["version"] == "2.0.0"
    assert anomaly_entry["loading_status"] == "loaded"
    assert anomaly_entry["xai_available"] is True
    assert "accuracy" in anomaly_entry["evaluation_metrics"]

    nlp_entry = next((m for m in summary if m["model_type"] == "nlp_ner"), None)
    assert nlp_entry is not None
    assert nlp_entry["version"] == "2.0.0"


def test_anomaly_result_model_version_recording():
    """Verify anomaly detector records exact model_version ('2.0.0') in finding details and XAI trace."""
    detector = LogAnomalyDetector()
    sample_logs = [
        {"event_id": 4625, "provider": "Security", "timestamp": "2026-08-18T12:00:00Z", "data": {"TargetUserName": "administrator", "Workstation": "C2-SERVER"}}
    ]

    findings = detector.analyze_logs(sample_logs, threshold=0.10)
    assert len(findings) > 0

    finding = findings[0]
    details = finding["details"]
    assert details["model_version"] == "2.0.0"
    assert details["model_name"] == "TACTIC Log Anomaly Detector"
    
    xai = details["xai_explanation"]
    assert xai["explanation_trace"]["model_version"] == "2.0.0"


if __name__ == "__main__":
    print("Running TACTIC Model Management System Unit Tests...")
    test_model_registry_seeding_and_status()
    print("  [PASS] test_model_registry_seeding_and_status")
    test_anomaly_result_model_version_recording()
    print("  [PASS] test_anomaly_result_model_version_recording")
    print("ALL MODEL MANAGEMENT SYSTEM UNIT TESTS PASSED!")
