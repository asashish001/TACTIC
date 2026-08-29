import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.models.system_setting import SystemSetting
from app.models.forensic_records import AuditLog
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.services.settings_service import (
    get_anomaly_threshold,
    get_system_settings,
    update_system_settings,
)
from app.ai.anomaly_detector import LogAnomalyDetector
from app.ai.risk_analyzer import run_risk_analysis


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_default_settings():
    """Verify system settings default to 0.80 clearly labeled as configurable default."""
    db = setup_in_memory_db()
    settings = get_system_settings(db)
    assert settings["anomaly_threshold"] == 0.80
    assert settings["anomaly_threshold_default"] == 0.80
    assert "Configurable Default" in settings["anomaly_threshold_label"]


def test_update_settings_and_audit_logging():
    """Verify threshold updates save to DB and create SETTINGS_UPDATED audit logs."""
    db = setup_in_memory_db()
    
    updated = update_system_settings(db, {"anomaly_threshold": 0.85}, actor_id=1)
    assert updated["anomaly_threshold"] == 0.85

    thresh = get_anomaly_threshold(db)
    assert thresh == 0.85

    # Check Audit Log record
    logs = db.query(AuditLog).filter(AuditLog.action == "SETTINGS_UPDATED").all()
    assert len(logs) == 1
    assert "anomaly threshold" in logs[0].description
    assert logs[0].details["old_anomaly_threshold"] == 0.80
    assert logs[0].details["new_anomaly_threshold"] == 0.85


def test_threshold_validation_boundaries():
    """Verify invalid threshold values (<0.0 or >1.0) raise ValueError."""
    db = setup_in_memory_db()
    
    try:
        update_system_settings(db, {"anomaly_threshold": -0.1})
        assert False, "Should have raised ValueError for negative threshold"
    except ValueError as e:
        assert "between 0.0 and 1.0" in str(e)

    try:
        update_system_settings(db, {"anomaly_threshold": 1.2})
        assert False, "Should have raised ValueError for threshold > 1.0"
    except ValueError as e:
        assert "between 0.0 and 1.0" in str(e)


def test_anomaly_classification_with_configured_threshold():
    """Verify Isolation Forest detector and risk analyzer attach threshold and XAI explanation."""
    db = setup_in_memory_db()
    update_system_settings(db, {"anomaly_threshold": 0.85})

    detector = LogAnomalyDetector()
    sample_records = [
        {"event_id": 4624, "provider": "Security", "timestamp": "2026-08-18T10:00:00Z", "data": {"TargetUserName": "Alice"}},
        {"event_id": 4625, "provider": "Security", "timestamp": "2026-08-18T10:05:00Z", "data": {"TargetUserName": "Admin", "IpAddress": "192.168.1.100"}},
        {"event_id": 9999, "provider": "MaliciousApp", "timestamp": "2026-08-18T10:10:00Z", "data": {"Cmd": "powershell -enc AAAA..."}}
    ]

    anomalies = detector.analyze_logs(sample_records, threshold=0.85)
    assert isinstance(anomalies, list)
    for a in anomalies:
        assert "details" in a
        assert a["details"]["anomaly_threshold"] == 0.85
        xai = a["details"]["xai_explanation"]
        assert isinstance(xai, dict), f"xai_explanation should be dict, got {type(xai)}"
        assert "anomaly_score" in xai
        assert "summary" in xai

    # Test run_risk_analysis with DB session
    evidence = Evidence(
        id=1,
        case_id=10,
        filename="Security_Audit.evtx",
        stored_path="case_10/Security_Audit.evtx",
        file_size=1024,
        extension="evtx",
        md5="md5hash",
        sha256="abc123hash",
        detected_mime="application/x-evtx",
        extracted_metadata={"records": sample_records}
    )

    findings = run_risk_analysis(evidence, Path("fake/path.evtx"), db=db)
    anomaly_findings = [f for f in findings if "Anomaly Event ID" in f.title]
    assert len(anomaly_findings) > 0
    for f in anomaly_findings:
        assert f.details["anomaly_threshold"] == 0.85
        assert "0.85" in f.description


if __name__ == "__main__":
    print("Running Configurable Anomaly Threshold Unit Tests...")
    test_default_settings()
    print("  [PASS] test_default_settings")
    test_update_settings_and_audit_logging()
    print("  [PASS] test_update_settings_and_audit_logging")
    test_threshold_validation_boundaries()
    print("  [PASS] test_threshold_validation_boundaries")
    test_anomaly_classification_with_configured_threshold()
    print("  [PASS] test_anomaly_classification_with_configured_threshold")
    print("ALL CONFIGURABLE ANOMALY THRESHOLD UNIT TESTS PASSED!")
