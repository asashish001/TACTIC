import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.ai.anomaly_detector import LogAnomalyDetector
from app.ai.risk_analyzer import run_risk_analysis
from app.utils.report_generator import build_pdf_report


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_explain_anomaly_structure():
    """Verify LogAnomalyDetector._explain_anomaly produces structured, non-fabricated XAI payloads."""
    detector = LogAnomalyDetector()
    sample_records = [
        {"event_id": 4624, "provider": "Security", "timestamp": "2026-08-18T10:00:00Z", "data": {"TargetUserName": "Alice"}},
        {"event_id": 4625, "provider": "Security", "timestamp": "2026-08-18T10:05:00Z", "data": {"TargetUserName": "Admin", "IpAddress": "192.168.1.100"}},
        {"event_id": 9999, "provider": "MaliciousApp", "timestamp": "2026-08-18T10:10:00Z", "data": {"Cmd": "powershell -enc AAAA..."}}
    ]

    anomalies = detector.analyze_logs(sample_records, threshold=0.80)
    assert len(anomalies) > 0, "Should detect outlier log events"

    for item in anomalies:
        details = item["details"]
        assert "xai_explanation" in details
        xai = details["xai_explanation"]
        
        # Verify required XAI schema fields
        assert "anomaly_score" in xai
        assert "threshold" in xai
        assert "top_contributing_features" in xai
        assert "human_readable_reasons" in xai
        assert "summary" in xai
        assert "evidence_reference" in xai
        assert "explanation_trace" in xai

        # Verify top features and percentages
        top_feats = xai["top_contributing_features"]
        assert len(top_feats) > 0
        total_pct = sum(f["contribution_pct"] for f in top_feats)
        assert 95.0 <= total_pct <= 105.0, f"Contribution percentages should sum close to 100%, got {total_pct}"

        # Verify trace proof metadata
        trace = xai["explanation_trace"]
        assert trace["method"] == "IsolationForest-FeatureAblation-Attribution"
        assert "trace_id" in trace


def test_end_to_end_xai_and_report():
    """Verify run_risk_analysis persists XAI payload in Finding.details and builds PDF report."""
    db = setup_in_memory_db()

    sample_records = [
        {"event_id": 4625, "provider": "Security", "timestamp": "2026-08-18T12:00:00Z", "data": {"TargetUserName": "Administrator", "IpAddress": "10.0.0.99"}},
        {"event_id": 6416, "provider": "Kernel-PnP", "timestamp": "2026-08-18T12:05:00Z", "data": {"DeviceId": "USB\\VID_0000&PID_0000\\12345"}}
    ]

    evidence = Evidence(
        id=10,
        case_id=100,
        filename="system_audit.evtx",
        stored_path="case_100/system_audit.evtx",
        file_size=2048,
        extension="evtx",
        md5="md5val",
        sha256="sha256val",
        detected_mime="application/x-evtx",
        extracted_metadata={"records": sample_records}
    )

    findings = run_risk_analysis(evidence, Path("fake.evtx"), db=db)
    anomaly_findings = [f for f in findings if "Anomaly Event ID" in f.title]
    assert len(anomaly_findings) > 0

    for f in anomaly_findings:
        db.add(f)
        assert "xai_explanation" in f.details
        xai = f.details["xai_explanation"]
        assert xai["threshold"] == 0.80
        assert len(xai["human_readable_reasons"]) > 0

    db.commit()

    # Verify PDF report generation with XAI payload
    case_payload = {
        "case": {"case_number": "CASE-XAI-1", "name": "XAI Test Case", "description": "Testing XAI reports", "incident_date": "2026-08-18"},
        "settings": {"anomaly_threshold": 0.80, "anomaly_threshold_label": "Configurable Default (0.80)"},
        "evidence": [{"filename": "system_audit.evtx", "detected_mime": "application/x-evtx", "sha256": "sha256val", "integrity_status": "VERIFIED"}],
        "findings": [{"title": f.title, "severity": f.severity, "risk_score": f.risk_score, "reason": f.reason, "recommendation": f.recommendation, "details": f.details} for f in anomaly_findings],
        "timeline": []
    }

    out_pdf = Path(__file__).parent / "test_xai_report.pdf"
    try:
        build_pdf_report(case_payload, out_pdf)
        assert out_pdf.exists() and out_pdf.stat().st_size > 1000
    finally:
        if out_pdf.exists():
            out_pdf.unlink()


if __name__ == "__main__":
    print("Running Explainable AI (XAI) Unit Tests...")
    test_explain_anomaly_structure()
    print("  [PASS] test_explain_anomaly_structure")
    test_end_to_end_xai_and_report()
    print("  [PASS] test_end_to_end_xai_and_report")
    print("ALL EXPLAINABLE AI (XAI) UNIT TESTS PASSED!")
