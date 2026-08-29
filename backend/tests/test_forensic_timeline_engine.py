import sys
import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.models.user import User
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.extracted_artifact import ExtractedArtifact
from app.models.browser_artifact import BrowserArtifact
from app.models.network_artifact import NetworkArtifact
from app.models.artifact_correlation import ArtifactCorrelation
from app.services.timeline_builder import build_forensic_timeline


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_multi_source_forensic_timeline_engine():
    """Verify complete forensic timeline interleaving, timestamp normalization, missing/duplicate timestamp handling, and correlation metadata."""
    db = setup_in_memory_db()

    # User & Case
    user = User(id=1, username="timeline_inv", full_name="Timeline Investigator", password_hash="hash", role="investigator")
    db.add(user)
    db.commit()

    case = Case(id=1, case_number="CASE-TL-01", name="Timeline Test Case", description="Testing forensic timeline engine", incident_date=datetime.date.today(), created_by_id=1)
    db.add(case)
    db.commit()

    # Evidence item
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    t1 = now_utc - datetime.timedelta(hours=2)
    t2 = now_utc - datetime.timedelta(hours=1)
    t_dup = t1 # Duplicate timestamp

    ev1 = Evidence(
        id=10, case_id=1, filename="security.evtx", stored_path="p1", file_size=2048, extension="evtx", md5="m1", sha256="s1", detected_mime="application/x-evtx",
        extracted_metadata={
            "kind": "evtx",
            "records": [
                {"event_id": 4625, "provider": "Security", "timestamp": t1.isoformat(), "data": {"TargetUserName": "Admin"}},
                {"event_id": 4688, "provider": "Security", "timestamp": t2.isoformat(), "data": {"NewProcessName": "cmd.exe"}}
            ]
        }
    )
    db.add(ev1)
    db.commit()

    # Extracted Artifact (NLP)
    art1 = ExtractedArtifact(
        id=101, case_id=1, evidence_id=10, source_evidence_id=10, artifact_type="ip", value="192.168.1.100", confidence=0.95, extractor="bert-base-ner", extracted_at=t1
    )

    # Browser Artifact (Duplicate timestamp t1)
    art2 = BrowserArtifact(
        id=201, case_id=1, evidence_id=10, browser="chrome", artifact_type="history", url="http://malicious-c2.com", domain="malicious-c2.com", timestamp=t_dup
    )

    # Network Artifact (Missing timestamp -> None)
    art3 = NetworkArtifact(
        id=301, case_id=1, evidence_id=10, artifact_type="flow", source_ip="192.168.1.100", destination_ip="10.0.0.1", protocol="TCP", timestamp=None
    )

    # AI Finding
    finding1 = Finding(
        id=401, case_id=1, evidence_id=10, title="Credential Dumping Detected", description="Test finding description", threat_category="Credential Access", severity="CRITICAL", risk_score=95.0, reason="Isolaton Forest outlier score -0.85", recommendation="Isolate host", details={"xai_explanation": {"anomaly_score": 0.95, "threshold": 0.80}}
    )

    # Correlation Record
    corr = ArtifactCorrelation(
        id=501, case_id=1, artifact_a_type="Extracted_IP", artifact_a_id="ext_101", artifact_a_label="IP: 192.168.1.100",
        artifact_b_type="BrowserArtifact", artifact_b_id="browser_201", artifact_b_label="Chrome: malicious-c2.com",
        correlation_type="ENTITY_MATCH", score=0.88, strength_category="Strong", reason="Matching domain & IP timestamp",
        components={"time_similarity": 1.0, "entity_similarity": 0.8}, timestamp=t1
    )

    db.add_all([art1, art2, art3, finding1, corr])
    db.commit()

    # Execute timeline engine in UTC
    timeline_res = build_forensic_timeline(case_id=1, db=db, target_timezone="UTC")

    assert timeline_res["case_id"] == 1
    assert timeline_res["total_events"] > 0
    assert timeline_res["suspicious_count"] > 0

    events = timeline_res["events"]

    # Verify duplicate timestamps preserved stable insertion order without crashing
    dup_events = [e for e in events if e["timestamp"] and t1.strftime("%Y-%m-%d") in e["display_timestamp"]]
    assert len(dup_events) >= 2

    # Verify missing timestamp artifact (NetworkArtifact) was safely assigned to the end
    missing_events = [e for e in events if e["artifact_id"] == "net_301"]
    assert len(missing_events) == 1
    assert missing_events[0]["timestamp"] is None
    assert missing_events[0]["display_timestamp"] == "No Timestamp / Missing"
    assert missing_events[0]["timezone_badge"] == "MISSING"

    # Verify correlation metadata attachment
    corr_events = [e for e in events if e["artifact_id"] in ("ext_101", "browser_201")]
    assert len(corr_events) >= 1
    for ce in corr_events:
        assert ce["correlation_score"] == 0.88
        assert ce["correlation_category"] == "Strong"
        assert "group_" in ce["correlated_group_id"]

    # Verify target timezone conversion to IST (+05:30)
    timeline_ist = build_forensic_timeline(case_id=1, db=db, target_timezone="Asia/Kolkata")
    assert timeline_ist["target_timezone"] == "Asia/Kolkata"
    ist_events = timeline_ist["events"]
    assert any("IST" in e["timezone_badge"] for e in ist_events if e["timestamp"])


if __name__ == "__main__":
    print("Running Forensic Timeline Engine Unit Tests...")
    test_multi_source_forensic_timeline_engine()
    print("  [PASS] test_multi_source_forensic_timeline_engine")
    print("ALL FORENSIC TIMELINE ENGINE UNIT TESTS PASSED!")
