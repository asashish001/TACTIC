import sys
import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.extracted_artifact import ExtractedArtifact
from app.models.artifact_correlation import ArtifactCorrelation
from app.services.correlation_engine import (
    compute_time_similarity,
    compute_entity_similarity,
    compute_source_relationship,
    compute_event_relationship,
    calculate_correlation_score,
    categorize_score,
    correlate_case_artifacts
)


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_explainable_components_and_categorization():
    """Verify component similarity functions and boundary categorization."""
    # 1. Time similarity
    t1 = "2026-08-18T10:00:00Z"
    t2 = "2026-08-18T10:10:00Z" # 600s difference
    s_time = compute_time_similarity(t1, t2, window_seconds=3600)
    assert 0.80 <= s_time <= 0.85, f"Expected time similarity ~0.83, got {s_time}"

    # Time outside window
    t3 = "2026-08-18T12:00:00Z" # 2 hours diff
    s_time_far = compute_time_similarity(t1, t3, window_seconds=3600)
    assert s_time_far == 0.0

    # 2. Entity similarity
    s_ent, desc = compute_entity_similarity("192.168.1.100", "ip", "192.168.1.100", "ip")
    assert s_ent == 1.0
    assert "Exact" in desc

    s_ent_diff, desc_diff = compute_entity_similarity("10.0.0.1", "ip", "192.168.1.100", "ip")
    assert s_ent_diff == 0.0

    # 3. Categorization boundaries
    assert categorize_score(0.85) == "Strong"
    assert categorize_score(0.70) == "Strong"
    assert categorize_score(0.65) == "Moderate"
    assert categorize_score(0.40) == "Moderate"
    assert categorize_score(0.35) == "Weak"
    assert categorize_score(0.10) == "Weak"


from app.models.user import User

def test_known_correlated_and_unrelated_artifacts():
    """Verify cross-evidence correlation engine on known correlated vs. unrelated artifacts."""
    db = setup_in_memory_db()

    # Create User
    user = User(id=1, username="test_investigator", full_name="Test Investigator", password_hash="hash", role="investigator")
    db.add(user)
    db.commit()

    # Create Case
    case = Case(id=1, case_number="CASE-CORR-01", name="Correlation Test Case", description="Test correlation description", incident_date=datetime.date.today(), created_by_id=1)
    db.add(case)
    db.commit()

    # Create Evidence 1 and 2
    ev1 = Evidence(id=10, case_id=1, filename="auth.log", stored_path="p1", file_size=100, extension="log", md5="m1", sha256="s1", detected_mime="text/plain")
    ev2 = Evidence(id=11, case_id=1, filename="network.pcap", stored_path="p2", file_size=100, extension="pcap", md5="m2", sha256="s2", detected_mime="pcap")
    db.add_all([ev1, ev2])
    db.commit()

    # 1. Correlated pair: Matching IP '192.168.1.50' within 5 minutes (300s)
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    t_correlated_1 = now_utc
    t_correlated_2 = now_utc + datetime.timedelta(minutes=5)

    art1 = ExtractedArtifact(case_id=1, evidence_id=10, source_evidence_id=10, artifact_type="ip", value="192.168.1.50", extracted_at=t_correlated_1)
    art2 = ExtractedArtifact(case_id=1, evidence_id=11, source_evidence_id=11, artifact_type="ip", value="192.168.1.50", extracted_at=t_correlated_2)

    # 2. Unrelated pair: Different IP '10.99.99.99' 24 hours later
    t_unrelated = now_utc + datetime.timedelta(hours=24)
    art3 = ExtractedArtifact(case_id=1, evidence_id=11, source_evidence_id=11, artifact_type="ip", value="10.99.99.99", extracted_at=t_unrelated)

    db.add_all([art1, art2, art3])
    db.commit()

    # Run correlation engine
    correlations = correlate_case_artifacts(case_id=1, db=db, time_window_seconds=3600)

    # Inspect generated correlations in DB
    db_records = db.query(ArtifactCorrelation).filter(ArtifactCorrelation.case_id == 1).all()
    assert len(db_records) > 0

    strong_correlations = [c for c in db_records if c.strength_category == "Strong"]
    assert len(strong_correlations) > 0, "Correlated pair matching IP within 5 min should yield Strong category score"
    
    correlated_record = strong_correlations[0]
    assert correlated_record.score >= 0.70
    assert "ENTITY_MATCH" in correlated_record.correlation_type or "Strong" in correlated_record.strength_category
    assert "192.168.1.50" in correlated_record.reason

    # Verify unrelated pair (art1 vs art3) has score < 0.40 or was filtered out
    unrelated_matches = [c for c in db_records if "10.99.99.99" in c.artifact_a_label or "10.99.99.99" in c.artifact_b_label]
    for un in unrelated_matches:
        assert un.score < 0.40, f"Unrelated pair should have Weak score < 0.40, got {un.score}"
        assert un.strength_category == "Weak"


def test_custom_configurable_formula():
    """Verify custom weights and time window configuration altering calculation results."""
    # Test formula weights
    weights_custom = {"time": 0.50, "entity": 0.20, "source": 0.10, "event": 0.20}
    score = calculate_correlation_score(s_time=1.0, s_entity=0.0, s_source=0.0, s_event=0.0, weights=weights_custom)
    assert score == 0.50, f"Expected 0.50 with custom time weight, got {score}"


if __name__ == "__main__":
    print("Running Complete Cross-Evidence Correlation Engine Unit Tests...")
    test_explainable_components_and_categorization()
    print("  [PASS] test_explainable_components_and_categorization")
    test_known_correlated_and_unrelated_artifacts()
    print("  [PASS] test_known_correlated_and_unrelated_artifacts")
    test_custom_configurable_formula()
    print("  [PASS] test_custom_configurable_formula")
    print("ALL CROSS-EVIDENCE CORRELATION ENGINE UNIT TESTS PASSED!")
