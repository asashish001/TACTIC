import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.database.session import Base
from app.services.model_evaluator import (
    evaluate_anomaly_detector,
    evaluate_nlp_extractor,
)


def setup_in_memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    return Session()


def test_anomaly_detector_evaluation_and_confusion_matrix():
    """Test Isolation Forest Anomaly Detector evaluation on labeled dataset."""
    db = setup_in_memory_db()

    run = evaluate_anomaly_detector(db)

    assert run.id is not None
    assert run.has_ground_truth == 1
    assert run.model_name == "TACTIC Anomaly Detector (Isolation Forest)"
    assert run.dataset_size > 0

    m = run.metrics
    assert m["status"] == "EVALUATED"
    assert "accuracy" in m and 0.0 <= m["accuracy"] <= 1.0
    assert "precision" in m and 0.0 <= m["precision"] <= 1.0
    assert "recall" in m and 0.0 <= m["recall"] <= 1.0
    assert "f1_score" in m and 0.0 <= m["f1_score"] <= 1.0
    assert "roc_auc" in m and 0.0 <= m["roc_auc"] <= 1.0

    cm = m["confusion_matrix"]
    assert len(cm) == 2 and len(cm[0]) == 2
    assert cm[0][0] == m["tn"]
    assert cm[0][1] == m["fp"]
    assert cm[1][0] == m["fn"]
    assert cm[1][1] == m["tp"]

    assert m["avg_processing_time_ms"] >= 0.0
    assert m["memory_rss_mb"] > 0.0
    assert m["throughput_samples_per_sec"] >= 0.0


def test_nlp_extractor_evaluation():
    """Test Hugging Face NLP Extractor evaluation on labeled benchmark text samples."""
    db = setup_in_memory_db()

    run = evaluate_nlp_extractor(db)

    assert run.id is not None
    assert run.has_ground_truth == 1
    assert run.model_name == "TACTIC NLP Artifact Extractor (dslim/bert-base-NER)"

    m = run.metrics
    assert m["status"] == "EVALUATED"
    assert "accuracy" in m
    assert "precision" in m
    assert "recall" in m
    assert "f1_score" in m


def test_missing_ground_truth_safety():
    """Verify evaluator reports NO_GROUND_TRUTH without fabricating statistical metrics when ground truth is missing."""
    db = setup_in_memory_db()

    unlabeled_dataset = {
        "dataset_name": "Unlabeled Raw Security Log Ingestion",
        "anomaly_logs": [
            {"event_id": 4624, "provider": "Security", "data": {"User": "admin"}},
            {"event_id": 4625, "provider": "Security", "data": {"User": "unknown"}}
        ]
    }

    run = evaluate_anomaly_detector(db, dataset=unlabeled_dataset)

    assert run.has_ground_truth == 0
    assert run.metrics["status"] == "NO_GROUND_TRUTH"
    assert "message" in run.metrics
    assert "accuracy" not in run.metrics, "Must not fabricate accuracy without ground-truth data"


if __name__ == "__main__":
    print("Running TACTIC Model Evaluation Module Unit Tests...")
    test_anomaly_detector_evaluation_and_confusion_matrix()
    print("  [PASS] test_anomaly_detector_evaluation_and_confusion_matrix")
    test_nlp_extractor_evaluation()
    print("  [PASS] test_nlp_extractor_evaluation")
    test_missing_ground_truth_safety()
    print("  [PASS] test_missing_ground_truth_safety")
    print("ALL MODEL EVALUATION MODULE UNIT TESTS PASSED!")
