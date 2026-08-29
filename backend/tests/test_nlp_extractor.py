import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.ai.nlp_extractor import NLPArtifactExtractor, nlp_extractor_instance


def test_model_status():
    """Verify that /model/status info contains mandatory keys."""
    status = nlp_extractor_instance.get_status()
    assert "model_name" in status
    assert "version" in status
    assert "loaded" in status
    assert "error_state" in status
    assert isinstance(status["loaded"], bool)


def test_nlp_extractor_all_13_artifact_types():
    """Verify extraction of all 13 mandatory artifact types with source evidence linking."""
    sample_forensic_text = (
        "2026-08-02T10:15:00Z - Forensic Investigation Report\n"
        "Investigator: Alice Smith\n"
        "User: admin_john@corp.local\n"
        "Target Account: SubjectUserName: jsmith\n"
        "Source IP: 192.168.1.105 connected to destination domain: malware-c2-server.com\n"
        "Target URL: https://malware-c2-server.com/payload.bin\n"
        "Alert Email: security-team@forensics.org\n"
        "Malicious File Path: C:\\Windows\\System32\\mimikatz.exe\n"
        "Unix Storage Path: /var/log/auth.log\n"
        "Suspicious Process Execution: powershell.exe -ExecutionPolicy Bypass -File C:\\script.ps1\n"
        "Workstation Hostname: WIN-SRV2026-DC\n"
        "Security Session ID: S-1-5-21-3623811015-3361044348-30300820-1013\n"
        "UUID Token: 550e8400-e29b-41d4-a716-446655440000\n"
        "Command: net user attacker P@ssw0rd123 /add\n"
        "Event ID 4625: Failed login attempt detected on authentication server.\n"
    )

    extractor = NLPArtifactExtractor()
    artifacts = extractor.extract_artifacts(sample_forensic_text, case_id=1, evidence_id=42)

    extracted_types = {item["artifact_type"] for item in artifacts}
    
    # Mandatory 13 types: PERSON, USERNAME, IP_ADDRESS, DOMAIN, URL, EMAIL,
    # FILE_PATH, PROCESS, HOSTNAME, TIMESTAMP, SESSION_ID, COMMAND, EVENT
    required_types = {
        "PERSON", "USERNAME", "IP_ADDRESS", "DOMAIN", "URL", "EMAIL",
        "FILE_PATH", "PROCESS", "HOSTNAME", "TIMESTAMP", "SESSION_ID", "COMMAND", "EVENT"
    }

    missing_types = required_types - extracted_types
    assert not missing_types, f"Missing entity types: {missing_types}"

    # Verify source evidence linking and non-null properties
    for item in artifacts:
        assert item["case_id"] == 1
        assert item["evidence_id"] == 42
        assert item["source_evidence_id"] == 42  # Source evidence linking requirement!
        assert item["value"] is not None and len(str(item["value"])) > 0
        assert 0.0 <= item["confidence"] <= 1.0
        assert item["extractor"] in ("transformer-ner", "regex-fallback", "rule-based", "hybrid")
        assert item["context_snippet"] is not None


def test_fallback_when_model_load_fails():
    """Verify that failure in model loading falls back seamlessly to deterministic extraction."""
    invalid_extractor = NLPArtifactExtractor(model_name="nonexistent/invalid-transformer-model-xyz")
    assert invalid_extractor.loaded is False
    assert invalid_extractor.error_state is not None
    
    status = invalid_extractor.get_status()
    assert status["loaded"] is False
    assert status["error_state"] is not None

    # Extraction must still succeed cleanly via fallback pipeline
    test_text = "Suspicious connection to 10.0.0.5 by user admin."
    artifacts = invalid_extractor.extract_artifacts(test_text, case_id=2, evidence_id=99)
    assert len(artifacts) > 0
    assert any(a["artifact_type"] == "IP_ADDRESS" and a["value"] == "10.0.0.5" for a in artifacts)
    assert all(a["source_evidence_id"] == 99 for a in artifacts)


if __name__ == "__main__":
    print("Running NLP Extractor Unit Tests...")
    test_model_status()
    print("  [PASS] test_model_status")
    test_nlp_extractor_all_13_artifact_types()
    print("  [PASS] test_nlp_extractor_all_13_artifact_types")
    test_fallback_when_model_load_fails()
    print("  [PASS] test_fallback_when_model_load_fails")
    print("ALL NLP EXTRACTOR UNIT TESTS PASSED!")
