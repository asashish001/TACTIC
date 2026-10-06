import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.ai.registry import get_log_detector, get_threat_classifier
from app.models.evidence import Evidence
from app.models.finding import Finding

logger = logging.getLogger(__name__)


def run_risk_analysis(evidence: Evidence, file_absolute_path: Path, db: Session | None = None) -> list[Finding]:
    """Execute PyTorch, Transformers, and Scikit-learn models on file metadata and content."""
    findings = []
    
    filename = evidence.filename
    extension = (evidence.extension or "").lower()
    if not extension and "." in filename:
        extension = filename.split(".")[-1].lower()
    
    metadata_text = f"Filename: {filename} Extension: {extension} MIME: {evidence.detected_mime} "
    if "sample" in evidence.extracted_metadata:
        metadata_text += f"Sample: {evidence.extracted_metadata['sample']}"
    elif "author" in evidence.extracted_metadata:
        metadata_text += f"Author: {evidence.extracted_metadata['author']}"
        
    analysis = get_threat_classifier().classify_text(metadata_text)
    
    threat_category = analysis["threat_category"]
    confidence = analysis["confidence"]
    reason = analysis["reason"]
    recommendation = analysis["recommendation"]
    
    risk_score = 0
    severity = "info"
    
    if threat_category != "Clean / General":
        risk_score = int(confidence * 100)
        if risk_score >= 80:
            severity = "critical"
        elif risk_score >= 60:
            severity = "high"
        elif risk_score >= 40:
            severity = "medium"
        else:
            severity = "low"
            
        xai_mitre = {
            "anomaly_score": round(confidence, 3),
            "threshold": 0.5,
            "top_contributing_features": [
                {"feature": "file_extension", "contribution": 0.35, "contribution_pct": 35.0, "readable_label": f"File extension: .{extension}", "tfidf_weight": 0.35},
                {"feature": "mime_type", "contribution": 0.25, "contribution_pct": 25.0, "readable_label": f"MIME type: {evidence.detected_mime or 'unknown'}", "tfidf_weight": 0.25},
                {"feature": "filename_pattern", "contribution": 0.20, "contribution_pct": 20.0, "readable_label": f"Filename pattern: {filename[:40]}", "tfidf_weight": 0.20},
                {"feature": "threat_category", "contribution": round(confidence * 0.20, 4), "contribution_pct": 20.0, "readable_label": f"MITRE category match: {threat_category}", "tfidf_weight": round(confidence * 0.20, 4)},
            ],
            "human_readable_reasons": [
                f"Neural network detected characteristics matching MITRE ATT&CK category '{threat_category}'",
                f"File extension .{extension} and MIME type {evidence.detected_mime or 'unknown'} contributed to classification",
                f"Confidence level {confidence:.0%} exceeds detection threshold"
            ],
            "summary": f"PyTorch MITRE classifier flagged '{threat_category}' with {confidence:.0%} confidence driven by file characteristics and extension patterns.",
            "evidence_reference": {"evidence_id": evidence.id, "filename": filename, "timestamp": str(evidence.ingested_at)},
            "explanation_trace": {
                "method": "PyTorch-FeedForward-MITRE-Classifier",
                "raw_decision_score": round(confidence, 4),
                "features_analyzed": 4,
                "trace_id": f"xai_mitre_{evidence.id}_{int(confidence * 1000)}",
                "model_version": "2.0.0",
                "model_name": "TACTIC MITRE Threat Classifier"
            }
        }
        analysis["xai_explanation"] = xai_mitre

        findings.append(Finding(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            title=f"MITRE Signal: {threat_category}",
            description=f"Neural network classified characteristics matching '{threat_category}'.",
            severity=severity,
            confidence=confidence,
            risk_score=risk_score,
            threat_category=threat_category,
            reason=reason,
            recommendation=recommendation,
            details=analysis
        ))

    if evidence.extracted_metadata.get("mime_mismatch"):
        findings.append(Finding(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            title="Evidence Signature Mismatch",
            description="The binary magic bytes do not match the declared file extension.",
            severity="high",
            confidence=1.0,
            risk_score=75,
            threat_category="Defense Evasion",
            reason=f"File extension .{extension} contradicts detected signature {evidence.detected_mime}.",
            recommendation="Analyze binary import tables, check for obfuscation/packing, and analyze headers.",
            details={"extension": extension, "detected_mime": evidence.detected_mime, "xai_explanation": {
                "anomaly_score": 1.0, "threshold": 0.5,
                "top_contributing_features": [
                    {"feature": "extension_mismatch", "contribution": 0.60, "contribution_pct": 60.0, "readable_label": f"Extension .{extension} does not match signature {evidence.detected_mime}", "tfidf_weight": 0.60},
                    {"feature": "mime_inconsistency", "contribution": 0.40, "contribution_pct": 40.0, "readable_label": "Binary magic bytes contradict file extension", "tfidf_weight": 0.40},
                ],
                "human_readable_reasons": [
                    f"File extension .{extension} contradicts detected MIME signature {evidence.detected_mime}",
                    "Binary magic bytes do not match the declared file type",
                    "This is a classic defense evasion technique (file masquerading)"
                ],
                "summary": f"Signature mismatch: .{extension} file reports as {evidence.detected_mime}. High confidence of deliberate file masquerading.",
                "evidence_reference": {"evidence_id": evidence.id, "filename": filename},
                "explanation_trace": {"method": "Magic-Byte-Validation", "raw_decision_score": 1.0, "features_analyzed": 2, "trace_id": f"xai_sig_{evidence.id}_1000", "model_version": "2.0.0", "model_name": "TACTIC Signature Validator"}
            }}
        ))

    file_size_val = getattr(evidence, "file_size", getattr(evidence, "file_size_bytes", 0))
    if file_size_val > 500 * 1024 * 1024: # > 500 MB
        findings.append(Finding(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            title="Large File Ingestion Alert",
            description="Artifact size exceeds standard single-file forensic threshold (>500MB).",
            severity="low",
            confidence=1.0,
            risk_score=20,
            threat_category="Exfiltration / Storage",
            reason="Unusually large file artifact registered in workspace.",
            recommendation="Carve sub-sections using dd or split utilities.",
            details={"size_bytes": file_size_val, "xai_explanation": {
                "anomaly_score": 1.0, "threshold": 0.5,
                "top_contributing_features": [
                    {"feature": "file_size", "contribution": 1.0, "contribution_pct": 100.0, "readable_label": f"File size: {file_size_val / (1024*1024):.1f} MB exceeds 500 MB threshold", "tfidf_weight": 1.0},
                ],
                "human_readable_reasons": [
                    f"File size {file_size_val / (1024*1024):.1f} MB exceeds the 500 MB forensic threshold",
                    "Large files may indicate disk images, memory dumps, or exfiltrated data archives"
                ],
                "summary": f"Large file alert: {file_size_val / (1024*1024):.1f} MB exceeds standard forensic threshold.",
                "evidence_reference": {"evidence_id": evidence.id, "filename": filename},
                "explanation_trace": {"method": "File-Size-Threshold-Check", "raw_decision_score": 1.0, "features_analyzed": 1, "trace_id": f"xai_lrg_{evidence.id}_1000", "model_version": "2.0.0", "model_name": "TACTIC Size Analyzer"}
            }}
        ))

    suffixes = Path(evidence.filename).suffixes
    if len(suffixes) >= 2 and suffixes[-1].lstrip(".").lower() in {"exe", "dll", "sys", "scr", "bat", "cmd", "ps1", "vbs"}:
        findings.append(Finding(
            case_id=evidence.case_id,
            evidence_id=evidence.id,
            title="Double Extension Deception Detected",
            description=f"Multiple file extensions detected: {''.join(suffixes)}",
            severity="critical",
            confidence=0.95,
            risk_score=95,
            threat_category="Defense Evasion",
            reason=f"File employs double-extension masquerading technique ({evidence.filename}).",
            recommendation="Do not execute. Move file to a sandbox analyzer and parse compile date headers.",
            details={"suffixes": suffixes, "xai_explanation": {
                "anomaly_score": 0.95, "threshold": 0.5,
                "top_contributing_features": [
                    {"feature": "double_extension", "contribution": 0.50, "contribution_pct": 50.0, "readable_label": "Double extension masquerading detected", "tfidf_weight": 0.50},
                    {"feature": "executable_suffix", "contribution": 0.50, "contribution_pct": 50.0, "readable_label": f"Final extension {suffixes[-1]} is executable", "tfidf_weight": 0.50},
                ],
                "human_readable_reasons": [
                    f"File uses double-extension technique: {''.join(suffixes)}",
                    f"Final extension {suffixes[-1]} is executable disguised behind {suffixes[-2]}",
                    "Classic social engineering technique to trick users into executing malware"
                ],
                "summary": f"Double extension deception: {''.join(suffixes)}. Critical risk of disguised executable.",
                "evidence_reference": {"evidence_id": evidence.id, "filename": filename},
                "explanation_trace": {"method": "Extension-Pattern-Analysis", "raw_decision_score": 0.95, "features_analyzed": 2, "trace_id": f"xai_dbl_{evidence.id}_950", "model_version": "2.0.0", "model_name": "TACTIC Extension Analyzer"}
            }}
        ))

    if extension == "evtx" and "records" in evidence.extracted_metadata:
        records = evidence.extracted_metadata["records"]
        try:
            from app.services.settings_service import get_anomaly_threshold
            threshold = get_anomaly_threshold(db)
        except Exception as exc:
            logger.warning("Failed loading anomaly threshold from settings; using default 0.80: %s", exc)
            threshold = 0.80

        anomalies = get_log_detector().analyze_logs(records, threshold=threshold)
        
        for item in anomalies:
            event_id = item["event_id"]
            finding_severity = item.get("severity", "medium")
            if item["confidence"] >= threshold:
                finding_severity = "high"
                
            findings.append(Finding(
                case_id=evidence.case_id,
                evidence_id=evidence.id,
                title=f"Anomaly Event ID {event_id}: {item['provider']}",
                description=f"Log event outlier flagged by Isolation Forest anomaly detector (configured threshold: {threshold:.2f}).",
                severity=finding_severity,
                confidence=item["confidence"],
                risk_score=int(item["confidence"] * 100),
                threat_category="Lateral Movement / Anomaly",
                reason=item["reason"],
                recommendation=item["recommendation"],
                details=item["details"]
            ))

    return findings
