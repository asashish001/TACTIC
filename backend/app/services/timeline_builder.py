"""TACTIC Complete Multi-Source Forensic Timeline Reconstruction Engine."""
import datetime
import logging
from typing import Any
from sqlalchemy.orm import Session

from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.extracted_artifact import ExtractedArtifact
from app.models.browser_artifact import BrowserArtifact
from app.models.network_artifact import NetworkArtifact
from app.models.artifact_correlation import ArtifactCorrelation
from app.services.timezone_service import (
    format_for_timezone,
    normalize_to_utc,
    safe_parse_timestamp,
)

logger = logging.getLogger("tactic.timeline_builder")


def build_forensic_timeline(
    case_id: int,
    db: Session,
    target_timezone: str = "UTC"
) -> dict[str, Any]:
    """Collect artifacts across all evidence sources, normalize timestamps, group correlated events, and return stable timeline schema."""
    raw_event_items = []
    seq_counter = 0

    # Query correlation mapping for this case
    corr_records = db.query(ArtifactCorrelation).filter(ArtifactCorrelation.case_id == case_id).all()
    corr_map = {}
    for c in corr_records:
        corr_map[c.artifact_a_id] = {"score": c.score, "category": c.strength_category, "reason": c.reason, "group_id": f"group_{c.correlation_type.lower()}_{c.id}"}
        corr_map[c.artifact_b_id] = {"score": c.score, "category": c.strength_category, "reason": c.reason, "group_id": f"group_{c.correlation_type.lower()}_{c.id}"}

    # 1. Fetch Evidence items & internal metadata (EVTX, EXIF, PDF, DOCX)
    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    for item in evidence_items:
        seq_counter += 1
        raw_event_items.append({
            "seq": seq_counter,
            "event_id": f"ev_ingest_{item.id}",
            "event": f"Evidence file ingested: {item.filename}",
            "raw_timestamp": item.ingested_at,
            "evidence_source": item.filename,
            "priority": "info",
            "is_suspicious": False,
            "confidence": 1.0,
            "evidence_id": item.id,
            "artifact_id": f"evidence_{item.id}",
            "artifact_type": "evidence_container",
            "provider": "Ingest Engine",
            "details": {"mime": item.detected_mime, "sha256": item.sha256, "file_size": item.file_size}
        })

        meta = item.extracted_metadata or {}
        
        # Image EXIF
        if meta.get("kind") == "image" and meta.get("timestamp"):
            seq_counter += 1
            raw_event_items.append({
                "seq": seq_counter,
                "event_id": f"ev_exif_{item.id}",
                "event": "Image captured (EXIF DateTimeOriginal)",
                "raw_timestamp": meta.get("timestamp"),
                "evidence_source": item.filename,
                "priority": "low",
                "is_suspicious": False,
                "confidence": 0.90,
                "evidence_id": item.id,
                "artifact_id": f"exif_{item.id}",
                "artifact_type": "exif_metadata",
                "provider": "EXIF Extractor",
                "details": {
                    "original_timestamp": meta.get("original_timestamp"),
                    "original_timezone": meta.get("original_timezone"),
                    "camera_make": meta.get("camera_make"),
                    "camera_model": meta.get("camera_model")
                }
            })

        # PDF creation
        if meta.get("kind") == "pdf" and meta.get("creation_date"):
            seq_counter += 1
            raw_event_items.append({
                "seq": seq_counter,
                "event_id": f"ev_pdf_{item.id}",
                "event": f"PDF document created (Author: {meta.get('author') or 'Unknown'})",
                "raw_timestamp": meta.get("creation_date"),
                "evidence_source": item.filename,
                "priority": "low",
                "is_suspicious": False,
                "confidence": 0.90,
                "evidence_id": item.id,
                "artifact_id": f"pdf_{item.id}",
                "artifact_type": "pdf_metadata",
                "provider": "PDF Parser",
                "details": {"original_timestamp": meta.get("original_creation_date"), "title": meta.get("title")}
            })

        # DOCX creation
        if meta.get("kind") == "docx" and meta.get("created"):
            seq_counter += 1
            raw_event_items.append({
                "seq": seq_counter,
                "event_id": f"ev_docx_{item.id}",
                "event": "DOCX document created",
                "raw_timestamp": meta.get("created"),
                "evidence_source": item.filename,
                "priority": "low",
                "is_suspicious": False,
                "confidence": 0.90,
                "evidence_id": item.id,
                "artifact_id": f"docx_{item.id}",
                "artifact_type": "docx_metadata",
                "provider": "DOCX Parser",
                "details": {"original_timestamp": meta.get("original_created"), "author": meta.get("author")}
            })

        # EVTX log records
        if meta.get("kind") == "evtx" and "records" in meta:
            for rec_idx, record in enumerate(meta["records"]):
                seq_counter += 1
                ev_id = record.get("event_id", 0)
                timestamp = record.get("timestamp")
                provider = record.get("provider", "Security")
                
                is_suspicious = ev_id in (4625, 4688, 6416, 1)
                priority = "critical" if ev_id == 4625 else "high" if ev_id in (4688, 6416, 1) else "info"
                
                raw_event_items.append({
                    "seq": seq_counter,
                    "event_id": f"evtx_{item.id}_{ev_id}_{rec_idx}",
                    "event": f"Windows Log Event ID {ev_id} ({provider})",
                    "raw_timestamp": timestamp,
                    "evidence_source": item.filename,
                    "priority": priority,
                    "is_suspicious": is_suspicious,
                    "confidence": 0.95 if is_suspicious else 0.80,
                    "evidence_id": item.id,
                    "artifact_id": f"evtx_rec_{item.id}_{rec_idx}",
                    "artifact_type": "evtx_record",
                    "provider": provider,
                    "details": record.get("data", {})
                })

    # 2. Fetch ExtractedArtifacts (NLP / rule-based)
    ext_arts = db.query(ExtractedArtifact).filter(ExtractedArtifact.case_id == case_id).all()
    for art in ext_arts:
        seq_counter += 1
        art_id_key = f"ext_{art.id}"
        is_susp = art.artifact_type in ("ip", "command", "process", "session_id")
        
        raw_event_items.append({
            "seq": seq_counter,
            "event_id": f"extracted_art_{art.id}",
            "event": f"Extracted {art.artifact_type.upper()}: {art.value[:35]}",
            "raw_timestamp": art.extracted_at,
            "evidence_source": art.evidence.filename if art.evidence else "NLP Extractor",
            "priority": "high" if is_susp else "medium",
            "is_suspicious": is_susp,
            "confidence": round(float(art.confidence), 2),
            "evidence_id": art.evidence_id,
            "artifact_id": art_id_key,
            "artifact_type": art.artifact_type,
            "provider": f"Extractor ({art.extractor})",
            "details": {
                "value": art.value,
                "context_snippet": art.context_snippet,
                "start_char": art.start_char,
                "end_char": art.end_char
            }
        })

    # 3. Fetch BrowserArtifacts
    browser_arts = db.query(BrowserArtifact).filter(BrowserArtifact.case_id == case_id).all()
    for b in browser_arts:
        seq_counter += 1
        b_id_key = f"browser_{b.id}"
        raw_event_items.append({
            "seq": seq_counter,
            "event_id": f"browser_art_{b.id}",
            "event": f"Browser {b.artifact_type.replace('_', ' ').title()}: {b.domain or b.url or b.title or 'Record'[:35]}",
            "raw_timestamp": getattr(b, "timestamp", None),
            "evidence_source": f"Browser ({b.browser})",
            "priority": "medium",
            "is_suspicious": False,
            "confidence": 0.90,
            "evidence_id": b.evidence_id,
            "artifact_id": b_id_key,
            "artifact_type": f"browser_{b.artifact_type}",
            "provider": f"Browser ({b.browser})",
            "details": {
                "url": b.url,
                "domain": b.domain,
                "title": b.title,
                "visit_count": getattr(b, "visit_count", None),
                "username_value": getattr(b, "username_value", None)
            }
        })

    # 4. Fetch NetworkArtifacts
    net_arts = db.query(NetworkArtifact).filter(NetworkArtifact.case_id == case_id).all()
    for n in net_arts:
        seq_counter += 1
        net_id_key = f"net_{n.id}"
        val = n.destination_ip or n.source_ip or n.domain or ""
        raw_event_items.append({
            "seq": seq_counter,
            "event_id": f"net_art_{n.id}",
            "event": f"Network Session ({n.protocol}): {val}",
            "raw_timestamp": getattr(n, "timestamp", None),
            "evidence_source": f"PCAP ({n.protocol})",
            "priority": "medium",
            "is_suspicious": False,
            "confidence": 0.90,
            "evidence_id": n.evidence_id,
            "artifact_id": net_id_key,
            "artifact_type": "network_packet",
            "provider": "Network Forensic Engine",
            "details": {
                "source_ip": n.source_ip,
                "destination_ip": n.destination_ip,
                "source_port": n.source_port,
                "destination_port": n.destination_port,
                "protocol": n.protocol,
                "length_bytes": getattr(n, "length_bytes", None)
            }
        })

    # 5. Fetch Findings
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    for f in findings:
        seq_counter += 1
        f_id_key = f"finding_{f.id}"
        raw_event_items.append({
            "seq": seq_counter,
            "event_id": f"finding_evt_{f.id}",
            "event": f"AI Threat Alert: {f.title}",
            "raw_timestamp": f.created_at,
            "evidence_source": f.evidence.filename if f.evidence else "AI Risk Engine",
            "priority": f.severity.lower(),
            "is_suspicious": True,
            "confidence": round(float(f.risk_score) / 100.0, 2),
            "evidence_id": f.evidence_id,
            "artifact_id": f_id_key,
            "artifact_type": "ai_finding",
            "provider": "PyTorch / Isolation Forest AI",
            "details": {
                "threat_category": f.threat_category,
                "reason": f.reason,
                "recommendation": f.recommendation,
                "finding_details": f.details
            }
        })

    # Normalize timestamps, convert to target timezone, attach correlation metadata, and sort
    processed_events = []
    suspicious_count = 0

    for item in raw_event_items:
        raw_ts = item["raw_timestamp"]
        utc_dt, orig_str, orig_tz = normalize_to_utc(raw_ts) if raw_ts else (None, None, None)

        if utc_dt:
            tz_info = format_for_timezone(utc_dt, target_tz=target_timezone)
            iso_utc = tz_info["utc_iso"]
            disp_ts = tz_info["formatted"]
            tz_badge = f"{tz_info['tz_name']} ({tz_info['offset_str']})"
            sort_ts_val = utc_dt.timestamp()
        else:
            iso_utc = None
            disp_ts = "No Timestamp / Missing"
            tz_badge = "MISSING"
            sort_ts_val = float('inf') # Push missing timestamps safely to end

        # Lookup correlation metadata
        art_id = item["artifact_id"]
        c_info = corr_map.get(art_id, {})
        c_score = c_info.get("score")
        c_cat = c_info.get("category")
        c_grp = c_info.get("group_id")

        if item["is_suspicious"]:
            suspicious_count += 1

        event_entry = {
            "event_id": item["event_id"],
            "event": item["event"],
            "timestamp": iso_utc,
            "original_timestamp": orig_str or iso_utc or "MISSING",
            "original_timezone": orig_tz or "+00:00",
            "display_timestamp": disp_ts,
            "target_timezone": target_timezone,
            "timezone_badge": tz_badge,
            "priority": item["priority"],
            "is_suspicious": item["is_suspicious"],
            "confidence": item["confidence"],
            "correlation_score": c_score,
            "correlation_category": c_cat,
            "correlated_group_id": c_grp,
            "evidence_id": item["evidence_id"],
            "artifact_id": item["artifact_id"],
            "artifact_type": item["artifact_type"],
            "evidence_source": item["evidence_source"],
            "provider": item["provider"],
            "details": item["details"]
        }

        processed_events.append((sort_ts_val, item["seq"], event_entry))

    # Stable chronological sort by UTC timestamp, then by sequence insertion index
    processed_events.sort(key=lambda t: (t[0], t[1]))
    final_events = [t[2] for t in processed_events]

    return {
        "case_id": case_id,
        "session_id": case_id,
        "total_events": len(final_events),
        "suspicious_count": suspicious_count,
        "target_timezone": target_timezone,
        "events": final_events
    }


def extract_timeline_events(case_id: int, db: Session, target_timezone: str = "UTC") -> list[dict]:
    """Legacy helper returning event list for backward compatibility."""
    result = build_forensic_timeline(case_id, db, target_timezone=target_timezone)
    return result["events"]
