"""System-level endpoints: health check and model status."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.health_service import check_system_health
from app.services.model_registry_service import (
    get_model_status_summary,
    seed_default_model_registry,
)

router = APIRouter(tags=["System"])


@router.get("/api/health")
@router.get("/api/health/details")
def health_check(db: Session = Depends(get_db)):
    """Comprehensive system health check: DB latency, NLP/ML model status,
    storage usage, and uptime."""
    return check_system_health(db)


@router.get("/model/status")
def get_global_model_status(db: Session = Depends(get_db)):
    """Active models, versions, loading status, evaluation metrics,
    and XAI availability."""
    seed_default_model_registry(db)
    active = get_model_status_summary(db)
    return {
        "loaded": True,
        "model_name": "TACTIC AI Model Suite (v2.0.0)",
        "error_state": None,
        "active_models": active,
    }


from app.models.case import Case
from app.models.forensic_job import ForensicJob
from sqlalchemy import func
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.intelligence import ThreatIntelIndicator
from app.models.forensic_records import TimelineEvent
import datetime

@router.get("/api/dashboard")
def get_dashboard_stats(case_id: int | None = None, db: Session = Depends(get_db)):
    """Aggregate global statistics for the dashboard view, optionally filtered by case."""
    
    if case_id:
        cases_count = 1
        evidence_count = db.query(Evidence).filter(Evidence.case_id == case_id).count()
        threats_count = db.query(ThreatIntelIndicator).count()
        recent_findings = db.query(Finding).filter(Finding.case_id == case_id).order_by(Finding.risk_score.desc()).limit(3).all()
        evidence_items = db.query(Evidence.extension).filter(Evidence.case_id == case_id).all()
        events = db.query(TimelineEvent.generated_at).filter(TimelineEvent.case_id == case_id).all()
        
        critical_alerts = db.query(Finding).filter(Finding.case_id == case_id, Finding.severity == 'critical').count()
        analysis_jobs = db.query(ForensicJob).filter(ForensicJob.case_id == case_id).count()
        ev_size_res = db.query(func.sum(Evidence.file_size)).filter(Evidence.case_id == case_id).scalar()
        total_evidence_size = ev_size_res if ev_size_res else 0
    else:
        cases_count = db.query(Case).count()
        evidence_count = db.query(Evidence).count()
        threats_count = db.query(ThreatIntelIndicator).count()
        recent_findings = db.query(Finding).order_by(Finding.risk_score.desc()).limit(3).all()
        evidence_items = db.query(Evidence.extension).all()
        events = db.query(TimelineEvent.generated_at).all()
        
        critical_alerts = db.query(Finding).filter(Finding.severity == 'critical').count()
        analysis_jobs = db.query(ForensicJob).count()
        ev_size_res = db.query(func.sum(Evidence.file_size)).scalar()
        total_evidence_size = ev_size_res if ev_size_res else 0
    
    alerts = []
    for f in recent_findings:
        alerts.append({
            "id": f.id,
            "title": f.title,
            "severity": f.severity,
            "time": f.created_at.strftime("%I:%M %p"),
            "source": f.threat_category or "System",
            "description": f.title,
            "full_description": f.description,
            "status": "Investigating",
            "threat_category": f.threat_category,
            "confidence": f.confidence,
            "reason": f.reason,
            "recommendation": f.recommendation,
            "details": f.details,
            "evidence_filename": f.evidence.filename if f.evidence else "Unknown Source"
        })
        
    # --- Chart Data Calculation ---
    
    # 1. Evidence Types
    evidence_types = {"Disk Images": 0, "Memory Dumps": 0, "Documents": 0, "Logs & Network": 0, "Other": 0}
    for (ext,) in evidence_items:
        ext = ext.lower().replace(".", "") if ext else ""
        if ext in ["e01", "dd", "iso", "raw", "img", "ova", "001"]:
            evidence_types["Disk Images"] += 1
        elif ext in ["mem", "vmem", "dmp"]:
            evidence_types["Memory Dumps"] += 1
        elif ext in ["pdf", "docx", "txt", "csv", "xlsx", "doc", "rtf", "msg"]:
            evidence_types["Documents"] += 1
        elif ext in ["pcap", "pcapng", "log", "evtx", "evt", "json"]:
            evidence_types["Logs & Network"] += 1
        else:
            evidence_types["Other"] += 1
            
    # Filter out categories with 0 to keep the donut chart clean, unless all are 0
    filtered_types = {k: v for k, v in evidence_types.items() if v > 0}
    if not filtered_types:
        filtered_types = {"No Evidence": 1} # placeholder for empty state
    
    evidence_labels = list(filtered_types.keys())
    evidence_data = list(filtered_types.values())

    # 2. Timeline Events (Dynamic Last 7 Days based on newest event)
    valid_dates = []
    if case_id:
        from app.services.timeline_builder import build_forensic_timeline
        from dateutil.parser import parse as parse_date
        t_payload = build_forensic_timeline(case_id, db)
        for ev in t_payload.get("events", []):
            rt = ev.get("original_timestamp") or ev.get("timestamp")
            if isinstance(rt, datetime.datetime):
                valid_dates.append(rt.date())
            elif isinstance(rt, str) and rt != "MISSING":
                try:
                    valid_dates.append(parse_date(rt).date())
                except Exception:
                    pass
    else:
        events = db.query(Evidence.ingested_at).all()
        valid_dates = [gen_at.date() for (gen_at,) in events if gen_at]
    
    if valid_dates:
        today = max(valid_dates)
    else:
        today = datetime.datetime.now(datetime.timezone.utc).date()
        
    dates = [(today - datetime.timedelta(days=i)) for i in range(6, -1, -1)]
    timeline_labels = [d.strftime("%a") for d in dates]
    events_per_day = {d: 0 for d in dates}
    
    for d in valid_dates:
        if d in events_per_day:
            events_per_day[d] += 1
            
    timeline_data = [events_per_day[d] for d in dates]

    return {
        "stats": {
            "active_cases": cases_count,
            "active_threats": threats_count,
            "processed_artifacts": evidence_count,
            "ai_detections": len(recent_findings),
            "critical_alerts": critical_alerts,
            "analysis_jobs": analysis_jobs,
            "total_evidence_size": total_evidence_size
        },
        "recent_alerts": alerts,
        "charts": {
            "evidence": {
                "labels": evidence_labels,
                "data": evidence_data
            },
            "timeline": {
                "labels": timeline_labels,
                "data": timeline_data
            }
        }
    }

@router.get("/api/dashboard/summary")
def get_dashboard_summary(case_id: int | None = None, db: Session = Depends(get_db)):
    """Generate an AI executive triage summary based on the highest risk findings."""
    from app.models.finding import Finding
    
    query = db.query(Finding).filter(Finding.severity.in_(["critical", "high"]))
    if case_id:
        query = query.filter(Finding.case_id == case_id)
        
    recent_findings = query.order_by(Finding.risk_score.desc()).limit(5).all()
    
    if not recent_findings:
        return {"summary": "The system is currently stable. There are no high-severity active alerts requiring immediate triage."}
        
    intro = f"The TACTIC engine has identified {len(recent_findings)} critical or high-severity threats demanding immediate attention. "
    
    body = "Key observations include: "
    observations = []
    for f in recent_findings:
        target = f.title
        if isinstance(f.details, dict):
            target = f.details.get("ip") or f.details.get("domain") or f.title
        observations.append(f"{f.threat_category} involving '{target}' (Risk Score: {f.risk_score})")
    
    body += "; ".join(observations) + ". "
    
    conclusion = "Recommendation: Isolate affected hosts and begin incident response procedures immediately to prevent further lateral movement or data exfiltration."
    
    return {"summary": intro + body + conclusion}
