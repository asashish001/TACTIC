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


@router.get("/api/dashboard")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Aggregate global statistics for the dashboard view."""
    from app.models.case import Case
    from app.models.evidence import Evidence
    from app.models.finding import Finding
    from app.models.intelligence import ThreatIntelIndicator
    cases_count = db.query(Case).count()
    evidence_count = db.query(Evidence).count()
    threats_count = db.query(ThreatIntelIndicator).count()
    
    recent_findings = db.query(Finding).order_by(Finding.risk_score.desc()).limit(3).all()
    
    alerts = []
    for f in recent_findings:
        alerts.append({
            "severity": f.severity,
            "time": f.created_at.strftime("%I:%M %p"),
            "source": f.threat_category or "System",
            "description": f.title,
            "status": "Investigating"
        })
        
    return {
        "stats": {
            "active_cases": cases_count,
            "active_threats": threats_count,
            "processed_artifacts": evidence_count,
            "ai_detections": len(recent_findings),
            "active_agents": 3
        },
        "recent_alerts": alerts
    }

@router.get("/api/dashboard/summary")
def get_dashboard_summary(db: Session = Depends(get_db)):
    """Generate an AI executive triage summary based on the highest risk findings."""
    from app.models.finding import Finding
    
    recent_findings = db.query(Finding).filter(Finding.severity.in_(["critical", "high"])).order_by(Finding.risk_score.desc()).limit(5).all()
    
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
