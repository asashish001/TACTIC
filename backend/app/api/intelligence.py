import math
from pydantic import BaseModel
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session

from app.auth.security import RoleChecker, get_current_user, require_case_access
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_HEAVY
from app.database.session import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.intelligence import ThreatIntelIndicator, VulnerabilityMatch
from app.models.user import User
from app.schemas.intelligence import IntelligenceAnalysisResponse, ThreatIndicatorResponse, VulnerabilityMatchResponse
from app.services.threat_intelligence import extract_iocs, extract_software, lookup_cves, remote_lookups_enabled

router = APIRouter(prefix="/api/intelligence", tags=["CVE & Threat Intelligence"])


@router.post("/cases/{case_id}/analyze", response_model=IntelligenceAnalysisResponse)
@limiter.limit(RATE_LIMIT_HEAVY)
def analyze_case_intelligence(request: Request, case_id: int, db: Session = Depends(get_db), current_user: User = Depends(RoleChecker(["admin", "investigator"]))):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    db.query(VulnerabilityMatch).filter(VulnerabilityMatch.case_id == case_id).delete()
    db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.case_id == case_id).delete()
    db.query(Finding).filter(Finding.case_id == case_id, Finding.details["source"].as_string() == "threat_intelligence").delete(synchronize_session=False)
    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    identified, cve_count, ioc_count, warnings = 0, 0, 0, []
    for evidence in evidence_items:
        for ioc in extract_iocs(evidence):
            db.add(ThreatIntelIndicator(case_id=case_id, evidence_id=evidence.id, **ioc))
            ioc_count += 1
        for software in extract_software(evidence):
            identified += 1
            try:
                matches = lookup_cves(software["product"], software["version"])
            except Exception as exc:
                warnings.append(f"CVE lookup failed for {software['product']} {software['version']}: {exc}")
                continue
            for match in matches:
                record = VulnerabilityMatch(case_id=case_id, evidence_id=evidence.id, product=software["product"], version=software["version"], cpe_uri=None, **match)
                db.add(record)
                cve_count += 1
                db.add(Finding(case_id=case_id, evidence_id=evidence.id, title=f"CVE correlation: {match['cve_id']}", description=match["description"] or f"Known vulnerability matched to {software['product']} {software['version']}.", severity=match["severity"] if match["severity"] in {"critical", "high", "medium", "low"} else "info", confidence=0.8, risk_score=match["risk_score"], threat_category="Vulnerability Intelligence", reason=f"Observed software indicator {software['product']} {software['version']} correlated with {match['cve_id']}." + (" Listed in CISA KEV." if match["is_kev"] else ""), recommendation="Validate the installed version and patch or isolate affected systems according to the vendor advisory.", details={"source": "threat_intelligence", "cve_id": match["cve_id"], "cvss_score": match["cvss_score"], "epss_score": match["epss_score"], "is_kev": match["is_kev"]}))
    db.commit()
    return IntelligenceAnalysisResponse(case_id=case_id, software_identified=identified, vulnerabilities_found=cve_count, indicators_found=ioc_count, remote_lookups_enabled=remote_lookups_enabled(), warnings=warnings)


class PaginatedVulnerabilityResponse(BaseModel):
    items: list[VulnerabilityMatchResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

class PaginatedIndicatorResponse(BaseModel):
    items: list[ThreatIndicatorResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

@router.get("/cases/{case_id}/vulnerabilities", response_model=PaginatedVulnerabilityResponse)
@limiter.limit(RATE_LIMIT_READ)
def list_vulnerabilities(request: Request, case_id: int, page: int = 1, page_size: int = 50, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    page_size = min(max(page_size, 1), 200)
    total = db.query(VulnerabilityMatch).filter(VulnerabilityMatch.case_id == case_id).count()
    total_pages = max(1, math.ceil(total / page_size))
    items = db.query(VulnerabilityMatch).filter(VulnerabilityMatch.case_id == case_id).order_by(VulnerabilityMatch.risk_score.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedVulnerabilityResponse(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)


@router.get("/cases/{case_id}/indicators", response_model=PaginatedIndicatorResponse)
@limiter.limit(RATE_LIMIT_READ)
def list_indicators(request: Request, case_id: int, page: int = 1, page_size: int = 50, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    page_size = min(max(page_size, 1), 200)
    total = db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.case_id == case_id).count()
    total_pages = max(1, math.ceil(total / page_size))
    items = db.query(ThreatIntelIndicator).filter(ThreatIntelIndicator.case_id == case_id).order_by(ThreatIntelIndicator.last_checked.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedIndicatorResponse(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)
