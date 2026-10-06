"""Report generation service.

Contains the core business logic for collating case data, generating
PDF/DOCX reports, and persisting the report record.

Previously this logic lived inside ``app.api.reports.generate_report``
which forced ``job_runner`` to import from the API layer and pass
``current_user=None`` (which crashed at ``require_case_access``).
"""
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy.orm import Session

from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.report import Report
from app.services.forensic_audit import record_audit, record_custody
from app.services.settings_service import get_system_settings
from app.services.timeline_builder import extract_timeline_events
from app.utils.report_generator import build_docx_report, build_pdf_report

logger = logging.getLogger(__name__)

_REPORTS_BASE = Path(__file__).resolve().parent.parent / "reports"


@dataclass
class ReportResult:
    """Result of a successful report generation."""
    report: Report
    filepath: Path


def generate_report(
    case_id: int,
    fmt: str = "pdf",
    *,
    db: Session,
    actor_id: int | None = None,
) -> ReportResult:
    """Collate case data, render a report document, and persist a Report record.

    Parameters
    ----------
    case_id : int
        The case to generate a report for.
    fmt : str
        Output format — ``"pdf"`` or ``"docx"``.
    db : Session
        Active database session.
    actor_id : int | None
        User who requested the report (for audit trail).  May be ``None``
        when called from the background job runner.

    Returns
    -------
    ReportResult
        The persisted :class:`Report` model and the absolute file path.

    Raises
    ------
    ValueError
        If the case is not found or the format is unsupported.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise ValueError(f"Case {case_id} not found.")

    # ── 1. Collate case data ────────────────────────────────────
    evidence = db.query(Evidence).filter(Evidence.case_id == case.id).all()
    findings = (
        db.query(Finding)
        .filter(Finding.case_id == case.id)
        .order_by(Finding.risk_score.desc())
        .all()
    )
    timeline = extract_timeline_events(case.id, db)
    settings_dict = get_system_settings(db)

    case_payload = {
        "case": {
            "case_number": case.case_number,
            "name": case.name,
            "description": case.description,
            "incident_date": str(case.incident_date),
        },
        "settings": settings_dict,
        "evidence": [
            {
                "filename": item.filename,
                "detected_mime": item.detected_mime,
                "sha256": item.sha256,
                "integrity_status": item.integrity_status,
            }
            for item in evidence
        ],
        "findings": [
            {
                "title": item.title,
                "severity": item.severity,
                "risk_score": item.risk_score,
                "reason": item.reason,
                "recommendation": item.recommendation,
                "details": item.details or {},
            }
            for item in findings
        ],
        "timeline": timeline,
    }

    # ── 2. Resolve save paths ───────────────────────────────────
    report_dir = (_REPORTS_BASE / f"case_{case.id}").resolve()
    report_dir.mkdir(parents=True, exist_ok=True)

    normalised_fmt = fmt.lower()
    filename = f"{case.case_number}_{uuid.uuid4().hex[:8]}.{normalised_fmt}"
    destination = report_dir / filename

    if report_dir not in destination.parents:
        raise ValueError("Invalid path escape detected.")

    # ── 3. Generate document ────────────────────────────────────
    if normalised_fmt == "pdf":
        build_pdf_report(case_payload, destination)
    elif normalised_fmt == "docx":
        build_docx_report(case_payload, destination)
    else:
        raise ValueError(f"Unsupported report format: {normalised_fmt}")

    # ── 4. Persist report record ────────────────────────────────
    relative_path = str(destination.relative_to(_REPORTS_BASE))
    report = Report(
        case_id=case.id,
        filename=filename,
        format=normalised_fmt,
        stored_path=relative_path,
    )
    db.add(report)
    db.flush()

    record_audit(
        db,
        "report_generated",
        f"Generated {normalised_fmt.upper()} report '{filename}'.",
        actor_id=actor_id,
        case_id=case.id,
        details={"report_id": report.id},
    )
    record_custody(
        db,
        "report_generated",
        f"Generated forensic report '{filename}'.",
        actor_id=actor_id,
        case_id=case.id,
        details={"report_id": report.id},
    )

    db.commit()
    db.refresh(report)

    return ReportResult(report=report, filepath=destination)
