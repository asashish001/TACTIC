import math
from pydantic import BaseModel
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.case import Case
from app.models.report import Report
from app.models.user import User
from app.schemas.report import ReportCreate, ReportResponse
from app.auth.security import get_current_user, require_case_access, RoleChecker
from app.config import limiter, RATE_LIMIT_READ, RATE_LIMIT_WRITE
from app.services.forensic_audit import record_audit, record_custody
from app.services.report_service import generate_report as _generate_report

router = APIRouter(prefix="/api/report", tags=["Forensic Reports Engine"])

class GenerateReportRequest(ReportCreate):
    pass

@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_WRITE)
def generate_report(request: Request, 
    payload: GenerateReportRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Generate a formal PDF or DOCX report for a specific case with findings and timelines."""
    case = db.query(Case).filter(Case.id == payload.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    try:
        result = _generate_report(
            case_id=payload.case_id,
            fmt=payload.format,
            db=db,
            actor_id=current_user.id,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed compiling report document: {str(e)}")

    return result.report

class PaginatedReportResponse(BaseModel):
    items: list[ReportResponse]
    total: int
    page: int
    page_size: int
    total_pages: int

@router.get("", response_model=PaginatedReportResponse)
@limiter.limit(RATE_LIMIT_READ)
def list_reports(request: Request, 
    case_id: int,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """List compiled reports for a case with pagination."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    page_size = min(max(page_size, 1), 200)
    total = db.query(Report).filter(Report.case_id == case_id).count()
    total_pages = max(1, math.ceil(total / page_size))
    items = db.query(Report).filter(Report.case_id == case_id).order_by(Report.generated_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    return PaginatedReportResponse(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)

@router.get("/download/{report_id}")
@limiter.limit(RATE_LIMIT_READ)
def download_report(request: Request, 
    report_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve and stream the physical report file for download."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found in database registry.")
    require_case_access(report.case, current_user)
        
    base_dir = Path(__file__).resolve().parent.parent.parent
    file_path = (base_dir / "app" / "reports" / report.stored_path).resolve()
    
    # Traversal escape verification
    if (base_dir / "app" / "reports") not in file_path.parents or not file_path.is_file():
        raise HTTPException(status_code=404, detail="The report file could not be located on disk.")
    record_audit(db, "report_downloaded", f"Downloaded report '{report.filename}'.", actor_id=current_user.id,
                 case_id=report.case_id, details={"report_id": report.id})
    db.commit()
        
    return FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=report.filename
    )
