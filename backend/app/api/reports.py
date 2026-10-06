import math
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.auth.security import (
    RoleChecker,
    decode_token,
    get_current_user,
    require_case_access,
)
from app.config import RATE_LIMIT_READ, RATE_LIMIT_WRITE, limiter
from app.database.session import get_db
from app.models.case import Case
from app.models.report import Report
from app.models.user import User
from app.schemas.report import ReportCreate, ReportResponse
from app.services.forensic_audit import record_audit
from app.services.report_service import generate_report as _generate_report

router = APIRouter(prefix="/api/report", tags=["Forensic Reports Engine"])

def get_user_for_download(
    request: Request,
    token: str | None = None,
    db: Session = Depends(get_db),
) -> User:
    """Authenticate via either Bearer header or URL token parameter."""
    auth_header = request.headers.get("Authorization")
    token_str = None
    if auth_header and auth_header.startswith("Bearer "):
        token_str = auth_header[7:].strip()
    elif token:
        token_str = token

    if not token_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = decode_token(token_str, expected_type="access")
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    user = db.query(User).filter(User.id == payload.get("user_id")).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user

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
        raise HTTPException(status_code=500, detail=f"Failed compiling report document: {e!s}")

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
    return PaginatedReportResponse(items=items, total=total, page=page, page_size=page_size, total_pages=total_pages)  # type: ignore[arg-type]

@router.get("/download/{report_id}")
@limiter.limit(RATE_LIMIT_READ)
def download_report(request: Request, 
    report_id: int,
    inline: bool = False,
    token: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_user_for_download)
):
    """Retrieve and stream the physical report file for download or inline preview."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found in database registry.")
    require_case_access(report.case, current_user)
        
    base_dir = Path(__file__).resolve().parent.parent.parent
    file_path = (base_dir / "app" / "reports" / report.stored_path).resolve()
    
    if (base_dir / "app" / "reports") not in file_path.parents or not file_path.is_file():
        raise HTTPException(status_code=404, detail="The report file could not be located on disk.")
    record_audit(db, "report_downloaded", f"Downloaded report '{report.filename}'.", actor_id=current_user.id,
                 case_id=report.case_id, details={"report_id": report.id})
    db.commit()

    fmt = (report.format or "").lower()
    if fmt == "pdf":
        media_type = "application/pdf"
    elif fmt == "docx":
        media_type = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
    else:
        media_type = "application/octet-stream"

    content_disposition = "inline" if inline else "attachment"
        
    return FileResponse(
        path=file_path,
        media_type=media_type,
        filename=report.filename,
        content_disposition_type=content_disposition,
    )
