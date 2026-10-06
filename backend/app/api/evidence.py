import logging
import os
import tempfile
from pathlib import Path

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Request,
    UploadFile,
    status,
)
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.auth.security import RoleChecker, get_current_user, require_case_access
from app.config import RATE_LIMIT_READ, RATE_LIMIT_UPLOAD, limiter
from app.database.session import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.user import User
from app.schemas.evidence import EvidenceResponse
from app.services.duplicate_evidence import find_duplicate_evidence
from app.services.evidence_processor import calculate_hashes, process_evidence
from app.services.forensic_audit import (
    record_audit,
    record_custody,
    store_evidence_hashes,
)
from app.services.upload_validation import (
    UploadValidationError,
    sanitize_evidence_filename,
    secure_stored_filename,
    validate_evidence_content,
)

logger = logging.getLogger(__name__)


def _sanitize_like(value: str) -> str:
    """Escape SQL LIKE wildcards to prevent pattern injection in search queries."""
    bs = chr(92)  # backslash
    return value.replace(bs, bs + bs).replace(chr(37), bs + chr(37)).replace(chr(95), bs + chr(95))


router = APIRouter(prefix="/api/evidence", tags=["Evidence Ingestion"])
MAX_UPLOAD_BYTES = int(os.getenv("MAX_UPLOAD_BYTES", str(500 * 1024 * 1024)))

def upload_error(status_code: int, code: str, message: str, **details):
    """Return stable, machine-readable API errors without exposing server paths."""
    return HTTPException(status_code=status_code, detail={"code": code, "message": message, **details})

@router.post("/upload", response_model=EvidenceResponse, status_code=status.HTTP_201_CREATED)
@limiter.limit(RATE_LIMIT_UPLOAD)
async def upload_evidence(request: Request, 
    case_id: int = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(RoleChecker(["admin", "investigator"]))
):
    """Securely upload an evidence file, verify its magic bytes, hash it, and extract metadata."""
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)
    
    try:
        filename, suffix = sanitize_evidence_filename(file.filename or "")
    except UploadValidationError as error:
        raise upload_error(status.HTTP_400_BAD_REQUEST, error.code, error.message)

    base_dir = Path(__file__).resolve().parent.parent.parent
    upload_dir = (base_dir / "app" / "uploads" / f"case_{case_id}").resolve()
    upload_dir.mkdir(parents=True, exist_ok=True)
    temp_dir = (upload_dir / ".staging").resolve()
    temp_dir.mkdir(mode=0o700, exist_ok=True)
    if upload_dir not in temp_dir.parents:
        raise upload_error(status.HTTP_500_INTERNAL_SERVER_ERROR, "STORAGE_CONFIGURATION_ERROR", "Secure upload staging is unavailable.")

    temp_path = None
    final_path = None

    try:
        with tempfile.NamedTemporaryFile(mode="wb", dir=temp_dir, prefix="evidence-", suffix=".part", delete=False) as buffer:
            temp_path = Path(buffer.name)
            written = 0
            while chunk := await file.read(1024 * 1024):
                written += len(chunk)
                if written > MAX_UPLOAD_BYTES:
                    raise upload_error(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "FILE_TOO_LARGE", f"Evidence exceeds the {MAX_UPLOAD_BYTES // (1024 * 1024)} MB upload limit.")
                buffer.write(chunk)
    except HTTPException:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise
    except OSError:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        raise upload_error(status.HTTP_500_INTERNAL_SERVER_ERROR, "STORAGE_WRITE_FAILED", "Evidence could not be safely staged.")

    try:
        hashes = calculate_hashes(temp_path)
        detected_mime = validate_evidence_content(temp_path, suffix)
    except UploadValidationError as error:
        temp_path.unlink(missing_ok=True)
        raise upload_error(status.HTTP_422_UNPROCESSABLE_ENTITY, error.code, error.message)
    except OSError:
        temp_path.unlink(missing_ok=True)
        raise upload_error(status.HTTP_500_INTERNAL_SERVER_ERROR, "HASH_CALCULATION_FAILED", "Evidence hash calculation failed.")

    duplicate = find_duplicate_evidence(db, case_id, hashes["sha256"])
    if duplicate:
        record_audit(
            db,
            "DUPLICATE_EVIDENCE",
            f"Rejected duplicate evidence '{filename}'; it matches '{duplicate.filename}'.",
            actor_id=current_user.id,
            case_id=case_id,
            evidence_id=duplicate.id,
            details={
                "sha256": hashes["sha256"],
                "attempted_filename": filename,
                "original_evidence_id": duplicate.id,
                "original_filename": duplicate.filename,
            },
        )
        db.commit()
        temp_path.unlink(missing_ok=True)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "message": "Duplicate evidence rejected: identical SHA-256 already exists in this investigation.",
                "duplicate": True,
                "original_evidence": {"id": duplicate.id, "filename": duplicate.filename},
            },
        )

    try:
        metadata = process_evidence(temp_path, suffix)
        if metadata.get("kind") == "error":
            raise UploadValidationError("MALFORMED_FILE", metadata.get("message", "Evidence parser rejected this file."))
        
        metadata["mime_mismatch"] = False
        metadata["detected_mime"] = detected_mime

        final_path = (upload_dir / secure_stored_filename(suffix)).resolve()
        if upload_dir not in final_path.parents:
            raise UploadValidationError("STORAGE_CONFIGURATION_ERROR", "Secure evidence destination is unavailable.")
        relative_path = str(final_path.relative_to(base_dir / "app" / "uploads"))
        
        evidence = Evidence(
            case_id=case_id,
            filename=filename,
            stored_path=relative_path,
            file_size=temp_path.stat().st_size,
            extension=suffix,
            md5=hashes["md5"],
            sha1=hashes["sha1"],
            sha256=hashes["sha256"],
            detected_mime=detected_mime,
            extracted_metadata=metadata
        )
        db.add(evidence)
        db.flush()
        os.replace(temp_path, final_path)
        store_evidence_hashes(db, evidence, hashes)
        record_custody(
            db, "evidence_ingested", f"Evidence '{filename}' was preserved and hashed.",
            actor_id=current_user.id, case_id=case_id, evidence_id=evidence.id,
            hash_snapshot=hashes["sha256"],
            details={"original_filename": filename, "file_size": evidence.file_size, "algorithms": list(hashes)},
        )
        record_audit(
            db, "evidence_uploaded", f"Uploaded evidence '{filename}'.", actor_id=current_user.id,
            case_id=case_id, evidence_id=evidence.id, details={"sha256": hashes["sha256"]},
        )
        db.commit()
        db.refresh(evidence)
        return evidence
    except UploadValidationError as error:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        db.rollback()
        raise upload_error(status.HTTP_422_UNPROCESSABLE_ENTITY, error.code, error.message)
    except IntegrityError:
        db.rollback()
        if temp_path and temp_path.exists():
            temp_path.unlink()
        duplicate = find_duplicate_evidence(db, case_id, hashes["sha256"])
        if duplicate:
            record_audit(db, "DUPLICATE_EVIDENCE", f"Rejected concurrent duplicate evidence '{filename}'; it matches '{duplicate.filename}'.", actor_id=current_user.id, case_id=case_id, evidence_id=duplicate.id, details={"sha256": hashes["sha256"], "attempted_filename": filename, "original_evidence_id": duplicate.id, "original_filename": duplicate.filename})
            db.commit()
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail={"message": "Duplicate evidence rejected: identical SHA-256 already exists in this investigation.", "duplicate": True, "original_evidence": {"id": duplicate.id, "filename": duplicate.filename}})
        raise upload_error(status.HTTP_409_CONFLICT, "DUPLICATE_EVIDENCE", "An equivalent evidence upload is already being processed.")
    except Exception:
        if temp_path and temp_path.exists():
            temp_path.unlink()
        db.rollback()
        raise upload_error(status.HTTP_500_INTERNAL_SERVER_ERROR, "EVIDENCE_PROCESSING_FAILED", "Evidence could not be processed safely.")

class EvidenceListResponse(BaseModel):
    """Paginated evidence list with metadata."""
    items: list[EvidenceResponse]
    total: int
    page: int
    page_size: int
    total_pages: int


@router.get("", response_model=EvidenceListResponse)
@limiter.limit(RATE_LIMIT_READ)
def list_evidence(request: Request, 
    case_id: int,
    q: str | None = None,
    page: int = 1,
    page_size: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Retrieve evidence files for a case with pagination.

    The database performs all filtering and pagination — no Python-side
    loading of the full result set.
    """
    case = db.query(Case).filter(Case.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    page_size = max(1, min(page_size, 200))
    page = max(1, page)

    query = db.query(Evidence).filter(Evidence.case_id == case_id)
    if q:
        query = query.filter(
            or_(
                Evidence.filename.ilike(f"%{_sanitize_like(q)}%"),
                Evidence.detected_mime.ilike(f"%{_sanitize_like(q)}%")
            )
        )

    total = query.count()
    total_pages = max(1, -(-total // page_size))  # ceil division

    items = (
        query
        .order_by(Evidence.ingested_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )

    return EvidenceListResponse(
        items=items,  # type: ignore[arg-type]
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
    )


@router.get("/download/{evidence_id}")
@limiter.limit(RATE_LIMIT_READ)
def download_evidence(request: Request,
    evidence_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Download an evidence file with authentication and case access verification."""
    from fastapi.responses import FileResponse

    evidence = db.query(Evidence).filter(Evidence.id == evidence_id).first()
    if not evidence:
        raise HTTPException(status_code=404, detail="Evidence not found.")

    case = db.query(Case).filter(Case.id == evidence.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    base_dir = Path(__file__).resolve().parent.parent.parent
    file_path = (base_dir / "app" / "uploads" / evidence.stored_path).resolve()

    uploads_root = (base_dir / "app" / "uploads").resolve()
    if uploads_root not in file_path.parents or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Evidence file could not be located on disk.")

    record_audit(
        db, "evidence_downloaded",
        f"Downloaded evidence '{evidence.filename}'.",
        actor_id=current_user.id,
        case_id=evidence.case_id,
        evidence_id=evidence.id,
    )
    db.commit()

    return FileResponse(
        path=file_path,
        media_type="application/octet-stream",
        filename=evidence.filename,
    )
