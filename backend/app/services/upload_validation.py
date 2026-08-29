"""Trust-boundary validation for evidence uploads."""
import json
import re
import uuid
from pathlib import Path, PureWindowsPath
from xml.etree import ElementTree

from PIL import Image, UnidentifiedImageError

from app.services.evidence_processor import ALLOWED_EXTENSIONS, detect_file_type

TEXT_EXTENSIONS = {"txt", "csv", "log", "json", "xml", "ps1", "bat", "cmd", "py", "js", "html", "htm", "md", "markdown"}
IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "webp"}
MAGIC_REQUIRED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "pdf", "zip", "rar", "7z"}
BROWSER_ARTIFACT_NAMES = {"history", "cookies", "bookmarks", "favicons", "top sites"}


class UploadValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def sanitize_evidence_filename(client_filename: str) -> tuple[str, str]:
    """Reject path names and return a display-safe basename and trusted suffix."""
    raw = (client_filename or "").strip()
    windows_path = PureWindowsPath(raw)
    if (
        not raw
        or "\x00" in raw
        or "/" in raw
        or "\\" in raw
        or Path(raw).is_absolute()
        or windows_path.is_absolute()
        or any(part in {".", ".."} for part in windows_path.parts)
    ):
        raise UploadValidationError("INVALID_FILENAME", "Filename must be a simple relative file name.")

    safe_name = re.sub(r"[^A-Za-z0-9._ -]", "_", raw).strip(" .")
    if not safe_name or safe_name in {".", ".."}:
        raise UploadValidationError("INVALID_FILENAME", "Filename contains no safe display characters.")
    if len(safe_name) > 255:
        raise UploadValidationError("INVALID_FILENAME", "Filename exceeds 255 characters.")

    suffix = Path(safe_name).suffix.lower().lstrip(".")
    if not suffix and safe_name.lower() in BROWSER_ARTIFACT_NAMES:
        suffix = "json" if safe_name.lower() == "bookmarks" else "db"
    if not suffix or suffix not in ALLOWED_EXTENSIONS:
        raise UploadValidationError("UNSUPPORTED_FORMAT", f"File extension .{suffix or 'unknown'} is not supported.")
    return safe_name, suffix


def secure_stored_filename(extension: str) -> str:
    """Generate a server-controlled filename that cannot contain client path data."""
    return f"{uuid.uuid4().hex}.{extension.lower()}"


def validate_evidence_content(file_path: Path, extension: str) -> str:
    """Validate bytes on disk; client MIME headers are intentionally ignored."""
    if not file_path.is_file() or file_path.stat().st_size == 0:
        raise UploadValidationError("EMPTY_FILE", "Evidence file is empty.")

    detected_mime, mismatch = detect_file_type(file_path, extension)
    if mismatch:
        raise UploadValidationError(
            "CONTENT_TYPE_MISMATCH",
            f"File content is {detected_mime}, which is inconsistent with .{extension}.",
        )
    with file_path.open("rb") as f:
        header = f.read(32)
    expected_signatures = {
        "png": (b"\x89PNG\r\n\x1a\n",), "jpg": (b"\xff\xd8\xff",), "jpeg": (b"\xff\xd8\xff",),
        "gif": (b"GIF87a", b"GIF89a"), "pdf": (b"%PDF-",), "zip": (b"PK\x03\x04",),
        "rar": (b"Rar!\x1a\x07",), "7z": (b"7z\xbc\xaf\x27\x1c",),
        "exe": (b"MZ",), "dll": (b"MZ",), "sys": (b"MZ",), "scr": (b"MZ",),
    }
    if extension in MAGIC_REQUIRED_EXTENSIONS and not header.startswith(expected_signatures[extension]):
        raise UploadValidationError("MALFORMED_FILE", f".{extension} does not contain a recognized file signature.")

    try:
        if extension in IMAGE_EXTENSIONS:
            with Image.open(file_path) as image:
                image.verify()
        elif extension == "json":
            # Stream-parse JSON to avoid loading entire file
            with file_path.open("r", encoding="utf-8") as f:
                json.load(f)
        elif extension == "xml":
            ElementTree.parse(file_path)
        elif extension in TEXT_EXTENSIONS:
            # Read only first 8KB to check for NUL bytes
            with file_path.open("rb") as f:
                sample = f.read(8192)
            if b"\x00" in sample:
                raise ValueError("NUL bytes are not valid text evidence")
            sample.decode("utf-8")
    except (UnidentifiedImageError, OSError, UnicodeDecodeError, json.JSONDecodeError, ElementTree.ParseError, ValueError) as exc:
        raise UploadValidationError("MALFORMED_FILE", f".{extension} content is malformed: {exc}") from exc

    return detected_mime
