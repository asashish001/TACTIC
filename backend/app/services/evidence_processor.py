import hashlib
import logging
import mimetypes
import uuid
import shutil
import json
from pathlib import Path
from datetime import datetime, timezone
import exifread
from PIL import Image, ExifTags
from PyPDF2 import PdfReader
from docx import Document
from Evtx.Evtx import Evtx
from xml.etree import ElementTree

logger = logging.getLogger(__name__)

# MIME check mapping
SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png", {"png"}),
    (b"\xff\xd8\xff", "image/jpeg", {"jpg", "jpeg"}),
    (b"GIF87a", "image/gif", {"gif"}),
    (b"GIF89a", "image/gif", {"gif"}),
    (b"%PDF-", "application/pdf", {"pdf"}),
    (b"PK\x03\x04", "application/zip", {"zip", "docx", "xlsx", "pptx", "jar", "apk"}),
    (b"MZ", "application/vnd.microsoft.portable-executable", {"exe", "dll", "sys", "scr"}),
    (b"Rar!\x1a\x07", "application/vnd.rar", {"rar"}),
    (b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed", {"7z"}),
)

ALLOWED_EXTENSIONS = {
    "zip", "7z", "rar", "tar", "gz", "jpg", "jpeg", "png", "gif", "bmp", "webp",
    "pdf", "docx", "doc", "txt", "csv", "json", "xml", "log", "evtx", "db", "sqlite",
    "pcap", "pcapng",
    "mp4", "avi", "mov", "mkv", "wav", "mp3", "iso", "img", "dd", "raw", "e01",
    "exe", "dll", "ps1", "bat", "cmd", "py", "js", "html", "htm", "docm", "xlsm", "pptm",
    "md", "markdown",
}

def calculate_hashes(file_path: Path, chunk_size: int = 1024 * 1024) -> dict[str, str]:
    """Calculate MD5, SHA-1, and SHA-256 without loading an artifact into memory."""
    md5 = hashlib.md5(usedforsecurity=False)
    sha1 = hashlib.sha1(usedforsecurity=False)
    sha256 = hashlib.sha256()
    with file_path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(chunk_size), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
    return {"md5": md5.hexdigest(), "sha1": sha1.hexdigest(), "sha256": sha256.hexdigest()}

def detect_file_type(file_path: Path, extension: str) -> tuple[str, bool]:
    """Validate file headers (magic bytes) to identify sign/extension mismatches."""
    with file_path.open("rb") as stream:
        header = stream.read(32)
    for signature, detected_mime, expected_extensions in SIGNATURES:
        if header.startswith(signature):
            return detected_mime, extension.lower() not in expected_extensions
    guessed_mime, _ = mimetypes.guess_type(file_path.name)
    return guessed_mime or "application/octet-stream", False

def _as_text(value) -> str | None:
    if value is None:
        return None
    return str(value)

def _gps_decimal(values, reference) -> float | None:
    if not values or len(values) != 3:
        return None
    try:
        parts = [float(item.num) / float(item.den) if hasattr(item, "num") else float(item) for item in values]
        coordinate = parts[0] + parts[1] / 60 + parts[2] / 3600
        return -coordinate if str(reference).upper() in {"S", "W"} else coordinate
    except (TypeError, ValueError, ZeroDivisionError):
        return None

def extract_image_metadata(file_path: Path) -> dict:
    """Extract resolution, camera make/model, timestamps, and decimal GPS coordinates."""
    with Image.open(file_path) as image:
        exif = image.getexif()
        tags = {ExifTags.TAGS.get(key, str(key)): _as_text(value) for key, value in exif.items()}
        result = {
            "kind": "image", "format": image.format, "width": image.width, "height": image.height,
            "camera_make": tags.get("Make"), "camera_model": tags.get("Model"),
            "timestamp": tags.get("DateTimeOriginal") or tags.get("DateTime"),
            "software": tags.get("Software"), "raw_exif": tags,
        }
    # Exifread GPS processing
    with file_path.open("rb") as stream:
        gps = exifread.process_file(stream, details=False, stop_tag="GPS GPSLongitude")
    latitude = _gps_decimal(gps.get("GPS GPSLatitude").values if gps.get("GPS GPSLatitude") else None, gps.get("GPS GPSLatitudeRef"))
    longitude = _gps_decimal(gps.get("GPS GPSLongitude").values if gps.get("GPS GPSLongitude") else None, gps.get("GPS GPSLongitudeRef"))
    if latitude is not None and longitude is not None:
        result["gps"] = {"latitude": latitude, "longitude": longitude}
    return result

def extract_pdf_metadata(file_path: Path) -> dict:
    """Extract metadata using PyPDF2."""
    reader = PdfReader(str(file_path), strict=False)
    properties = reader.metadata or {}
    return {
        "kind": "pdf", "pages": len(reader.pages), "encrypted": reader.is_encrypted,
        "author": _as_text(properties.get("/Author")), "title": _as_text(properties.get("/Title")),
        "creator": _as_text(properties.get("/Creator")), "producer": _as_text(properties.get("/Producer")),
        "creation_date": _as_text(properties.get("/CreationDate")), "modification_date": _as_text(properties.get("/ModDate")),
    }

def extract_docx_metadata(file_path: Path) -> dict:
    """Extract metadata using python-docx."""
    properties = Document(str(file_path)).core_properties
    return {
        "kind": "docx", "author": _as_text(properties.author), "title": _as_text(properties.title),
        "subject": _as_text(properties.subject), "revision": properties.revision,
        "created": _as_text(properties.created), "modified": _as_text(properties.modified),
        "last_modified_by": _as_text(properties.last_modified_by), "category": _as_text(properties.category),
    }

def stream_evtx_records(file_path: Path, max_events: int = 10_000):
    """Generator streaming normalized EVTX events with malformed-record XML recovery."""
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    count = 0
    try:
        with Evtx(str(file_path)) as log:
            for index, record in enumerate(log.records()):
                if count >= max_events:
                    break
                try:
                    xml_data = record.xml()
                    root = ElementTree.fromstring(xml_data)
                    event_id_str = root.findtext("e:System/e:EventID", default="0", namespaces=namespace)
                    event_id = int(event_id_str) if event_id_str.isdigit() else 0
                    provider = root.find("e:System/e:Provider", namespace)
                    time_created = root.find("e:System/e:TimeCreated", namespace)
                    
                    data = {}
                    for i, item in enumerate(root.findall(".//e:EventData/e:Data", namespace)):
                        name = item.get("Name") or f"field_{i}"
                        data[name] = item.text

                    time_str = time_created.get("SystemTime") if time_created is not None else None
                    count += 1
                    yield {
                        "event_id": event_id,
                        "provider": provider.get("Name") if provider is not None else None,
                        "timestamp": time_str,
                        "data": data
                    }
                except Exception as rec_err:
                    logger.warning("Skipped malformed EVTX record at index #%d: %s", index, rec_err)
                    continue
    except Exception as e:
        logger.error("EVTX streaming error: %s", e)


def extract_evtx_records(file_path: Path, max_events: int = 100) -> list[dict]:
    """Parse and normalize security events from EVTX binary logs."""
    return list(stream_evtx_records(file_path, max_events=max_events))

def process_evidence(file_path: Path, extension: str) -> dict:
    """Trigger appropriate metadata parser based on the evidence file suffix."""
    meta = {"kind": "unsupported", "message": f"No custom parser mapped for .{extension}."}
    try:
        ext = extension.lower()
        if ext in {"jpg", "jpeg", "png", "gif", "bmp", "webp"}:
            meta = extract_image_metadata(file_path)
        elif ext == "pdf":
            meta = extract_pdf_metadata(file_path)
        elif ext == "docx":
            meta = extract_docx_metadata(file_path)
        elif ext == "evtx":
            meta = {"kind": "evtx", "records": extract_evtx_records(file_path)}
        elif ext in {"txt", "csv", "log", "json", "xml", "md", "markdown"}:
            # Stream first 5KB without loading entire file into memory
            sample_size = 5000
            with file_path.open("r", encoding="utf-8", errors="replace") as f:
                sample = f.read(sample_size)
            meta = {"kind": "text", "sample": sample}
    except Exception as e:
        meta = {"kind": "error", "message": f"Parsing failed: {str(e)}"}
    return meta
