"""Centralized Timezone Normalization and Conversion Service for TACTIC.

All timestamps across logs, browser history, media EXIF, PDF/DOCX metadata,
PCAP network traffic, and forensic events are normalized and stored internally
in UTC while retaining original timestamps and source timezone offsets.
"""
import datetime
from datetime import timezone, timedelta
import os
import re
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

# Common Forensic & Timezone Aliases
TIMEZONE_ALIASES = {
    "IST": "Asia/Kolkata",
    "EST": "America/New_York",
    "EDT": "America/New_York",
    "CST": "America/Chicago",
    "CDT": "America/Chicago",
    "MST": "America/Denver",
    "MDT": "America/Denver",
    "PST": "America/Los_Angeles",
    "PDT": "America/Los_Angeles",
    "GMT": "UTC",
    "UTC": "UTC",
    "Z": "UTC",
    "CET": "Europe/Paris",
    "CEST": "Europe/Paris",
    "JST": "Asia/Tokyo",
    "AEST": "Australia/Sydney",
    "AEDT": "Australia/Sydney",
}

OFFSET_REGEX = re.compile(r"^([+-])(\d{2}):?(\d{2})$")


def resolve_timezone(tz_str: str | None) -> datetime.tzinfo:
    """Resolve timezone string, offset, or alias into a datetime.tzinfo object."""
    if not tz_str:
        tz_str = os.getenv("DEFAULT_TIMEZONE", "UTC")

    clean_tz = tz_str.strip().upper()
    if clean_tz in TIMEZONE_ALIASES:
        clean_tz = TIMEZONE_ALIASES[clean_tz]

    # Check for direct IANA timezone (e.g. Asia/Kolkata, America/New_York)
    try:
        return ZoneInfo(tz_str.strip())
    except (ZoneInfoNotFoundError, ValueError):
        pass

    try:
        return ZoneInfo(clean_tz)
    except (ZoneInfoNotFoundError, ValueError):
        pass

    # Check for ISO offset strings like +05:30, -0500, +00:00
    match = OFFSET_REGEX.match(clean_tz)
    if match:
        sign, hours, minutes = match.groups()
        delta = timedelta(hours=int(hours), minutes=int(minutes))
        if sign == "-":
            delta = -delta
        return timezone(delta)

    return timezone.utc


def get_timezone_name_and_offset(tz: datetime.tzinfo, dt: datetime.datetime | None = None) -> tuple[str, str]:
    """Get abbreviation/name and formatted ISO offset string (e.g., '+05:30') for a timezone."""
    if dt is None:
        dt = datetime.datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)

    local_dt = dt.astimezone(tz)
    offset = local_dt.utcoffset() or timedelta(0)
    total_minutes = int(offset.total_seconds() // 60)
    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)
    hours = total_minutes // 60
    minutes = total_minutes % 60
    offset_str = f"{sign}{hours:02d}:{minutes:02d}"
    
    tz_name = local_dt.tzname() or offset_str
    return tz_name, offset_str


def safe_parse_timestamp(val: Any, default_tz: str = "UTC") -> datetime.datetime | None:
    """Exception-safe parser returning timezone-aware UTC datetime or None."""
    utc_dt, _, _ = normalize_to_utc(val, default_tz=default_tz)
    return utc_dt


def normalize_to_utc(
    val: Any,
    default_tz: str = "UTC"
) -> tuple[datetime.datetime | None, str | None, str | None]:
    """Normalize arbitrary input timestamp to UTC, preserving original string and source timezone offset.

    Returns:
        (utc_datetime, original_timestamp_str, original_timezone_str)
    """
    if val is None or val == "":
        return None, None, None

    orig_str = str(val).strip()

    # 1. Handle already-constructed datetime objects
    if isinstance(val, datetime.datetime):
        if val.tzinfo is None:
            # Naive datetime: attach default timezone then convert to UTC
            tz = resolve_timezone(default_tz)
            aware_dt = val.replace(tzinfo=tz)
            _, offset_str = get_timezone_name_and_offset(tz, aware_dt)
            return aware_dt.astimezone(timezone.utc), val.isoformat(), offset_str
        else:
            _, offset_str = get_timezone_name_and_offset(val.tzinfo, val)
            return val.astimezone(timezone.utc), val.isoformat(), offset_str

    # 2. Handle numeric timestamps (Epoch floats, seconds, ms, Chrome, Firefox)
    if isinstance(val, (int, float)) or (isinstance(orig_str, str) and (orig_str.isdigit() or (orig_str.replace(".", "", 1).isdigit() and orig_str.count(".") <= 1))):
        try:
            num = float(orig_str)
            # Chrome epoch (microseconds since 1601-01-01)
            if num > 10_000_000_000_000_000:
                epoch_1601 = datetime.datetime(1601, 1, 1, tzinfo=timezone.utc)
                utc_dt = epoch_1601 + timedelta(microseconds=num)
                return utc_dt, orig_str, "+00:00"
            # Microseconds epoch
            if num > 1_000_000_000_000_000:
                utc_dt = datetime.datetime.fromtimestamp(num / 1_000_000, tz=timezone.utc)
                return utc_dt, orig_str, "+00:00"
            # Milliseconds epoch
            if num > 10_000_000_000:
                utc_dt = datetime.datetime.fromtimestamp(num / 1000, tz=timezone.utc)
                return utc_dt, orig_str, "+00:00"
            # Standard seconds epoch
            if num > 0:
                utc_dt = datetime.datetime.fromtimestamp(num, tz=timezone.utc)
                return utc_dt, orig_str, "+00:00"
        except (ValueError, OverflowError, OSError):
            pass

    # 3. Handle PDF Format: D:YYYYMMDDHHMMSS[+|-]HH'MM'
    if orig_str.startswith("D:"):
        try:
            pdf_str = orig_str[2:].replace("'", "")
            clean = pdf_str[:14]
            dt_naive = datetime.datetime.strptime(clean, "%Y%m%d%H%M%S")
            tz_part = pdf_str[14:]
            if tz_part and (tz_part.startswith("+") or tz_part.startswith("-")):
                sign = tz_part[0]
                tz_clean = tz_part[1:].zfill(4)
                h, m = int(tz_clean[:2]), int(tz_clean[2:4])
                delta = timedelta(hours=h, minutes=m)
                tz_info = timezone(-delta if sign == "-" else delta)
                dt_aware = dt_naive.replace(tzinfo=tz_info)
                return dt_aware.astimezone(timezone.utc), orig_str, f"{sign}{h:02d}:{m:02d}"
            else:
                dt_aware = dt_naive.replace(tzinfo=timezone.utc)
                return dt_aware, orig_str, "+00:00"
        except Exception:
            pass

    # 4. Handle EXIF Format: YYYY:MM:DD HH:MM:SS
    if re.match(r"^\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}$", orig_str):
        try:
            parsed = datetime.datetime.strptime(orig_str, "%Y:%m:%d %H:%M:%S")
            default_tz_info = resolve_timezone(default_tz)
            aware_dt = parsed.replace(tzinfo=default_tz_info)
            _, offset_str = get_timezone_name_and_offset(default_tz_info, aware_dt)
            return aware_dt.astimezone(timezone.utc), orig_str, offset_str
        except Exception:
            pass

    # 5. Handle ISO 8601 Strings & Variants
    cleaned_str = orig_str.replace("Z", "+00:00")
    try:
        parsed_dt = datetime.datetime.fromisoformat(cleaned_str)
        if parsed_dt.tzinfo is None:
            # Naive timestamp: attach default_tz safely
            default_tz_info = resolve_timezone(default_tz)
            aware_dt = parsed_dt.replace(tzinfo=default_tz_info)
            _, offset_str = get_timezone_name_and_offset(default_tz_info, aware_dt)
            return aware_dt.astimezone(timezone.utc), orig_str, offset_str
        else:
            _, offset_str = get_timezone_name_and_offset(parsed_dt.tzinfo, parsed_dt)
            return parsed_dt.astimezone(timezone.utc), orig_str, offset_str
    except (ValueError, TypeError):
        pass

    # 6. Fallback string parse attempts
    known_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d/%b/%Y:%H:%M:%S",
        "%b %d %H:%M:%S",
    ]
    for fmt in known_formats:
        try:
            parse_input = orig_str[:26]
            if fmt == "%b %d %H:%M:%S":
                # Inject a year to avoid Python 3.13+ deprecation warning
                parse_input = f"{datetime.datetime.now().year} " + parse_input
                parsed = datetime.datetime.strptime(parse_input, "%Y %b %d %H:%M:%S")
            else:
                parsed = datetime.datetime.strptime(parse_input, fmt)
            default_tz_info = resolve_timezone(default_tz)
            aware_dt = parsed.replace(tzinfo=default_tz_info)
            _, offset_str = get_timezone_name_and_offset(default_tz_info, aware_dt)
            return aware_dt.astimezone(timezone.utc), orig_str, offset_str
        except (ValueError, TypeError):
            continue

    # Malformed timestamp safeguard: return None safely without crashing
    return None, orig_str, None


def format_for_timezone(utc_dt: datetime.datetime | None, target_tz: str = "UTC") -> dict[str, Any]:
    """Format a UTC datetime for display in the investigator's selected target timezone."""
    if utc_dt is None:
        return {
            "utc_iso": None,
            "display_iso": None,
            "target_timezone": target_tz,
            "offset_str": None,
            "tz_name": None,
            "formatted": "N/A"
        }

    # Ensure utc_dt is aware
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    else:
        utc_dt = utc_dt.astimezone(timezone.utc)

    target_tz_info = resolve_timezone(target_tz)
    local_dt = utc_dt.astimezone(target_tz_info)
    tz_name, offset_str = get_timezone_name_and_offset(target_tz_info, local_dt)

    return {
        "utc_iso": utc_dt.isoformat(),
        "display_iso": local_dt.isoformat(),
        "target_timezone": target_tz,
        "offset_str": offset_str,
        "tz_name": tz_name,
        "formatted": f"{local_dt.strftime('%Y-%m-%d %H:%M:%S')} {tz_name} ({offset_str})"
    }
