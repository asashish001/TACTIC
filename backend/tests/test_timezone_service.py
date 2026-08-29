import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import datetime
from app.services.timezone_service import (
    format_for_timezone,
    normalize_to_utc,
    resolve_timezone,
    safe_parse_timestamp,
)


def test_utc_timestamp_parsing():
    """Verify UTC ISO timestamp parsing."""
    utc_dt, orig_str, orig_tz = normalize_to_utc("2026-08-18T08:30:00Z")
    assert utc_dt is not None
    assert utc_dt.year == 2026 and utc_dt.month == 8 and utc_dt.day == 18
    assert utc_dt.hour == 8 and utc_dt.minute == 30
    assert utc_dt.tzinfo == datetime.timezone.utc
    assert orig_str == "2026-08-18T08:30:00Z"
    assert orig_tz in ("+00:00", "UTC")


def test_ist_timestamp_parsing():
    """Verify IST (+05:30 / Asia/Kolkata) timestamp normalization to UTC."""
    # 14:00:00 IST (+05:30) == 08:30:00 UTC
    utc_dt, orig_str, orig_tz = normalize_to_utc("2026-08-18T14:00:00+05:30")
    assert utc_dt is not None
    assert utc_dt.hour == 8 and utc_dt.minute == 30
    assert orig_tz == "+05:30"

    # Test IANA Asia/Kolkata aware datetime
    ist_tz = resolve_timezone("Asia/Kolkata")
    dt_ist = datetime.datetime(2026, 8, 18, 14, 0, 0, tzinfo=ist_tz)
    utc_dt2, _, _ = normalize_to_utc(dt_ist)
    assert utc_dt2.hour == 8 and utc_dt2.minute == 30


def test_utc_offset_parsing():
    """Verify custom UTC offsets (-05:00, +02:00, +09:00)."""
    # EST (-05:00): 10:00:00 EST == 15:00:00 UTC
    est_dt, _, est_tz = normalize_to_utc("2026-08-18T10:00:00-05:00")
    assert est_dt.hour == 15 and est_dt.minute == 0
    assert est_tz == "-05:00"

    # +02:00 offset: 12:00:00 +02:00 == 10:00:00 UTC
    plus2_dt, _, p2_tz = normalize_to_utc("2026-08-18T12:00:00+02:00")
    assert plus2_dt.hour == 10 and plus2_dt.minute == 0
    assert p2_tz == "+02:00"

    # JST (+09:00): 18:00:00 +09:00 == 09:00:00 UTC
    jst_dt, _, jst_tz = normalize_to_utc("2026-08-18T18:00:00+09:00")
    assert jst_dt.hour == 9 and jst_dt.minute == 0
    assert jst_tz == "+09:00"


def test_missing_naive_timezone_handling():
    """Verify safe handling of naive timestamps without offset."""
    # Naive timestamp should safely attach default timezone (e.g. UTC or Asia/Kolkata) without crashing
    naive_str = "2026-08-18 14:00:00"
    utc_dt, orig_str, orig_tz = normalize_to_utc(naive_str, default_tz="UTC")
    assert utc_dt is not None
    assert utc_dt.hour == 14 and utc_dt.minute == 0

    # Naive with default_tz="Asia/Kolkata" (IST) -> converted to 08:30:00 UTC
    utc_dt_ist, _, _ = normalize_to_utc(naive_str, default_tz="Asia/Kolkata")
    assert utc_dt_ist.hour == 8 and utc_dt_ist.minute == 30


def test_malformed_timestamp_safety():
    """Verify malformed timestamps do not crash and handle safely."""
    bad_inputs = ["invalid-date-xyz", "9999999999999999999", None, "", "2026-99-99T99:99:99"]
    for val in bad_inputs:
        utc_dt, orig_str, orig_tz = normalize_to_utc(val)
        assert utc_dt is None or isinstance(utc_dt, datetime.datetime)

    assert safe_parse_timestamp("malformed_text_input") is None


def test_format_for_investigator_timezone():
    """Verify formatting UTC datetimes into target investigator timezones."""
    utc_dt = datetime.datetime(2026, 8, 18, 8, 30, 0, tzinfo=datetime.timezone.utc)
    
    # Convert to IST (Asia/Kolkata)
    ist_fmt = format_for_timezone(utc_dt, target_tz="Asia/Kolkata")
    assert "14:00:00" in ist_fmt["formatted"]
    assert ist_fmt["offset_str"] == "+05:30"
    assert ist_fmt["target_timezone"] == "Asia/Kolkata"

    # Convert to EST (America/New_York) -> EDT is -04:00 in August
    est_fmt = format_for_timezone(utc_dt, target_tz="America/New_York")
    assert est_fmt["target_timezone"] == "America/New_York"
    assert "04:30:00" in est_fmt["formatted"]


if __name__ == "__main__":
    print("Running Centralized Timezone Service Unit Tests...")
    test_utc_timestamp_parsing()
    print("  [PASS] test_utc_timestamp_parsing")
    test_ist_timestamp_parsing()
    print("  [PASS] test_ist_timestamp_parsing")
    test_utc_offset_parsing()
    print("  [PASS] test_utc_offset_parsing")
    test_missing_naive_timezone_handling()
    print("  [PASS] test_missing_naive_timezone_handling")
    test_malformed_timestamp_safety()
    print("  [PASS] test_malformed_timestamp_safety")
    test_format_for_investigator_timezone()
    print("  [PASS] test_format_for_investigator_timezone")
    print("ALL TIMEZONE SERVICE UNIT TESTS PASSED!")
