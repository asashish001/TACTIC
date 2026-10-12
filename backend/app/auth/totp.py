"""RFC 6238 Time-Based One-Time Password (TOTP) pure-Python implementation.

Zero external dependencies: uses Python standard library (hmac, hashlib, struct, base64, time, secrets).
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse


def generate_totp_secret() -> str:
    """Generate a standard 160-bit (20 bytes) Base32-encoded TOTP secret."""
    raw = secrets.token_bytes(20)
    # Base32 encode and remove padding
    return base64.b32encode(raw).decode("ascii").replace("=", "")


def get_totp_uri(secret: str, username: str, issuer: str = "TACTIC") -> str:
    """Generate the standard otpauth:// URI for authenticator apps (Google Authenticator, Authy, etc.)."""
    label = urllib.parse.quote(f"{issuer}:{username}")
    issuer_param = urllib.parse.quote(issuer)
    clean_secret = secret.strip().upper()
    return f"otpauth://totp/{label}?secret={clean_secret}&issuer={issuer_param}&algorithm=SHA1&digits=6&period=30"


def generate_totp_code(secret: str, for_time: int | None = None, interval_step: int = 30) -> str:
    """Generate the current 6-digit TOTP code for a given secret."""
    if for_time is None:
        for_time = int(time.time())

    clean_secret = secret.strip().upper()
    padding = (8 - len(clean_secret) % 8) % 8
    key = base64.b32decode(clean_secret + "=" * padding)

    interval = for_time // interval_step
    counter = struct.pack(">Q", interval)
    digest = hmac.new(key, counter, hashlib.sha1).digest()

    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return f"{(code_int % 1000000):06d}"


def verify_totp(secret: str, code: str, window: int = 1, interval_step: int = 30) -> bool:
    """Verify a user-provided 6-digit TOTP code against a secret with time drift allowance (window intervals)."""
    if not secret or not code:
        return False
    code_str = str(code).strip()
    if len(code_str) != 6 or not code_str.isdigit():
        return False

    clean_secret = secret.strip().upper()
    try:
        padding = (8 - len(clean_secret) % 8) % 8
        key = base64.b32decode(clean_secret + "=" * padding)
    except Exception:
        return False

    now = int(time.time())
    current_interval = now // interval_step

    for offset in range(-window, window + 1):
        interval = current_interval + offset
        counter = struct.pack(">Q", interval)
        digest = hmac.new(key, counter, hashlib.sha1).digest()
        offset_idx = digest[-1] & 0x0F
        code_int = struct.unpack(">I", digest[offset_idx:offset_idx + 4])[0] & 0x7FFFFFFF
        expected = f"{(code_int % 1000000):06d}"
        if hmac.compare_digest(expected, code_str):
            return True

    return False
