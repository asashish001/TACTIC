"""Application-level configuration shared across modules.

Keeps ``main.py`` thin by extracting CORS origins, rate limiter, and
other cross-cutting settings into one importable location.
"""
import os

from dotenv import load_dotenv
from slowapi import Limiter
from slowapi.util import get_remote_address

load_dotenv()

# ── CORS ────────────────────────────────────────────────────────
CORS_ORIGINS: list[str] = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "",
    ).split(",")
    if origin.strip()
]

# ── Rate limiter ────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Rate-limit tiers ───────────────────────────────────────────
RATE_LIMIT_READ: str = "120/minute"   # light GET / list endpoints
RATE_LIMIT_WRITE: str = "30/minute"    # create / update / delete
RATE_LIMIT_HEAVY: str = "10/minute"    # AI analysis, extraction, eval
RATE_LIMIT_AI_CHAT: str = "20/minute"  # LLM-backed chat queries
RATE_LIMIT_UPLOAD: str = "10/minute"    # evidence file upload
