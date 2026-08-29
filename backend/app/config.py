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
# In production, restrict to the actual deployed origin(s).
# Set CORS_ORIGINS env var (comma-separated) for production deployments.
CORS_ORIGINS: list[str] = [
    origin.strip()
    for origin in os.getenv(
        "CORS_ORIGINS",
        "http://127.0.0.1:8000,http://localhost:8000",
    ).split(",")
    if origin.strip()
]

# ── Rate limiter ────────────────────────────────────────────────
limiter = Limiter(key_func=get_remote_address)

# ── Rate-limit tiers ───────────────────────────────────────────
# Applied per-endpoint via ``@limiter.limit(TIER)`` on every router.
# Auth endpoints override these with their own stricter values.
RATE_LIMIT_READ: str | None = "120/minute"   # light GET / list endpoints
RATE_LIMIT_WRITE: str | None = "30/minute"    # create / update / delete
RATE_LIMIT_HEAVY: str | None = "10/minute"    # AI analysis, extraction, eval
RATE_LIMIT_AI_CHAT: str | None = "20/minute"  # LLM-backed chat queries
RATE_LIMIT_UPLOAD: str | None = "10/minute"    # evidence file upload
