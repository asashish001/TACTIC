"""Application entry-point.

This file is intentionally thin — it wires together modules that own
their respective responsibilities:

  - ``app/startup``   – database schema, migrations, admin seeding
  - ``app/config``    – CORS origins, rate limiter
  - ``app/api/system`` – health check & model status endpoints
  - ``app/api/assets`` – logo, favicon, frontend mount
"""
import logging
import sys

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest
from starlette.responses import Response

load_dotenv()

# ── Logging configuration ──────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stderr,
)

# ── Side-effect imports: run DB migrations & seed admin ─────────
import app.startup  # noqa: F401  – creates tables, migrates schema, seeds admin

# ── Config ──────────────────────────────────────────────────────
from app.config import CORS_ORIGINS, limiter

# ── Create app ──────────────────────────────────────────────────
app = FastAPI(
    title="AI Digital Forensics Assistant API",
    description=(
        "FastAPI service mapping database records, timeline builders, "
        "graph analysis, and PyTorch AI threat detection."
    ),
    version="2.0.0",
)

# ── Middleware ───────────────────────────────────────────────────
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add standard security headers to every response."""
    async def dispatch(self, request: StarletteRequest, call_next):
        response: Response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        # CSP: allow inline scripts/styles needed by the SPA, and allow same-origin iframe previews
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "frame-src 'self' blob:; "
            "frame-ancestors 'self'"
        )
        return response


app.add_middleware(SecurityHeadersMiddleware)

# ── Routers ─────────────────────────────────────────────────────
from app.api.auth import router as auth_router
from app.api.users import router as users_router
from app.api.cases import router as cases_router
from app.api.evidence import router as evidence_router
from app.api.analysis import router as analysis_router
from app.api.timeline import router as timeline_router
from app.api.correlation import router as correlation_router
from app.api.chat import router as chat_router
from app.api.reports import router as reports_router
from app.api.admin import router as admin_router
from app.api.intelligence import router as intelligence_router
from app.api.forensic_records import router as forensic_records_router
from app.api.browser import router as browser_router
from app.api.network import router as network_router
from app.api.artifacts import router as artifacts_router
from app.api.settings import router as settings_router
from app.api.jobs import router as jobs_router
from app.api.evaluation import router as evaluation_router
from app.api.model_management import router as model_management_router
from app.api.system import router as system_router
from app.api.assets import router as assets_router

for r in (
    auth_router,
    users_router,
    cases_router,
    evidence_router,
    analysis_router,
    timeline_router,
    correlation_router,
    chat_router,
    reports_router,
    admin_router,
    intelligence_router,
    forensic_records_router,
    browser_router,
    network_router,
    artifacts_router,
    settings_router,
    jobs_router,
    evaluation_router,
    model_management_router,
    system_router,
    assets_router,
):
    app.include_router(r)

# ── Frontend SPA (mount last so it doesn't shadow API routes) ───
from app.api.assets import mount_frontend

mount_frontend(app)
