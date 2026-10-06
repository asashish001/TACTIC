"""Static asset serving: logo, favicon."""
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse

router = APIRouter(tags=["Assets"])

_ROOT_DIR = Path(__file__).resolve().parent.parent.parent.parent  # project root


@router.get("/assets/logo.png")
def get_logo():
    """Serve the project logo.

    Checks for a custom logo (logo.{png,jpg,svg,...}) in the project root
    first, then falls back to the bundled default.
    """
    for ext in ("png", "jpg", "jpeg", "svg", "gif"):
        custom = _ROOT_DIR / f"logo.{ext}"
        if custom.exists():
            return FileResponse(custom)

    static_default = _ROOT_DIR / "static" / "logo.png"
    if static_default.exists():
        return FileResponse(static_default)

    return {"error": "Logo not found"}


@router.get("/favicon.ico")
def get_favicon():
    """Serve the favicon, supporting customization via root-level files."""
    for ext in ("ico", "png", "jpg", "jpeg", "svg"):
        custom_logo = _ROOT_DIR / f"logo.{ext}"
        if custom_logo.exists():
            return FileResponse(custom_logo)
        custom_fav = _ROOT_DIR / f"favicon.{ext}"
        if custom_fav.exists():
            return FileResponse(custom_fav)

    return {"error": "Favicon not found"}



