"""Privacy-preserving extraction for Chrome/Edge and Firefox browser artifacts."""
import datetime
import json
import sqlite3
from pathlib import Path
from urllib.parse import urlsplit


def _domain(url: str | None) -> str | None:
    if not url:
        return None
    try:
        return urlsplit(url).hostname
    except ValueError:
        return None


def _chrome_time(value) -> str | None:
    try:
        from app.services.timezone_service import normalize_to_utc
        utc_dt, _, _ = normalize_to_utc(value)
        if utc_dt:
            return utc_dt.isoformat()
        value = int(value)
        if value <= 0:
            return None
        epoch = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
        return (epoch + datetime.timedelta(microseconds=value)).isoformat()
    except (TypeError, ValueError, OverflowError):
        return None


def _firefox_time(value) -> str | None:
    try:
        from app.services.timezone_service import normalize_to_utc
        utc_dt, _, _ = normalize_to_utc(value)
        if utc_dt:
            return utc_dt.isoformat()
        value = int(value)
        if value <= 0:
            return None
        return datetime.datetime.fromtimestamp(value / 1_000_000, tz=datetime.timezone.utc).isoformat()
    except (TypeError, ValueError, OverflowError, OSError):
        return None


def _readonly_db(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def _tables(connection: sqlite3.Connection) -> set[str]:
    return {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}


def _safe_rows(connection: sqlite3.Connection, query: str, limit: int = 2_000) -> list[sqlite3.Row]:
    try:
        return connection.execute(query, (limit,)).fetchall()
    except sqlite3.Error:
        return []


def _artifact(browser: str, artifact_type: str, *, url: str | None = None, title: str | None = None,
              timestamp: str | None = None, details: dict | None = None) -> dict:
    return {
        "browser": browser, "artifact_type": artifact_type, "url": url,
        "domain": _domain(url), "title": title, "timestamp": timestamp,
        "details": details or {},
    }


def _extract_chromium(connection: sqlite3.Connection, tables: set[str]) -> list[dict]:
    artifacts: list[dict] = []
    if "urls" in tables:
        for url, title, last_visit, count in _safe_rows(connection, "SELECT url, title, last_visit_time, visit_count FROM urls ORDER BY last_visit_time DESC LIMIT ?"):
            artifacts.append(_artifact("chromium", "history", url=url, title=title, timestamp=_chrome_time(last_visit), details={"visit_count": count or 0}))
    if "downloads" in tables:
        rows = _safe_rows(connection, "SELECT target_path, tab_url, start_time, total_bytes, danger_type FROM downloads ORDER BY start_time DESC LIMIT ?")
        for target_path, tab_url, started, total_bytes, danger_type in rows:
            artifacts.append(_artifact("chromium", "download", url=tab_url, timestamp=_chrome_time(started), details={"target_path": target_path, "total_bytes": total_bytes, "danger_type": danger_type}))
    if "cookies" in tables:
        for host, name, path, expires, secure in _safe_rows(connection, "SELECT host_key, name, path, expires_utc, is_secure FROM cookies LIMIT ?"):
            artifacts.append(_artifact("chromium", "cookie_metadata", url=f"https://{host}", timestamp=_chrome_time(expires), details={"name": name, "path": path, "secure": bool(secure)}))
    return artifacts


def _extract_firefox(connection: sqlite3.Connection, tables: set[str]) -> list[dict]:
    artifacts: list[dict] = []
    if "moz_places" in tables:
        for url, title, last_visit, count in _safe_rows(connection, "SELECT url, title, last_visit_date, visit_count FROM moz_places ORDER BY last_visit_date DESC LIMIT ?"):
            artifacts.append(_artifact("firefox", "history", url=url, title=title, timestamp=_firefox_time(last_visit), details={"visit_count": count or 0}))
    if {"moz_bookmarks", "moz_places"}.issubset(tables):
        query = "SELECT p.url, b.title, b.dateAdded FROM moz_bookmarks b JOIN moz_places p ON b.fk = p.id WHERE b.fk IS NOT NULL ORDER BY b.dateAdded DESC LIMIT ?"
        for url, title, added in _safe_rows(connection, query):
            artifacts.append(_artifact("firefox", "bookmark", url=url, title=title, timestamp=_firefox_time(added)))
    if "moz_cookies" in tables:
        for host, name, path, expiry, secure in _safe_rows(connection, "SELECT host, name, path, expiry, isSecure FROM moz_cookies LIMIT ?"):
            artifacts.append(_artifact("firefox", "cookie_metadata", url=f"https://{host}", timestamp=datetime.datetime.fromtimestamp(expiry, tz=datetime.timezone.utc).isoformat() if expiry else None, details={"name": name, "path": path, "secure": bool(secure)}))
    return artifacts


def _extract_chrome_bookmarks(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    artifacts: list[dict] = []
    def visit(node):
        if isinstance(node, dict):
            if node.get("type") == "url" and node.get("url"):
                artifacts.append(_artifact("chromium", "bookmark", url=node["url"], title=node.get("name"), timestamp=_chrome_time(node.get("date_added"))))
            for child in node.get("children", []):
                visit(child)
            for value in node.values():
                if isinstance(value, dict):
                    visit(value)
    visit(payload.get("roots", {}))
    return artifacts


def _extract_firefox_logins(path: Path) -> list[dict]:
    payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    return [_artifact("firefox", "saved_password_metadata", url=item.get("hostname"), timestamp=_firefox_time(item.get("timeLastUsed")), details={"username_field": item.get("usernameField"), "password_field": item.get("passwordField"), "times_used": item.get("timesUsed", 0)}) for item in payload.get("logins", [])]


def extract_browser_artifacts(path: Path, filename: str) -> tuple[list[dict], list[str]]:
    """Extract safe browser artifacts; return warnings rather than failing a case analysis."""
    warnings: list[str] = []
    lower_name = filename.lower()
    try:
        if "bookmark" in lower_name and (lower_name.endswith(".json") or "." not in Path(lower_name).name):
            return _extract_chrome_bookmarks(path), warnings
        if "login" in lower_name and lower_name.endswith(".json"):
            return _extract_firefox_logins(path), warnings
        connection = _readonly_db(path)
        try:
            tables = _tables(connection)
            if "urls" in tables or "downloads" in tables or "cookies" in tables:
                return _extract_chromium(connection, tables), warnings
            if "moz_places" in tables or "moz_cookies" in tables:
                return _extract_firefox(connection, tables), warnings
        finally:
            connection.close()
    except (OSError, sqlite3.Error, json.JSONDecodeError, UnicodeDecodeError) as exc:
        warnings.append(f"{filename}: browser extraction failed ({exc}).")
    return [], warnings


def is_suspicious_browser_artifact(artifact: dict) -> bool:
    """Conservative indicators for analyst review; not a maliciousness verdict."""
    url = (artifact.get("url") or "").lower()
    target = str(artifact.get("details", {}).get("target_path") or "").lower()
    return any(term in url for term in ("xn--", ".onion", "verify-account", "wallet-connect", "login-secure")) or target.endswith((".exe", ".scr", ".js", ".vbs", ".ps1"))
