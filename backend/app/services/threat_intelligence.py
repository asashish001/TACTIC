"""Evidence-to-CVE and IOC correlation helpers for the FastAPI intelligence module."""
import json
import logging
import os
import re
from functools import lru_cache
from urllib.parse import quote
from urllib.request import Request, urlopen

from app.models.evidence import Evidence

logger = logging.getLogger(__name__)
SOFTWARE_PATTERN = re.compile(
    r"\b(google\s+chrome|chrome|mozilla\s+firefox|firefox|adobe\s+reader|acrobat|"
    r"openssl|apache|tomcat|java|vlc|winrar|7-zip|7zip|putty)\b[\s_:-]*(?:version\s*)?v?(\d+(?:\.\d+){1,3})",
    re.IGNORECASE,
)
IP_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"']+", re.IGNORECASE)


def remote_lookups_enabled() -> bool:
    """Remote enrichment is opt-in because evidence strings may be sensitive."""
    return os.getenv("THREAT_INTEL_REMOTE_LOOKUPS", "false").lower() in {"1", "true", "yes"}


def evidence_text(evidence: Evidence) -> str:
    metadata = evidence.extracted_metadata or {}
    parts = [evidence.filename.replace("_", " ").replace("-", " "), evidence.detected_mime, evidence.extension]
    for key in ("sample", "software", "producer", "creator", "author", "raw_exif"):
        value = metadata.get(key)
        if value:
            parts.append(json.dumps(value) if isinstance(value, (dict, list)) else str(value))
    return " ".join(parts)[:30_000]


def extract_software(evidence: Evidence) -> list[dict]:
    """Return conservative product/version candidates observed in evidence content."""
    found, seen = [], set()
    for product, version in SOFTWARE_PATTERN.findall(evidence_text(evidence)):
        normalized = " ".join(product.lower().split())
        key = (normalized, version)
        if key not in seen:
            seen.add(key)
            found.append({"product": normalized, "version": version})
    return found


def extract_iocs(evidence: Evidence) -> list[dict]:
    text = evidence_text(evidence)
    values = []
    for value in sorted(set(IP_PATTERN.findall(text))):
        values.append({"indicator_type": "ip", "value": value})
    for value in sorted(set(URL_PATTERN.findall(text))):
        values.append({"indicator_type": "url", "value": value.rstrip(".,;)")})
    values.append({"indicator_type": "sha256", "value": evidence.sha256})
    return values


def _get_json(url: str, timeout: int = 12) -> dict:
    request = Request(url, headers={"User-Agent": "AIDFA-Forensics-Research/1.0"})
    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


@lru_cache(maxsize=1)
def _kev_ids() -> set[str]:
    payload = _get_json("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json")
    return {item["cveID"] for item in payload.get("vulnerabilities", []) if item.get("cveID")}


def _cvss(cve: dict) -> tuple[float | None, str]:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {})
            return data.get("baseScore"), str(data.get("baseSeverity") or "unknown").lower()
    return None, "unknown"


def lookup_cves(product: str, version: str) -> list[dict]:
    """Query NVD keyword search and enrich returned CVEs with KEV/EPSS context."""
    if not remote_lookups_enabled():
        return []
    query = quote(f"{product} {version}")
    payload = _get_json(f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}&resultsPerPage=20")
    kev_ids = _kev_ids()
    results = []
    for entry in payload.get("vulnerabilities", []):
        cve = entry.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        cvss_score, severity = _cvss(cve)
        epss = None
        try:
            epss_data = _get_json(f"https://api.first.org/data/v1/epss?cve={quote(cve_id)}")
            records = epss_data.get("data", [])
            epss = float(records[0]["epss"]) if records else None
        except Exception as exc:
            logger.debug("EPSS lookup failed for %s: %s", cve_id, exc)
        description = next((item.get("value", "") for item in cve.get("descriptions", []) if item.get("lang") == "en"), "")
        references = [item.get("url") for item in cve.get("references", []) if item.get("url")][:10]
        kev = cve_id in kev_ids
        risk_score = min(100, int((cvss_score or 0) * 8 + (epss or 0) * 30 + (20 if kev else 0)))
        results.append({"cve_id": cve_id, "severity": severity, "cvss_score": cvss_score, "epss_score": epss, "is_kev": kev, "risk_score": risk_score, "description": description, "references": references, "source_data": {"source": "NVD", "keyword": f"{product} {version}"}})
    return results
