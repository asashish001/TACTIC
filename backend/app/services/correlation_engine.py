"""TACTIC Complete Cross-Evidence Correlation Engine.

Optimised with entity indexing, time-window bucketing, and batched
persistence to avoid O(n²) blow-ups on large cases.
"""
import datetime
import logging
from collections import defaultdict
from typing import Any

from sqlalchemy.orm import Session

from app.models.artifact_correlation import ArtifactCorrelation
from app.models.browser_artifact import BrowserArtifact
from app.models.extracted_artifact import ExtractedArtifact
from app.models.finding import Finding
from app.models.network_artifact import NetworkArtifact
from app.services.timezone_service import safe_parse_timestamp

logger = logging.getLogger("tactic.correlation_engine")

DEFAULT_WEIGHTS = {"time": 0.30, "entity": 0.35, "source": 0.15, "event": 0.20}
DEFAULT_TIME_WINDOW = 3600 # 1 hour in seconds

BATCH_SIZE = 500


def compute_time_similarity(t1: Any, t2: Any, window_seconds: float = 3600) -> float:
    """Calculate normalized time similarity S_time between 0.0 and 1.0."""
    dt1 = safe_parse_timestamp(t1) if t1 else None
    dt2 = safe_parse_timestamp(t2) if t2 else None

    if not dt1 or not dt2:
        return 0.0

    delta_seconds = abs((dt1 - dt2).total_seconds())
    if delta_seconds >= window_seconds:
        return 0.0

    return round(max(0.0, 1.0 - (delta_seconds / window_seconds)), 4)


def compute_entity_similarity(
    val1: str,
    type1: str,
    val2: str,
    type2: str
) -> tuple[float, str]:
    """Calculate normalized entity similarity S_entity and match description."""
    if not val1 or not val2:
        return 0.0, ""

    v1_clean = str(val1).strip().lower()
    v2_clean = str(val2).strip().lower()

    if not v1_clean or not v2_clean:
        return 0.0, ""

    if v1_clean == v2_clean:
        ent_label = type1.upper() if type1 == type2 else f"{type1.upper()}/{type2.upper()}"
        return 1.0, f"Exact {ent_label} match ({val1})"

    if (v1_clean in v2_clean or v2_clean in v1_clean) and len(min(v1_clean, v2_clean)) >= 4:
        return 0.75, f"Sub-string entity match ({val1} ~ {val2})"

    return 0.0, ""


def compute_source_relationship(source1: str, source2: str) -> float:
    """Calculate source relationship similarity S_source between 0.0 and 1.0."""
    if not source1 or not source2:
        return 0.1

    s1 = str(source1).strip().lower()
    s2 = str(source2).strip().lower()

    if s1 == s2:
        return 1.0
    if s1 in s2 or s2 in s1:
        return 0.6
    return 0.2


def compute_event_relationship(event_type1: str, event_type2: str) -> float:
    """Calculate event-type relationship similarity S_event between 0.0 and 1.0."""
    if not event_type1 or not event_type2:
        return 0.2

    e1 = str(event_type1).strip().lower()
    e2 = str(event_type2).strip().lower()

    if e1 == e2:
        return 1.0

    auth_types = {"successful_login", "failed_login", "4624", "4625", "logon"}
    exec_types = {"program_execution", "4688", "1", "execution", "process"}

    if (e1 in auth_types and e2 in exec_types) or (e1 in exec_types and e2 in auth_types):
        return 0.7

    return 0.3


def categorize_score(score: float) -> str:
    """Categorize normalized correlation score into Weak, Moderate, or Strong."""
    if score >= 0.70:
        return "Strong"
    elif score >= 0.40:
        return "Moderate"
    return "Weak"


def calculate_correlation_score(
    s_time: float,
    s_entity: float,
    s_source: float,
    s_event: float,
    weights: dict[str, float] | None = None
) -> float:
    """Calculate normalized score S_total from weighted explainable components."""
    w = weights or DEFAULT_WEIGHTS
    w_sum = sum(w.values()) or 1.0

    raw = (
        (w.get("time", 0.30) * s_time) +
        (w.get("entity", 0.35) * s_entity) +
        (w.get("source", 0.15) * s_source) +
        (w.get("event", 0.20) * s_event)
    ) / w_sum

    return round(min(1.0, max(0.0, raw)), 4)


def _collect_artifacts(case_id: int, db: Session) -> list[dict]:
    """Gather all case artifacts into a normalised list of dicts."""
    items: list[dict] = []

    for art in db.query(ExtractedArtifact).filter(ExtractedArtifact.case_id == case_id).all():
        items.append({
            "type": f"Extracted_{art.artifact_type.upper()}",
            "id": f"ext_{art.id}",
            "label": f"{art.artifact_type}: {art.value[:30]}",
            "entity_value": art.value,
            "entity_type": art.artifact_type,
            "timestamp": getattr(art, "timestamp", None) or getattr(art, "extracted_at", None),
            "source": art.evidence.filename if art.evidence else "Extracted Engine",
            "event_type": (art.artifact_type or "unknown").lower(),
            "_ts_dt": safe_parse_timestamp(
                getattr(art, "timestamp", None) or getattr(art, "extracted_at", None)
            ),
        })

    for f in db.query(Finding).filter(Finding.case_id == case_id).all():
        items.append({
            "type": "Finding",
            "id": f"find_{f.id}",
            "label": f.title[:35],
            "entity_value": f.threat_category,
            "entity_type": "finding_category",
            "timestamp": f.created_at,
            "source": f.evidence.filename if f.evidence else "AI Engine",
            "event_type": (f.severity or "info").lower(),
            "_ts_dt": safe_parse_timestamp(f.created_at),
        })

    for b in db.query(BrowserArtifact).filter(BrowserArtifact.case_id == case_id).all():
        ts = getattr(b, "timestamp", None) or getattr(b, "extracted_at", None)
        items.append({
            "type": "BrowserArtifact",
            "id": f"browser_{b.id}",
            "label": f"{b.browser.upper()} {b.artifact_type}: {b.domain or b.url or b.title or 'Record'}"[:35],
            "entity_value": b.domain or b.url or (b.details.get("username_value") if isinstance(b.details, dict) else "") or "",
            "entity_type": "domain" if b.domain else "url",
            "timestamp": ts,
            "source": f"Browser ({b.browser})",
            "event_type": (b.artifact_type or "unknown").lower(),
            "_ts_dt": safe_parse_timestamp(ts),
        })

    for n in db.query(NetworkArtifact).filter(NetworkArtifact.case_id == case_id).all():
        val = n.destination_ip or n.source_ip or (n.details.get("domain") if isinstance(n.details, dict) else "") or n.value or ""
        ts = getattr(n, "timestamp", None) or getattr(n, "extracted_at", None)
        items.append({
            "type": "NetworkArtifact",
            "id": f"net_{n.id}",
            "label": f"Network {n.protocol or n.artifact_type or 'Unknown'}: {val}"[:35],
            "entity_value": val,
            "entity_type": "ip" if (n.destination_ip or n.source_ip) else "domain",
            "timestamp": ts,
            "source": f"Network ({n.protocol or n.artifact_type or 'Unknown'})",
            "event_type": (n.protocol or n.artifact_type or "unknown").lower(),
            "_ts_dt": safe_parse_timestamp(ts),
        })

    return items


def _build_entity_index(items: list[dict]) -> dict[str, list[int]]:
    """Index items by normalised entity value for O(1) candidate lookups.

    Only items with a non-empty, normalised entity value are indexed.
    Items without an entity value still need pair-wise comparison with
    everything else, but those are handled via the ``unindexed`` list.
    """
    index: dict[str, list[int]] = defaultdict(list)
    for idx, item in enumerate(items):
        ev = (item.get("entity_value") or "").strip().lower()
        if ev:
            index[ev].append(idx)
    return index


def _build_time_buckets(
    items: list[dict], window_seconds: float
) -> list[list[int]]:
    """Bucket items into sorted time windows for temporal pre-filtering.

    Items are sorted by their parsed datetime, then grouped into buckets
    of *window_seconds* width.  Two items in distant buckets can never
    achieve a time_similarity > 0, so we skip those pairs.
    """
    indexed = [
        (i, item["_ts_dt"])
        for i, item in enumerate(items)
        if item.get("_ts_dt") is not None
    ]
    indexed.sort(key=lambda t: t[1])

    if not indexed:
        return [[i for i in range(len(items))]]  # fallback: one big bucket

    buckets: list[list[int]] = []
    bucket_start = indexed[0][1]
    current: list[int] = []

    for idx, dt in indexed:
        if (dt - bucket_start).total_seconds() > window_seconds:
            if current:
                buckets.append(current)
            current = []
            bucket_start = dt
        current.append(idx)
    if current:
        buckets.append(current)

    no_ts = [i for i, item in enumerate(items) if item.get("_ts_dt") is None]
    if no_ts:
        for bucket in buckets:
            bucket.extend(no_ts)

    return buckets or [[i for i in range(len(items))]]


def _create_record(
    case_id: int, a: dict, b: dict,
    s_time: float, s_entity: float, s_source: float, s_event: float,
    ent_desc: str, w: dict, win_sec: float,
) -> ArtifactCorrelation:
    """Build an ArtifactCorrelation record from a scored pair."""
    score = calculate_correlation_score(s_time, s_entity, s_source, s_event, weights=w)
    if score < 0.15:
        return None

    category = categorize_score(score)

    if s_entity > 0.8:
        corr_type, reason_part = "ENTITY_MATCH", ent_desc
    elif s_time > 0.7:
        corr_type, reason_part = "TIME_PROXIMITY", f"High temporal closeness (time sim: {s_time:.2f})"
    elif s_source > 0.8:
        corr_type, reason_part = "COMMON_SOURCE", f"Shared evidence source ({a['source']})"
    else:
        corr_type, reason_part = "MULTI_FACTOR", "Multi-factor heuristic correlation"

    reason = (
        f"{category} correlation ({corr_type}): {reason_part}. "
        f"Breakdown -> Time: {s_time:.2f}, Entity: {s_entity:.2f}, "
        f"Source: {s_source:.2f}, Event: {s_event:.2f}."
    )

    components = {
        "time_similarity": round(s_time, 4),
        "entity_similarity": round(s_entity, 4),
        "source_relationship": round(s_source, 4),
        "event_relationship": round(s_event, 4),
        "weights": w,
        "time_window_seconds": win_sec,
    }

    ref_ts = a.get("_ts_dt") or datetime.datetime.now(datetime.timezone.utc)

    return ArtifactCorrelation(
        case_id=case_id,
        artifact_a_type=a["type"], artifact_a_id=a["id"],
        artifact_a_label=a["label"],
        artifact_b_type=b["type"], artifact_b_id=b["id"],
        artifact_b_label=b["label"],
        correlation_type=corr_type, score=score,
        strength_category=category, reason=reason,
        components=components, timestamp=ref_ts,
    )


def correlate_case_artifacts(
    case_id: int,
    db: Session,
    weights: dict[str, float] | None = None,
    time_window_seconds: float = 3600,
) -> list[ArtifactCorrelation]:
    """Execute cross-evidence correlation engine with O(e + k) candidate pairs.

    Instead of comparing every item against every other (O(n²)), the engine:

    1. **Entity index** – groups items by normalised entity value; only pairs
       sharing an entity value are compared via that path.
    2. **Time buckets** – sorts items by timestamp and splits into fixed-width
       windows; items in distant buckets are never compared.
    3. **Batch inserts** – flushes to the database every *BATCH_SIZE* records
       to bound memory.
    """
    w = weights or DEFAULT_WEIGHTS
    win_sec = time_window_seconds or DEFAULT_TIME_WINDOW

    db.query(ArtifactCorrelation).filter(ArtifactCorrelation.case_id == case_id).delete()

    items = _collect_artifacts(case_id, db)
    n = len(items)
    if n < 2:
        db.commit()
        return []

    # ── Build lookup structures ────────────────────────────────────────
    entity_index = _build_entity_index(items)
    time_buckets = _build_time_buckets(items, win_sec)

    bucket_sets = [set(b) for b in time_buckets]

    # ── Candidate pair generation ──────────────────────────────────────
    seen_pairs: set[tuple[str, str]] = set()
    candidates: list[tuple[int, int]] = []

    for indices in entity_index.values():
        for i in range(len(indices)):
            for j in range(i + 1, len(indices)):
                pair = (items[indices[i]]["id"], items[indices[j]]["id"])
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    candidates.append((indices[i], indices[j]))

    for bucket in bucket_sets:
        bucket_list = sorted(bucket)
        for i in range(len(bucket_list)):
            for j in range(i + 1, len(bucket_list)):
                ai, aj = bucket_list[i], bucket_list[j]
                pair = (items[ai]["id"], items[aj]["id"])
                if pair not in seen_pairs:
                    seen_pairs.add(pair)
                    candidates.append((ai, aj))

    logger.info(
        f"Case {case_id}: {n} artifacts → {len(candidates)} candidate pairs "
        f"(vs {n * (n - 1) // 2} brute-force)"
    )

    # ── Score and persist in batches ───────────────────────────────────
    created_correlations: list[ArtifactCorrelation] = []
    batch: list[ArtifactCorrelation] = []

    for i, j in candidates:
        a, b = items[i], items[j]
        s_time = compute_time_similarity(a["timestamp"], b["timestamp"], window_seconds=win_sec)
        s_entity, ent_desc = compute_entity_similarity(
            a["entity_value"], a["entity_type"], b["entity_value"], b["entity_type"],
        )
        s_source = compute_source_relationship(a["source"], b["source"])
        s_event = compute_event_relationship(a["event_type"], b["event_type"])

        record = _create_record(case_id, a, b, s_time, s_entity, s_source, s_event, ent_desc, w, win_sec)
        if record is not None:
            batch.append(record)
            if len(batch) >= BATCH_SIZE:
                db.add_all(batch)
                db.flush()
                created_correlations.extend(batch)
                batch = []

    if batch:
        db.add_all(batch)
        db.flush()
        created_correlations.extend(batch)

    db.commit()
    logger.info("Compiled %s cross-evidence correlation pairs for Case %s.", len(created_correlations), case_id)
    return created_correlations
