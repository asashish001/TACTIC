import json
import re
from sqlalchemy.orm import Session
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.artifact_correlation import ArtifactCorrelation
from app.services.correlation_engine import correlate_case_artifacts, categorize_score
from app.services.settings_service import get_correlation_config
import logging


logger = logging.getLogger(__name__)
IP_REGEX = re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


def get_category_color(category: str) -> str:
    """Return stroke color for correlation graph edges based on strength category."""
    if category == "Strong":
        return "#06b6d4" # Cyan / Neon Green
    elif category == "Moderate":
        return "#f59e0b" # Amber / Yellow
    return "#64748b" # Slate / Gray


def build_correlation_graph(case_id: int, db: Session) -> dict:
    """Scan evidence, findings, and computed ArtifactCorrelation records to generate nodes and weighted edges."""
    nodes = []
    edges = []
    
    seen_nodes = set()
    seen_edges = set()
    
    def add_node(node_id: str, label: str, node_type: str):
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "label": label, "type": node_type})

    def add_edge(
        source: str,
        target: str,
        label: str,
        score: float = 1.0,
        category: str = "Strong",
        reason: str = "Structural link",
        components: dict | None = None
    ):
        edge_key = f"{source}-{target}"
        reverse_key = f"{target}-{source}"
        if edge_key not in seen_edges and reverse_key not in seen_edges:
            seen_edges.add(edge_key)
            edges.append({
                "source": source,
                "target": target,
                "label": label,
                "score": round(score, 2),
                "strength_category": category,
                "reason": reason,
                "components": components or {},
                "color": get_category_color(category)
            })

    # 1. Fetch case evidence
    evidence_items = db.query(Evidence).filter(Evidence.case_id == case_id).all()
    if not evidence_items:
        return {"nodes": [], "edges": []}

    case_node_id = f"case_{case_id}"
    add_node(case_node_id, f"Case {case_id}", "case")

    for item in evidence_items:
        ev_node_id = f"evidence_{item.id}"
        add_node(ev_node_id, item.filename, "evidence")
        add_edge(case_node_id, ev_node_id, "contains", score=1.0, category="Strong", reason="Case evidence container")

        # Hashes
        hash_node_id = f"hash_{item.sha256[:8]}"
        add_node(hash_node_id, f"SHA256: {item.sha256[:8]}...", "hash")
        add_edge(ev_node_id, hash_node_id, "hashes_to", score=1.0, category="Strong", reason="SHA256 cryptographic hash")

        meta_str = json_to_str(item.extracted_metadata)
        
        # Match IPs
        ips = set(IP_REGEX.findall(meta_str))
        for ip in ips:
            ip_node_id = f"ip_{ip}"
            add_node(ip_node_id, ip, "ip")
            add_edge(ev_node_id, ip_node_id, "references_ip", score=0.85, category="Strong", reason=f"Extracted IP endpoint {ip}")

        # Match Emails
        emails = set(EMAIL_REGEX.findall(meta_str))
        for email in emails:
            email_node_id = f"email_{email}"
            add_node(email_node_id, email, "email")
            add_edge(ev_node_id, email_node_id, "contains_email", score=0.85, category="Strong", reason=f"Extracted Email {email}")

        # Log specific fields (Usernames)
        meta = item.extracted_metadata
        if meta.get("kind") == "evtx" and "records" in meta:
            for record in meta["records"]:
                data = record.get("data", {})
                for key in ("TargetUserName", "SubjectUserName", "User", "AccountName"):
                    user = data.get(key)
                    if user and user not in ("SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE", "-"):
                        user_node_id = f"user_{user.lower()}"
                        add_node(user_node_id, user, "username")
                        add_edge(ev_node_id, user_node_id, "logs_auth_user", score=0.80, category="Strong", reason=f"Log auth username {user}")

        if hasattr(item, "extracted_artifacts") and item.extracted_artifacts:
            for art in item.extracted_artifacts:
                art_node_id = f"art_{art.artifact_type.lower()}_{art.value[:30].replace(' ', '_')}"
                add_node(art_node_id, f"{art.artifact_type}: {art.value[:25]}", art.artifact_type.lower())
                add_edge(ev_node_id, art_node_id, f"extracted_{art.artifact_type.lower()}", score=0.75, category="Strong", reason=f"Extracted {art.artifact_type}")

    # 2. Fetch case findings
    findings = db.query(Finding).filter(Finding.case_id == case_id).all()
    for finding in findings:
        finding_node_id = f"finding_{finding.id}"
        add_node(finding_node_id, finding.title, "finding")
        
        if finding.evidence_id:
            add_edge(f"evidence_{finding.evidence_id}", finding_node_id, f"triggers ({finding.severity})", score=0.90, category="Strong", reason=f"AI finding triggered from evidence #{finding.evidence_id}")
        else:
            add_edge(case_node_id, finding_node_id, "affects", score=0.80, category="Strong", reason="AI finding affects case")

    # 3. Query computed ArtifactCorrelation records (or build them if empty)
    correlations = db.query(ArtifactCorrelation).filter(ArtifactCorrelation.case_id == case_id).all()
    if not correlations:
        cfg = get_correlation_config(db)
        correlations = correlate_case_artifacts(case_id, db, weights=cfg["weights"], time_window_seconds=cfg["time_window_seconds"])

    for c in correlations:
        node_a_id = f"corr_{c.artifact_a_id}"
        node_b_id = f"corr_{c.artifact_b_id}"

        add_node(node_a_id, c.artifact_a_label, c.artifact_a_type.lower())
        add_node(node_b_id, c.artifact_b_label, c.artifact_b_type.lower())

        add_edge(
            node_a_id,
            node_b_id,
            f"{c.correlation_type} ({c.score:.2f})",
            score=c.score,
            category=c.strength_category,
            reason=c.reason,
            components=c.components
        )

    return {"nodes": nodes, "edges": edges}


def json_to_str(data) -> str:
    """Helper to convert nested dictionary structure into flat search text string."""
    try:
        return json.dumps(data)
    except Exception as exc:
        logger.debug("JSON serialization failed, falling back to str(): %s", exc)
        return str(data)
