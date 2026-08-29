import logging
import os
import json
import re
from urllib.request import Request as UrlRequest, urlopen
from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.models.case import Case
from app.models.evidence import Evidence
from app.models.finding import Finding
from app.models.user import User
from app.auth.security import get_current_user, require_case_access
from app.config import limiter, RATE_LIMIT_AI_CHAT

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/chat", tags=["AI Chat Assistant"])


class ChatRequest(BaseModel):
    case_id: int = Field(...)
    question: str = Field(..., max_length=1000)


def build_rag_context(case: Case, db: Session) -> dict:
    """Build factual context payload to bound the LLM answer."""
    evidence = db.query(Evidence).filter(Evidence.case_id == case.id).limit(50).all()
    findings = db.query(Finding).filter(Finding.case_id == case.id).order_by(Finding.risk_score.desc()).limit(50).all()

    return {
        "case": {
            "number": case.case_number,
            "name": case.name,
            "description": case.description
        },
        "evidence": [
            {"filename": item.filename, "mime": item.detected_mime, "sha256": item.sha256}
            for item in evidence
        ],
        "findings": [
            {"title": item.title, "severity": item.severity, "reason": item.reason, "category": item.threat_category}
            for item in findings
        ]
    }


def validate_response(answer: str, context: dict) -> tuple:
    """Post-response validation: check for fabricated entities and add grounding metadata."""
    # Extract entities mentioned in the response
    mentioned_ips = set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', answer))
    mentioned_domains = set(re.findall(r'\b[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}\b', answer))

    # Build known entity set from context
    known_ips = set()
    known_filenames = set()

    for ev in context.get("evidence", []):
        known_filenames.add(ev.get("filename", "").lower())
    for f in context.get("findings", []):
        reason = f.get("reason", "")
        for ip in re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', reason):
            known_ips.add(ip)

    # Check for fabrication
    fabricated_ips = mentioned_ips - known_ips
    fabricated_domains = mentioned_domains - {"example.com", "localhost"} - {d for d in mentioned_domains if any(d.endswith(ext) for ext in [".log", ".txt", ".csv", ".json", ".pdf", ".docx", ".exe", ".dll", ".evtx", ".pcap", ".png", ".jpg"])}

    warnings = []
    if fabricated_ips:
        warnings.append("Response mentions IP(s) not found in case evidence: " + ", ".join(fabricated_ips))
    if fabricated_domains:
        warnings.append("Response mentions domain(s) not found in case evidence: " + ", ".join(fabricated_domains))

    # Check if disclaimer is present
    has_disclaimer = "verified by the investigator" in answer.lower() or "available case data" in answer.lower()

    # Calculate grounding score
    total_entities = len(mentioned_ips) + len(mentioned_domains)
    fabricated_count = len(fabricated_ips) + len(fabricated_domains)
    grounding_score = max(0, 1.0 - (fabricated_count / max(total_entities, 1))) if total_entities > 0 else 1.0

    metadata = {
        "grounding_score": round(grounding_score, 2),
        "has_disclaimer": has_disclaimer,
        "entities_checked": total_entities,
        "fabricated_entities": fabricated_count,
        "warnings": warnings
    }

    # Append warning if fabrication detected
    if warnings:
        answer += "\n\n[SYSTEM WARNING: " + "; ".join(warnings) + ". Verify these claims against case evidence.]"

    # Ensure disclaimer is present
    if not has_disclaimer:
        answer += "\n\n[This analysis is based on available case data and should be verified by the investigator.]"

    return answer, metadata


def build_local_fallback(context: dict, question: str) -> str:
    """Format database fields into a structured textual report fallback summary."""
    findings = context.get("findings", [])
    evidence = context.get("evidence", [])
    case_info = context.get("case", {})

    lines = [
        "--- LOCAL FORENSIC ASSISTANT SUMMARY (Case: " + case_info.get('number', 'N/A') + ") ---",
        "Case Description: " + (case_info.get('description') or 'No description provided.'),
        "Preserved Evidence Files: " + str(len(evidence))
    ]

    for i, item in enumerate(evidence[:5]):
        lines.append("  [" + str(i+1) + "] " + item.get('filename', 'unknown') + " (" + item.get('mime', 'unknown') + ")")

    lines.append("\nAI Flagged Findings: " + str(len(findings)))
    for i, finding in enumerate(findings[:5]):
        lines.append("  - Severity " + finding.get('severity', 'info').upper() + ": " + finding.get('title', ''))
        lines.append("    Reason: " + finding.get('reason', ''))

    lines.append("\nRecommendation: Audit filesystems, compare hashes against standard baselines, and restrict network scopes.")
    lines.append("\n[This analysis is based on available case data and should be verified by the investigator.]")
    return "\n".join(lines)


def fetch_ai_response(context: dict, question: str) -> tuple:
    """Interrogate a configured LLM, or use an explainable local fallback."""
    try:
        from dotenv import load_dotenv
        load_dotenv(override=True)
    except Exception:
        pass

    provider = os.getenv("AI_PROVIDER", "disabled").lower().strip()

    if provider == "disabled":
        return build_local_fallback(context, question), "local"

    if provider == "gemini" and not os.getenv("GEMINI_API_KEY", "").strip():
        logger.warning("AI_PROVIDER is set to 'gemini' but GEMINI_API_KEY is not configured in .env")
        return build_local_fallback(context, question), "local (GEMINI_API_KEY not configured in .env)"

    if provider == "openai" and not os.getenv("OPENAI_API_KEY", "").strip():
        logger.warning("AI_PROVIDER is set to 'openai' but OPENAI_API_KEY is not configured in .env")
        return build_local_fallback(context, question), "local (OPENAI_API_KEY not configured in .env)"

    prompt = (
        "You are an expert Digital Forensics Investigator AI assistant named TACTIC.\n"
        "RULES - You MUST follow these rules strictly:\n"
        "1. ONLY use information present in the CONTEXT below. Do NOT fabricate, invent, or assume any facts.\n"
        "2. Do NOT invent IP addresses, hostnames, usernames, filenames, or event details not in the context.\n"
        "3. Do NOT invent timestamps, dates, or sequences of events not in the context.\n"
        "4. Do NOT make legal conclusions, attributions to specific threat actors, or accusations.\n"
        "5. If the context does not contain enough information, say: The available case evidence does not contain sufficient information.\n"
        "6. Always qualify uncertain statements with 'Based on available evidence...' or 'The data suggests...'.\n"
        "7. Clearly distinguish between facts (from evidence) and your analysis (interpretation).\n"
        "8. Reference specific evidence files and findings when making claims.\n"
        "9. Include a confidence qualifier: HIGH (directly supported), MEDIUM (inferred), LOW (limited data).\n"
        "10. End every response with: [This analysis is based on available case data and should be verified by the investigator.]\n\n"
        "CONTEXT:\n" + json.dumps(context, default=str)[:20000] + "\n\n"
        "QUESTION: " + question + "\n\n"
        "ANSWER (following all rules above):"
    )

    try:
        if provider == "openai" and os.getenv("OPENAI_API_KEY"):
            payload = json.dumps({
                "model": os.getenv("OPENAI_MODEL", "gpt-4-mini"),
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2
            }).encode()
            request = UrlRequest(
                "https://api.openai.com/v1/chat/completions",
                data=payload,
                headers={
                    "Authorization": "Bearer " + os.environ["OPENAI_API_KEY"].strip(),
                    "Content-Type": "application/json"
                },
                method="POST"
            )
            with urlopen(request, timeout=30) as response:
                result = json.load(response)
            answer = result["choices"][0]["message"]["content"]
            answer, meta = validate_response(answer, context)
            return answer, "openai (grounded: " + str(meta['grounding_score']) + ")"

        elif provider == "gemini" and os.getenv("GEMINI_API_KEY"):
            api_key = os.environ["GEMINI_API_KEY"].strip()
            configured_model = os.getenv("GEMINI_MODEL", "gemini-3.5-flash-lite").strip() or "gemini-3.5-flash-lite"
            # Try configured model first, then ultra-fast active fallbacks
            models_to_try = [configured_model]
            for fb_model in ("gemini-3.5-flash-lite", "gemini-3.5-flash", "gemini-3.1-flash-lite", "gemini-3.6-flash"):
                if fb_model not in models_to_try:
                    models_to_try.append(fb_model)

            last_error = None
            answer = None
            for model in models_to_try:
                url = (
                    "https://generativelanguage.googleapis.com/v1beta/models/"
                    + model + ":generateContent"
                )
                payload = json.dumps({
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {
                        "temperature": 0.2,
                        "maxOutputTokens": 1024
                    },
                }).encode()
                request = UrlRequest(
                    url,
                    data=payload,
                    headers={
                        "x-goog-api-key": api_key,
                        "Content-Type": "application/json",
                    },
                    method="POST",
                )
                try:
                    with urlopen(request, timeout=30) as response:
                        result = json.load(response)
                    candidates = result.get("candidates") or []
                    if not candidates:
                        block_reason = result.get("promptFeedback", {}).get("blockReason", "No candidates returned")
                        raise ValueError(f"Gemini API returned no candidates: {block_reason}")
                    parts = candidates[0].get("content", {}).get("parts", [])
                    extracted_text = "".join(
                        part.get("text", "") for part in parts if isinstance(part, dict) and "text" in part
                    ).strip()
                    if extracted_text:
                        answer = extracted_text
                        break
                except Exception as model_err:
                    last_error = model_err
                    logger.warning("Gemini model %s query failed: %s", model, type(model_err).__name__)
                    continue

            if not answer:
                if last_error:
                    raise last_error
                raise ValueError("Gemini returned no text content.")

            answer, meta = validate_response(answer, context)
            return answer, "gemini (grounded: " + str(meta['grounding_score']) + ")"

        elif provider == "ollama":
            url = os.getenv("OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/") + "/api/generate"
            payload = json.dumps({
                "model": os.getenv("OLLAMA_MODEL", "llama3"),
                "prompt": prompt,
                "stream": False
            }).encode()
            request = UrlRequest(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
            with urlopen(request, timeout=60) as response:
                result = json.load(response)
            answer = result.get("response", "No response content.")
            answer, meta = validate_response(answer, context)
            return answer, "ollama (grounded: " + str(meta['grounding_score']) + ")"

    except Exception as exc:
        logger.warning("External AI query failed: %s", type(exc).__name__)

    return build_local_fallback(context, question), "local (provider error fallback)"


@router.post("", status_code=status.HTTP_200_OK)
@limiter.limit(RATE_LIMIT_AI_CHAT)
def ask_assistant(request: Request,
    payload: ChatRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Query the context-bounded assistant, utilizing local SQLAlchemy relations as prompt limits."""
    case = db.query(Case).filter(Case.id == payload.case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Case not found.")
    require_case_access(case, current_user)

    context = build_rag_context(case, db)
    answer, provider = fetch_ai_response(context, payload.question)
    # Run validation on final answer
    answer, validation_meta = validate_response(answer, context)
    return {
        "answer": answer,
        "provider": provider,
        "safeguards": {
            "grounding_score": validation_meta["grounding_score"],
            "fabricated_entities": validation_meta["fabricated_entities"],
            "warnings": validation_meta["warnings"],
            "disclaimer_present": validation_meta["has_disclaimer"]
        }
    }
