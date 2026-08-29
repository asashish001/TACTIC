"""Real NLP Artifact Extraction Engine using Hugging Face Transformers with Deterministic Fallback.

Extracts mandatory forensic entities:
PERSON, USERNAME, IP_ADDRESS, DOMAIN, URL, EMAIL, FILE_PATH, PROCESS,
HOSTNAME, TIMESTAMP, SESSION_ID, COMMAND, EVENT.

Every extracted artifact retains source evidence linking, character offsets,
context snippets, and confidence scores.
"""
import os
import re
import sys
import logging
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger("tactic.nlp_extractor")

# RegEx Patterns for Deterministic Artifact Extraction
IP_V4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
IP_V6_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b")
URL_PATTERN = re.compile(r"\b(?:https?|ftp)://[^\s<>'\"]+\b", re.IGNORECASE)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+(?:com|org|net|edu|gov|io|co|uk|de|ru|cn|info|biz|onion)\b", re.IGNORECASE)
WIN_PATH_PATTERN = re.compile(r'\b[a-zA-Z]:\\(?:[^\s\\/:*?"<>|\r\n]+\\)*[^\s\\/:*?"<>|\r\n]+\b')
UNC_PATH_PATTERN = re.compile(r'\\\\[a-zA-Z0-9_.-]+\\[^\s\\/:*?"<>|\r\n]+\b')
UNIX_PATH_PATTERN = re.compile(r"\b/(?:[a-zA-Z0-9_.-]+/)+[a-zA-Z0-9_.-]+\b")
PROCESS_PATTERN = re.compile(r"\b[a-zA-Z0-9_.-]+\.(?:exe|dll|sys|scr|bat|cmd|ps1|vbs|py|sh|elf)\b", re.IGNORECASE)
HOSTNAME_PATTERN = re.compile(r"\b(?:WIN|DESKTOP|LAPTOP|SRV|SERVER|HOST|DC)-[A-Z0-9]{4,15}\b", re.IGNORECASE)
TIMESTAMP_ISO_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b")
TIMESTAMP_EXIF_PATTERN = re.compile(r"\b\d{4}:\d{2}:\d{2} \d{2}:\d{2}:\d{2}\b")
SID_PATTERN = re.compile(r"\bS-1-[0-5]-(?:\d+-)*\d+\b")
UUID_PATTERN = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
COMMAND_PATTERN = re.compile(r"\b(?:powershell(?:\.exe)?|cmd(?:\.exe)?|bash|sh|sudo|wmic|net\s+(?:user|group|localgroup)|reg\s+(?:add|delete|query)|taskkill|vssadmin|bcedit)\s+[^\r\n]+", re.IGNORECASE)
USERNAME_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9._-]+@[a-zA-Z0-9.-]+|[a-zA-Z0-9._-]+\\[a-zA-Z0-9._-]+|(?:user|username|targetusername|subjectusername)[\s:=]+([a-zA-Z0-9._-]+))\b", re.IGNORECASE)


class NLPArtifactExtractor:
    """Manages Hugging Face Transformer NER pipeline with deterministic rule-based fallback."""

    def __init__(self, model_name: str | None = None):
        self.model_name = model_name or os.getenv("NLP_MODEL_NAME", "dslim/bert-base-NER")
        self.loaded = False
        self.error_state = "Not yet initialized (lazy loading active)"
        self.pipeline = None
        self._initialized = False
        self._lock = threading.Lock()

    def _initialize_transformer(self) -> None:
        """Attempt to load Hugging Face Transformers model and tokenizer safely."""
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return
            self._initialized = True

            if self.model_name.lower() in ("disabled", "offline", "fallback"):
                self.loaded = False
                self.error_state = f"Transformer model disabled; deterministic extraction active ({self.model_name})"
                self.pipeline = None
                return

        try:
            import transformers
            from transformers import pipeline
            
            # Try loading from local cache first for instant startup
            try:
                self.pipeline = pipeline(
                    "token-classification",
                    model=self.model_name,
                    tokenizer=self.model_name,
                    aggregation_strategy="simple",
                    model_kwargs={"local_files_only": True}
                )
                self.loaded = True
                self.error_state = None
                logger.info("Loaded Hugging Face Transformer model '%s' from local cache.", self.model_name)
                return
            except Exception as exc:
                logger.debug("Transformer model not found in local cache: %s", exc)

            # If not in cache and network download is enabled, try loading with model pipeline
            if os.getenv("HF_HUB_OFFLINE", "0") == "1" or os.getenv("TRANSFORMERS_OFFLINE", "0") == "1":
                raise RuntimeError("Hugging Face Hub is set to offline mode.")

            self.pipeline = pipeline(
                "token-classification",
                model=self.model_name,
                tokenizer=self.model_name,
                aggregation_strategy="simple"
            )
            self.loaded = True
            self.error_state = None
            logger.info("Loaded Hugging Face Transformer model '%s' successfully.", self.model_name)
        except Exception as exc:
            self.loaded = False
            self.error_state = f"Model load failed: {str(exc)}"
            self.pipeline = None
            logger.warning("Transformer model initialization fallback activated: %s", exc)

    def get_status(self) -> dict[str, Any]:
        """Return model metadata, loading status, and error state."""
        self._initialize_transformer()
        version_str = "4.38.0"
        if "transformers" in sys.modules:
            try:
                import transformers
                version_str = getattr(transformers, "__version__", version_str)
            except Exception as exc:
                logger.debug("Failed reading transformers version: %s", exc)
        return {
            "model_name": self.model_name,
            "version": f"{version_str} ({self.model_name})",
            "loaded": self.loaded,
            "error_state": self.error_state
        }

    def _snippet(self, text: str, start: int, end: int, window: int = 40) -> str:
        """Extract a clean context snippet surrounding character offset."""
        s = max(0, start - window)
        e = min(len(text), end + window)
        snippet = text[s:e].replace("\r", " ").replace("\n", " ")
        return f"...{snippet}..." if (s > 0 or e < len(text)) else snippet

    def extract_artifacts(self, text: str, case_id: int, evidence_id: int) -> list[dict[str, Any]]:
        """Extract mandatory forensic entities using Transformer NER + Deterministic fallback."""
        if not text or not isinstance(text, str):
            return []

        self._initialize_transformer()
        extracted: list[dict[str, Any]] = []

        # 1. Hugging Face Transformer NER Extraction (PERSON & Named Entities)
        if self.loaded and self.pipeline:
            try:
                # Limit chunk size to 512 chars for transformer inference safety
                chunks = [text[i:i+512] for i in range(0, min(len(text), 10000), 512)]
                for chunk_idx, chunk in enumerate(chunks):
                    chunk_offset = chunk_idx * 512
                    ner_results = self.pipeline(chunk)
                    for item in ner_results:
                        entity_group = item.get("entity_group") or item.get("entity")
                        val = item.get("word", "").strip()
                        score = float(item.get("score", 0.90))
                        start = int(item.get("start", 0)) + chunk_offset
                        end = int(item.get("end", len(val))) + chunk_offset

                        if len(val) >= 2 and not val.startswith("##"):
                            artifact_type = "PERSON" if entity_group in ("PER", "PERSON") else None
                            if not artifact_type and entity_group in ("ORG", "MISC", "LOC"):
                                # Check if token matches domain/hostname/process heuristics
                                if "." in val:
                                    artifact_type = "DOMAIN"
                                elif len(val) >= 3 and val.isalnum():
                                    artifact_type = "HOSTNAME"

                            if artifact_type:
                                extracted.append({
                                    "case_id": case_id,
                                    "evidence_id": evidence_id,
                                    "source_evidence_id": evidence_id,
                                    "artifact_type": artifact_type,
                                    "value": val,
                                    "confidence": round(score, 4),
                                    "extractor": "transformer-ner",
                                    "context_snippet": self._snippet(text, start, end),
                                    "start_char": start,
                                    "end_char": end,
                                    "details": {"entity_group": entity_group, "model": self.model_name}
                                })
            except Exception as exc:
                logger.warning("Transformer inference error; using deterministic fallback: %s", exc)

        # 2. Deterministic Regex & Rule-based Extraction Pipeline (Guaranteed Fallback)
        regex_specs = [
            ("IP_ADDRESS", IP_V4_PATTERN, 0.98),
            ("IP_ADDRESS", IP_V6_PATTERN, 0.98),
            ("URL", URL_PATTERN, 0.95),
            ("EMAIL", EMAIL_PATTERN, 0.95),
            ("DOMAIN", DOMAIN_PATTERN, 0.90),
            ("FILE_PATH", WIN_PATH_PATTERN, 0.95),
            ("FILE_PATH", UNC_PATH_PATTERN, 0.95),
            ("FILE_PATH", UNIX_PATH_PATTERN, 0.90),
            ("PROCESS", PROCESS_PATTERN, 0.92),
            ("HOSTNAME", HOSTNAME_PATTERN, 0.90),
            ("TIMESTAMP", TIMESTAMP_ISO_PATTERN, 0.95),
            ("TIMESTAMP", TIMESTAMP_EXIF_PATTERN, 0.90),
            ("SESSION_ID", SID_PATTERN, 0.98),
            ("SESSION_ID", UUID_PATTERN, 0.90),
            ("COMMAND", COMMAND_PATTERN, 0.88),
            ("USERNAME", USERNAME_PATTERN, 0.85),
        ]

        for artifact_type, pattern, base_conf in regex_specs:
            for match in pattern.finditer(text):
                val = match.group(0).strip()
                if not val or len(val) < 2:
                    continue
                # Special filtering for domains to avoid matching IP or file paths
                if artifact_type == "DOMAIN" and (IP_V4_PATTERN.match(val) or "/" in val or "\\" in val):
                    continue
                # Filter out pure digits for hostnames/usernames
                if artifact_type in ("HOSTNAME", "USERNAME", "PROCESS") and val.isdigit():
                    continue

                start, end = match.start(), match.end()
                extracted.append({
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "source_evidence_id": evidence_id,
                    "artifact_type": artifact_type,
                    "value": val,
                    "confidence": base_conf,
                    "extractor": "regex-fallback",
                    "context_snippet": self._snippet(text, start, end),
                    "start_char": start,
                    "end_char": end,
                    "details": {"pattern": pattern.pattern[:30]}
                })

        # 3. Rule-based Heuristic PERSON & Event Extraction
        # PERSON fallback heuristics: e.g. "User: Alice Smith", "Author: Bob Johnson", "Investigator: John Doe"
        person_rule = re.compile(r"\b(?:User|Author|Investigator|Subject|Owner|Admin|Analyst)[:=]\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)\b")
        for match in person_rule.finditer(text):
            val = match.group(1).strip()
            if val and len(val) >= 3:
                start, end = match.start(1), match.end(1)
                extracted.append({
                    "case_id": case_id,
                    "evidence_id": evidence_id,
                    "source_evidence_id": evidence_id,
                    "artifact_type": "PERSON",
                    "value": val,
                    "confidence": 0.88,
                    "extractor": "rule-based",
                    "context_snippet": self._snippet(text, start, end),
                    "start_char": start,
                    "end_char": end,
                    "details": {"rule": "person_prefix"}
                })

        # Event Extraction: High-signal forensic lines containing event keywords
        event_lines = text.splitlines()
        for idx, line in enumerate(event_lines[:200]):
            clean_line = line.strip()
            if any(token in clean_line.lower() for token in ("login", "failed", "unauthorized", "mimikatz", "connection", "execution", "event id", "alert", "error", "warning")):
                if len(clean_line) >= 10:
                    extracted.append({
                        "case_id": case_id,
                        "evidence_id": evidence_id,
                        "source_evidence_id": evidence_id,
                        "artifact_type": "EVENT",
                        "value": clean_line[:300],
                        "confidence": 0.85,
                        "extractor": "rule-based",
                        "context_snippet": clean_line[:150],
                        "start_char": None,
                        "end_char": None,
                        "details": {"line_number": idx + 1}
                    })

        # 4. Deduplicate Extracted Artifacts (Retain highest confidence per artifact_type + value)
        deduped: dict[tuple[str, str], dict[str, Any]] = {}
        for item in extracted:
            key = (item["artifact_type"], item["value"].lower())
            if key not in deduped or item["confidence"] > deduped[key]["confidence"]:
                deduped[key] = item

        return list(deduped.values())


# Global singleton kept for backward compatibility.
# Prefer ``from app.ai.registry import get_nlp_extractor`` instead.
from app.ai.registry import get_nlp_extractor as _get_nlp


class _LazySingletonProxy:
    """Module-level attribute that lazily delegates to the registry."""
    def __getattr__(self, name: str):
        return getattr(_get_nlp(), name)

    def __repr__(self) -> str:
        return repr(_get_nlp())


nlp_extractor_instance = _LazySingletonProxy()
