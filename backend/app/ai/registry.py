"""Central registry for AI model instances.

Provides lazy-initialized singletons that can be swapped at runtime or
overridden in tests.  Every consumer should call ``get_<model>()`` instead
of creating instances at module level.

Usage in production (automatic — no setup needed)::

    from app.ai.registry import get_threat_classifier
    classifier = get_threat_classifier()

Usage in tests (swap for a mock)::

    from app.ai import registry
    registry.set_threat_classifier(MyFakeClassifier())

The registry is intentionally stateless — it holds references, not copies.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.ai.threat_classifier import ThreatClassifier
    from app.ai.anomaly_detector import LogAnomalyDetector
    from app.ai.nlp_extractor import NLPArtifactExtractor

logger = logging.getLogger(__name__)

# ── Internal storage ────────────────────────────────────────────
_threat_classifier: ThreatClassifier | None = None
_log_detector: LogAnomalyDetector | None = None
_nlp_extractor: NLPArtifactExtractor | None = None


# ── Threat Classifier (PyTorch) ─────────────────────────────────
def get_threat_classifier() -> ThreatClassifier:
    """Return the global :class:`ThreatClassifier`, creating it on first call."""
    global _threat_classifier
    if _threat_classifier is None:
        from app.ai.threat_classifier import ThreatClassifier
        _threat_classifier = ThreatClassifier()
        logger.debug("ThreatClassifier instantiated.")
    return _threat_classifier


def set_threat_classifier(instance: ThreatClassifier) -> None:
    """Override the global threat classifier (for tests or hot-swap)."""
    global _threat_classifier
    _threat_classifier = instance


# ── Log Anomaly Detector (Scikit-learn) ─────────────────────────
def get_log_detector() -> LogAnomalyDetector:
    """Return the global :class:`LogAnomalyDetector`, creating it on first call."""
    global _log_detector
    if _log_detector is None:
        from app.ai.anomaly_detector import LogAnomalyDetector
        _log_detector = LogAnomalyDetector()
        logger.debug("LogAnomalyDetector instantiated.")
    return _log_detector


def set_log_detector(instance: LogAnomalyDetector) -> None:
    """Override the global log anomaly detector (for tests or hot-swap)."""
    global _log_detector
    _log_detector = instance


# ── NLP Artifact Extractor (HuggingFace) ────────────────────────
def get_nlp_extractor() -> NLPArtifactExtractor:
    """Return the global :class:`NLPArtifactExtractor`, creating it on first call."""
    global _nlp_extractor
    if _nlp_extractor is None:
        from app.ai.nlp_extractor import NLPArtifactExtractor
        _nlp_extractor = NLPArtifactExtractor()
        logger.debug("NLPArtifactExtractor instantiated.")
    return _nlp_extractor


def set_nlp_extractor(instance: NLPArtifactExtractor) -> None:
    """Override the global NLP extractor (for tests or hot-swap)."""
    global _nlp_extractor
    _nlp_extractor = instance


def reset_all() -> None:
    """Reset all singletons to ``None`` (useful in test teardown)."""
    global _threat_classifier, _log_detector, _nlp_extractor
    _threat_classifier = None
    _log_detector = None
    _nlp_extractor = None
