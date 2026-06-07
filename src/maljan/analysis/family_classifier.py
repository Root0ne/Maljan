"""Static-feature malware-family classifier: a deterministic family prior.

Companion to :mod:`maljan.analysis.function_hash_attribution` — the same shape
of "deterministic family-prior producer", but generalising to *unseen* samples.
Where function-hash attribution needs an exact opcode-hash already in the corpus
(cold-start: "no known-family overlap"), this module predicts a family from PE
**static features** (the EMBER feature vector: byte/entropy histograms, PE header,
imports, sections, strings) via an offline-trained gradient-boosted model. That
fills the static-only gap: in ``SANDBOX__BACKEND=mock`` mode there is no Triage
CTI / sandbox signature to name a family, yet a decompile already exposes every
feature the classifier needs.

Granularity note: the prediction is a *specific family* (e.g. "AsyncRAT"), which
is a different axis from the report's top-level ``malware_category`` field (a
*category* like "dropper"/"rat"). So this is recorded as its own
``FamilyAttribution.classifier_matches`` block — a sibling of
``function_hash_matches`` — NOT a replacement for the category grounding. Its
runtime value is twofold: (1) an analyst PRIOR hint that focuses the ReAct loop,
and (2) a recorded specific-family hypothesis with a confidence the report/UI can
surface even when the category path abstains.

Feature parity is the one real risk: the model is only valid on the exact feature
schema it was trained on. This module and ``scripts/train_family_classifier.py``
therefore share a single feature definition — EMBER's ``PEFeatureExtractor`` — so
training-time and inference-time vectors are identical by construction.

Everything here is FAIL-SAFE and OPTIONAL: heavy deps (numpy / ember / joblib /
the model's estimator lib) are imported lazily; if any is missing, or the model
file is absent, or the binary is unreadable, the public surface degrades to
"no prediction" (``load_classifier`` -> ``None``; ``predict`` -> ``[]``) and the
analysis proceeds exactly as before. The feature is gated OFF by default
(``PreprocessingConfig.use_static_feature_classifier``).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from maljan.core.logger import logger

# Process-level model cache: loading a gradient-boosted model + feature extractor
# is expensive, and the model is immutable, so load once per path per process.
# Mirrors the "construct once" intent of the container singletons without making
# the (container-unaware) static analyst hold a container reference — consistent
# with how function_hash_attribution is driven from config + module functions.
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, FamilyClassifier | None] = {}


@dataclass(frozen=True)
class FamilyPrediction:
    """One predicted family with its model confidence."""

    family: str
    confidence: float


class FamilyClassifier:
    """Loaded offline model + EMBER feature extractor. Construct via ``load_classifier``."""

    def __init__(self, estimator: Any, families: list[str], *, model_path: str) -> None:
        self._estimator = estimator
        self._families = families
        self._model_path = model_path

    def predict(self, file_path: str, *, top_k: int, threshold: float) -> list[FamilyPrediction]:
        """Return up to ``top_k`` families with confidence >= ``threshold``.

        Fail-safe: any error (unreadable binary, missing ember/numpy, estimator
        mismatch) yields ``[]`` so the caller proceeds without a prior.
        """
        try:
            vec = _extract_features(file_path)
            if vec is None:
                return []
            import numpy as np

            proba = self._estimator.predict_proba(vec.reshape(1, -1))[0]
            classes = list(getattr(self._estimator, "classes_", self._families))
            order = np.argsort(proba)[::-1]
            out: list[FamilyPrediction] = []
            for idx in order[: max(top_k, 0)]:
                conf = float(proba[int(idx)])
                if conf < threshold:
                    break  # sorted descending — nothing below will pass either
                out.append(
                    FamilyPrediction(family=str(classes[int(idx)]), confidence=round(conf, 3))
                )
            return out
        except Exception as exc:  # fail-safe: never break analysis over a prior
            logger.warning(
                "family-classifier predict failed (%s: %s); continuing without prior.",
                type(exc).__name__,
                exc,
            )
            return []


def _extract_features(file_path: str) -> Any | None:
    """EMBER PE feature vector for ``file_path`` (None when unavailable).

    Uses EMBER's ``PEFeatureExtractor`` — the SAME extractor the training script
    uses — so inference and training vectors match by construction. Lazy-imports
    ember/numpy; returns None (not raising) when they are absent or the bytes
    cannot be parsed.
    """
    try:
        import numpy as np
        from ember import PEFeatureExtractor
    except ImportError:
        logger.debug("family-classifier: ember/numpy not installed — no features.")
        return None
    try:
        raw = Path(file_path).read_bytes()
    except OSError as exc:
        logger.debug("family-classifier: cannot read '%s' (%s).", file_path, exc)
        return None
    try:
        extractor = PEFeatureExtractor(print_feature_warning=False)
        return np.array(extractor.feature_vector(raw), dtype=np.float32)
    except Exception as exc:  # noqa: BLE001 - LIEF/ember can raise broadly on odd PEs
        logger.debug("family-classifier: feature extraction failed (%s).", exc)
        return None


def load_classifier(model_path: str) -> FamilyClassifier | None:
    """Load (and cache) the offline-trained classifier, or None if unavailable.

    None is returned — never raised — when the model file is absent or joblib is
    not installed, so callers can treat "no classifier" as the normal disabled
    state. Cached per ``model_path`` for the process lifetime.
    """
    key = str(model_path)
    with _CACHE_LOCK:
        if key in _CACHE:
            return _CACHE[key]
        result = _load_uncached(key)
        _CACHE[key] = result
        return result


def _load_uncached(model_path: str) -> FamilyClassifier | None:
    if not model_path or not Path(model_path).is_file():
        logger.info("family-classifier: model not found at '%s' — classifier disabled.", model_path)
        return None
    try:
        import joblib
    except ImportError:
        logger.info("family-classifier: joblib not installed — classifier disabled.")
        return None
    try:
        artifact = joblib.load(model_path)
    except Exception as exc:  # noqa: BLE001 - corrupt/incompatible artifact
        logger.warning("family-classifier: failed to load '%s' (%s).", model_path, exc)
        return None
    # Artifact contract (see scripts/train_family_classifier.py): either a bare
    # fitted estimator (exposes predict_proba + classes_) or a dict wrapper.
    estimator = artifact.get("estimator") if isinstance(artifact, dict) else artifact
    families = (
        list(artifact.get("families", []))
        if isinstance(artifact, dict)
        else list(getattr(estimator, "classes_", []))
    )
    if estimator is None or not hasattr(estimator, "predict_proba"):
        logger.warning("family-classifier: artifact '%s' has no predict_proba.", model_path)
        return None
    logger.info("family-classifier: loaded '%s' (%d families).", model_path, len(families) or -1)
    return FamilyClassifier(estimator, families, model_path=model_path)


def reset_cache() -> None:
    """Clear the process model cache (test hook; not used at runtime)."""
    with _CACHE_LOCK:
        _CACHE.clear()


# ---------------------------------------------------------------------------
# Pure rendering helpers (no heavy deps — unit-testable on their own)
# ---------------------------------------------------------------------------


def build_classifier_hint(results: list[FamilyPrediction]) -> str:
    """Render the analyst prompt hint, or '' when there is no prediction.

    Mirrors ``function_hash_attribution.build_attribution_hint``: a clearly-labelled
    PRIOR the analyst must corroborate, never an assertion.
    """
    if not results:
        return ""
    lines = [
        "FAMILY PRIOR (static-feature classifier — a learned guess from PE structure "
        "[imports, entropy, header, sections], NOT proof):",
    ]
    for r in results:
        lines.append(f"- family '{r.family}' (prior confidence ~{r.confidence})")
    lines.append(
        "Treat the highest-confidence family as a hypothesis to CONFIRM behaviorally "
        "(imports, call-sites, decompiled logic, strings) before asserting attribution. "
        "Do NOT raise a family CLAIM above this prior confidence on the model score alone.\n"
    )
    return "\n".join(lines)


def to_report_dicts(results: list[FamilyPrediction]) -> list[dict[str, Any]]:
    """Convert predictions into FamilyAttribution.classifier_matches rows."""
    return [
        {
            "family": r.family,
            "confidence": r.confidence,
            "match_method": "static-feature-classifier",
            "source": "maljan-ember-gbdt",
        }
        for r in results
    ]
