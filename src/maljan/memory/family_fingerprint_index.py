"""In-memory semantic index over malware-family static-feature fingerprints.

The LLM-centric half of the family-feature RAG (findings-log §4 U3). An offline
builder (``scripts/build_family_feature_kb.py``) distils a reference dataset
(MABEL and/or a folder-per-family raw-binary corpus) into one short *fingerprint
description* per family — a natural-language summary of that family's typical
static-feature profile (dominant import capabilities, packer, entropy/section
traits). This module loads that vendored catalog and, at analysis time, retrieves
the families whose fingerprint is most similar to the current sample's profile.

The retrieved families are handed to the static analyst **as candidate evidence**;
the LLM decides the attribution. Nothing here predicts a family — it only surfaces
candidates (the same role YARA / sink-reachability / the ATT&CK index already play).

Parity by construction: the catalog stores fingerprint **text**, not vectors, and
this index embeds it at load with the SAME ``embeddings.encode_batch`` the runtime
query uses — so query and catalog always live in one embedding space (mirrors
``SemanticATTCKIndex``, which also embeds at load rather than vendoring vectors).

Fail-safe + OFF by default: a missing catalog yields ``None`` (no candidates), and
the feature is gated behind ``PreprocessingConfig.use_family_feature_rag``.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from pathlib import Path

from maljan.core.logger import logger
from maljan.memory import embeddings

# Process-level cache: one index per catalog path (embedding the catalog is the
# expensive part). Mirrors the function-hash / function-index "build once" intent.
_CACHE_LOCK = threading.Lock()
_CACHE: dict[str, FamilyFingerprintIndex | None] = {}


@dataclass(frozen=True)
class FamilyCandidate:
    """One retrieved family fingerprint with its similarity to the sample."""

    family: str
    score: float
    malware_category: str
    sample_count: int


class FamilyFingerprintIndex:
    """In-memory cosine index over family fingerprint descriptions."""

    def __init__(self) -> None:
        # (family_id, malware_category, sample_count, L2-normalized embedding)
        self._entries: list[tuple[str, str, int, list[float]]] = []

    @classmethod
    def from_records(cls, families: list[dict]) -> FamilyFingerprintIndex:
        """Embed each family's fingerprint ``description`` once (batch)."""
        idx = cls()
        rows = [
            f for f in families if isinstance(f, dict) and str(f.get("description", "")).strip()
        ]
        if not rows:
            return idx
        vectors = embeddings.encode_batch([str(f["description"]) for f in rows])
        idx._entries = [
            (
                str(f.get("family_id", "")),
                str(f.get("malware_category", "") or ""),
                int(f.get("sample_count", 0) or 0),
                vec,
            )
            for f, vec in zip(rows, vectors, strict=True)
        ]
        return idx

    def __len__(self) -> int:
        return len(self._entries)

    def search(self, profile_text: str, top_k: int, min_score: float) -> list[FamilyCandidate]:
        """Return up to ``top_k`` families with cosine >= ``min_score``, best first."""
        if not self._entries or not profile_text.strip():
            return []
        qv = embeddings.encode(profile_text)
        scored = [
            FamilyCandidate(fam, embeddings.cosine(qv, vec), cat, n)
            for fam, cat, n, vec in self._entries
        ]
        scored = [c for c in scored if c.score >= min_score]
        scored.sort(key=lambda c: c.score, reverse=True)
        return scored[: max(top_k, 0)]


def load_family_index(catalog_path: str) -> FamilyFingerprintIndex | None:
    """Load (and cache) the vendored family-fingerprint catalog, or None.

    None — never raised — when the catalog file is absent or malformed, so callers
    treat "no catalog" as the normal disabled state. Cached per path for the
    process lifetime.
    """
    key = str(catalog_path)
    with _CACHE_LOCK:
        if key in _CACHE:
            return _CACHE[key]
        result = _load_uncached(key)
        _CACHE[key] = result
        return result


def _load_uncached(catalog_path: str) -> FamilyFingerprintIndex | None:
    if not catalog_path or not Path(catalog_path).is_file():
        logger.info(
            "family-RAG: fingerprint catalog not found at '%s' — RAG disabled.", catalog_path
        )
        return None
    try:
        doc = json.loads(Path(catalog_path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        logger.warning("family-RAG: failed to read catalog '%s' (%s).", catalog_path, exc)
        return None
    families = doc.get("families") if isinstance(doc, dict) else None
    if not isinstance(families, list) or not families:
        logger.warning("family-RAG: catalog '%s' has no 'families' — RAG disabled.", catalog_path)
        return None
    index = FamilyFingerprintIndex.from_records(families)
    logger.info("family-RAG: loaded %d family fingerprints from '%s'.", len(index), catalog_path)
    return index if len(index) else None


def reset_cache() -> None:
    """Clear the process catalog cache (test hook; not used at runtime)."""
    with _CACHE_LOCK:
        _CACHE.clear()
