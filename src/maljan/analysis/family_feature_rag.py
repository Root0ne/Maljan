"""Family-feature RAG orchestration: profile a sample, retrieve candidate families.

The LLM-centric replacement for the (removed) trained family classifier. Flow:

    sample binary
      -> deterministic static-feature PROFILE  (build_sample_profile_text)
      -> retrieve nearest family fingerprints   (FamilyFingerprintIndex.search)
      -> render a CANDIDATE-FAMILIES hint        (build_rag_hint)
      -> the static analyst LLM decides the attribution.

No model is trained and nothing here asserts a family — retrieval only surfaces
candidates as evidence, exactly like the YARA / sink-reachability / ATT&CK-index
tools. ``build_sample_profile_text`` is shared with the offline catalog builder
(``scripts/build_family_feature_kb.py``) so the query and the family fingerprints
are rendered in one vocabulary (embedding parity).

Everything is fail-safe: a missing catalog or an unreadable binary yields no
candidates and the analysis proceeds unchanged. Gated OFF by default
(``PreprocessingConfig.use_family_feature_rag``).
"""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.memory.family_fingerprint_index import FamilyCandidate, FamilyFingerprintIndex
    from maljan.reporting.models import StaticAnalysis

# Entropy at/above which a PE/ELF section is treated as packed/encrypted. Matches
# pe_extractor._HIGH_ENTROPY_THRESHOLD; duplicated as a module constant so the
# profile renderer has no import-time dependency on the extractor internals.
_HIGH_ENTROPY = 7.0
# Cap list lengths so the rendered profile stays a tight embedding query.
_MAX_IMPORTS = 12
_MAX_SECTIONS = 6


def build_sample_profile_text(static: StaticAnalysis) -> str:
    """Render a deterministic NL static-feature profile (the RAG query / fingerprint).

    Shared by the runtime query path and the offline catalog builder so both sides
    speak the same vocabulary. Summarises the signals that distinguish families:
    import-capability mix, characteristic suspicious imports, packer, and
    high-entropy sections. Returns '' when there is nothing to say.
    """
    parts: list[str] = []

    # Import-capability histogram (the 10 _SUSPICIOUS_IMPORTS groups).
    cap_counts = Counter(imp.category for imp in static.imports if getattr(imp, "category", None))
    if cap_counts:
        caps = ", ".join(f"{cat} x{n}" for cat, n in cap_counts.most_common())
        parts.append(f"capabilities: {caps}")

    # Characteristic suspicious imports (the API names themselves carry signal).
    sus_funcs = [imp.function for imp in static.imports if getattr(imp, "is_suspicious", False)]
    if sus_funcs:
        # Stable, de-duplicated, capped.
        seen: list[str] = []
        for fn in sus_funcs:
            if fn and fn not in seen:
                seen.append(fn)
        parts.append("suspicious imports: " + ", ".join(seen[:_MAX_IMPORTS]))

    # Packer / obfuscation.
    if static.packer_hint:
        parts.append(f"packer: {static.packer_hint}")
    if static.obfuscation_indicators:
        parts.append("obfuscation: " + ", ".join(static.obfuscation_indicators[:6]))

    # High-entropy / suspicious sections.
    hot = [
        f"{s.name}~{s.entropy:.1f}"
        for s in static.sections
        if getattr(s, "is_suspicious", False) or s.entropy >= _HIGH_ENTROPY
    ]
    if hot:
        parts.append("high-entropy sections: " + ", ".join(hot[:_MAX_SECTIONS]))

    return "; ".join(parts)


def build_family_fingerprint_text(profiles: list[str]) -> str:
    """Aggregate many per-sample profiles into one family fingerprint description.

    Offline only (catalog build). Pools the per-sample profile texts and keeps the
    most frequent capability/import/packer/section tokens, re-rendered in the same
    vocabulary ``build_sample_profile_text`` emits so family fingerprints and
    sample queries embed into the same space.
    """
    if not profiles:
        return ""
    # Token-frequency over the rendered profiles is a cheap, deterministic way to
    # surface a family's *typical* signals; we keep the rendered text itself (the
    # union of common phrases) rather than re-parsing structure.
    phrase_counts: Counter[str] = Counter()
    for prof in profiles:
        for seg in prof.split(";"):
            for token in seg.split(","):
                t = token.strip()
                if t:
                    phrase_counts[t] += 1
    if not phrase_counts:
        return ""
    # Keep phrases seen in a meaningful share of the family's samples (>=2 or 20%).
    floor = max(2, len(profiles) // 5)
    common = [p for p, n in phrase_counts.most_common() if n >= floor]
    if not common:  # small family — fall back to the most frequent few
        common = [p for p, _ in phrase_counts.most_common(12)]
    return "; ".join(common[:24])


def retrieve_candidates(
    profile_text: str,
    index: FamilyFingerprintIndex | None,
    *,
    top_k: int,
    min_score: float,
) -> list[FamilyCandidate]:
    """Retrieve nearest family candidates for a sample profile (fail-safe -> [])."""
    if index is None or not profile_text.strip():
        return []
    try:
        return index.search(profile_text, top_k=top_k, min_score=min_score)
    except Exception as exc:  # noqa: BLE001 - retrieval must never break analysis
        logger.warning("family-RAG: retrieval failed (%s: %s).", type(exc).__name__, exc)
        return []


def build_rag_hint(candidates: list[FamilyCandidate]) -> str:
    """Render the analyst prompt hint, or '' when nothing was retrieved.

    Frames the retrieved families as CANDIDATES to corroborate — never an
    assertion (mirrors function_hash_attribution.build_attribution_hint).
    """
    if not candidates:
        return ""
    lines = [
        "CANDIDATE FAMILIES (retrieved by static-feature similarity to known families "
        "— evidence to weigh, NOT a verdict):",
    ]
    for c in candidates:
        cat = f", category {c.malware_category}" if c.malware_category else ""
        lines.append(f"- {c.family} (similarity ~{c.score:.2f}{cat})")
    lines.append(
        "Decide attribution yourself: confirm a candidate ONLY if the decompiled logic, "
        "imports, strings, and behaviour support it; reject all candidates if they do not. "
        "Do NOT assert a family on retrieval similarity alone.\n"
    )
    return "\n".join(lines)


def to_report_dicts(candidates: list[FamilyCandidate]) -> list[dict[str, Any]]:
    """Convert candidates into FamilyAttribution.family_rag_candidates rows."""
    return [
        {
            "family": c.family,
            "similarity": round(c.score, 3),
            "malware_category": c.malware_category,
            "sample_count": c.sample_count,
            "match_method": "family-feature-rag",
            "source": "maljan-family-fingerprints",
        }
        for c in candidates
    ]
