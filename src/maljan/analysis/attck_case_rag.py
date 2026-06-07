"""ATT&CK case-prior RAG orchestration: surface recurring TTPs from prior cases.

The cross-sample knowledge half of the function-level RAG (findings-log §4 U2). Flow:

    sample binary
      -> deterministic static-feature PROFILE  (build_sample_profile_text, shared with U3)
      -> retrieve behaviourally-similar prior LTM cases (AttckCaseIndex.search)
      -> aggregate their technique_ids into ranked candidates (recommend_techniques)
      -> render a CANDIDATE-TECHNIQUES hint              (build_attck_case_hint)
      -> the static analyst LLM decides which TTPs apply.

No model is trained and nothing here asserts a technique — retrieval only surfaces
ATT&CK techniques that recur in behaviourally-similar prior malware as evidence, the
same advisory role YARA / sink-reachability / the family-feature RAG already play. The
corpus is mined from our OWN growing long-term memory (Qdrant ``StoredCase``), not an
external dataset.

The query reuses ``family_feature_rag.build_sample_profile_text`` so U2 and U3 speak one
vocabulary. NOTE (honest caveat): the LTM corpus stores *behavioural* ``summary_text``
(claim-derived) while this static-stage query is a *static-feature* profile, so matching
is coarse — which is precisely why the candidates are advisory and the LLM corroborates.
As the corpus grows and a behavioural query becomes available, ``retrieve_techniques``
accepts any query text, so the judge (which has full claim text) can reuse this index.

Everything is fail-safe: a missing corpus or an unreadable binary yields no candidates
and the analysis proceeds unchanged. Gated OFF by default
(``PreprocessingConfig.use_attck_case_rag``).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.memory.attck_case_index import AttckCaseIndex, TechniqueCandidate


def retrieve_techniques(
    query_text: str,
    index: AttckCaseIndex | None,
    *,
    top_k: int,
    min_score: float,
    max_techniques: int,
) -> list[TechniqueCandidate]:
    """Retrieve ranked ATT&CK technique candidates for a query (fail-safe -> [])."""
    if index is None or not query_text.strip():
        return []
    try:
        return index.recommend_techniques(
            query_text,
            top_k=top_k,
            min_score=min_score,
            max_techniques=max_techniques,
        )
    except Exception as exc:  # noqa: BLE001 - retrieval must never break analysis
        logger.warning("attck-case-RAG: retrieval failed (%s: %s).", type(exc).__name__, exc)
        return []


def build_attck_case_hint(candidates: list[TechniqueCandidate]) -> str:
    """Render the analyst prompt hint, or '' when nothing was retrieved.

    Frames the techniques as CANDIDATES recurring in similar prior malware — never an
    assertion (mirrors family_feature_rag.build_rag_hint).
    """
    if not candidates:
        return ""
    lines = [
        "CANDIDATE ATT&CK TECHNIQUES (recurring in behaviourally-similar prior cases "
        "from long-term memory — evidence to weigh, NOT a verdict):",
    ]
    for c in candidates:
        lines.append(
            f"- {c.technique_id} (seen in {c.support} similar case(s), "
            f"best similarity ~{c.score:.2f})"
        )
    lines.append(
        "Decide the TTPs yourself: assign a technique ONLY if the decompiled logic, "
        "imports, strings, and behaviour support it; ignore candidates that do not match. "
        "Do NOT assign a technique on prior-case recurrence alone.\n"
    )
    return "\n".join(lines)


def to_report_dicts(candidates: list[TechniqueCandidate]) -> list[dict[str, Any]]:
    """Convert candidates into FamilyAttribution.attck_case_candidates rows."""
    return [
        {
            "technique_id": c.technique_id,
            "support": c.support,
            "similarity": round(c.score, 3),
            "match_method": "attck-case-rag",
            "source": "maljan-attck-case-corpus",
        }
        for c in candidates
    ]
