"""Family / threat-actor attribution — the single home for attribution logic.

Two concerns live here:

1. ``build_family_attribution`` — the build-phase step that constructs
   ``FamilyAttribution`` from what the judge decided, falling back to the
   sandbox's own ``cti.family[]``. It vetoes nothing: a family the judge could
   not cite evidence for is kept and flagged unverified, because a name with a
   caveat is more useful than a name silently zeroed. Called by
   ``MalwareReportBuilder.build_deterministic``.
2. ``populate_similar_samples`` — the post-hoc *enrichment* step that fills
   ``attribution.similar_samples`` from the Qdrant LTM store.

The Qdrant-backed long-term memory holds every previously analysed sample as a
:class:`maljan.memory.long_term_memory.StoredCase`; the enrichment step wires
that store in so the comprehensive report carries a "you have seen this before"
panel — the top-k nearest neighbours by behavioural similarity.

Design notes:

- ``populate_similar_samples`` operates on the **dict** projection of
  ``MalwareReport`` (the same shape stored in the JSONB column). That matches
  the rest of the enrichment package, keeps the function trivially testable with
  fixtures, and avoids pulling Pydantic into the hot path. ``build_family_attribution``
  instead returns a typed ``FamilyAttribution`` because it runs during the
  deterministic build where the Pydantic model is assembled.
- ``populate_similar_samples`` is **idempotent**: if ``attribution.similar_samples``
  already holds entries, we leave them alone. The current sample's own
  ``sha256`` is filtered out of the results — Qdrant always returns the
  sample itself first when re-running an analysis.
- All enrichment failures degrade to ``None`` / no-op with a single warning log —
  the enrichment task must never raise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.reporting.models import FamilyAttribution

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore


def _extract_sandbox_family(sandbox_report: dict[str, Any] | None) -> str | None:
    """Return a real malware family name from sandbox CTI, or ``None``.

    Only ``cti.family[]`` entries count — a behavioural category is never a
    family. The first non-empty string wins.
    """
    cti = (sandbox_report or {}).get("cti") or {}
    fams = cti.get("family") if isinstance(cti, dict) else None
    if isinstance(fams, list):
        for f in fams:
            if isinstance(f, str) and f.strip():
                return f.strip()
    return None


def build_family_attribution(
    *,
    judge_family: Any | None,
    sandbox_report: dict[str, Any] | None,
) -> FamilyAttribution:
    """Construct ``FamilyAttribution`` from the judge's answer, or the sandbox's.

    The judge's ``family`` wins when it named one, because the judge read the
    evidence and this function did not. The sandbox's ``cti.family[]`` is the
    fallback for a run where the judge abstained — a real detonation naming a
    family is a fact, and the behavioural *category* is not a family and is
    never echoed here.

    ``grounded`` is now descriptive rather than a veto: a family the judge could
    not cite evidence ids for is kept, flagged, and printed as unverified. The
    previous guardrail deleted the confidence of any family no deterministic
    layer had already named, which meant the judge's own reading of the sample
    could never produce an attribution at all.
    """
    name = str(getattr(judge_family, "name", "") or "").strip()
    if name:
        evidence_ids = list(getattr(judge_family, "evidence_ids", None) or [])
        confidence = float(getattr(judge_family, "confidence", 0.0) or 0.0)
        if not evidence_ids:
            logger.info(
                "Attribution: the judge named family=%r without citing evidence ids; "
                "it is kept and flagged unverified.",
                name,
            )
        return FamilyAttribution(
            family=name,
            family_confidence=max(0.0, min(1.0, confidence)),
            family_grounded=bool(evidence_ids),
        )

    sandbox_family = _extract_sandbox_family(sandbox_report)
    return FamilyAttribution(
        family=sandbox_family,
        family_confidence=0.0,
        family_grounded=True,
    )


def populate_similar_samples(
    malware_report: dict[str, Any],
    store: MemoryStore | None,
    *,
    top_k: int = 5,
) -> dict[str, Any]:
    """Fill ``attribution.similar_samples`` with the top-k Qdrant neighbours.

    Mutates and returns the dict for symmetry with the rest of the
    enrichment pipeline. No-ops in three cases:

    1. ``store`` is ``None`` (Qdrant unavailable / not configured).
    2. The report already carries ``similar_samples``.
    3. We cannot build a non-empty search query from the report.
    """
    if store is None:
        return malware_report

    attribution = malware_report.setdefault("attribution", {})
    if attribution.get("similar_samples"):
        return malware_report

    query = _build_query(malware_report)
    if not query.strip():
        return malware_report

    own_sha256 = (malware_report.get("identity") or {}).get("hashes", {}).get("sha256")

    try:
        # +1 so we can drop the sample's own entry without falling short of top_k.
        hits = store.retrieve(query, top_k=top_k + 1)
    except Exception as exc:  # noqa: BLE001
        logger.warning("attribution: store.retrieve failed (%s).", exc)
        return malware_report

    similars: list[dict[str, Any]] = []
    for case in hits:
        if own_sha256 and case.sample_id == own_sha256:
            continue
        similars.append(
            {
                "sample_id": case.sample_id,
                "malware_category": case.malware_category,
                "technique_ids": list(case.technique_ids),
                "summary": _trim(case.summary_text, 240),
                "source": "maljan-ltm",
            }
        )
        if len(similars) >= top_k:
            break

    attribution["similar_samples"] = similars
    logger.info(
        "attribution: similar_samples populated (count=%d, query_chars=%d).",
        len(similars),
        len(query),
    )
    return malware_report


def _build_query(malware_report: dict[str, Any]) -> str:
    """Construct a semantic query string from the report.

    We deliberately concatenate human-readable signals (category, TTP names,
    suspicious indicators) instead of the sha256 — Qdrant's embedding model
    cannot reason about hash strings, but it can about behaviour.
    """
    parts: list[str] = []

    category = malware_report.get("malware_category")
    if isinstance(category, str) and category:
        parts.append(f"Category: {category}")

    attribution = malware_report.get("attribution") or {}
    family = attribution.get("family")
    if isinstance(family, str) and family:
        parts.append(f"Family: {family}")

    ttps = malware_report.get("ttp_mappings") or []
    technique_terms: list[str] = []
    for ttp in ttps[:10]:
        if not isinstance(ttp, dict):
            continue
        tid = ttp.get("technique_id")
        tname = ttp.get("technique_name")
        if isinstance(tid, str) and isinstance(tname, str):
            technique_terms.append(f"{tid} {tname}")
    if technique_terms:
        parts.append("Techniques: " + ", ".join(technique_terms))

    dynamic = malware_report.get("dynamic") or {}
    sigs = dynamic.get("sandbox_signatures") or []
    sig_names: list[str] = []
    for s in sigs[:5]:
        if not isinstance(s, dict):
            continue
        name = s.get("name")
        if isinstance(name, str) and name:
            sig_names.append(name)
    if sig_names:
        parts.append("Signatures: " + ", ".join(sig_names))

    # Suspicious network infrastructure: links samples that share C2 even when
    # behaviour differs. Prefer suspicious entries; cap to keep the query tight.
    network = malware_report.get("network") or {}
    iocs: list[str] = []
    for dom in (network.get("domains") or [])[:20]:
        if isinstance(dom, dict) and dom.get("is_suspicious") and isinstance(dom.get("fqdn"), str):
            iocs.append(dom["fqdn"])
    for ip in (network.get("ips") or [])[:20]:
        if isinstance(ip, dict) and ip.get("is_suspicious") and isinstance(ip.get("address"), str):
            iocs.append(ip["address"])
    if iocs:
        parts.append("Infrastructure: " + ", ".join(iocs[:8]))

    return ". ".join(parts)


def _trim(value: str, max_len: int) -> str:
    if not isinstance(value, str):
        return ""
    return value if len(value) <= max_len else value[: max_len - 1] + "…"
