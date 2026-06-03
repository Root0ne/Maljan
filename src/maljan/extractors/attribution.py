"""Family / threat-actor attribution — the single home for attribution logic.

Two concerns live here:

1. ``build_family_attribution`` — the deterministic *build-phase* step that
   constructs ``FamilyAttribution`` from the inferred family plus the D11
   grounding guardrail (a family is only assigned confidence when some
   deterministic layer corroborates it). Called by ``MalwareReportBuilder.
   build_deterministic`` alongside the other ``build_*`` extractors.
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


def _is_family_grounded(
    family: str | None,
    sandbox_report: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
) -> bool:
    """Return True when ``family`` is corroborated by deterministic evidence.

    D11 fix: in the 2026-05-23 E2E run the judge fallback path emitted
    ``attribution.family = "rat"`` despite Triage returning an empty
    ``families[]`` and no analyst claim ever naming the family. The previous
    builder copied the value through unconditionally with the global
    ``overall_confidence`` as ``family_confidence`` — UI consumers had no way to
    tell which family assertions had grounding.

    Grounding sources (any one is enough):
    - Triage CTI ``family[]`` list contains the candidate (case insensitive
      substring match — Triage often emits multi-token entries like
      ``"trojan/rat"``).
    - Triage ``signatures[].name`` mentions the family literally.
    - Any ISR claim's ``claim``, ``evidence_ref``, or ``technique_id`` text
      contains the family name.

    Returns ``True`` for an empty family input so callers that pass ``None`` get
    the legacy "no claim made" default and don't trip the guardrail on samples
    that simply have no family hypothesis.
    """
    if not family:
        return True
    needle = family.strip().lower()
    if not needle:
        return True

    # Triage CTI block (synthesised by TriageClient._synthesize_cti)
    cti = (sandbox_report or {}).get("cti") or {}
    if isinstance(cti.get("family"), list):
        for f in cti["family"]:
            if isinstance(f, str) and needle in f.lower():
                return True

    # Triage / CAPE sandbox signatures
    sigs = (sandbox_report or {}).get("signatures") or []
    for sig in sigs:
        if not isinstance(sig, dict):
            continue
        name = str(sig.get("name") or "").lower()
        desc = str(sig.get("description") or "").lower()
        if needle in name or needle in desc:
            return True

    # ISR claims (analyst / yara_layer / sigma_layer)
    for isr in (isr_reports or {}).values():
        for claim in getattr(isr, "claims", []) or []:
            _ctext = " ".join(
                (
                    str(getattr(claim, "claim", "") or ""),
                    str(getattr(claim, "evidence_ref", "") or ""),
                    str(getattr(claim, "technique_id", "") or ""),
                )
            ).lower()
            if needle in _ctext:
                return True

    return False


def build_family_attribution(
    *,
    malware_category: str | None,
    sandbox_report: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
    overall_confidence: float,
) -> FamilyAttribution:
    """Construct ``FamilyAttribution`` with the D11 grounding guardrail.

    ``family_confidence`` is the run's ``overall_confidence`` only when the
    family is corroborated by a deterministic layer; otherwise it is forced to
    ``0.0`` so ungrounded (often hallucinated) family strings cannot inherit the
    verdict confidence. ``similar_samples`` / ``function_hash_matches`` are left
    at their defaults here and filled later by the enrichment / report nodes.
    """
    family = malware_category if malware_category else None
    grounded = _is_family_grounded(family, sandbox_report, isr_reports)
    if family and not grounded:
        logger.info(
            "Attribution guardrail: family=%r marked as ungrounded — no "
            "Triage CTI / sandbox sig / ISR claim corroborates it. "
            "family_confidence forced to 0.0.",
            family,
        )
    return FamilyAttribution(
        family=family,
        family_confidence=(overall_confidence if grounded else 0.0),
        family_grounded=grounded if family else True,
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
