"""Populate ``MalwareReport.attribution.similar_samples`` from the LTM store.

The Qdrant-backed long-term memory already holds every previously analysed
sample as a :class:`maljan.memory.long_term_memory.StoredCase`. Phase 9
wires that store into the post-hoc enrichment step so the comprehensive
report carries a "you have seen this before" panel — the top-k nearest
neighbours by behavioural similarity.

Design notes:

- This module operates on the **dict** projection of ``MalwareReport``
  (the same shape stored in the JSONB column). That matches the rest of
  the enrichment package, keeps the function trivially testable with
  fixtures, and avoids pulling Pydantic into the hot path.
- The function is **idempotent**: if ``attribution.similar_samples``
  already holds entries, we leave them alone. The current sample's own
  ``sha256`` is filtered out of the results — Qdrant always returns the
  sample itself first when re-running an analysis.
- All failures degrade to ``None`` / no-op with a single warning log —
  the enrichment task must never raise.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore


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
