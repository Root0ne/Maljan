"""The reference knowledge an analyst consults, as lookups rather than layers.

ATT&CK, the API-behaviour catalog, the LOLBin table and the three vector
indices all existed already; each was wired into exactly one pipeline stage and
reachable from nowhere else. Here they are questions an agent can ask at any
point: is this technique id real, what does this API do, what family does this
profile look like.

Every index is built on first call and kept for the process lifetime — a
sidecar answers many calls and the ATT&CK bundle is fifty megabytes. Anything
that needs Qdrant or an embedding model returns an empty result with a
``reason`` when the dependency is not there. Nothing in this module raises for
a missing backend: a knowledge lookup that cannot answer is a thinner report,
never a failed job.
"""

from __future__ import annotations

import threading
from typing import Any

from maljan.core.logger import logger
from maljan.core.paths import resolve_data

# The catalogs the pipeline ships. Passed as explicit arguments everywhere, so
# an operator with their own catalog hands the tool the path and this module
# never reads ``Settings``.
DEFAULT_API_BEHAVIOUR_MAP = "data/api_behaviour_map_v1.json"
DEFAULT_API_ATTCK_MAP = "data/api_attck_map_v1.json"
DEFAULT_FAMILY_CATALOG = "data/family_fingerprints_v1.json"
DEFAULT_CASE_CORPUS = "data/attck_case_corpus_v1.json"

_INDEX_LOCK = threading.Lock()
_HYBRID_INDEX: Any = None
_HYBRID_FAILED: str = ""
_CATALOG: dict[str, Any] | None = None


def reset_indices() -> None:
    """Drop the warm index and catalog. For tests and for a refresh."""
    global _HYBRID_INDEX, _HYBRID_FAILED, _CATALOG
    with _INDEX_LOCK:
        _HYBRID_INDEX = None
        _HYBRID_FAILED = ""
        _CATALOG = None


def _catalog() -> dict[str, Any]:
    """``{technique_id: ATTCKTechnique}`` across every domain, or ``{}``.

    Deliberately *not* the vector index. Looking up a technique by its id needs
    the catalogue and nothing else, and routing that through the hybrid index
    would load an embedding model — seconds and hundreds of megabytes — to
    answer a dictionary lookup. ``resolve_technique`` is the one function here
    that genuinely ranks, and it is the only one that pays for the index.
    """
    global _CATALOG
    with _INDEX_LOCK:
        if _CATALOG is not None:
            return _CATALOG
    catalog: dict[str, Any] = {}
    try:
        from maljan.memory.attck_loader import load_all_domains

        for data in load_all_domains().values():
            for technique in data.techniques:
                catalog.setdefault(technique.technique_id, technique)
    except Exception as exc:  # noqa: BLE001 — a knowledge lookup degrades, never raises
        logger.warning("knowledge: the ATT&CK catalogue is unavailable (%s).", exc)
    with _INDEX_LOCK:
        _CATALOG = catalog
    return catalog


def _hybrid_index() -> tuple[Any, str]:
    """The hybrid ATT&CK index, or ``(None, reason)`` when it cannot be built.

    A failure is remembered as well as a success: a box that cannot reach MITRE
    would otherwise retry a fifty-megabyte download on every single lookup.
    """
    global _HYBRID_INDEX, _HYBRID_FAILED
    with _INDEX_LOCK:
        if _HYBRID_INDEX is not None:
            return _HYBRID_INDEX, ""
        if _HYBRID_FAILED:
            return None, _HYBRID_FAILED
    try:
        from maljan.memory.hybrid_attck_index import HybridATTCKIndex

        index = HybridATTCKIndex.from_loader()
    except Exception as exc:  # noqa: BLE001 — a knowledge lookup degrades, never raises
        reason = f"the ATT&CK index is unavailable: {type(exc).__name__}: {exc}"
        logger.warning("knowledge: %s", reason)
        with _INDEX_LOCK:
            _HYBRID_FAILED = reason
        return None, reason
    with _INDEX_LOCK:
        _HYBRID_INDEX = index
    return index, ""


# ---------------------------------------------------------------------------
# ATT&CK
# ---------------------------------------------------------------------------


def resolve_technique(text: str, k: int = 5, domain: str | None = None) -> dict[str, Any]:
    """Candidate techniques for a behavioural description, best first.

    Two numbers per candidate, because the two indices are good at different
    things. ``score`` is the semantic ranking, which orders candidates well but
    crowds every value near 0.7 whether the match is right or not. ``score_gate``
    is the TF-IDF alignment, which ranks worse but scores near zero for
    unrelated evidence — so it is the one to threshold on.
    """
    index, reason = _hybrid_index()
    if index is None:
        return {"candidates": [], "reason": reason}
    from maljan.memory.attck_loader import domain_of

    wanted = (domain or "").strip().lower() or None
    # Over-fetch when a domain filter is on: the ranking is domain-blind, so
    # asking for k and then filtering would routinely return fewer than k.
    results = index.search(text, top_k=k * 4 if wanted else k)
    candidates: list[dict[str, Any]] = []
    for result in results:
        tid = result.technique.technique_id
        owner = domain_of(tid)
        if wanted and owner != wanted:
            continue
        candidates.append(
            {
                "technique_id": tid,
                "name": result.technique.name,
                "domain": owner,
                "score": round(float(result.score), 4),
                "score_gate": round(float(index.validate_and_score(tid, text)), 4),
            }
        )
        if len(candidates) >= k:
            break
    return {"candidates": candidates}


def attck_lookup(technique_id: str) -> dict[str, Any]:
    """One technique's catalogue entry, and whether it exists at all."""
    from maljan.memory.attck_loader import domain_of, platforms_for, valid_ids

    tid = (technique_id or "").strip().upper()
    if not tid:
        return {"valid": False, "technique_id": "", "reason": "no technique id given"}
    technique = _catalog().get(tid)
    out: dict[str, Any] = {
        "valid": tid in valid_ids(),
        "technique_id": tid,
        "name": technique.name if technique else "",
        "domain": domain_of(tid),
        "platforms": list(platforms_for(tid)),
        "tactics": list(technique.tactic_phases) if technique else [],
        "url": (technique.url if technique and technique.url else None)
        or f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/",
    }
    if technique is None:
        out["reason"] = "the ATT&CK catalogue has no entry for this id"
    return out


def attck_validate(ids: list[str]) -> dict[str, Any]:
    """Which of the given ids are not real techniques, and what was probably meant.

    Only the invalid ones come back. A validator that echoed every id would
    make the caller diff two lists to find the one that matters.
    """
    from maljan.memory.attck_loader import valid_ids

    known = valid_ids()
    catalog = _catalog()
    invalid: list[dict[str, Any]] = []
    for raw in ids or []:
        tid = str(raw).strip().upper()
        if not tid or tid in known:
            continue
        row: dict[str, Any] = {"id": tid, "suggestions": []}
        # The parent of a bogus sub-technique is the single most likely intent,
        # and it is a string operation rather than a search — a suggestion that
        # cost an embedding model would be worse than no suggestion.
        parent = tid.split(".")[0]
        if parent != tid and parent in known:
            row["suggestions"].append(parent)
        # Then the parent's real sub-techniques, which is where an id like
        # ``T1055.999`` was reaching for.
        row["suggestions"].extend(
            sorted(
                other
                for other in catalog
                if other.startswith(f"{parent}.") and other not in row["suggestions"]
            )[:3]
        )
        if not catalog:
            row["reason"] = "the ATT&CK catalogue is unavailable"
        invalid.append(row)
    return {"invalid": invalid, "checked": len(ids or [])}


# ---------------------------------------------------------------------------
# API behaviour
# ---------------------------------------------------------------------------


def api_capability(
    api_names: list[str],
    behaviour_map: str = DEFAULT_API_BEHAVIOUR_MAP,
    attck_map: str = DEFAULT_API_ATTCK_MAP,
) -> dict[str, Any]:
    """What each named API does, and which techniques cite it as evidence.

    ``behaviours`` is the catalog's own category for the API; ``techniques``
    are the technique rules that list it. Both are lookups in a vendored table,
    so an API absent from the table comes back with empty lists rather than a
    guess.

    ``catalog_flags`` carries the catalog's own labels — ``suspicious`` for an
    API it tiers high or medium — named for where they come from rather than
    presented as this tool's finding. A bare ``suspicious: true`` would be a
    verdict, and the tools state facts.
    """
    from maljan.analysis.api_capability_db import load_api_attck_map, load_api_behaviour_db

    names = [str(n).strip() for n in (api_names or []) if str(n).strip()]
    behaviours = load_api_behaviour_db(str(resolve_data(behaviour_map)))
    techniques = load_api_attck_map(str(resolve_data(attck_map)))
    rows: list[dict[str, Any]] = []
    for name in names:
        category, suspicious = behaviours.classify(name) if behaviours else (None, False)
        cited: list[dict[str, Any]] = []
        if techniques is not None:
            for rule, matched in techniques.match({name}):
                cited.append(
                    {
                        "technique_id": rule.technique_id,
                        "name": rule.name,
                        "matched": matched,
                        "min_apis": rule.min_apis,
                    }
                )
        rows.append(
            {
                "api": name,
                "category": category,
                "behaviours": [category] if category else [],
                "techniques": cited,
                "catalog_flags": ["suspicious"] if suspicious else [],
            }
        )
    out: dict[str, Any] = {"capabilities": rows}
    if behaviours is None:
        out["reason"] = f"the API behaviour catalog is not readable at {behaviour_map}"
    return out


def lolbin_lookup(command_lines: list[str]) -> dict[str, Any]:
    """Command lines that match a known signed-proxy-execution shape.

    The table's rule is that presence is not enough — ``rundll32`` runs on
    every Windows box every minute — so a hit needs a remote URL, a scriptlet,
    an ordinal export or a payload under a user-writable path. The hit says
    which binary and which technique; there is no confidence number, because
    the match either holds or it does not.
    """
    from maljan.analysis.lolbin_layer import classify_lolbin

    hits: list[dict[str, Any]] = []
    for raw in command_lines or []:
        command = str(raw)
        if not command.strip():
            continue
        classified = classify_lolbin(command)
        if classified is None:
            continue
        technique_id, binary = classified
        hits.append({"binary": binary, "technique_id": technique_id, "pattern": command})
    return {"hits": hits, "checked": len(command_lines or [])}


# ---------------------------------------------------------------------------
# Retrieval over prior cases
# ---------------------------------------------------------------------------


def family_lookup(
    query: str, k: int = 5, catalog: str = DEFAULT_FAMILY_CATALOG, min_score: float = 0.0
) -> dict[str, Any]:
    """Families whose fingerprint description is closest to the query text.

    Needs the embedding model. Without it, or without a catalog, this answers
    an empty list and a ``reason`` — a family attribution that silently becomes
    "no families matched" is worse than one that says it could not look.
    """
    from maljan.memory.family_fingerprint_index import load_family_index

    path = str(resolve_data(catalog))
    try:
        index = load_family_index(path)
    except Exception as exc:  # noqa: BLE001
        return {"families": [], "reason": f"the family catalog could not be read: {exc}"}
    if index is None:
        return {"families": [], "reason": f"no family fingerprint catalog at {path}"}
    try:
        candidates = index.search(query, top_k=max(0, int(k)), min_score=float(min_score))
    except Exception as exc:  # noqa: BLE001 — the embedding backend is optional
        return {"families": [], "reason": f"the embedding backend is unavailable: {exc}"}
    return {
        "families": [
            {
                "family": c.family,
                "score": round(float(c.score), 4),
                "malware_category": c.malware_category,
                "sample_count": c.sample_count,
            }
            for c in candidates
        ]
    }


def similar_cases(
    query: str, k: int = 5, corpus: str = DEFAULT_CASE_CORPUS, min_score: float = 0.0
) -> dict[str, Any]:
    """Prior cases whose behavioural summary is closest to the query text.

    Returns both the neighbours and the techniques they agree on: ``support``
    is how many of the retrieved cases exhibited the technique, which is the
    number that says whether a candidate is a pattern or one case's quirk.
    """
    from maljan.memory.attck_case_index import load_attck_case_index

    path = str(resolve_data(corpus))
    try:
        index = load_attck_case_index(path)
    except Exception as exc:  # noqa: BLE001
        return {
            "cases": [],
            "techniques": [],
            "reason": f"the case corpus could not be read: {exc}",
        }
    if index is None:
        return {"cases": [], "techniques": [], "reason": f"no ATT&CK case corpus at {path}"}
    top_k = max(0, int(k))
    try:
        neighbours = index.search(query, top_k=top_k, min_score=float(min_score))
        techniques = index.recommend_techniques(
            query, top_k=top_k, min_score=float(min_score), max_techniques=top_k
        )
    except Exception as exc:  # noqa: BLE001 — the embedding backend is optional
        return {
            "cases": [],
            "techniques": [],
            "reason": f"the embedding backend is unavailable: {exc}",
        }
    return {
        "cases": [
            {
                "sample_id": n.sample_id,
                "score": round(float(n.score), 4),
                "technique_ids": list(n.technique_ids),
                "malware_category": n.malware_category,
            }
            for n in neighbours
        ],
        "techniques": [
            {
                "technique_id": c.technique_id,
                "support": c.support,
                "score": round(float(c.score), 4),
            }
            for c in techniques
        ],
    }


def function_matches(
    func_hashes: list[str],
    qdrant_url: str,
    collection: str = "maljan_function_hashes_v1",
    api_key: str | None = None,
    exclude_sample_id: str = "",
) -> dict[str, Any]:
    """Stored samples that share a function hash with this one.

    Exact-match attribution: two binaries sharing a compiled function body is
    a much stronger signal than two binaries scoring alike on prose. Needs
    Qdrant, and says so instead of raising when it is not reachable.
    """
    from maljan.memory.function_hash_store import (
        FunctionHashStore,
        FunctionHashStoreUnavailableError,
    )

    wanted = [str(h).strip() for h in (func_hashes or []) if str(h).strip()]
    if not wanted:
        return {"matches": []}
    try:
        store = FunctionHashStore(url=qdrant_url, collection=collection, api_key=api_key)
        found = store.match(wanted, exclude_sample_id=exclude_sample_id)
    except FunctionHashStoreUnavailableError as exc:
        return {"matches": [], "reason": f"qdrant-client is not installed: {exc}"}
    except Exception as exc:  # noqa: BLE001
        return {"matches": [], "reason": f"the function-hash store is unavailable: {exc}"}
    return {
        "matches": [
            {
                "func_hash": m.func_hash,
                "family": m.family,
                "sample_id": m.sample_id,
                "func_name": m.func_name,
            }
            for m in found
        ]
    }
