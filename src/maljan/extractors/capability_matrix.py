"""Build the MITRE ATT&CK capability matrix (tactic × technique heatmap).

Inputs:
  - ``cascade_summary`` — already-computed TTP cascade with per-technique
    weighted confidence, contributing layers and evidence quotes
    (``maljan.analysis.ttp_cascade.CascadeSummary``).
  - ``isr_reports`` — agent ISRs with raw claims that mention technique IDs
    (used as a fallback when the cascade is empty).
  - ``ATTCKIndex`` — gives technique name and tactic phases (slugs) for any
    ATT&CK ID. We use the lazy singleton ``ATTCKValidator.get_instance()``
    so we don't re-load the bundle from disk.

The output is two complementary structures:
  - ``CapabilityCell[]`` — one row per (tactic, technique) pair for the
    heatmap UI.
  - ``TTPMapping[]`` — one row per technique with all the evidence quotes,
    confidence, contributing layers; this is what the narrative agent reads.

The mapping ``technique_phase_slug → (tactic_id, tactic_name)`` is resolved
from the LIVE ATT&CK bundle's tactic catalogue (so new releases — e.g. the v19
"Defense Evasion" → "Stealth" + "Defense Impairment" split — map with no code
change). The inlined ``_TACTIC_TABLE`` below is kept only as an offline
fallback for when the catalogue is unavailable (first run with no network,
tests, etc.).
"""

from __future__ import annotations

from typing import Any

from maljan.core.logger import logger
from maljan.reporting.models import CapabilityCell, TTPMapping

# Fallback MITRE ATT&CK Enterprise tactic catalogue (pre-v19 names). Used only
# when the live bundle's tactic catalogue is unavailable. ``kill_chain_phases``
# in the STIX bundle uses the slug form ("defense-evasion"); we map each slug
# to the canonical TA-id and the human-readable name.
_TACTIC_TABLE: tuple[tuple[str, str, str], ...] = (
    ("TA0043", "reconnaissance", "Reconnaissance"),
    ("TA0042", "resource-development", "Resource Development"),
    ("TA0001", "initial-access", "Initial Access"),
    ("TA0002", "execution", "Execution"),
    ("TA0003", "persistence", "Persistence"),
    ("TA0004", "privilege-escalation", "Privilege Escalation"),
    ("TA0005", "defense-evasion", "Defense Evasion"),
    ("TA0006", "credential-access", "Credential Access"),
    ("TA0007", "discovery", "Discovery"),
    ("TA0008", "lateral-movement", "Lateral Movement"),
    ("TA0009", "collection", "Collection"),
    ("TA0011", "command-and-control", "Command and Control"),
    ("TA0010", "exfiltration", "Exfiltration"),
    ("TA0040", "impact", "Impact"),
)

_TACTIC_BY_SLUG: dict[str, tuple[str, str]] = {
    slug: (tid, name) for tid, slug, name in _TACTIC_TABLE
}


def build_capability_matrix(
    *,
    cascade_summary: Any,
    isr_reports: dict[str, Any] | None,
) -> tuple[list[CapabilityCell], list[TTPMapping]]:
    """Return ``(capability_cells, ttp_mappings)`` for the report.

    Both lists are sorted by descending confidence so the UI renders the
    most relevant rows first.
    """
    techniques = _collect_techniques(cascade_summary, isr_reports)
    if not techniques:
        return [], []

    index = _load_attck_index()

    cells: list[CapabilityCell] = []
    mappings: list[TTPMapping] = []
    for tid, info in techniques.items():
        name, tactic_slug = _resolve_technique_meta(index, tid)
        evidence = info["evidence"]
        confidence = float(info.get("confidence") or 0.0)
        layers = info.get("layers") or []

        # Signal-quality §2.4: never emit a zero-confidence cell with no
        # evidence and no contributing layer — it is an empty claim the UI
        # would render as a "verified" capability and the narrative agent
        # would expand into fabricated prose.
        if confidence <= 0.0 and not evidence and not layers:
            continue

        tactic_id, tactic_name = _resolve_tactic(index, tactic_slug)
        cells.append(
            CapabilityCell(
                tactic=tactic_id or "TA0000",
                tactic_name=tactic_name or "Unknown",
                technique_id=tid,
                technique_name=name,
                evidence=evidence[:6],
                confidence=max(0.0, min(1.0, confidence)),
                contributing_layers=layers,
            )
        )
        mappings.append(
            TTPMapping(
                technique_id=tid,
                technique_name=name,
                tactic=tactic_id,
                tactic_name=tactic_name,
                evidence_quotes=evidence[:8],
                confidence=max(0.0, min(1.0, confidence)),
                contributing_layers=layers,
                is_corroborated=len(layers) >= 2,
            )
        )

    cells.sort(key=lambda c: c.confidence, reverse=True)
    mappings.sort(key=lambda m: m.confidence, reverse=True)
    logger.info("capability_matrix: %d cells, %d ttp mappings", len(cells), len(mappings))
    return cells, mappings


def _collect_techniques(
    cascade_summary: Any,
    isr_reports: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Merge cascade entries and ISR claims into a single dict by technique."""
    techniques: dict[str, dict[str, Any]] = {}

    # 1. Cascade — primary source, has weighted confidence + layers + evidence.
    if cascade_summary is not None:
        entries = _cascade_entries(cascade_summary)
        for entry in entries:
            tid = _coerce_technique_id(entry)
            if not tid:
                continue
            techniques.setdefault(
                tid,
                {"evidence": [], "confidence": 0.0, "layers": []},
            )
            techniques[tid]["confidence"] = max(
                techniques[tid]["confidence"],
                float(getattr(entry, "weighted_confidence", 0.0) or 0.0),
            )
            layers = list(getattr(entry, "contributing_layers", []) or [])
            for lyr in layers:
                if lyr not in techniques[tid]["layers"]:
                    techniques[tid]["layers"].append(lyr)
            ev = getattr(entry, "evidence", None) or getattr(entry, "evidence_quote", None)
            if isinstance(ev, list):
                for q in ev:
                    if q and q not in techniques[tid]["evidence"]:
                        techniques[tid]["evidence"].append(str(q))
            elif isinstance(ev, str):
                if ev not in techniques[tid]["evidence"]:
                    techniques[tid]["evidence"].append(ev)

    # 2. ISR claims — fallback. Adds evidence quotes the cascade missed.
    if isr_reports:
        for agent_name, isr in isr_reports.items():
            claims = getattr(isr, "claims", None) or []
            for claim in claims:
                tid = getattr(claim, "technique_id", None)
                if not tid:
                    continue
                techniques.setdefault(
                    tid,
                    {"evidence": [], "confidence": 0.0, "layers": []},
                )
                techniques[tid]["confidence"] = max(
                    techniques[tid]["confidence"],
                    float(getattr(claim, "confidence", 0.0) or 0.0),
                )
                layer = getattr(isr, "domain", None) or agent_name or "agent"
                if layer and layer not in techniques[tid]["layers"]:
                    techniques[tid]["layers"].append(str(layer))
                quote = getattr(claim, "claim", None) or getattr(claim, "evidence_ref", None) or ""
                if quote and quote not in techniques[tid]["evidence"]:
                    techniques[tid]["evidence"].append(str(quote)[:200])

    return techniques


def _cascade_entries(summary: Any) -> list[Any]:
    """Return the per-technique iterable from any CascadeSummary-like object."""
    for attr in ("top_techniques", "techniques", "entries", "items"):
        candidate = getattr(summary, attr, None)
        if callable(candidate):
            try:
                result = candidate()
            except Exception:  # noqa: BLE001
                continue
            if isinstance(result, list | tuple):
                return list(result)
        elif isinstance(candidate, list | tuple):
            return list(candidate)
    if isinstance(summary, list | tuple):
        return list(summary)
    return []


def _coerce_technique_id(entry: Any) -> str | None:
    for attr in ("technique_id", "id", "tid"):
        tid = getattr(entry, attr, None)
        if tid:
            return str(tid)
    if isinstance(entry, dict):
        for key in ("technique_id", "id", "tid"):
            if key in entry:
                return str(entry[key])
    return None


def _load_attck_index() -> Any | None:
    """Return a singleton ATTCKIndex or None if loading fails."""
    try:
        from maljan.memory.attck_validator import ATTCKValidator

        validator = ATTCKValidator.get_instance()
        return getattr(validator, "_index", None)
    except Exception as exc:  # noqa: BLE001
        logger.warning("capability_matrix: ATTCKValidator unavailable (%s)", exc)
        return None


def _resolve_technique_meta(index: Any | None, tid: str) -> tuple[str, str]:
    """Return (technique_name, tactic_slug). Falls back to (tid, '')."""
    if index is None:
        return tid, ""
    try:
        tech = index.get_by_id(tid)
    except Exception:  # noqa: BLE001
        return tid, ""
    if tech is None:
        # Try the parent technique when the input is a sub-technique
        if "." in tid:
            parent = tid.split(".")[0]
            try:
                tech = index.get_by_id(parent)
            except Exception:  # noqa: BLE001
                tech = None
    if tech is None:
        return tid, ""
    name = getattr(tech, "name", None) or tid
    tactic_phases = getattr(tech, "tactic_phases", None) or []
    primary_phase = tactic_phases[0] if tactic_phases else ""
    return str(name), str(primary_phase)


def _resolve_tactic(index: Any | None, tactic_slug: str) -> tuple[str, str]:
    """Resolve a kill-chain slug to ``(tactic_id, tactic_name)``.

    Prefers the live ATT&CK bundle's tactic catalogue (via the index), so new
    releases — e.g. the v19 Stealth / Defense Impairment split — resolve with no
    code change. Falls back to the inlined ``_TACTIC_BY_SLUG`` table when the
    catalogue is unavailable (offline first run, fixture-built index, tests).
    """
    if not tactic_slug:
        return "", ""
    getter = getattr(index, "get_tactic_by_slug", None)
    if callable(getter):
        tactic = getter(tactic_slug)
        if tactic is not None:
            return str(getattr(tactic, "tactic_id", "")), str(getattr(tactic, "name", ""))
    return _TACTIC_BY_SLUG.get(tactic_slug, ("", tactic_slug))
