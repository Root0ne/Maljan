"""Build the MITRE ATT&CK capability matrix (tactic x technique heatmap).

A projection, and only a projection. Two inputs:

  - the judge's STIX bundle — the attack-patterns it emitted and the confidence
    it put on each relationship;
  - ``isr_reports`` — the analysts' own claims, which add the technique ids and
    the evidence quotes the judge did not carry over.

An id the ATT&CK catalogue does not have is carried through and marked
(``technique_id_valid``), not dropped: it is the analyst's answer, and the
report is where a reader is told it does not resolve.

Neither input is adjusted here. The cap this module used to apply — halving the
confidence of an obfuscation or injection claim whose supporting static
evidence the module could not find — is gone: the analyst's number is the
analyst's, and an unsupported claim is now something the analyst is told about
in its own loop, not something a matrix builder quietly discounts.

``ATTCKIndex`` gives technique name and tactic phases for any ATT&CK ID, via the
lazy singleton ``ATTCKValidator.get_instance()`` so the bundle is not re-read.

The output is two complementary structures:
  - ``CapabilityCell[]`` — one row per (tactic, technique) pair for the
    heatmap UI.
  - ``TTPMapping[]`` — one row per technique with all the evidence quotes,
    confidence, contributing layers; this is what the narrative agent reads.

The mapping ``technique_phase_slug -> (tactic_id, tactic_name)`` is resolved
from the LIVE ATT&CK bundle's tactic catalogue (so new releases map with no code
change). The inlined ``_TACTIC_TABLE`` below is kept only as an offline fallback
for when the catalogue is unavailable (first run with no network, tests, etc.).
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

# Canonical Enterprise tactic name per TA-id. Used to pin the display name even
# when the live ATT&CK bundle renames a tactic (v19 relabelled TA0005
# "Defense Evasion" -> "Stealth"). The frontend pins the same table.
_TACTIC_NAME_BY_ID: dict[str, str] = {tid: name for tid, _slug, name in _TACTIC_TABLE}


def build_capability_matrix(
    *,
    stix_output: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
) -> tuple[list[CapabilityCell], list[TTPMapping]]:
    """Return ``(capability_cells, ttp_mappings)`` for the report.

    Both lists are sorted by descending confidence so the UI renders the
    most relevant rows first.
    """
    techniques = _collect_techniques(stix_output, isr_reports)
    if not techniques:
        return [], []

    index = _load_attck_index()

    cells: list[CapabilityCell] = []
    mappings: list[TTPMapping] = []
    for tid, info in techniques.items():
        name, tactic_slug = _resolve_technique_meta(index, tid)
        evidence = info["evidence"]
        # The highest number any source put on this technique. Taken once, here,
        # rather than accumulated into the row as it was collected.
        confidence = max((float(c) for c in info.get("confidences") or ()), default=0.0)
        layers = info.get("layers") or []
        valid = bool(info.get("valid", True))

        # Never emit a zero-confidence cell with no evidence and no contributing
        # source — it is an empty claim the UI would render as a "verified"
        # capability and the narrative agent would expand into prose.
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
                technique_id_valid=valid,
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
                technique_id_valid=valid,
            )
        )

    cells.sort(key=lambda c: c.confidence, reverse=True)
    mappings.sort(key=lambda m: m.confidence, reverse=True)
    logger.info("capability_matrix: %d cells, %d ttp mappings", len(cells), len(mappings))
    return cells, mappings


def _collect_techniques(
    stix_output: dict[str, Any] | None,
    isr_reports: dict[str, Any] | None,
) -> dict[str, dict[str, Any]]:
    """Merge the judge's technique list and the analysts' claims, by technique.

    Each row collects what every source said — the evidence quotes, the source
    names, and every confidence — without deciding anything. The caller reduces
    the confidences to one number, once.
    """
    techniques: dict[str, dict[str, Any]] = {}

    def _row(tid: str) -> dict[str, Any]:
        # ``confidences`` is every number a source put on this technique, kept
        # as a list rather than folded into a running maximum. The projection
        # takes the max once, where a reader can see it happen; a row that
        # rewrites its own ``confidence`` key as it goes reads like the thing
        # this phase removed even when it is only accumulating.
        return techniques.setdefault(
            tid, {"evidence": [], "confidences": [], "layers": [], "valid": True}
        )

    # 1. The judge's bundle. An attack-pattern says the technique is in the
    # verdict; the relationship annotations say how sure the judge was and which
    # agents it credited.
    for tid in _judge_technique_ids(stix_output):
        _row(tid)
    for tid, confidence, agents in _judge_relationship_rows(stix_output):
        row = _row(tid)
        row["confidences"].append(confidence)
        for agent in agents:
            if agent and agent not in row["layers"]:
                row["layers"].append(str(agent))

    # 2. ISR claims. The analysts carry the evidence quotes and the techniques
    # the judge did not name.
    if isr_reports:
        for agent_name, isr in isr_reports.items():
            for claim in getattr(isr, "claims", None) or []:
                claim_tid = getattr(claim, "technique_id", None)
                if not claim_tid:
                    continue
                row = _row(str(claim_tid))
                # An id the catalogue does not have stays in the matrix and is
                # marked. Dropping it deleted the analyst's answer from the one
                # surface a reader looks at, which is the behaviour this whole
                # phase replaced; the marker is how a reader learns instead.
                if not getattr(claim, "technique_id_valid", True):
                    row["valid"] = False
                row["confidences"].append(float(getattr(claim, "confidence", 0.0) or 0.0))
                layer = getattr(isr, "domain", None) or agent_name or "agent"
                if layer and str(layer) not in row["layers"]:
                    row["layers"].append(str(layer))
                quote = getattr(claim, "claim", None) or getattr(claim, "evidence_ref", None) or ""
                if quote and quote not in row["evidence"]:
                    row["evidence"].append(str(quote)[:200])

    return techniques


def _judge_objects(stix_output: dict[str, Any] | None) -> list[dict[str, Any]]:
    objects = (stix_output or {}).get("objects")
    return [obj for obj in objects if isinstance(obj, dict)] if isinstance(objects, list) else []


def _judge_technique_ids(stix_output: dict[str, Any] | None) -> list[str]:
    """The technique ids the judge's attack-patterns name."""
    found: list[str] = []
    for obj in _judge_objects(stix_output):
        if obj.get("type") != "attack-pattern":
            continue
        for ref in obj.get("external_references") or []:
            external_id = ref.get("external_id") if isinstance(ref, dict) else None
            if isinstance(external_id, str) and external_id.strip():
                tid = external_id.strip().upper()
                if tid not in found:
                    found.append(tid)
                break
    return found


def _judge_relationship_rows(
    stix_output: dict[str, Any] | None,
) -> list[tuple[str, float, list[str]]]:
    """``(technique_id, the judge's confidence, contributing agents)`` per relationship."""
    rows: list[tuple[str, float, list[str]]] = []
    for obj in _judge_objects(stix_output):
        if obj.get("type") != "relationship":
            continue
        tid = obj.get("x_maljan_technique_id")
        if not isinstance(tid, str) or not tid.strip():
            continue
        try:
            confidence = float(obj.get("x_maljan_confidence") or 0.0)
        except (TypeError, ValueError):
            confidence = 0.0
        agents = [str(a) for a in obj.get("x_maljan_contributing_agents") or [] if a]
        rows.append((tid.strip().upper(), confidence, agents))
    return rows


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

    Prefers the live ATT&CK bundle's tactic catalogue (via the index) for
    resolution, then pins the *display name* to the canonical Enterprise label
    for known TA-ids. A v19+ bundle returns the renamed label "Stealth" for
    TA0005, which leaked into the markdown export /
    ``ttp_mappings`` and contradicted the frontend's "Defense Evasion". Pinning
    keeps every surface consistent. Falls back to the inlined ``_TACTIC_BY_SLUG``
    table when the catalogue is unavailable (offline first run, fixtures, tests).
    """
    if not tactic_slug:
        return "", ""
    getter = getattr(index, "get_tactic_by_slug", None)
    if callable(getter):
        tactic = getter(tactic_slug)
        if tactic is not None:
            tid = str(getattr(tactic, "tactic_id", ""))
            name = str(getattr(tactic, "name", ""))
            return tid, _TACTIC_NAME_BY_ID.get(tid, name)
    return _TACTIC_BY_SLUG.get(tactic_slug, ("", tactic_slug))
