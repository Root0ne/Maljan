"""An ATT&CK Navigator layer of the techniques a report publishes.

Built from the report's stored ``ttp_mappings`` (the published technique list)
and nothing else: a draft, a rejected id or a technique the report left out is
not in the layer. Each technique is scored and coloured by the support the
report itself states for it, and its comment is its evidence ids. Deterministic,
no model call.

Support, from the mapping's own fields (``support``, ``is_corroborated``):

* 100 — behaviour (code, a run or a rule backs it) corroborated by independent sources;
* 75  — behaviour, not corroborated;
* 50  — ``capability``: what the file can do, not what it was seen doing;
* 25  — ``unobserved``: no source is behaviour.

A Navigator layer holds one ATT&CK domain. The layer's domain is the one most
published techniques belong to (``domain`` picks another); the techniques of the
other domains are named in the description, never silently dropped.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from typing import Any

from maljan.memory import attck_defense, attck_loader

# Navigator layer file format 4.5, the one Navigator 5.x reads and writes.
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.1.0"

# (score, colour, label), best supported first.
_TIERS: tuple[tuple[int, str, str], ...] = (
    (100, "#2e7d32", "Behaviour, corroborated by independent sources"),
    (75, "#81c784", "Behaviour, not corroborated"),
    (50, "#ffca28", "Capability: what the file can do, not seen done"),
    (25, "#ef9a9a", "Unobserved: no source is behaviour"),
)
_BY_SCORE = {score: (colour, label) for score, colour, label in _TIERS}


def support_score(mapping: Mapping[str, Any]) -> int | None:
    """The layer score for one stored mapping, from the report's own support fields.

    ``None`` when the mapping records no support at all (no ``support`` and no
    sources: a report stored before they were recorded): it is not scored as
    behaviour.
    """
    support = str(mapping.get("support") or "").strip().lower()
    if support == "capability":
        return 50
    if support == "unobserved":
        return 25
    if not mapping.get("sources") and not mapping.get("source_kinds"):
        return None
    return 100 if mapping.get("is_corroborated") else 75


def _layer_domain(domain: str) -> str:
    return f"{domain}-attack"


def attack_version(domain: str = "enterprise") -> str:
    """The cached ATT&CK release's major number for ``domain``, read without parsing the bundle."""
    return attck_defense.cached_version(domain).split(".", 1)[0]


def build_layer(
    malware_report: Mapping[str, Any],
    *,
    name: str = "",
    domain: str | None = None,
) -> dict[str, Any]:
    """The Navigator layer for the published techniques of one stored report."""
    entries: list[tuple[str, Mapping[str, Any]]] = []
    for mapping in malware_report.get("ttp_mappings") or []:
        if not isinstance(mapping, Mapping):
            continue
        tid = str(mapping.get("technique_id") or "").strip().upper()
        if tid:
            entries.append((tid, mapping))

    owner = {tid: attck_loader.domain_of(tid) or "enterprise" for tid, _ in entries}
    counts = Counter(owner.values())
    chosen = domain or (
        max(counts, key=lambda d: (counts[d], -attck_loader.DOMAINS.index(d)))
        if counts
        else "enterprise"
    )
    elsewhere = sorted({tid for tid, d in owner.items() if d != chosen})

    techniques: list[dict[str, Any]] = []
    seen: set[str] = set()
    for tid, mapping in entries:
        if owner[tid] != chosen or tid in seen:
            continue
        seen.add(tid)
        score = support_score(mapping)
        entry: dict[str, Any] = {"techniqueID": tid}
        if score is None:
            metadata = [{"name": "support", "value": "not recorded"}]
        else:
            entry["score"] = score
            entry["color"] = _BY_SCORE[score][0]
            metadata = [
                {"name": "support", "value": str(mapping.get("support") or "behaviour")},
                {
                    "name": "corroborated",
                    "value": "yes" if mapping.get("is_corroborated") else "no",
                },
                {
                    "name": "independent sources",
                    "value": str(mapping.get("independent_sources") or 0),
                },
            ]
        if mapping.get("confidence") is not None:
            metadata.append({"name": "confidence", "value": str(mapping["confidence"])})
        entry.update(
            {
                "comment": ", ".join(str(s) for s in mapping.get("sources") or []),
                "enabled": True,
                "metadata": metadata,
                "links": [],
                "showSubtechniques": False,
            }
        )
        techniques.append(entry)

    description = "The ATT&CK techniques this report publishes, scored by the report's own support."
    if elsewhere:
        description += (
            f" {len(elsewhere)} published technique(s) belong to another ATT&CK domain and "
            f"are not in this layer: {', '.join(elsewhere)}."
        )
    return {
        "name": name or "Maljan report",
        "versions": {
            "attack": attack_version(chosen),
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": _layer_domain(chosen),
        "description": description,
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": [_TIERS[-1][1], _TIERS[0][1]],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [{"label": label, "color": colour} for _, colour, label in _TIERS],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
        "selectVisibleTechniques": False,
    }
