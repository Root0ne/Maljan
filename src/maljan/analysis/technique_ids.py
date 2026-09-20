"""ATT&CK technique ids in the shapes the deterministic tools really emit.

Three producers spell a technique three ways. capa's ``attck`` field is a
list of decorated strings — ``Defense Evasion::Process Injection [T1055]``;
a Sigma rule's ``tags`` are lower-case dotted — ``attack.t1055.012``; the
LOLBin table and the API-to-technique rules give a bare ``technique_id``.
Every reader that counts what a tool asserted goes through here, so the
corroboration table, the persistence projection and the pack's rendering
agree on what fired.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
SIGMA_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
# A whole string that is one id, for a field an agent wrote as the id itself.
TECHNIQUE_ID_EXACT_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def technique_ids_in(value: Any) -> list[str]:
    """Every technique id written anywhere in ``value``, first seen first.

    A string is searched; an iterable of strings is searched element by
    element; anything else names no technique. Ids come back upper-case and
    de-duplicated, in the order they were met.
    """
    found: list[str] = []
    for text in _strings(value):
        for match in TECHNIQUE_RE.findall(text):
            tid = match.upper()
            if tid not in found:
                found.append(tid)
    return found


def sigma_technique_ids(row: Mapping[str, Any] | None) -> list[str]:
    """The techniques one Sigma match names, from its ``attack.t…`` tags.

    ``tags`` is what ``tools.rules.sigma_match`` emits. A ``technique_ids``
    list on the row or under ``meta`` is read too, for a row written by hand.
    """
    if not isinstance(row, Mapping):
        return []
    found: list[str] = []
    for tag in _strings(row.get("tags")):
        match = SIGMA_TAG_RE.match(tag.strip())
        if match:
            tid = match.group(1).upper()
            if tid not in found:
                found.append(tid)
    meta = row.get("meta")
    for tid in technique_ids_in(row.get("technique_ids")) + technique_ids_in(
        meta.get("technique_ids") if isinstance(meta, Mapping) else None
    ):
        if tid not in found:
            found.append(tid)
    return found


def api_capability_hits(payload: Mapping[str, Any] | None) -> list[dict[str, Any]]:
    """The technique rules an ``api_capability`` result cleared, one row per rule.

    The tool answers per API and repeats a rule under every API it matched;
    here the matched APIs are pooled per rule and the rule counts only when
    they clear its own ``min_apis``. Each row: ``technique_id``, ``name``,
    ``rule``, ``matched_apis`` in first-seen order. Corroboration and the
    report's projection both read this, so what one calls asserted the other
    shows.

    **A row is a rule, not a technique.** Two rules can name one technique by
    two mechanisms — the catalogue's own name is on both, so the name does not
    tell them apart, and each carries its own ``min_apis``. Keyed by name
    alone they pooled: one rule's APIs counted toward the other's floor, so a
    technique could be asserted on a combination no single rule ever cleared.
    The rule's own label is part of the key, and is on the row so a reader can
    tell two rows for one technique apart. Corroboration keys on the technique
    id and is unchanged by the split.
    """
    if not isinstance(payload, Mapping):
        return []
    rules: dict[tuple[str, str, str], tuple[int, list[str]]] = {}
    for row in payload.get("capabilities") or []:
        if not isinstance(row, Mapping):
            continue
        for rule in row.get("techniques") or []:
            if not isinstance(rule, Mapping):
                continue
            ids = technique_ids_in(rule.get("technique_id"))
            if not ids:
                continue
            key = (ids[0], str(rule.get("name") or ""), str(rule.get("rule") or ""))
            _floor, apis = rules.setdefault(key, (_min_apis(rule), []))
            for api in rule.get("matched") or []:
                name = str(api).strip()
                if name and name not in apis:
                    apis.append(name)
    return [
        {"technique_id": tid, "name": name, "rule": label, "matched_apis": apis}
        for (tid, name, label), (floor, apis) in rules.items()
        if len(apis) >= floor
    ]


def _min_apis(rule: Mapping[str, Any]) -> int:
    try:
        return max(1, int(rule.get("min_apis") or 1))
    except (TypeError, ValueError):
        return 1


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Iterable) and not isinstance(value, bytes | Mapping):
        for item in value:
            if isinstance(item, str):
                yield item
