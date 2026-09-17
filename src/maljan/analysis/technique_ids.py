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


def _strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Iterable) and not isinstance(value, bytes | Mapping):
        for item in value:
            if isinstance(item, str):
                yield item
