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
    ``rule``, ``matched_apis`` in first-seen order, and ``benign_rate`` —
    what share of a named benign corpus the rule fires on, which is the fact
    the platform states about a deterministic association and the thing a
    reader needs to weigh one. Corroboration and the report's projection both
    read this, so what one calls asserted the other shows.

    The rate is carried down here, and not looked up again later, because the
    answer that produced the row is the answer the run recorded: the report has
    to show what the catalogue said when the tool was asked, not what a
    catalogue edited since would say.

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
    corpus = ""
    corpora = payload.get("corpora")
    if isinstance(corpora, Mapping):
        corpus = str(corpora.get("benign") or "")
    rules: dict[tuple[str, str, str], tuple[int, list[str], str]] = {}
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
            _floor, apis, _rate = rules.setdefault(
                key, (_min_apis(rule), [], _benign_rate(rule, corpus))
            )
            for api in rule.get("matched") or []:
                name = str(api).strip()
                if name and name not in apis:
                    apis.append(name)
    out: list[dict[str, Any]] = []
    for (tid, name, label), (floor, apis, rate) in rules.items():
        if len(apis) < floor:
            continue
        row_out: dict[str, Any] = {
            "technique_id": tid,
            "name": name,
            "rule": label,
            "matched_apis": apis,
        }
        if rate:
            row_out["benign_rate"] = rate
        out.append(row_out)
    return out


def _benign_rate(rule: Mapping[str, Any], corpus: str) -> str:
    """One sentence for how common a rule is in software that is not a sample.

    The sentence is written so it cannot be read as anything else. It says what
    the rule did — *fires on* — before it says a number, it names the corpus the
    number is a share of, and it carries the count behind the share, because a
    share rounded to one decimal place reads as zero for a rule that fires on
    one file in three thousand. It is emphatically not a probability that this
    sample is benign, and the value is persisted and read on its own, so the
    words that rule that reading out have to be inside the string rather than in
    the column it happens to be drawn in. A rule with no measurement gets no
    sentence rather than a zero.
    """
    measured = rule.get("measured")
    if not isinstance(measured, Mapping):
        return ""
    percent, files = measured.get("seen_on_benign_percent"), measured.get("seen_on_benign_files")
    if not isinstance(percent, int | float) or not isinstance(files, int):
        return ""
    of = f" of {corpus}" if corpus else " measured"
    return f"fires on {percent:.1f}% of benign software ({files}{of})"


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
