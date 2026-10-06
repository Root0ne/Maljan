"""Values a revision no longer states, and whether a revision is the answer in force again.

A revision replaces the analyst's answer in force, and what it no longer said
was gone without a trace. The platform records, per analyst, round and claim,
the values of the answer in force that appear nowhere in the revision's whole
text: its answer as written, its claims, their evidence and techniques, its
findings and its disputes. Nothing is asked; the model decides what its
answer is, and the record says what left it.

A claim's values:

- a number in hex (``0x…``) or in decimal, compared as one number, so ``0xf``
  and ``15`` are the same value;
- an ATT&CK technique id, in the claim text or on its technique line;
- a quoted value with no space inside (in backticks or double quotes); quoted
  prose is words, not a value.

The search is generous about spelling, because the record must be right
whenever it says a value is gone: a decompiler's name (``FUN_``, ``sub_``,
``fcn.``, ``LAB_``, ``loc_``) carries its address under any image base aligned
to 64 KiB, and a defanged host or URL is the value it defangs.

``answer_unchanged`` is the debate's convergence test, a fact of the same
kind: a revision whose text is the answer in force again after whitespace
changed nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

_HEX = re.compile(r"(?<![0-9A-Za-z_])0x([0-9a-fA-F]+)(?![0-9A-Za-z_])")
_DECIMAL = re.compile(r"(?<![\w.%-])(\d+)(?![\w%]|\.\d)")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_QUOTED = re.compile(r"`([^`\s]{2,})`|\"([^\"\s]{2,})\"")
# A decompiler's own name for a function or a label: a fixed prefix and the
# address in hex.
_DECOMPILER_NAME = re.compile(
    r"(?<![0-9A-Za-z_])(?:fun|sub|fcn|lab|loc|func)[_.]([0-9a-fA-F]{1,16})(?![0-9A-Za-z_])",
    re.IGNORECASE,
)
# Where a loaded image's base may sit: a multiple of 64 KiB. A decompiler's
# name and a claim's address are one address when they differ by a positive
# multiple of it.
_IMAGE_BASE_ALIGNMENT = 0x10000


def _refanged(text: str) -> str:
    """``text`` with the usual defanging undone: ``[.]``, ``(.)``, ``[:]``, ``hxxp``."""
    out = re.sub(r"\[(\.|:)\]|\((\.)\)", lambda m: m.group(1) or m.group(2), str(text or ""))
    return re.sub(r"\bhxxp", "http", out, flags=re.IGNORECASE)


# A number that names a place in the debate rather than states a value: a
# claim, round, step, stage or phase reference ("Claim 14/15", "round 2"),
# which a revision renumbers, and the list number a claim opens with ("1." or
# "(1)"). A number after any other word ("line 75", "item 3", "no. 5", "#3")
# is compared as a value, because it may be one: recorded only when the
# revision states that number nowhere.
_REFERENCE_NUMBER = re.compile(
    r"(?i)\b(?:claims?|rounds?|steps?|stages?|phases?)\s*#?\d+"
    r"(?:\s*(?:/|,|&|\+|and|to|-|–)\s*#?\d+)*"
)
_LIST_NUMBER = re.compile(r"(?m)^\s*\(?\d+[.)](?=\s)")


def _without_hex_and_ids(text: str) -> str:
    text = _HEX.sub(" ", text)
    text = _DECOMPILER_NAME.sub(" ", text)
    text = _TECHNIQUE.sub(" ", text)
    return re.sub(r"\bev_\d+\b", " ", text)


def _stated_decimals(text: str) -> set[str]:
    """The decimal numbers a claim states as values, references and list numbers aside."""
    plain = _LIST_NUMBER.sub(" ", _REFERENCE_NUMBER.sub(" ", _without_hex_and_ids(text)))
    return {str(int(n)) for n in _DECIMAL.findall(plain)}


def claim_values(text: str, technique_id: str | None = "") -> frozenset[str]:
    """The values a claim states: numbers (hex as ``0x…``), technique ids, quoted values."""
    plain = _refanged(text)
    values: set[str] = {f"0x{int(m.group(1), 16):x}" for m in _HEX.finditer(plain)}
    values.update(_TECHNIQUE.findall(plain))
    if technique_id and _TECHNIQUE.fullmatch(str(technique_id).strip()):
        values.add(str(technique_id).strip())
    for match in _QUOTED.finditer(plain):
        quoted = (match.group(1) or match.group(2) or "").strip().casefold()
        if len(quoted) >= 2:
            values.add(quoted)
    values.update(_stated_decimals(plain))
    return frozenset(values)


@dataclass(frozen=True)
class _Searched:
    numbers: set[int]
    names: set[int]
    techniques: set[str]
    folded: str


def _searched(text: str) -> _Searched:
    plain = _refanged(text)
    numbers = {int(m.group(1), 16) for m in _HEX.finditer(plain)}
    names = {int(m.group(1), 16) for m in _DECOMPILER_NAME.finditer(plain)}
    numbers.update(int(n) for n in _DECIMAL.findall(_without_hex_and_ids(plain)))
    return _Searched(
        numbers=numbers | names,
        names=names,
        techniques=set(_TECHNIQUE.findall(plain)),
        folded=plain.casefold(),
    )


def _is_stated(value: str, searched: _Searched) -> bool:
    if _TECHNIQUE.fullmatch(value):
        return value in searched.techniques
    number: int | None = None
    if re.fullmatch(r"0x[0-9a-f]+", value):
        number = int(value, 16)
    elif value.isdigit():
        number = int(value)
    if number is not None:
        if number in searched.numbers:
            return True
        return any(
            name > number and (name - number) % _IMAGE_BASE_ALIGNMENT == 0
            for name in searched.names
        )
    return value in searched.folded


def _whole_text(revision: Any, answer: str) -> str:
    """Everything a revision states: answer, claims, evidence, techniques, findings, disputes."""
    parts: list[str] = [str(answer or ""), str(getattr(revision, "answer_text", "") or "")]
    for claim in getattr(revision, "claims", None) or []:
        parts.append(str(getattr(claim, "claim", "") or ""))
        parts.append(str(getattr(claim, "evidence_ref", "") or ""))
        parts.append(str(getattr(claim, "technique_id", "") or ""))
    for finding in getattr(revision, "findings", None) or []:
        parts.append(str(getattr(finding, "title", "") or ""))
        parts.append(str(getattr(finding, "detail", "") or ""))
        parts.extend(str(t) for t in getattr(finding, "technique_ids", None) or [])
    parts.extend(str(item) for item in getattr(revision, "dissent_items", None) or [])
    return "\n".join(parts)


@dataclass(frozen=True)
class DroppedValues:
    """The values of one claim of the answer in force a revision states nowhere."""

    claim: str
    missing: tuple[str, ...]


def dropped_values(
    in_force: Any, revision: Any, answer: str = "", revision_round: int | None = None
) -> list[DroppedValues]:
    """Each claim of ``in_force`` with values ``revision`` states nowhere, in order.

    The round's own number is never one of them: a claim that names its round
    states no value by it.
    """
    if in_force is None or revision is None:
        return []
    searched = _searched(_whole_text(revision, answer))
    dropped: list[DroppedValues] = []
    for claim in getattr(in_force, "claims", None) or []:
        values = claim_values(
            str(getattr(claim, "claim", "") or ""), getattr(claim, "technique_id", None) or ""
        )
        if revision_round is not None:
            values = values - {str(int(revision_round))}
        missing = tuple(sorted(v for v in values if not _is_stated(v, searched)))
        if missing:
            dropped.append(
                DroppedValues(claim=str(getattr(claim, "claim", "") or ""), missing=missing)
            )
    return dropped


def defanged(text: str) -> str:
    """``text`` with the network values it names written defanged, for a sentence a reader sees."""
    from maljan.pipeline.validation import network_values_in
    from maljan.reporting.defang import defang_text

    return defang_text(text, [(value, kind) for kind, value in network_values_in(text)])


def dropped_values_sentence(name: str, revision_round: int, dropped: DroppedValues) -> str:
    """The run summary's sentence for one claim's values, its network values defanged."""
    return defanged(
        f"The {name} analyst's round-{int(revision_round)} revision states nowhere "
        f"{', '.join(dropped.missing)}, which its answer in force stated in the claim "
        f'"{dropped.claim}".'
    )


def answer_unchanged(in_force: str, revision: str) -> bool:
    """Whether a revision's text is the answer in force again, whitespace aside."""
    before = " ".join(str(in_force or "").split())
    after = " ".join(str(revision or "").split())
    return bool(before) and before == after
