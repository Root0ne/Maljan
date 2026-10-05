"""What the platform settles of the contradictions a mediator lists.

The mediator's final ``CONTRADICTIONS:`` block decides whether the analysts
revise, and every line of it used to open a revision round for every analyst.
Two kinds of line have nothing left to settle, and the platform says so
instead of opening a round:

- **closed**: the line is about a claim no analyst still holds. The block's
  rule puts the disputed claim first ("the analyst, its claim, and what
  contradicts it"), so the first analyst the line names with claim numbers is
  the holder; when none of those numbers is a claim of that analyst's answer
  in force, the claim was withdrawn or dropped and the line is closed.
- **settled**: the line disputes a count, and a ledger entry it cites, or one
  the claims it names cite, states that count. The platform states the entry
  and its number. A line that names an ATT&CK technique, a network value or a
  hash is never settled here: those are what the report publishes, and the
  analysts settle them.

Every other line stands. Only numbers are matched, and only against the
entry's own count fields (``total``, ``count`` and names ending in either), so
a sample's constant is never read as a tool's tally.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

# A ledger id as the evidence ledger writes it.
_ENTRY_ID = re.compile(r"\bev_\d+\b")
# A technique id, with or without its sub-technique.
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
# A hash written out: 32, 40 or 64 hex digits standing alone.
_HASH = re.compile(
    r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{40}|[0-9a-fA-F]{32})(?![0-9A-Za-z])"
)
# A decimal number standing alone: not part of a hex value, an id, a version or
# a word.
_NUMBER = re.compile(r"(?<![\w.%])(\d+)(?![\w%]|\.\d)")
# The claim numbers after "Claim" or "Claims": "Claim 3", "Claims 4/40",
# "Claims 6, 7 and 37".
_CLAIM_NUMBERS = re.compile(
    r"\s+(?:ANALYST\s+)?(?:['’]s\s+)?claims?\s*#?\s*"
    r"(\d+(?:\s*(?:/|,|&|and|\+)\s*#?\d+)*)",
    re.IGNORECASE,
)
# A key of a tool's structured answer that holds a count.
_COUNT_KEY = re.compile(r"(?:^|_)(?:total|count)(?:$|_)", re.IGNORECASE)


@dataclass(frozen=True)
class Settlement:
    """The mediator's lines, split by what the platform could say of them."""

    standing: list[str] = field(default_factory=list)
    closed: list[str] = field(default_factory=list)
    settled: list[str] = field(default_factory=list)


def _name_pattern(name: str) -> re.Pattern[str]:
    """``name`` as a mediator writes it: any case, ``_``, ``-`` or a space between its parts."""
    parts = [re.escape(part) for part in re.split(r"[_\-\s]+", name) if part]
    return re.compile(
        r"(?<![0-9A-Za-z_])" + r"[_\-\s]+".join(parts) + r"(?![0-9A-Za-z_])", re.IGNORECASE
    )


def claim_references(line: str, agent_names: Iterable[str]) -> list[tuple[str, list[int]]]:
    """``(agent, claim numbers)`` for each analyst the line names with claim numbers, in order.

    A longer name is matched before a name it contains, so ``ALPHA_STATIC`` is
    never read as ``STATIC``.
    """
    names = sorted({str(n) for n in agent_names if str(n).strip()}, key=len, reverse=True)
    taken: list[tuple[int, int]] = []
    found: list[tuple[int, str, list[int]]] = []
    for name in names:
        for match in _name_pattern(name).finditer(line):
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in taken):
                continue
            taken.append(span)
            numbers = _CLAIM_NUMBERS.match(line, match.end())
            if numbers is None:
                continue
            found.append((span[0], name, [int(n) for n in re.findall(r"\d+", numbers.group(1))]))
    found.sort(key=lambda item: item[0])
    return [(name, numbers) for _start, name, numbers in found]


def _claims_of(isr_reports: Mapping[str, Any], name: str) -> list[Any]:
    for key, isr in isr_reports.items():
        if str(key).lower() == name.lower():
            return list(getattr(isr, "claims", None) or [])
    return []


def _entry_fields(entry: Any) -> tuple[str, str, Any]:
    if isinstance(entry, Mapping):
        return (
            str(entry.get("id") or entry.get("entry_id") or ""),
            str(entry.get("tool") or ""),
            entry.get("structured"),
        )
    return (
        str(getattr(entry, "id", "") or ""),
        str(getattr(entry, "tool", "") or ""),
        getattr(entry, "structured", None),
    )


def _counts_of(structured: Any) -> list[tuple[str, int]]:
    """The integer count fields at the top of a tool's structured answer."""
    if not isinstance(structured, Mapping):
        return []
    return [
        (str(key), int(value))
        for key, value in structured.items()
        if _COUNT_KEY.search(str(key)) and isinstance(value, int) and not isinstance(value, bool)
    ]


def _touches_a_published_kind(line: str) -> bool:
    """Whether the line names a technique, a network value or a hash."""
    if _TECHNIQUE.search(line) or _HASH.search(line):
        return True
    from maljan.pipeline.validation import network_values_in

    return bool(network_values_in(line))


def _numbers_disputed(line: str) -> set[int]:
    """The decimal numbers the line states, without its claim numbers, hex values and ledger ids."""
    text = _ENTRY_ID.sub(" ", line)
    text = re.sub(r"\b0x[0-9a-fA-F]+\b", " ", text)
    text = _CLAIM_NUMBERS.sub(" ", text)
    return {int(n) for n in _NUMBER.findall(text)}


def _settled_by_a_count(
    line: str,
    references: Sequence[tuple[str, list[int]]],
    isr_reports: Mapping[str, Any],
    entries: Mapping[str, tuple[str, Any]],
) -> str:
    """The platform's sentence for a count dispute a cited entry answers, or ``""``."""
    if _touches_a_published_kind(line):
        return ""
    numbers = _numbers_disputed(line)
    if len(numbers) < 2:
        return ""
    cited = list(dict.fromkeys(_ENTRY_ID.findall(line)))
    for name, claimed in references:
        claims = _claims_of(isr_reports, name)
        for number in claimed:
            if 1 <= number <= len(claims):
                ref = str(getattr(claims[number - 1], "evidence_ref", "") or "")
                cited.extend(i for i in _ENTRY_ID.findall(ref) if i not in cited)
    for entry_id in cited:
        if entry_id not in entries:
            continue
        tool, structured = entries[entry_id]
        stated = [(key, value) for key, value in _counts_of(structured) if value in numbers]
        if stated:
            said = ", ".join(f"{key} = {value}" for key, value in stated)
            return (
                f"Settled from the ledger: entry {entry_id}"
                f"{f' ({tool})' if tool else ''} states {said}. Line: {line}"
            )
    return ""


def settle_contradictions(
    lines: Sequence[str],
    isr_reports: Mapping[str, Any],
    ledger: Iterable[Any],
    agent_names: Iterable[str],
) -> Settlement:
    """Split the mediator's lines into standing, closed and settled ones.

    ``isr_reports`` is each analyst's answer in force, ``ledger`` the run's
    entries (``LedgerEntry`` or its dump) and ``agent_names`` the debate's
    analysts. Never raises on a line it cannot read: such a line stands.
    """
    names = list(agent_names) or [str(k) for k in isr_reports]
    entries: dict[str, tuple[str, Any]] = {}
    for entry in ledger or ():
        entry_id, tool, structured = _entry_fields(entry)
        if entry_id:
            entries[entry_id] = (tool, structured)
    standing: list[str] = []
    closed: list[str] = []
    settled: list[str] = []
    for line in lines:
        text = str(line)
        try:
            references = claim_references(text, names)
            if references:
                holder, numbers = references[0]
                held = len(_claims_of(isr_reports, holder))
                if numbers and all(not 1 <= n <= held for n in numbers):
                    from maljan.pipeline.claim_drops import defanged

                    closed.append(
                        defanged(
                            f"Closed: {holder} claim(s) {', '.join(str(n) for n in numbers)} "
                            f"are not in its answer in force ({held} claim(s)), so no analyst "
                            f"holds what this line disputes. Line: {text}"
                        )
                    )
                    continue
            sentence = _settled_by_a_count(text, references, isr_reports, entries)
        except Exception:  # noqa: BLE001 — a line that cannot be read stands
            sentence = ""
        if sentence:
            settled.append(sentence)
        else:
            standing.append(text)
    return Settlement(standing=standing, closed=closed, settled=settled)


# The head of the block a revision round is told the platform's sentences
# under, after the mediator's feedback.
PLATFORM_SETTLEMENT_HEAD = (
    "The platform closed or settled these lines of the mediator's block; they open no "
    "dispute, and an answer does not argue them again:"
)


def with_platform_settlement(directive: str, sentences: Sequence[str]) -> str:
    """The revision directive with the platform's sentences after it, or as it was."""
    said = [str(s) for s in sentences if str(s).strip()]
    if not said:
        return directive
    block = "\n".join([PLATFORM_SETTLEMENT_HEAD, *(f"- {s}" for s in said)])
    return f"{directive}\n\n{block}" if directive else block
