"""The ledger's counts for the contradictions a mediator lists, and the mediator's own marks.

The mediator's final ``CONTRADICTIONS:`` block decides whether the analysts
revise. The platform decides nothing about a line's content. It does two
things:

- **states facts**: for a listed line whose cited ledger entries (cited by
  the line itself, or by a claim the line names) hold, in a field whose name
  says count or total, a number the line itself states, it states every such
  value, also when two entries disagree. No call is made for them: they ride
  on the calls the debate makes anyway, the revision directive of the analysts
  the line names and the next mediation's prompt;
- **reads marks**: the mediator ends each line with ``[blocking: <reason>]`` or
  ``[not blocking: <reason>]``. A line marked not blocking does not stand
  against consensus. An unmarked line blocks, as every line did before marks
  existed, so a mediator that writes none is read exactly as before.

A size or a time is not a count: keys naming seconds, milliseconds, bytes or a
size are left out.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

# A ledger id as the evidence ledger writes it.
_ENTRY_ID = re.compile(r"\bev_\d+\b")
# A decimal number standing alone.
_NUMBER = re.compile(r"(?<![\w.%])\d+(?![\w%]|\.\d)")
# The claim numbers after "Claim" or "Claims": "Claim 3", "Claims 4/40".
_CLAIM_NUMBERS = re.compile(
    r"\s+(?:ANALYST\s+)?(?:['’]s\s+)?claims?\s*#?\s*"
    r"(\d+(?:\s*(?:/|,|&|and|\+)\s*#?\d+)*)",
    re.IGNORECASE,
)
# A key of a tool's structured answer that holds a count, and one that holds a
# size or a time however it is named.
_COUNT_KEY = re.compile(r"(?:^|_)(?:total|count)(?:$|_)", re.IGNORECASE)
_NOT_A_COUNT_KEY = re.compile(r"(?:^|_)(?:seconds?|secs?|ms|millis|bytes?|size|kb|mb)(?:$|_)", re.I)
# The mark the mediator ends a line with, with any emphasis around it.
_MARK = re.compile(
    r"\s*[*_`]*\[\s*(?P<kind>not\s+blocking|blocking)\s*(?::\s*(?P<reason>[^\]]*))?\]"
    r"[*_`]*\s*\.?\s*$",
    re.IGNORECASE,
)

# The head of the facts a revision round is told, after the mediator's feedback.
LEDGER_FACTS_HEAD = "The evidence ledger states these counts for the lines the mediator listed:"


def _name_pattern(name: str) -> re.Pattern[str]:
    parts = [re.escape(part) for part in re.split(r"[_\-\s]+", name) if part]
    return re.compile(
        r"(?<![0-9A-Za-z_])" + r"[_\-\s]+".join(parts) + r"(?![0-9A-Za-z_])", re.IGNORECASE
    )


def _claims_named(line: str, agent_names: Iterable[str]) -> list[tuple[str, list[int]]]:
    """``(agent, claim numbers)`` for each analyst the line names with claim numbers."""
    names = sorted({str(n) for n in agent_names if str(n).strip()}, key=len, reverse=True)
    taken: list[tuple[int, int]] = []
    found: list[tuple[str, list[int]]] = []
    for name in names:
        for match in _name_pattern(name).finditer(line):
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in taken):
                continue
            taken.append(span)
            numbers = _CLAIM_NUMBERS.match(line, match.end())
            if numbers is not None:
                found.append((name, [int(n) for n in re.findall(r"\d+", numbers.group(1))]))
    return found


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
        if _COUNT_KEY.search(str(key))
        and not _NOT_A_COUNT_KEY.search(str(key))
        and isinstance(value, int)
        and not isinstance(value, bool)
    ]


def ledger_count_facts(
    lines: Sequence[str],
    isr_reports: Mapping[str, Any],
    ledger: Iterable[Any],
    agent_names: Iterable[str],
) -> list[str]:
    """One sentence per listed line whose cited entries state a count the line states.

    The numbers a line states are its decimal numbers, its claim numbers, hex
    values and ledger ids aside; only a count equal to one of them is stated,
    every such count of every cited entry. Never raises on a line it cannot
    read.
    """
    names = list(agent_names) or [str(k) for k in isr_reports]
    entries: dict[str, tuple[str, Any]] = {}
    for entry in ledger or ():
        entry_id, tool, structured = _entry_fields(entry)
        if entry_id:
            entries[entry_id] = (tool, structured)
    facts: list[str] = []
    for line in lines:
        text = str(line)
        try:
            bare = _CLAIM_NUMBERS.sub(
                " ", re.sub(r"\b0x[0-9a-fA-F]+\b", " ", _ENTRY_ID.sub(" ", text))
            )
            numbers = {int(n) for n in _NUMBER.findall(bare)}
            if not numbers:
                continue
            cited = list(dict.fromkeys(_ENTRY_ID.findall(text)))
            for name, claim_numbers in _claims_named(text, names):
                claims = _claims_of(isr_reports, name)
                for number in claim_numbers:
                    if 1 <= number <= len(claims):
                        ref = str(getattr(claims[number - 1], "evidence_ref", "") or "")
                        cited.extend(i for i in _ENTRY_ID.findall(ref) if i not in cited)
            stated = []
            for entry_id in cited:
                if entry_id not in entries:
                    continue
                tool, structured = entries[entry_id]
                counts = [(key, value) for key, value in _counts_of(structured) if value in numbers]
                if counts:
                    said = ", ".join(f"{key} = {value}" for key, value in counts)
                    stated.append(f"entry {entry_id}{f' ({tool})' if tool else ''} states {said}")
        except Exception:  # noqa: BLE001 — a line that cannot be read gets no fact
            continue
        if stated:
            facts.append(f'For the line "{text}": {"; ".join(stated)}.')
    return facts


def facts_naming(name: str, facts: Iterable[str]) -> list[str]:
    """The facts whose line names the analyst ``name``: the ones its revision is told."""
    pattern = _name_pattern(name)
    return [str(f) for f in facts if pattern.search(str(f))]


@dataclass(frozen=True)
class Mark:
    """One listed line as the mediator marked it."""

    line: str
    blocking: bool
    marked: bool
    reason: str = ""


def read_marks(lines: Iterable[str]) -> list[Mark]:
    """The mediator's mark on each line; an unmarked line blocks."""
    marks: list[Mark] = []
    for line in lines:
        text = str(line)
        match = _MARK.search(text)
        if match is None:
            marks.append(Mark(line=text, blocking=True, marked=False))
            continue
        kind = " ".join(match.group("kind").lower().split())
        marks.append(
            Mark(
                line=text,
                blocking=kind == "blocking",
                marked=True,
                reason=(match.group("reason") or "").strip(),
            )
        )
    return marks


def with_ledger_facts(directive: str, facts: Sequence[str]) -> str:
    """The revision directive with the ledger's counts after it, or as it was."""
    said = [str(f) for f in facts if str(f).strip()]
    if not said:
        return directive
    block = "\n".join([LEDGER_FACTS_HEAD, *(f"- {f}" for f in said)])
    return f"{directive}\n\n{block}" if directive else block
