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
  existed, so a mediator that writes none is read exactly as before;
- **reads names**: the mediator opens each line with ``[analysts: <name>, ...]``,
  the analysts who must revise over it. A revision round asks the analysts the
  blocking lines name, each shown the lines that name it and the peers they
  name. A blocking line without the field, or naming no analyst of the
  debate, leaves the names unread and the round asks every analyst.

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
# The reason may hold one level of bracketed text, such as a ledger id
# written ``[ev_0021]``.
_REASON = r"(?:[^\[\]]|\[[^\[\]]*\])*"
_MARK = re.compile(
    r"\s*[*_`]*\[\s*(?P<kind>not\s+blocking|blocking)\s*(?::(?P<reason>" + _REASON + r"))?\]"
    r"[*_`]*\s*\.?\s*$",
    re.IGNORECASE,
)
# Any mark the line holds, wherever it stands: two of different kinds conflict.
_ANY_MARK = re.compile(
    r"\[\s*(?P<kind>not\s+blocking|blocking)\s*(?::" + _REASON + r")?\]", re.IGNORECASE
)
# What a mark opens with: a line that holds it and no mark that reads was
# written a mark the parser could not read.
_MARK_OPENING = re.compile(r"\[\s*(?:not\s+)?blocking\b", re.IGNORECASE)

# The head of the facts a revision round is told, after the mediator's feedback.
LEDGER_FACTS_HEAD = "The evidence ledger states these counts for the lines the mediator listed:"


def _name_pattern(name: str) -> re.Pattern[str]:
    parts = [re.escape(part) for part in re.split(r"[_\-\s]+", name) if part]
    return re.compile(
        r"(?<![0-9A-Za-z_])" + r"[_\-\s]+".join(parts) + r"(?![0-9A-Za-z_])", re.IGNORECASE
    )


def _mentions(line: str, agent_names: Iterable[str]) -> list[tuple[str, list[int] | None]]:
    """``(agent, claim numbers or None)`` for each time the line names an analyst.

    Longer names are read first, so a name inside a longer one is not read
    again. ``None`` is a mention that cites no claim number right after it.
    """
    names = sorted({str(n) for n in agent_names if str(n).strip()}, key=len, reverse=True)
    taken: list[tuple[int, int]] = []
    found: list[tuple[str, list[int] | None]] = []
    for name in names:
        for match in _name_pattern(name).finditer(line):
            span = match.span()
            if any(span[0] < end and start < span[1] for start, end in taken):
                continue
            taken.append(span)
            numbers = _CLAIM_NUMBERS.match(line, match.end())
            found.append(
                (name, [int(n) for n in re.findall(r"\d+", numbers.group(1))] if numbers else None)
            )
    return found


def _claims_named(line: str, agent_names: Iterable[str]) -> list[tuple[str, list[int]]]:
    """``(agent, claim numbers)`` for each analyst the line names with claim numbers."""
    return [(name, numbers) for name, numbers in _mentions(line, agent_names) if numbers]


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
    """One listed line as the mediator marked it.

    ``unread`` says the line was written with a mark the platform did not
    honour: one it could not read, a ``not blocking`` one with no reason, or
    two that conflict.
    Such a line blocks, and the run records it.
    """

    line: str
    blocking: bool
    marked: bool
    reason: str = ""
    unread: bool = False


def _kind(match: re.Match[str]) -> str:
    return " ".join(match.group("kind").lower().split())


def read_marks(lines: Iterable[str]) -> list[Mark]:
    """The mediator's mark on each line; an unmarked line blocks.

    - A mark ends its line and gives a reason, which may cite a ledger id in
      brackets.
    - A line with marks of both kinds blocks.
    - ``[not blocking]`` with no reason is no mark: the line blocks.
      ``[blocking]`` with no reason blocks as it asks.
    - A line that opens a mark the parser cannot read blocks.

    Conflicting marks, a ``[not blocking]`` with no reason and a mark that
    cannot be read are recorded as unread.
    """
    marks: list[Mark] = []
    for line in lines:
        text = str(line)
        kinds = {_kind(m) for m in _ANY_MARK.finditer(text)}
        match = _MARK.search(text)
        reason = (match.group("reason") or "").strip() if match is not None else ""
        if len(kinds) > 1:
            marks.append(Mark(line=text, blocking=True, marked=True, unread=True))
        elif match is not None and not reason and _kind(match) == "blocking":
            # The line blocks as the mark asks; only a mark that would set a
            # line aside needs its reason.
            marks.append(Mark(line=text, blocking=True, marked=True))
        elif match is None or not reason:
            marks.append(
                Mark(
                    line=text,
                    blocking=True,
                    marked=False,
                    unread=bool(_MARK_OPENING.search(text)),
                )
            )
        else:
            marks.append(
                Mark(line=text, blocking=_kind(match) == "blocking", marked=True, reason=reason)
            )
    return marks


def with_ledger_facts(directive: str, facts: Sequence[str]) -> str:
    """The revision directive with the ledger's counts after it, or as it was."""
    said = [str(f) for f in facts if str(f).strip()]
    if not said:
        return directive
    block = "\n".join([LEDGER_FACTS_HEAD, *(f"- {f}" for f in said)])
    return f"{directive}\n\n{block}" if directive else block


# The field the mediator opens a listed line with: the analysts who must
# revise over it, by the names their reports are headed with.
_ANALYSTS_FIELD = re.compile(r"\[\s*analysts?\s*:(?P<names>[^\[\]]*)\]", re.IGNORECASE)
# What separates two names in the field.
_NAME_SEPARATOR = re.compile(r"\s*(?:,|;|&|\band\b)\s*", re.IGNORECASE)
# The word a report heading closes a name with.
_HEADING_WORD = "_analyst"

# Why a revision round asked every analyst, as its record says.
BLOCK_NOT_READ_NOTE = (
    "The mediator's final CONTRADICTIONS: block was not read; every analyst was asked to revise."
)
ANALYSTS_FIELD_MISSING_NOTE = (
    "A blocking line of the mediator's final CONTRADICTIONS: block named no analyst in an "
    "[analysts: ...] field; every analyst was asked to revise."
)


def analysts_field_unknown_note(written: str) -> str:
    """Why a round asked every analyst: a blocking line named someone outside the debate."""
    return (
        "A blocking line of the mediator's final CONTRADICTIONS: block named "
        f"'{written}' in its [analysts: ...] field, which is no analyst of this debate; "
        "every analyst was asked to revise."
    )


def read_analysts_field(line: str) -> list[str] | None:
    """The names a line's ``[analysts: ...]`` fields hold, as written, or ``None``.

    ``None`` is a line with no such field, or with fields that hold no name.
    """
    names: list[str] = []
    for match in _ANALYSTS_FIELD.finditer(str(line)):
        for part in _NAME_SEPARATOR.split(match.group("names")):
            name = part.strip().strip("*_`'\"").strip()
            if name and name not in names:
                names.append(name)
    return names or None


def _key(name: str) -> str:
    return "_".join(part for part in re.split(r"[_\-\s]+", str(name).lower()) if part)


def resolve_analyst(written: str, participants: Sequence[str]) -> str | None:
    """The participant a name in the field stands for, or ``None``.

    Read as the platform heads a report: case, spaces, hyphens and underscores
    alike, and the closing word ``ANALYST`` of a heading left off where the
    name without it is a participant's.
    """
    keys = {_key(p): str(p) for p in participants}
    key = _key(written)
    if key in keys:
        return keys[key]
    if key.endswith(_HEADING_WORD):
        return keys.get(key[: -len(_HEADING_WORD)])
    return None


def analysts_to_revise(
    blocking: Sequence[str], participants: Sequence[str]
) -> tuple[list[str] | None, str]:
    """``(the analysts the blocking lines name, "")``, or ``(None, why)``.

    The names come from each line's ``[analysts: ...]`` field and nowhere else.
    No blocking line names nobody: ``[]``. A blocking line without the field,
    or naming someone who is no participant, leaves the round unread: every
    analyst is asked, as before, and the sentence says why. The names are in
    the participants' order.
    """
    named: set[str] = set()
    for line in blocking:
        written = read_analysts_field(line)
        if written is None:
            return None, ANALYSTS_FIELD_MISSING_NOTE
        for name in written:
            found = resolve_analyst(name, participants)
            if found is None:
                return None, analysts_field_unknown_note(name)
            named.add(found)
    return [str(p) for p in participants if str(p) in named], ""


def points_naming(name: str, lines: Iterable[str], participants: Sequence[str]) -> list[str]:
    """The lines whose ``[analysts: ...]`` field names the analyst ``name``."""
    found: list[str] = []
    for line in lines:
        written = read_analysts_field(line) or []
        if any(resolve_analyst(w, participants) == name for w in written):
            found.append(str(line))
    return found


# How the mediation's finding lays out its listed lines (``JudgeAgent.mediate``).
_LISTED_HEAD = "\n\nContradictions: "
_CONFIDENCE_TAIL = "\nConfidence: "


def _claim_line(number: int, claim: Any) -> str:
    return (
        f"Claim {number}: {getattr(claim, 'claim', '')} | Evidence: "
        f"{getattr(claim, 'evidence_ref', '')}"
    )


def contested_input(
    name: str,
    finding: str,
    blocking: Sequence[str],
    participants: Sequence[str],
    reports: Mapping[str, str],
    isr_reports: Mapping[str, Any],
) -> tuple[str, dict[str, str]]:
    """``(mediator feedback, peer reports)`` for a named analyst's revision.

    The feedback is the mediation's finding with its listed lines cut to the
    blocking lines whose field names ``name``; a finding not laid out as the
    mediation writes it is passed whole. The peers are the ones those lines
    name, in the field or by the name their report is headed with, in the
    participants' order. A peer whose every mention in those lines cites its
    claims by number is shown those claims as the mediator read them; any
    other peer, and one cited past its claims, is shown its whole answer in
    force. The lines themselves are kept whole, with every claim number and
    ledger id they cite.
    """
    mine = points_naming(name, blocking, participants)
    head_at = finding.rfind(_LISTED_HEAD)
    tail_at = finding.rfind(_CONFIDENCE_TAIL)
    if 0 <= head_at < tail_at:
        feedback = f"{finding[:head_at]}{_LISTED_HEAD}{'; '.join(mine)}{finding[tail_at:]}"
    else:
        feedback = finding
    whole: set[str] = set()
    cited: dict[str, list[int]] = {}
    mentioned: list[str] = []
    for line in mine:
        in_field = {
            found
            for w in (read_analysts_field(line) or [])
            if (found := resolve_analyst(w, participants)) is not None
        }
        # The names the line's prose gives, the field itself left out.
        in_prose: set[str] = set()
        for peer, numbers in _mentions(_ANALYSTS_FIELD.sub(" ", line), participants):
            in_prose.add(peer)
            if peer == name:
                continue
            if peer not in mentioned:
                mentioned.append(peer)
            if numbers is None:
                whole.add(peer)
            else:
                cited.setdefault(peer, []).extend(numbers)
        # A peer the field names and the prose does not cites no claim.
        for peer in in_field - in_prose - {name}:
            if peer not in mentioned:
                mentioned.append(peer)
            whole.add(peer)
    peers: dict[str, str] = {}
    for peer in [str(p) for p in participants if str(p) in mentioned]:
        claims = _claims_of(isr_reports, peer)
        numbers = list(dict.fromkeys(cited.get(peer, [])))
        if peer in whole or not numbers or any(not 1 <= n <= len(claims) for n in numbers):
            peers[peer] = str(reports.get(peer, ""))
        else:
            peers[peer] = "\n".join(_claim_line(n, claims[n - 1]) for n in numbers)
    return feedback, peers
