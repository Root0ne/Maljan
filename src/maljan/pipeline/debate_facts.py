"""The ledger's counts for the contradictions a mediator lists, and the mediator's own marks.

The mediator's final ``CONTRADICTIONS:`` block decides whether the analysts
revise. The platform decides nothing about a line's content. It does two
things:

- **states facts**: for a listed line whose cited ledger entries (cited by
  the line itself, or by a claim the line names) hold, in a field whose name
  says count or total, a number the line itself states, it states every such
  value, also when two entries disagree; the length of a list field only
  where its key names the noun the line counts with that number ("0 hits"
  for ``matches``). No call is made for them: they ride on the calls the
  debate makes anyway, the revision directive of the analysts the line names
  and the next mediation's prompt;
- **says what the ledger already stated**: a blocking line that disputes a
  count itself (two numbers for one noun: "three matches" against "0 hits"),
  every count of which (a number before a plural noun: "0 hits", "31 rules") the cited
  entries state, in keys naming its nouns, as one record that agrees with
  itself, and whose facts an earlier mediation of the debate told the
  analysts, is stated and told (``ledger_stated``). The line stays a blocking
  line, and the next mediation is shown it was told, so the mediator decides
  whether it still blocks. When every blocking line of a mediation is stated
  and told, the debate ends on its own reason (``routing.LEDGER_STATED``),
  never as consensus. A line with a count no entry states is never stated;
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

import bisect
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.core.config import AGENT_KEY_PATTERN

# A ledger id as the evidence ledger writes it.
_ENTRY_ID = re.compile(r"\bev_\d+\b")
# A decimal number standing alone.
_NUMBER = re.compile(r"(?<![\w.%])\d+(?![\w%]|\.\d)")
# The claim numbers after "Claim" or "Claims": "Claim 3", "Claims 4/40".
# Each run of whitespace is read from its start and possessively, so a long
# run is read once (linear time).
_CLAIM_NUMBERS = re.compile(
    r"(?<!\s)\s++(?:ANALYST\s++)?(?:['’]s\s++)?claims?\s*+#?\s*+"
    r"(\d++(?:\s*+(?:/|,|&|and|\+)\s*+#?\d++)*+)",
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

# The field the mediator writes on a listed line: the analysts who must
# revise over it, by the names their reports are headed with.
_ANALYSTS_FIELD = re.compile(r"\[\s*analysts?\s*:(?P<names>[^\[\]]*)\]", re.IGNORECASE)

# The head of the facts a revision round is told, after the mediator's feedback.
LEDGER_FACTS_HEAD = "The evidence ledger states these counts for the lines the mediator listed:"


def _name_pattern(name: str) -> re.Pattern[str]:
    parts = [re.escape(part) for part in re.split(r"[_\-\s]+", name) if part]
    return re.compile(
        r"(?<![0-9A-Za-z_])" + r"[_\-\s]+".join(parts) + r"(?![0-9A-Za-z_])", re.IGNORECASE
    )


def _claims_named(line: str, agent_names: Iterable[str]) -> list[tuple[str, list[str]]]:
    """``(agent, claim numbers)`` for each analyst the line names with claim numbers.

    A number is kept as the digits the line wrote, never converted: digits of
    any length are read (``_claim_place``).
    """
    names = sorted({str(n) for n in agent_names if str(n).strip()}, key=len, reverse=True)
    # The characters a name already read covers: a match over any of them is
    # inside a longer name. One name's matches never overlap each other, so
    # each name looks at each character at most once.
    taken = bytearray(len(line))
    found: list[tuple[str, list[str]]] = []
    for name in names:
        for match in _name_pattern(name).finditer(line):
            start, end = match.span()
            if taken.find(1, start, end) != -1:
                continue
            taken[start:end] = b"\x01" * (end - start)
            numbers = _CLAIM_NUMBERS.match(line, match.end())
            if numbers is not None:
                found.append((name, re.findall(r"\d+", numbers.group(1))))
    return found


def _claim_place(number: str, count: int) -> int | None:
    """The place of claim ``number`` (digits as written) among ``count`` claims, or ``None``.

    Compared as text first: a number with more digits than ``count`` is no
    place, so no digits of any length are converted.
    """
    digits = number.lstrip("0")
    if not digits.isdecimal() or len(digits) > len(str(count)):
        return None
    value = int(digits)
    return value - 1 if value <= count else None


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


def _counts_of(structured: Any) -> list[tuple[str, int, str, bool]]:
    """The counts at the top of a tool's structured answer: ``(key, count, as stated, listed)``.

    An integer field whose name says count or total, and the length of a list
    field (a match list, a hit list), which is how many items the answer holds
    (``listed``).
    """
    if not isinstance(structured, Mapping):
        return []
    found: list[tuple[str, int, str, bool]] = []
    for key, value in structured.items():
        if _NOT_A_COUNT_KEY.search(str(key)):
            continue
        if isinstance(value, list):
            found.append((str(key), len(value), f"{len(value)} items", True))
        elif _COUNT_KEY.search(str(key)) and isinstance(value, int) and not isinstance(value, bool):
            found.append((str(key), int(value), str(int(value)), False))
    return found


# The number words a count may be written with ("three YARA matches").
_NUMBER_WORDS: dict[str, int] = {
    word: value
    for value, word in enumerate(
        "zero one two three four five six seven eight nine ten eleven twelve thirteen "
        "fourteen fifteen sixteen seventeen eighteen nineteen twenty".split()
    )
} | {"thirty": 30, "forty": 40, "fifty": 50, "sixty": 60, "seventy": 70, "eighty": 80, "ninety": 90}
# A count a line states: a number, in digits or a number word, directly
# before a plural noun, at most one word (an adjective) between them ("0
# hits", "31 rules", "three YARA matches"). The noun is the first plural word
# after the number. Every run is read possessively, so a start scans each word
# once. A number after a slash is a ratio's (``_PARTITIVE_BEFORE``).
_STATED_COUNT = re.compile(
    r"(?<![\w.%#/])(\d++|(?i:" + "|".join(sorted(_NUMBER_WORDS, key=len, reverse=True)) + r")\b)"
    r"\s++(?:[A-Za-z][\w-]*+\s++)??([A-Za-z][\w-]*+)(?<=s)\b"
)
# What makes a number the whole of a partitive or a ratio, never a count of
# the noun after it: "of" or "out of" before it ("0 hits of 31 rules", "two of
# the three rules", "3 out of 31 rules"), or a slash ("3/31 rules"). Read in
# a short window before the number, so a line is read once.
_PARTITIVE_BEFORE = re.compile(r"(?:\bout\s++)?\bof(?:\s++the)?\s*+$|/\s*+$", re.IGNORECASE)
_PARTITIVE_WINDOW = 24
# What separates the sides of a disputed line: a count dispute needs two
# numbers for one noun written by two sides ("A reports three matches while B
# reports 0 hits"); two numbers in one side's own statement ("31 rules
# loaded, 3 matched") are two quantities, not a dispute.
_SIDE_BREAK = re.compile(
    r"\b(?:while|whereas|but|against|versus|vs|although|though|however|yet)\b|;",
    re.IGNORECASE,
)


def _count_value(written: str) -> int:
    """A count as written: digits, or a number word."""
    return int(written) if written.isdecimal() else _NUMBER_WORDS[written.lower()]


# The words of a key's name ("rule_count", "hitCount"), and the ones that only
# say the field is a count.
_KEY_WORD = re.compile(r"[A-Z]?[a-z]+|[A-Z]+(?![a-z])")
_COUNT_WORDS = frozenset({"count", "counts", "total", "totals", "num", "number", "n"})
# Two count nouns that name one thing: a rule scan's hit is its match. A
# closed, deliberately minimal vocabulary: any other pair ("detections",
# "alerts" against "matches") is not joined, which leaves such a line
# unstated, never wrongly stated. Not to be widened without a review.
_SAME_COUNT_NOUN = {"hit": "match"}


def _singular(word: str) -> str:
    """``word`` lower-cased, its plural ending off ("matches" is "match", "entries" "entry")."""
    w = word.lower()
    if len(w) > 3 and w.endswith("ies"):
        return w[:-3] + "y"
    if w.endswith(("ches", "shes", "sses", "xes", "zes")):
        return w[:-2]
    if w.endswith("s") and not w.endswith("ss"):
        return w[:-1]
    return w


def _count_noun(word: str) -> str:
    """The noun a count names, folded: its last run of letters, singular."""
    letters = re.findall(r"[A-Za-z]+", word)
    noun = _singular(letters[-1]) if letters else ""
    return _SAME_COUNT_NOUN.get(noun, noun)


def _key_noun(key: str) -> str:
    """The noun a count key names ("rule_count" is "rule", "matches" "match"), or ``""``."""
    words = [w for w in _KEY_WORD.findall(str(key)) if w.lower() not in _COUNT_WORDS]
    return _count_noun(words[-1]) if words else ""


def ledger_count_facts(
    lines: Sequence[str],
    isr_reports: Mapping[str, Any],
    ledger: Iterable[Any],
    agent_names: Iterable[str],
) -> list[str]:
    """One sentence per listed line whose cited entries state a count the line states.

    The numbers a line states are its decimal numbers, its claim numbers, hex
    values and ledger ids aside. A field whose name says count or total is
    stated when its value is one of them, every such count of every cited
    entry; a list field's length only when, besides, its key names the noun
    the line counts with that number ("0 hits" for ``matches``, "3 domains"
    for ``domains``). Never raises on a line it cannot read.
    """
    names = list(agent_names) or [str(k) for k in isr_reports]
    entries = _ledger_counts_by_id(ledger)
    facts: list[str] = []
    for line in lines:
        text = str(line)
        stated = _line_counts(text, names, entries, isr_reports).said
        if stated:
            facts.append(f'For the line "{text}": {"; ".join(stated)}.')
    return facts


@dataclass(frozen=True)
class _LineCounts:
    """What the cited entries state for one line, and whether they state every count of it."""

    said: tuple[str, ...] = ()
    # Whether the line states at least one count (a number before a plural
    # noun) and the cited entries state each one as one record that agrees
    # with itself (``_answers``).
    answered: bool = False
    # ``(entry id, "key = value")`` for each fact that states one of the
    # line's counts: the ones the analysts must have been told.
    atoms: frozenset[tuple[str, str]] = frozenset()


def _ledger_counts_by_id(ledger: Iterable[Any]) -> dict[str, tuple[str, Any]]:
    entries: dict[str, tuple[str, Any]] = {}
    for entry in ledger or ():
        entry_id, tool, structured = _entry_fields(entry)
        if entry_id:
            entries[entry_id] = (tool, structured)
    return entries


def _answers(
    sided: set[tuple[int, str, int]],
    by_entry: Sequence[tuple[str, list[tuple[str, int, str, bool]]]],
) -> tuple[bool, frozenset[tuple[str, str]]]:
    """Whether the line disputes a count the cited entries state, and the facts that state it.

    The dispute must be about the count itself: two sides of the line
    (``_SIDE_BREAK``) write two different numbers directly before one noun
    ("three matches" against "0 hits"); ``sided`` holds each count with the
    side it was written on. Two numbers on one side ("31 rules loaded, 3
    matched") are two quantities, and a partitive is no count. A line whose
    sides read different facts differently ("0 matches as benign" against
    "31 rules as malicious") writes one number per noun and is a dispute
    about meaning the ledger does not answer. Each noun the line counts must
    be stated by the cited entries in a field whose key names it, with one
    value: for a disputed noun one of the line's numbers, for any other the
    line's own. The entries must agree (every cited field of a counted noun
    holds one value) and be one record: an entry that states one of the
    line's nouns states all of them (0 connections in one entry against 2
    domains in another is no record).
    """
    written: dict[str, set[int]] = {}
    by_side: dict[str, dict[int, set[int]]] = {}
    for value, noun, side in sided:
        written.setdefault(noun, set()).add(value)
        by_side.setdefault(noun, {}).setdefault(side, set()).add(value)

    def _two_sides_differ(sides: dict[int, set[int]]) -> bool:
        # Two sides each write one number for the noun, and they differ. A
        # side writing two numbers for it ("31 rules loaded, 3 matched") is
        # two quantities of its own: unsure, so no dispute.
        if len(sides) < 2 or any(len(values) > 1 for values in sides.values()):
            return False
        return len({next(iter(values)) for values in sides.values()}) > 1

    if not any(_two_sides_differ(sides) for sides in by_side.values()):
        return False, frozenset()
    nouns = set(written)
    values: dict[str, set[int]] = {}
    facts: list[tuple[str, str, int, str]] = []
    for entry_id, counts in by_entry:
        held = {(_key_noun(key), value, f"{key} = {shown}") for key, value, shown, _l in counts}
        named = {noun for noun, _value, _shown in held if noun in nouns}
        if named and named != nouns:
            return False, frozenset()
        for noun, value, shown in held:
            if noun in nouns:
                values.setdefault(noun, set()).add(value)
                facts.append((entry_id, noun, value, shown))
    for noun, line_values in written.items():
        stated = values.get(noun, set())
        if len(stated) != 1 or not stated <= line_values:
            return False, frozenset()
    return True, frozenset((entry_id, shown) for entry_id, _noun, _value, shown in facts)


def _count_or_reference(match: re.Match[str]) -> str:
    """A claim reference taken out of a line, or kept where it may be a count.

    "claims" with one number after it ("the analyst claims 2 domains") reads
    as a verb as well as a reference, so it is kept for the counts.
    """
    head = match.group(0)[: match.start(1) - match.start(0)]
    if match.group(1).isdecimal() and re.search(r"claims\s*+$", head, re.IGNORECASE):
        return match.group(0)
    return " "


def _line_counts(
    text: str,
    names: Sequence[str],
    entries: Mapping[str, tuple[str, Any]],
    isr_reports: Mapping[str, Any],
) -> _LineCounts:
    """The counts the entries a line cites state that the line states too. Never raises."""
    try:
        idless = re.sub(r"\b0x[0-9a-fA-F]+\b", " ", _ENTRY_ID.sub(" ", text))
        bare = _CLAIM_NUMBERS.sub(" ", idless)
        numbers = {int(n) for n in _NUMBER.findall(bare)}
        if not numbers:
            return _LineCounts()
        # The counts are read with one number after "claims" kept: "the
        # analyst claims 2 domains" may be a count, and a count read that the
        # ledger does not state leaves the line unstated.
        read = _CLAIM_NUMBERS.sub(_count_or_reference, idless)
        breaks = [m.start() for m in _SIDE_BREAK.finditer(read)]
        sided: set[tuple[int, str, int]] = set()
        for match in _STATED_COUNT.finditer(read):
            if _PARTITIVE_BEFORE.search(
                read, max(0, match.start() - _PARTITIVE_WINDOW), match.start()
            ):
                continue
            side = bisect.bisect_right(breaks, match.start())
            sided.add((_count_value(match.group(1)), _count_noun(match.group(2)), side))
        counted = {(value, noun) for value, noun, _side in sided}
        nouns_of: dict[int, set[str]] = {}
        for value, noun in counted:
            nouns_of.setdefault(value, set()).add(noun)
        cited = list(dict.fromkeys(_ENTRY_ID.findall(text)))
        for name, claim_numbers in _claims_named(text, names):
            claims = _claims_of(isr_reports, name)
            for number in claim_numbers:
                place = _claim_place(number, len(claims))
                if place is not None:
                    ref = str(getattr(claims[place], "evidence_ref", "") or "")
                    cited.extend(i for i in _ENTRY_ID.findall(ref) if i not in cited)
        stated: list[str] = []
        by_entry: list[tuple[str, list[tuple[str, int, str, bool]]]] = []
        for entry_id in cited:
            if entry_id not in entries:
                continue
            tool, structured = entries[entry_id]
            held = _counts_of(structured)
            by_entry.append((entry_id, held))
            counts = [
                (key, shown)
                for key, value, shown, listed in held
                if value in numbers and (not listed or _key_noun(key) in nouns_of.get(value, ()))
            ]
            if counts:
                said = ", ".join(f"{key} = {shown}" for key, shown in counts)
                stated.append(f"entry {entry_id}{f' ({tool})' if tool else ''} states {said}")
        answered, atoms = _answers(sided, by_entry)
        return _LineCounts(said=tuple(stated), answered=answered, atoms=atoms)
    except Exception:  # noqa: BLE001 — a line that cannot be read gets no fact
        return _LineCounts()


# One entry's part of a stated fact: its id, its tool and the counts it lists.
# The facts are split on the part separator first and each part is read with
# one anchored match, so a long fact is read in one pass.
_PART_SEPARATOR = re.compile(r"; entry (?=ev_\d++ )")
_STATED_PART = re.compile(r"(ev_\d++)(?: \([^)]*+\))? states (.*)", re.DOTALL)


def fact_atoms(facts: Iterable[str]) -> frozenset[tuple[str, str]]:
    """``(entry id, "key = value")`` for every count these stated facts carry."""
    atoms: set[tuple[str, str]] = set()
    for fact in facts:
        text = str(fact)
        head = text.rfind('": entry ev_')
        body = text[head + 3 :] if head >= 0 else text
        body = body.removeprefix("entry ").removesuffix(".")
        for part in _PART_SEPARATOR.split(body):
            match = _STATED_PART.match(part)
            if match is None:
                continue
            for count in match.group(2).split(", "):
                atoms.add((match.group(1), count.strip()))
    return frozenset(atoms)


def ledger_stated(
    lines: Sequence[str],
    isr_reports: Mapping[str, Any],
    ledger: Iterable[Any],
    agent_names: Iterable[str],
    told: Iterable[str],
) -> list[tuple[str, tuple[str, ...]]]:
    """``(line, facts)`` for each blocking line the ledger states and the analysts were told.

    A line is stated when the cited entries state every count it states
    (``_answers``: a key naming the counted noun, entries that agree, one
    record). It is told when, besides, every fact stating one of its counts
    was stated by an earlier mediation of the debate (``told``). The line is
    never taken away: it stays among the mediation's blocking lines, and the
    next mediation is shown that it was told. When every blocking line of a
    mediation is stated and told, another round would argue counts the
    analysts already heard, and the debate ends on its own reason
    (``routing.LEDGER_STATED``). Each line once. Linear in the lines, the
    claims they name and the ledger.
    """
    names = list(agent_names) or [str(k) for k in isr_reports]
    entries = _ledger_counts_by_id(ledger)
    heard = fact_atoms(told)
    found: list[tuple[str, tuple[str, ...]]] = []
    if not heard:
        return found
    for text in dict.fromkeys(str(line) for line in lines):
        counts = _line_counts(text, names, entries, isr_reports)
        if counts.answered and counts.atoms <= heard:
            found.append((text, counts.said))
    return found


# The head of the lines the next mediation is shown as stated and told.
LEDGER_STATED_HEAD = (
    "The ledger states every count these blocking lines of the last mediation state, and "
    "the analysts they name were told those counts in an earlier round:"
)


def ledger_stated_sentence(line: str, facts: Sequence[str]) -> str:
    """The run's record of one blocking line the ledger states, told before."""
    return f'Stated by the ledger and told to the analysts before: "{line}": {"; ".join(facts)}.'


def with_ledger_stated(text: str, sentences: Sequence[str]) -> str:
    """``text`` with the stated-and-told lines after it under their head, or as it was."""
    said = [str(s) for s in sentences if str(s).strip()]
    if not said:
        return text
    block = "\n".join([LEDGER_STATED_HEAD, *(f"- {s}" for s in said)])
    return f"{text}\n\n{block}" if text else block


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
        # The [analysts: ...] field is no part of the mark, wherever it stands.
        marked = _ANALYSTS_FIELD.sub(" ", text)
        kinds = {_kind(m) for m in _ANY_MARK.finditer(marked)}
        match = _MARK.search(marked)
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
                    unread=bool(_MARK_OPENING.search(marked)),
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


# What separates two names in the field.
_NAME_SEPARATOR = re.compile(r"\s*(?:,|;|&|\band\b)\s*", re.IGNORECASE)
# The word a report heading closes a name with.
_HEADING_WORD = "_analyst"
# An analyst key, its characters and its length, as the configuration admits one.
_AGENT_KEY = re.compile(AGENT_KEY_PATTERN)

# Why a revision round asked every analyst, as its record says.
BLOCK_NOT_READ_NOTE = (
    "The mediator's final CONTRADICTIONS: block was not read; every analyst was asked to revise."
)
ANALYSTS_FIELD_MISSING_NOTE = (
    "A blocking line of the mediator's final CONTRADICTIONS: block named no analyst in an "
    "[analysts: ...] field; every analyst was asked to revise."
)


def _readable_name(written: str) -> str | None:
    """A name from the field as an analyst key, where it can be one, or ``None``.

    Read as ``resolve_analyst`` reads it (case, spaces, hyphens and
    underscores alike) and kept only where it fits the analyst-key pattern,
    its characters and its length (``core.config.AGENT_KEY_PATTERN``).
    """
    key = _key(written)
    return key if _AGENT_KEY.fullmatch(key) else None


def analysts_field_unknown_note(written: Sequence[str]) -> str:
    """Why a round asked every analyst: blocking lines named names outside the debate.

    It counts the distinct names, quotes each distinct one that reads as an
    analyst key once, in that form, and counts the ones that cannot be read
    as one, so no name is quoted whole and the sentence grows only with the
    distinct analyst keys written.
    """
    names = dict.fromkeys(str(w) for w in written)
    readable: dict[str, None] = {}
    unreadable = 0
    for name in names:
        key = _readable_name(name)
        if key is None:
            unreadable += 1
        else:
            readable[key] = None
    quoted = f": {', '.join(repr(k) for k in readable)}" if readable else ""
    unread = f"; {unreadable} of them cannot be read as an analyst name" if unreadable else ""
    return (
        "The blocking lines of the mediator's final CONTRADICTIONS: block named "
        f"{len(names)} name(s) in their [analysts: ...] field that are no analyst of this "
        f"debate{quoted}{unread}; every analyst was asked to revise."
    )


def read_analysts_field(line: str) -> list[str] | None:
    """The names a line's ``[analysts: ...]`` fields hold, as written, or ``None``.

    ``None`` is a line with no such field, or with fields that hold no name.
    """
    names: dict[str, None] = {}
    for match in _ANALYSTS_FIELD.finditer(str(line)):
        for part in _NAME_SEPARATOR.split(match.group("names")):
            name = part.strip().strip("*_`'\"").strip()
            if name:
                names[name] = None
    return list(names) or None


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
    unknown: dict[str, None] = {}
    for line in blocking:
        written = read_analysts_field(line)
        if written is None:
            return None, ANALYSTS_FIELD_MISSING_NOTE
        for name in written:
            found = resolve_analyst(name, participants)
            if found is None:
                unknown[name] = None
            else:
                named.add(found)
    if unknown:
        return None, analysts_field_unknown_note(list(unknown))
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


def contested_input(
    name: str,
    finding: str,
    blocking: Sequence[str],
    participants: Sequence[str],
    reports: Mapping[str, str],
    labels: Mapping[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    """``(mediator feedback, peer reports)`` for a named analyst's revision.

    The feedback is the mediation's finding with its listed lines cut to the
    blocking lines whose field names ``name``; a finding not laid out as the
    mediation writes it is passed whole. The lines themselves are kept whole,
    with every claim number and ledger id they cite.

    The peers shown are the ones those lines name in their field, and every
    peer, or other analyst whose report ``reports`` holds, whose key or label
    (``labels``) the lines write, in any case or form:
    a peer the prose may mean is shown rather than left out. Each is shown
    exactly as a round that asks every analyst shows it, its answer in force
    from ``reports`` whole, in ``reports``' order; no claim is picked out of it.
    """
    mine = points_naming(name, blocking, participants)
    head_at = finding.rfind(_LISTED_HEAD)
    tail_at = finding.rfind(_CONFIDENCE_TAIL)
    if 0 <= head_at < tail_at:
        feedback = f"{finding[:head_at]}{_LISTED_HEAD}{'; '.join(mine)}{finding[tail_at:]}"
    else:
        feedback = finding
    spellings = {
        str(p): [
            _name_pattern(spelling)
            for spelling in dict.fromkeys([str(p), str((labels or {}).get(str(p)) or "")])
            if spelling.strip()
        ]
        # Every report a round shows, a participant's or not, as dev shows it.
        for p in dict.fromkeys([*map(str, participants), *map(str, reports)])
    }
    shown: set[str] = set()
    for line in mine:
        shown.update(
            found
            for written in (read_analysts_field(line) or [])
            if (found := resolve_analyst(written, participants)) is not None
        )
        shown.update(
            peer for peer, patterns in spellings.items() if any(p.search(line) for p in patterns)
        )
    return feedback, {k: v for k, v in reports.items() if k != name and str(k) in shown}


# The words of a listed line once its fields, its mark and its numbers are read
# apart: compared only for a line that cites, places and counts nothing.
_WORDS = re.compile(r"[a-z0-9]+")
_HEX_VALUE = re.compile(r"\b0x[0-9a-fA-F]+\b")


@dataclass(frozen=True)
class PointKey:
    """What a contested point is about, read from its line alone.

    The analysts its ``[analysts: ...]`` field names, the ledger ids it cites,
    the hex values and the decimal numbers it writes (claim numbers aside: a
    revision renumbers claims), and, for a line that holds none of those,
    its words. Two lines with one key are one point however the mediator
    worded it the second time.
    """

    analysts: tuple[str, ...]
    entries: tuple[str, ...]
    hexes: tuple[int, ...]
    numbers: tuple[int, ...]
    words: tuple[str, ...] = ()


def _field_key(name: str) -> str:
    key = _key(name)
    return key[: -len(_HEADING_WORD)] if key.endswith(_HEADING_WORD) else key


def point_key(line: str) -> PointKey:
    """The ``PointKey`` of one listed line. Linear in the line."""
    text = str(line)
    named = tuple(sorted({_field_key(n) for n in read_analysts_field(text) or [] if _key(n)}))
    body = _ANY_MARK.sub(" ", _ANALYSTS_FIELD.sub(" ", text))
    entries = tuple(sorted({i.lower() for i in _ENTRY_ID.findall(body)}))
    hexes = tuple(sorted({int(h, 16) for h in _HEX_VALUE.findall(body)}))
    bare = _CLAIM_NUMBERS.sub(" ", _HEX_VALUE.sub(" ", _ENTRY_ID.sub(" ", body)))
    numbers = tuple(sorted({int(n) for n in _NUMBER.findall(bare)}))
    words: tuple[str, ...] = ()
    if not (entries or hexes or numbers):
        words = tuple(_WORDS.findall(bare.lower()))
    return PointKey(analysts=named, entries=entries, hexes=hexes, numbers=numbers, words=words)


# How much of the shorter line's content words the other has to hold for two
# lines with one key to be one point (the overlap coefficient of their word sets).
SAME_POINT_WORDS_SHARE = 0.5
# Words every listed line writes and that say nothing of its point.
_FRAME_WORDS = frozenset({"analyst", "analysts", "claim", "claims", "says", "said", "states"})


def content_words(line: str) -> frozenset[str]:
    """The words of four letters or more a listed line writes about its point.

    Its field, its mark, its ledger ids, hex values and numbers are left out,
    and so are the names its field gives and the words every line writes.
    """
    text = str(line)
    named = {part for n in read_analysts_field(text) or [] for part in _key(n).split("_")}
    body = _ANY_MARK.sub(" ", _ANALYSTS_FIELD.sub(" ", text))
    bare = _HEX_VALUE.sub(" ", _ENTRY_ID.sub(" ", body)).lower()
    return frozenset(
        word
        for word in _WORDS.findall(bare)
        if len(word) >= 4 and not word.isdigit() and word not in named and word not in _FRAME_WORDS
    )


def _one_point(a: frozenset[str], b: frozenset[str]) -> bool:
    if not a or not b:
        return a == b
    return len(a & b) / min(len(a), len(b)) >= SAME_POINT_WORDS_SHARE


def same_points(before: Sequence[str], after: Sequence[str]) -> bool:
    """Whether two mediations' blocking lines are the same contested points.

    Each line is read by ``point_key`` and its content words
    (``content_words``). Two lines are one point when their keys are equal and
    their content words overlap by ``SAME_POINT_WORDS_SHARE``: a resolved point
    replaced by a new one over the same entry is a change. The same points,
    none resolved and none new, are the same; two empty lists are no contested
    point and are not. Linear in the lines: lines of one key are paired in the
    order of their words, once.
    """
    if not before or not after or len(before) != len(after):
        return False
    groups: dict[PointKey, list[frozenset[str]]] = {}
    for line in before:
        groups.setdefault(point_key(line), []).append(content_words(line))
    others: dict[PointKey, list[frozenset[str]]] = {}
    for line in after:
        others.setdefault(point_key(line), []).append(content_words(line))
    if set(groups) != set(others):
        return False
    for key, words in groups.items():
        theirs = others[key]
        if len(words) != len(theirs):
            return False
        order = sorted(words, key=lambda w: sorted(w))
        their_order = sorted(theirs, key=lambda w: sorted(w))
        if not all(_one_point(a, b) for a, b in zip(order, their_order, strict=True)):
            return False
    return True


# The head of the places a revision round is told, after the ledger's counts.
PLACE_FACTS_HEAD = "The run's record of the functions the lines naming you name:"
# The words a place fact uses for a function the ledger holds no listing of.
NO_LISTING = "the ledger holds no listing of it"
# What an analyst with tools is told beside a function the ledger never listed.
PLACE_READ_OFFER = (
    "A function the ledger holds no listing of can be read in this round with your tools that "
    "take an address; what you keep, correct or withdraw about it is yours to decide."
)


def _hex_text(value: int) -> str:
    return f"{value:#x}"


def place_facts(
    lines: Sequence[str],
    isr_reports: Mapping[str, Any],
    ledger: Iterable[Any],
    agent_names: Iterable[str],
) -> list[str]:
    """One sentence per listed line naming a function the run knows, and whether it was read.

    The places a line names are the addresses it writes and the addresses the
    claims it names write (claim, evidence line). A place is a function the
    run knows: a row of the function index, or a function a decompile or
    disassembly call listed (``function_map.build_function_map`` over the
    whole ledger); an offset and its virtual address are one function where
    an image base the run read joins them. For each, the sentence says
    whether the ledger holds a listing of it, and which entries hold it. An
    address that is no function the run knows is not named. Never raises on
    a line it cannot read; linear in the lines, the claims they name and the
    ledger.
    """
    from maljan.agents.function_map import build_function_map
    from maljan.pipeline.validation import _addresses_written
    from maljan.schemas.evidence import LedgerEntry

    entries: list[Any] = []
    for row in ledger or ():
        if isinstance(row, Mapping):
            try:
                row = LedgerEntry.model_validate(row)
            except Exception:  # noqa: BLE001 — one unreadable row is not a lost fact
                continue
        entries.append(row)
    try:
        found = build_function_map(entries, None, [])
    except Exception:  # noqa: BLE001 — no map is no fact
        return []
    bases = tuple(found.image_bases)
    # Every spelling of each known function, offset and virtual address alike.
    listed: dict[int, tuple[str, ...]] = {}
    for visited in found.visited:
        if visited.address is None:
            continue
        held = tuple(dict.fromkeys([*visited.decompiled, *visited.listed]))
        for key in (visited.address, *(visited.address - b for b in bases if visited.address >= b)):
            listed.setdefault(key, held)
    indexed = {offset for offset, _rank in found.index_unvisited} | {
        e.address for e in found.visited if e.indexed and e.address is not None
    }
    indexed_keys: set[int] = set()
    for offset in indexed:
        indexed_keys.update((offset, *(offset + b for b in bases)))
    index_entry = found.index_entry

    def spellings(address: int) -> tuple[int, ...]:
        return (address, *(address - b for b in bases if address >= b))

    names = list(agent_names) or [str(k) for k in isr_reports]
    facts: list[str] = []
    for line in lines:
        text = str(line)
        try:
            said = [text]
            for name, numbers in _claims_named(text, names):
                claims = _claims_of(isr_reports, name)
                for number in numbers:
                    place = _claim_place(number, len(claims))
                    if place is not None:
                        claim = claims[place]
                        said.append(
                            f"{getattr(claim, 'claim', '') or ''} "
                            f"{getattr(claim, 'evidence_ref', '') or ''}"
                        )
            parts: list[str] = []
            seen: set[int] = set()
            for address in (a for part in said for a in _addresses_written(part)):
                keys = spellings(address)
                if seen.intersection(keys):
                    continue
                read = next((listed[k] for k in keys if k in listed), None)
                known = read is not None or any(k in indexed_keys for k in keys)
                if not known:
                    continue
                seen.update(keys)
                if read is not None:
                    parts.append(f"{_hex_text(address)} is listed in {', '.join(read)}")
                else:
                    where = f" [{index_entry}]" if index_entry else ""
                    parts.append(
                        f"{_hex_text(address)} is a function of the run's function index{where}, "
                        f"and {NO_LISTING}"
                    )
        except Exception:  # noqa: BLE001 — a line that cannot be read gets no fact
            continue
        if parts:
            facts.append(f'For the line "{text}": {"; ".join(parts)}.')
    return facts


def names_an_unlisted_place(facts: Iterable[str]) -> bool:
    """Whether any of these place facts names a function the ledger holds no listing of."""
    return any(NO_LISTING in str(f) for f in facts)


def with_place_facts(directive: str, facts: Sequence[str], *, can_read: bool) -> str:
    """The revision directive with the place facts after it, or as it was.

    An analyst with tools is told, beside a function the ledger never listed,
    that it can read it in this round; nothing is adopted or rejected for it.
    """
    said = [str(f) for f in facts if str(f).strip()]
    if not said:
        return directive
    block = [PLACE_FACTS_HEAD, *(f"- {f}" for f in said)]
    if can_read and names_an_unlisted_place(said):
        block.append(PLACE_READ_OFFER)
    text = "\n".join(block)
    return f"{directive}\n\n{text}" if directive else text


def place_facts_for(name: str, facts: Iterable[str], participants: Sequence[str]) -> list[str]:
    """The place facts the analyst ``name`` is told: those whose line names it in its field.

    A fact quotes its line whole, so the line's ``[analysts: ...]`` field is
    read from the fact. A line with no field is put to every analyst, as a
    round that cannot read the names asks every analyst.
    """
    found: list[str] = []
    for fact in facts:
        written = read_analysts_field(str(fact))
        if written is None or any(resolve_analyst(w, participants) == name for w in written):
            found.append(str(fact))
    return found


def tools_taking_an_address(tools: Iterable[Any]) -> list[str]:
    """The names of the tools whose declared arguments take a function's address.

    Read from each tool's own argument schema, by the argument its
    declaration names for an address and the shared list after it
    (``core.undeclared_tools.address_arguments``): what a tool can be asked is
    what it declares, whichever server serves it. A field named for a code
    address (``core.undeclared_tools.named_as_address``) counts only for a tool
    whose answer is a code listing, so a reputation lookup taking
    ``ip_address`` is never listed.
    """
    from maljan.agents.tool_pinning import declared_facts_of
    from maljan.core.undeclared_tools import address_arguments, code_kind

    names: list[str] = []
    for tool in tools or ():
        fields = getattr(getattr(tool, "args_schema", None), "model_fields", None)
        if not isinstance(fields, dict):
            continue
        facts = declared_facts_of(tool)
        # A field read by its name only for a tool whose answer is a code listing.
        offered = fields if code_kind(facts, getattr(tool, "name", "")) else ()
        taking = {name.lower() for name in address_arguments(facts, offered)}
        if any(str(field).strip().lower() in taking for field in fields):
            names.append(str(getattr(tool, "name", "") or ""))
    return [n for n in names if n]
