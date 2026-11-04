"""The ledger's counts for the contradictions a mediator lists, and the mediator's own marks.

The mediator's final ``CONTRADICTIONS:`` block decides whether the analysts
revise. The platform decides nothing about a line's content. It does these
things:

- **states facts**: for a listed line whose cited ledger entries (cited by
  the line itself, or by a claim the line names) hold, in a field whose name
  says count or total, a number the line itself states, it states every such
  value, also when two entries disagree; the length of a list field only
  where its key names the noun the line counts with that number ("0 hits"
  for ``matches``). No call is made for them: they ride on the calls the
  debate makes anyway, the revision directive of the analysts the line names
  and the next mediation's prompt;
- **states rule matches**: when listed lines cite a rule-match answer
  (``core.rule_matches``: read by its declaration, or by its shape where its
  tool declares no kind) and speak of rules, it states every such answer of
  the ledger once, with where it came from and what matched, "0 rule
  matches of 31 rules run" included, so two rule sets that disagree are both
  heard, whichever one a line cites. The fact is kept apart from the count
  facts: no count is read from it, and the report leaves it out;
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
  name: of each peer, the claims the lines cite by number, quoted from its
  answer in force, or its whole report where they cannot be, with the
  reason recorded (``contested_input``). A blocking line without the field,
  or naming no analyst of the debate, leaves the names unread and the round
  asks every analyst.

A size or a time is not a count: keys naming seconds, milliseconds, bytes or a
size are left out.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, NamedTuple

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
# written ``[ev_0021]``. Read from its bracket: spaces or emphasis before it
# are no part of it, and a search starting at each of them read the run
# again, which made a long run of spaces quadratic. Read possessively: a
# reason whose bracket never closes is read once, not once per split of it.
_REASON = r"(?:[^\[\]]++|\[[^\[\]]*+\])*+"
_MARK = re.compile(
    r"\[\s*+(?P<kind>not\s+blocking|blocking)\s*(?::(?P<reason>" + _REASON + r"))?\]"
    r"[*_`]*\s*\.?\s*$",
    re.IGNORECASE,
)
# Any mark the line holds, wherever it stands: two of different kinds conflict.
_ANY_MARK = re.compile(
    r"\[\s*(?P<kind>not\s+blocking|blocking)\s*(?::" + _REASON + r")?\]", re.IGNORECASE
)
# The carried-or-new mark (``_LINE_MARK``) as a part of a pattern.
_CARRIED_OR_NEW = r"\[\s*+(?:carried\s*+:\s*+L?\s*+\d{1,9}\s*+|new\s*+)\]"
# The mediator's mark with a reason, and with a reason or none.
_REASONED_MARK = r"\[\s*+(?:not\s+blocking|blocking)\s*+:" + _REASON + r"\]"
_ANY_MARK_PART = r"\[\s*+(?:not\s+blocking|blocking)\s*(?::" + _REASON + r")?\]"


def _marks_after_field(mark: str, emphasis: str = "") -> str:
    """The marks written right after a line's field: ``mark`` or the carried-or-new mark.

    The one fragment both readers of them compose (``_FIELD_MARKS`` for the
    line's mark, ``_MARKS_AFTER_FIELD`` for the claim numbers after them), each
    mark with any ``emphasis`` around it.
    """
    return r"(?:\s*+" + emphasis + r"(?:" + mark + r"|" + _CARRIED_OR_NEW + r")" + emphasis + r")++"


# A line's marks written right after its opening [analysts: ...] field, before
# its text, with any emphasis around the field and each mark: a mark there,
# with only other marks or the carried-or-new mark beside it, is the line's
# mark as one that ends the line is.
_FIELD_MARKS = re.compile(
    r"^[\s*_`]*+(?:(?:[-*•]|\d+[.)])\s+)?[*_`]*+\[\s*analysts?\s*:[^\[\]]*\][*_`]*+"
    r"(?P<marks>" + _marks_after_field(_ANY_MARK_PART, r"[*_`]*+") + r")",
    re.IGNORECASE,
)
_FIELD_MARK = re.compile(
    r"\[\s*+(?P<kind>not\s+blocking|blocking)\s*(?::(?P<reason>" + _REASON + r"))?\]",
    re.IGNORECASE,
)
# What a mark opens with: a line that holds it and no mark that reads was
# written a mark the parser could not read.
_MARK_OPENING = re.compile(r"\[\s*(?:not\s+)?blocking\b", re.IGNORECASE)
# The [analysts: ...] field opening a line, after any list marker or emphasis.
# A quoted line is never one.
_LINE_FIELD_OPEN = re.compile(
    r"^[\s*_`]*+(?:(?:[-*•]|\d+[.)])\s+)?[*_`]*+\[\s*analysts?\s*:", re.IGNORECASE
)

# The field the mediator writes on a listed line: the analysts who must
# revise over it, by the names their reports are headed with.
_ANALYSTS_FIELD = re.compile(r"\[\s*analysts?\s*:(?P<names>[^\[\]]*)\]", re.IGNORECASE)

# The mark the mediator writes on a blocking line after a revision round: the
# last mediation's line it raises again (``[carried: L2]``, by the number the
# round's record gave it), or a point none of those lines raised (``[new]``).
# No part of the point: it is read apart from the line's field, its words and
# its numbers.
_LINE_MARK = re.compile(
    r"\[\s*+(?:carried\s*+:\s*+L?\s*+(?P<number>\d{1,9})\s*+|new\s*+)\]", re.IGNORECASE
)


def without_line_mark(line: str) -> str:
    """``line`` with its carried-or-new mark (``_LINE_MARK``) taken out, or as it was."""
    return _LINE_MARK.sub(" ", str(line))


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
    return [
        (name, re.findall(r"\d+", numbers.group(1)))
        for name, numbers in _claim_numbers_named(line, agent_names)
    ]


def _claim_numbers_named(line: str, agent_names: Iterable[str]) -> list[tuple[str, re.Match[str]]]:
    """``(agent, the claim numbers' match)`` for each analyst the line names with claim numbers."""
    names = sorted({str(n) for n in agent_names if str(n).strip()}, key=len, reverse=True)
    # The characters a name already read covers: a match over any of them is
    # inside a longer name. One name's matches never overlap each other, so
    # each name looks at each character at most once.
    taken = bytearray(len(line))
    found: list[tuple[str, re.Match[str]]] = []
    for name in names:
        for match in _name_pattern(name).finditer(line):
            start, end = match.span()
            if taken.find(1, start, end) != -1:
                continue
            taken[start:end] = b"\x01" * (end - start)
            numbers = _CLAIM_NUMBERS.match(line, match.end())
            if numbers is not None:
                found.append((name, numbers))
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
    """The analyst's claims by claim block, one per block, so "claim N" is block N.

    A block whose TECHNIQUE line listed several ids is read as one claim per
    id, each with the block's sentence and evidence
    (``validation.claim_block_indexes``); the summaries the mediator reads and
    the report number it once, and so does this.
    """
    from maljan.pipeline.validation import claim_block_indexes

    for key, isr in isr_reports.items():
        if str(key).lower() == name.lower():
            claims = list(getattr(isr, "claims", None) or [])
            firsts: dict[int, Any] = {}
            for block, claim in zip(claim_block_indexes(claims), claims, strict=True):
                firsts.setdefault(block, claim)
            return list(firsts.values())
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
    ledger = list(ledger or ())
    entries = _ledger_counts_by_id(ledger)
    matched = _rule_match_entries(ledger)
    facts: list[str] = []
    for line in lines:
        text = str(line)
        stated = _line_counts(text, names, entries, isr_reports).said
        if stated:
            facts.append(f'For the line "{text}": {"; ".join(stated)}.')
    rules = _rule_match_fact([str(line) for line in lines], names, isr_reports, matched)
    if rules:
        facts.append(rules)
    return facts


# The most rule-match results one fact names (answers that say one thing are
# one), and the most rule names it gives one result; the rest are counted.
_RULE_FACT_ENTRIES = 12
_RULE_FACT_NAMES = 10
# A line about rules says so in a word, or names one of the rules or tools.
_RULE_WORD = re.compile(r"\b(?:rules?|signatures?)\b", re.IGNORECASE)


def _rule_match_entries(ledger: Sequence[Any]) -> list[Any]:
    """Every rule-match answer of the ledger, in ledger order (``core.rule_matches``)."""
    from maljan.core.rule_matches import rule_matches_of

    found = []
    for entry in ledger:
        try:
            held = rule_matches_of(entry)
        except Exception:  # noqa: BLE001 — an entry that cannot be read holds no match
            held = None
        if held is not None and held.entry_id:
            found.append(held)
    return found


def _about_rules(line: str, cited: Sequence[Any]) -> bool:
    """Whether a line citing rule-match answers speaks of rules: a rule word, rule or tool name."""
    if _RULE_WORD.search(line):
        return True
    words = {w.lower() for w in re.findall(r"[\w.:\-]+", line)}
    for held in cited:
        named = {*held.rules, held.tool, held.source}
        if any(name and name.lower() in words for name in named):
            return True
    return False


def _same_answer(held: Any) -> tuple[Any, ...]:
    """What makes two rule-match answers say one thing: one tool, one origin, one result."""
    return (held.tool, held.server, held.source, held.declared, held.rules, held.rule_count)


def _rule_match_part(group: Sequence[Any]) -> str:
    """Answers that say one thing, as a fact states them: their entries, origin and matches."""
    held = group[0]
    origin = [f"tool {held.tool}"] if held.tool else []
    if held.server:
        origin.append(f"server {held.server}")
    if held.declared:
        origin.append(f"declared {held.source}" if held.source else "declared")
    else:
        origin.append("read from its answer's shape")
    ids = ", ".join(each.entry_id for each in group)
    count = len(held.rules)
    said = f"entr{'ies' if len(group) > 1 else 'y'} {ids} ({', '.join(origin)}) "
    said += f"{'each hold' if len(group) > 1 else 'holds'} {count} rule match"
    said += "" if count == 1 else "es"
    if held.rule_count is not None:
        said += f" of {held.rule_count} rules run"
    if held.rules:
        tally: dict[str, int] = {}
        for rule in held.rules:
            tally[rule] = tally.get(rule, 0) + 1
        shown = [f"{rule} ({n})" if n > 1 else rule for rule, n in tally.items()]
        rest = len(shown) - _RULE_FACT_NAMES
        said += ": " + ", ".join(shown[:_RULE_FACT_NAMES])
        said += f" and {rest} more rules" if rest > 0 else ""
    return said


def _rule_match_fact(
    lines: Sequence[str],
    names: Sequence[str],
    isr_reports: Mapping[str, Any],
    matched: Sequence[Any],
) -> str:
    """Every rule-match answer of the ledger, once, for the lines that cite one and speak of rules.

    A line about a rule match cites one answer, the side it argues from; the
    others may hold another rule set's matches, or none. Each answer is
    stated with where it came from (its tool and server, and whether its
    declaration or its shape was read), so contradictory rule sets are both
    heard; answers that say one thing (one tool, origin and result) are
    stated once with every entry id. One fact per mediation, quoting every
    such line (so a revision told the facts naming its analyst hears it),
    opening with :data:`~maljan.core.rule_matches.RULE_FACT_HEAD`, which
    keeps it apart from the count facts. ``""`` when no line is such a line.
    Never raises.
    """
    from maljan.core.rule_matches import RULE_FACT_HEAD

    if not matched:
        return ""
    try:
        about: list[str] = []
        cited_ids: set[str] = set()
        for text in dict.fromkeys(lines):
            bare = without_line_mark(text)
            ids = set(_cited_ids(bare, names, isr_reports))
            own = [held for held in matched if held.entry_id in ids]
            if own and _about_rules(bare, own):
                about.append(text)
                cited_ids |= ids
        if not about:
            return ""
        cited = [held for held in matched if held.entry_id in cited_ids]
        groups: dict[tuple[Any, ...], list[Any]] = {}
        for held in matched:
            groups.setdefault(_same_answer(held), []).append(held)
        # The results a cited answer holds always, then the others in ledger
        # order, up to the bound.
        holds_cited = {_same_answer(held) for held in cited}
        room = max(0, _RULE_FACT_ENTRIES - len(holds_cited))
        kept = holds_cited | set([key for key in groups if key not in holds_cited][:room])
        parts = [_rule_match_part(group) for key, group in groups.items() if key in kept]
        rest = sum(len(group) for key, group in groups.items() if key not in kept)
        if rest > 0:
            parts.append(f"and {rest} more rule-match entries")
        quoted = "; ".join(f'"{text}"' for text in about)
        return f"{RULE_FACT_HEAD} {quoted}: {'; '.join(parts)}."
    except Exception:  # noqa: BLE001 — lines that cannot be read get no fact
        return ""


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


def _cited_ids(text: str, names: Sequence[str], isr_reports: Mapping[str, Any]) -> list[str]:
    """The ledger ids a line cites: its own, then those of the claims it names, each once."""
    cited = list(dict.fromkeys(_ENTRY_ID.findall(text)))
    for name, claim_numbers in _claims_named(text, names):
        claims = _claims_of(isr_reports, name)
        for number in claim_numbers:
            place = _claim_place(number, len(claims))
            if place is not None:
                ref = str(getattr(claims[place], "evidence_ref", "") or "")
                cited.extend(i for i in _ENTRY_ID.findall(ref) if i not in cited)
    return cited


def _line_counts(
    text: str,
    names: Sequence[str],
    entries: Mapping[str, tuple[str, Any]],
    isr_reports: Mapping[str, Any],
) -> _LineCounts:
    """The counts the entries a line cites state that the line states too. Never raises."""
    try:
        text = without_line_mark(text)
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
        cited = _cited_ids(text, names, isr_reports)
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
    from maljan.core.rule_matches import is_rule_fact

    atoms: set[tuple[str, str]] = set()
    for fact in facts:
        text = str(fact)
        # The rule-match fact states no count; the lines it quotes are the
        # mediator's words.
        if is_rule_fact(text):
            continue
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


def _mark_after_field(text: str) -> re.Match[str] | None:
    """The mark written right after the line's opening field (``_FIELD_MARKS``), or None.

    Of several, the first that gives a reason; a second of the other kind is a
    conflict the caller reads first.
    """
    opened = _FIELD_MARKS.match(text)
    if opened is None:
        return None
    found = list(_FIELD_MARK.finditer(text, opened.start("marks"), opened.end("marks")))
    return next(
        (m for m in found if (m.group("reason") or "").strip()), found[0] if found else None
    )


def read_marks(lines: Iterable[str]) -> list[Mark]:
    """The mediator's mark on each line; an unmarked line blocks.

    - A mark ends its line, or stands right after the line's opening
      ``[analysts: ...]`` field (with only other marks or the carried-or-new
      mark between them, emphasis around any of them), and gives a reason,
      which may cite a ledger id in brackets. A reasoned mark after the field
      is the line's over a bare one ending it.
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
        # Nor is the carried-or-new mark.
        marked = without_line_mark(_ANALYSTS_FIELD.sub(" ", text))
        kinds = {_kind(m) for m in _ANY_MARK.finditer(marked)}
        match = _MARK.search(marked)
        if match is None or not (match.group("reason") or "").strip():
            # A reasoned mark after the field is the line's over a bare one
            # ending it; a bare one is read as before. Not where the line also
            # opens a mark that cannot be read: such a line blocks.
            after = _mark_after_field(text)
            if after is not None and _MARK_OPENING.search(_ANY_MARK.sub(" ", marked)) is None:
                match = after
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


def carries_line_field(line: str) -> bool:
    """Whether a line holds a field every listed line is asked for.

    The ``[analysts: ...]`` field the line opens with (after a list marker or
    emphasis; a quoted line is never one), or a ``[blocking ...]`` or ``[not blocking ...]``
    mark that ends it. Prose between two lists, or after one, holds neither,
    even where it names a field or a mark inside a sentence.
    """
    text = str(line)
    if _LINE_FIELD_OPEN.match(text):
        return True
    # The carried-or-new mark is no field of its own, wherever it stands.
    text = without_line_mark(text)
    if _LINE_FIELD_OPEN.match(text):
        return True
    # Only the last mark opening can end the line: the mark is read from there
    # alone and what follows it checked by hand, as ``_MARK`` reads its end, so
    # a line costs one pass whatever it holds.
    last = None
    for opening in _MARK_OPENING.finditer(text):
        last = opening
    mark = _ANY_MARK.match(text, last.start()) if last is not None else None
    return mark is not None and text[mark.end() :].lstrip("*_`").strip() in ("", ".")


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
    isrs: Mapping[str, Any] | None = None,
    revision_round: int = 0,
) -> tuple[str, dict[str, str]]:
    """``(mediator feedback, peer reports)`` for a named analyst's revision.

    The feedback is the mediation's finding with its listed lines cut to the
    blocking lines whose field names ``name``; a finding not laid out as the
    mediation writes it is passed whole. The lines themselves are kept whole,
    with every claim number and ledger id they cite.

    The peers shown are the ones those lines name in their field, and every
    peer, or other analyst whose report ``reports`` holds, whose key or label
    (``labels``) the lines write, in any case or form:
    a peer the prose may mean is shown rather than left out, in ``reports``'
    order. Without ``isrs`` each is shown exactly as a round that asks every
    analyst shows it, its answer in force from ``reports`` whole.

    With ``isrs``, the answers in force the mediator read, each is a
    :class:`ShownReport`: the claims those lines name of it, quoted from its
    answer in force, and its disputes naming ``name``
    (:func:`peer_excerpt`); or its whole report, with the sentence saying why
    no excerpt was made. ``revision_round`` is the round those sentences name.
    """
    # The places of the lines naming ``name`` among the lines given.
    mine_at = [i for i, line in enumerate(blocking) if points_naming(name, [line], participants)]
    mine = [str(blocking[i]) for i in mine_at]
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
    # Per peer shown, the places of the lines naming it.
    shown: dict[str, list[int]] = {}
    for at, line in zip(mine_at, mine, strict=True):
        for peer in [
            *(
                found
                for written in (read_analysts_field(line) or [])
                if (found := resolve_analyst(written, participants)) is not None
            ),
            *(
                peer
                for peer, patterns in spellings.items()
                if any(p.search(line) for p in patterns)
            ),
        ]:
            places = shown.setdefault(peer, [])
            if at not in places:
                places.append(at)
    peers = {k: v for k, v in reports.items() if k != name and str(k) in shown}
    if isrs is None:
        return feedback, peers
    # Numbered among the blocking lines the round was given, as the
    # sentences name them ("blocking line N").
    refs = contested_refs([str(line) for line in blocking], participants)
    held = {str(k).lower(): v for k, v in isrs.items()}
    return feedback, {
        peer: peer_excerpt(
            name,
            str(peer),
            [refs[at] for at in shown[str(peer)]],
            str(whole or ""),
            held.get(str(peer).lower()),
            spellings.get(name) or [_name_pattern(name)],
            revision_round,
            participants,
        )
        for peer, whole in peers.items()
    }


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
    text = without_line_mark(line)
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
    text = without_line_mark(line)
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


# ---------------------------------------------------------------------------
# The entries a contested line cites, shown to the analysts it names and to
# the next mediation; what the round did on each line, told once
# ---------------------------------------------------------------------------

# Where a place fact's own words begin: after the line it quotes whole.
_FACT_AFTER_LINE = '": '
# A place a fact names, and the entries it says hold its listing.
_LISTED_IN = re.compile(r"(0x[0-9a-fA-F]+) is listed in ((?:ev_\d+(?:, )?)+)")
_PLACE_NAMED = re.compile(r"(0x[0-9a-fA-F]+) is (?:listed in|a function of)")


def _fact_words(fact: str) -> str:
    """The words a place fact says about its line, the line it quotes left out."""
    text = str(fact)
    at = text.rfind(_FACT_AFTER_LINE)
    return text[at + len(_FACT_AFTER_LINE) :] if at >= 0 else ""


def place_facts_for_line(line: str, facts: Iterable[str]) -> list[str]:
    """The place facts stated for ``line`` itself (``place_facts`` quotes it whole)."""
    head = f'For the line "{line}": '
    return [str(f) for f in facts if str(f).startswith(head)]


def line_entry_ids(
    lines: Iterable[str], facts: Iterable[str] = (), *, every_listing: bool = True
) -> list[str]:
    """The ledger ids the lines cite, then the entries their place facts say list a function.

    Lower-cased, each once, in the order first written. A function index a
    fact names a function of is no listing of it and is not one of them.
    With ``every_listing=False`` a function is listed once: one whose listing
    is already among the ids (cited by a line, or listing another function)
    adds none, and any other adds the first entry the fact names for it, so
    a function read twice is not shown twice. Linear in the lines and the
    facts.
    """
    found: dict[str, None] = {}
    for line in lines:
        for entry_id in _ENTRY_ID.findall(without_line_mark(line)):
            found.setdefault(entry_id.lower(), None)
    for fact in facts:
        for match in _LISTED_IN.finditer(_fact_words(fact)):
            listing = [i.lower() for i in _ENTRY_ID.findall(match.group(2))]
            if not every_listing:
                if any(i in found for i in listing):
                    continue
                listing = listing[:1]
            for entry_id in listing:
                found.setdefault(entry_id, None)
    return list(found)


def line_places(line: str, facts: Iterable[str] = ()) -> set[int]:
    """The hex values a line writes and the functions its own place facts name, as numbers."""
    places = {int(h, 16) for h in _HEX_VALUE.findall(without_line_mark(line))}
    for fact in place_facts_for_line(line, facts):
        places.update(int(m.group(1), 16) for m in _PLACE_NAMED.finditer(_fact_words(fact)))
    return places


# The head of the entries a revision shows the analysts a contested line names,
# and what it says of one that does not fit beside the revision.
DEBATE_ENTRIES_HEAD = (
    "The ledger entries the contested lines naming you cite, and the listings of the functions "
    "they name, as recorded, each whole:"
)
DEBATE_ENTRIES_UNFIT = (
    "The ledger holds these entries the lines naming you cite; they do not fit beside this "
    "revision and the entries shown above, so they are not shown here:"
)
# The same for the mediation after a revision round, for the lines the last
# mediation marked blocking.
MEDIATION_ENTRIES_HEAD = (
    "The ledger entries the blocking lines of the last mediation cite, and the listings of "
    "the functions they name, as recorded, each whole; the analysts those lines name were "
    "shown them in the revision round where they fit:"
)
MEDIATION_ENTRIES_UNFIT = (
    "The ledger holds these entries the blocking lines of the last mediation cite; they do "
    "not fit beside this mediation and the entries shown above, so they are not shown here:"
)


def entries_block(
    entries: Mapping[str, str], unfit: Sequence[str] = (), *, mediation: bool = False
) -> str:
    """The entries shown under their head, then the ones named as too large, or ``""``."""
    head, unfit_head = (
        (MEDIATION_ENTRIES_HEAD, MEDIATION_ENTRIES_UNFIT)
        if mediation
        else (DEBATE_ENTRIES_HEAD, DEBATE_ENTRIES_UNFIT)
    )
    lines: list[str] = []
    if entries:
        lines.append(head)
        lines.extend(str(text).rstrip() for text in entries.values())
    if unfit:
        lines.append(f"{unfit_head} {', '.join(unfit)}.")
    return "\n".join(lines)


def fit_entries(
    entries: Mapping[str, str], room: float | None, *, mediation: bool = False
) -> tuple[dict[str, str], list[str]]:
    """``(entries shown, ids named as too large)`` for the characters ``room`` leaves.

    The names of every entry and the head are reserved first, so taking an
    entry in never makes the turn outgrow the room; an entry that does not
    fit beside those shown is named by id. With no room known (``None``)
    every entry is shown. When none fits, none is named either: a line of
    names alone only makes the turn longer. Nothing is cut. Linear in the
    entries.
    """
    if room is None:
        return dict(entries), []
    used = len(entries_block({}, list(entries), mediation=mediation)) + 2
    used += len(entries_block({"": ""}, mediation=mediation)) + 2
    shown: dict[str, str] = {}
    unfit: list[str] = []
    for entry_id, text in entries.items():
        taken = len(str(text).rstrip()) + 1
        if used + taken <= room:
            shown[entry_id] = text
            used += taken
        else:
            unfit.append(entry_id)
    if not shown:
        return {}, []
    return shown, unfit


def with_entries(text: str, block: str) -> str:
    """``text`` with an entries block after it, or as it was."""
    if not block:
        return text
    return f"{text}\n\n{block}" if text else block


def read_line_mark(line: str) -> int | str | None:
    """The carried-or-new mark of a line: the earlier line's number, ``"new"``, or ``None``.

    Two marks that say different things are no mark.
    """
    said: set[int | str] = set()
    for match in _LINE_MARK.finditer(str(line)):
        number = match.group("number")
        said.add(int(number) if number is not None else "new")
    return next(iter(said)) if len(said) == 1 else None


def carried_marks(lines: Iterable[str], earlier: int) -> dict[str, int]:
    """``{line: the earlier line's number}`` for each line marked carried from one of ``earlier``.

    A number outside ``1..earlier`` names no line the mediator was shown and
    is no mark.
    """
    found: dict[str, int] = {}
    for line in lines:
        mark = read_line_mark(line)
        if isinstance(mark, int) and 1 <= mark <= int(earlier):
            found[str(line)] = mark
    return found


def _named_in(line: str, participants: Sequence[str]) -> list[str] | None:
    """The participants a line's field names, or ``None`` for no field or a name not read."""
    written = read_analysts_field(line)
    if written is None:
        return None
    names: list[str] = []
    for name in written:
        found = resolve_analyst(name, participants)
        if found is None:
            return None
        if found not in names:
            names.append(found)
    return names


def line_round_facts(
    lines: Sequence[str],
    facts: Sequence[str],
    asked: Sequence[str],
    revised: Sequence[str],
    shown: Mapping[str, Sequence[str]],
    changed: Any,
    participants: Sequence[str],
    filed: Mapping[str, Sequence[str]] | None = None,
    cited: Any = None,
    carried_valid: Mapping[str, bool] | None = None,
) -> list[dict[str, Any]]:
    """One record per blocking line of the mediation a revision round answered.

    ``named`` is who the line's field names (every analyst asked, for a line
    whose names were not read), ``revised`` the ones of them whose revision
    stood, ``shown`` the entries of the line (``line_entry_ids`` over the
    line and its own place facts) each was shown, and ``changed`` the ones
    ``changed(name, entry ids, places)`` reads as moved (the revision node
    asks whether any claim of its answer changed, ``claim_drops
    .changed_anywhere``). An analyst that filed entries in the round (``filed``)
    read something new and is counted as changed; its claims citing those
    entries are read with the line's. ``entries`` and ``places`` keep what
    the line is about, for the carried mark to be read against.

    Given ``cited``, ``cited_new`` is the analysts named on the line that
    filed entries in the round and whose revised answer has a claim citing
    one of them beside the line's entries or places (``cited(name, filed
    ids, entry ids, places)``): they read something new on the point. Given
    ``carried_valid``, ``carried_valid`` says whether the line's own carried
    mark was one that counts (:func:`valid_carries`). Linear in the lines,
    the analysts and the claims ``changed`` and ``cited`` read.
    """
    out: list[dict[str, Any]] = []
    stood = set(revised)
    own_filed = {n: [str(i).lower() for i in ids or ()] for n, ids in (filed or {}).items()}
    for line in lines:
        text = str(line)
        named = _named_in(text, participants)
        if named is None:
            named = list(asked)
        mine = place_facts_for_line(text, facts)
        ids = line_entry_ids([text], mine)
        places = line_places(text, mine)
        out.append(
            {
                "line": text,
                "named": named,
                "revised": [n for n in named if n in stood],
                "shown": {n: [i for i in shown.get(n, ()) if i in ids] for n in named},
                "changed": [
                    n
                    for n in named
                    if n in stood
                    and (
                        bool(own_filed.get(n)) or changed(n, [*ids, *own_filed.get(n, [])], places)
                    )
                ],
                "entries": ids,
                "places": [_hex_text(p) for p in sorted(places)],
            }
        )
        if cited is not None:
            out[-1]["cited_new"] = [
                n
                for n in named
                if n in stood and own_filed.get(n) and cited(n, own_filed[n], ids, places)
            ]
        if carried_valid is not None:
            out[-1]["carried_valid"] = bool(carried_valid.get(text))
    return out


def carry_shares_point(line: str, fact: Mapping[str, Any], facts_now: Sequence[str] = ()) -> bool:
    """Whether ``line`` shares an entry id or a place with the earlier line ``fact`` records.

    Its own and its place facts' (``facts_now``); a carried mark naming a
    line about other things is read as no mark.
    """
    ids, places = _about(str(line), facts_now)
    earlier_ids = {str(i).lower() for i in fact.get("entries") or []}
    earlier_places = {int(str(p), 16) for p in fact.get("places") or []}
    return bool(ids & earlier_ids or places & earlier_places)


def valid_carries(
    lines: Sequence[str],
    carried: Mapping[str, int],
    record: Mapping[str, Any] | None,
    facts_now: Sequence[str] = (),
) -> dict[str, bool]:
    """Per line, whether its carried mark counts: it names a line ``record`` holds, sharing a point.

    A line not marked carried, or marked from a line the record does not
    hold, is ``False``. Linear in the lines.
    """
    facts = record.get("lines") if isinstance(record, Mapping) else None
    out: dict[str, bool] = {}
    for line in lines:
        number = carried.get(str(line))
        fact = (
            facts[int(number) - 1]
            if isinstance(facts, list) and number is not None and 1 <= int(number) <= len(facts)
            else None
        )
        out[str(line)] = isinstance(fact, Mapping) and carry_shares_point(line, fact, facts_now)
    return out


def _about(line: str, facts: Iterable[str] = ()) -> tuple[set[str], set[int]]:
    """The entry ids and places a line is about: its own, and its own place facts'."""
    mine = place_facts_for_line(line, facts)
    return set(line_entry_ids([line], mine)), line_places(line, mine)


# The head of what the next mediation is told the round did, and what it is asked.
ROUND_FACTS_HEAD = (
    "The run's record of the last revision round, for each blocking line of the last mediation "
    "(numbered as below):"
)
LINE_MARK_RULE = (
    "On each blocking line you list, write [carried: L<number>] right after its "
    "[analysts: ...] field when it raises again the point of that line of the last mediation, "
    "or [new] when it raises a point none of those lines raised."
)


def _names(names: Sequence[str]) -> str:
    return ", ".join(names) if names else "none"


def round_facts_text(record: Mapping[str, Any] | None) -> str:
    """What the next mediation is told the revision round did on each line, or ``""``.

    One line per blocking line of the mediation the round answered, numbered:
    who it named, who revised, the entries of the line each was shown, and
    who changed a claim of its answer; then the
    entries the round filed, by agent, and the question for the
    carried-or-new mark. Linear in the record.
    """
    lines = record.get("lines") if isinstance(record, Mapping) else None
    if not isinstance(lines, list) or not lines:
        return ""
    said = [ROUND_FACTS_HEAD]
    for number, fact in enumerate(lines, start=1):
        if not isinstance(fact, Mapping):
            continue
        named = [str(n) for n in fact.get("named") or []]
        shown = fact.get("shown") or {}
        seen = "; ".join(f"{n}: {_names([str(i) for i in shown.get(n) or []])}" for n in named)
        said.append(
            f'- L{number} "{fact.get("line", "")}": named {_names(named)}; revised '
            f"{_names([str(n) for n in fact.get('revised') or []])}; entries of the line shown "
            f"({seen or 'none'}); changed a claim of its answer in the round: "
            f"{_names([str(n) for n in fact.get('changed') or []])}."
        )
    filed = (record or {}).get("filed") or {}
    by_agent = "; ".join(f"{a}: {', '.join(map(str, ids))}" for a, ids in filed.items() if ids)
    said.append(f"Entries the round filed: {by_agent or 'none'}.")
    said.append(LINE_MARK_RULE)
    return "\n".join(said)


def carried_unmoved(
    lines: Sequence[str],
    carried: Mapping[str, int],
    record: Mapping[str, Any] | None,
    facts_now: Sequence[str] = (),
) -> bool:
    """Whether every blocking line raises again a line of the last mediation nobody moved on.

    Each of ``lines`` must be marked carried (``carried``: the earlier line's
    number in the round's record). A mark counts only where the line shares
    an entry id or a place with the earlier line it names (its own and its
    place facts', ``facts_now`` for this mediation's lines); a mark naming a
    line about other things is read as no mark. Every analyst the line's
    field names must have been named on that earlier line, every analyst the
    earlier line named must have revised in the round, and none of them may
    have changed a claim on it (``line_round_facts``). A line not marked, an
    analyst that has not answered the earlier line yet, or a record without
    the facts is no such line; no line is not either. Linear in the lines.
    """
    facts = record.get("lines") if isinstance(record, Mapping) else None
    if not lines or not isinstance(facts, list) or not facts:
        return False
    participants = [
        *map(str, record.get("revised") or []),  # type: ignore[union-attr]
        *map(str, (record.get("not_revised") or {}).keys()),  # type: ignore[union-attr]
    ]
    for line in lines:
        number = carried.get(str(line))
        if number is None or not 1 <= int(number) <= len(facts):
            return False
        fact = facts[int(number) - 1]
        if not isinstance(fact, Mapping) or not carry_shares_point(line, fact, facts_now):
            return False
        before = {str(n) for n in fact.get("named") or []}
        answered = {str(n) for n in fact.get("revised") or []}
        named = _named_in(str(line), participants)
        if not named or not set(named) <= before or not before <= answered:
            return False
        if fact.get("changed"):
            return False
    return True


def carried_without_new_evidence(
    lines: Sequence[str],
    carried: Mapping[str, int],
    record: Mapping[str, Any] | None,
    facts_now: Sequence[str] = (),
) -> bool:
    """Whether every blocking line raises again, a second time, a point nothing new was read on.

    Each of ``lines`` must be marked carried (``carried``) from a line of the
    last mediation whose own carried mark counted (the record's
    ``carried_valid``, :func:`valid_carries`): the point has been put to the
    analysts in two revision rounds. The mark counts only where the line
    shares an entry id or a place with that earlier line, as in
    :func:`carried_unmoved`; every analyst the line's field names must have
    been named on the earlier line, and every analyst named there must have
    revised in the round. Nothing new may have been read on it: no analyst
    named there cited in its revised answer, beside the line's entries or
    places, an entry it filed in the round (the record's ``cited_new``); the
    line writes no entry id the earlier line did not write; and neither it
    nor its place facts (``facts_now``) reach an entry the round filed
    (``record["filed"]``). A revision that rewrites its claims with nothing
    new to read leaves the point where it was; a function the line names
    that an older listing holds is nothing new. A line not marked, a first
    carry, or a record without those facts is no such line; no line is not
    either. Linear in the lines.
    """
    facts = record.get("lines") if isinstance(record, Mapping) else None
    if not lines or not isinstance(facts, list) or not facts:
        return False
    participants = [
        *map(str, record.get("revised") or []),  # type: ignore[union-attr]
        *map(str, (record.get("not_revised") or {}).keys()),  # type: ignore[union-attr]
    ]
    filed = {
        str(i).lower()
        for ids in ((record.get("filed") or {}).values())  # type: ignore[union-attr]
        for i in ids or ()
    }
    for line in lines:
        number = carried.get(str(line))
        if number is None or not 1 <= int(number) <= len(facts):
            return False
        fact = facts[int(number) - 1]
        if (
            not isinstance(fact, Mapping)
            or fact.get("carried_valid") is not True
            or not isinstance(fact.get("cited_new"), list)
            or fact.get("cited_new")
            or not carry_shares_point(line, fact, facts_now)
        ):
            return False
        ids, _places = _about(str(line), facts_now)
        written = set(line_entry_ids([str(line)]))
        if not written <= set(line_entry_ids([str(fact.get("line") or "")])) or ids & filed:
            return False
        before = {str(n) for n in fact.get("named") or []}
        answered = {str(n) for n in fact.get("revised") or []}
        named = _named_in(str(line), participants)
        if not named or not set(named) <= before or not before <= answered:
            return False
    return True


# Claim numbers written right after a line's [analysts: ...] field, with no
# name before them ("[analysts: X ANALYST] Claims 30 and 62 say ...").
_BARE_CLAIMS = re.compile(
    r"[\s*_`]*+claims?\s*+#?\s*+(\d++(?:\s*+(?:/|,|&|and|\+)\s*+#?\d++)*+)", re.IGNORECASE
)


# "claim(s) N" anywhere on a line, with the words written before it read
# apart (``_short_named``).
_CLAIM_REFERENCE = re.compile(
    r"\bclaims?\s*+#?\s*+(\d++(?:\s*+(?:/|,|&|and|\+)\s*+#?\d++)*+)", re.IGNORECASE
)
_WORD_BEFORE = re.compile(r"[A-Za-z][A-Za-z0-9]*+")
# Words a short form of a name may carry that are no part of the name.
_FILLER_WORDS = frozenset(
    {
        "analyst", "analysts", "the", "s", "to", "all", "in", "as", "of", "and", "versus",
        "per", "its",
    }
)  # fmt: skip
# How long a word of a short form must be to open a part of a name, unless it
# is a whole part ("r2").
_SHORT_WORD_LENGTH = 3


def _short_named(text: str, start: int, participants: Sequence[str]) -> str | None:
    """The one participant the words just before ``start`` name in a short form, or ``None``.

    The mediator writes a peer's claim as "Static R2 claim 3" or "Reverser
    claims 1 and 9": the one, two or three words right before "claim" (the
    nearest that read). Words that name the participant whole ("Static" for
    the static analyst) name it outright; otherwise each word opens a part of
    the participant's name (three letters at least, or a whole part such as
    "r2"), and the form names a participant only when exactly one of all the
    participants fits it. The caller keeps it only for an analyst the line's
    field names.
    """
    before = text[max(0, start - 80) : start]
    tail = re.split(r"[^A-Za-z0-9'\s]", before)[-1]
    words = [w.lower() for w in _WORD_BEFORE.findall(tail) if w.lower() not in _FILLER_WORDS]
    parts = {name: [p for p in re.split(r"[_\-\s]+", name.lower()) if p] for name in participants}
    for size in (3, 2, 1):
        if len(words) < size:
            continue
        chosen = words[-size:]
        whole = [name for name, pieces in parts.items() if pieces == chosen]
        if len(whole) == 1:
            return whole[0]
        fits = [
            name
            for name, pieces in parts.items()
            if all(
                w in pieces
                or (len(w) >= _SHORT_WORD_LENGTH and any(piece.startswith(w) for piece in pieces))
                for w in chosen
            )
        ]
        if len(fits) == 1:
            return fits[0]
    return None


# The most claims a range ("claims 67 to 82") is read as, claim by claim. Of a
# longer range only its first number is named, as before ranges were read;
# the rest is read as no claim and stated (``ClaimNumbers.unplaced``): the
# platform never guesses which claims of it the line means.
CLAIM_RANGE_CAP = 20
# The digits a claim number may have and still be counted (``_claim_place``
# compares longer ones as text and never converts them).
_CLAIM_DIGITS = 6

# The first number of a reference, at the place its numbers start.
_FIRST_CLAIM_NUMBER = re.compile(r"#?\s*+(\d++)")
# One more number of the same reference: after a dash or a range word ("32-34",
# "32 – 34", "17 to 19", "32 through 34"), or after a joiner ("3/4", "3, 4",
# "3 and 4", "3 or 4", "3, 4, and 5", "3 & 4", "3 + 4"), the word "claim"
# written again or not ("claim #3 and claim 4").
_NEXT_CLAIM_NUMBER = re.compile(
    r"\s*+(?:(?P<range>[-–—]|(?:to|through|thru)\b)"
    r"|,\s*+(?:(?:and|or|&)\s*+)?|/|&|and|or\b|\+)"
    r"\s*+(?:(?P<again>claims?)\s*+)?#?\s*+(?P<n>\d++)",
    re.IGNORECASE,
)
# What tells that a number after "claim" written again is another analyst's
# ("claim 3 and claim 4 of the static analyst"): the reference ends before it.
_CLAIM_OF_ANOTHER = re.compile(r"\s*+(?:of|from|by|in)\b", re.IGNORECASE)
# The parenthesis that may name the analyst of a number ("claim 4 (TRIAGE)").
_PARENTHESIS_OPENS = re.compile(r"\s*+\(\s*+")
# A range's last number that goes on as a word or a decimal ("3 to 0x5a").
_NUMBER_GOES_ON = re.compile(r"[0-9A-Za-z_]|\.\d")


@dataclass(frozen=True)
class ClaimNumbers:
    """The claim numbers one reference writes, read from where its numbers start.

    ``numbers`` are the claims it names one by one, as digits: those it
    writes, in order, and each claim inside a range it bounds
    (:data:`CLAIM_RANGE_CAP` claims at most). ``unplaced`` are the parts of
    its ranges read as no claim, ``(first, last)``: the claims after the
    first of a range longer than the cap. ``end`` is where the reference ends
    in the text.
    """

    numbers: tuple[str, ...]
    unplaced: tuple[tuple[str, str], ...]
    end: int


def _as_claim_number(written: str) -> int | None:
    digits = written.lstrip("0")
    return int(digits) if digits and len(digits) <= _CLAIM_DIGITS else None


def _named_next(text: str, at: int, participants: Sequence[str]) -> bool:
    """Whether a parenthesis at ``at`` opens with a participant's name ("(TRIAGE)")."""
    opened = _PARENTHESIS_OPENS.match(text, at)
    return opened is not None and any(
        _name_pattern(name).match(text, opened.end()) for name in participants
    )


def read_claim_numbers(
    text: str, start: int, participants: Sequence[str] = ()
) -> ClaimNumbers | None:
    """The claim numbers a reference writes from ``start`` on (:class:`ClaimNumbers`), or ``None``.

    ``start`` is where a reference's first number is written (the number
    group of "claim(s) N"). The numbers that follow it in the same reference
    are read too, each named by whoever names the first: a list ("3, 4, and
    5", "3 or 4"), the word "claim" written again ("claim #3 and claim 4",
    unless what follows gives the number to someone else, "claim 4 of ..."
    or a participant's name in a parenthesis, "claim 4 (TRIAGE)"), and a
    range ("32-34", "3 - 5", "17 to 19", "32 through 34"), whose every claim
    is named up to :data:`CLAIM_RANGE_CAP` claims. Every number the earlier
    reading read is named as it was: the first number of a longer range
    too, its other claims unplaced. A range that ends below where it starts
    ("3-2 analysts"), that has no first number of its own ("3-5-7", a date in
    a list) or whose last number goes on as a word ends the reference there,
    and is no range. The reader of the merge's reading
    (:func:`read_claim_references`) and of a revision's disputes
    (``revision_merge``). Linear in the reference.
    """
    first = _FIRST_CLAIM_NUMBER.match(text, start)
    if first is None:
        return None
    numbers: list[str] = [first.group(1)]
    unplaced: list[tuple[str, str]] = []
    end = first.end()
    # Whether the number written last may start a range (it ends none).
    single = True
    while (more := _NEXT_CLAIM_NUMBER.match(text, end)) is not None:
        written = more.group("n")
        if more.group("again") and (
            _CLAIM_OF_ANOTHER.match(text, more.end()) or _named_next(text, more.end(), participants)
        ):
            break
        if not more.group("range"):
            numbers.append(written)
            end, single = more.end(), True
            continue
        if not single or _NUMBER_GOES_ON.match(text, more.end()):
            break
        low, high = _as_claim_number(numbers[-1]), _as_claim_number(written)
        if low is None or high is None or high < low:
            break
        if high - low < CLAIM_RANGE_CAP:
            numbers.extend(str(n) for n in range(low + 1, high + 1))
        else:
            unplaced.append((str(low + 1), written))
        end, single = more.end(), False
    return ClaimNumbers(numbers=tuple(numbers), unplaced=tuple(unplaced), end=end)


def _claim_spans(numbers: Sequence[int]) -> str:
    """``1, 3-5, 9`` for ``[1, 3, 4, 5, 9]``."""
    out: list[str] = []
    ordered = sorted(set(numbers))
    start = previous = None
    for number in [*ordered, None]:
        if previous is not None and number == previous + 1:
            previous = number
            continue
        if start is not None:
            out.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = number
    return ", ".join(out)


# Why a reference names no claim.
RANGE_NOT_READ = f"a range of more than {CLAIM_RANGE_CAP} claims"
NO_ANALYST_NAMED = "the platform reads no analyst for it"


@dataclass(frozen=True)
class UnplacedClaims:
    """A claim reference of a blocking mediation line that names no claim.

    Kept only for a line that blocks by a mark that was read, or by having
    none: a line that does not block, or whose mark is not read, withdraws
    nothing by rule and is not stated. ``line`` counts from 1 in the order
    the lines were given, ``marked`` whether the line's blocking mark was
    written, ``analysts`` the participants whose claims it may mean (the one
    it names, for a range; the line's field, or every participant, for
    numbers no analyst is read for), each of their merges stating it;
    ``claims`` the platform's own rendering of its numbers ("claims 2-50",
    "claim 45"), ``why`` the reason it names no claim and ``lowest`` the
    lowest claim number it may mean. Its numbers are never guessed onto a
    claim: no claim is withdrawn by rule on it, and the merge says so.
    """

    line: int
    marked: bool
    analysts: tuple[str, ...]
    claims: str
    why: str
    lowest: int = 0


@dataclass(frozen=True)
class OwnedClaim:
    """A claim number of a blocking line, written for no analyst, read for its owner.

    A "claim N" no analyst is read for ("Claim 35 (and claim 6 of the same
    revision)") is read for the one analyst the line may mean (its field's,
    or any participant where it has none) whose claim N in force shares a
    ledger id or an address with the reference's own clause
    (:func:`clause_tokens`) that no other claim of that answer writes.
    ``line`` counts from 1, ``marked`` whether the line's blocking mark was
    written, ``analyst`` the owner, ``claim`` the number and ``shared`` how
    many such ids and addresses the two share. The claim is carried with the
    line, never withdrawn by rule: the reading is the platform's, not the
    mediator's. Where no candidate's claim, or more than one, has such a
    token, the number stays unplaced (:class:`UnplacedClaims`), as before.
    """

    line: int
    marked: bool
    analyst: str
    claim: int
    shared: int


# A ledger id or an address a line and a claim may share: a hex value of three
# digits or more once its leading zeros are dropped (a small value such as
# 0x1 is no evidence the two are about the same thing).
_LINE_ID = re.compile(r"\bev_\d++\b", re.IGNORECASE)
_LINE_ADDRESS = re.compile(r"\b0x0*+([0-9a-f]{3,})\b", re.IGNORECASE)


def line_tokens(text: str) -> frozenset[str]:
    """The ledger ids and addresses ``text`` writes, lower-cased (``ev_0012``, ``0x401000``)."""
    return frozenset(
        [
            *(m.group(0).lower() for m in _LINE_ID.finditer(text)),
            *("0x" + m.group(1).lower() for m in _LINE_ADDRESS.finditer(text)),
        ]
    )


@dataclass(frozen=True)
class ExpandedNaming:
    """A line that names a claim only by what the earlier reading did not read.

    The earlier reading read a reference's first numbers alone ("claims
    32-34" as claim 32) and no "Claim N" after a mark that follows the line's
    field; a claim the line reaches only so, and cites nowhere else by a
    number that reading read, is named here. ``line`` counts from 1,
    ``reference`` is the platform's rendering of the reference's numbers
    ("claims 32-34"), ``tokens`` the ledger ids and addresses the
    reference's own clause writes (:func:`line_tokens`): from the reference
    to the next reference named for an analyst, a ";" or the end of the
    sentence, never a mark's reason. A blocking line that names a claim only
    so withdraws it by rule only when the claim shares one of them
    (``revision_merge``): a range drawn wider than its point never withdraws
    a claim it does not speak to.
    """

    line: int
    reference: str
    tokens: frozenset[str]


@dataclass(frozen=True)
class ClaimReferences:
    """What the lines of a mediation name by claim number.

    ``named`` is ``{analyst: {claim number: [(line number, blocking), ...]}}``
    (:func:`claims_named_by_lines`); ``unplaced`` each reference that names
    no claim (:class:`UnplacedClaims`), each once, in line order;
    ``expanded`` per analyst and claim the lines that reach it only by the
    newer reading (:class:`ExpandedNaming`); ``owned`` each claim number no
    analyst is written for that is read for its owner (:class:`OwnedClaim`),
    in line order.
    """

    named: dict[str, dict[int, list[tuple[int, bool]]]]
    unplaced: tuple[UnplacedClaims, ...] = ()
    expanded: dict[str, dict[int, tuple[ExpandedNaming, ...]]] = field(default_factory=dict)
    owned: tuple[OwnedClaim, ...] = ()

    def owned_for(self, analyst: str) -> tuple[OwnedClaim, ...]:
        """The claim numbers read for ``analyst`` as their owner, in line order."""
        return tuple(o for o in self.owned if o.analyst == analyst)

    def unplaced_for(self, analyst: str) -> tuple[UnplacedClaims, ...]:
        """The unplaced references that may mean ``analyst``'s claims, in line order.

        Each candidate's merge states the reference, in the same words where
        no analyst is read for it: the run summary keeps each sentence once.
        """
        return tuple(u for u in self.unplaced if analyst in u.analysts)

    def expanded_for(self, analyst: str) -> dict[int, tuple[ExpandedNaming, ...]]:
        """Per claim number of ``analyst``, the lines that reach it only by the newer reading."""
        return dict(self.expanded.get(analyst, {}))


class NamedClaims(dict[int, list[tuple[int, bool]]]):
    """One analyst's ``{claim number: [(line number, blocking), ...]}``, as a plain dict.

    It carries, for the merge (``revision_merge.merge_revision``), the
    references its merge states (``unplaced``) and the claims the lines
    reach only by the newer reading (``expanded``) and the claim numbers read
    for it as their owner (``owned``).
    """

    def __init__(
        self,
        rows: Mapping[int, list[tuple[int, bool]]] | None = None,
        *,
        unplaced: Sequence[UnplacedClaims] = (),
        expanded: Mapping[int, tuple[ExpandedNaming, ...]] | None = None,
        owned: Sequence[OwnedClaim] = (),
    ) -> None:
        super().__init__(rows or {})
        self.unplaced: tuple[UnplacedClaims, ...] = tuple(unplaced)
        self.expanded: dict[int, tuple[ExpandedNaming, ...]] = dict(expanded or {})
        self.owned: tuple[OwnedClaim, ...] = tuple(owned)


class NamedByLines(dict[str, dict[int, list[tuple[int, bool]]]]):
    """``claims_named_by_lines``' answer: a plain dict, a :class:`NamedClaims` per analyst.

    Its keys and rows are the ones the earlier reading gave a line it reads
    alike. ``get`` hands an analyst no line names a claim of the references
    its merge states, as an empty :class:`NamedClaims`, where there are any.
    """

    def __init__(self, references: ClaimReferences) -> None:
        super().__init__(
            {
                name: NamedClaims(
                    rows,
                    unplaced=references.unplaced_for(name),
                    expanded=references.expanded_for(name),
                    owned=references.owned_for(name),
                )
                for name, rows in references.named.items()
            }
        )
        self.references = references

    def get(self, key: str, default: Any = None) -> Any:  # type: ignore[override]
        found = super().get(key)
        if found is not None:
            return found
        stated = self.references.unplaced_for(key)
        return NamedClaims(unplaced=stated) if stated else default


def _range_rendering(first: str, last: str) -> str:
    """Claims of a range read as no claim, in the platform's words: digits only."""
    return f"claims {first.lstrip('0') or '0'}-{last.lstrip('0') or '0'}"


# The mediator's mark wherever it stands on a line, its reason included: a
# "claim N" inside it is its reason, not a reference the line puts to anyone.
_MARK_ANYWHERE = re.compile(
    r"\[\s*+(?:not\s+blocking|blocking)\s*+:" + _REASON + r"\]", re.IGNORECASE
)
# The mediator's marks written right after a line's field, before its text.
_MARKS_AFTER_FIELD = re.compile(_marks_after_field(_REASONED_MARK), re.IGNORECASE)
# Where a reference's clause ends: a ";", or a "." that ends a sentence (one
# an uppercase letter, a ledger id, an address or the end of the line follows).
_CLAUSE_END = re.compile(r";|\.(?=\s*+(?:[A-Z]|ev_|0x|$))")
# The claim numbers the earlier reading read where a reference's numbers start.
_EARLIER_NUMBERS = re.compile(r"\d++(?:\s*+(?:/|,|&|and|\+)\s*+#?\d++)*+", re.IGNORECASE)
# "round-2" or "round 2" right before "claim(s)", after a name or its "'s".
_ROUND_BEFORE = re.compile(r"(?:['’]s)?\s*+round[-\s]*+\d++\s*+$", re.IGNORECASE)


def marks_blanked(text: str) -> str:
    """``text`` with every mark's reason blanked out, one space for one character."""
    masked = text
    for m in _MARK_ANYWHERE.finditer(text):
        start, end = m.span()
        masked = masked[:start] + " " * (end - start) + masked[end:]
    return masked


def clause_tokens(
    text: str, masked: str, at: int, end: int, starts: Sequence[int]
) -> frozenset[str]:
    """The ledger ids and addresses of a reference's own clause (:func:`line_tokens`).

    The clause runs from where the reference's numbers start (``at``) to the
    next reference named for an analyst (``starts``), a ";" or the end of the
    sentence after its numbers (``end``), whichever comes first; it is read
    in ``masked`` (:func:`marks_blanked`), so a mark's reason never counts.
    """
    next_start = min((s for s in starts if s > at), default=len(text))
    ended = _CLAUSE_END.search(text, end)
    clause_end = min(next_start, ended.start() if ended is not None else len(text))
    return line_tokens(masked[at:clause_end])


def _earlier_round(text: str, start: int, names: Sequence[str]) -> bool:
    """Whether the "claim(s)" at ``start`` is an analyst's claim of an earlier round.

    "TRIAGE ANALYST round-3 claim 24", "the static's round-2 claims 9 to 20":
    the numbers index the answer of that round, not the one in force, so they
    name no claim, and no analyst is wanting for them.
    """
    found = _ROUND_BEFORE.search(text[max(0, start - 40) : start])
    if found is None:
        return False
    return _short_named(text, max(0, start - 40) + found.start(), names) is not None


class ClaimReference(NamedTuple):
    """One claim reference a line writes for a participant (:func:`claim_references_of`)."""

    analyst: str
    numbers_start: int
    numbers: ClaimNumbers
    read_before: bool
    in_mark: bool


def claim_references_of(
    text: str, names: Sequence[str], field_names: Sequence[str] | None
) -> list[ClaimReference]:
    """Every claim reference a line writes for a participant, in the order found.

    A :class:`ClaimReference` (``analyst``, where its numbers start, its
    ``numbers``, ``read_before``, ``in_mark``) per reference, for every
    participant the line names, whether its
    ``[analysts: ...]`` field (``field_names``, from ``_named_in``) names it
    or not: a consumer that needs the claims of one set of analysts filters
    on top of it (the merge's reading keeps the field's, a revision's excerpt
    of its peers keeps every analyst's). ``text`` is the line without its
    carried-or-new mark (``without_line_mark``). A reference is read for an
    analyst written by name right before "claim(s) N" (``_claims_named``),
    for the field's one analyst where "claim(s) N" follows the field
    directly or after the mediator's marks written after it, and for an
    analyst a short form of whose name stands before "claim(s) N"
    (``_short_named``). Its numbers are read whole (:func:`read_claim_numbers`).

    ``read_before`` says whether the earlier reading read the reference,
    ``in_mark`` whether it stands inside a ``[blocking: ...]`` or ``[not
    blocking: ...]`` mark. A reference inside a mark is its reason: it is
    kept only where the earlier reading read it, with the
    numbers that reading read and no more (no range, no list going on); a
    reference only the newer reading reads there is not returned. A claim of
    an earlier round ("TRIAGE ANALYST round-3 claim 24") is never one: its
    numbers index another answer. Linear in the line.
    """
    in_marks = [m.span() for m in _MARK_ANYWHERE.finditer(text)]
    # (analyst, where its numbers start, whether the earlier reading read it).
    found: list[tuple[str, int, bool]] = [
        (name, match.start(1), True) for name, match in _claim_numbers_named(text, names)
    ]
    if field_names is not None and len(field_names) == 1:
        opened = _ANALYSTS_FIELD.search(text)
        if opened is not None:
            bare = _BARE_CLAIMS.match(text, opened.end())
            if bare is not None:
                found.append((field_names[0], bare.start(1), True))
            elif (after := _MARKS_AFTER_FIELD.match(text, opened.end())) is not None:
                # "[analysts: X] [not blocking: ...] Claim 18 says ...".
                bare = _BARE_CLAIMS.match(text, after.end())
                if bare is not None:
                    found.append((field_names[0], bare.start(1), False))
    # A short form of a participant's name before "claim(s) N"; the earlier
    # reading read it on a line whose field names analysts only.
    for reference in _CLAIM_REFERENCE.finditer(text):
        short = _short_named(text, reference.start(), names)
        if short is not None:
            found.append((short, reference.start(1), bool(field_names)))
    out: list[ClaimReference] = []
    for name, at, old in found:
        if any(start <= at < end for start, end in in_marks):
            earlier = _EARLIER_NUMBERS.match(text, at) if old else None
            if earlier is not None:
                digits = tuple(re.findall(r"\d+", earlier.group(0)))
                numbers = ClaimNumbers(digits, (), earlier.end())
                out.append(ClaimReference(name, at, numbers, True, True))
            continue
        read = read_claim_numbers(text, at, names)
        if read is not None:
            out.append(ClaimReference(name, at, read, old, False))
    return out


def unattributed_references(
    text: str, names: Sequence[str], references: Sequence[ClaimReference]
) -> list[tuple[int, ClaimNumbers]]:
    """The claim references of a line that no analyst is read for, in order.

    ``(where its "claim(s)" starts, its numbers)`` per "claim(s) N" that no
    reference of ``references`` (:func:`claim_references_of` over the same
    ``text``) reads, read whole (:func:`read_claim_numbers`): "the
    reverser's own claim 45", a bare "Claim 1" on a line whose field names
    two analysts. A "claim N" inside a mark is its reason, "claims" with a
    single number reads as a verb ("the dropper claims 3 hosts") and an
    earlier round's claim names another answer: none is one. Linear in the
    line.
    """
    in_marks = [m.span() for m in _MARK_ANYWHERE.finditer(text)]
    read = [(ref.numbers_start, ref.numbers.end) for ref in references]
    out: list[tuple[int, ClaimNumbers]] = []
    for reference in _CLAIM_REFERENCE.finditer(text):
        at = reference.start(1)
        if any(start <= at < end for start, end in read) or any(
            s <= reference.start() < e for s, e in in_marks
        ):
            continue
        numbers = read_claim_numbers(text, at, names)
        if numbers is None:
            continue
        read.append((at, numbers.end))
        head = reference.group(0)[: at - reference.start()].lower()
        if head.startswith("claims") and len(numbers.numbers) == 1 and not numbers.unplaced:
            continue
        if _earlier_round(text, reference.start(), names):
            continue
        out.append((reference.start(), numbers))
    return out


def _owner_of(
    claim: int,
    tokens: frozenset[str],
    candidates: Sequence[str],
    owners: Mapping[str, Mapping[int, frozenset[str]]],
) -> tuple[str, int] | None:
    """``(analyst, ids and addresses shared)`` for the one candidate whose claim alone shares one.

    A candidate's claim counts only with a ledger id or an address of the
    reference's clause (``tokens``) that no other claim of the same answer
    in force writes: a listing many claims cite is no sign of which one the
    line means. ``None`` where no candidate's claim, or more than one, has
    such a token.
    """
    found: list[tuple[str, int]] = []
    for name in candidates:
        claims = owners.get(name) or {}
        shared = tokens & claims.get(claim, frozenset())
        if not shared:
            continue
        others = frozenset().union(*(t for n, t in claims.items() if n != claim))
        if shared - others:
            found.append((name, len(shared - others)))
    return found[0] if len(found) == 1 else None


def read_claim_references(
    lines: Sequence[str],
    participants: Sequence[str],
    owners: Mapping[str, Mapping[int, frozenset[str]]] | None = None,
) -> ClaimReferences:
    """Per analyst, the claims each line names, and the references that name none.

    The merge's reading. A line names the claims :func:`claim_references_of`
    reads on it, for the analysts its ``[analysts: ...]`` field names (a
    line whose field names analysts counts only for them: a claim number it
    writes for another is no question put to that one), or for any analyst
    on a line without a field, as the earlier reading named them there. The
    line number counts from 1 in the order given; ``blocking`` is the
    mediator's mark (``read_marks``), except that a line whose mark is not
    read blocks with no claim only the newer reading reaches (``expanded``).

    The rest of a range longer than the cap, and a "claim N" no analyst is
    read for ("the reverser's own claim 45"), is an unplaced reference
    (:class:`UnplacedClaims`) where the line blocks and its mark is read or
    absent. "claims" with a single number after it and no analyst named
    reads as a verb ("the dropper claims 3 hosts"), a "claim N" inside a mark
    is its reason and an earlier round's claim names another answer: none is
    a reference.

    ``owners`` is, per analyst, the ledger ids and addresses each claim of its
    answer in force writes, by claim number. Given, a "claim N" no analyst is
    read for on a blocking line whose mark is read or absent is read for its
    owner where exactly one analyst the line may mean has a claim N sharing
    with the reference's clause an id or an address no other claim of its
    answer writes (:class:`OwnedClaim`): it names that claim as a line that
    does not block, so it is carried with the line and never withdrawn by
    rule, and the merge says so. Linear in the lines and the claims.
    """
    names = [str(p) for p in participants if str(p).strip()]
    out: dict[str, dict[int, list[tuple[int, bool]]]] = {}
    unplaced: dict[UnplacedClaims, None] = {}
    owned: dict[OwnedClaim, None] = {}
    expanded: dict[str, dict[int, list[ExpandedNaming]]] = {}
    for number, (line, mark) in enumerate(zip(lines, read_marks(lines), strict=True), 1):
        text = without_line_mark(str(line))
        field_names = _named_in(text, names)
        # The text with every mark's reason blanked out, for the clauses' tokens.
        masked = marks_blanked(text)
        stated = mark.blocking and not mark.unread
        references = claim_references_of(text, names, field_names)
        starts = sorted(ref.numbers_start for ref in references)
        # Per reference kept: (analyst, its numbers, the tokens of its clause).
        kept: list[tuple[str, ClaimNumbers, frozenset[str]]] = []
        cited: dict[str, set[int]] = {}
        for name, at, numbers, old, _in_mark in references:
            if field_names is not None and name not in field_names:
                continue
            if not field_names and not old:
                # A short form on a line without a field: read, never named.
                continue
            earlier = _EARLIER_NUMBERS.match(text, at) if old else None
            before = (
                {n for n in map(_as_claim_number, re.findall(r"\d+", earlier.group(0))) if n}
                if earlier is not None
                else set()
            )
            cited.setdefault(name, set()).update(before)
            kept.append((name, numbers, clause_tokens(text, masked, at, numbers.end, starts)))
        for name, numbers, tokens in kept:
            for first, last in numbers.unplaced:
                if stated:
                    said = UnplacedClaims(
                        number,
                        mark.marked,
                        (name,),
                        _range_rendering(first, last),
                        RANGE_NOT_READ,
                        _as_claim_number(first) or 0,
                    )
                    unplaced.setdefault(said, None)
            counted = [n for n in map(_as_claim_number, numbers.numbers) if n is not None]
            rendering = ("claim " if len(counted) == 1 else "claims ") + _claim_spans(counted)
            if not numbers.numbers:
                continue
            claims = out.setdefault(name, {})
            for written in numbers.numbers:
                stripped = written.lstrip("0")
                if not stripped or len(stripped) > _CLAIM_DIGITS:
                    continue
                claim = int(stripped)
                newly = claim not in cited.get(name, set())
                # A line whose mark is not read blocks only with what the
                # earlier reading read on it.
                row = (number, mark.blocking and not (newly and mark.unread))
                rows = claims.setdefault(claim, [])
                if row not in rows:
                    rows.append(row)
                if newly:
                    reached = expanded.setdefault(name, {}).setdefault(claim, [])
                    if reached and reached[-1].line == number:
                        reached[-1] = ExpandedNaming(
                            number, reached[-1].reference, reached[-1].tokens | tokens
                        )
                    else:
                        reached.append(ExpandedNaming(number, rendering, tokens))
        # A "claim(s) N" no reference above read: no analyst is read for it.
        candidates = tuple(field_names) if field_names else tuple(names)
        if not stated or not candidates:
            continue
        unattributed = unattributed_references(text, names, references)
        # Where each reference starts, for a clause to end at the next one.
        clause_starts = sorted([*starts, *(at for at, _n in unattributed)])
        for start, numbers in unattributed:
            counted = [n for n in map(_as_claim_number, numbers.numbers) if n is not None]
            if owners and counted:
                tokens = clause_tokens(text, masked, start, numbers.end, clause_starts)
                left: list[int] = []
                for claim in counted:
                    owner = _owner_of(claim, tokens, candidates, owners)
                    if owner is None:
                        left.append(claim)
                        continue
                    # Read, never withdrawn by rule: the claim is carried
                    # with the line as one a line contests without blocking.
                    rows = out.setdefault(owner[0], {}).setdefault(claim, [])
                    if (number, False) not in rows:
                        rows.append((number, False))
                    owned.setdefault(
                        OwnedClaim(number, mark.marked, owner[0], claim, owner[1]), None
                    )
                counted = left
            rendered = [_range_rendering(first, last) for first, last in numbers.unplaced]
            if counted:
                kind = "claim " if len(counted) == 1 else "claims "
                rendered.insert(0, kind + _claim_spans(counted))
            if not rendered:
                continue
            lows = [*counted, *(n for f, _l in numbers.unplaced if (n := _as_claim_number(f)))]
            said = UnplacedClaims(
                number,
                mark.marked,
                candidates,
                "; ".join(rendered),
                NO_ANALYST_NAMED,
                min(lows) if lows else 0,
            )
            unplaced.setdefault(said, None)
    return ClaimReferences(
        named=out,
        unplaced=tuple(unplaced),
        expanded={k: {n: tuple(v) for n, v in c.items()} for k, c in expanded.items()},
        owned=tuple(owned),
    )


def claims_named_by_lines(
    lines: Sequence[str],
    participants: Sequence[str],
    owners: Mapping[str, Mapping[int, frozenset[str]]] | None = None,
) -> dict[str, dict[int, list[tuple[int, bool]]]]:
    """``{analyst: {claim number: [(line number, blocking), ...]}}`` for the lines given.

    The claims :func:`read_claim_references` reads each line to name (a claim
    number written for no analyst read for its owner where ``owners`` is
    given), each analyst's carrying what its merge reads besides
    (:class:`NamedClaims`). Linear in the lines.
    """
    return NamedByLines(read_claim_references(lines, participants, owners))


@dataclass(frozen=True)
class ContestedRef:
    """What one listed line of a mediation refers to, read from its text.

    ``line`` counts from 1 in the order the lines were given; ``blocking`` is
    the mediator's mark (``read_marks``); ``analysts`` the participants its
    ``[analysts: ...]`` field names (none for a line without one); ``claims``
    each ``(analyst, claim number)`` it writes, for any participant, field or
    not, in the order written, a range read as every claim in it;
    ``unplaced`` the analysts it gives a claim number too long to be a place;
    ``wide`` the analysts it gives a range longer than
    :data:`CLAIM_RANGE_CAP` claims; ``unattributed`` whether it writes a
    claim number it attributes to no analyst; ``entries`` the ledger ids it
    cites, lower-cased; ``question`` the line without its carried-or-new
    mark; ``tokens`` per ``(analyst, claim number)`` the ledger ids and
    addresses of the clause of the reference that names it
    (:func:`clause_tokens`).
    """

    line: int
    blocking: bool
    analysts: tuple[str, ...]
    claims: tuple[tuple[str, int], ...]
    entries: tuple[str, ...]
    question: str
    unplaced: tuple[str, ...] = ()
    wide: tuple[str, ...] = ()
    unattributed: bool = False
    tokens: tuple[tuple[str, int, frozenset[str]], ...] = ()

    def claims_of(self, analyst: str) -> tuple[int, ...]:
        """The claim numbers the line writes for ``analyst``, each once, in order."""
        return tuple(dict.fromkeys(n for who, n in self.claims if who == analyst))

    def tokens_of(self, analyst: str, number: int) -> frozenset[str]:
        """The ids and addresses of the clauses that name ``analyst``'s claim ``number``."""
        found: frozenset[str] = frozenset()
        for who, n, tokens in self.tokens:
            if who == analyst and n == number:
                found |= tokens
        return found


def contested_refs(lines: Sequence[str], participants: Sequence[str]) -> list[ContestedRef]:
    """One :class:`ContestedRef` per line, in order. Linear in the lines.

    Every reference the merged reader reads on a line
    (:func:`claim_references_of`), for any participant, field or not: a
    peer's claim a line cites is what a revision is shown of it. A reference
    inside the mediator's ``[blocking: ...]`` or ``[not blocking: ...]`` mark
    is its reason and is not quoted. A range longer than
    :data:`CLAIM_RANGE_CAP` claims names its analyst in ``wide``; a number of
    zero is kept (no claim has it); one longer than :data:`_CLAIM_DIGITS`
    digits is never converted and names its analyst in ``unplaced``. A
    "claim(s) N" the reader gives to no analyst
    (:func:`unattributed_references`) marks the line ``unattributed``.
    """
    names = [str(p) for p in participants if str(p).strip()]
    out: list[ContestedRef] = []
    for number, (line, mark) in enumerate(zip(lines, read_marks(lines), strict=True), 1):
        text = without_line_mark(str(line))
        field_names = _named_in(text, names)
        references = claim_references_of(text, names, field_names)
        masked = marks_blanked(text)
        starts = sorted(ref.numbers_start for ref in references)
        claims: dict[tuple[str, int], None] = {}
        tokens: dict[tuple[str, int, frozenset[str]], None] = {}
        unplaced: dict[str, None] = {}
        wide: dict[str, None] = {}
        # A reference the reader finds twice (by name and by a short form) is one.
        seen: set[tuple[str, int]] = set()
        for ref in references:
            if ref.in_mark or (ref.analyst, ref.numbers_start) in seen:
                continue
            seen.add((ref.analyst, ref.numbers_start))
            if ref.numbers.unplaced:
                wide[ref.analyst] = None
            clause = clause_tokens(text, masked, ref.numbers_start, ref.numbers.end, starts)
            for written in ref.numbers.numbers:
                stripped = written.lstrip("0")
                if len(stripped) > _CLAIM_DIGITS:
                    unplaced[ref.analyst] = None
                    continue
                claim = (ref.analyst, int(stripped or "0"))
                claims[claim] = None
                tokens[(*claim, clause)] = None
        out.append(
            ContestedRef(
                line=number,
                blocking=mark.blocking,
                analysts=tuple(field_names or ()),
                claims=tuple(claims),
                entries=tuple(line_entry_ids([str(line)])),
                question=" ".join(text.split()),
                unplaced=tuple(unplaced),
                wide=tuple(wide),
                unattributed=bool(unattributed_references(text, names, references)),
                tokens=tuple(tokens),
            )
        )
    return out


class ShownReport(str):
    """A peer's report as a named analyst's revision is shown it, with what was cut.

    The text is the excerpt, or the whole report. ``claims`` are the claim
    numbers quoted (none: the whole report is shown), ``whole_chars`` the
    length of the whole report and ``note`` the sentence saying why a peer
    whose report could have been cut is shown whole ("" otherwise). An
    excerpt's text opens with the sentence saying what it quotes and that the
    whole report is not shown, so every prompt that carries it says so; the
    revision prompts head it as an excerpt (:func:`peer_report_heading`).
    """

    claims: tuple[int, ...]
    whole_chars: int
    note: str

    def __new__(
        cls, text: str = "", claims: Sequence[int] = (), whole_chars: int = 0, note: str = ""
    ) -> ShownReport:
        made = super().__new__(cls, text)
        made.claims = tuple(int(n) for n in claims)
        made.whole_chars = int(whole_chars)
        made.note = str(note)
        return made

    def __reduce__(self) -> tuple[Any, ...]:
        return (ShownReport, (str(self), self.claims, self.whole_chars, self.note))

    def written(self, text: str) -> ShownReport:
        """``text`` (this report written again: same length, same claims) with this one's record."""
        return ShownReport(text, self.claims, self.whole_chars, self.note)


def peer_report_heading(name: str, report: str, *, analyst: bool = False) -> str:
    """The heading a revision prompt writes over one peer's report.

    ``<NAME> REPORT:`` for a whole report (``<NAME> ANALYST REPORT:`` on the
    plain text revision, ``analyst=True``), as every revision prompt wrote
    it; ``<NAME> REPORT (excerpt):`` for an excerpt (a :class:`ShownReport`
    with claims), whose own first line says what it quotes.
    """
    label = f"{name.upper()} ANALYST REPORT" if analyst else f"{name.upper()} REPORT"
    claims = report.claims if isinstance(report, ShownReport) else ()
    return f"{label} (excerpt):" if claims else f"{label}:"


def excerpt_statement(claims: Sequence[int]) -> str:
    """An excerpt's first line: the claims it quotes, and that the whole report is not shown."""
    which = "Claim" if len(claims) == 1 else "Claims"
    numbers = ", ".join(str(n) for n in claims)
    return (
        f"{which} {numbers} quoted, with its disputes and other points naming you; "
        "the whole report is not shown."
    )


def _blocks_of(isr: Any) -> list[list[Any]]:
    """The analyst's claims grouped by block, in order: block N is claim N.

    ``AgentISR.claim_blocks``; an answer held in another shape is grouped as
    that method groups it.
    """
    blocks_of = getattr(isr, "claim_blocks", None)
    if callable(blocks_of):
        return [list(block) for block in blocks_of()]
    from maljan.pipeline.validation import claim_block_indexes

    claims = list(getattr(isr, "claims", None) or [])
    blocks: list[list[Any]] = []
    for index, claim in zip(claim_block_indexes(claims), claims, strict=True):
        if index == len(blocks):
            blocks.append([])
        blocks[index].append(claim)
    return blocks


def _whole_note(name: str, peer: str, revision_round: int, why: str) -> str:
    return (
        f"The {name} analyst's round-{int(revision_round)} revision was shown the {peer} "
        f"analyst's whole report: {why}."
    )


# How many claim numbers a sentence writes out before it counts the rest.
_NUMBERS_SAID = 5


def _claim_numbers_said(numbers: Sequence[int]) -> str:
    which = "claim" if len(numbers) == 1 else "claims"
    said = ", ".join(str(n) for n in numbers[:_NUMBERS_SAID])
    rest = len(numbers) - _NUMBERS_SAID
    return f"{which} {said}" + (f" and {rest} more" if rest > 0 else "")


def _names_analyst(
    text: str, name: str, patterns: Sequence[re.Pattern[str]], participants: Sequence[str]
) -> bool:
    """Whether ``text`` writes ``name``: its key or label, or a short form before a claim number."""
    if any(p.search(text) for p in patterns):
        return True
    names = [str(p) for p in participants if str(p).strip()]
    return any(
        _short_named(text, reference.start(), names) == name
        for reference in _CLAIM_REFERENCE.finditer(text)
    )


# Where a line opens an item of a list: a bullet or a number.
_ITEM_OPENS = re.compile(r"^\s*+(?:[-*•]|\d++[.)])\s")


def _items_besides_claims(report: str) -> list[str]:
    """The items of a report's section written besides its claims, each whole.

    The section an answer in force carries after
    ``base_agent.WRITTEN_BESIDES_CLAIMS``: each bullet with the lines that
    continue it, and each other line on its own; ``[]`` without one.
    """
    from maljan.agents.base_agent import WRITTEN_BESIDES_CLAIMS

    at = report.find(WRITTEN_BESIDES_CLAIMS)
    if at < 0:
        return []
    items: list[list[str]] = []
    opened = False
    for line in report[at + len(WRITTEN_BESIDES_CLAIMS) :].splitlines():
        if not line.strip():
            opened = False
            continue
        if _ITEM_OPENS.match(line) or not opened:
            items.append([line.rstrip()])
            opened = bool(_ITEM_OPENS.match(line))
        else:
            items[-1].append(line.rstrip())
    return ["\n".join(item) for item in items]


def peer_excerpt(
    name: str,
    peer: str,
    refs: Sequence[ContestedRef],
    whole: str,
    isr: Any,
    patterns: Sequence[re.Pattern[str]],
    revision_round: int = 0,
    participants: Sequence[str] = (),
) -> ShownReport:
    """The peer's report as the ``name`` analyst's revision is shown it.

    ``refs`` are the blocking lines naming ``name`` that name ``peer`` too (in
    the field, or by key or label). Their claim numbers for the peer are
    quoted from its answer in force (``isr``, the ISR the mediator read),
    numbered by block as every summary numbers them, each as the summary
    writes it (``claim_summary_line``), after the sentence saying what is
    quoted (:func:`excerpt_statement`). Then the peer's disputes, and the
    items of its report's section written besides its claims, that write
    ``name``: its key or label (``patterns``), or a short form of it before a
    claim number (``participants``).

    The whole report is shown instead, with a note saying why, when a line
    names the peer with no claim number for it, one too long to read or a
    range it cannot place, when it cites a claim of no analyst it names, when
    a number is past the claims of the answer in force, when a quoted claim
    shares no ledger id or address with the clause of the line that cites it
    (:func:`clause_tokens`: the mediator may have cited a claim by another
    number), or when the answer in force is not held.
    """
    from maljan.schemas.isr_models import claim_summary_line

    def _whole(why: str) -> ShownReport:
        return ShownReport(whole, (), len(whole), _whole_note(name, peer, revision_round, why))

    if isr is None:
        return _whole("its answer in force was not read")
    blocks = _blocks_of(isr)
    numbers: dict[int, None] = {}
    for ref in refs:
        at = f"blocking line {ref.line}"
        if peer in ref.unplaced:
            return _whole(f"{at} writes a claim number for it too long to be one")
        if peer in ref.wide:
            return _whole(f"{at} writes a claim range it cannot place")
        if ref.unattributed:
            return _whole(f"{at} cites a claim without naming its analyst")
        written = ref.claims_of(peer)
        if not written:
            return _whole(f"{at} names it without a claim number")
        past = [n for n in written if not 1 <= n <= len(blocks)]
        if past:
            return _whole(
                f"{at} names its {_claim_numbers_said(past)}, and its answer in force holds "
                f"{len(blocks)} claim(s)"
            )
        for n in written:
            said = " ".join(
                f"{getattr(c, 'claim', '') or ''} {getattr(c, 'evidence_ref', '') or ''}"
                for c in blocks[n - 1]
            )
            if not ref.tokens_of(peer, n) & line_tokens(said):
                return _whole(
                    f"{at} cites claim {n} of it, which shares no ledger id or address with "
                    f"the clause of {at} that cites it"
                )
        numbers.update(dict.fromkeys(written))
    if not numbers:
        return _whole("no contested line names a claim of it")
    quoted = sorted(numbers)
    lines = [excerpt_statement(quoted)]
    lines.extend(f"  {claim_summary_line(n, blocks[n - 1][0], blocks[n - 1])}" for n in quoted)
    disputes = [
        str(item)
        for item in getattr(isr, "dissent_items", None) or []
        if _names_analyst(str(item), name, patterns, participants)
    ]
    if disputes:
        lines.append(f"  Disputes naming the {name} analyst:")
        lines.extend(f"    - {item}" for item in disputes)
    # An item that restates a dispute listed above is not shown twice.
    listed = [" ".join(d.split()) for d in disputes if d.strip()]
    besides = [
        item
        for item in _items_besides_claims(whole)
        if _names_analyst(item, name, patterns, participants)
        and not any(
            (said := " ".join(_ITEM_OPENS.sub("", item, count=1).split())) == d
            or said.startswith(d)
            for d in listed
        )
    ]
    if besides:
        lines.append(f"  Written besides its claims, naming the {name} analyst:")
        lines.extend(
            "\n".join(f"    {part.strip()}" for part in item.splitlines()) for item in besides
        )
    return ShownReport("\n".join(lines), quoted, len(whole))


def peers_shown_record(shown: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    """What a round's revisions were shown of their peers, for the round's record.

    ``shown`` is, per named analyst, each peer report its revision was given
    (:func:`contested_input` with the answers in force). ``excerpted`` and
    ``whole`` count the peer reports cut to the claims the lines name and the
    ones shown whole; ``excerpt_chars`` is what the excerpts hold and
    ``excerpted_whole_chars`` what the same reports hold whole, the saving
    being the difference; ``whole_chars`` is what the reports shown whole
    hold. ``quoted`` is the claim numbers quoted per analyst and peer, and
    ``notes`` the sentence for each report shown whole, in order. ``{}`` for a
    round that showed no peer.
    """
    excerpted = whole = excerpt_chars = excerpted_whole = whole_chars = 0
    quoted: dict[str, dict[str, list[int]]] = {}
    notes: list[str] = []
    for name, peers in shown.items():
        for peer, text in peers.items():
            claims = text.claims if isinstance(text, ShownReport) else ()
            if claims:
                excerpted += 1
                excerpt_chars += len(text)
                excerpted_whole += text.whole_chars
                quoted.setdefault(str(name), {})[str(peer)] = list(claims)
                continue
            whole += 1
            whole_chars += len(str(text or ""))
            note = text.note if isinstance(text, ShownReport) else ""
            if note:
                notes.append(note)
    if not excerpted and not whole:
        return {}
    return {
        "excerpted": excerpted,
        "whole": whole,
        "excerpt_chars": excerpt_chars,
        "excerpted_whole_chars": excerpted_whole,
        "whole_chars": whole_chars,
        **({"quoted": quoted} if quoted else {}),
        **({"notes": notes} if notes else {}),
    }
