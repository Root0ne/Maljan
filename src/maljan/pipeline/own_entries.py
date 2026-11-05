"""A blocking line that only sets an analyst's claim against its own dispute entry, settled by rule.

A mediation may block on a line whose whole point is one analyst
contradicting itself: its claim states a confidence, and its own dispute entry
in the same answer holds the point at a lower figure ("Claim 10 gives the name
at 0.85 ... its own dispute entry holds it at 0.50"). No peer and no ledger
entry is argued over, so a revision round spent on it asks the analyst to pick
one of its own two figures. The platform picks it, by one rule, and no round is
opened for the line:

- **the line**: it blocks, its ``[analysts: ...]`` field (one field only) names
  the analysts it is about, the text names no other participant and no claim
  of anyone else, and it says the contradiction is with the analyst's own
  words ("its own", "their own");
- **the claim**: each analyst the field names has a claim the line names by
  number (``debate_facts.read_claim_references``), in its answer in force;
- **the entry**: a dispute entry of that same answer
  (``AgentISR.dissent_items``) is about the same point as the claim and the
  line: the three share a ledger id, an address or a quoted value of three
  characters or more;
- **the figure**: the entry states a confidence figure that the line states
  too and that is below the claim's confidence.

The lower figure stands: the claim is held at it, the one figure both the
analyst's entry and the mediator's line state. A claim is never raised and
never withdrawn here. Where any analyst the field names has no claim so
settled, the line is not settled and the debate goes on as before. Every
settled line is recorded with its claims, both figures and the entry
(:meth:`SettledLine.sentence`): in the events, the run summary and the report.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.pipeline.claim_drops import defanged
from maljan.pipeline.debate_facts import (
    _name_pattern,
    claim_references_of,
    line_tokens,
    read_analysts_field,
    read_claim_references,
    read_marks,
    resolve_analyst,
    without_line_mark,
)

# The line says the contradiction is with the analyst's own words.
_OWN = re.compile(r"\b(?:its|their)\s++own\b", re.IGNORECASE)
# An [analysts: ...] field: a line with two sets one side against another.
_FIELD = re.compile(r"\[\s*+analysts?\s*+:", re.IGNORECASE)
# A confidence figure as an answer writes one: 0.5, 0.85, 1.0.
_FIGURE = re.compile(r"(?<![\w.])(?:0?\.\d{1,3}|1\.0{1,3})(?![\w%]|\.\d)")
# A quoted value, straight or curly quotes.
_QUOTED = re.compile(r"[\"“”]([^\"“”\n]{3,120})[\"“”]")
# How far before a claim number a name may stand and be part of its short form.
_SHORT_FORM_SPAN = 24
# How much of a model's text a sentence quotes.
_QUOTE_CHARS = 240
# The head of the settled lines the next mediation is shown.
SETTLED_HEAD = (
    "The platform settled these blocking lines of the last mediation by rule, with no "
    "revision round: each set an analyst's claim against its own dispute entry, and the claim "
    "is held at the lower figure both state:"
)
# Why the line no longer blocks, as the revision round reads it.
SETTLED_REASON = "settled by rule: the analyst's own dispute entry states the lower figure"


@dataclass(frozen=True)
class SettledClaim:
    """One claim a settled line names, held at the lower of its two figures."""

    analyst: str
    claim: int
    was: float
    now: float
    entry: str


@dataclass(frozen=True)
class SettledLine:
    """A blocking line settled by rule, with the claims it settled (``line`` counts from 1)."""

    line: int
    text: str
    claims: tuple[SettledClaim, ...]

    def sentence(self, mediation: int) -> str:
        """The run's record of the settlement: model text cleaned and capped, defanged."""
        held = "; ".join(
            f"the {c.analyst} analyst's claim {c.claim} is held at {c.now:.2f} (it stated "
            f'{c.was:.2f}; its own dispute entry: "{_quoted(c.entry)}")'
            for c in self.claims
        )
        return defanged(
            f"Settled by rule after the round-{int(mediation)} mediation, with no revision "
            f'round: blocking line L{self.line} ("{_quoted(self.text)}") sets an analyst\'s '
            f"claim against its own dispute entry, and the lower figure stands: {held}."
        )


def _quoted(text: str) -> str:
    """``text`` on one line, quote marks, brackets and run-state markers written out, capped."""
    from maljan.utils.written_forms import markers_written_out

    said = " ".join(re.sub(r"[\"“”\[\]]", "'", markers_written_out(str(text))).split())
    return said if len(said) <= _QUOTE_CHARS else said[: _QUOTE_CHARS - 1].rstrip() + "…"


def _figures(text: str) -> set[float]:
    found: set[float] = set()
    for match in _FIGURE.finditer(text):
        value = float(match.group(0))
        if 0.0 < value <= 1.0:
            found.add(round(value, 2))
    return found


def _quoted_values(text: str) -> set[str]:
    """The quoted values of ``text``, folded, of three characters or more once trimmed."""
    out: set[str] = set()
    for match in _QUOTED.finditer(text):
        value = " ".join(match.group(1).split()).strip(" .,;:").lower()
        if len(value) >= 3:
            out.add(value)
    return out


def _shares_point(line: str, claim: str, entry: str) -> bool:
    """Whether the line, the claim and the entry share a ledger id, an address or a quoted value."""
    if line_tokens(line) & line_tokens(claim) & line_tokens(entry):
        return True
    claim_folded, entry_folded = claim.lower(), entry.lower()
    return any(v in claim_folded and v in entry_folded for v in _quoted_values(line))


def _blocks(isr: Any) -> dict[int, list[Any]]:
    """``{claim number: its claims}`` of an answer in force, numbered by claim block."""
    from maljan.pipeline.validation import claim_block_indexes

    claims = list(getattr(isr, "claims", None) or [])
    out: dict[int, list[Any]] = {}
    for claim, index in zip(claims, claim_block_indexes(claims), strict=True):
        out.setdefault(index + 1, []).append(claim)
    return out


def _field_analysts(text: str, participants: Sequence[str]) -> list[str] | None:
    """The participants the line's one field names; ``None`` for no field, two, or a name unread."""
    if len(_FIELD.findall(text)) != 1:
        return None
    written = read_analysts_field(text)
    if not written:
        return None
    names: list[str] = []
    for name in written:
        found = resolve_analyst(name, participants)
        if found is None:
            return None
        if found not in names:
            names.append(found)
    return names


def _about_itself(text: str, field: Sequence[str], participants: Sequence[str]) -> bool:
    """Whether the line speaks of its own analysts' words alone: "own", and no one else named."""
    if _OWN.search(text) is None:
        return False
    references = claim_references_of(text, participants, None)
    if any(ref.analyst not in field for ref in references):
        return False
    # Where the field's analysts' claim numbers start: a name right before one
    # is part of that analyst's short form ("static R2 claim 14"), no one else.
    starts = [ref.numbers_start for ref in references]
    opened = _FIELD.search(text)
    body_start = text.find("]", opened.end()) + 1 if opened is not None else 0
    for other in (p for p in participants if p not in field):
        for match in _name_pattern(other).finditer(text, body_start):
            if not any(0 <= at - match.end() <= _SHORT_FORM_SPAN for at in starts):
                return False
    return True


def _settle_claim(name: str, number: int, text: str, isr: Any) -> SettledClaim | None:
    """Claim ``number`` of ``name``'s answer held at its own entry's lower figure, or ``None``."""
    blocks = _blocks(isr).get(number)
    if not blocks:
        return None
    first = blocks[0]
    stated = getattr(first, "confidence", None)
    if isinstance(stated, bool) or not isinstance(stated, int | float):
        return None
    was = round(float(stated), 2)
    said = f"{getattr(first, 'claim', '') or ''}\n{getattr(first, 'evidence_ref', '') or ''}"
    on_line = _figures(text)
    best: tuple[float, str] | None = None
    for entry in getattr(isr, "dissent_items", None) or []:
        entry_text = str(entry or "")
        if not entry_text.strip() or not _shares_point(text, said, entry_text):
            continue
        for figure in _figures(entry_text) & on_line:
            if figure < was and (best is None or figure < best[0]):
                best = (figure, entry_text)
    if best is None:
        return None
    return SettledClaim(name, number, was, best[0], best[1])


def settle_own_entry_lines(
    lines: Sequence[str], participants: Sequence[str], isrs: Mapping[str, Any]
) -> tuple[list[SettledLine], dict[str, Any]]:
    """The blocking lines settled by rule, and the answers in force with their claims held so.

    ``lines`` are a mediation's blocking lines in its order; ``isrs`` the
    answers in force by analyst. Returns the settled lines in line order and,
    per analyst a settled claim belongs to, its answer in force with each
    settled claim block held at the lower figure (a copy; ``isrs`` is not
    changed). A line not settled is left out, and the debate reads it as
    before. Never raises on a model's text: a line that cannot be read is not
    settled.
    """
    names = [str(p) for p in participants if str(p).strip()]
    settled: list[SettledLine] = []
    held: dict[str, Any] = {}
    # Per analyst, claim number -> the figure it is held at.
    lowered: dict[str, dict[int, float]] = {}
    marks = read_marks(lines)
    for number, (line, mark) in enumerate(zip(lines, marks, strict=True), 1):
        if not mark.blocking:
            continue
        text = without_line_mark(str(line))
        field = _field_analysts(text, names)
        if not field or not _about_itself(text, field, names):
            continue
        named = read_claim_references([str(line)], names).named
        claims: list[SettledClaim] = []
        for name in field:
            isr = held.get(name, isrs.get(name))
            mine = [
                c
                for n in sorted(named.get(name) or {})
                if (c := _settle_claim(name, n, text, isr)) is not None
            ]
            if not mine:
                claims = []
                break
            claims.extend(mine)
        if not claims:
            continue
        for claim in claims:
            lowered.setdefault(claim.analyst, {})[claim.claim] = claim.now
            held[claim.analyst] = _held_at(isrs.get(claim.analyst), lowered[claim.analyst])
        settled.append(SettledLine(number, str(line), tuple(claims)))
    return settled, held


def _held_at(isr: Any, figures: Mapping[int, float]) -> Any:
    """``isr`` with each claim of the numbered blocks held at its figure, as a copy."""
    from maljan.pipeline.validation import claim_block_indexes

    claims = list(getattr(isr, "claims", None) or [])
    out = [
        claim.model_copy(update={"confidence": figures[index + 1]})
        if index + 1 in figures
        else claim
        for claim, index in zip(claims, claim_block_indexes(claims), strict=True)
    ]
    return isr.model_copy(update={"claims": out})


def with_settled_by_rule(text: str, sentences: Sequence[str]) -> str:
    """``text`` with the settled lines' sentences after it under their head, or as it was."""
    said = [str(s) for s in sentences if str(s).strip()]
    if not said:
        return text
    block = "\n".join([SETTLED_HEAD, *(f"- {s}" for s in said)])
    return f"{text}\n\n{block}" if text else block
