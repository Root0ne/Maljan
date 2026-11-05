"""A blocking line that only sets an analyst's claim against its own dispute entry, settled by rule.

A mediation may block on a line whose whole point is one analyst
contradicting itself: its claim states a confidence, and its own dispute entry
in the same answer holds the point at a lower figure ("Claim 10 gives the name
at 0.85 ... its own dispute entry holds it at 0.50"). No peer and no ledger
entry is argued over, so a revision round spent on it asks the analyst to pick
one of its own two figures. The platform picks it, by one rule, and no round is
opened for the line:

- **the line**: it blocks, its one ``[analysts: ...]`` field names one
  analyst, it says the contradiction is with the analyst's own words ("its
  own", "their own"), and it names no other participant (by key or label), no
  analyst or report besides its own, and no claim of anyone else;
- **the claims**: every claim number the line writes is the analyst's, read
  for it (``debate_facts.read_claim_references``) with none left unplaced, and
  each is settled below; a line that writes one claim it cannot settle (a
  dispute of another claim against the ledger, say) is not settled at all;
- **the entry**: a dispute entry of that same answer
  (``AgentISR.dissent_items``) is about the same point as the claim and the
  line: the three share a ledger id, an address or a quoted value of four
  characters or more, matched as whole words;
- **the figure**: an entry any sentence of which names another participant,
  a claim read for anyone else, or a third or unnamed party ("they", "the
  sandbox") is refused whole; the entry states exactly one figure, in a
  first-person clause ("I hold ... at 0.50", "my figure is 0.50"), as a
  confidence and not a measurement ("ratio", "share", "detections"); the line
  states it too after a cue of its own ("entry", "figure", "hold"), and it is
  below the claim's. In doubt, nothing is settled.

The lower figure stands: the claim is held at it. A claim is never raised and
never withdrawn here. Where anything above fails, the line is not settled and
the debate goes on as before. Every settled line is recorded with its claims,
both figures and the entry (:meth:`SettledLine.sentence`): in the events, the
run summary and the report, and the analyst's next revision is told it.
"""

from __future__ import annotations

import bisect
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, NamedTuple

from maljan.pipeline.claim_drops import defanged
from maljan.pipeline.debate_facts import (
    _name_pattern,
    claim_references_of,
    line_tokens,
    marks_blanked,
    read_analysts_field,
    read_claim_numbers,
    read_claim_references,
    read_marks,
    resolve_analyst,
    without_line_mark,
)

# The line says the contradiction is with the analyst's own words.
_OWN = re.compile(r"\b(?:its|their)\s++own\b", re.IGNORECASE)
# An [analysts: ...] field: a line with two sets one side against another.
_FIELD = re.compile(r"\[\s*+analysts?\s*+:", re.IGNORECASE)
# A word that names an analyst or a report the line's own analyst is not.
_SOMEONE = re.compile(r"\b(?:analysts?|reports?|peers?|reviewers?)\b", re.IGNORECASE)
# "claim(s) N" anywhere: where a claim number is written.
_CLAIM_WORD = re.compile(r"\bclaims?\s*+#?\s*+(?=\d)", re.IGNORECASE)
# A decimal figure of [0, 1] as an answer writes one: 0.5, 0.85, .5, 1.0.
_FIGURE = re.compile(r"(?<![\w.])(?:0?\.\d{1,3}|1\.0{1,3})(?![\w%]|\.\d)")
# What makes a figure a confidence: a word saying so right before it, with
# at most a few words between ("hold the name link at 0.50", "my figure is 0.50").
_CONFIDENCE_CUE = re.compile(
    r"\b(?:at|confidence|figure|hold|holds|held|holding|reduce|reduced|reduces|lower|lowered|"
    r"lowers)\b[^.;\d\n]{0,30}$",
    re.IGNORECASE,
)
# A clause whose subject is the analyst itself.
_FIRST_PERSON = re.compile(r"\b(?:I|my|me|we|our|us)\b", re.IGNORECASE)
# A third or unnamed party an entry may give a figure to.
_THIRD_PARTY = re.compile(
    r"\b(?:they|them|their|theirs|he|she|his|her|another|others|the\s++(?:sandbox|tool|other|"
    r"peer|engine|vendor|scanner))\b",
    re.IGNORECASE,
)
# A word that makes a figure near it a measurement, not a confidence.
_MEASURE_NEAR = re.compile(
    r"\b(?:ratio|ratios|rate|rates|share|shares|entropy|score|scores|percent|percentage|"
    r"detections?|engines?|out\s++of)\b|\bof\s++\d",
    re.IGNORECASE,
)
# How far either side of a figure a measure word is looked for.
_MEASURE_SPAN = 40
# What the line writes right before a figure it gives an entry or a claim.
_LINE_CUE = re.compile(
    r"\b(?:entry|entries|figure|figures|confidence|hold|holds|held|holding)\b[^.;\d\n]{0,30}$",
    re.IGNORECASE,
)
# Where an entry's sentences and clauses end.
_CLAUSE_END = re.compile(r";|(?<=[.!?])\s++(?=\S)")
# A quoted value, straight or curly quotes.
_QUOTED = re.compile(r"[\"“”]([^\"“”\n]{4,120})[\"“”]")
# The fewest characters a quoted value matches with.
_QUOTED_LEAST = 4
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
# The head of the settlements a revising analyst is told about its own claims.
SETTLED_FOR_YOU_HEAD = (
    "The platform held these claims of your answer in force at the lower figure your own "
    "dispute entry states, by rule, after the last mediation:"
)
# Why the line no longer blocks, as the revision round reads it.
SETTLED_REASON = "settled by rule: the analyst's own dispute entry states the lower figure"


@dataclass(frozen=True)
class SettledClaim:
    """One claim a settled line names, held at the lower of its two figures.

    ``sentence`` is the claim's own sentence, whitespace collapsed: what a
    later revision is compared with (:func:`raised_again`).
    """

    analyst: str
    claim: int
    was: float
    now: float
    entry: str
    sentence: str = ""


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

    def records(self, mediation: int) -> list[dict[str, Any]]:
        """One plain record per settled claim, with the line's sentence: kept on the mediation."""
        said = self.sentence(mediation)
        return [
            {
                "analyst": c.analyst,
                "claim": c.claim,
                "was": c.was,
                "now": c.now,
                "claim_sentence": c.sentence,
                "claim_values": sorted(claim_values(c.sentence)),
                "mediation": int(mediation),
                "sentence": said,
            }
            for c in self.claims
        ]


def _quoted(text: str) -> str:
    """``text`` on one line, quote marks, brackets and run-state markers written out, capped."""
    from maljan.utils.written_forms import markers_written_out

    said = " ".join(re.sub(r"[\"“”\[\]]", "'", markers_written_out(str(text))).split())
    return said if len(said) <= _QUOTE_CHARS else said[: _QUOTE_CHARS - 1].rstrip() + "…"


def _figures(text: str) -> list[tuple[float, int]]:
    """Each figure of [0, 1] ``text`` writes, rounded to two places, with where it starts."""
    found: list[tuple[float, int]] = []
    for match in _FIGURE.finditer(text):
        value = float(match.group(0))
        if 0.0 <= value <= 1.0:
            found.append((round(value, 2), match.start()))
    return found


def _quoted_values(text: str) -> set[str]:
    """The quoted values of ``text``, folded, of four characters or more once trimmed."""
    out: set[str] = set()
    for match in _QUOTED.finditer(text):
        value = " ".join(match.group(1).split()).strip(" .,;:").lower()
        if len(value) >= _QUOTED_LEAST:
            out.add(value)
    return out


def _says_value(text: str, value: str) -> bool:
    """Whether ``text`` writes ``value`` as a whole word or words, case folded."""
    pattern = r"(?<![0-9a-z_])" + re.escape(value) + r"(?![0-9a-z_])"
    return re.search(pattern, text.lower()) is not None


def _shares_point(line: str, claim: str, entry: str) -> bool:
    """Whether the line, the claim and the entry share a ledger id, an address or a quoted value."""
    if line_tokens(line) & line_tokens(claim) & line_tokens(entry):
        return True
    return any(_says_value(claim, v) and _says_value(entry, v) for v in _quoted_values(line))


def _blocks(isr: Any) -> dict[int, list[Any]]:
    """``{claim number: its claims}`` of an answer in force, numbered by claim block."""
    from maljan.pipeline.validation import claim_block_indexes

    claims = list(getattr(isr, "claims", None) or [])
    out: dict[int, list[Any]] = {}
    for claim, index in zip(claims, claim_block_indexes(claims), strict=True):
        out.setdefault(index + 1, []).append(claim)
    return out


def _owner(text: str, participants: Sequence[str]) -> str | None:
    """The one participant the line's one field names; ``None`` for anything else."""
    if len(_FIELD.findall(text)) != 1:
        return None
    written = read_analysts_field(text)
    if not written:
        return None
    found = {resolve_analyst(name, participants) for name in written}
    owner = found.pop() if len(found) == 1 else None
    return owner


def _spellings(name: str, labels: Mapping[str, Sequence[str]]) -> list[re.Pattern[str]]:
    """How a line may write participant ``name``: its key, and each label it is shown by."""
    forms = dict.fromkeys([name, *(str(x) for x in labels.get(name) or ())])
    return [_name_pattern(form) for form in forms if form.strip()]


def _names_someone_else(
    text: str,
    owner: str,
    participants: Sequence[str],
    labels: Mapping[str, Sequence[str]],
    starts: Sequence[int] = (),
) -> bool:
    """Whether ``text`` names a participant, an analyst or a report besides ``owner``.

    A name ending within a short span before one of ``starts`` (where the
    owner's claim numbers start, sorted) is part of the owner's short form
    ("static R2 claim 14"). Linear in the text: each name is searched once,
    and each match looks up the next start by bisection.
    """
    own = text
    for pattern in _spellings(owner, labels):
        own = re.sub(
            pattern.pattern + r"(?:[_\s\-]+analyst(?:['’]s|s)?)?",
            lambda m: " " * len(m.group(0)),
            own,
            flags=re.IGNORECASE,
        )
    for other in (p for p in participants if p != owner):
        for pattern in _spellings(other, labels):
            for match in pattern.finditer(own):
                at = bisect.bisect_left(starts, match.end())
                if at == len(starts) or starts[at] - match.end() > _SHORT_FORM_SPAN:
                    return True
    return _SOMEONE.search(own) is not None


def _line_owner(
    text: str, participants: Sequence[str], labels: Mapping[str, Sequence[str]]
) -> str | None:
    """The line's one analyst where the line speaks of that analyst's own words alone."""
    if _OWN.search(text) is None:
        return None
    owner = _owner(text, participants)
    if owner is None:
        return None
    references = claim_references_of(text, participants, [owner])
    if any(ref.analyst != owner for ref in references):
        return None
    opened = _FIELD.search(text)
    body_start = text.find("]", opened.end()) + 1 if opened is not None else 0
    body = marks_blanked(text)[body_start:]
    starts = sorted(ref.numbers_start - body_start for ref in references)
    if _names_someone_else(body, owner, participants, labels, starts):
        return None
    return owner


def _numbers_written(text: str, participants: Sequence[str]) -> set[int] | None:
    """Every claim number the line writes outside its marks; ``None`` for a range or an odd one."""
    masked = marks_blanked(text)
    out: set[int] = set()
    for match in _CLAIM_WORD.finditer(masked):
        numbers = read_claim_numbers(masked, match.end(), participants)
        if numbers is None or numbers.unplaced:
            return None
        for written in numbers.numbers:
            digits = written.lstrip("0")
            if not digits or len(digits) > 6:
                return None
            out.add(int(digits))
    return out


def _own_figure(
    entry: str, owner: str, participants: Sequence[str], labels: Mapping[str, Sequence[str]]
) -> float | None:
    """The one confidence figure the entry states as the analyst's own, or ``None``.

    The whole entry is refused when any sentence of it names another
    participant (key or label), a claim read for anyone else, another analyst
    or report, or a third or unnamed party ("they", "the sandbox", "the
    other", ``_THIRD_PARTY``): a figure in it may be someone else's. The
    entry must then state exactly one figure of [0, 1], in a clause with a
    first-person subject ("I", "my", "we", "our"), after a confidence cue
    (``_CONFIDENCE_CUE``) and with no measure word near it
    (``_MEASURE_NEAR``): "raised from 0.40 to 0.95", "a ratio of 0.30" or
    "the detection ratio stands at 0.30" is no figure of its own. In doubt,
    nothing is settled: the dispute stays the agents'.
    """
    figures: list[float] = []
    for clause in _CLAUSE_END.split(entry):
        if not clause.strip():
            continue
        if any(ref.analyst != owner for ref in claim_references_of(clause, participants, None)):
            return None
        if _names_someone_else(clause, owner, participants, labels):
            return None
        if _THIRD_PARTY.search(clause) is not None:
            return None
        for value, at in _figures(clause):
            if (
                _FIRST_PERSON.search(clause) is None
                or _CONFIDENCE_CUE.search(clause[max(0, at - 60) : at]) is None
                or _MEASURE_NEAR.search(clause[max(0, at - _MEASURE_SPAN) : at + _MEASURE_SPAN])
            ):
                return None
            figures.append(value)
    return figures[0] if len(figures) == 1 else None


def _line_figures(text: str) -> set[float]:
    """The figures the line states as an entry's or a claim's figure, after a cue."""
    return {
        value
        for value, at in _figures(text)
        if _LINE_CUE.search(text[max(0, at - 60) : at]) is not None
        and _MEASURE_NEAR.search(text[max(0, at - _MEASURE_SPAN) : at + _MEASURE_SPAN]) is None
    }


def _settle_claim(
    name: str,
    number: int,
    text: str,
    isr: Any,
    participants: Sequence[str],
    labels: Mapping[str, Sequence[str]],
) -> SettledClaim | None:
    """Claim ``number`` of ``name``'s answer held at its own entry's lower figure, or ``None``."""
    blocks = _blocks(isr).get(number)
    if not blocks:
        return None
    first = blocks[0]
    stated = getattr(first, "confidence", None)
    if isinstance(stated, bool) or not isinstance(stated, int | float):
        return None
    was = round(float(stated), 2)
    sentence = str(getattr(first, "claim", "") or "")
    said = f"{sentence}\n{getattr(first, 'evidence_ref', '') or ''}"
    on_line = _line_figures(text)
    best: tuple[float, str] | None = None
    for entry in getattr(isr, "dissent_items", None) or []:
        entry_text = str(entry or "")
        if not entry_text.strip() or not _shares_point(text, said, entry_text):
            continue
        figure = _own_figure(entry_text, name, participants, labels)
        if figure is None or figure not in on_line or figure >= was:
            continue
        if best is None or figure < best[0]:
            best = (figure, entry_text)
    if best is None:
        return None
    return SettledClaim(name, number, was, best[0], best[1], " ".join(sentence.split()))


def settle_own_entry_lines(
    lines: Sequence[str],
    participants: Sequence[str],
    isrs: Mapping[str, Any],
    labels: Mapping[str, Sequence[str]] | None = None,
) -> tuple[list[SettledLine], dict[str, Any]]:
    """The blocking lines settled by rule, and the answers in force with their claims held so.

    ``lines`` are a mediation's blocking lines in its order; ``isrs`` the
    answers in force by analyst; ``labels`` the other names each participant
    is shown by (its label, its spoken name), so a line naming a peer by
    one is not read as the analyst's own. Returns the settled lines in line
    order and, per analyst a settled claim belongs to, its answer in force
    with each settled claim block held at the lower figure (a copy; ``isrs``
    is not changed). A line not settled is left out, and the debate reads it
    as before. Linear in the lines.
    """
    names = [str(p) for p in participants if str(p).strip()]
    shown = {str(k): [str(x) for x in v or ()] for k, v in (labels or {}).items()}
    settled: list[SettledLine] = []
    held: dict[str, Any] = {}
    # Per analyst, claim number -> the figure it is held at.
    lowered: dict[str, dict[int, float]] = {}
    marks = read_marks(lines)
    for number, (line, mark) in enumerate(zip(lines, marks, strict=True), 1):
        if not mark.blocking:
            continue
        text = without_line_mark(str(line))
        owner = _line_owner(text, names, shown)
        if owner is None:
            continue
        references = read_claim_references([str(line)], names)
        named = sorted(references.named.get(owner) or {})
        written = _numbers_written(text, names)
        if not named or references.unplaced or written is None or set(named) != written:
            continue
        isr = held.get(owner, isrs.get(owner))
        mine = [
            c for n in named if (c := _settle_claim(owner, n, text, isr, names, shown)) is not None
        ]
        if len(mine) != len(named):
            continue
        for claim in mine:
            lowered.setdefault(owner, {})[claim.claim] = claim.now
        held[owner] = _held_at(isrs.get(owner), lowered[owner])
        settled.append(SettledLine(number, str(line), tuple(mine)))
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


def with_settled_by_rule(text: str, sentences: Sequence[str], head: str = SETTLED_HEAD) -> str:
    """``text`` with the settled lines' sentences after it under ``head``, or as it was."""
    said = list(dict.fromkeys(str(s) for s in sentences if str(s).strip()))
    if not said:
        return text
    block = "\n".join([head, *(f"- {s}" for s in said)])
    return f"{text}\n\n{block}" if text else block


def claim_values(sentence: str) -> frozenset[str]:
    """The addresses and quoted values a claim's sentence writes: what a reworded claim keeps.

    Ledger ids are left out, since a revision cites its evidence anew. A
    quoted value counts from four characters.
    """
    return frozenset(
        [
            *(t for t in line_tokens(sentence) if t.startswith("0x")),
            *(f'"{v}"' for v in _quoted_values(sentence)),
        ]
    )


class Raised(NamedTuple):
    """A claim held by rule that a revision states again above its held figure."""

    sentence: str
    analyst: str
    claim_sentence: str


def raised_again(
    name: str, revision_round: int, held: Sequence[Mapping[str, Any]], isr: Any
) -> list[Raised]:
    """Each claim held by rule that ``isr`` states again above its held figure, with its record.

    ``held`` are the settlement records of ``name``'s claims
    (:meth:`SettledLine.records`). A claim is matched by its sentence,
    whitespace collapsed; failing that, by its values (:func:`claim_values`:
    every address and quoted value the held claim wrote, at least one), when
    exactly one claim of the revision writes them all, and the sentence says
    the match was made so. Recorded, never undone: the revision decides.
    """
    rows = [r for r in held if r.get("analyst") == name and r.get("claim_sentence")]
    claims = list(getattr(isr, "claims", None) or [])
    said_of = [" ".join(str(getattr(c, "claim", "") or "").split()) for c in claims]
    out: list[Raised] = []
    for row in rows:
        held_sentence = str(row["claim_sentence"])
        found = [c for c, s in zip(claims, said_of, strict=True) if s == held_sentence]
        how = ""
        if not found:
            values = frozenset(
                str(v) for v in row.get("claim_values") or claim_values(held_sentence)
            )
            if values:
                found = [
                    c for c, s in zip(claims, said_of, strict=True) if values <= claim_values(s)
                ]
                how = " (matched by the addresses and quoted values it writes, reworded)"
                if len(found) != 1:
                    found = []
        # The claim held and a retry's restatement of it may stand side by
        # side: the highest figure the answer gives it is the one compared.
        stated = [
            float(c.confidence)
            for c in found
            if isinstance(getattr(c, "confidence", None), int | float)
            and not isinstance(c.confidence, bool)
        ]
        if stated and round(max(stated), 2) > float(row["now"]):
            sentence = defanged(
                f"The {name} analyst's round-{int(revision_round)} revision states claim "
                f'"{_quoted(held_sentence)}"{how} at {max(stated):.2f} again, above the '
                f"{float(row['now']):.2f} it was held at by rule (its own dispute entry's "
                "figure); the revision's figure stands."
            )
            out.append(Raised(sentence, name, held_sentence))
    return out


def rows_in_force(
    held: Sequence[Mapping[str, Any]], rounds: Sequence[Mapping[str, Any]]
) -> list[Mapping[str, Any]]:
    """The settlement records still held: none whose raise a later round recorded.

    A hold a revision stated again above is told and recorded once; a newer
    mediation that holds the claim again starts a new hold.
    """
    raised: dict[tuple[str, str], int] = {}
    for record in rounds:
        for row in record.get("raised_again") or []:
            if isinstance(row, Mapping):
                key = (str(row.get("analyst")), str(row.get("claim_sentence")))
                raised[key] = max(raised.get(key, -1), int(record.get("round") or 0))
    return [
        r
        for r in held
        if int(r.get("mediation") or 0)
        > raised.get((str(r.get("analyst")), str(r.get("claim_sentence"))), -1)
    ]
