"""The mediator's rulings on the blocking lines the round limit leaves undecided.

A debate the round limit ends while its last mediation still lists blocking
lines used to hand those lines on as they stood: no analyst revised over them,
and nobody decided them. A real point raised there (haiku11: the anti-debug
line against an entry read in the debate) never reached the claims.

When the router would have opened another round and the limit forbids it
(``routing.HARD_LIMIT``), the mediator is asked one question more, in its own
mediation's conversation, with ``read_evidence`` over the run's ledger
(``JudgeAgent.rule_on_standing_lines``): for each blocking line, whether the
entries it cites and the entries cited against it uphold it. No round is
held and no analyst is called.

Each ruling is written onto the claims the line names, read as the revision
merge reads them (``debate_facts.claims_named_by_lines``), and only where the
claim shares a ledger id or an address with the line (with the reference's own
clause, for a claim a range reaches, as ``revision_merge`` withdraws by rule),
as a note the claim carries to the
judge's summary, the transcript and the report
(``ClaimEvidence.limit_rulings``, ``isr_models.carried_note``). The claim
itself stands as its analyst wrote it: a ruling never removes a value, and a
line that names no claim, or a reference that names none, is stated with the
reason. Every ruling, every line the answer did not rule on and every
question not made is a sentence in the run summary.

The reader of the answer is linear in its length (one anchored pattern per
line, possessive quantifiers).
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from malspark.pipeline.claim_drops import defanged
from malspark.pipeline.debate_facts import claims_named_by_lines, line_tokens, read_marks
from malspark.pipeline.revision_merge import _blocks, claim_tokens_by_number
from malspark.pipeline.routing import debate_rounds, route_within_limit, with_debate_start

# How much of a ruling's reason a note or a sentence quotes.
REASON_LIMIT = 300
# How much of a blocking line a sentence quotes.
LINE_LIMIT = 300

# One ruling line: "L2: UPHELD: reason", "- **L2** - NOT UPHELD - reason". The
# decision word stands whole; the reason is the rest of the line.
_RULING = re.compile(
    r"^[\s*_`#>\-]*+L(\d{1,3}+)\b[\s*_`]*+[:.\-–—)]?+[\s*_`]*+"
    r"(NOT[\s_]++UPHELD|UPHELD)\b[\s*_`]*+[:.\-–—]?+[\s*_`]*+(.*+)$",
    re.IGNORECASE,
)
# Characters a quoted reason never carries into a note: they would read as a
# citation bracket, a table cell or markup.
_NOT_IN_A_REASON = str.maketrans({"[": "(", "]": ")", "|": "/", "<": " ", ">": " ", "`": "'"})


@dataclass(frozen=True)
class Ruling:
    """The mediator's ruling on one blocking line: upheld or not, and its reason."""

    line: int
    upheld: bool
    reason: str


def clean_quote(text: Any, limit: int) -> str:
    """Model text fit to quote: one line, no bracket or markup character, bounded.

    The network values it names are written defanged after it is bounded, so
    a URL or an address a reason quotes never stands live in a claim's note.
    """
    one_line = " ".join(str(text or "").split()).translate(_NOT_IN_A_REASON)
    one_line = " ".join(one_line.split())
    bounded = one_line if len(one_line) <= limit else f"{one_line[: limit - 1].rstrip()}…"
    return defanged(bounded)


# A blocking line with the number the mediation's block gave it.
NumberedLine = tuple[int, str]


def numbered_blocking(lines: Sequence[str] | Sequence[NumberedLine]) -> list[NumberedLine]:
    """``lines`` as ``(number, line)``, the blocking ones only, each with its own number.

    Plain lines are numbered from 1 in the order given, as the block listed
    them. A line the mediator marked ``[not blocking: ...]`` (``read_marks``)
    is left out and lends no number to another: the question and the rulings
    speak only of lines that block.
    """
    pairs = [
        (int(item[0]), str(item[1])) if isinstance(item, tuple) else (index, str(item))
        for index, item in enumerate(lines, 1)
    ]
    marks = read_marks([line for _number, line in pairs])
    return [pair for pair, mark in zip(pairs, marks, strict=True) if mark.blocking]


class RulingsRead(dict[int, Ruling]):
    """``{line number: Ruling}`` as read, with a sentence for each ruling not read (``stated``)."""

    def __init__(
        self, rows: Mapping[int, Ruling] | None = None, stated: Sequence[str] = ()
    ) -> None:
        super().__init__(rows or {})
        self.stated: list[str] = list(stated)


def read_rulings(text: str, numbers: int | Iterable[int]) -> RulingsRead:
    """The rulings read from the mediator's answer, for the line numbers of the block.

    ``numbers`` is the block's line numbers (an ``int`` reads 1 to it). A line
    ruled twice the same way is read once; a line given two different
    rulings has none, and that is stated; a number that is no line of the
    block is no ruling, and is stated. Linear in the answer.
    """
    wanted = set(range(1, numbers + 1)) if isinstance(numbers, int) else set(numbers)
    found: dict[int, Ruling] = {}
    twice: set[int] = set()
    outside: dict[int, None] = {}
    for raw in str(text or "").splitlines():
        match = _RULING.match(raw)
        if match is None:
            continue
        number = int(match.group(1))
        if number not in wanted:
            outside.setdefault(number, None)
            continue
        upheld = not match.group(2).upper().startswith("NOT")
        earlier = found.get(number)
        if earlier is not None:
            if earlier.upheld != upheld:
                twice.add(number)
            continue
        found[number] = Ruling(number, upheld, clean_quote(match.group(3), REASON_LIMIT))
    stated = [
        f"The mediator's answer gave two different rulings on blocking line L{number}; "
        "neither is read, and the claims it names stand with no ruling."
        for number in sorted(twice)
    ]
    stated += [
        f"The mediator's answer ruled on L{number}, which is no blocking line of the block; "
        "that ruling is not read."
        for number in outside
    ]
    return RulingsRead({n: r for n, r in found.items() if n not in twice}, stated)


def lines_text(lines: Sequence[str] | Sequence[NumberedLine]) -> str:
    """The blocking lines as the question lists them, each with the number the block gave it."""
    return "Blocking lines:\n" + "\n".join(
        f"L{number}: {' '.join(line.split())}" for number, line in numbered_blocking(lines)
    )


def ruling_note(mediation_round: int, ruling: Ruling) -> str:
    """The note a claim carries for one ruling (``ClaimEvidence.limit_rulings``).

    Neutral and attributed: a line names the claims on both of its sides, so
    the note says which line names the claim and what the mediator ruled on
    the line, never which side the claim is on.
    """
    said = "UPHELD" if ruling.upheld else "NOT UPHELD"
    reason = f": {ruling.reason}" if ruling.reason else ""
    return (
        f"at the round limit the mediator ruled blocking line L{ruling.line} of the "
        f"round-{int(mediation_round)} mediation, which names this claim, {said}{reason} "
        "(the mediator's ruling)"
    )


@dataclass
class LimitRulings:
    """What the rulings made: the claims marked, per analyst, and every sentence said."""

    isrs: dict[str, Any] = field(default_factory=dict)
    sentences: list[str] = field(default_factory=list)


def round_limit(config: Any, stage: Any) -> int:
    """The round limit debate ``stage`` is routed by, as ``routing.ConsensusRouter`` reads it."""
    options = getattr(stage, "debate", None)
    if options is not None:
        return int(options.max_rounds)
    return int(config.negotiation.max_iterations)


def state_after(state: Mapping[str, Any], update: Mapping[str, Any], stage: str | None) -> dict:
    """The state the router reads once the mediation's ``update`` is applied.

    The lists the graph adds to are added to, the debate's start recorded as
    the stage's wrapper records it (``routing.with_debate_start``), and every
    other key the update writes replaces the state's.
    """
    update = with_debate_start(state, stage, dict(update))
    after = dict(state)
    for key, value in update.items():
        if key in ("discussion_history", "confidence_history", "revision_rounds"):
            after[key] = [*(state.get(key) or []), *(value or [])]
        elif key == "debate_starts":
            after[key] = {**(state.get(key) or {}), **(value or {})}
        else:
            after[key] = value
    return after


def ends_at_the_limit(
    state: Mapping[str, Any], update: Mapping[str, Any], stage: str | None, max_rounds: int
) -> bool:
    """Whether the router ends the debate on this mediation only because of the round limit.

    ``True`` when the mediation holds the last round the limit allows and the
    router would otherwise open a revision round (``routing.HARD_LIMIT``);
    ``False`` when any other rule ends it there, or the debate goes on.
    """
    after = state_after(state, update, stage)
    if debate_rounds(after, stage) < int(max_rounds):
        return False
    route, _reason = route_within_limit(after, log=False, stage=stage)
    return route == "revision"


def _quoted_line(line: str) -> str:
    return clean_quote(line, LINE_LIMIT)


def mark_claims(
    lines: Sequence[str] | Sequence[NumberedLine],
    rulings: Mapping[int, Ruling],
    isr_reports: Mapping[str, Any],
    participants: Sequence[str],
    mediation_round: int,
) -> LimitRulings:
    """Each ruling written onto the claims its line names, and every sentence said.

    ``lines`` are the mediation's lines, as ``(number, line)`` or numbered
    from 1 as the block listed them; only the blocking ones are read
    (:func:`numbered_blocking`), each by its own number. A claim is marked
    only when it shares a ledger id or an address with what names it: the
    line, or, for a claim the line reaches
    only through a range or a list, that reference's own clause (as
    ``revision_merge`` withdraws by rule). A claim number the mediator gave
    from another numbering than the answer in force (haiku10's last line
    named claims of a loop by numbers whose claims in force are about other
    things) is so never marked with a ruling about something else; it is
    stated. A reference that names no claim marks none and is stated.
    ``isr_reports`` is not changed: the marked answers are copies.
    """
    r = int(mediation_round)
    out = LimitRulings(sentences=list(getattr(rulings, "stated", ()) or ()))
    blocking = numbered_blocking(lines)
    by_number = dict(blocking)
    # A ruling on a number that is no blocking line (one marked not blocking,
    # or none of the block's) is not read, and that is said.
    out.sentences += [
        f"The mediator's answer ruled on L{n}, which is no blocking line of the block; "
        "that ruling is not read."
        for n in sorted(rulings)
        if n not in by_number
    ]
    rulings = {n: ruling for n, ruling in rulings.items() if n in by_number}
    for number, line_text in blocking:
        ruling = rulings.get(number)
        if ruling is None:
            quoted = _quoted_line(line_text)
            out.sentences.append(
                defanged(
                    f"Blocking line L{number} of the round-{r} mediation stood at the round limit, "
                    f'and the mediator\'s answer gave no ruling on it ("{quoted}"); '
                    "the claims it names stand as written, with no ruling."
                )
            )
            continue
        said = "upheld" if ruling.upheld else "did not uphold"
        out.sentences.append(
            defanged(
                f"At the round limit the mediator {said} blocking line L{number} of the round-{r} "
                f'mediation ("{_quoted_line(line_text)}")'
                + (f": {ruling.reason}" if ruling.reason else "")
                + "."
            )
        )
    if not rulings:
        out.sentences = list(dict.fromkeys(out.sentences))
        return out
    owners = {name: claim_tokens_by_number(isr_reports.get(name)) for name in participants}
    # Read in place, each line at its own number: a line left out stands as
    # an empty one, which names nothing.
    placed = [by_number.get(n, "") for n in range(1, max(by_number) + 1)]
    named = claims_named_by_lines(placed, list(participants), owners)
    # The lines whose ruling was written onto a claim, and those a sentence
    # already says why it was not.
    marked_lines: set[int] = set()
    stated_lines: set[int] = set()
    for name in participants:
        rows = named.get(name)
        isr = isr_reports.get(name)
        for reference in getattr(rows, "unplaced", ()) or ():
            if reference.line in rulings:
                out.sentences.append(_unplaced_sentence(name, r, reference))
                stated_lines.add(int(reference.line))
        if not rows or isr is None:
            continue
        claims = list(getattr(isr, "claims", None) or [])
        expanded = dict(getattr(rows, "expanded", {}) or {})
        notes: dict[int, list[tuple[int, str]]] = {}
        for block in _blocks(claims):
            reaching = {e.line: e for e in expanded.get(block.number, ())}
            for line, _blocking in rows.get(block.number, ()):
                ruling = rulings.get(line)
                if ruling is None:
                    continue
                # The tokens the reference speaks with: its own clause for a
                # range or a list, the whole line for a number it names.
                spoken = reaching[line].tokens if line in reaching else line_tokens(by_number[line])
                if not spoken & _block_tokens(block):
                    quoted = _quoted_line(block.sentence)
                    reference = (
                        reaching[line].reference if line in reaching else f"claim {block.number}"
                    )
                    out.sentences.append(
                        defanged(
                            f"Blocking line L{line} of the round-{r} mediation names "
                            f"{reference} of the {name} analyst; claim "
                            f'{block.number} ("{quoted}") shares no ledger id '
                            "or address with it, so the ruling is not written onto it."
                        )
                    )
                    stated_lines.add(line)
                    continue
                notes.setdefault(block.number, []).append((line, ruling_note(r, ruling)))
                marked_lines.add(line)
        if not notes:
            continue
        copies: list[Any] = []
        for block in _blocks(claims):
            for claim in block.claims:
                if block.number in notes:
                    copy = claim.model_copy()
                    copy.limit_rulings = [
                        *list(claim.limit_rulings or []),
                        *(note for _line, note in notes[block.number]),
                    ]
                    copies.append(copy)
                else:
                    copies.append(claim)
        out.isrs[name] = isr.model_copy(update={"claims": copies})
        for number, written in sorted(notes.items()):
            on = ", ".join(f"L{line}" for line, _note in written)
            out.sentences.append(
                f"The ruling on {on} is written onto claim {number} of the {name} analyst's "
                "answer in force, which stands as written."
            )
    for number in sorted(set(rulings) - marked_lines - stated_lines):
        out.sentences.append(
            f"Blocking line L{number} of the round-{r} mediation names no claim the platform "
            "reads for an analyst; its ruling is written onto no claim."
        )
    out.sentences = list(dict.fromkeys(out.sentences))
    return out


def _block_tokens(block: Any) -> frozenset[str]:
    return line_tokens(
        "\n".join(
            f"{getattr(c, 'claim', '') or ''}\n{getattr(c, 'evidence_ref', '') or ''}"
            for c in block.claims
        )
    )


def _unplaced_sentence(name: str, mediation_round: int, reference: Any) -> str:
    return (
        f"Blocking line L{int(reference.line)} of the round-{int(mediation_round)} mediation "
        f"writes {reference.claims} for the {name} analyst and {reference.why}: its ruling is "
        "written onto no claim on that reference."
    )


async def rule_at_the_limit(
    judge: Any,
    lines: Sequence[str] | Sequence[NumberedLine],
    isr_reports: Mapping[str, Any],
    participants: Sequence[str],
    mediation_round: int,
    ledger: Sequence[Any] | None,
    run: Callable[[Any], Awaitable[str]],
) -> LimitRulings:
    """The mediator's rulings on ``lines``, asked once, written onto the claims they name.

    ``run`` awaits the judge's question where the judge's calls run
    (``base_agent.run_on_agent_loop``). A question that fails, is not made or
    brings no ruling back changes no claim and is said, with the reason the
    judge recorded (``JudgeAgent.limit_ruling_failure``) where it gave one.
    """
    blocking = numbered_blocking(lines)
    if not blocking:
        return LimitRulings()
    try:
        answer = await run(judge.rule_on_standing_lines(lines_text(blocking), ledger))
    except Exception as exc:  # noqa: BLE001 — a question that failed changes nothing
        return LimitRulings(
            sentences=[
                not_ruled_sentence(
                    mediation_round, len(blocking), f"it failed: {type(exc).__name__}"
                )
            ]
        )
    if not str(answer or "").strip():
        why = getattr(judge, "limit_ruling_failure", "")
        return LimitRulings(
            sentences=[
                not_ruled_sentence(
                    mediation_round,
                    len(blocking),
                    why if isinstance(why, str) and why else "the question was not answered",
                )
            ]
        )
    return mark_claims(
        blocking,
        read_rulings(answer, [n for n, _line in blocking]),
        isr_reports,
        participants,
        mediation_round,
    )


def not_ruled_sentence(mediation_round: int, count: int, why: str) -> str:
    """The sentence for a limit question that brought no ruling back."""
    return (
        f"The round limit ended the debate on {int(count)} blocking line(s) of the "
        f"round-{int(mediation_round)} mediation; the mediator gave no ruling on them ({why}), "
        "so the claims they name stand as written."
    )
