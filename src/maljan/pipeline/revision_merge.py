"""A debate revision merged into the answer in force, claim by claim.

A revision used to stand as the analyst's whole answer: a claim it did not
write again was gone, and the platform only said how many claims it had
before and after. Here a revision changes only what it states:

- a claim it writes again replaces its predecessor;
- a claim it withdraws is removed, with the reason it gives: a
  ``WITHDRAW CLAIM <n>: <reason>`` line (``retry_merge.read_withdrawals``),
  or a claim block under the number of a claim in force whose heading or
  sentence declares the withdrawal ("CLAIM 5 (withdrawn): ...");
- a claim in force that a blocking line of the round's mediation named, and
  that the revision neither wrote again nor withdrew, is withdrawn by rule,
  with the line as its reason: a challenged claim left unanswered never
  reaches the report as if it stood. A line names a claim by its number, in
  a list or inside a bounded range ("claims 32-34",
  ``debate_facts.read_claim_numbers``); a reference that names no claim (a
  longer range, or a number no analyst is named for) withdraws nothing and
  is stated, one sentence per reference (``unplaced_sentence``);
- a claim it writes under a new number, or one that writes again no claim in
  force, is added;
- every other claim in force stays as the answer in force wrote it, marked
  as carried forward from that round (``ClaimEvidence.carried_since_round``),
  and, where a line that does not block named it, with that line
  (``ClaimEvidence.carried_contested_by``).

The identity is the claim block's place in the answer in force, counted from
1: the number the mediator, the questions and every summary name a claim by.
A revision whose every block writes a number, each of which either names a
claim in force the block restates (below) or lies after the last one, is
placed by those numbers. Any other revision is placed by what it states.

A revision block restates a claim in force when it states four fifths of the
claim's content words, or at least half of the claim's values that are no
mere small number (a value of three characters or more, or a technique id)
with at least one of them strong (four characters or more, or a technique
id), or a third of them with the claim's technique id. Values, never words,
may be pooled over several blocks of the revision, and only over blocks that
each state one of the claim's values: a claim split over two of the
revision's claims is written again, a claim whose words merely recur is not.
A revision that writes again or withdraws every claim in force merges
nothing: it stands as written, as it always did.

The rule reads only the lines of the mediation right before the round: a
claim a line of an earlier mediation contested, and that the mediator no
longer listed, is carried with its mark like any other. A claim a blocking
line named that the revision argues in its disputes (by its number, or by
restating it there) is answered, and carried with that line.

Nothing here edits a claim's words; the merge only chooses which claims
stand, and :class:`RevisionMerge` records every choice.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.technique_ids import is_technique_id
from maljan.pipeline.claim_drops import (
    _is_stated,
    _searched,
    claim_values,
    content_words,
    defanged,
)
from maljan.pipeline.debate_facts import UnplacedClaims, read_claim_numbers
from maljan.pipeline.retry_merge import (
    _WITHDRAW_OR_RETRACT_RE,
    _WITHDRAW_WORD_RE,
    _WITHDRAWING_OPENER_RE,
    read_withdrawals,
)

# The share of a claim's values the revision must state to write it again.
RESTATED_SHARE = 0.5
# The share of a claim's content words one revision block must state to write
# it again, whatever values it states.
WORDED_SHARE = 0.8
# The share of a claim's values one block must state, beside its technique
# id, to write it again.
CORRECTED_SHARE = 0.34
# A value shorter than this is a small number that many claims state ("0",
# "17"): it is never counted.
TRIVIAL_LENGTH = 3
# A value this long, or a technique id, is one a match must include.
STRONG_LENGTH = 4

# One line of the round's mediation that named a claim: its number (from 1)
# and whether it blocks.
NamingLine = tuple[int, bool]


@dataclass
class _Block:
    """One claim block: its place (from 1) and every claim read from it."""

    number: int
    claims: list[Any] = field(default_factory=list)

    @property
    def sentence(self) -> str:
        return " ".join(str(getattr(self.claims[0], "claim", "") or "").split())


def _blocks(claims: Sequence[Any]) -> list[_Block]:
    """``claims`` by claim block, numbered by place (``validation.claim_block_indexes``)."""
    from maljan.pipeline.validation import claim_block_indexes

    blocks: list[_Block] = []
    for claim, index in zip(claims, claim_block_indexes(list(claims)), strict=True):
        if index == len(blocks):
            blocks.append(_Block(number=index + 1))
        blocks[index].claims.append(claim)
    return blocks


def _text_of(block: _Block) -> str:
    """Everything a revision block states: sentence, evidence and techniques."""
    parts: list[str] = [str(getattr(block.claims[0], "claim", "") or "")]
    parts.append(str(getattr(block.claims[0], "evidence_ref", "") or ""))
    parts.extend(str(getattr(c, "technique_id", "") or "") for c in block.claims)
    return "\n".join(parts)


def _techniques(block: _Block) -> frozenset[str]:
    return frozenset(
        str(getattr(c, "technique_id", "") or "").strip().upper()
        for c in block.claims
        if getattr(c, "technique_id", None)
    )


def _counted_values(block: _Block) -> frozenset[str]:
    """The values a claim states that a restatement is measured by: no small numbers."""
    values: set[str] = set()
    for claim in block.claims:
        values |= claim_values(
            str(getattr(claim, "claim", "") or ""), getattr(claim, "technique_id", None) or ""
        )
    return frozenset(v for v in values if is_technique_id(v) or len(v) >= TRIVIAL_LENGTH)


def _strong(value: str) -> bool:
    return is_technique_id(value) or len(value) >= STRONG_LENGTH


@dataclass(frozen=True)
class _Reading:
    """What a revision block states, read once."""

    searched: Any
    words: frozenset[str]
    techniques: frozenset[str]


def _read(block: _Block) -> _Reading:
    text = _text_of(block)
    return _Reading(
        searched=_searched(text), words=content_words(text), techniques=_techniques(block)
    )


def _stated(values: frozenset[str], reading: _Reading) -> set[str]:
    return {v for v in values if _is_stated(v, reading.searched)}


def _block_restates(earlier: _Block, reading: _Reading) -> bool:
    """Whether one revision block, read as ``reading``, writes ``earlier`` again."""
    words = content_words(earlier.sentence)
    if words and len(words & reading.words) / len(words) >= WORDED_SHARE:
        return True
    values = _counted_values(earlier)
    if not values:
        return False
    got = _stated(values, reading)
    if not any(_strong(v) for v in got):
        return False
    share = len(got) / len(values)
    if share >= RESTATED_SHARE:
        return True
    return share >= CORRECTED_SHARE and bool(_techniques(earlier) & reading.techniques)


def _restated(earlier: _Block, readings: Sequence[_Reading]) -> tuple[bool, int | None]:
    """``(restated, the first block that restates it by itself or None)``.

    Values may be pooled over the blocks that each state one of the claim's
    values; words never are.
    """
    for index, reading in enumerate(readings):
        if _block_restates(earlier, reading):
            return True, index
    values = _counted_values(earlier)
    if not values:
        return False, None
    pooled: set[str] = set()
    for reading in readings:
        pooled |= _stated(values, reading)
    if any(_strong(v) for v in pooled) and len(pooled) / len(values) >= RESTATED_SHARE:
        return True, None
    return False, None


_OWN_CLAIM_NUMBERS = re.compile(
    r"\bclaims?\s*+#?\s*+(\d++(?:\s*+(?:/|,|&|and|\+)\s*+#?\d++)*+)", re.IGNORECASE
)


def _numbers_written(item: str) -> set[int]:
    """The claim numbers an item writes, each claim of a bounded range among them."""
    out: set[int] = set()
    for match in _OWN_CLAIM_NUMBERS.finditer(item):
        read = read_claim_numbers(item, match.start(1))
        out.update(
            int(n) for n in (read.numbers if read is not None else ()) if len(n.lstrip("0")) <= 6
        )
    return out


def _disputed(earlier: _Block, disputes: Sequence[str]) -> bool:
    """Whether one of the revision's dispute items argues ``earlier``: by number or by statement.

    An item that writes "claim N" for the claim's number, a range bounding
    it among them ("claims 3-5", ``debate_facts.read_claim_numbers``), or
    that restates it (:func:`_block_restates`), answers the line that named it.
    """
    for item in disputes:
        if earlier.number in _numbers_written(item):
            return True
        reading = _Reading(
            searched=_searched(item), words=content_words(item), techniques=frozenset()
        )
        if _block_restates(earlier, reading):
            return True
    return False


def _declares_withdrawal(claim: Any) -> bool:
    """Whether a claim block's heading note or sentence withdraws its own claim."""
    note = str(getattr(claim, "heading_note", "") or "")
    sentence = str(getattr(claim, "claim", "") or "")
    return bool(
        _WITHDRAW_WORD_RE.search(note)
        or _WITHDRAW_OR_RETRACT_RE.search(sentence)
        or _WITHDRAWING_OPENER_RE.match(sentence)
    )


def _written_number(block: _Block) -> int | None:
    written = getattr(block.claims[0], "number", None)
    text = str(written or "").strip()
    return int(text) if text.isdigit() else None


def _spans(numbers: Sequence[int]) -> str:
    """``1, 3-5, 9`` for ``[1, 3, 4, 5, 9]``."""
    out: list[str] = []
    ordered = sorted(numbers)
    start = previous = None
    for number in [*ordered, None]:
        if previous is not None and number == previous + 1:
            previous = number
            continue
        if start is not None:
            out.append(str(start) if start == previous else f"{start}-{previous}")
        start = previous = number
    return ", ".join(out)


def _lines(numbers: Sequence[int]) -> str:
    return ", ".join(f"L{n}" for n in numbers)


@dataclass(frozen=True)
class RevisionMerge:
    """What merging a revision into the answer in force made.

    ``merged`` is the answer that stands, ``None`` when the revision stands as
    written (it wrote again or withdrew every claim in force). ``placed_by``
    is ``"number"`` or ``"statement"``. ``replaced`` are the numbers of the
    claims in force a revision claim wrote again, ``added`` how many revision
    blocks wrote again none, ``withdrawn`` ``(number, sentence, reason)`` per
    claim in force the revision withdrew, ``withdrawn_by_rule`` the same for
    each a blocking line named and the revision left unanswered (with its
    claims, ``ruled_claims``), ``carried`` ``(number, sentence)`` per claim in
    force carried forward, ``unread`` how many withdrawing lines were not read
    exactly (the claims they may name are carried), ``unplaced`` the round's
    claim references that name no claim and may mean this analyst's
    (``debate_facts.UnplacedClaims``): no claim is withdrawn by rule on them.
    """

    merged: Any | None = None
    placed_by: str = ""
    replaced: tuple[int, ...] = ()
    added: int = 0
    withdrawn: tuple[tuple[int, str, str], ...] = ()
    withdrawn_by_rule: tuple[tuple[int, str, str], ...] = ()
    ruled_claims: tuple[Any, ...] = ()
    carried: tuple[tuple[int, str], ...] = ()
    unread: int = 0
    before: int = 0
    after: int = 0
    unplaced: tuple[UnplacedClaims, ...] = ()

    def sentences(self, name: str, revision_round: int) -> list[str]:
        """The run summary's sentences: the merge, each withdrawal, each unplaced reference."""
        out: list[str] = []
        r = int(revision_round)
        if self.carried:
            how = "their numbers" if self.placed_by == "number" else "what they state"
            ruled = (
                f" and {len(self.withdrawn_by_rule)} were withdrawn by rule"
                if self.withdrawn_by_rule
                else ""
            )
            out.append(
                f"The {name} analyst's round-{r} revision wrote {self.after - len(self.carried)} "
                f"claim(s) against {self.before} in force: by {how}, they restate "
                f"{len(self.replaced)} of those and add {self.added}; it withdrew "
                f"{len(self.withdrawn)}{ruled}, and the other {len(self.carried)} stand carried "
                f"forward unchanged (claims {_spans([n for n, _s in self.carried])} of its "
                "answer in force)."
                + (
                    f" {self.unread} line(s) that withdraw were not read exactly."
                    if self.unread
                    else ""
                )
            )
        for number, sentence, reason in self.withdrawn:
            out.append(
                defanged(
                    f"The {name} analyst's round-{r} revision withdrew claim {number} "
                    f'("{sentence}")'
                    + (f": {reason.rstrip('.')}" if reason else " and gave no reason")
                    + "."
                )
            )
        for number, sentence, reason in self.withdrawn_by_rule:
            out.append(rule_sentence(name, r, number, sentence, reason))
        for reference in self.unplaced:
            out.append(unplaced_sentence(name, r, reference))
        return out


def unplaced_sentence(name: str, revision_round: int, reference: UnplacedClaims) -> str:
    """The sentence for a claim reference that names no claim: never acted on in silence."""
    return (
        f"{'Blocking line' if reference.blocking else 'Line'} L{int(reference.line)} of the "
        f"round-{int(revision_round)} mediation writes {reference.claims} and names no claim of "
        f"the {name} analyst by it ({reference.why}): no claim of that analyst's answer in force "
        "is withdrawn by rule on that reference."
    )


def rule_sentence(name: str, revision_round: int, number: int, sentence: str, reason: str) -> str:
    """The sentence for a claim withdrawn by rule, its network values defanged."""
    return defanged(
        f'Claim {number} of the {name} analyst\'s answer in force ("{sentence}") is withdrawn '
        f"by rule after the round-{int(revision_round)} revision: {reason}."
    )


def _by_number(
    first: list[_Block], revision: list[_Block], readings: list[_Reading]
) -> dict[int, int] | None:
    """``{revision block index: claim in force number}`` from written numbers, or ``None``.

    ``None`` when a block wrote no number or one twice, or a number naming a
    claim in force it does not restate: then its numbers may not name the
    claims in force.
    """
    if not revision:
        return None
    by_number = {block.number: block for block in first}
    placed: dict[int, int] = {}
    seen: set[int] = set()
    sentences = {block.sentence: block.number for block in first}
    for index, block in enumerate(revision):
        number = _written_number(block)
        if number is None or number in seen or number < 1:
            return None
        seen.add(number)
        moved = sentences.get(block.sentence)
        if moved is not None and moved != number:
            return None
        earlier = by_number.get(number)
        if earlier is None:
            continue
        if (
            earlier.sentence != block.sentence
            and not _declares_withdrawal(block.claims[0])
            and not _block_restates(earlier, readings[index])
        ):
            return None
        placed[index] = number
    return placed


def _by_statement(first: list[_Block], readings: list[_Reading]) -> tuple[set[int], dict[int, int]]:
    """``(numbers restated, {revision block index: claim in force number})``.

    Each revision block stands at the first claim in force it restates by
    itself.
    """
    restated: set[int] = set()
    target: dict[int, int] = {}
    for earlier in first:
        found, index = _restated(earlier, readings)
        if not found:
            continue
        restated.add(earlier.number)
        if index is not None and index not in target:
            target[index] = earlier.number
    return restated, target


def merge_revision(
    in_force: Any,
    revision: Any,
    answer: str,
    revision_round: int,
    named: Mapping[int, Sequence[NamingLine]] | None = None,
    unplaced: Sequence[UnplacedClaims] = (),
) -> RevisionMerge:
    """``revision`` merged into ``in_force`` by claim (:class:`RevisionMerge`).

    ``answer`` is the revision as written, its ``WITHDRAW`` lines included.
    ``named`` is, per claim number of the answer in force, each line of the
    round's mediation that named it (``debate_facts.claims_named_by_lines``),
    and ``unplaced`` each reference of those lines that names no claim and
    may mean this analyst's (``ClaimReferences.unplaced_for``): it withdraws
    nothing and is stated. ``in_force`` is not changed.
    """
    first_claims = list(getattr(in_force, "claims", None) or [])
    revision_claims = list(getattr(revision, "claims", None) or [])
    first = _blocks(first_claims)
    # A reference whose every number lies past the answer in force names
    # none of its claims, and is no question about this merge.
    unplaced = tuple(u for u in unplaced if int(u.lowest) <= len(first))
    if not first_claims or not revision_claims:
        return RevisionMerge(unplaced=unplaced)
    named = named or {}
    revised = _blocks(revision_claims)
    known = {block.number for block in first}
    read = read_withdrawals(answer)
    withdrawn: dict[int, str] = {}
    for low, high, reason in read.claims:
        a, b = int(low), int(high)
        for number in range(a, b + 1) if a <= b else ():
            if number in known:
                withdrawn.setdefault(number, reason)
    unread = read.unread

    readings = [_read(block) for block in revised]
    numbered = _by_number(first, revised, readings)
    kept_blocks: list[int] = list(range(len(revised)))
    # Where each revision block stands in the merged answer: the number of
    # the claim in force it writes again; a block with none is added.
    target: dict[int, int] = {}
    written_again: set[int] = set()
    if numbered is not None:
        placed_by = "number"
        declared = 0
        for index, block in enumerate(revised):
            written = _written_number(block)
            if written in known and _declares_withdrawal(block.claims[0]):
                # A block under a claim's number that withdraws it: the
                # claim goes, with the block's sentence as the reason. The
                # reader counted its line as a withdrawal not read exactly.
                withdrawn.setdefault(int(written or 0), block.sentence)
                kept_blocks.remove(index)
                declared += 1
            elif index in numbered:
                target[index] = numbered[index]
        unread = max(0, unread - declared)
        written_again = set(target.values())
    else:
        placed_by = "statement"
        written_again, target = _by_statement(first, readings)
    # A claim written again stands as written, whatever a line withdrew.
    for number in written_again:
        withdrawn.pop(number, None)

    disputes = [str(item) for item in getattr(revision, "dissent_items", None) or [] if item]
    # What the revision left unanswered: withdrawn by rule where a blocking
    # line named it and the revision's disputes do not argue it, carried
    # forward otherwise.
    ruled: dict[int, str] = {}
    contested: dict[int, list[int]] = {}
    for block in first:
        if block.number in written_again or block.number in withdrawn:
            continue
        lines = list(named.get(block.number, ()))
        blocking = sorted({line for line, blocks in lines if blocks})
        if blocking and _disputed(block, disputes):
            # The revision did not restate it but argued for it in its
            # disputes: an answer, carried with the line that contested it.
            contested[block.number] = sorted({line for line, _b in lines})
        elif blocking:
            ruled[block.number] = (
                f"named by blocking line {_lines(blocking)} of the round-{int(revision_round)} "
                "mediation; the revision did not restate it"
            )
        elif lines:
            contested[block.number] = sorted({line for line, _b in lines})
    carried_blocks = [
        block
        for block in first
        if block.number not in written_again
        and block.number not in withdrawn
        and block.number not in ruled
    ]
    replaced = tuple(sorted(written_again))
    added = sum(1 for index in kept_blocks if index not in target)
    withdrawn_rows = tuple(
        (block.number, block.sentence, withdrawn[block.number])
        for block in first
        if block.number in withdrawn
    )
    ruled_blocks = [block for block in first if block.number in ruled]
    ruled_rows = tuple(
        (block.number, block.sentence, ruled[block.number]) for block in ruled_blocks
    )
    ruled_claims = tuple(claim for block in ruled_blocks for claim in block.claims)
    if not carried_blocks:
        return RevisionMerge(
            placed_by=placed_by,
            replaced=replaced,
            added=added,
            withdrawn=withdrawn_rows,
            withdrawn_by_rule=ruled_rows,
            ruled_claims=ruled_claims,
            unread=unread,
            before=len(first),
            after=len(kept_blocks),
            unplaced=unplaced,
        )

    # In the order of the answer in force: each claim carried where it stood,
    # each revision block at the first claim it writes again, and the blocks
    # that write none again after them, in the revision's order.
    at: dict[int, list[int]] = {}
    for index in kept_blocks:
        if index in target:
            at.setdefault(target[index], []).append(index)
    claims: list[Any] = []
    carried_numbers = {block.number for block in carried_blocks}
    for block in first:
        if block.number in carried_numbers:
            for claim in block.claims:
                copy = claim.model_copy()
                # The earliest round that carried it is kept.
                if getattr(copy, "carried_since_round", None) is None:
                    copy.carried_since_round = int(revision_round)
                if block.number in contested:
                    copy.carried_contested_by = [
                        f"L{n} (round {int(revision_round)})" for n in contested[block.number]
                    ]
                claims.append(copy)
        for index in at.get(block.number, ()):
            claims.extend(revised[index].claims)
    for index in kept_blocks:
        if index not in target:
            claims.extend(revised[index].claims)
    merged = revision.model_copy(update={"claims": claims})
    return RevisionMerge(
        merged=merged,
        placed_by=placed_by,
        replaced=replaced,
        added=added,
        withdrawn=withdrawn_rows,
        withdrawn_by_rule=ruled_rows,
        ruled_claims=ruled_claims,
        carried=tuple((block.number, block.sentence) for block in carried_blocks),
        unread=unread,
        before=len(first),
        after=len(kept_blocks) + len(carried_blocks),
        unplaced=unplaced,
    )
