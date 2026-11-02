"""A debate revision merged into the answer in force, claim by claim.

A revision used to stand as the analyst's whole answer: a claim it did not
write again was gone, and the platform only said how many claims it had
before and after. Here a revision changes only what it states:

- a claim it writes again replaces its predecessor;
- a claim it withdraws is removed, with the reason it gives: a
  ``WITHDRAW CLAIM <n>: <reason>`` line (``retry_merge.read_withdrawals``),
  or a claim block under the number of a claim in force whose heading or
  sentence declares the withdrawal ("CLAIM 5 (withdrawn): ...");
- a claim it writes under a new number, or one that writes again no claim in
  force, is added;
- a claim in force it neither writes again nor withdraws stays as the answer
  in force wrote it, marked as carried forward from that round
  (``ClaimEvidence.carried_since_round``).

The identity is the claim block's place in the answer in force, counted from
1: the number the mediator, the questions and every summary name a claim by.
A revision whose every block writes a number, each of which either names a
claim in force it shares a value with (or, with no value on either side, its
words) or lies after the last one, is placed by those numbers. Any other
revision is placed by what it states: a claim in force is written again when
the revision's claims together state at least half of its values or four
fifths of its content words (half of its content words, for a claim that
states no value), and stands where the
first revision claim stating that share by itself stands; one the revision
does not restate so is carried forward. A revision that writes again or withdraws
every claim in force merges nothing: it stands as written, as it always did.

Nothing here edits a claim's words; the merge only chooses which claims
stand, and :class:`RevisionMerge` records every choice.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.pipeline.claim_drops import (
    _is_stated,
    _searched,
    claim_values,
    content_words,
    defanged,
)
from maljan.pipeline.retry_merge import (
    _WITHDRAW_OR_RETRACT_RE,
    _WITHDRAW_WORD_RE,
    _WITHDRAWING_OPENER_RE,
    read_withdrawals,
)

# The share of a claim in force's values (or, with none, its content words)
# the revision's claims must state to write that claim again.
RESTATED_SHARE = 0.5
# The share of the content words of a claim that states values the revision's
# claims must state to write it again when they state too few of its values.
WORDED_SHARE = 0.8


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


def _values(block: _Block) -> frozenset[str]:
    values: set[str] = set()
    for claim in block.claims:
        values |= claim_values(
            str(getattr(claim, "claim", "") or ""), getattr(claim, "technique_id", None) or ""
        )
    return frozenset(values)


@dataclass(frozen=True)
class _Reading:
    """What a revision block states, read once."""

    searched: Any
    words: frozenset[str]


def _read(block: _Block) -> _Reading:
    text = _text_of(block)
    return _Reading(searched=_searched(text), words=content_words(text))


def _share(earlier: _Block, reading: _Reading) -> float:
    """How much of ``earlier`` the revision block read as ``reading`` states, from 0 to 1."""
    values = _values(earlier)
    words = content_words(earlier.sentence)
    worded = len(words & reading.words) / len(words) if words else 0.0
    if not values:
        return worded
    share = sum(1 for v in values if _is_stated(v, reading.searched)) / len(values)
    # A claim whose values a correction changed is still the claim nearly
    # all of its words state again.
    return max(share, RESTATED_SHARE if worded >= WORDED_SHARE else 0.0)


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


@dataclass(frozen=True)
class RevisionMerge:
    """What merging a revision into the answer in force made.

    ``merged`` is the answer that stands, ``None`` when the revision stands as
    written (it wrote again or withdrew every claim in force). ``placed_by``
    is ``"number"`` or ``"statement"``. ``replaced`` are the numbers of the
    claims in force a revision claim wrote again, ``added`` how many revision
    blocks wrote again none, ``withdrawn`` ``(number, sentence, reason)`` per
    claim in force withdrawn, ``carried`` ``(number, sentence)`` per claim in
    force carried forward, ``unread`` how many withdrawing lines were not read
    exactly (the claims they may name are carried).
    """

    merged: Any | None = None
    placed_by: str = ""
    replaced: tuple[int, ...] = ()
    added: int = 0
    withdrawn: tuple[tuple[int, str, str], ...] = ()
    carried: tuple[tuple[int, str], ...] = ()
    unread: int = 0
    before: int = 0
    after: int = 0

    def sentences(self, name: str, revision_round: int) -> list[str]:
        """The run summary's sentences for this merge: one for the merge, one per withdrawal."""
        out: list[str] = []
        r = int(revision_round)
        if self.carried:
            numbers = ", ".join(str(n) for n, _s in self.carried)
            how = "their numbers" if self.placed_by == "number" else "what they state"
            out.append(
                f"The {name} analyst's round-{r} revision wrote {self.after - len(self.carried)} "
                f"claim(s) against {self.before} in force: by {how}, they restate "
                f"{len(self.replaced)} of those and add {self.added}; it withdrew "
                f"{len(self.withdrawn)}, and the other {len(self.carried)} stand carried forward "
                f"unchanged (claims {numbers} of its answer in force)."
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
        return out


def _by_number(
    first: list[_Block], revision: list[_Block], readings: list[_Reading]
) -> dict[int, int] | None:
    """``{revision block index: claim in force number}`` from written numbers, or ``None``.

    ``None`` when a block wrote no number or one twice, or a number naming a
    claim in force with which it shares nothing: then its numbers may not
    name the claims in force.
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
            and not _share(earlier, readings[index])
        ):
            return None
        placed[index] = number
    return placed


def _by_statement(
    first: list[_Block], revised: list[_Block], readings: list[_Reading]
) -> tuple[set[int], dict[int, int]]:
    """``(numbers restated, {revision block index: claim in force number})``.

    A claim in force is restated when the revision's claims together state
    at least :data:`RESTATED_SHARE` of it: a claim the revision split over
    two of its own is written again. Each revision block stands at the first
    claim in force it states that share of by itself.
    """
    text = "\n".join(_text_of(block) for block in revised)
    whole = _Reading(searched=_searched(text), words=content_words(text))
    restated = {block.number for block in first if _share(block, whole) >= RESTATED_SHARE}
    target: dict[int, int] = {}
    for earlier in first:
        if earlier.number not in restated:
            continue
        for index, reading in enumerate(readings):
            if index not in target and _share(earlier, reading) >= RESTATED_SHARE:
                target[index] = earlier.number
                break
    return restated, target


def merge_revision(in_force: Any, revision: Any, answer: str, revision_round: int) -> RevisionMerge:
    """``revision`` merged into ``in_force`` by claim (:class:`RevisionMerge`).

    ``answer`` is the revision as written, its ``WITHDRAW`` lines included.
    ``in_force`` is not changed.
    """
    first_claims = list(getattr(in_force, "claims", None) or [])
    revision_claims = list(getattr(revision, "claims", None) or [])
    if not first_claims or not revision_claims:
        return RevisionMerge()
    first = _blocks(first_claims)
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
        written_again, target = _by_statement(first, revised, readings)
    # A claim written again stands as written, whatever a line withdrew.
    for number in written_again:
        withdrawn.pop(number, None)

    carried_blocks = [
        block
        for block in first
        if block.number not in written_again and block.number not in withdrawn
    ]
    replaced = tuple(sorted(written_again))
    added = sum(1 for index in kept_blocks if index not in target)
    withdrawn_rows = tuple(
        (block.number, block.sentence, withdrawn[block.number])
        for block in first
        if block.number in withdrawn
    )
    if not carried_blocks:
        return RevisionMerge(
            placed_by=placed_by,
            replaced=replaced,
            added=added,
            withdrawn=withdrawn_rows,
            unread=unread,
            before=len(first),
            after=len(kept_blocks),
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
                if getattr(copy, "carried_since_round", None) is None:
                    copy.carried_since_round = int(revision_round)
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
        carried=tuple((block.number, block.sentence) for block in carried_blocks),
        unread=unread,
        before=len(first),
        after=len(kept_blocks) + len(carried_blocks),
    )
