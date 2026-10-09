"""A validation retry merged into the answer it fixes, claim by claim, by the claim's block number.

The validation turn asks an analyst to fix the claims a check flagged. Its
retry used to be taken as the analyst's whole answer, so every claim it did
not write again was lost and then had to be asked back. Here the retry changes
only what it writes:

- a claim it writes again under the number of a claim block of the answer it
  fixes replaces that block, every claim the block reads (one per technique
  id) at once;
- a claim it takes out with a ``WITHDRAW CLAIM <n>`` line is withdrawn, with
  the reason the line gives;
- a claim under a number the answer it fixes did not use is added;
- every other claim stays as the answer it fixes wrote it.

Findings are merged the same way by their title: a finding the retry writes
again under the same title replaces it, a ``WITHDRAW FINDING`` line takes one
out and a finding with a new title is added. A finding the retry left
unwritten while it added a new title may be the one it renamed, so it is put
to the analyst (``unplaced``) rather than kept beside the new one in silence.

The merged answer is the first answer with those changes and nothing else: its
disputes, its notes and every field the retry does not write stay its own.

The identity is the claim block's number: its place among the answer's claim
blocks, counted from 1 (``validation.claim_block_indexes``). It is the one
number the platform names claims by everywhere: a flag's path
(``claims[<block>]``), a question's "claim N", and the question that asks
for the retry. The answer being fixed has it when it was read from one
written answer, with every block it began read, none set aside, and the
numbers its headings wrote, if any, equal to their places. Every retry block
must write its number.

Nothing here edits a claim's words: the merge only chooses which version of
each claim stands. Where the numbers do not place the retry beyond doubt it
merges nothing and says why (:attr:`RetryMerge.why`); the caller then asks the
analyst once for its whole corrected answer. The doubts are a block written
without its number or twice, a block left unread, a ``WITHDRAW`` line not
read exactly or naming what the answer has not, a number both written and
withdrawn, a sentence written as written under another number, a claim no
question was about written again with no value in common with the claim it
replaces (or with no value on either side to compare), and a retry that wrote
again a claim no question was about while it left a claim a question was
about neither written nor withdrawn.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from maljan.agents.claim_headings import LINE_PREFIX
from maljan.pipeline.claim_drops import claim_values, dropped_claims

_MARKS = r"[ \t*_`]"
# One claim number or a range of them: ``7``, ``#7``, ``3-5``, ``3 to 5``.
_NUMBER_OR_RANGE = rf"#?\d++(?:{_MARKS}*+(?:-|–|—|\bto\b){_MARKS}*+#?\d++)?+"
# ``WITHDRAW CLAIM 7: reason``, ``WITHDRAW CLAIMS 3, 5 and 9 - reason``,
# ``withdraw claims 1-3``: any case, marks and a list marker before it, its
# reason after a mark or ``because``, or nothing after it.
_WITHDRAW_CLAIM_RE = re.compile(
    r"^" + LINE_PREFIX + rf"withdraw{_MARKS}++claims?+{_MARKS}*+"
    rf"(?P<numbers>{_NUMBER_OR_RANGE}(?:{_MARKS}*+(?:,|&|\band\b){_MARKS}*+{_NUMBER_OR_RANGE})*+)"
    rf"{_MARKS}*+(?:$|(?:[:.\-–—)]|\bbecause\b){_MARKS}*+(?P<reason>.*)$)",
    re.IGNORECASE,
)
# ``WITHDRAW FINDING "<title>": <reason>``, or ``WITHDRAW FINDING: <title>``.
_WITHDRAW_FINDING_RE = re.compile(
    r"^" + LINE_PREFIX + rf"withdraw{_MARKS}++finding{_MARKS}*+"
    rf"(?:\"(?P<quoted>[^\"\n]+)\"{_MARKS}*+(?:[:.\-–—]{_MARKS}*+(?P<reason>.*))?+"
    r"|:(?P<title>.*))$",
    re.IGNORECASE,
)
# Any line that begins with the word: one the two forms above do not read
# exactly is a doubt, never a line passed over.
_WITHDRAW_LINE_RE = re.compile(r"^" + LINE_PREFIX + r"withdraw\b", re.IGNORECASE)
_NUMBER_RE = re.compile(r"\d++")
_RANGE_SPLIT_RE = re.compile(r"(?:,|&|\band\b)", re.IGNORECASE)
# Where a flag names the claim block it is about: ``static.claims[5].T1041``.
_CLAIM_PATH_RE = re.compile(r"claims\[(\d++)\]")


def flagged_blocks(violations: Iterable[Any]) -> list[int]:
    """The claim blocks the flags in ``violations`` name by their paths, each once, in order."""
    found: dict[int, None] = {}
    for violation in violations:
        match = _CLAIM_PATH_RE.search(str(getattr(violation, "path", "") or ""))
        if match is not None:
            found.setdefault(int(match.group(1)))
    return list(found)


def folded_title(value: Any) -> str:
    """A finding's title as two titles are compared: case, marks and spacing aside."""
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(value or "").lower()).split())


def _number(digits: str) -> str:
    return digits.lstrip("0") or "0"


def _said(reason: str | None) -> str:
    return str(reason or "").strip().strip("*_`").strip()


@dataclass(frozen=True)
class Withdrawals:
    """What a retry's ``WITHDRAW`` lines read.

    ``claims`` is ``(first, last, reason)`` per number or range, as digits;
    ``findings`` is ``(folded title, title as written, reason)``; ``unread``
    counts the lines that begin with the word and were not read exactly.
    """

    claims: tuple[tuple[str, str, str], ...] = ()
    findings: tuple[tuple[str, str, str], ...] = ()
    unread: int = 0

    def __bool__(self) -> bool:
        return bool(self.claims or self.findings)


def read_withdrawals(text: str) -> Withdrawals:
    """The ``WITHDRAW`` lines of ``text``, in order, each read once from its start."""
    claims: list[tuple[str, str, str]] = []
    findings: list[tuple[str, str, str]] = []
    unread = 0
    for line in str(text or "").splitlines():
        if _WITHDRAW_LINE_RE.match(line) is None:
            continue
        found = _WITHDRAW_CLAIM_RE.match(line)
        if found is not None:
            reason = _said(found.group("reason"))
            for part in _RANGE_SPLIT_RE.split(found.group("numbers")):
                ends = _NUMBER_RE.findall(part)
                if ends:
                    claims.append((_number(ends[0]), _number(ends[-1]), reason))
            continue
        titled = _WITHDRAW_FINDING_RE.match(line)
        written = ""
        if titled is not None:
            written = _said(titled.group("quoted") or titled.group("title"))
        if titled is None or not folded_title(written):
            unread += 1
            continue
        findings.append((folded_title(written), written, _said(titled.group("reason"))))
    return Withdrawals(claims=tuple(claims), findings=tuple(findings), unread=unread)


@dataclass
class _Block:
    number: str
    claims: list[Any] = field(default_factory=list)


def _parse_left_unread(isr: Any) -> str:
    """Why the parse of ``isr`` left a claim block it began unread, or ``""``."""
    if int(getattr(isr, "blocks_without_confidence", 0) or 0):
        return "a claim block stated no confidence"
    if list(getattr(isr, "confidence_unreadable", None) or []):
        return "a claim block's confidence could not be read"
    if str(getattr(isr, "claims_unread_reason", "") or ""):
        return "a claim block it began was not read"
    return ""


def _first_blocks(first: Any) -> tuple[list[_Block], str]:
    """The answer being fixed by claim block, numbered by place, or why it cannot be."""
    from maljan.pipeline.validation import claim_block_indexes

    claims = list(getattr(first, "claims", None) or [])
    places = claim_block_indexes(claims)
    blocks: list[_Block] = []
    for claim, place in zip(claims, places, strict=True):
        ordinal = getattr(claim, "block", None)
        if ordinal is None:
            return [], "a claim was not read from a claim block"
        if int(ordinal) != place:
            # The reader's own count and the platform's disagree: claims of
            # answers read apart and put together, or set aside after reading.
            return [], "the answer's claim blocks are not one answer's blocks in order"
        number = str(place + 1)
        written = getattr(claim, "number", None)
        if written is not None and written != number:
            return [], (
                f"the answer being fixed numbered a claim {written} where it is claim {number}"
            )
        if blocks and blocks[-1].number == number:
            blocks[-1].claims.append(claim)
        else:
            blocks.append(_Block(number=number, claims=[claim]))
    return blocks, ""


def numbering_unsettled(first: Any) -> str:
    """Why a retry of ``first`` cannot be merged by claim number, or ``""`` when it can.

    Decided before the retry is asked, so the question names claims by number
    only when they can be named so.
    """
    if not list(getattr(first, "claims", None) or []):
        return "the answer being fixed has no claim"
    if not str(getattr(first, "answer_text", "") or "").strip():
        return "the answer being fixed was not written as one answer"
    if list(getattr(first, "gate_removed", None) or []):
        return "claims of the answer being fixed were set aside before it was checked"
    unread = _parse_left_unread(first)
    if unread:
        return f"in the answer being fixed, {unread}"
    return _first_blocks(first)[1]


def _retry_blocks(claims: Sequence[Any]) -> tuple[list[_Block], str]:
    """The retry's claim blocks, each by the number it wrote, or why they cannot be placed."""
    blocks: list[_Block] = []
    last: int | None = None
    seen: set[str] = set()
    for claim in claims:
        ordinal = getattr(claim, "block", None)
        if ordinal is None:
            return [], "a claim was not read from a claim block"
        written = getattr(claim, "number", None)
        if blocks and ordinal == last:
            blocks[-1].claims.append(claim)
            continue
        last = ordinal
        if written is None:
            return [], "the retry wrote a claim block without its number"
        if written in seen:
            return [], f"the retry wrote claim {written} twice"
        seen.add(written)
        blocks.append(_Block(number=written, claims=[claim]))
    return blocks, ""


def _sentence(block: _Block) -> str:
    """A block's sentence as two are compared: spacing aside."""
    return " ".join(str(getattr(block.claims[0], "claim", "") or "").split())


def _sentence_values(block: _Block) -> frozenset[str]:
    """The values a block's sentence states; its technique ids aside, which a fix may change."""
    return claim_values(str(getattr(block.claims[0], "claim", "") or ""), "")


def _digits_key(number: str) -> tuple[int, str]:
    return (len(number), number)


@dataclass(frozen=True)
class RetryMerge:
    """What merging a retry into the answer it fixes made, or why it merged nothing.

    ``merged`` is the answer that stands, ``None`` when the numbers did not
    place the retry (``why``). ``withdrawn`` is ``(kind, item, reason)`` for
    each claim block and finding of the answer being fixed that a
    ``WITHDRAW`` line read exactly names, whether or not the rest merged:
    the item is the first answer's own object (each claim of a block). The
    caller applies and records them on every path. ``unplaced`` is
    ``(kind, item, missing values)`` for each claim a question was about that
    the retry neither wrote again nor withdrew, and each finding it left
    unwritten while it added a new title: each stays in ``merged`` as
    written, and they are the items left to ask about.
    """

    merged: Any | None = None
    why: str = ""
    replaced: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    unchanged: int = 0
    findings_replaced: int = 0
    findings_added: int = 0
    withdrawn: tuple[tuple[str, Any, str], ...] = ()
    unplaced: tuple[tuple[str, Any, tuple[str, ...]], ...] = ()

    def record(self) -> dict[str, Any]:
        """The merge on the loop's record: what it did, or why it did nothing."""
        claims_out = sorted({id(item) for kind, item, _r in self.withdrawn if kind == "claim"})
        findings_out = sum(1 for kind, _item, _r in self.withdrawn if kind == "finding")
        if self.merged is None:
            return {
                "merged": False,
                "why": self.why,
                "withdrawn_claims": len(claims_out),
                "withdrawn_findings": findings_out,
            }
        return {
            "merged": True,
            "replaced": list(self.replaced),
            "added": list(self.added),
            "unchanged_blocks": self.unchanged,
            "withdrawn_claims": len(claims_out),
            "findings_replaced": self.findings_replaced,
            "withdrawn_findings": findings_out,
            "findings_added": self.findings_added,
            "unplaced": len(self.unplaced),
        }


def _withdrawn_items(
    first_blocks: Sequence[_Block], first_findings: Sequence[Any], read: Withdrawals
) -> tuple[list[tuple[str, Any, str]], dict[str, str], set[str], str]:
    """``(items, number → reason, titles withdrawn, doubt)`` for what the lines read exactly name.

    A range names every number from its first to its last; both ends must be
    numbers of the answer. Linear in the answer and the lines: the ranges
    are laid over the answer's numbers once.
    """
    by_number = {block.number: index for index, block in enumerate(first_blocks)}
    doubt = ""
    # Where each range starts and stops, over the blocks in order.
    opens: dict[int, list[str]] = {}
    closes: dict[int, int] = {}
    for low, high, reason in read.claims:
        if low not in by_number or high not in by_number:
            missing = low if low not in by_number else high
            doubt = doubt or f"the retry withdrew claim {missing}, which the answer has not"
            continue
        start, stop = by_number[low], by_number[high]
        if start > stop:
            doubt = doubt or f"the retry withdrew claims {low} to {high}, which run backwards"
            continue
        opens.setdefault(start, []).append(reason)
        closes[stop + 1] = closes.get(stop + 1, 0) + 1
    numbers: dict[str, str] = {}
    open_reasons: list[str] = []
    still_open = 0
    for index, block in enumerate(first_blocks):
        still_open -= closes.get(index, 0)
        for reason in opens.get(index, []):
            open_reasons.append(reason)
            still_open += 1
        if still_open > 0:
            numbers[block.number] = next((r for r in reversed(open_reasons) if r), "")
    items: list[tuple[str, Any, str]] = [
        ("claim", claim, numbers[block.number])
        for block in first_blocks
        if block.number in numbers
        for claim in block.claims
    ]
    titles = {title for title, _written, _reason in read.findings}
    reasons = {title: reason for title, _written, reason in read.findings}
    have = {folded_title(getattr(f, "title", "")) for f in first_findings}
    for title in titles:
        if title not in have:
            doubt = doubt or "the retry withdrew a finding the answer has not"
    items += [
        ("finding", finding, reasons[folded_title(getattr(finding, "title", ""))])
        for finding in first_findings
        if folded_title(getattr(finding, "title", "")) in titles
    ]
    return items, numbers, titles, doubt


def merge_retry(
    first: Any,
    retried: Any,
    answer: str,
    asked: Iterable[int] = (),
    asked_about: Iterable[str] = (),
) -> RetryMerge:
    """``retried`` merged into ``first`` by claim block number (:class:`RetryMerge`).

    ``answer`` is the retry as written, its ``WITHDRAW`` lines included.
    ``asked`` are the claim blocks of ``first`` (by index, as a flag's path
    names them) the question was about; ``asked_about`` the technique ids it
    asked about, which a claim the retry left as it was does not count as
    values the retry dropped. Linear in the size of both answers.
    """
    why = numbering_unsettled(first)
    if why:
        return RetryMerge(why=why)
    first_blocks, _ = _first_blocks(first)
    first_findings = list(getattr(first, "findings", None) or [])
    read = read_withdrawals(answer)
    withdrawn, withdrawn_numbers, withdrawn_titles, doubt = _withdrawn_items(
        first_blocks, first_findings, read
    )

    def _not_merged(reason: str) -> RetryMerge:
        return RetryMerge(why=reason, withdrawn=tuple(withdrawn))

    if read.unread:
        return _not_merged("a WITHDRAW line of the retry could not be read exactly")
    if doubt:
        return _not_merged(doubt)
    unread = _parse_left_unread(retried)
    if unread:
        return _not_merged(f"in the retry, {unread}")
    retry_blocks, why = _retry_blocks(list(getattr(retried, "claims", None) or []))
    if why:
        return _not_merged(why)
    retry_findings = list(getattr(retried, "findings", None) or [])
    if not retry_blocks and not read and not retry_findings:
        return _not_merged("the retry wrote no claim block, finding or withdrawal")

    by_number = {block.number: block for block in first_blocks}
    written_again = {block.number: block for block in retry_blocks}
    asked_numbers = {str(int(index) + 1) for index in asked if 0 <= int(index) < len(first_blocks)}
    for number in withdrawn_numbers:
        if number in written_again:
            return _not_merged(f"the retry both wrote claim {number} again and withdrew it")
    numbered_sentence: dict[str, dict[str, None]] = {}
    for block in first_blocks:
        numbered_sentence.setdefault(_sentence(block), {})[block.number] = None
    for block in retry_blocks:
        moved = numbered_sentence.get(_sentence(block)) or {}
        if moved and block.number not in moved:
            return _not_merged(
                f"the retry wrote claim {next(iter(moved))}'s sentence as claim "
                f"{block.number}, so its numbers do not name the claims of the answer being fixed"
            )
    unasked_written = [
        block
        for block in retry_blocks
        if block.number in by_number and block.number not in asked_numbers
    ]
    for block in unasked_written:
        earlier = by_number[block.number]
        if _sentence(earlier) == _sentence(block):
            continue
        before, after = _sentence_values(earlier), _sentence_values(block)
        if not before or not after or not before & after:
            return _not_merged(
                f"the retry wrote again claim {block.number}, which no question was about, "
                "with no value in common with it, so its number may not name that claim"
            )
    left = [
        number
        for number in sorted(asked_numbers, key=_digits_key)
        if number not in written_again and number not in withdrawn_numbers
    ]
    if left and any(_sentence(by_number[b.number]) != _sentence(b) for b in unasked_written):
        return _not_merged(
            f"the retry wrote again a claim no question was about and left claim {left[0]}, "
            "which a question was about, neither written again nor withdrawn"
        )

    retry_titles: dict[str, Any] = {}
    for finding in retry_findings:
        title = folded_title(getattr(finding, "title", ""))
        if title in retry_titles:
            return _not_merged("the retry wrote one finding title twice")
        if title in withdrawn_titles:
            return _not_merged("the retry both wrote a finding again and withdrew it")
        retry_titles[title] = finding

    claims: list[Any] = []
    replaced: list[str] = []
    unchanged = 0
    for block in first_blocks:
        if block.number in withdrawn_numbers:
            continue
        again = written_again.get(block.number)
        if again is not None:
            claims.extend(again.claims)
            replaced.append(block.number)
        else:
            claims.extend(block.claims)
            unchanged += 1
    added = [block.number for block in retry_blocks if block.number not in by_number]
    for block in retry_blocks:
        if block.number not in by_number:
            claims.extend(block.claims)

    findings: list[Any] = []
    findings_replaced = 0
    unwritten: list[Any] = []
    for finding in first_findings:
        title = folded_title(getattr(finding, "title", ""))
        if title in withdrawn_titles:
            continue
        again = retry_titles.pop(title, None)
        if again is not None:
            findings.append(again)
            findings_replaced += 1
        else:
            findings.append(finding)
            unwritten.append(finding)
    # What is left of the retry's findings has titles the answer had not.
    new_findings = list(retry_titles.values())
    findings.extend(new_findings)

    artifacts = list(getattr(first, "artifacts", None) or [])
    artifacts.extend(a for a in getattr(retried, "artifacts", None) or [] if a not in artifacts)

    unplaced: list[tuple[str, Any, tuple[str, ...]]] = [
        ("claim", claim, missing)
        for claim, missing in _unplaced(retried, answer, [by_number[n] for n in left], asked_about)
    ]
    # A finding left unwritten beside a new title may be the one renamed.
    if new_findings:
        unplaced += [("finding", finding, ()) for finding in unwritten]

    merged = first.model_copy(
        update={"claims": claims, "findings": findings, "artifacts": artifacts}
    )
    # Claim headings the answer wrote under its DISPUTES section that the
    # retry writes as claims of its own come in under new numbers: then where
    # its headings stand is as the retry wrote them.
    if added and hasattr(merged, "note_claims_under_disputes"):
        merged.note_claims_under_disputes(int(getattr(retried, "claims_under_disputes", 0) or 0))
    return RetryMerge(
        merged=merged,
        replaced=tuple(replaced),
        added=tuple(added),
        unchanged=unchanged,
        findings_replaced=findings_replaced,
        findings_added=len(new_findings),
        withdrawn=tuple(withdrawn),
        unplaced=tuple(unplaced),
    )


def _unplaced(
    retried: Any,
    answer: str,
    blocks: Sequence[_Block],
    asked_about: Iterable[str],
) -> list[tuple[Any, tuple[str, ...]]]:
    """Each claim of ``blocks`` with the values the retry states nowhere, asked ids aside."""
    if not blocks:
        return []
    asked = {str(value).strip().upper() for value in asked_about if str(value).strip()}
    wanted = [claim for block in blocks for claim in block.claims]
    missing = {
        id(claim): values
        for claim, values in dropped_claims(SimpleNamespace(claims=wanted), retried, answer)
    }
    return [
        (claim, tuple(v for v in missing.get(id(claim), ()) if v.upper() not in asked))
        for claim in wanted
    ]
