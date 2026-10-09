"""A validation retry merged into the answer it fixes, claim by claim, by the claim's number.

The validation turn asks an analyst to fix the claims a check flagged. Its
retry used to be taken as the analyst's whole answer, so every claim it did
not write again was lost and then had to be asked back. Here the retry changes
only what it writes:

- a claim it writes again under the number of a claim of the answer it fixes
  replaces that claim, every claim its block reads (one per technique id) at
  once;
- a claim it takes out with a ``WITHDRAW CLAIM <n>`` line is withdrawn;
- a claim under a number the answer it fixes did not use is added;
- every other claim stays as the answer it fixes wrote it, flagged or not.

Findings are merged the same way by their title: a finding the retry writes
again under the same title replaces it, a ``WITHDRAW FINDING: <title>`` line
takes one out, a finding with a new title is added and the rest stay.

The identity is the claim's number. It is what the code already tracks of a
claim across the two answers: the reader records the block every claim was
read from (``ClaimEvidence.block``) and the number its heading wrote
(``ClaimEvidence.number``); the platform's own questions name a claim as
"claim N", N its block's place in the answer (``function_claims``); and a
flag names the claim it is about by its place in the answer's claims
(``Violation.path``), which is a block, so a number. The sentence is not the
identity, because a fix rewrites it, nor the technique id, because a fix may
change that. The answer being fixed has a number for every block when the
numbers it wrote, if any, are each block's place in it, counted from 1; the
retry is told those are the numbers (``ANALYST_FEEDBACK_CLOSING_BY_NUMBER``)
and must write one on every block.

Nothing here edits a claim's words: the merge only chooses which version of
each claim stands. Where the numbers do not decide which claim is which, it
does not guess: :func:`merge_retry` says why and merges nothing, and the
caller takes the retry as it always did. One case the numbers cannot show by
themselves is a retry that numbered its claims afresh. Two facts show it, and
either one merges nothing: a sentence written as written under another
number of the answer it fixes, and a claim written again under a number
whose earlier claim states values (``claim_drops.claim_values``) and shares
none of them.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from maljan.agents.claim_headings import LINE_PREFIX
from maljan.pipeline.claim_drops import claim_values, dropped_claims

# ``WITHDRAW CLAIM 7``, ``WITHDRAW CLAIMS 3, 5 and 9``, marks and a list
# marker allowed before it, its reason after. Upper case, as a claim heading
# is: prose that says it withdraws something is the analyst's prose.
_WITHDRAW_CLAIM_RE = re.compile(
    r"^" + LINE_PREFIX + r"WITHDRAW[ \t*_`]++CLAIMS?+[ \t*_`]*+#?"
    r"(?P<numbers>\d++(?:[ \t*_`]*+(?:,|&|\band\b)[ \t*_`]*+#?\d++)*+)"
)
# ``WITHDRAW FINDING: <title>``: the rest of the line is the title.
_WITHDRAW_FINDING_RE = re.compile(
    r"^" + LINE_PREFIX + r"WITHDRAW[ \t*_`]++FINDING[ \t*_`]*+:(?P<title>.*)$"
)
_DIGITS_RE = re.compile(r"\d++")
# Where a flag names the claim it is about: ``static.claims[5].T1041``.
_CLAIM_PATH_RE = re.compile(r"claims\[(\d++)\]")


def flagged_claim_indexes(violations: Iterable[Any]) -> list[int]:
    """The claim indexes the flags in ``violations`` name by their paths, each once, in order."""
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


@dataclass(frozen=True)
class Withdrawals:
    """The claim numbers and finding titles (folded) a retry's ``WITHDRAW`` lines name."""

    claims: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()


def read_withdrawals(text: str) -> Withdrawals:
    """The ``WITHDRAW CLAIM <n>`` and ``WITHDRAW FINDING: <title>`` lines of ``text``, in order.

    Each line is read once, from its start; a title folded to nothing names
    no finding.
    """
    claims: dict[str, None] = {}
    findings: dict[str, None] = {}
    for line in str(text or "").splitlines():
        found = _WITHDRAW_CLAIM_RE.match(line)
        if found is not None:
            for digits in _DIGITS_RE.findall(found.group("numbers")):
                claims.setdefault(_number(digits))
            continue
        titled = _WITHDRAW_FINDING_RE.match(line)
        if titled is not None:
            title = folded_title(titled.group("title"))
            if title:
                findings.setdefault(title)
    return Withdrawals(claims=tuple(claims), findings=tuple(findings))


@dataclass
class _Block:
    number: str
    claims: list[Any] = field(default_factory=list)


def _blocks(claims: Sequence[Any], *, first: bool) -> tuple[list[_Block], str]:
    """The claim blocks of an answer, each with its number, or why the numbers do not decide.

    Claims read from one block are adjacent and carry that block's ordinal.
    In the answer being fixed a block's number is its place, counted from 1;
    a number its heading wrote must be that place. In a retry every block
    must write its number.
    """
    blocks: list[_Block] = []
    last: int | None = None
    for claim in claims:
        ordinal = getattr(claim, "block", None)
        if ordinal is None:
            return [], "a claim was not read from a claim block"
        written = getattr(claim, "number", None)
        if blocks and ordinal == last:
            head = blocks[-1].claims[0]
            if written != getattr(head, "number", None):
                return [], "one claim block was read with two numbers"
            if getattr(claim, "claim", None) != getattr(head, "claim", None):
                # Answers read apart and put together (a chunked answer's)
                # number their blocks each from the start.
                return [], "two claim blocks were read under one place"
            blocks[-1].claims.append(claim)
            continue
        last = ordinal
        if first:
            place = str(int(ordinal) + 1)
            if written is not None and written != place:
                return [], (
                    f"the answer being fixed numbered a claim {written} where it is claim {place}"
                )
            number = place
        else:
            if written is None:
                return [], "the retry wrote a claim block without its number"
            number = written
        blocks.append(_Block(number=number, claims=[claim]))
    seen: set[str] = set()
    for block in blocks:
        if block.number in seen:
            whose = "the answer being fixed" if first else "the retry"
            return [], f"{whose} wrote claim {block.number} twice"
        seen.add(block.number)
    return blocks, ""


def _parse_left_unread(isr: Any) -> str:
    """Why the parse of ``isr`` left a claim block it began unread, or ``""``."""
    if int(getattr(isr, "blocks_without_confidence", 0) or 0):
        return "a claim block stated no confidence"
    if list(getattr(isr, "confidence_unreadable", None) or []):
        return "a claim block's confidence could not be read"
    if str(getattr(isr, "claims_unread_reason", "") or ""):
        return "a claim block it began was not read"
    return ""


def numbering_unsettled(first: Any) -> str:
    """Why a retry of ``first`` cannot be merged by claim number, or ``""`` when it can.

    ``first`` has claims, every claim block it began was read, and each
    block's number is its place in it. Decided before the retry is asked, so
    the question says how claims are named only when they can be.
    """
    if not list(getattr(first, "claims", None) or []):
        return "the answer being fixed has no claim"
    unread = _parse_left_unread(first)
    if unread:
        return f"in the answer being fixed, {unread}"
    return _blocks(first.claims, first=True)[1]


def _sentence(block: _Block) -> str:
    """A block's sentence as two are compared: spacing aside."""
    return " ".join(str(getattr(block.claims[0], "claim", "") or "").split())


def _sentence_values(block: _Block) -> frozenset[str]:
    """The values a block's sentence states; its technique ids aside, which a fix may change."""
    return claim_values(str(getattr(block.claims[0], "claim", "") or ""), "")


@dataclass(frozen=True)
class RetryMerge:
    """What merging a retry into the answer it fixes made, or why it merged nothing.

    ``merged`` is the answer that stands, ``None`` when the numbers did not
    decide which claim is which (``why``). ``unplaced`` pairs each claim the
    retry was asked to fix and neither wrote again nor withdrew with the
    values of it the retry states nowhere: it stays in ``merged`` as written,
    and is the one thing left to ask about. ``replaced``, ``withdrawn`` and
    ``added`` are claim numbers; the finding counts are by title.
    """

    merged: Any | None = None
    why: str = ""
    replaced: tuple[str, ...] = ()
    withdrawn: tuple[str, ...] = ()
    added: tuple[str, ...] = ()
    unchanged: int = 0
    findings_replaced: int = 0
    findings_withdrawn: int = 0
    findings_added: int = 0
    unplaced: tuple[tuple[Any, tuple[str, ...]], ...] = ()

    def record(self) -> dict[str, Any]:
        """The merge on the loop's record: what it did, or why it did nothing."""
        if self.merged is None:
            return {"merged": False, "why": self.why}
        return {
            "merged": True,
            "replaced": list(self.replaced),
            "withdrawn": list(self.withdrawn),
            "added": list(self.added),
            "unchanged_blocks": self.unchanged,
            "findings_replaced": self.findings_replaced,
            "findings_withdrawn": self.findings_withdrawn,
            "findings_added": self.findings_added,
            "unplaced": len(self.unplaced),
        }


def _not_merged(why: str) -> RetryMerge:
    return RetryMerge(merged=None, why=why)


def merge_retry(
    first: Any,
    retried: Any,
    answer: str,
    flagged: Iterable[int] = (),
    asked_about: Iterable[str] = (),
) -> RetryMerge:
    """``retried`` merged into ``first`` by claim number (:class:`RetryMerge`).

    ``answer`` is the retry as written, its ``WITHDRAW`` lines included.
    ``flagged`` are the indexes in ``first.claims`` of the claims the
    question was about (``Violation.path``); ``asked_about`` the technique
    ids it asked about, which a claim the retry left as it was does not count
    as values the retry dropped. Linear in the size of both answers.
    """
    why = numbering_unsettled(first)
    if why:
        return _not_merged(why)
    unread = _parse_left_unread(retried)
    if unread:
        return _not_merged(f"in the retry, {unread}")
    first_blocks, _ = _blocks(first.claims, first=True)
    retry_blocks, why = _blocks(list(getattr(retried, "claims", None) or []), first=False)
    if why:
        return _not_merged(why)
    withdrawals = read_withdrawals(answer)
    retry_findings = list(getattr(retried, "findings", None) or [])
    if not retry_blocks and not withdrawals.claims and not withdrawals.findings:
        if not retry_findings:
            return _not_merged("the retry wrote no claim block, finding or withdrawal")

    by_number = {block.number: block for block in first_blocks}
    written_again = {block.number: block for block in retry_blocks}
    for number in withdrawals.claims:
        if number not in by_number:
            return _not_merged(f"the retry withdrew claim {number}, which the answer has not")
        if number in written_again:
            return _not_merged(f"the retry both wrote claim {number} again and withdrew it")
    # A sentence the retry writes as written under another number of the
    # answer it fixes shows the retry numbered its claims afresh.
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
        earlier = by_number.get(block.number)
        if earlier is None:
            continue
        before, after = _sentence_values(earlier), _sentence_values(block)
        if before and after and not before & after:
            return _not_merged(
                f"the retry's claim {block.number} states none of the values the claim it "
                "replaces stated, so its numbers may not name the same claims"
            )

    first_findings = list(getattr(first, "findings", None) or [])
    first_titles = {folded_title(getattr(f, "title", "")) for f in first_findings}
    for title in withdrawals.findings:
        if title not in first_titles:
            return _not_merged("the retry withdrew a finding the answer has not")
    retry_titles: dict[str, Any] = {}
    for finding in retry_findings:
        title = folded_title(getattr(finding, "title", ""))
        if title in retry_titles:
            return _not_merged("the retry wrote one finding title twice")
        retry_titles[title] = finding
    for title in withdrawals.findings:
        if title in retry_titles:
            return _not_merged("the retry both wrote a finding again and withdrew it")

    withdrawn = set(withdrawals.claims)
    claims: list[Any] = []
    replaced: list[str] = []
    unchanged = 0
    for block in first_blocks:
        if block.number in withdrawn:
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
    withdrawn_titles = set(withdrawals.findings)
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
    # What is left of the retry's findings has titles the answer had not, or
    # had twice and the retry wrote once: each is added.
    new_findings = list(retry_titles.values())
    findings.extend(new_findings)

    artifacts = list(getattr(first, "artifacts", None) or [])
    artifacts.extend(a for a in getattr(retried, "artifacts", None) or [] if a not in artifacts)

    # The claims the question was about that the retry neither wrote again
    # nor withdrew: they stay as written, and are the ones left to ask about.
    flagged_numbers: dict[str, None] = {}
    claim_number = {id(claim): block.number for block in first_blocks for claim in block.claims}
    for index in flagged:
        if 0 <= int(index) < len(first.claims):
            named = claim_number.get(id(first.claims[int(index)]))
            if named is not None:
                flagged_numbers.setdefault(named)
    left = [
        number
        for number in flagged_numbers
        if number not in written_again and number not in withdrawn
    ]
    unplaced = _unplaced(retried, answer, [by_number[n] for n in left], asked_about)

    merged = retried.model_copy(
        update={
            "claims": claims,
            "findings": findings,
            "artifacts": artifacts,
            "status": getattr(first, "status", None),
            "status_reason": getattr(first, "status_reason", None),
        }
    )
    # The parse facts are the retry's, which left nothing unread; an answer
    # of withdrawals alone read as prose is not prose the merged answer has.
    merged.note_parse()
    return RetryMerge(
        merged=merged,
        replaced=tuple(replaced),
        withdrawn=withdrawals.claims,
        added=tuple(added),
        unchanged=unchanged,
        findings_replaced=findings_replaced,
        findings_withdrawn=len(withdrawn_titles),
        findings_added=len(new_findings),
        unplaced=unplaced,
    )


def _unplaced(
    retried: Any,
    answer: str,
    blocks: Sequence[_Block],
    asked_about: Iterable[str],
) -> tuple[tuple[Any, tuple[str, ...]], ...]:
    """Each claim of ``blocks`` with the values the retry states nowhere, asked ids aside."""
    if not blocks:
        return ()
    asked = {str(value).strip().upper() for value in asked_about if str(value).strip()}
    wanted = [claim for block in blocks for claim in block.claims]
    missing = {
        id(claim): values
        for claim, values in dropped_claims(SimpleNamespace(claims=wanted), retried, answer)
    }
    return tuple(
        (
            claim,
            tuple(v for v in missing.get(id(claim), ()) if v.upper() not in asked),
        )
        for claim in wanted
    )
