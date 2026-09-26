"""Which analyst claims in force the report's body neither cites nor discusses.

The report models write the body from bundles that carry the analysts' claims,
and a claim they leave out is otherwise gone without a trace: a run's report
dropped a check three analysts had stated, in force and read, for the fourth
run in a row. After the body is composed this check reads it once, claim by
claim, and the report prints every claim it finds neither cited nor discussed
in a section of its own. Nothing is decided about the claim; it is listed, with
what the check found.

The rule, stated in the report beside the list:

* **Cited.** The body names the claim by its label (``claim_label``: the
  analyst and the claim's number in its answer in force), the label every
  report model's input shows the claim under.
* **Discussed.** The body carries more than half of the identifiers the claim
  names: its addresses and function names (compared by their hexadecimal
  digits, so ``FUN_1400068e8`` and ``0x68e8`` are the same place when one's
  digits end the other's, from four digits on), the values it quotes in
  backticks or double quotes, its API-style names (a word with two or more
  capitals, six characters or more), and its numbers of three digits or more.
  A claim that names no identifier at all is read by its words of five letters
  or more, with the same majority.

A claim that is neither is listed with the count the check found ("the body
carries 8 of the 20 identifiers it names"). The check is arithmetic over the
two texts: a claim the body restates in other words is listed, and one whose
identifiers the body carries for another reason is not; the count says which
reading a reader is looking at.

What counts as the body is what the report models wrote: the summary, the key
findings, the capability narrative, the recommendations, the background, the
technical analysis and the C2 channels. The ATT&CK table quotes each claim's
own words and is not a discussion of it.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from maljan.reporting.models import ClaimNotDiscussed, MalwareReport

# The report fields the report models write, in the order a reader meets them.
BODY_FIELDS = (
    "executive_summary",
    "key_findings",
    "capabilities_narrative",
    "defensive_recommendations",
    "intro_background",
    "technical_analysis",
    "c2_channels",
)

# The sentence the report prints above the list: the rule, as applied.
COVERAGE_RULE = (
    "A claim in force is listed here when the body neither names it by its label nor "
    "carries more than half of the identifiers it names (addresses and function names, "
    "quoted values, API-style names, numbers of three digits or more; for a claim that "
    "names none, its words of five letters or more). Each row says how many the body "
    "carries."
)

# Addresses and function names, by their hexadecimal digits.
_ADDRESS_RE = re.compile(
    r"(?<![0-9A-Za-z_])(?:0x|FUN_(?:0x)?|fcn\.(?:0x)?|sub_|LAB_|DAT_)([0-9a-fA-F]{3,16})\b"
)
_BACKTICKED_RE = re.compile(r"`([^`\n]{3,})`")
_QUOTED_RE = re.compile(r"\"([^\"\n]{3,})\"")
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{5,}\b")
_NUMBER_RE = re.compile(r"(?<![0-9A-Za-z_.])(\d{3,})(?![0-9A-Za-z_])")
_WORD_RE = re.compile(r"\b[A-Za-z]{5,}\b")
# Digits two addresses must share, at the least, to be read as one place.
_SHORTEST_SHARED_DIGITS = 4


def claim_label(agent: str, number: int) -> str:
    """How a claim in force is named wherever a report model or a reader meets it."""
    return f"{agent} claim {int(number)}"


@dataclass(frozen=True)
class ClaimInForce:
    """One claim of an answer in force, with its label."""

    agent: str
    number: int
    claim: str
    evidence_ref: str
    confidence: float | None

    @property
    def label(self) -> str:
        return claim_label(self.agent, self.number)


def claims_in_force(isr_reports: Mapping[str, Any] | None) -> list[ClaimInForce]:
    """Every claim of every answer in force, numbered in its answer, in the answers' order."""
    out: list[ClaimInForce] = []
    for name, isr in (isr_reports or {}).items():
        agent = str(getattr(isr, "agent_id", "") or name)
        for number, claim in enumerate(getattr(isr, "claims", None) or [], start=1):
            confidence = getattr(claim, "confidence", None)
            out.append(
                ClaimInForce(
                    agent=agent,
                    number=number,
                    claim=str(getattr(claim, "claim", "") or ""),
                    evidence_ref=str(getattr(claim, "evidence_ref", "") or ""),
                    confidence=float(confidence) if isinstance(confidence, int | float) else None,
                )
            )
    return out


def _strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _strings(item)
    elif isinstance(value, list | tuple):
        for item in value:
            yield from _strings(item)
    elif hasattr(value, "model_dump"):
        yield from _strings(value.model_dump(mode="json"))


def body_text(report: MalwareReport) -> str:
    """What the report models wrote, as one text."""
    return "\n".join(text for name in BODY_FIELDS for text in _strings(getattr(report, name, None)))


def _addresses(text: str) -> set[str]:
    return {m.group(1).lower().lstrip("0") or "0" for m in _ADDRESS_RE.finditer(text)}


def _markers(text: str) -> set[tuple[str, str]]:
    """The identifiers a claim names, each as ``(kind, value)``."""
    found: set[tuple[str, str]] = {("address", digits) for digits in _addresses(text)}
    for pattern in (_BACKTICKED_RE, _QUOTED_RE):
        found.update(("text", m.group(1).strip().lower()) for m in pattern.finditer(text))
    for m in _IDENTIFIER_RE.finditer(text):
        word = m.group(0)
        if sum(ch.isupper() for ch in word) >= 2 and not _ADDRESS_RE.fullmatch(word):
            found.add(("text", word.lower()))
    found.update(("number", m.group(1)) for m in _NUMBER_RE.finditer(text))
    return {(kind, value) for kind, value in found if value}


@dataclass(frozen=True)
class _Body:
    lowered: str
    addresses: frozenset[str]
    numbers: frozenset[str]

    @classmethod
    def of(cls, text: str) -> _Body:
        return cls(
            lowered=text.lower(),
            addresses=frozenset(_addresses(text)),
            numbers=frozenset(m.group(1) for m in _NUMBER_RE.finditer(text)),
        )

    def carries(self, marker: tuple[str, str]) -> bool:
        kind, value = marker
        if kind == "address":
            if value in self.addresses:
                return True
            if len(value) < _SHORTEST_SHARED_DIGITS:
                return False
            return any(
                len(held) >= _SHORTEST_SHARED_DIGITS
                and (held.endswith(value) or value.endswith(held))
                for held in self.addresses
            )
        if kind == "number":
            return value in self.numbers
        return value in self.lowered


def coverage_of(claim: ClaimInForce, body: _Body) -> tuple[bool, int, int, str]:
    """``(covered, carried, named, what)`` for one claim against the body.

    ``what`` names what was counted: ``identifiers``, or ``words`` for a claim
    that names no identifier.
    """
    if claim.label.lower() in body.lowered:
        return True, 0, 0, "label"
    markers = _markers(claim.claim)
    what = "identifiers"
    if not markers:
        markers = {("text", word.lower()) for word in _WORD_RE.findall(claim.claim)}
        what = "words"
    if not markers:
        return False, 0, 0, what
    carried = sum(1 for marker in markers if body.carries(marker))
    return carried * 2 > len(markers), carried, len(markers), what


def claims_not_discussed(
    report: MalwareReport, isr_reports: Mapping[str, Any] | None
) -> list[ClaimNotDiscussed]:
    """The claims in force the report's body neither cites nor discusses, in the answers' order."""
    body = _Body.of(body_text(report))
    out: list[ClaimNotDiscussed] = []
    for claim in claims_in_force(isr_reports):
        covered, carried, named, what = coverage_of(claim, body)
        if covered:
            continue
        out.append(
            ClaimNotDiscussed(
                agent=claim.agent,
                claim_number=claim.number,
                claim=claim.claim,
                evidence_ref=claim.evidence_ref,
                confidence=claim.confidence,
                carried=carried,
                named=named,
                counted=what,
            )
        )
    return out


def carried_sentence(row: ClaimNotDiscussed) -> str:
    """What the check found for one listed claim, in words."""
    if not row.named:
        return "it names nothing the check can look for"
    return f"the body carries {row.carried} of the {row.named} {row.counted} it names"
