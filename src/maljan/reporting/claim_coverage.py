"""Which analyst claims in force the report's body does not name the code of.

The report models write the body from bundles that carry the analysts' claims,
and a claim they leave out, or a clause of one, is otherwise gone without a
trace. After the body is composed this check reads it once, claim by claim, and
the report prints every claim whose code the body does not name in a section of
its own, with the names it lacks. Nothing is decided about the claim; what the
check states is a fact about the two texts: the body never names these.

The rule, stated in the report beside the list:

* **Cited.** A claim the body names by its label (``claim_label``: the analyst
  and the claim's number in its answer in force), the label every report
  model's input shows the claim under, is not listed.
* **Code locations and API names.** Otherwise a claim is listed when the body
  does not name one or more of its code locations — ``FUN_``, ``fcn.``,
  ``sub_``, ``LAB_`` and ``DAT_`` names of four hex digits or more — or its
  API-style names (a word of six characters or more with lower case and two or
  more capitals: ``GetAdaptersInfo``), whatever share of them the body does
  name. Each row lists the names the body lacks, as the claim wrote them. A
  bare ``0x`` value in a claim is not one of them: it is as often a flag, a size
  or a machine type as a place. In the body every ``0x`` value and function
  name is read as a place, so a body that writes ``0x68e8`` names
  ``FUN_0x68e8``. Two places are one when their values are equal, or when the
  longer is the shorter plus an image base: a difference of 1 MiB or more
  that is a whole number of 64 KiB and leaves the longer with more digits
  (``FUN_1400068e8`` and ``0x68e8``). No other shared ending makes two one.
* **Words.** A claim that names no code location and no API-style name is
  listed when the body carries half or fewer of its words of five letters or
  more; its row says how many.

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
    "A claim in force is listed here when the body does not name it by its label and does "
    "not name one or more of its code locations (function names of four hex digits or "
    "more) or API-style names; each row lists the names the body lacks. A claim "
    "that names none of these is listed when the body carries half or fewer of its words of "
    "five letters or more."
)

# Code locations: a function or label name, or an address, by its hexadecimal digits.
_ADDRESS_RE = re.compile(
    r"(?<![0-9A-Za-z_])(?:0x|FUN_(?:0x)?|fcn\.(?:0x)?|sub_|LAB_|DAT_)([0-9a-fA-F]{4,16})\b"
)
_IDENTIFIER_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]{5,}\b")
_WORD_RE = re.compile(r"\b[A-Za-z]{5,}\b")
# An image base is a whole number of 64 KiB, and a linker's default one is far
# above an image's own offsets: 0x400000 for an x86 program, 0x10000000 for a
# DLL, 0x140000000 on x64. A difference of less than 1 MiB is read as two places.
_IMAGE_BASE_ALIGNMENT = 0x10000
_SMALLEST_IMAGE_BASE = 0x100000


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


def _address(digits: str) -> int:
    return int(digits, 16)


def code_names(text: str) -> dict[tuple[str, int | str], str]:
    """The code locations and API-style names ``text`` names: ``{key: as written}``.

    An address is keyed by its value, an API-style name by its lower case.
    """
    found: dict[tuple[str, int | str], str] = {}
    for m in _ADDRESS_RE.finditer(text):
        if not m.group(0).startswith("0x"):
            found.setdefault(("address", _address(m.group(1))), m.group(0))
    for m in _IDENTIFIER_RE.finditer(text):
        word = m.group(0)
        camel = any(ch.islower() for ch in word) and sum(ch.isupper() for ch in word) >= 2
        if camel and not _ADDRESS_RE.fullmatch(word):
            found.setdefault(("name", word.lower()), word)
    return found


def _same_place(one: int, other: int) -> bool:
    """Equal, or the longer is the shorter plus an image base (64 KiB aligned, 1 MiB or more)."""
    if one == other:
        return True
    longer, shorter = (one, other) if one > other else (other, one)
    return (
        (longer - shorter) % _IMAGE_BASE_ALIGNMENT == 0
        and len(f"{longer:x}") > len(f"{shorter:x}")
        and longer - shorter >= _SMALLEST_IMAGE_BASE
    )


@dataclass(frozen=True)
class _Body:
    lowered: str
    addresses: frozenset[int]

    @classmethod
    def of(cls, text: str) -> _Body:
        return cls(
            lowered=text.lower(),
            addresses=frozenset(_address(m.group(1)) for m in _ADDRESS_RE.finditer(text)),
        )

    def names(self, key: tuple[str, int | str]) -> bool:
        kind, value = key
        if kind == "address" and isinstance(value, int):
            return any(_same_place(value, held) for held in self.addresses)
        return str(value) in self.lowered


def coverage_of(claim: ClaimInForce, body: _Body) -> ClaimNotDiscussed | None:
    """The row for one claim the body does not name the code of, or ``None`` when it does."""
    if claim.label.lower() in body.lowered:
        return None
    names = code_names(claim.claim)
    if names:
        missing = [written for key, written in names.items() if not body.names(key)]
        if not missing:
            return None
        return _row(claim, missing=missing, named=len(names), counted="names")
    words = {word.lower() for word in _WORD_RE.findall(claim.claim)}
    carried = sum(1 for word in words if word in body.lowered)
    if words and carried * 2 > len(words):
        return None
    return _row(claim, carried=carried, named=len(words), counted="words")


def _row(
    claim: ClaimInForce,
    *,
    missing: list[str] | None = None,
    carried: int = 0,
    named: int = 0,
    counted: str,
) -> ClaimNotDiscussed:
    return ClaimNotDiscussed(
        agent=claim.agent,
        claim_number=claim.number,
        claim=claim.claim,
        evidence_ref=claim.evidence_ref,
        confidence=claim.confidence,
        missing=list(missing or []),
        carried=carried,
        named=named,
        counted=counted,
    )


def claims_not_discussed(
    report: MalwareReport, isr_reports: Mapping[str, Any] | None
) -> list[ClaimNotDiscussed]:
    """The claims in force whose code the report's body does not name, in the answers' order."""
    body = _Body.of(body_text(report))
    rows = [coverage_of(claim, body) for claim in claims_in_force(isr_reports)]
    return [row for row in rows if row is not None]


def carried_sentence(row: ClaimNotDiscussed) -> str:
    """What the check found for one listed claim, in words."""
    if row.missing:
        return "the body never names " + ", ".join(row.missing)
    if not row.named:
        return "it names nothing the check can look for"
    return f"the body carries {row.carried} of the {row.named} {row.counted} it names"
