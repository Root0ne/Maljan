"""Claims a revision dropped, and whether a revision changed anything at all.

A revision replaces the analyst's answer in force. What it no longer says was
gone without a trace, and a mapping a reverser had read in one round was in no
final answer. This module reads a claim's content as the values it states:

- an address or a constant written in hex (``0x…``), compared by value;
- an ATT&CK technique id, in the claim text or on its technique line;
- a quoted value, in backticks or double quotes.

These are the kinds of fact the report carries: a mapping, a command id, a
configuration value. A claim of the answer in force with at least one value is
**dropped** when a value it states is in no claim and no finding of the
revision. A dropped claim is withdrawn when the revision's answer has a
``WITHDRAWN:`` line naming one of its values and a reason after a dash; any
other is asked about once (``claims_dropped_violation``), and what the analyst
answers stands. A claim that states no value is not tracked: rewording it is
not a drop the platform can tell from a change of words.

``revision_changed`` is the debate's convergence test: a revision that wrote
the same claims (by their values and technique, or by their words where they
state no value), the same techniques and the same findings changed nothing.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import Violation

CLAIMS_DROPPED_CODE = "isr.claims_dropped"

# The label of the line a revision withdraws a claim on.
WITHDRAWN_LABEL = "WITHDRAWN:"

_HEX = re.compile(r"(?<![0-9A-Za-z_])0x([0-9a-fA-F]+)(?![0-9A-Za-z_])")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_QUOTED = re.compile(r"`([^`\n]{2,})`|\"([^\"\n]{2,})\"")
# A withdrawal line: the label, with any list marker or emphasis around it.
_WITHDRAWN_LINE = re.compile(
    r"^[\s>*_`#-]*(?:\d+[.)]\s*)?[*_`]*withdrawn[*_`]*\s*:[*_`]*\s*(.*)$", re.IGNORECASE
)
# What separates a withdrawal's claim from its reason.
_REASON_SEPARATOR = re.compile(r"\s+(?:—|–|--|-)\s+|\s+because\s+", re.IGNORECASE)


def _hex_values(text: str) -> set[str]:
    return {f"0x{int(m.group(1), 16):x}" for m in _HEX.finditer(text)}


def claim_values(text: str, technique_id: str | None = "") -> frozenset[str]:
    """The values a claim states: hex values by value, technique ids, quoted values casefolded."""
    values: set[str] = set(_hex_values(text))
    values.update(_TECHNIQUE.findall(text))
    if technique_id and _TECHNIQUE.fullmatch(str(technique_id).strip()):
        values.add(str(technique_id).strip())
    for match in _QUOTED.finditer(text):
        quoted = (match.group(1) or match.group(2) or "").strip().casefold()
        if len(quoted) >= 2:
            values.add(quoted)
    return frozenset(values)


def _values_of_claim(claim: Any) -> frozenset[str]:
    return claim_values(
        str(getattr(claim, "claim", "") or ""), getattr(claim, "technique_id", None) or ""
    )


def _carried_text(isr: Any) -> str:
    """Everything a revision states: its claims, their techniques and its findings."""
    parts: list[str] = []
    for claim in getattr(isr, "claims", None) or []:
        parts.append(str(getattr(claim, "claim", "") or ""))
        parts.append(str(getattr(claim, "technique_id", "") or ""))
    for finding in getattr(isr, "findings", None) or []:
        parts.append(str(getattr(finding, "title", "") or ""))
        parts.append(str(getattr(finding, "detail", "") or ""))
        parts.extend(str(t) for t in getattr(finding, "technique_ids", None) or [])
    return "\n".join(parts)


def _is_carried(value: str, hexes: set[str], techniques: set[str], folded: str) -> bool:
    if value.startswith("0x") and _HEX.fullmatch(value):
        return value in hexes
    if _TECHNIQUE.fullmatch(value):
        return value in techniques
    return value in folded


def _withdrawals(answer: str) -> list[tuple[frozenset[str], str]]:
    """``(values named, reason)`` of each ``WITHDRAWN:`` line of an answer."""
    found: list[tuple[frozenset[str], str]] = []
    for line in str(answer or "").splitlines():
        match = _WITHDRAWN_LINE.match(line)
        if match is None:
            continue
        rest = match.group(1).strip()
        parts = _REASON_SEPARATOR.split(rest, maxsplit=1)
        named, reason = (parts[0], parts[1].strip()) if len(parts) == 2 else (rest, "")
        if not re.search(r"[A-Za-z]", reason):
            reason = ""
        found.append((claim_values(named) | claim_values(rest), reason))
    return found


@dataclass(frozen=True)
class DroppedClaim:
    """One claim of the answer in force a revision no longer carries."""

    claim: str
    values: tuple[str, ...]
    missing: tuple[str, ...]
    # The reason the revision withdrew it with, or ``""`` when it did not.
    reason: str = ""


def dropped_claims(in_force: Any, revision: Any) -> list[DroppedClaim]:
    """The claims of ``in_force`` with a value ``revision`` no longer carries, in order."""
    if in_force is None or revision is None:
        return []
    carried = _carried_text(revision)
    hexes = _hex_values(carried)
    techniques = set(_TECHNIQUE.findall(carried))
    folded = carried.casefold()
    withdrawals = _withdrawals(
        str(getattr(revision, "answer_text", "") or "")
        + "\n"
        + "\n".join(str(item) for item in getattr(revision, "dissent_items", None) or [])
    )
    dropped: list[DroppedClaim] = []
    for claim in getattr(in_force, "claims", None) or []:
        values = _values_of_claim(claim)
        if not values:
            continue
        missing = sorted(v for v in values if not _is_carried(v, hexes, techniques, folded))
        if not missing:
            continue
        reason = next(
            (why for named, why in withdrawals if why and named & values),
            "",
        )
        dropped.append(
            DroppedClaim(
                claim=str(getattr(claim, "claim", "") or ""),
                values=tuple(sorted(values)),
                missing=tuple(missing),
                reason=reason,
            )
        )
    return dropped


def _dropped_words(dropped: DroppedClaim) -> str:
    """One dropped claim as the question quotes it: the claim and the values no longer stated."""
    return f'"{dropped.claim}" (no longer stated: {", ".join(dropped.missing)})'


def claims_dropped_violation(dropped: Sequence[DroppedClaim]) -> Violation | None:
    """The question for the dropped claims not withdrawn with a reason, or ``None``."""
    unexplained = [d for d in dropped if not d.reason]
    if not unexplained:
        return None
    return Violation(
        code=CLAIMS_DROPPED_CODE,
        message=(
            f"Your revision no longer carries {len(unexplained)} claim(s) of your answer in "
            "force, each stating a value this analysis reports: "
            f"{'; '.join(safe_finding_value(_dropped_words(d)) for d in unexplained)}. "
            "For each one, either keep it, written again as a claim block (revised where "
            "you have reason), or withdraw it on a line of your DISPUTES section reading "
            f"'{WITHDRAWN_LABEL} <the values it states> — <the reason>'. A claim neither "
            "kept nor withdrawn stays out of your answer."
        ),
    )


def defanged(text: str) -> str:
    """``text`` with the network values it names written defanged, for a sentence a reader sees."""
    from maljan.pipeline.validation import network_values_in
    from maljan.reporting.defang import defang_text

    return defang_text(text, [(value, kind) for kind, value in network_values_in(text)])


def dropped_claim_sentence(name: str, revision_round: int, dropped: DroppedClaim) -> str:
    """The run summary's sentence for one dropped claim, its network values defanged."""
    how = f"withdrawn: {dropped.reason}" if dropped.reason else "not withdrawn with a reason"
    return defanged(
        f"The {name} analyst's round-{int(revision_round)} revision dropped the claim "
        f'"{dropped.claim}" ({how}).'
    )


def without_withdrawals(items: Iterable[str]) -> list[str]:
    """Dispute items without the analyst's own ``WITHDRAWN:`` lines: those dispute no peer."""
    return [str(item) for item in items if _WITHDRAWN_LINE.match(str(item)) is None]


def _claim_key(claim: Any) -> tuple[str, frozenset[str] | str]:
    technique = str(getattr(claim, "technique_id", "") or "")
    values = _values_of_claim(claim)
    if values:
        return (technique, values)
    return (technique, " ".join(str(getattr(claim, "claim", "") or "").lower().split()))


def _finding_key(finding: Any) -> tuple[str, tuple[str, ...]]:
    return (
        " ".join(str(getattr(finding, "title", "") or "").lower().split()),
        tuple(sorted(str(t) for t in getattr(finding, "technique_ids", None) or [])),
    )


def revision_changed(in_force: Any, revision: Any) -> bool:
    """Whether ``revision`` changed a claim, a technique or a finding of ``in_force``."""
    if in_force is None:
        return bool(getattr(revision, "claims", None) or getattr(revision, "findings", None))
    before = Counter(_claim_key(c) for c in getattr(in_force, "claims", None) or [])
    after = Counter(_claim_key(c) for c in getattr(revision, "claims", None) or [])
    if before != after:
        return True
    found_before = Counter(_finding_key(f) for f in getattr(in_force, "findings", None) or [])
    found_after = Counter(_finding_key(f) for f in getattr(revision, "findings", None) or [])
    return found_before != found_after
