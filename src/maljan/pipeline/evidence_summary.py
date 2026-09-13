"""What each technique id was claimed by, put in front of the judge.

Deliberately no arithmetic. Hand a judge one weighted number per technique and
it treats that number as the answer and its own reading of the evidence as
commentary — and nobody can say where the number came from, because it comes
from a table of constants rather than from the sample.

So the block carries the same information without the summing: the technique
id, every source that named it, and what each source said its own confidence
was. Two analysts and a capa rule agreeing is three lines; what that is worth
is the judge's decision, which is the judge's job.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Any

# How many techniques the block names. The judge's prompt is already a
# multi-kilobyte assembly and the tail of a confidence-ordered list is noise;
# the count of what was left out is printed instead.
MAX_TECHNIQUES = 25

# How many sources are listed per technique before the rest are counted.
MAX_SOURCES_PER_TECHNIQUE = 6

_TID_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def summarise(isrs: dict[str, Any] | None, ledger: Sequence[Any] | None = None) -> str:
    """The evidence summary block, or "" when nothing named a technique."""
    rows = collect(isrs, ledger)
    if not rows:
        return ""

    lines = [
        "EVIDENCE SUMMARY — which sources named each technique, and how sure each one was.",
        "These are the sources' own numbers. Nothing here is combined or weighted; the",
        "verdict's confidence is yours to set.",
    ]
    shown = sorted(rows.items(), key=lambda item: (-len(item[1]), item[0]))
    for tid, sources in shown[:MAX_TECHNIQUES]:
        head = sources[:MAX_SOURCES_PER_TECHNIQUE]
        rest = len(sources) - len(head)
        rendered = "; ".join(
            f"{name} ({confidence:.2f})" if confidence is not None else name
            for name, confidence in head
        )
        tail = f"; +{rest} more" if rest > 0 else ""
        lines.append(f"- {tid}: {len(sources)} source(s) — {rendered}{tail}")
    if len(shown) > MAX_TECHNIQUES:
        lines.append(f"- (+{len(shown) - MAX_TECHNIQUES} further techniques not listed)")
    return "\n".join(lines)


def collect(
    isrs: dict[str, Any] | None, ledger: Sequence[Any] | None = None
) -> dict[str, list[tuple[str, float | None]]]:
    """``{technique_id: [(source, its own confidence or None), ...]}``.

    A tool entry carries no confidence of its own — a capa rule either matched
    or it did not — so its second element is ``None`` rather than a number
    invented to fill the column.
    """
    rows: dict[str, list[tuple[str, float | None]]] = {}
    seen: dict[str, set[str]] = {}

    def add(tid: str, source: str, confidence: float | None) -> None:
        if not _TID_RE.match(tid):
            return
        if source in seen.setdefault(tid, set()):
            return
        seen[tid].add(source)
        rows.setdefault(tid, []).append((source, confidence))

    for name, isr in (isrs or {}).items():
        source = str(getattr(isr, "agent_id", "") or name)
        for claim in getattr(isr, "claims", None) or []:
            if not getattr(claim, "technique_id_valid", True):
                continue
            tid = str(getattr(claim, "technique_id", "") or "").strip().upper()
            if tid:
                add(tid, source, _as_confidence(getattr(claim, "confidence", None)))
        for finding in getattr(isr, "findings", None) or []:
            confidence = _as_confidence(getattr(finding, "confidence", None))
            for raw in getattr(finding, "technique_ids", None) or []:
                add(str(raw).strip().upper(), source, confidence)

    for entry in ledger or []:
        tool = str(getattr(entry, "tool", "") or "tool")
        for tid in _technique_ids(getattr(entry, "structured", None)):
            add(tid, tool, None)

    return rows


def _as_confidence(value: Any) -> float | None:
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _technique_ids(structured: Any, depth: int = 0) -> set[str]:
    """Every ATT&CK id a tool result names, wherever in its shape it sits."""
    if depth > 6:
        return set()
    found: set[str] = set()
    if isinstance(structured, dict):
        for key, value in structured.items():
            if key in ("technique_id", "attck", "technique_ids") and isinstance(value, str):
                if _TID_RE.match(value.strip().upper()):
                    found.add(value.strip().upper())
                continue
            found |= _technique_ids(value, depth + 1)
    elif isinstance(structured, list):
        for item in structured:
            if isinstance(item, str) and _TID_RE.match(item.strip().upper()):
                found.add(item.strip().upper())
            else:
                found |= _technique_ids(item, depth + 1)
    return found
