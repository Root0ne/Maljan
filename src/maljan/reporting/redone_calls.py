"""The failed calls a later call redid, read off the ledger.

A call that failed and was then asked again, and answered, for the same
address (the same tool, or for a call that lists code any later listing of
that function: ``agreement_facts.answered_later``, T-396) left no gap in the
evidence. The report said every failed call as a gap: haiku8 said "5 of 214
tool calls failed" while three of them had been redone (T-494 D6), and the
limitations paragraph then said the reversing tools failed.

A failed call is redone only when every address it was asked for was
answered later. A call asked for no address (a scan, a lookup, an emulation
by candidate names) has nothing to be matched by, and stays a failure: two
calls of one tool with other arguments are no answer to the same question.
The rows are the platform's own ids and the tool's name, cleaned to one
capped line; the failure itself is still counted and listed where the run's
counts are (``run_summary.evidence.failed`` and ``failures``).
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

__all__ = ["redone_failures"]

# The characters of a tool's name a row keeps: a server's word, one line.
_TOOL_CHARS = 80


def _tool(entry: Any) -> str:
    return " ".join(str(getattr(entry, "tool", "") or "").split())[:_TOOL_CHARS]


def redone_failures(ledger: Iterable[Any]) -> list[dict[str, Any]]:
    """Each failed call a later call answered for every address it was asked, in ledger order.

    Only a call ``run_summary.evidence`` counts as failed (one that ran: not
    answered from an earlier entry). Each row is ``{"entry_id", "tool",
    "answered_by"}``, the later entries in ledger order. Empty when nothing
    failed, without reading the ledger further.
    """
    entries = list(ledger)
    failed = [
        entry
        for entry in entries
        if not getattr(entry, "ok", True) and not getattr(entry, "repeated_of", None)
    ]
    if not failed:
        return []
    from maljan.agents.function_map import build_function_map, one_spelling
    from maljan.reporting.agreement_facts import _asked, answered_later

    bases = tuple(build_function_map(entries, None, ()).image_bases)
    links: dict[str, dict[int, str]] = {}
    for link in answered_later(entries, bases):
        links.setdefault(link.failed, {}).setdefault(link.address, link.answered)
    out: list[dict[str, Any]] = []
    for entry in failed:
        entry_id = str(getattr(entry, "id", "") or "")
        asked = {one_spelling(address, bases) for address in _asked(entry)}
        held = links.get(entry_id) or {}
        if not asked or not asked <= held.keys():
            continue
        out.append(
            {
                "entry_id": entry_id,
                "tool": _tool(entry),
                "answered_by": sorted({held[address] for address in asked}, key=_ledger_order),
            }
        )
    return out


def _ledger_order(entry_id: str) -> tuple[int, str]:
    """An entry id's place in the ledger: by its number (``ev_0171``), else after them."""
    _, _, number = entry_id.rpartition("_")
    return (int(number), entry_id) if number.isdigit() else (1 << 62, entry_id)
