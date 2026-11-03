"""The failed calls a later call redid, read off the ledger.

A call that failed and was then asked the same question again, and answered,
left no gap in the evidence. The report said every failed call as a gap:
haiku8 said "5 of 214 tool calls failed" while three of them had been redone
(T-494 D6), and the limitations paragraph then said the reversing tools
failed.

A failed call is redone only when, for every address it was asked for, a
later call answered the same question (the addresses are read as the
agreement question reads them, ``agreement_facts``, T-396):

* a later call of the same tool, for that address, whose every other argument
  is the failed call's, except one absent or null on either side and one whose
  failed value the failure's own message names (the value it refused);
* for a failed call that lists code, a later call of another tool that lists
  that function whole: a decompiled listing holding it, or a disassembly of the
  whole function. A read of some instructions from the address is no redo.

The answering call must hold its answer whole (``holds_its_answer``, and
nothing cut by the byte budget or the tool-output guardrail), and an answer
that is error text answers nothing, a listing or not. A call asked for no address (a scan, a
lookup, an emulation by candidate names) has nothing to be matched by, and
stays a failure. The rows are the platform's own ids and the tool's name,
cleaned to one capped line; the failure itself is still counted and listed
where the run's counts are (``run_summary.evidence.failed`` and ``failures``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Any

__all__ = ["ENTRY_ID", "redone_failures"]

# The characters of a tool's name a row keeps: a server's word, one line.
_TOOL_CHARS = 80
# An entry id as a redone row may name it where it is shown readable: the
# platform's own shape, one token.
ENTRY_ID = re.compile(r"[\w.-]{1,64}")
# A failed value shorter than this is never read as named by the failure's
# message: a digit or a short word is found in any message.
_NAMED_VALUE_CHARS = 3


def _tool(entry: Any) -> str:
    return " ".join(str(getattr(entry, "tool", "") or "").split())[:_TOOL_CHARS]


def _empty(value: Any) -> bool:
    return value is None or value == "" or value == [] or value == {}


def _same_question(failed: Any, answering: Any) -> bool:
    """Whether a later call of the failed call's tool asked what it asked, but for its addresses."""
    from maljan.core.undeclared_tools import entry_address_arguments
    from maljan.pipeline.validation import _ADDRESS_LIST_ARGUMENTS

    skip = {*entry_address_arguments(failed), *entry_address_arguments(answering)}
    skip.update(_ADDRESS_LIST_ARGUMENTS)
    asked = getattr(failed, "args", None) or {}
    again = getattr(answering, "args", None) or {}
    message = str(getattr(failed, "error", "") or getattr(failed, "output", "") or "")
    for name in {*asked, *again} - skip:
        before, after = asked.get(name), again.get(name)
        if _empty(before) or _empty(after) or before == after or str(before) == str(after):
            continue
        refused = str(before)
        if len(refused) >= _NAMED_VALUE_CHARS and refused in message:
            continue
        return False
    return True


def _whole_listings(answering: Any, bases: Sequence[int]) -> set[int]:
    """The functions a call of another tool listed whole: decompiled, or disassembled whole."""
    from maljan.agents.function_map import one_spelling
    from maljan.core.undeclared_tools import entry_decompiles, entry_lists_a_function
    from maljan.pipeline.validation import _entry_functions
    from maljan.reporting.agreement_facts import asked_addresses

    if entry_decompiles(answering):
        held = [address for address, _names in _entry_functions(answering) if address is not None]
    elif entry_lists_a_function(answering):
        held = asked_addresses(answering)
    else:
        return set()
    return {one_spelling(address, bases) for address in held}


def _answers(answering: Any) -> bool:
    """Whether a later entry is an answer: a call that ran, worked and holds its answer whole.

    An answer the byte budget or the tool-output guardrail cut holds part of
    what was asked, and one whose text is an error answered nothing, listing
    or not.
    """
    from maljan.agents.function_callees import listing_is_error
    from maljan.schemas.evidence import answer_not_shown, holds_its_answer

    if not getattr(answering, "ok", True) or getattr(answering, "repeated_of", None):
        return False
    if getattr(answering, "truncated", False) or int(getattr(answering, "chars_dropped", 0) or 0):
        return False
    if answer_not_shown(answering) or not holds_its_answer(answering):
        return False
    return not listing_is_error(answering)


def redone_failures(ledger: Iterable[Any]) -> list[dict[str, Any]]:
    """Each failed call a later call redid for every address it was asked, in ledger order.

    Only a call ``run_summary.evidence`` counts as failed (one that ran: not
    answered from an earlier entry). Each row is ``{"entry_id", "tool",
    "answered_by"}``, the first later answer for each address, in ledger
    order. Empty when nothing failed, without reading the ledger further.
    """
    entries = list(ledger)
    failed_at = [
        at
        for at, entry in enumerate(entries)
        if not getattr(entry, "ok", True) and not getattr(entry, "repeated_of", None)
    ]
    if not failed_at:
        return []
    from maljan.agents.function_map import build_function_map, one_spelling
    from maljan.core.undeclared_tools import entry_lists_any_code
    from maljan.reporting.agreement_facts import answered_addresses, asked_addresses

    bases = tuple(build_function_map(entries, None, ()).image_bases)
    answers = [at for at, entry in enumerate(entries) if _answers(entry)]
    out: list[dict[str, Any]] = []
    for at in failed_at:
        failed = entries[at]
        asked = {one_spelling(address, bases) for address in asked_addresses(failed)}
        if not asked:
            continue
        lists_code = entry_lists_any_code(failed)
        by: dict[int, int] = {}
        for later in answers:
            if later <= at:
                continue
            answering = entries[later]
            if getattr(answering, "tool", None) == getattr(failed, "tool", None):
                if not _same_question(failed, answering):
                    continue
                covered = {one_spelling(a, bases) for a in answered_addresses(answering)}
            elif lists_code:
                covered = _whole_listings(answering, bases)
            else:
                continue
            for address in (asked & covered) - by.keys():
                by[address] = later
            if by.keys() >= asked:
                break
        if by.keys() != asked:
            continue
        out.append(
            {
                "entry_id": str(getattr(failed, "id", "") or ""),
                "tool": _tool(failed),
                "answered_by": [
                    str(getattr(entries[i], "id", "") or "") for i in sorted(set(by.values()))
                ],
            }
        )
    return out
