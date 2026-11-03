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
  is the failed call's, except one the redo leaves absent or null and one whose
  failed value the failure's own message names (the value it refused). The
  redo is never narrower than the failed call (T-529): an argument the failed
  call left absent or null and the redo sets counts only where the failure's
  own message names that argument, as a word of its own (the call was refused
  for it: "timeout ... Input should be a valid integer"), and the redo's answer
  is not cut ("disassemble X" redone as "disassemble 3 instructions of X", a
  failure that named no instruction count, is no redo); a refused value
  replaced by a number counts only when the number is not smaller than the
  refused one (a read of 0x1000 bytes redone as a read of 4 is no redo);
* for a failed call that lists code, a later call of another tool, or of the
  same tool that changed no value the failed call set (but for the refused
  value, replaced by one not narrower), that lists that function whole: a
  decompiled listing holding it, or a disassembly of the whole function (the
  entry's declared kind says which). A read of some instructions from the
  address is no redo. Known limit: an argument the same tool's call only adds
  is not checked on this route; the listing is read as whole by its kind, so a
  bound only the redo sets (``max_lines=3``) is not seen.

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
from collections.abc import Iterable, Iterator, Sequence
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


def _number(value: Any) -> int | float | None:
    """``value`` as a number: an int or a float, or a decimal or ``0x`` hex text; else None."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    text = str(value).strip()
    try:
        return int(text, 0)
    except ValueError:
        pass
    try:
        return float(text)
    except ValueError:
        return None


def _narrower(before: Any, after: Any) -> bool:
    """Whether a refused value ``before`` is replaced by a smaller number ``after``."""
    refused, now = _number(before), _number(after)
    return refused is not None and now is not None and now < refused


def _names_argument(message: str, name: str) -> bool:
    """Whether a failure's message names the argument ``name`` as an argument.

    Written alone on a line (``timeout`` above its validation error), quoted
    (``'limit'``), or followed by ``=`` or ``:`` (``count=4096``): a word of
    ordinary prose (a name, a type, a path, a size) is not one.
    """
    if len(name) < _NAMED_VALUE_CHARS:
        return False
    word = re.escape(name)
    shaped = (
        rf"^[ \t]*{word}[ \t]*$"
        rf"|(['\"`]){word}\1"
        rf"|(?<![\w-]){word}[ \t]*[=:]"
    )
    return re.search(shaped, message, re.MULTILINE) is not None


def _cut(answering: Any) -> bool:
    """Whether an answer was cut: by the byte budget or the guardrail, or not held whole."""
    from maljan.schemas.evidence import answer_not_shown, holds_its_answer

    if getattr(answering, "truncated", False) or int(getattr(answering, "chars_dropped", 0) or 0):
        return True
    return answer_not_shown(answering) or not holds_its_answer(answering)


def _changed(failed: Any, answering: Any) -> Iterator[tuple[str, bool, bool]]:
    """Each argument, but for the addresses, a later call set to another value than the failed one.

    ``(name, added, fixed)``: ``added`` when the failed call left it absent or
    null; ``fixed`` when the failure's own message names it (an added one) or
    the value it refused (a set one, replaced by a value not narrower). An
    argument the redo leaves absent or null is no change.
    """
    from maljan.core.undeclared_tools import entry_address_arguments
    from maljan.pipeline.validation import _ADDRESS_LIST_ARGUMENTS

    skip = {*entry_address_arguments(failed), *entry_address_arguments(answering)}
    skip.update(_ADDRESS_LIST_ARGUMENTS)
    asked = getattr(failed, "args", None) or {}
    again = getattr(answering, "args", None) or {}
    message = str(getattr(failed, "error", "") or getattr(failed, "output", "") or "")
    for name in sorted({*asked, *again} - skip, key=str):
        before, after = asked.get(name), again.get(name)
        if _empty(after) or before == after or str(before) == str(after):
            continue
        if _empty(before):
            yield str(name), True, _names_argument(message, str(name))
            continue
        refused = str(before)
        named = len(refused) >= _NAMED_VALUE_CHARS and refused in message
        yield str(name), False, named and not _narrower(before, after)


def _same_question(failed: Any, answering: Any) -> bool:
    """Whether a later call of the failed call's tool asked what it asked, but for its addresses.

    Never a narrower question: an argument only the redo sets, unless the
    failure named it, and a refused value replaced by a smaller number, each
    make it another question. The answer is whole: ``_answers`` keeps no cut
    one.
    """
    return all(fixed for _name, _added, fixed in _changed(failed, answering))


def _changes_a_set_value(failed: Any, answering: Any) -> bool:
    """Whether a later call changed a value the failed call set, but for a refusal's fix.

    A value set on both sides and different (another program, a smaller
    bound) asks another question, unless it is the refused value the failure
    names, replaced by one not narrower. An argument only the later call adds
    is not read here.
    """
    return any(not added and not fixed for _name, added, fixed in _changed(failed, answering))


def _whole_listings(answering: Any, bases: Sequence[int]) -> set[int]:
    """The functions a call listed whole: decompiled, or disassembled whole."""
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

    if not getattr(answering, "ok", True) or getattr(answering, "repeated_of", None):
        return False
    if _cut(answering):
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
                if _same_question(failed, answering):
                    covered = {one_spelling(a, bases) for a in answered_addresses(answering)}
                elif lists_code and not _changes_a_set_value(failed, answering):
                    # The same name listing the function whole, with an
                    # argument added but no value the failed call set changed,
                    # still answers a failed listing of it.
                    covered = _whole_listings(answering, bases)
                else:
                    continue
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
