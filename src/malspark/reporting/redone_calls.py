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
* for a failed call that lists code, a later call that lists that function
  whole, of the same tool that changed no value the failed call set (but for
  the refused value, replaced by one not narrower), or of another tool that
  names no other program in an argument both declare to name the program
  (T-542; the role ``program`` of each entry's stored ``arguments``, two
  values naming the same program when their last path segments agree, by the
  one rule ``agents.image_range.same_program`` reads a program argument with;
  a refused program the failure names, replaced, is the refusal's fix): a
  decompiled listing holding it, or a disassembly of the whole function (the
  entry's declared kind says which). A read of some instructions from the
  address is no redo. Known limit: an argument the same tool's call only adds
  is not checked on this route; the listing is read as whole by its kind, so a
  bound only the redo sets (``max_lines=3``) is not seen. Known limit: two
  different folders that hold the same file name (``a/x.exe``, ``b/x.exe``)
  are read as one program.

A value given again as the same items in another shape (a comma-separated
text given again as a list holding every one of its items, and more) is the
same question, never a narrower one: haiku11's emulations refused a comma text
("No candidates provided") and were asked again with the list (T-562).

A call asked for no address (a scan, a lookup, an emulation by candidate
names) is redone by a later call of the same tool that asked the same
question: every argument, address arguments included, the failed call's, but
for the refusal's fix and a value given again in another shape (haiku11's
byte reads refused a quoted offset and were asked again with the number,
T-562). Another call of the same tool with other arguments asks another
question.

The answering call must hold its answer whole (``holds_its_answer``, and
nothing cut by the byte budget or the tool-output guardrail), and an answer
that is error text answers nothing, a listing or not. The rows are the
platform's own ids and the tool's name, cleaned to one capped line; the
failure itself is still counted and listed where the run's counts are
(``run_summary.evidence.failed`` and ``failures``).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
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
    from malspark.schemas.evidence import answer_not_shown, holds_its_answer

    if getattr(answering, "truncated", False) or int(getattr(answering, "chars_dropped", 0) or 0):
        return True
    return answer_not_shown(answering) or not holds_its_answer(answering)


def _items(value: Any) -> tuple[list[str], bool]:
    """``value`` as the items it gives, and whether it is written as a list.

    A list, or a text that reads as a JSON list, gives its items; any other
    text gives its comma-separated parts. Each item is one stripped text; an
    empty one is left out.
    """
    shaped = value
    if isinstance(value, str) and value.lstrip().startswith("["):
        import json

        try:
            shaped = json.loads(value)
        except ValueError:
            shaped = value
    if isinstance(shaped, list | tuple):
        return [text for text in (str(item).strip() for item in shaped) if text], True
    return [text for text in (part.strip() for part in str(value).split(",")) if text], False


def _reshaped(before: Any, after: Any) -> bool:
    """Whether ``after`` gives every item ``before`` gave, written in another shape.

    One side a list and the other not: a comma-separated text given again as
    a list holding each of its items (and maybe more) asks what it asked, never
    less.
    """
    was, was_list = _items(before)
    now, now_list = _items(after)
    return bool(was) and was_list != now_list and set(was) <= set(now)


def _same_value(before: Any, after: Any, named: bool) -> bool:
    """Whether ``after`` is the refused ``before`` in another spelling.

    Quotes around a text are no part of it; two numbers are one where they are
    equal (``"0xf000"`` and ``61440``). Case is kept: ``MZ`` is not ``mz``. A
    bare hex text is read as hex only beside a number and only where the
    failure's message names the refused value (``572d5d8e`` refused, asked as
    ``0x572d5d8e``): ``a`` is never ``10``.
    """
    was = str(before).strip().strip("\"'`").strip()
    now = str(after).strip().strip("\"'`").strip()
    if was == now:
        return True
    left, right = _number(was), _number(now)
    if left is not None and right is not None:
        return left == right
    if not named:
        return False
    if left is None and right is not None and re.fullmatch(r"[0-9a-fA-F]+", was):
        return int(was, 16) == right
    if right is None and left is not None and re.fullmatch(r"[0-9a-fA-F]+", now):
        return int(now, 16) == left
    return False


def _program_argument(entry: Any) -> str:
    """The argument an entry's tool declares to name the program, or ``""``."""
    from malspark.core.declared_reading import kind_free_facts

    roles = getattr(kind_free_facts(entry), "arguments", None)
    return str(roles.get("program") or "") if isinstance(roles, Mapping) else ""


def _changed(
    failed: Any, answering: Any, *, by_address: bool = True, sample: Sequence[str] = ()
) -> Iterator[tuple[str, bool, bool]]:
    """Each argument a later call set to another value than the failed one.

    The address arguments are left out when the calls are matched by address
    (``by_address``). ``(name, added, fixed)``: ``added`` when the failed call
    left it absent or null; ``fixed`` when the failure's own message names it
    (an added one) or the value it refused (a set one, replaced by a value not
    narrower), or the redo gives the same items in another shape
    (:func:`_reshaped`). An argument the redo leaves absent or null is no
    change.

    A call asked for no address (not ``by_address``) is matched on every
    argument, and its question is its values: a refused value is fixed only
    when the redo gives the same value in another spelling (``"0xf000"`` as
    ``61440``, :func:`_same_value`) or the same items in another shape. A value
    the redo leaves absent or null is another question (a name looked up, a
    pattern searched), but for the program the tool declares an argument for,
    whose refused value the failure's message names and is the run's own
    sample by the pipeline pack's record (``image_range._sample_names``): left
    out, the server's own program, the sample, is asked the same question; a
    refused other file (a dropped payload) left out asks about the sample, another
    question.
    """
    from malspark.agents.image_range import same_program
    from malspark.core.undeclared_tools import entry_address_arguments
    from malspark.pipeline.validation import _ADDRESS_LIST_ARGUMENTS

    skip: set[str] = set()
    if by_address:
        skip = {*entry_address_arguments(failed), *entry_address_arguments(answering)}
        skip.update(_ADDRESS_LIST_ARGUMENTS)
    asked = getattr(failed, "args", None) or {}
    again = getattr(answering, "args", None) or {}
    message = str(getattr(failed, "error", "") or getattr(failed, "output", "") or "")
    program = "" if by_address else _program_argument(failed)
    for name in sorted({*asked, *again} - skip, key=str):
        before, after = asked.get(name), again.get(name)
        if before == after or str(before) == str(after) or (_empty(before) and _empty(after)):
            continue
        refused = str(before)
        named = len(refused) >= _NAMED_VALUE_CHARS and refused in message
        if _empty(after):
            if by_address:
                continue
            # Left out, the server's own program is asked: the same question
            # only where the refused one is the run's own sample.
            own = any(same_program(refused, held) for held in sample)
            yield str(name), False, named and own and bool(program) and str(name) == program
            continue
        if _empty(before):
            yield str(name), True, _names_argument(message, str(name))
            continue
        if by_address:
            fixed = named and not _narrower(before, after)
        else:
            fixed = _same_value(before, after, named)
        yield str(name), False, fixed or _reshaped(before, after)


def _same_question(
    failed: Any, answering: Any, *, by_address: bool = True, sample: Sequence[str] = ()
) -> bool:
    """Whether a later call of the failed call's tool asked what it asked, but for its addresses.

    Never a narrower question: an argument only the redo sets, unless the
    failure named it, and a refused value replaced by a smaller number, each
    make it another question. The answer is whole: ``_answers`` keeps no cut
    one. Without ``by_address`` the addresses are read like every other
    argument.
    """
    return all(
        fixed
        for _name, _added, fixed in _changed(
            failed, answering, by_address=by_address, sample=sample
        )
    )


def _changes_a_set_value(failed: Any, answering: Any) -> bool:
    """Whether a later call changed a value the failed call set, but for a refusal's fix.

    A value set on both sides and different (another program, a smaller
    bound) asks another question, unless it is the refused value the failure
    names, replaced by one not narrower. An argument only the later call adds
    is not read here. For a call of the same tool only: another tool may give
    one name another meaning (:func:`_names_another_program`).
    """
    return any(not added and not fixed for _name, added, fixed in _changed(failed, answering))


def _program_value(entry: Any) -> str:
    """The program a call named in the argument its tool declares to name the program; else ''.

    Read off the entry's stored declaration (its ``arguments`` role
    ``program``), as the value it gives; :func:`_names_another_program` reads
    it by its last path segment (``agents.image_range.same_program``).
    """
    from malspark.core.declared_reading import kind_free_facts

    roles = getattr(kind_free_facts(entry), "arguments", None)
    name = str(roles.get("program") or "") if isinstance(roles, Mapping) else ""
    args = getattr(entry, "args", None)
    value = args.get(name) if name and isinstance(args, Mapping) else None
    return "" if _empty(value) else str(value)


def _names_another_program(failed: Any, answering: Any) -> bool:
    """Whether a call of another tool named another program than the failed call did.

    Only where both tools declare an argument to name the program and both
    calls set it: any other argument may mean another thing to another tool
    (a ``mode``, a ``format``, a ``timeout``), so it is not read. The refused
    program the failure's own message names, replaced, is the refusal's fix.
    """
    from malspark.agents.image_range import program_name, same_program

    named = _program_value(failed)
    before, after = program_name(named), program_name(_program_value(answering))
    if not before or not after or same_program(named, after):
        return False
    message = str(getattr(failed, "error", "") or getattr(failed, "output", "") or "")
    return not (len(before) >= _NAMED_VALUE_CHARS and before in message)


def _whole_listings(answering: Any, bases: Sequence[int]) -> set[int]:
    """The functions a call listed whole: decompiled, or disassembled whole."""
    from malspark.agents.function_map import one_spelling
    from malspark.core.undeclared_tools import entry_decompiles, entry_lists_a_function
    from malspark.pipeline.validation import _entry_functions
    from malspark.reporting.agreement_facts import asked_addresses

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
    from malspark.agents.function_callees import listing_is_error

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
    order; for a call asked for no address, the first later call of its tool
    that asked the same question. Empty when nothing failed, without reading
    the ledger further.
    """
    entries = list(ledger)
    failed_at = [
        at
        for at, entry in enumerate(entries)
        if not getattr(entry, "ok", True) and not getattr(entry, "repeated_of", None)
    ]
    if not failed_at:
        return []
    from malspark.agents.function_map import build_function_map, one_spelling
    from malspark.core.undeclared_tools import entry_lists_any_code
    from malspark.reporting.agreement_facts import answered_addresses, asked_addresses

    bases = tuple(build_function_map(entries, None, ()).image_bases)
    answers = [at for at, entry in enumerate(entries) if _answers(entry)]
    held: list[tuple[str, ...]] = []

    def _sample() -> tuple[str, ...]:
        # The run's own sample by the platform's record: the names the
        # pipeline's own pack answers read it by, never a failure's message.
        if not held:
            from malspark.agents.image_range import _sample_names
            from malspark.pipeline.triage_pack import pack_entries

            held.append(_sample_names(pack_entries(entries)))
        return held[0]

    out: list[dict[str, Any]] = []
    for at in failed_at:
        failed = entries[at]
        asked = {one_spelling(address, bases) for address in asked_addresses(failed)}
        if not asked:
            # Nothing to match by address: the same question, every argument read.
            again = next(
                (
                    later
                    for later in answers
                    if later > at
                    and getattr(entries[later], "tool", None) == getattr(failed, "tool", None)
                    and _same_question(failed, entries[later], by_address=False, sample=_sample())
                ),
                None,
            )
            if again is not None:
                out.append(
                    {
                        "entry_id": str(getattr(failed, "id", "") or ""),
                        "tool": _tool(failed),
                        "answered_by": [str(getattr(entries[again], "id", "") or "")],
                    }
                )
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
            elif lists_code and not _names_another_program(failed, answering):
                # Another tool listing the function whole answers a failed
                # listing of it, but of another program (T-542).
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
