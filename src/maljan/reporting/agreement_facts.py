"""The ledger's own facts the agreement round is shown beside the bound values.

Section 5 is written from the code and the tool answers, and the round asked a
section 5 sentence only against the decoded texts bound to an API argument: a
sentence that called a behaviour absent while the routine behind a read gate
was never read (T-404), or that blamed "two decompile failures" for a routine
a later call decompiled (T-396), had no fact to be asked against. Two more are
read here, from the ledger alone:

* **An unread callee** (``agents.function_callees``): a routine a read routine
  calls, by a decompiled listing or a function index answer, that no entry
  reads.
* **A failed call answered later**: a call for an address that failed, and the
  first later call that answered for the same address, of the same tool or,
  for a call that lists code, any later listing of that function.

Each is stated in the platform's words, with the entries it rests on; which
sentence it bears on is the model's call. Linear in the ledger.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.agents.function_callees import UnreadCallee, listing_is_error, unread_callees
from maljan.agents.function_map import build_function_map, one_spelling
from maljan.core.undeclared_tools import (
    entry_address_arguments,
    entry_decompiles,
    entry_lists_any_code,
)
from maljan.pipeline.validation import (
    _ADDRESS_LIST_ARGUMENTS,
    _address_list,
    _address_value,
    _entry_functions,
)
from maljan.schemas.evidence import answer_not_shown

__all__ = ["AnsweredLater", "LedgerFacts", "answered_later", "ledger_facts", "spelled"]


@dataclass(frozen=True)
class AnsweredLater:
    """A call for ``address`` that failed, and the first later call that answered for it."""

    address: int
    failed: str
    failed_tool: str
    answered: str
    answered_tool: str
    # Whether the answering call lists code (decompiled or disassembled).
    answered_lists_code: bool = False


@dataclass(frozen=True)
class LedgerFacts:
    """The facts read off one ledger, and the image bases its answers stated."""

    unread: tuple[UnreadCallee, ...] = ()
    answered: tuple[AnsweredLater, ...] = ()
    image_bases: tuple[int, ...] = ()


def _asked(entry: Any) -> list[int]:
    """The addresses a call was given, by its address arguments and its address lists."""
    args = getattr(entry, "args", None) or {}
    found: list[int] = []
    for name in entry_address_arguments(entry):
        if name in args:
            value = _address_value(args[name])
            if value is not None:
                found.append(value)
    for name in _ADDRESS_LIST_ARGUMENTS:
        if name in args:
            found.extend(_address_list(args[name]))
    return list(dict.fromkeys(found))


def _answered_for(entry: Any) -> list[int]:
    """The addresses a call answered for: a listing's functions, else what it was asked.

    A code listing whose one answer is error text answered for none, as a
    batch's ``Error`` key is no listing (``function_callees.listing_is_error``).
    """
    if entry_lists_any_code(entry) and listing_is_error(entry):
        return []
    if entry_decompiles(entry):
        held = [address for address, _names in _entry_functions(entry) if address is not None]
        if held:
            return list(dict.fromkeys(held))
    return _asked(entry)


def _groups(entry: Any) -> tuple[tuple[str, str], ...]:
    """What a call answers as: its own tool, and a listing of code when it lists code."""
    tool = ("tool", str(getattr(entry, "tool", "") or ""))
    return (tool, ("code", "")) if entry_lists_any_code(entry) else (tool,)


def answered_later(entries: Iterable[Any], image_bases: Sequence[int] = ()) -> list[AnsweredLater]:
    """Each failed call for an address, linked to the first later call that answered for it.

    Read in ledger order. A failed call waits under each address it was asked
    for, as what it is (its tool; a listing of code); a later call that
    answered, was shown and is no repeat takes every call waiting under an
    address it answered for, as what it is. A failed repeat waits as its own
    call. An offset and its virtual address are one address when exactly one
    image base was read.
    """
    waiting: dict[tuple[int, tuple[str, str]], list[Any]] = {}
    out: list[AnsweredLater] = []
    linked: set[tuple[int, int]] = set()
    for entry in entries:
        if not getattr(entry, "ok", True):
            for address in _asked(entry):
                for group in _groups(entry):
                    waiting.setdefault((one_spelling(address, image_bases), group), []).append(
                        entry
                    )
            continue
        if answer_not_shown(entry) or getattr(entry, "repeated_of", None):
            continue
        for address in _answered_for(entry):
            key = one_spelling(address, image_bases)
            for group in _groups(entry):
                for failed in waiting.pop((key, group), ()):
                    # A call waits as its tool and as a listing: linked once.
                    if (id(failed), key) in linked:
                        continue
                    linked.add((id(failed), key))
                    out.append(
                        AnsweredLater(
                            address=key,
                            failed=str(getattr(failed, "id", "") or ""),
                            failed_tool=str(getattr(failed, "tool", "") or ""),
                            answered=str(getattr(entry, "id", "") or ""),
                            answered_tool=str(getattr(entry, "tool", "") or ""),
                            answered_lists_code=entry_lists_any_code(entry),
                        )
                    )
    return out


def ledger_facts(entries: Iterable[Any]) -> LedgerFacts:
    """The unread callees and the failed calls answered later, read off ``entries``."""
    entries = list(entries)
    found = build_function_map(entries, None, ())
    bases = tuple(found.image_bases)
    return LedgerFacts(
        unread=tuple(unread_callees(entries, found)),
        answered=tuple(answered_later(entries, bases)),
        image_bases=bases,
    )


def spelled(address: int, bases: Sequence[int]) -> str:
    """An address as a fact writes it: the virtual address, and its offset by the one base read."""
    if len(bases) == 1 and address >= bases[0]:
        return f"{hex(address)} (offset {hex(address - bases[0])})"
    return hex(address)
