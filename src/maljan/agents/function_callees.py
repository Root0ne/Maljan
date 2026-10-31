"""The routines a read routine calls whose code no entry lists.

The function map's not-visited line ranks the functions by the artefacts they
reach; a routine a read routine calls and nobody listed reaches none of its
own and is never on it. Yet a sentence that calls a behaviour absent rests on
the code read, and a routine behind a read gate whose code nobody listed is
part of what was not read: the report says "no anti-debugging is established"
beside a gate whose callee nobody opened (T-404). This module states that fact
from the evidence alone:

* **Read routines** are the map's visited functions (``function_map.
  build_function_map``), and every function a code listing of any kind
  (decompiled, disassembled, a byte range disassembled) lists: the function its
  signature names, the address a batch keys it under, the address it was
  asked for.
* **Calls** are read from two places. A decompiled listing of a read routine
  calls a function by the decompiler's own name for it (``FUN_…``, ``fcn.…``,
  every prefix a server declares) followed by a call's parenthesis, its
  comments and its own signature aside; the listing's caller is the function
  its signature names, else the address it is keyed or asked under; a batch
  answer is one listing per address key, and a listing that is error text is
  none. A function index answer (kind ``function_index``) about the sample
  itself states each row's callees and callers and the callees of the
  functions it holds no row for (``other_callees``); an answer for one address
  states that function's callees.
* **Unread** is a callee no read routine is, by the map's own rule (equal, or
  an offset and its virtual address apart by an image base the run read).

Nothing here reads a tool's name: the listing kinds and the index kind are the
tools' declared kinds. Linear in the ledger: each entry and each listing is
read once, and every lookup is a dict or a set.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from maljan.agents.function_map import (
    _INDEX_KIND,
    FunctionMap,
    _hex,
    _listed_at,
    _map_kind,
    _parsed,
    address_spellings,
    build_function_map,
    one_spelling,
    same_function,
)
from maljan.core.declared_reading import kind_free_facts
from maljan.core.undeclared_tools import (
    entry_address_arguments,
    entry_decompiles,
    entry_lists_any_code,
)
from maljan.pipeline.validation import (
    _address_value,
    _batch_listings,
    _entry_functions,
    _listing_text,
    _signature_name,
    generic_function_name,
)
from maljan.schemas.evidence import answer_not_shown

__all__ = [
    "CallEdges",
    "UnreadCallee",
    "call_edges",
    "listing_is_error",
    "unread_callees",
]

# The argument a tool reads a produced file under when it declares none
# (``reporting.call_bindings``): an answer about another file holds that
# file's addresses, not the sample's.
_CARVED_ROLE = "carved"
_CARVED_ARGUMENT = "carved_path"


def _without_comments(text: str) -> str:
    """A listing with its comments, which may name a function without calling it, left out.

    One pass: a ``/*`` comment ends at the first ``*/`` after it, found once,
    and one never closed runs to the end; a ``//`` comment runs to the end of
    its line; a ``"`` string, escapes read, is kept whole, so a ``//`` inside
    one cuts nothing, and so is a ``'`` character literal, which closes within
    two characters (four after a backslash); a lone ``'`` opens nothing. A listing carries the
    sample's own strings, so no step reads the text twice.
    """
    kept: list[str] = []
    length = len(text)
    start = at = 0
    while at < length:
        char = text[at]
        if char == '"':
            at += 1
            while at < length and text[at] != char and text[at] != "\n":
                at += 2 if text[at] == "\\" else 1
            at += 1
            continue
        if char == "'":
            # A character literal closes within two characters, or four after
            # an escape; any other quote is prose (``It's``) and opens nothing.
            reach = 4 if text[at + 1 : at + 2] == "\\" else 2
            close = text.find("'", at + 2, at + 2 + reach)
            at = close + 1 if close > at + 1 else at + 1
            continue
        if char == "/" and at + 1 < length and text[at + 1] in "*/":
            kept.append(text[start:at])
            if text[at + 1] == "*":
                close = text.find("*/", at + 2)
                if close < 0:
                    return "".join(kept)
                kept.append(" ")
                at = close + 2
            else:
                close = text.find("\n", at + 2)
                if close < 0:
                    return "".join(kept)
                at = close
            start = at
            continue
        at += 1
    kept.append(text[start:])
    return "".join(kept)


@dataclass
class CallEdges:
    """``caller → callee → the entries that state the call``, in the order first stated,
    and ``listed``: each function a code listing lists, with the entries that list it."""

    calls: dict[int, dict[int, list[str]]] = field(default_factory=dict)
    listed: dict[int, list[str]] = field(default_factory=dict)

    def add(self, caller: int, callee: int, entry: str) -> None:
        held = self.calls.setdefault(caller, {}).setdefault(callee, [])
        if entry and entry not in held:
            held.append(entry)

    def lists(self, address: int, entry: str) -> None:
        held = self.listed.setdefault(address, [])
        if entry and entry not in held:
            held.append(entry)


@dataclass(frozen=True)
class UnreadCallee:
    """One routine read routines call whose code no entry lists.

    ``callers`` are the read routines that call it; ``read_in`` the entries
    that read them; ``stated_in`` the entries that state the calls.
    """

    address: int
    callers: tuple[int, ...]
    read_in: tuple[str, ...]
    stated_in: tuple[str, ...]


def _about_the_sample(entry: Any) -> bool:
    """Whether an entry's call read the sample itself, not a file the run produced."""
    arguments = getattr(kind_free_facts(entry), "arguments", None) or {}
    name = str(arguments.get(_CARVED_ROLE) or _CARVED_ARGUMENT)
    args = getattr(entry, "args", None)
    return not (isinstance(args, Mapping) and str(args.get(name) or "").strip())


def _call_pattern() -> re.Pattern[str]:
    """A decompiler's own name for a function, with a call's parenthesis after it."""
    named = generic_function_name()
    return re.compile(named.pattern + r"\s*\(", named.flags)


def _shown(entry: Any) -> bool:
    return (
        bool(getattr(entry, "ok", True))
        and not answer_not_shown(entry)
        and not getattr(entry, "repeated_of", None)
    )


def listing_is_error(entry: Any) -> bool:
    """Whether a code listing's one answer is error text, as a batch's ``Error`` key is."""
    output = str(getattr(entry, "output", "") or "")
    shown, _listings = _batch_listings(output)
    return not shown and _listing_text(output).lstrip().lower().startswith("error")


def _signature_start(text: str) -> int | None:
    """The function a listing's signature names by the decompiler's own name, or ``None``."""
    named = generic_function_name().fullmatch(_signature_name(text))
    return int(named.group(1), 16) if named is not None else None


def _listing_calls(entry: Any, edges: CallEdges, called: re.Pattern[str]) -> None:
    """The functions a decompile entry lists, and the calls each listing makes."""
    entry_id = str(getattr(entry, "id", "") or "")
    output = str(getattr(entry, "output", "") or "")
    shown, listings = _batch_listings(output)
    if shown:
        pairs: Iterable[tuple[int | None, str]] = listings.items()
    else:
        if listing_is_error(entry):
            return
        functions = _entry_functions(entry)
        if len(functions) != 1:
            return
        pairs = [(functions[0][0], _listing_text(output))]
    for asked, listing in pairs:
        text = _without_comments(listing)
        start = _signature_start(text)
        # The function the signature names is the caller: the address asked
        # may stand inside it, or be its offset.
        caller = start if start is not None else asked
        if caller is None:
            continue
        own = {caller, *([asked] if asked is not None else [])}
        for address in own:
            edges.lists(address, entry_id)
        for match in called.finditer(text):
            callee = int(match.group(1), 16)
            if callee not in own:
                edges.add(caller, callee, entry_id)


def _addresses(values: Any) -> list[int]:
    found = [_hex(value) for value in values] if isinstance(values, list) else []
    return [address for address in found if address is not None]


def _index_calls(entry: Any, data: Mapping[str, Any], edges: CallEdges) -> None:
    """The calls a function index answer states: per row, the rest, and an address's own."""
    entry_id = str(getattr(entry, "id", "") or "")
    rows = data.get("rows")
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping):
            continue
        function = _hex(row.get("function"))
        if function is None:
            function = _hex(row.get("offset"))
        if function is None:
            continue
        for callee in _addresses(row.get("callees")):
            edges.add(function, callee, entry_id)
        for caller in _addresses(row.get("callers")):
            edges.add(caller, function, entry_id)
    others = data.get("other_callees")
    if isinstance(others, Mapping):
        for key, callees in others.items():
            calling = _hex(key)
            if calling is not None:
                for callee in _addresses(callees):
                    edges.add(calling, callee, entry_id)
    if isinstance(rows, list):
        return
    # An answer for one address: the callees of the function it was asked
    # for. Its callers are not read: the address asked may stand inside the
    # function, and the function it starts is then not that address.
    args = getattr(entry, "args", None) or {}
    asked = next(
        (
            _address_value(args[name])
            for name in entry_address_arguments(entry)
            if name in args and _address_value(args[name]) is not None
        ),
        None,
    )
    if asked is not None:
        for callee in _addresses(data.get("callees")):
            edges.add(asked, callee, entry_id)


def call_edges(entries: Iterable[Any]) -> CallEdges:
    """Every call the run's decompiled listings and function index answers state, and
    every function a code listing lists."""
    edges = CallEdges()
    called = _call_pattern()
    for entry in entries:
        if not _shown(entry):
            continue
        if entry_decompiles(entry):
            _listing_calls(entry, edges, called)
        elif entry_lists_any_code(entry):
            if listing_is_error(entry):
                continue
            address, _names = _listed_at(entry)
            if address is not None:
                edges.lists(address, str(getattr(entry, "id", "") or ""))
        elif _map_kind(entry) == _INDEX_KIND and _about_the_sample(entry):
            data = _parsed(entry)
            if isinstance(data, Mapping):
                _index_calls(entry, data, edges)
    return edges


def unread_callees(entries: Iterable[Any], found: FunctionMap | None = None) -> list[UnreadCallee]:
    """The routines read routines call whose code no entry lists, by address.

    ``found`` is the map of ``entries`` when the caller built it already;
    otherwise it is built here with no pack artefacts and no claims, which a
    read routine does not depend on. An offset and its virtual address are one
    routine when exactly one image base was read, and are spelled by the
    virtual address.
    """
    entries = list(entries)
    if found is None:
        found = build_function_map(entries, None, ())
    bases = tuple(found.image_bases)
    edges = call_edges(entries)
    read: dict[int, list[str]] = {}
    for visit in found.visited:
        if visit.address is None:
            continue
        held = read.setdefault(visit.address, [])
        held.extend(e for e in (*visit.decompiled, *visit.listed) if e not in held)
    for address, listed in edges.listed.items():
        held = read.setdefault(address, [])
        held.extend(e for e in listed if e not in held)

    def _read_as(address: int) -> int | None:
        for key in address_spellings(address, bases):
            if key in read and same_function(key, address, bases):
                return key
        return None

    out: dict[int, tuple[list[int], list[str], list[str]]] = {}
    for caller, callees in edges.calls.items():
        caller_read = _read_as(caller)
        if caller_read is None:
            continue
        for callee, stated in callees.items():
            if _read_as(callee) is not None or same_function(caller, callee, bases):
                continue
            key = one_spelling(callee, bases)
            callers, read_in, stated_in = out.setdefault(key, ([], [], []))
            shown = one_spelling(caller_read, bases)
            if shown not in callers:
                callers.append(shown)
            read_in.extend(e for e in read[caller_read] if e not in read_in)
            stated_in.extend(e for e in stated if e not in stated_in)
    return [
        UnreadCallee(
            address=address,
            callers=tuple(sorted(callers)),
            read_in=tuple(read_in),
            stated_in=tuple(stated_in),
        )
        for address, (callers, read_in, stated_in) in sorted(out.items())
    ]
