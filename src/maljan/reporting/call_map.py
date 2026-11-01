"""The call map the console draws: the functions the run's code reading touched.

Read from the stored ledger alone, so a run stored before the map existed
draws it too, and nothing the run stored changes:

* **Read** functions are the function map's visited functions (``agents.
  function_map.build_function_map``) and every function a code listing of any
  kind lists (``agents.function_callees.call_edges``), each with the entries
  that hold its listing and the agents whose calls those were. A listing is
  read as the entry holds it: what the analyst was handed, never a part kept
  outside the row.
* **Calls** are the calls those listings make and the calls a function index
  answer about the sample states (``call_edges``); a function a call names
  whose code no entry lists is *named, not read*.
* **Roots** are the functions nothing in the map calls, in address order; a
  part of the map every function of which is called from inside it (a cycle)
  is entered at its lowest address.

One spelling per function: the virtual address, where the one image base the
run read makes one (``function_map.one_spelling``). Nothing here reads a
tool's name: the listings and the index are read by the tools' declared kinds.
Linear in the ledger and in the calls: each is read once.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from maljan.agents.function_callees import call_edges
from maljan.agents.function_map import build_function_map, one_spelling, same_function
from maljan.pipeline.validation import generic_function_name

__all__ = ["call_map"]


@dataclass
class _Function:
    address: int | None
    names: list[str] = field(default_factory=list)
    listed_in: list[str] = field(default_factory=list)
    calls: set[int] = field(default_factory=set)
    called_by: set[int] = field(default_factory=set)


def _own_names(names: Iterable[str], address: int | None, bases: tuple[int, ...]) -> list[str]:
    """The names a function was given, the decompiler's own name for its address aside.

    The own name may spell the address as an offset or as a virtual address;
    either is the decompiler's name for it (``function_map.one_spelling``).
    """
    generic = generic_function_name()
    out: list[str] = []
    for name in names:
        name = str(name or "").strip()
        named = generic.fullmatch(name)
        if not name or name in out:
            continue
        if (
            named is not None
            and address is not None
            and one_spelling(int(named.group(1), 16), bases) == address
        ):
            continue
        out.append(name)
    return out


def _roots(functions: dict[int, _Function]) -> list[int]:
    """The functions nothing calls, then the lowest address of each part none of them reaches."""
    roots = sorted(a for a, f in functions.items() if not (f.called_by - {a}))
    reached: set[int] = set()

    def _walk(start: int) -> None:
        stack = [start]
        while stack:
            at = stack.pop()
            if at in reached:
                continue
            reached.add(at)
            stack.extend(c for c in functions[at].calls if c not in reached)

    for root in roots:
        _walk(root)
    for address in sorted(functions):
        if address not in reached:
            roots.append(address)
            _walk(address)
    return roots


def call_map(entries: Iterable[Any]) -> dict[str, Any]:
    """The call map of ``entries`` as the console reads it.

    ``functions`` in address order, each with its ``address`` (hex), its
    ``offset`` from the one image base read (or ``None``), the ``names`` it
    was given beyond the decompiler's own, whether it was ``read``, the
    entries its listing is held in (``listed_in``), the agents whose calls
    those were (``read_by``), and the addresses it ``calls`` and is
    ``called_by``. A function listed under a name alone joins the row at an
    address that carries the same name; with none, it has no address and no
    calls. ``roots`` are where the tree starts (see the module).
    """
    entries = list(entries)
    found = build_function_map(entries, None, ())
    bases = tuple(found.image_bases)
    agents = {str(getattr(e, "id", "") or ""): str(getattr(e, "agent", "") or "") for e in entries}
    by_address: dict[int, _Function] = {}
    by_name: dict[str, _Function] = {}

    def _at(address: int) -> _Function:
        key = one_spelling(address, bases)
        return by_address.setdefault(key, _Function(address=key))

    def _listed(into: _Function, ids: Iterable[str]) -> None:
        into.listed_in.extend(i for i in ids if i and i not in into.listed_in)

    for visit in found.visited:
        if visit.address is None:
            name = next((n for n in visit.names if n), "")
            if not name:
                continue
            into = by_name.setdefault(name, _Function(address=None))
        else:
            into = _at(visit.address)
        into.names.extend(n for n in visit.names if n not in into.names)
        _listed(into, (*visit.decompiled, *visit.listed))
    edges = call_edges(entries)
    for address, ids in edges.listed.items():
        _listed(_at(address), ids)
    for caller, callees in edges.calls.items():
        for callee in callees:
            if same_function(caller, callee, bases):
                continue
            _at(caller).calls.add(one_spelling(callee, bases))
            _at(callee).called_by.add(one_spelling(caller, bases))
    # A function listed under a name alone is the function at an address
    # that carries the same name, where one does: its listing joins that row.
    named_at: dict[str, _Function] = {}
    for address in sorted(by_address):
        for name in by_address[address].names:
            named_at.setdefault(name, by_address[address])
    for name in list(by_name):
        held = named_at.get(name)
        if held is not None:
            alone = by_name.pop(name)
            held.names.extend(n for n in alone.names if n not in held.names)
            _listed(held, alone.listed_in)

    base = bases[0] if len(bases) == 1 else None
    rows: list[dict[str, Any]] = []
    for function in [*(by_address[a] for a in sorted(by_address)), *by_name.values()]:
        at = function.address
        rows.append(
            {
                "address": hex(at) if at is not None else None,
                "offset": (
                    hex(at - base) if at is not None and base is not None and at >= base else None
                ),
                "names": _own_names(function.names, at, bases),
                "read": bool(function.listed_in),
                "listed_in": list(function.listed_in),
                "read_by": sorted({agents[i] for i in function.listed_in if agents.get(i)}),
                "calls": [hex(a) for a in sorted(function.calls)],
                "called_by": [hex(a) for a in sorted(function.called_by)],
            }
        )
    return {
        "image_base": hex(base) if base is not None else None,
        "functions": rows,
        "roots": [hex(a) for a in _roots(by_address)],
    }
