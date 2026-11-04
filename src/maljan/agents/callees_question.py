"""The routines an analyst described whose callees it never read, asked about once.

An analyst reading code stopped on its own with the routine that reads its configuration
file, the one that writes it and the cipher wrapper of its channel unread:
each was a callee of a routine its claims described, and the function map
listed each as named and not read, a fact that asks for nothing. This module
turns that fact into one question before the analyst's answer stands:

* **Described** routines are the read routines (``function_callees.
  read_routines``: every function a code listing of the analyst lists) that a
  claim of its answer names, by an address in its sentence or its evidence
  line, or whose listing entry a claim cites.
* **Unread callees** are the callees of described routines no listing of the
  analyst holds (``function_callees.unread_callees``), from its own listings
  and the run's function index.
* **The main path** is what the run's answers state starts the code: the
  entry point and the exports a PE header answer states, the functions a
  function index answer states are started as threads (a loop such as a
  beacon runs in one) and its rows marked as entry points. Where none is
  stated, the described routines whose claim calls them an entry, main,
  dispatcher, beacon, start-up or command routine stand in for it.
* **The rank** is a callee's distance from the path: the calls between it
  and the nearest start, plus one for each function beyond the first that
  calls it (a routine called from everywhere is a shared helper, not a step
  of the path). One no start reaches comes last. Ties go to the one calling
  more functions itself, then to the lower address. No address is special to
  the platform.

The question lists at most :data:`CALLEES_SHOWN` of them, says how many there
are and that the rest are left out, and gives each its reason in the
platform's own words: addresses and counts, never a name or a string the
sample or a tool wrote. The analyst decides: it may read any of them with its
tools, or none; nothing is forced and no call is refused. Linear in the
ledger and the call graph: each entry is read once, the path is one
breadth-first walk, every lookup is a dict or a set.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.agents.function_callees import (
    call_edges,
    read_routines,
    unread_callees,
)
from maljan.agents.function_map import (
    _INDEX_KIND,
    _hex,
    _map_kind,
    _parsed,
    address_spellings,
    build_function_map,
    one_spelling,
    same_function,
)
from maljan.core.declared_reading import facts_of
from maljan.core.undeclared_tools import (
    declares_a_kind,
    entry_decompiles,
    entry_facts,
    entry_lists_any_code,
)
from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import Violation, _addresses_written
from maljan.schemas.evidence import entry_ids_in

__all__ = [
    "CALLEES_SHOWN",
    "UNREAD_CALLEES_CODE",
    "CalleeToRead",
    "CalleesFound",
    "callees_asked_record",
    "callees_to_read",
    "reads_code",
    "unread_callees_violation",
]

# An analyst reading code stopped on its own with the main-path callees of routines it
# described unread. Those callees, ranked by the main path, are listed to it,
# once per job, and it decides whether to read them.
UNREAD_CALLEES_CODE = "isr.callees_not_read"

# How many callees the question lists at most; the question says how many
# there are in all and that the others are left out.
CALLEES_SHOWN = 12

# The answer shape whose entry point and exports start the code.
_HEADER_READER = "pe_header"

# How the question says where the code starts, by what the starts were read from.
STARTS_STATED = "the entry point, the exports and the thread starts the run's answers state"
STARTS_CLAIMED = (
    "the routines your claims call an entry, main, dispatcher, beacon, start-up or command "
    "routine, since no answer states where the code starts"
)
STARTS_NONE = "no answer states where the code starts and no claim names such a routine"


# A claim that calls a routine one of these is the analyst's own word that it
# starts or steers the code; read only where no answer states a start.
_CENTRAL_WORDS = re.compile(
    r"\b(?:entry(?:[\s-]?point)?|main|dispatch(?:er|es|ing)?|beacon(?:ing)?|start[\s-]?up|"
    r"command\s+(?:loop|handler|router)|c2\s+loop)\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CalleeToRead:
    """One unread callee of a described routine, with what ranks it.

    ``callers`` are the described routines that call it; ``depth`` the calls
    between it and the path's nearest start (``None``: no start reaches it);
    ``called_from`` how many functions call it; ``calls`` how many it calls.
    """

    address: int
    callers: tuple[int, ...]
    depth: int | None
    start: int | None
    called_from: int
    calls: int

    def distance(self) -> int | None:
        """The rank: calls from the nearest start, plus one per further caller; ``None``: unreached."""
        if self.depth is None:
            return None
        return self.depth + max(0, self.called_from - 1)

    def reason(self) -> str:
        """Why it is listed, in the platform's words: addresses and counts."""
        callers = ", ".join(hex(c) for c in self.callers[:2])
        more = len(self.callers) - 2
        said = f"called by {callers}" + (f" and {more} more" if more > 0 else "")
        if self.depth is not None and self.start is not None:
            said += f"; {self.depth} call(s) from the start {hex(self.start)}"
        else:
            said += "; no stated start reaches it"
        return f"{said}; {self.called_from} caller(s); calls {self.calls}"


# Why the question was not put, in the words the run's events and record say
# it: what the platform could not read, never a silent skip.
NOT_RUN_NO_LISTING = (
    "no entry of this analyst lists code: no tool it called declares a decompile, "
    "disassembly or function-listing kind, and no tool that declares nothing is named as one"
)
NOT_RUN_NO_LISTING_UNDECLARED = (
    "no entry of this analyst lists code; {count} undeclared tool(s) it called ({tools}) "
    "answered, and neither a declared kind nor the tool's name says its answer is a code "
    "listing, so no routine it read is known"
)
NOT_RUN_NO_CLAIMS = "its answer holds no claim to read the routines it describes from"
NOT_RUN_NOT_DESCRIBED = "no claim names or cites a routine its listings hold"
NOT_RUN_NO_CALLS = (
    "neither its listings nor a function index state what the routines its claims describe call"
)
# How many undeclared tools the not-run sentence names at most.
_TOOLS_NAMED = 5


@dataclass(frozen=True)
class CalleesFound:
    """The ranked callees, how the question says where the code starts, and why none.

    ``not_run`` is why the platform could not tell which callees are unread
    (one of the ``NOT_RUN_*`` sentences); ``""`` when it could, the list
    empty or not.
    """

    ranked: tuple[CalleeToRead, ...] = ()
    starts: str = STARTS_NONE
    not_run: str = ""

    def addresses(self) -> list[str]:
        return [hex(c.address) for c in self.ranked]


def reads_code(
    definition: Any, ledger: Sequence[Any], declarations: Any = None
) -> tuple[bool, str]:
    """Whether an analyst reads code, and, when it does not, why: the one place that decides.

    Today from the ledger alone: an entry whose tool declares a decompile,
    disassembly or function-listing kind (the declaration each entry stored),
    or, for a tool that declares nothing, whose name says it is one. Neither
    the analyst's name nor a tool's or a server's name is read.
    ``definition`` (the analyst's definition) and ``declarations`` are taken
    so that a reading keyed on them first can stand in front of this one;
    neither is read yet.
    """
    del definition, declarations
    if any(entry_decompiles(e) or entry_lists_any_code(e) for e in ledger):
        return True, ""
    return False, _no_listing(ledger)


def _no_listing(entries: Sequence[Any]) -> str:
    """Why no routine is known: the undeclared tools that answered are named, bounded."""
    undeclared = list(
        dict.fromkeys(
            str(getattr(e, "tool", "") or "")
            for e in entries
            if getattr(e, "ok", True) is not False and not declares_a_kind(entry_facts(e))
        )
    )
    undeclared = [t for t in undeclared if t]
    if not undeclared:
        return NOT_RUN_NO_LISTING
    named = ", ".join(safe_finding_value(t)[:60] for t in undeclared[:_TOOLS_NAMED])
    more = len(undeclared) - _TOOLS_NAMED
    if more > 0:
        named += f" and {more} more"
    return NOT_RUN_NO_LISTING_UNDECLARED.format(count=len(undeclared), tools=named)


def _claim_texts(claims: Iterable[Any]) -> list[tuple[str, str, set[str]]]:
    """Each claim's sentence, its evidence line and the entry ids the line cites."""
    out: list[tuple[str, str, set[str]]] = []
    for claim in claims:
        sentence = str(getattr(claim, "claim", "") or "")
        evidence = str(getattr(claim, "evidence_ref", "") or "")
        out.append((sentence, evidence, entry_ids_in(evidence)))
    return out


def _stated_starts(entries: Iterable[Any], bases: Sequence[int]) -> list[int]:
    """The starts the run's answers state: entry point, exports, thread starts, entry rows."""
    starts: dict[int, None] = {}
    for entry in entries:
        if getattr(entry, "ok", True) is False:
            continue
        facts = facts_of(entry)
        data = _parsed(entry)
        if not isinstance(data, Mapping):
            continue
        if facts is not None and facts.reader == _HEADER_READER:
            point = data.get("entry_point")
            if isinstance(point, int) and not isinstance(point, bool) and point > 0:
                starts[one_spelling(point, bases)] = None
            for row in data.get("export_rows") or []:
                rva = _hex(row.get("rva")) if isinstance(row, Mapping) else None
                if rva is not None:
                    starts[one_spelling(rva, bases)] = None
        elif _map_kind(entry) == _INDEX_KIND:
            for row in data.get("thread_starts") or []:
                started = _hex(row.get("started")) if isinstance(row, Mapping) else None
                if started is not None:
                    starts[one_spelling(started, bases)] = None
            for row in data.get("rows") or []:
                if not isinstance(row, Mapping):
                    continue
                function = _hex(row.get("function")) or _hex(row.get("offset"))
                if function is not None and (row.get("entry_point") or row.get("names")):
                    starts[one_spelling(function, bases)] = None
    return sorted(starts)


def _depths(
    graph: Mapping[int, Iterable[int]], starts: Sequence[int]
) -> dict[int, tuple[int, int]]:
    """Each function's ``(calls from the nearest start, that start)``, one walk from all starts."""
    out: dict[int, tuple[int, int]] = {start: (0, start) for start in starts}
    queue = deque(starts)
    while queue:
        at = queue.popleft()
        depth, start = out[at]
        for callee in graph.get(at, ()):
            if callee not in out:
                out[callee] = (depth + 1, start)
                queue.append(callee)
    return out


def callees_to_read(
    claims: Iterable[Any],
    entries: Sequence[Any],
    pack: Sequence[Any] = (),
    definition: Any = None,
) -> CalleesFound:
    """The unread callees of the routines ``claims`` describe, ranked by the main path.

    ``entries`` are the analyst's own ledger entries, ``pack`` the triage
    pack's: its function index adds the calls the analyst's listings do not
    state and the threads it starts, its header the entry point and exports.
    ``definition`` is the analyst's, handed to :func:`reads_code`. Empty when
    the analyst reads no code, and when every callee of what it
    described is read.
    """
    own = list(entries)
    code, why = reads_code(definition, own)
    if not code:
        return CalleesFound(not_run=why)
    said = _claim_texts(claims)
    if not said:
        return CalleesFound(not_run=NOT_RUN_NO_CLAIMS)
    context = _context(pack)
    every = [*context, *own]
    found = build_function_map(every, None, ())
    bases = tuple(found.image_bases)
    edges = call_edges(every)
    read = read_routines(every, found, edges)
    if not read:
        return CalleesFound(not_run=_no_listing(own))

    def _held(address: int, keys: Mapping[int, Any]) -> int | None:
        return _held_in(address, keys, bases)

    # Each listing entry's routines, so a cited entry is one lookup.
    listing: dict[str, list[int]] = {}
    for key, listed in read.items():
        for entry_id in listed:
            listing.setdefault(entry_id.lower(), []).append(key)
    described: dict[int, None] = {}
    central: dict[int, None] = {}
    for sentence, evidence, cited in said:
        for address in _addresses_written(f"{sentence} {evidence}"):
            named = _held(address, read)
            if named is not None:
                described[named] = None
                if _CENTRAL_WORDS.search(sentence):
                    central[named] = None
        for entry_id in sorted(cited):
            described.update(dict.fromkeys(listing.get(entry_id, ())))
    if not described:
        return CalleesFound(not_run=NOT_RUN_NOT_DESCRIBED)

    # The call graph by one spelling per function, callees in the order stated.
    graph: dict[int, dict[int, None]] = {}
    callers_of: dict[int, set[int]] = {}
    for caller, callees in edges.calls.items():
        at = one_spelling(caller, bases)
        held = graph.setdefault(at, {})
        for callee in callees:
            to = one_spelling(callee, bases)
            if to != at:
                held[to] = None
                callers_of.setdefault(to, set()).add(at)
    if not any(graph.get(key) for key in described):
        return CalleesFound(not_run=NOT_RUN_NO_CALLS)
    starts = _stated_starts(context + own, bases)
    said_starts = STARTS_STATED
    if not starts:
        starts = sorted(central)
        said_starts = STARTS_CLAIMED if starts else STARTS_NONE
    depths = _depths(graph, starts)

    out: list[CalleeToRead] = []
    for unread in unread_callees(every, found, edges):
        callers = tuple(
            sorted(
                {
                    held_by
                    for caller in unread.callers
                    if (held_by := _held(caller, described)) is not None
                }
            )
        )
        if not callers:
            continue
        address = one_spelling(unread.address, bases)
        depth, start = depths.get(address, (None, None))
        out.append(
            CalleeToRead(
                address=address,
                callers=callers,
                depth=depth,
                start=start,
                called_from=len(callers_of.get(address, ())),
                calls=len(graph.get(address, ())),
            )
        )
    out.sort(key=lambda c: (c.distance() is None, c.distance() or 0, -c.calls, c.address))
    return CalleesFound(tuple(out), said_starts)


def _is_header(entry: Any) -> bool:
    facts = facts_of(entry)
    return facts is not None and facts.reader == _HEADER_READER


def _context(pack: Sequence[Any]) -> list[Any]:
    """The pack's entries the question reads: its function index and its header."""
    return [e for e in pack if _map_kind(e) == _INDEX_KIND or _is_header(e)]


def _held_in(address: int, keys: Mapping[int, Any], bases: Sequence[int]) -> int | None:
    """The key of ``keys`` that is ``address``'s function by the map's rule, or ``None``."""
    for key in address_spellings(address, bases):
        if key in keys and same_function(key, address, bases):
            return key
    return None


def unread_callees_violation(found: CalleesFound) -> Violation | None:
    """The one question about ``found``, or ``None`` when there is none.

    At most :data:`CALLEES_SHOWN` are listed, in rank order; the question
    says how many there are and that the rest are not listed. It asks
    whether to read them and forces nothing.
    """
    ranked = found.ranked
    if not ranked:
        return None
    shown = ranked[:CALLEES_SHOWN]
    left = len(ranked) - len(shown)
    listed = "; ".join(f"{hex(c.address)} ({c.reason()})" for c in shown)
    bound = (
        f" The first {len(shown)} of {len(ranked)} are listed (the question lists at most "
        f"{CALLEES_SHOWN}); the other {left} are not."
        if left
        else ""
    )
    return Violation(
        code=UNREAD_CALLEES_CODE,
        message=(
            f"Routines your claims describe call {len(ranked)} function(s) whose code none "
            f"of your listings holds. Where the code starts: {found.starts}. Ranked by "
            "distance from those starts (the calls between, plus one for each further "
            "function calling it, since a routine called from many places is a shared "
            f"helper): {listed}.{bound} Each is a step of what your claims describe that "
            "you have not read. Decide whether any matters to this analysis: you may read "
            "any of them with your tools and add or change claims for what their code "
            "does, citing the entries that list it, or leave them unread and change "
            "nothing. This is asked once."
        ),
    )


def callees_asked_record(
    claims: Iterable[Any],
    asked_over: Sequence[Any],
    now: Sequence[Any],
    pack: Sequence[Any] = (),
) -> tuple[dict[str, Any], Violation | None]:
    """What became of the question: the loop's record and the run's answered row.

    ``claims`` are those of the answer the question was put about and
    ``asked_over`` the entries it was read against, so the list is the one
    asked; ``now`` the entries after the analyst answered. Of the callees
    listed, the ones a listing in ``now`` holds were read since. ``({}, None)``
    when the answer had none to list.
    """
    found = callees_to_read(claims, asked_over, pack)
    if not found.ranked:
        return {}, None
    shown = found.ranked[:CALLEES_SHOWN]
    every = [*_context(pack), *now]
    mapped = build_function_map(every, None, ())
    held = read_routines(every, mapped)
    bases = tuple(mapped.image_bases)
    read = [hex(c.address) for c in shown if _held_in(c.address, held, bases) is not None]
    record: dict[str, Any] = {
        "listed": len(found.ranked),
        "shown": [hex(c.address) for c in shown],
        "shown_at_most": CALLEES_SHOWN,
        "read_after": read,
    }
    answered = Violation(
        code=UNREAD_CALLEES_CODE,
        message=(
            f"Asked once about {len(found.ranked)} unread callee(s) of the routines its claims "
            f"describe ({len(shown)} listed), the analyst read {len(read)} of those listed"
            + (f" ({', '.join(read)})" if read else "")
            + f" and left {len(shown) - len(read)} unread by its own choice."
        ),
        answered=True,
    )
    return record, answered
