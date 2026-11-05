"""The unread functions around the routines an analyst read, asked about once.

An analyst reading code stopped on its own with the routine that reads its
configuration file, the one that writes it and the cipher wrapper of its
channel unread: each was a callee of a routine it had read, and the function
map listed each as named and not read, a fact that asks for nothing. This
module turns that fact into one question before the analyst's answer stands:

* **Read** routines are the functions a code listing of the analyst lists
  (``function_callees.read_routines``). A listing asked for at an address
  inside a function, where the function index states the starts around it,
  reads the function that address falls in.
* **Unread** functions are the callees of read routines no listing of the
  analyst holds, from its own listings and the run's function index, and the
  functions on the path from where the code starts down to the routines it
  read that no listing holds.
* **The main path** is what the run's answers state starts the code: the
  entry point and the exports any declared format header answer states, the
  functions a function index answer states are started as threads (a loop
  such as a beacon runs in one) and its rows marked as entry points. Where
  none is stated, the read routines a claim calls an entry, main,
  dispatcher, beacon, start-up or command routine stand in for it (the
  address the claim writes nearest that word).
* **The rank** is a function's distance from the path: the calls between it
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
breadth-first walk each way, every lookup is a dict, a set or a bisection.
"""

from __future__ import annotations

import re
from bisect import bisect_right
from collections import deque
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from maljan.agents.function_callees import call_edges, read_routines
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
from maljan.core.agent_category import CODE_READER, OTHER, declared_category
from maljan.core.declared_reading import kind_of
from maljan.core.undeclared_tools import (
    declares_a_kind,
    entry_decompiles,
    entry_facts,
    entry_lists_any_code,
)
from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import (
    _BARE_ADDRESS,
    _HEX_ADDRESS,
    _SUFFIXED_ADDRESS,
    Violation,
    generic_function_name,
)

__all__ = [
    "CALLEES_SHOWN",
    "UNREAD_CALLEES_CODE",
    "CalleeToRead",
    "CalleesFound",
    "callees_asked_record",
    "callees_to_read",
    "reads_code",
    "states_why",
    "unread_callees_violation",
]

# An analyst reading code stopped on its own with the main-path callees of
# routines it read unread. Those functions, ranked by the main path, are
# listed to it, once per job, and it decides whether to read them.
UNREAD_CALLEES_CODE = "isr.callees_not_read"

# How many functions the question lists at most; the question says how many
# there are in all and that the others are left out.
CALLEES_SHOWN = 12

# The kind of answer that states a file's format header, whatever the format:
# its entry point and its exports start the code.
_HEADER_KIND = "format_info"

# How the question says where the code starts, by what the starts were read from.
STARTS_STATED = "the entry point, the exports and the thread starts the run's answers state"
STARTS_CLAIMED = (
    "the routines you read that your claims call an entry, main, dispatcher, beacon, "
    "start-up or command routine, since no answer states where the code starts"
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
    """One unread function, with what ranks it.

    ``callers`` are the read routines that call it (none for a function only
    on the path); ``on_path`` whether it lies on the path from a start down to
    a read routine; ``depth`` the calls between it and the nearest start
    (``None``: no start reaches it); ``called_from`` how many functions call
    it; ``calls`` how many it calls.
    """

    address: int
    callers: tuple[int, ...]
    depth: int | None
    start: int | None
    called_from: int
    calls: int
    on_path: bool = False

    def distance(self) -> int | None:
        """The rank: calls from the nearest start, plus one per further caller; ``None``: unreached."""
        if self.depth is None:
            return None
        return self.depth + max(0, self.called_from - 1)

    def reason(self) -> str:
        """Why it is listed, in the platform's words: addresses and counts."""
        said: list[str] = []
        if self.callers:
            callers = ", ".join(hex(c) for c in self.callers[:2])
            more = len(self.callers) - 2
            said.append(f"called by {callers}" + (f" and {more} more" if more > 0 else ""))
        if self.on_path:
            said.append("on the path from a start to routines you read")
        if self.depth is not None and self.start is not None:
            said.append(f"{self.depth} call(s) from the start {hex(self.start)}")
        else:
            said.append("no stated start reaches it")
        said.append(f"{self.called_from} caller(s); calls {self.calls}")
        return "; ".join(said)


# Why the question was not put, in the words the run's events and record say
# it. The first is a fact, not a gap: the analyst reads no code, and nothing
# is said. Every other one is what the platform could not tell, and is said.
NOT_RUN_NO_LISTING = (
    "no entry of this analyst lists code: no tool it called declares a decompile, "
    "disassembly or function-listing kind, and no tool that declares nothing is named as one"
)
NOT_RUN_NO_LISTING_UNDECLARED = (
    "no entry of this analyst lists code; {count} undeclared tool(s) it called ({tools}) "
    "answered, and neither a declared kind nor the tool's name says its answer is a code "
    "listing, so no routine it read is known"
)
NOT_RUN_NO_ROUTINE = (
    "its code listings name no function the platform can place: no address it was asked "
    "for, and no signature or batch key it could read"
)
NOT_RUN_NO_CALLS = (
    "neither its listings nor a function index state what the routines it read call, or the "
    "path from a start to them"
)
# Said for an analyst whose category is a code reader's when no entry of it
# lists code: it is meant to read code, so where none is known is a gap.
NOT_RUN_CODE_READER_NO_LISTING = (
    "it is in the code reader category, and no entry of it lists code: no tool it called "
    "declares a decompile, disassembly or function-listing kind, and no tool that declares "
    "nothing is named as one"
)
# Not said: the analyst's category is one that does not read code.
NOT_RUN_CATEGORY = "its category is not one that reads code"
# Said where the turn after the loop cannot carry the analyst's tools, so the
# question could not be answered with a read.
NOT_RUN_NO_TOOLS = "the turn after its loop carries no tools ({why}), so no function could be read"
# Said where the check raised.
NOT_RUN_FAILED = "the check could not run ({kind})"
# How many undeclared tools the not-run sentence names at most.
_TOOLS_NAMED = 5


@dataclass(frozen=True)
class CalleesFound:
    """The ranked functions, how the question says where the code starts, and why none.

    ``not_run`` is why the platform did not tell which functions are unread
    (one of the ``NOT_RUN_*`` sentences); ``""`` when it did, the list empty
    or not.
    """

    ranked: tuple[CalleeToRead, ...] = ()
    starts: str = STARTS_NONE
    not_run: str = ""

    def says_why(self) -> bool:
        """Whether its reason is one the run states (:func:`states_why`)."""
        return states_why(self.not_run)


def states_why(not_run: str) -> bool:
    """Whether a reason the question was not put is said: a gap, not a fact.

    "Reads no code" and "its category reads no code" are facts about the
    analyst, and nothing is said for them.
    """
    return bool(not_run) and not_run not in (NOT_RUN_NO_LISTING, NOT_RUN_CATEGORY)


def reads_code(
    definition: Any, ledger: Sequence[Any], declarations: Any = None
) -> tuple[bool, str]:
    """Whether an analyst reads code, and, when it does not, why: the one place that decides.

    By the category its definition declares first (``core.agent_category``):
    a code reader reads code, and where none of its entries lists any that is
    said; a category that does not read code is not asked, and nothing is
    said. For ``other`` and for a definition that declares none, from the
    ledger: an entry whose tool declares a decompile, disassembly or
    function-listing kind (the declaration each entry stored), or, for a tool
    that declares nothing, whose name says it is one, exactly as before the
    category existed. Neither the analyst's name nor a tool's or a server's
    name is read. ``declarations`` is taken so that a reading keyed on them
    can stand in front of the ledger's; it is not read yet.
    """
    del declarations
    category = declared_category(definition)
    if category not in (None, OTHER, CODE_READER):
        return False, NOT_RUN_CATEGORY
    if any(entry_decompiles(e) or entry_lists_any_code(e) for e in ledger):
        return True, ""
    why = _no_listing(ledger)
    if category == CODE_READER and why == NOT_RUN_NO_LISTING:
        return False, NOT_RUN_CODE_READER_NO_LISTING
    return False, why


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


def _written_at(text: str) -> list[tuple[int, int]]:
    """Every address ``text`` writes, in the forms the map reads, with where it is written."""
    return [
        (match.start(), int(match.group(1), 16))
        for pattern in (_HEX_ADDRESS, generic_function_name(), _SUFFIXED_ADDRESS, _BARE_ADDRESS)
        for match in pattern.finditer(text)
    ]


def _int_of(value: Any) -> int | None:
    """An address a header states: an integer, or hex text."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value if value > 0 else None
    return _hex(value)


def _stated_starts(entries: Iterable[Any], bases: Sequence[int]) -> list[int]:
    """The starts the run's answers state: entry point, exports, thread starts, entry rows."""
    starts: dict[int, None] = {}
    for entry in entries:
        if getattr(entry, "ok", True) is False:
            continue
        data = _parsed(entry)
        if not isinstance(data, Mapping):
            continue
        if _is_header(entry):
            point = _int_of(data.get("entry_point"))
            if point is not None:
                starts[one_spelling(point, bases)] = None
            for row in data.get("export_rows") or []:
                rva = _int_of(row.get("rva")) if isinstance(row, Mapping) else None
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


def _reaching(callers_of: Mapping[int, Iterable[int]], targets: Iterable[int]) -> set[int]:
    """Every function from which one of ``targets`` is reached by calls, one walk back."""
    seen = set(targets)
    queue = deque(sorted(seen))
    while queue:
        at = queue.popleft()
        for caller in callers_of.get(at, ()):
            if caller not in seen:
                seen.add(caller)
                queue.append(caller)
    return seen


@dataclass
class _Reading:
    """What the analyst's entries and the pack state of the code, read once."""

    context: list[Any]
    bases: tuple[int, ...]
    graph: dict[int, dict[int, None]]
    callers_of: dict[int, set[int]]
    read: dict[int, list[str]]


def _reading(entries: Sequence[Any], pack: Sequence[Any]) -> _Reading:
    """The call graph, one spelling per function, and the routines read, placed in it."""
    context = _context(pack)
    every = [*context, *entries]
    mapped = build_function_map(every, None, ())
    bases = tuple(mapped.image_bases)
    edges = call_edges(every)
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
    known = {*graph, *callers_of}
    # The function starts the index's own rows state: a function no row is
    # (a leaf no call was stated for) is never one an address is placed in.
    starts = sorted(_index_starts(every, bases))
    # A decompiled listing names its own function; an instruction listing is
    # of the address it was asked for, which may stand inside one.
    decompiled = {str(getattr(e, "id", "") or "") for e in entries if entry_decompiles(e)}
    read: dict[int, list[str]] = {}
    for address, listed in read_routines(every, mapped, edges).items():
        key = _held_in(address, known, bases)
        if key is None and starts and not decompiled.issuperset(listed):
            # An address inside a function: the function whose start is the
            # last one the index states before it, where a later start bounds it.
            at = bisect_right(starts, address)
            key = starts[at - 1] if 0 < at < len(starts) else None
        key = address if key is None else key
        held_listed = read.setdefault(key, [])
        held_listed.extend(e for e in listed if e not in held_listed)
    return _Reading(context, bases, graph, callers_of, read)


def _index_starts(entries: Iterable[Any], bases: Sequence[int]) -> set[int]:
    """The function starts the function index answers state as their rows."""
    out: set[int] = set()
    for entry in entries:
        data = _parsed(entry) if _map_kind(entry) == _INDEX_KIND else None
        rows = data.get("rows") if isinstance(data, Mapping) else None
        for row in rows if isinstance(rows, list) else ():
            if isinstance(row, Mapping):
                function = _hex(row.get("function")) or _hex(row.get("offset"))
                if function is not None:
                    out.add(one_spelling(function, bases))
    return out


def callees_to_read(
    claims: Iterable[Any],
    entries: Sequence[Any],
    pack: Sequence[Any] = (),
    definition: Any = None,
) -> CalleesFound:
    """The unread functions around the routines the analyst read, ranked by the main path.

    ``entries`` are the analyst's own ledger entries, ``pack`` the triage
    pack's: its function index adds the calls the analyst's listings do not
    state and the threads it starts, its format header the entry point and
    exports. ``claims`` give the starts only where no answer states one.
    ``definition`` is the analyst's, handed to :func:`reads_code`. Empty when
    the analyst reads no code, and when every function around what it read is
    read.
    """
    own = list(entries)
    code, why = reads_code(definition, own)
    if not code:
        return CalleesFound(not_run=why)
    found = _reading(own, pack)
    read, graph, bases = found.read, found.graph, found.bases
    if not read:
        return CalleesFound(not_run=NOT_RUN_NO_ROUTINE)
    starts = _stated_starts([*found.context, *own], bases)
    said_starts = STARTS_STATED
    if not starts:
        starts = sorted(_claimed_starts(claims, read, bases))
        said_starts = STARTS_CLAIMED if starts else STARTS_NONE
    depths = _depths(graph, starts)
    # The functions on the path from a start down to a routine read: reached
    # from a start, and reaching a routine read.
    path = (
        {n for n in _reaching(found.callers_of, read) if n in depths and n not in read}
        if starts
        else set()
    )
    callers: dict[int, list[int]] = {}
    for routine in read:
        for callee in graph.get(routine, ()):
            if callee not in read:
                callers.setdefault(callee, []).append(routine)
    if not callers and not path:
        stated = any(graph.get(r) for r in read)
        return CalleesFound(starts=said_starts, not_run="" if stated else NOT_RUN_NO_CALLS)
    out: list[CalleeToRead] = []
    for address in {*callers, *path}:
        depth, start = depths.get(address, (None, None))
        out.append(
            CalleeToRead(
                address=address,
                callers=tuple(sorted(callers.get(address, ()))),
                depth=depth,
                start=start,
                called_from=len(found.callers_of.get(address, ())),
                calls=len(graph.get(address, ())),
                on_path=address in path,
            )
        )
    out.sort(key=lambda c: (c.distance() is None, c.distance() or 0, -c.calls, c.address))
    return CalleesFound(tuple(out), said_starts)


def _claimed_starts(
    claims: Iterable[Any], read: Mapping[int, Any], bases: Sequence[int]
) -> set[int]:
    """The read routines a claim calls central: per word, the read address written nearest it."""
    out: set[int] = set()
    for claim in claims:
        sentence = str(getattr(claim, "claim", "") or "")
        words = [m.start() for m in _CENTRAL_WORDS.finditer(sentence)]
        if not words:
            continue
        written = [
            (place, key)
            for place, address in _written_at(sentence)
            if (key := _held_in(address, read, bases)) is not None
        ]
        for word in words:
            if written:
                out.add(min(written, key=lambda w: (abs(w[0] - word), w[0]))[1])
    return out


def _is_header(entry: Any) -> bool:
    return kind_of(entry) == _HEADER_KIND


def _context(pack: Sequence[Any]) -> list[Any]:
    """The pack's entries the question reads: its function index and its format header."""
    return [e for e in pack if _map_kind(e) == _INDEX_KIND or _is_header(e)]


def _held_in(address: int, keys: Iterable[int], bases: Sequence[int]) -> int | None:
    """The key of ``keys`` that is ``address``'s function by the map's rule, or ``None``."""
    for key in address_spellings(address, bases):
        if key in keys and same_function(key, address, bases):
            return key
    return None


def unread_callees_violation(found: CalleesFound) -> Violation | None:
    """The one question about ``found``, or ``None`` when there is none.

    At most :data:`CALLEES_SHOWN` are listed, in rank order; the question
    says how many there are and that the rest are not listed. It asks
    whether to read them and forces nothing, so it is advisory: a question
    never answered is no finding left unfixed.
    """
    ranked = found.ranked
    if not ranked:
        return None
    shown = ranked[:CALLEES_SHOWN]
    left = len(ranked) - len(shown)
    # Each item is the platform's own words (addresses and counts), held to
    # the row rule all the same, item by item, so a bound cuts one reason and
    # never the list.
    listed = "; ".join(safe_finding_value(f"{hex(c.address)} ({c.reason()})") for c in shown)
    bound = (
        f" The first {len(shown)} of {len(ranked)} are listed (the question lists at most "
        f"{CALLEES_SHOWN}); the other {left} are not."
        if left
        else ""
    )
    return Violation(
        code=UNREAD_CALLEES_CODE,
        message=(
            f"{len(ranked)} function(s) around the routines you read have code none of your "
            "listings holds: callees of those routines, and functions on the path from where "
            "the code starts down to them. Where the code starts: "
            f"{safe_finding_value(found.starts)}. Ranked by "
            "distance from those starts (the calls between, plus one for each further "
            "function calling it, since a routine called from many places is a shared "
            f"helper): {listed}.{bound} Decide whether any matters to this analysis: you may "
            "read any of them with your tools and add or change claims for what their code "
            "does, citing the entries that list it, or leave them unread and change "
            "nothing. This is asked once."
        ),
        advisory=True,
    )


def callees_asked_record(
    found: CalleesFound, now: Sequence[Any], pack: Sequence[Any] = ()
) -> tuple[dict[str, Any], Violation | None]:
    """What became of the question: the loop's record and the run's answered row.

    ``found`` is what the question was put about; ``now`` the entries after
    the analyst answered. Of the functions listed, the ones a listing in
    ``now`` holds were read since. ``({}, None)`` when none was listed.
    """
    if not found.ranked:
        return {}, None
    shown = found.ranked[:CALLEES_SHOWN]
    reading = _reading(now, pack)
    read = [
        hex(c.address)
        for c in shown
        if _held_in(c.address, reading.read, reading.bases) is not None
    ]
    record: dict[str, Any] = {
        "listed": len(found.ranked),
        "shown": [hex(c.address) for c in shown],
        "shown_at_most": CALLEES_SHOWN,
        "read_after": read,
    }
    left_unread = len(shown) - len(read)
    answered = Violation(
        code=UNREAD_CALLEES_CODE,
        message=(
            f"Asked once about {len(found.ranked)} unread function(s) around the routines it "
            f"read ({len(shown)} listed), the analyst read {len(read)} of those listed "
            f"({', '.join(safe_finding_value(a) for a in read) or 'none'}) and left "
            f"{left_unread} unread by its own choice."
        ),
        answered=True,
    )
    return record, answered
