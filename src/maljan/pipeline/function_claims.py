"""A function claim checked against the function's own facts.

A claim whose cited evidence is the listing of a function the analyst's own
calls decompiled or disassembled (``validation.decompiled_functions``, and a
disassembly call given the function's address) names calls and strings for
that function. The platform reads the Windows function names and the quoted
string values the claim's own sentence names, leaving out a name inside a
statement of absence ("does not use X"), and looks for each, in this order:

1. the listing's own text;
2. the function's row in the triage pack's function index
   (``tools.artefact_index``): the imports it calls, its calls through slots
   the hash resolution fills, the names its hashes resolve to, the decoded
   and plain strings it refers to and the capa rules matched in it;
3. the rows of every function reachable from it through call edges, a
   breadth-first walk over the index's whole call graph with no depth bound,
   read once per set of starting functions; a routine passed as an argument (a
   thread's start, a callback) is no call edge and is not followed;
4. the places the run's hash-resolution and decoded-string answers put inside
   any of those functions (``agents.function_map.function_artefacts``).

A value any of them holds holds; nothing else excuses one. A value is the
cited function's only where the claim gives it to it: the function the claim
names last before the value in its sentence, or, in a claim that names no
function at all, the cited one; any other value is recorded with why. API names are
compared without regard to case, a module written in front
(``kernel32.dll!Name``) read off, and the ANSI and wide spellings read as one
name, as the API catalogue compares them
(``analysis.api_capability_db.canonical_name``); strings by the citation
check's own whole-value reading (``EntryTexts``). A quoted value is read as a
claimed string only when it is a sample string some entry holds as data: a
strings tool's answer, FLOSS's, the blob decoder's, or the index's rows.

A value none of them holds is stated to the analyst, once, through the
validation turn every other question goes through: the claim, the function
and its entries, the index row, how many functions are reachable from it,
and what the function's row does hold, in the pack's own words for it. The
analyst keeps, corrects or withdraws the claim; nothing is edited or dropped
here.

Whatever is not checked is recorded with why, ``no: <reason>``: no index in
the run, an index answer not kept whole, a function the index does not know,
a row the pack the analyst was shown left out, a reachable function the
decoder stopped in, a quoted value no strings source holds, and, for an API
name, a reachable function whose calls the index cannot all name (a call
through a register no load names, an indirect jump, or a slot nothing names,
may be the call the claim names; one through a slot the hash resolution fills
is named in the row).

Linear in the claims, the index rows and the listings' size, and per claim in
the call graph: the rows are keyed by offset once, each listing and each row
is read into its names and its text once, the names a sentence may name are
gathered once, and each claim walks the graph once.
"""

from __future__ import annotations

import re
from collections import deque
from collections.abc import Collection, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import (
    _ADDRESS_ARGUMENTS,
    _BARE_ADDRESS,
    _CODE_SPAN_RE,
    _GENERIC_FUNCTION_NAME,
    _HEX_ADDRESS,
    _NAME_ARGUMENTS,
    _NEGATION_WINDOW,
    _QUOTED_SPAN_RE,
    _SUFFIXED_ADDRESS,
    FUNCTION_CLAIM_UNHELD,
    FUNCTION_QUESTION_ASK,
    DecompiledFunction,
    EntryTexts,
    _address_value,
    _is_negated,
    _named_by,
    claim_block_indexes,
    decidable,
    decompiled_functions,
    literal_values,
)
from maljan.schemas.evidence import answer_not_shown, entry_ids_in

__all__ = [
    "FUNCTION_CLAIM_UNHELD_CODE",
    "FunctionClaimCheck",
    "FunctionFacts",
    "check_function_claims",
    "facts_unread",
    "function_facts",
    "listed_functions",
]

# A claim naming a call or a string for a function whose own facts hold none.
FUNCTION_CLAIM_UNHELD_CODE = FUNCTION_CLAIM_UNHELD

# Why a fact is absent, as the run record says it.
NO_INDEX = "no: the run holds no function index"
NOT_KNOWN = "no: the function index does not know the function at {address}"
NO_ADDRESS = "no: the listing of {name} gives no address the index can be read by"
ROW_NOT_SHOWN = (
    "no: the function index row of {address} is not in the pack the analyst was shown (pack room)"
)
INDEX_CUT = "no: [{entry}] the function index answer the analyst read was cut"
UNDECODED = (
    "no: the decoder stopped in {address} or a function reachable from it, so its calls are "
    "not whole"
)
UNDECODED_UNKNOWN = (
    "no: [{entry}] the function index does not say which functions the decoder stopped in"
)
UNNAMED_CALLS = (
    "no: {address} or a function reachable from it makes calls the index cannot name (through "
    "a register no load names, an indirect jump, or a slot nothing names), so an API name "
    "none of them holds may be one of them"
)
UNNAMED_UNKNOWN = "no: [{entry}] the function index does not count the calls that name nothing"
CALLEES_UNKNOWN = (
    "no: [{entry}] the function index lists no callees for the functions that hold no "
    "artefact of their own, so the functions reachable from {address} are not all known"
)
NOT_A_SAMPLE_STRING = (
    'no: "{value}" is no string a strings tool, FLOSS, the blob decoder or the function index holds'
)
FACTS_UNREAD = "no: the function facts could not be read ({kind})"
# What the reach does not follow, said with every question.
NOT_FOLLOWED = (
    "routines passed as arguments (a thread's start, a callback) are not followed, only calls"
)
UNATTRIBUTED = (
    'no: "{value}" is given to no function the claim names: {where}, so it is not read as '
    "any function's"
)
BEFORE_ANY_NAME = "the value comes before any function its sentence names"
NO_NAME_IN_ITS_SENTENCE = "the value's sentence names no function"
GIVEN_ELSEWHERE = (
    'no: the claim gives "{value}" to {address}, which no function whose listing it cites '
    "reaches through its callees"
)

# A Windows function name as written in running text, a module in front read off.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A quoted value inside a code span: the span holds the quotes too.
_QUOTED_INSIDE = re.compile(r'"([^"\n]+)"|\'([^\'\n]+)\'|“([^”\n]+)”')
# A JSON escape a value may be written with; a value of escapes and marks alone
# spells no letter or digit, and no text can be said to hold or lack it.
_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|.)")

_CATALOGUE_LOWER: frozenset[str] | None = None


def facts_unread(exc: BaseException) -> str:
    """The run record's reason when the facts or the check failed: the exception's type only."""
    return FACTS_UNREAD.format(kind=type(exc).__name__)


def _api_key(name: str) -> str:
    from maljan.analysis.api_capability_db import canonical_name

    return canonical_name(name)


def _catalogue_lower() -> frozenset[str]:
    """The vendored export-name catalogue, lower-cased; empty when it cannot be read."""
    global _CATALOGUE_LOWER
    if _CATALOGUE_LOWER is None:
        from maljan.pipeline.events import _catalogue_names

        _CATALOGUE_LOWER = frozenset(name.lower() for name in _catalogue_names())
    return _CATALOGUE_LOWER


def _is_a_name(token: str, names: frozenset[str] | set[str]) -> bool:
    """Whether ``token`` is one of ``names`` without regard to case, or its ANSI or wide
    spelling is, or it is the name both of those spell (``CreateProcess``)."""
    lowered = token.lower()
    forms = {lowered, f"{lowered}a", f"{lowered}w"}
    if lowered.endswith(("a", "w")):
        forms |= {f"{lowered[:-1]}a", f"{lowered[:-1]}w"}
    return bool(forms & names)


def _names_in(text: str) -> set[str]:
    """The API keys of every identifier ``text`` writes."""
    return {_api_key(token) for token in _IDENTIFIER.findall(str(text or "")) if len(token) >= 3}


def _is_a_strings_source(tool: str) -> bool:
    """Whether an entry's tool answers with the sample's strings as data."""
    lowered = tool.lower()
    return "string" in lowered or "floss" in lowered


# ---------------------------------------------------------------------------
# The functions a claim may be about
# ---------------------------------------------------------------------------


def listed_functions(entries: Iterable[Any]) -> list[DecompiledFunction]:
    """The functions these ledger entries list: every decompile, then every disassembly
    of a whole function given its address or name, joined by address.

    A decompile is read as ``validation.decompiled_functions`` reads it. A
    disassembly counts when its tool's name says it disassembles a function,
    it answered, the model read the answer and it is no repeat.
    """
    entries = list(entries)
    found: dict[Any, DecompiledFunction] = {}
    for function in decompiled_functions(entries):
        found[function.address if function.address is not None else function.names[0]] = function
    for entry in entries:
        tool = str(getattr(entry, "tool", "") or "").lower()
        if "disassembl" not in tool or "function" not in tool:
            continue
        if not getattr(entry, "ok", True) or answer_not_shown(entry):
            continue
        if getattr(entry, "repeated_of", None):
            continue
        args = getattr(entry, "args", None) or {}
        address: int | None = None
        for argument in _ADDRESS_ARGUMENTS:
            if argument in args and address is None:
                address = _address_value(args[argument])
        names = [
            str(args.get(argument) or "").strip()
            for argument in _NAME_ARGUMENTS
            if str(args.get(argument) or "").strip()
        ]
        if address is None:
            for name in names:
                generic = _GENERIC_FUNCTION_NAME.fullmatch(name)
                if generic is not None:
                    address = int(generic.group(1), 16)
                    break
        if address is None and not names:
            continue
        key: Any = address if address is not None else names[0]
        entry_id = str(getattr(entry, "id", "") or "")
        known = found.get(key)
        found[key] = DecompiledFunction(
            address=address,
            names=tuple(dict.fromkeys([*(known.names if known else ()), *names])),
            entries=tuple(
                dict.fromkeys(
                    [*(known.entries if known else ()), *([entry_id] if entry_id else [])]
                )
            ),
        )
    return list(found.values())


# ---------------------------------------------------------------------------
# The facts, read once per run
# ---------------------------------------------------------------------------


def _hex(value: Any) -> int | None:
    match = re.fullmatch(r"\s*0x([0-9a-fA-F]{1,16})\s*", str(value or ""))
    return int(match.group(1), 16) if match else None


@dataclass
class _Held:
    """What one source holds: its API keys, and its text for strings, lower-cased."""

    names: set[str] = field(default_factory=set)
    texts: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class _Reach:
    """What the functions reachable from one set of starts hold, read once per set."""

    functions: frozenset[int]
    whole: bool
    stopped: bool
    unnamed: bool
    names: frozenset[str]
    texts: frozenset[str]


@dataclass
class FunctionFacts:
    """The facts a function claim is checked against, read once for an answer's checks.

    ``absent`` is the run-wide ``no: <reason>`` when there is no whole index.
    """

    absent: str = ""
    index_entry: str = ""
    base: int = 0
    bases: tuple[int, ...] = ()
    rows: dict[int, Mapping[str, Any]] = field(default_factory=dict)
    known: set[int] = field(default_factory=set)
    # The call graph by offset: each row's callees and, when the index lists
    # them, the callees of the functions that are no row.
    edges: dict[int, list[int]] = field(default_factory=dict)
    graph_whole: bool = False
    unnamed: dict[int, int] | None = None
    undecoded: set[int] | None = None
    shown: set[int] | None = None
    held_by_row: dict[int, _Held] = field(default_factory=dict)
    placed: dict[int, _Held] = field(default_factory=dict)
    # The names a sentence may name: the catalogue's and this run's, lower-cased.
    known_names: frozenset[str] = frozenset()
    listings: dict[str, _Held] = field(default_factory=dict)
    # The sample strings as data: the strings tools' answers, FLOSS's, the blob
    # decoder's, and the index rows' strings.
    strings: EntryTexts = field(default_factory=EntryTexts)
    # The index rows' strings, each whole, lower-cased.
    index_strings: frozenset[str] = frozenset()
    # Each distinct set of starts' reach, read once.
    reaches: dict[frozenset[int], _Reach] = field(default_factory=dict)

    def reach(self, starts: Sequence[int]) -> _Reach:
        """The reach of ``starts`` and what its functions hold, memoised per set."""
        key = frozenset(starts)
        found = self.reaches.get(key)
        if found is None:
            functions, whole = self.reachable(starts)
            names: set[str] = set()
            texts: set[str] = set()
            for at in functions:
                for held in (self.held_by_row.get(at), self.placed.get(at)):
                    if held is not None:
                        names |= held.names
                        texts.update(held.texts)
            found = _Reach(
                functions=frozenset(functions),
                whole=whole,
                stopped=any(at in (self.undecoded or ()) for at in functions),
                unnamed=any((self.unnamed or {}).get(at) for at in functions),
                names=frozenset(names),
                texts=frozenset(texts),
            )
            self.reaches[key] = found
        return found

    def offset(self, address: int | None) -> int | None:
        """The index offset of a function an answer gave by address, or ``None``."""
        if address is None:
            return None
        if address in self.known:
            return address
        for base in self.bases:
            if address >= base and address - base in self.known:
                return address - base
        return None

    def va(self, offset: int) -> str:
        return hex(self.base + offset)

    def reachable(self, starts: Iterable[int]) -> tuple[list[int], bool]:
        """Every function reachable from ``starts`` through callee edges, breadth first,
        and whether every one reached has its callees known."""
        seen = dict.fromkeys(starts)
        queue = deque(seen)
        whole = True
        while queue:
            at = queue.popleft()
            if at not in self.rows and not self.graph_whole:
                whole = False
            for callee in self.edges.get(at, ()):
                if callee not in seen:
                    seen[callee] = None
                    queue.append(callee)
        return list(seen), whole


def _row_held(row: Mapping[str, Any]) -> _Held:
    held = _Held()
    for key in ("imports", "slot_calls", "resolved"):
        for cell in row.get(key) or []:
            if isinstance(cell, Mapping) and cell.get("name"):
                held.names.add(_api_key(str(cell["name"]).rpartition("!")[2]))
                held.texts.append(str(cell["name"]).lower())
    for key, field_name in (
        ("decoded_strings", "text"),
        ("plain_strings", "text"),
        ("capa", "rule"),
    ):
        for cell in row.get(key) or []:
            if isinstance(cell, Mapping) and cell.get(field_name):
                held.texts.append(str(cell[field_name]).lower())
    return held


def _row_strings(row: Mapping[str, Any]) -> list[str]:
    return [
        str(cell["text"])
        for key in ("decoded_strings", "plain_strings")
        for cell in row.get(key) or []
        if isinstance(cell, Mapping) and cell.get("text")
    ]


def function_facts(
    entries: Sequence[Any],
    artefacts: Any,
    *,
    pack_entries: Sequence[Any] = (),
    facts_block: str = "",
    bases: Sequence[int] = (),
) -> FunctionFacts:
    """What the function claims of an answer are checked against.

    ``entries`` are the analyst's own ledger entries, ``artefacts`` the pack's
    ``FunctionArtefacts`` (``nodes.pack_function_artefacts``), ``pack_entries``
    the pack's entries (their strings sources are read), ``facts_block`` the
    pack text the analyst was shown (a row it left out is not checked against)
    and ``bases`` the image bases the run read.
    """
    from maljan.agents.function_map import function_artefacts, merged_artefacts
    from maljan.tools.artefact_index import row_line

    found = merged_artefacts(artefacts, function_artefacts(entries))
    facts = FunctionFacts()
    run_names: set[str] = set()
    sources = [
        entry
        for entry in [*pack_entries, *entries]
        if _is_a_strings_source(str(getattr(entry, "tool", "") or ""))
    ]
    for entry in entries:
        tool = str(getattr(entry, "tool", "") or "").lower()
        if "decompil" not in tool and "disassembl" not in tool:
            continue
        entry_id = str(getattr(entry, "id", "") or "")
        output = str(getattr(entry, "output", "") or "")
        if entry_id and output:
            facts.listings[entry_id.lower()] = _Held(_names_in(output), [output.lower()])
    data = getattr(found, "index_data", None)
    if not isinstance(data, Mapping):
        facts.strings = EntryTexts.from_ledger(sources)
        facts.known_names = _catalogue_lower()
        facts.absent = str(getattr(found, "index_unread", "") or "") or NO_INDEX
        return facts
    facts.index_entry = str(getattr(found, "index_entry", "") or "")
    if getattr(found, "index_cut", False):
        facts.strings = EntryTexts.from_ledger(sources)
        facts.known_names = _catalogue_lower()
        facts.absent = INDEX_CUT.format(entry=facts.index_entry)
        return facts
    facts.base = _hex(data.get("image_base")) or 0
    facts.bases = tuple(
        dict.fromkeys(
            [
                *([facts.base] if facts.base else []),
                *bases,
                *(getattr(found, "image_bases", None) or ()),
            ]
        )
    )

    def offset_of(value: Any) -> int | None:
        address = _hex(value)
        if address is None:
            return None
        return address - facts.base if facts.base and address >= facts.base else address

    index_strings: list[str] = []
    for row in data.get("rows") or []:
        if not isinstance(row, Mapping):
            continue
        start = _hex(row.get("offset"))
        if start is None:
            continue
        facts.rows[start] = row
        facts.known.add(start)
        facts.held_by_row[start] = _row_held(row)
        index_strings.extend(_row_strings(row))
        run_names |= {
            str(cell.get("name")).rpartition("!")[2].lower()
            for key in ("imports", "slot_calls", "resolved")
            for cell in row.get(key) or []
            if isinstance(cell, Mapping) and cell.get("name")
        }
        listed = [o for o in map(offset_of, row.get("callees") or []) if o is not None]
        facts.edges[start] = listed
        facts.known.update(listed)
        for caller in map(offset_of, row.get("callers") or []):
            if caller is not None:
                facts.known.add(caller)
    others = data.get("other_callees")
    if isinstance(others, Mapping):
        facts.graph_whole = True
        for address, callees in others.items():
            start = offset_of(address)
            if start is None or start in facts.rows:
                continue
            listed = [o for o in map(offset_of, callees or []) if o is not None]
            facts.edges[start] = listed
            facts.known.add(start)
            facts.known.update(listed)
    unnamed = data.get("calls_unnamed")
    if isinstance(unnamed, Mapping):
        facts.unnamed = {}
        for address, count in unnamed.items():
            start = offset_of(address)
            if start is not None:
                facts.unnamed[start] = int(count or 0)
                facts.known.add(start)
    undecoded = data.get("undecoded")
    if isinstance(undecoded, list):
        facts.undecoded = {o for o in map(offset_of, undecoded) if o is not None}
        facts.known |= facts.undecoded
    elif not int(data.get("undecoded_functions") or 0):
        facts.undecoded = set()
    if facts_block.strip():
        lines = set(facts_block.splitlines())
        facts.shown = {
            start for start, row in facts.rows.items() if row_line(row, facts.index_entry) in lines
        }
    for address, tied in (getattr(found, "by_function", None) or {}).items():
        start = facts.offset(address)
        if start is None:
            continue
        held = facts.placed.setdefault(start, _Held())
        for artefact in tied:
            value = str(getattr(artefact, "value", "") or "")
            if getattr(artefact, "kind", "") == "name":
                held.names.add(_api_key(value))
                run_names.add(value.lower())
            elif getattr(artefact, "kind", "") in ("text", "decoded"):
                held.texts.append(value.lower())
    strings = EntryTexts.from_ledger(sources)
    facts.index_strings = frozenset(text.lower() for text in index_strings)
    facts.strings = strings
    facts.known_names = _catalogue_lower() | frozenset(run_names)
    return facts


# ---------------------------------------------------------------------------
# What a claim names
# ---------------------------------------------------------------------------


def _named_alone(spans: Collection[str], token: str) -> bool:
    """Whether a code span holds ``token`` alone, or called with nothing in its parentheses:
    a span that is an expression (``(rand%9)``) writes pseudo-code, not a name."""
    return token in spans or f"{token}()" in spans


# Where one sentence of a claim ends and the next begins: a sentence's end or a
# line break. A dot inside a token or a number (``fcn.0x88f8``, ``kernel32.dll``,
# ``1.2``) ends nothing, nor does an abbreviation's (``e.g.``, ``i.e.``,
# ``etc.``); a semicolon, a colon or a dash keeps its sentence's subject.
_CLAUSE_END = re.compile(r"[.!?](?=\s|$)|\n")
_ABBREVIATIONS = frozenset({"e.g", "i.e", "etc", "cf", "vs", "viz", "approx", "resp"})
# The farthest back a dot's word is read: the longest abbreviation. A longer run
# of letters and dots before a dot is no abbreviation.
_ABBREVIATION_REACH = max(len(word) for word in _ABBREVIATIONS)
_WORD_OR_DOT = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.")


def _abbreviation_before(text: str, dot: int) -> bool:
    """Whether the run of letters and dots right before ``text[dot]`` is an abbreviation.

    Walked back from the dot over at most ``_ABBREVIATION_REACH`` characters,
    so a text of dots costs each dot that many steps, not its whole prefix.
    """
    begin = dot
    floor = max(dot - _ABBREVIATION_REACH, 0)
    while begin > floor and text[begin - 1] in _WORD_OR_DOT:
        begin -= 1
    if begin == floor and begin > 0 and text[begin - 1] in _WORD_OR_DOT:
        return False
    return text[begin:dot].lower().strip(".") in _ABBREVIATIONS


def _clause_starts(text: str) -> list[int]:
    """Where each sentence of ``text`` begins, in order (``_CLAUSE_END``)."""
    starts = [0]
    for match in _CLAUSE_END.finditer(text):
        if match.group(0) == "." and _abbreviation_before(text, match.start()):
            continue
        starts.append(match.end())
    return starts


def _negation_window(text: str, starts: Sequence[int], begin: int, end: int) -> tuple[str, int]:
    """``(the text a statement of absence over text[begin:end] is read in, where it begins)``.

    The value's own sentence, cut to ``_NEGATION_WINDOW`` characters before
    the value (as far back as ``_is_negated`` reads a cue) and as many after
    it (the absence predicate its helpers read after a value, "functionality
    remains not established" at its longest, fits in them), so each value
    costs a window, not its whole sentence.
    """
    from bisect import bisect_right

    k = bisect_right(starts, begin) - 1
    stop = starts[k + 1] if k + 1 < len(starts) else len(text)
    low = max(starts[k], begin - _NEGATION_WINDOW)
    high = min(stop, end + _NEGATION_WINDOW)
    return text[low:high], low


def _named_at(text: str, names: frozenset[str] | set[str]) -> list[tuple[str, int, bool]]:
    """``(value, where, is an API name)`` of every name and string a sentence claims.

    Each name is read once, at its first place: whether a statement of absence
    holds it is asked there, within a window of the sentence that holds it
    (``_negation_window``).
    """
    spans = {m.group(0).strip("`").strip() for m in _CODE_SPAN_RE.finditer(text)}
    starts = _clause_starts(text)

    def negated(begin: int, end: int) -> bool:
        window, offset = _negation_window(text, starts, begin, end)
        return _is_negated(window, begin - offset, end - offset)

    found: list[tuple[str, int, bool]] = []
    seen: set[str] = set()
    for match in _IDENTIFIER.finditer(text):
        token = match.group(0)
        if token in seen or len(token) < 3 or _GENERIC_FUNCTION_NAME.fullmatch(token):
            continue
        if not _is_a_name(token, names):
            continue
        if not (re.search(r"[A-Z]", token[1:]) or _named_alone(spans, token)):
            continue
        seen.add(token)
        if not negated(match.start(), match.end()):
            found.append((token, match.start(), True))
    keys = {_api_key(value) for value, _at, _api in found}
    for match in _QUOTED_SPAN_RE.finditer(text):
        if match.group(1) is not None:
            inner = _QUOTED_INSIDE.fullmatch(match.group(1).strip())
            if inner is None:
                continue
            value = next(g for g in inner.groups() if g is not None)
        else:
            value = next(g for g in match.groups()[1:] if g is not None)
        value = value.strip()
        if (
            value in seen
            or len(value) < 3
            or not re.search(r"[A-Za-z0-9]", _ESCAPE.sub("", value))
            or not decidable(value)
            or _api_key(value) in keys
            or _GENERIC_FUNCTION_NAME.fullmatch(value)
            or entry_ids_in(value)
        ):
            continue
        seen.add(value)
        if not negated(match.start(), match.end()):
            found.append((value, match.start(), False))
    for value in literal_values(text):
        if value in seen:
            continue
        seen.add(value)
        at = max(text.find(value), 0)
        if not negated(at, at + len(value)):
            found.append((value, at, False))
    return found


def named_values(
    text: str, known: frozenset[str] | set[str] | None = None
) -> tuple[list[str], list[str]]:
    """``(API names, string values)`` a claim's sentence names, once each, in order.

    An API name is an identifier ``known`` holds (the export catalogue and this
    run's own names; the catalogue alone with none given), written with a
    capital after its first letter, or alone in a code span (``send``,
    ``send()``), so neither a word of running text nor a name inside a span's
    expression is read as one. A string is a value written in double, single
    or typographic quotes, or a code span that holds such a quoted value, of
    three characters or more, that a text can be said to hold
    (``validation.decidable``); and an unquoted value whose shape makes it one
    (``validation.literal_values``). A name or a value inside a statement of
    absence (``validation._is_negated``: "does not use X") is no claimed one.
    """
    found = _named_at(str(text or ""), known if known is not None else _catalogue_lower())
    return (
        [value for value, _at, api in found if api],
        [value for value, _at, api in found if not api],
    )


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


@dataclass
class FunctionClaimCheck:
    """What the check found in one answer.

    ``flagged`` are the claim indexes asked about, ``checked`` the claim
    blocks whose functions' facts were read, and ``not_checked`` each value or
    claim no fact could be stated for, ``claim <n>: no: <reason>``.
    """

    violations: list[Any] = field(default_factory=list)
    flagged: list[int] = field(default_factory=list)
    checked: int = 0
    asked: int = 0
    not_checked: list[str] = field(default_factory=list)

    def record(self) -> dict[str, Any]:
        """The run record's row for this answer."""
        return {
            "checked": self.checked,
            "asked": self.asked,
            **({"not_checked": list(self.not_checked)} if self.not_checked else {}),
        }


def _held(value: str, api: bool, listings: Sequence[_Held], reached: _Reach) -> bool:
    """Whether the listings or the reachable functions' facts hold ``value``.

    The facts are looked up by membership: an API key in their names, a string
    as one of their whole texts. Only a listing's text is searched, for the
    value as a whole value inside it.
    """
    from maljan.agents._indicator_denylists import whole_value_in
    from maljan.utils.written_forms import written_forms

    if api:
        key = _api_key(value)
        return key in reached.names or any(key in listing.names for listing in listings)
    forms = written_forms(value.lower())
    if any(form in reached.texts for form in forms):
        return True
    return any(
        whole_value_in(form, text)
        for listing in listings
        for text in listing.texts
        for form in forms
    )


def _a_sample_string(value: str, facts: FunctionFacts) -> bool:
    """Whether a strings source of the run holds ``value`` as data: one of the index rows'
    strings as a whole, or a strings tool's answer holding it as a whole value."""
    from maljan.utils.written_forms import written_forms

    if any(form in facts.index_strings for form in written_forms(value.lower())):
        return True
    strings = facts.strings
    return any(strings.holds(ref, value) for ref in strings.may_hold(value))


def _function_words(function: DecompiledFunction) -> str:
    head = hex(function.address) if function.address is not None else function.names[0]
    entries = ", ".join(safe_finding_value(entry) for entry in function.entries)
    return f"{safe_finding_value(head)} [{entries}]"


def _row_words(row: Mapping[str, Any], entry: str, row_parts: Any) -> str:
    """What a row holds in the pack's own words, or counted when those run past a
    finding row's bound for one value (``events.FINDING_VALUE_LIMIT``)."""
    from maljan.agents.function_map import _count
    from maljan.pipeline.events import FINDING_VALUE_LIMIT

    said = str(row_parts(row, entry))
    if len(said) <= FINDING_VALUE_LIMIT:
        return safe_finding_value(said)
    counts = []
    for key, one, many in (
        ("imports", "import", "imports"),
        (
            "slot_calls",
            "call through a slot the hash resolution fills",
            "calls through slots the hash resolution fills",
        ),
        ("resolved", "resolved name", "resolved names"),
        ("decoded_strings", "decoded string", "decoded strings"),
        ("plain_strings", "plain string", "plain strings"),
        ("capa", "capa rule", "capa rules"),
    ):
        n = len([c for c in row.get(key) or [] if isinstance(c, Mapping)])
        if n:
            counts.append(_count(n, one, many))
    callers, callees = len(row.get("callers") or []), len(row.get("callees") or [])
    counted = ", ".join(counts) or "no artefact of its own"
    return safe_finding_value(
        f"{counted} ({safe_finding_value(entry)}); called by {callers}, calls "
        f"{_count(callees, 'function', 'functions')}"
    )


def check_function_claims(
    isr: Any,
    functions: Sequence[DecompiledFunction],
    facts: FunctionFacts | None,
    image_bases: Sequence[int] = (),
) -> FunctionClaimCheck:
    """The claims of ``isr`` that name a call or a string their function's facts do not hold.

    See the module docstring. One question per claim block, naming every
    such value; a block is one claim the analyst wrote, however many
    technique ids it listed.
    """
    from maljan.tools.artefact_index import row_parts

    out = FunctionClaimCheck()
    claims = list(getattr(isr, "claims", None) or [])
    if not claims or not functions or facts is None:
        return out
    bases = tuple(dict.fromkeys([*image_bases, *facts.bases]))
    by_entry: dict[str, list[DecompiledFunction]] = {}
    for function in functions:
        for entry_id in function.entries:
            by_entry.setdefault(entry_id.lower(), []).append(function)
    blocks = claim_block_indexes(claims)
    seen: set[int] = set()
    for index, claim in enumerate(claims):
        block = blocks[index] if index < len(blocks) else index
        if block in seen:
            continue
        seen.add(block)
        sentence = str(getattr(claim, "claim", "") or "")
        evidence = str(getattr(claim, "evidence_ref", "") or "")
        cited = entry_ids_in(f"{sentence} {evidence}")
        about = list(dict.fromkeys(f for ref in sorted(cited) for f in by_entry.get(ref, [])))
        if not about:
            continue
        if len(about) > 1:
            named = [f for f in about if _named_by(sentence, f, bases)]
            about = named or about
        number = block + 1
        if facts.absent:
            out.not_checked.append(f"claim {number}: {facts.absent}")
            continue
        named_here = _named_at(sentence, facts.known_names)
        listing_ids = {e.lower() for f in about for e in f.entries}
        sources: list[_Held] = [facts.listings[i] for i in listing_ids if i in facts.listings]
        reason = ""
        starts: list[int] = []
        for function in about:
            start = facts.offset(function.address)
            if start is None:
                reason = (
                    NO_ADDRESS.format(name=safe_finding_value(function.names[0]))
                    if function.address is None
                    else NOT_KNOWN.format(address=hex(function.address))
                )
                break
            if facts.shown is not None and start in facts.rows and start not in facts.shown:
                reason = ROW_NOT_SHOWN.format(address=facts.va(start))
                break
            starts.append(start)
        if not reason and facts.undecoded is None:
            reason = UNDECODED_UNKNOWN.format(entry=facts.index_entry)
        reached: _Reach | None = None
        if not reason:
            reached = facts.reach(starts)
            if reached.stopped:
                reason = UNDECODED.format(address=facts.va(starts[0]))
        if reason or reached is None:
            out.not_checked.append(f"claim {number}: {reason}")
            continue
        out.checked += 1
        where = facts.va(starts[0])
        api_reason = ""
        if facts.unnamed is None:
            api_reason = UNNAMED_UNKNOWN.format(entry=facts.index_entry)
        elif not reached.whole:
            api_reason = CALLEES_UNKNOWN.format(entry=facts.index_entry, address=where)
        elif reached.unnamed:
            api_reason = UNNAMED_CALLS.format(address=where)
        # Each value is the function's only where the claim gives it to it: the
        # function it last names before the value, in the value's own clause.
        apis: list[str] = []
        strings: list[str] = []
        given = _attribution(sentence, about, reached.functions, facts)
        for value, at, api in named_here:
            owner, stands = given(at)
            if owner is None:
                out.not_checked.append(
                    f"claim {number}: "
                    f"{UNATTRIBUTED.format(value=safe_finding_value(value), where=stands)}"
                )
            elif owner != "":
                out.not_checked.append(
                    f"claim {number}: "
                    f"{GIVEN_ELSEWHERE.format(value=safe_finding_value(value), address=owner)}"
                )
            else:
                (apis if api else strings).append(value)
        claimed: list[str] = []
        for value in strings:
            if _a_sample_string(value, facts):
                claimed.append(value)
            else:
                out.not_checked.append(
                    f"claim {number}: {NOT_A_SAMPLE_STRING.format(value=safe_finding_value(value))}"
                )
        unheld = [
            (value, api)
            for value, api in [*((a, True) for a in apis), *((s, False) for s in claimed)]
            if not _held(value, api, sources, reached)
        ]
        # An API name the facts hold is held whatever else the functions call;
        # one they do not hold is no fact where a call names nothing.
        if api_reason and any(api for _value, api in unheld):
            out.not_checked.append(f"claim {number}: {api_reason}")
            unheld = [(value, api) for value, api in unheld if not api]
        if not unheld:
            continue
        out.flagged.append(index)
        out.asked += 1
        out.violations.append(
            _question(
                index,
                number,
                sentence,
                about,
                starts,
                len(reached.functions) - len(starts),
                unheld,
                facts,
                row_parts,
            )
        )
    return out


def _attribution(
    sentence: str,
    about: Sequence[DecompiledFunction],
    reached: frozenset[int],
    facts: FunctionFacts,
) -> Any:
    """Who a value at a place of ``sentence`` is given to: ``""`` the cited functions (or a
    function they reach), an address for another function, ``None`` for none.

    A mention is an address the index reads as a function's start, or a name a
    decompiler gave a cited function. A value goes with the last mention before
    it in its own sentence. With no mention before it there, it goes with the
    cited functions only when the claim names no function at all: a claim that
    names a function anywhere gives such a value to nobody, and the record says
    where the value stands.
    """
    from bisect import bisect_right

    mentions: list[tuple[int, str]] = []
    for pattern in (_HEX_ADDRESS, _GENERIC_FUNCTION_NAME, _SUFFIXED_ADDRESS, _BARE_ADDRESS):
        for match in pattern.finditer(sentence):
            start = facts.offset(int(match.group(1), 16))
            if start is None:
                continue
            if start in reached:
                mentions.append((match.start(), ""))
            elif start in facts.rows or start in facts.edges:
                mentions.append((match.start(), facts.va(start)))
    for function in about:
        for name in function.names:
            if _GENERIC_FUNCTION_NAME.fullmatch(name) or len(name) < 3:
                continue
            for match in re.finditer(r"(?<![\w.])" + re.escape(name) + r"(?![\w])", sentence):
                mentions.append((match.start(), ""))
    mentions.sort()
    places = [where for where, _owner in mentions]
    clauses = _clause_starts(sentence)

    def given(at: int) -> tuple[str | None, str]:
        """``(owner, where the value stands)``; the second says why when there is none."""
        k = bisect_right(places, at - 1) - 1
        clause = bisect_right(clauses, at)
        if k >= 0 and bisect_right(clauses, places[k]) == clause:
            return mentions[k][1], ""
        if not mentions:
            return "", ""
        later = k + 1
        if later < len(places) and bisect_right(clauses, places[later]) == clause:
            return None, BEFORE_ANY_NAME
        return None, NO_NAME_IN_ITS_SENTENCE

    return given


def _question(
    index: int,
    number: int,
    sentence: str,
    about: Sequence[DecompiledFunction],
    starts: Sequence[int],
    reached: int,
    unheld: Sequence[tuple[str, bool]],
    facts: FunctionFacts,
    row_parts: Any,
) -> Any:
    from maljan.agents.function_map import _count
    from maljan.pipeline.validation import Violation

    values = [f'"{safe_finding_value(value)}"' for value, _api in unheld]
    named = values[0] if len(values) == 1 else ", ".join(values[:-1]) + f" and {values[-1]}"
    none = " or ".join(values)
    which = ", ".join(_function_words(f) for f in about)
    entry = f"[{safe_finding_value(facts.index_entry)}]"
    them = "it" if len(values) == 1 else "any of them"
    count = _count(reached, "function", "functions")
    if len(about) == 1:
        head = f"function {which}"
        sources = (
            f"neither its listing nor its index row {entry} holds {none}, and no function "
            f"reachable from {facts.va(starts[0])} through its call edges holds {them} "
            f"({count} reachable); {NOT_FOLLOWED}"
        )
    else:
        head = f"functions {which}"
        sources = (
            f"neither their listings nor their index rows {entry} hold {none}, and no function "
            f"reachable from them through their call edges holds {them} ({count} reachable); "
            f"{NOT_FOLLOWED}"
        )
    holds: list[str] = []
    for start in starts:
        row = facts.rows.get(start)
        where = facts.va(start)
        if row is None:
            holds.append(f"{where} holds no artefact of its own in the index")
        else:
            holds.append(f"{where}'s row holds: {_row_words(row, facts.index_entry, row_parts)}")
    return Violation(
        code=FUNCTION_CLAIM_UNHELD_CODE,
        message=(
            f"claim {number} ({safe_finding_value(sentence)!r}) names {named} for {head}; "
            f"{sources}; {'; '.join(holds)}. {FUNCTION_QUESTION_ASK}"
        ),
        path=f"claims[{index}]",
    )
