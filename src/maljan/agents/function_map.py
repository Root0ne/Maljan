"""The function map: an analyst's working memory of the functions it has read.

A reversing loop on a local model re-derives what it has already read from a
transcript the window keeps cutting, and then decompiles the same routine
again. The map is kept for it by the platform, from facts only:

* the functions the analyst's own calls decompiled or listed, with the ledger
  entries that hold each listing (read the way the decompiled-not-described
  check reads them, ``pipeline.validation.decompiled_functions``);
* the artefacts the analysis server tied to each function: the Windows names a
  hash in it resolves to (``resolve_api_hashes``), the texts it refers to and
  the call sites they are passed to (``decode_string_blobs``), and the strings
  FLOSS decoded in it (``floss``) — only where the answer puts the place
  *inside* the function, never after a function start;
* the first sentence of the first of the analyst's own parsed claims that
  names the function;
* whether the function is a row of the pack's function index
  (``tools.artefact_index``): with an index, the coverage line counts the
  visited functions among the index's rows, and the not-visited line lists
  the other rows in the pack's rank order.

The model never writes to it. The block is rendered fresh on every turn beside
the run-state lines and replaces nothing the model already sees.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.pipeline.validation import (
    _ADDRESS_ARGUMENTS,
    _DIGIT_RUN,
    _GENERIC_FUNCTION_NAME,
    _NAME_ARGUMENTS,
    _address_value,
    _addresses_written,
    decompiled_functions,
    image_bases_in,
)
from maljan.schemas.evidence import answer_not_shown

__all__ = [
    "FUNCTION_MAP_HEAD",
    "Artefact",
    "FunctionArtefacts",
    "FunctionMap",
    "MapEntry",
    "build_function_map",
    "keeps_for_the_map",
    "function_artefacts",
    "function_map_block",
]

FUNCTION_MAP_HEAD = (
    "function map (kept by the platform from the ledger and your parsed claims; you do not "
    "write to it):"
)

# The analysis server's tools whose answers tie an artefact to a function.
_HASH_TOOL = "resolve_api_hashes"
_BLOB_TOOL = "decode_string_blobs"
_FLOSS_TOOL = "floss"
_INDEX_TOOL = "function_index"

# How each kind of artefact is counted in the block, singular and plural.
_KIND_WORDS: dict[str, tuple[str, str]] = {
    "name": ("resolved name", "resolved names"),
    "text": ("decoded text", "decoded texts"),
    "call": ("call-site fact", "call-site facts"),
    "decoded": ("string FLOSS decoded", "strings FLOSS decoded"),
}
_KIND_ORDER = tuple(_KIND_WORDS)


@dataclass(frozen=True)
class Artefact:
    """One thing the analysis server tied to a function, and the entry that says so."""

    kind: str
    value: str
    entry: str


@dataclass
class FunctionArtefacts:
    """The artefacts per function, keyed by offset from the image base where one is known.

    ``virtual`` holds the keys that are virtual addresses no image base could
    turn into an offset.
    """

    by_function: dict[int, list[Artefact]] = field(default_factory=dict)
    image_bases: tuple[int, ...] = ()
    virtual: set[int] = field(default_factory=set)
    # The offsets of the function index's rows, and the entry that holds them.
    indexed: set[int] = field(default_factory=set)
    index_entry: str = ""
    # The rows as ``(offset, distinct artefacts of its own)``, in the pack's rank order.
    index_rows: list[tuple[int, int]] = field(default_factory=list)

    def add(self, address: int, artefact: Artefact, *, virtual: bool = False) -> None:
        self.by_function.setdefault(address, []).append(artefact)
        if virtual:
            self.virtual.add(address)


@dataclass
class MapEntry:
    """One visited function: where it is, the entries that read it, what it reaches."""

    address: int | None
    names: tuple[str, ...]
    decompiled: tuple[str, ...] = ()
    listed: tuple[str, ...] = ()
    artefacts: list[Artefact] = field(default_factory=list)
    summary: str = ""
    indexed: bool = False


@dataclass
class FunctionMap:
    """The visited functions and the functions reaching artefacts that were not visited."""

    visited: list[MapEntry] = field(default_factory=list)
    unvisited: list[tuple[int, list[Artefact]]] = field(default_factory=list)
    image_bases: tuple[int, ...] = ()
    virtual: frozenset[int] = frozenset()
    # How many rows the function index has, and the entry that holds it.
    indexed: int = 0
    index_entry: str = ""
    # The index's rows no visited function is, in the pack's rank order, as
    # ``(offset, distinct artefacts of its own)``.
    index_unvisited: list[tuple[int, int]] = field(default_factory=list)

    def coverage(self) -> str:
        """``N functions visited (…); M functions reach artefacts …, K of them visited``.

        With a function index, ``M`` is its rows and ``K`` the visited
        functions among them: the index counts every function the run's
        answers place an artefact in, the pack's own decoding included.
        """
        decompiled = sum(1 for e in self.visited if e.decompiled)
        listed = sum(1 for e in self.visited if e.listed and not e.decompiled)
        how = []
        if decompiled:
            how.append(f"{decompiled} decompiled")
        if listed:
            how.append(f"{listed} listed")
        visited = _count(len(self.visited), "function", "functions") + " visited"
        if how:
            visited += f" ({', '.join(how)})"
        if self.indexed:
            held = sum(1 for e in self.visited if e.indexed)
            verb = "holds" if self.indexed == 1 else "hold"
            return (
                f"{visited}; {_count(self.indexed, 'function', 'functions')} {verb} artefacts "
                f"in the function index ({self.index_entry}), {held} of them visited"
            )
        reached_visited = sum(1 for e in self.visited if e.artefacts)
        reaching = reached_visited + len(self.unvisited)
        verb = "reaches" if reaching == 1 else "reach"
        return (
            f"{visited}; {_count(reaching, 'function', 'functions')} {verb} artefacts the "
            f"analysis server tied to them, {reached_visited} of them visited"
        )

    def empty(self) -> bool:
        return not self.visited and not self.unvisited and not self.index_unvisited


def _count(n: int, one: str, many: str) -> str:
    return f"{n} {one if n == 1 else many}"


def _parsed(entry: Any) -> Any:
    structured = getattr(entry, "structured", None)
    if isinstance(structured, dict | list):
        return structured
    try:
        return json.loads(str(getattr(entry, "output", "") or ""))
    except (ValueError, TypeError, RecursionError):
        return None


def _hex(value: Any) -> int | None:
    match = re.fullmatch(r"\s*0x([0-9a-fA-F]{1,16})\s*", str(value or ""))
    return int(match.group(1), 16) if match else None


def _stated_base(data: Mapping[str, Any]) -> int | None:
    return _hex(data.get("image_base"))


def function_artefacts(entries: Iterable[Any]) -> FunctionArtefacts:
    """What the analysis server's answers among ``entries`` tie to each function.

    Read from answered calls only. A hash hit's place and a blob's reference
    count for a function only where the answer states the function around the
    place (``function``); a place after a function start is not inside it. A
    decoded blob referred to from a function is one decoded text for it, and
    one call-site fact more when the answer followed where its bytes are
    passed. A FLOSS string counts for the routine FLOSS names, as an offset
    when FLOSS gave one and otherwise as a virtual address, made an offset by
    the image base another answer stated.
    """
    rows = [e for e in entries if getattr(e, "ok", True)]
    found = FunctionArtefacts()
    bases: list[int] = list(image_bases_in(rows))
    parsed: list[tuple[Any, str, Any]] = []
    for entry in rows:
        tool = str(getattr(entry, "tool", "") or "")
        if tool not in (_HASH_TOOL, _BLOB_TOOL, _FLOSS_TOOL, _INDEX_TOOL):
            continue
        data = _parsed(entry)
        if not isinstance(data, dict):
            continue
        if tool == _INDEX_TOOL:
            _index_rows(found, data, str(getattr(entry, "id", "") or ""))
            base = _stated_base(data)
            if base and base not in bases:
                bases.append(base)
            continue
        base = _stated_base(data)
        if base and base not in bases:
            bases.append(base)
        parsed.append((entry, tool, data))
    found.image_bases = tuple(bases)
    for entry, tool, data in parsed:
        entry_id = str(getattr(entry, "id", "") or "")
        if tool == _HASH_TOOL:
            _hash_artefacts(found, data, entry_id)
        elif tool == _BLOB_TOOL:
            _blob_artefacts(found, data, entry_id)
        else:
            _floss_artefacts(found, data, entry_id)
    return found


def _index_rows(found: FunctionArtefacts, data: Mapping[str, Any], entry_id: str) -> None:
    """The function index's rows, by offset and in its rank order; the last index read counts.

    The index's own ``image_base`` is one of the bases the map joins an
    offset and its virtual address by (``function_artefacts`` adds it).
    """
    ranked: list[tuple[int, int]] = []
    for row in data.get("rows") or []:
        offset = _hex(row.get("offset")) if isinstance(row, dict) else None
        if offset is not None:
            direct = row.get("direct")
            ranked.append((offset, int(direct) if isinstance(direct, int) else 0))
    found.index_rows = ranked
    found.indexed = {offset for offset, _ in ranked}
    found.index_entry = entry_id


def _hash_artefacts(found: FunctionArtefacts, data: Mapping[str, Any], entry_id: str) -> None:
    for hit in data.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        names = [
            str(reading.get("name") or "")
            for reading in hit.get("readings") or []
            if isinstance(reading, dict) and reading.get("set") != "modules" and reading.get("name")
        ]
        if not names:
            continue
        for place in hit.get("occurrences") or []:
            address = _hex(place.get("function")) if isinstance(place, dict) else None
            if address is None:
                continue
            for name in dict.fromkeys(names):
                found.add(address, Artefact("name", name, entry_id))


def _blob_artefacts(found: FunctionArtefacts, data: Mapping[str, Any], entry_id: str) -> None:
    for result in data.get("results") or []:
        if not isinstance(result, dict):
            continue
        text = str(result.get("text") or "")
        if not text:
            continue
        for place in result.get("references") or []:
            address = _hex(place.get("function")) if isinstance(place, dict) else None
            if address is None:
                continue
            found.add(address, Artefact("text", text, entry_id))
            fact = _call_fact(text, place.get("passed_to"))
            if fact:
                found.add(address, Artefact("call", fact, entry_id))


def _call_fact(text: str, passed: Any) -> str:
    """One call-site fact as counted: the text, the argument position, the call and its callee.

    Two places passing one text to two calls are two facts; the same call
    recorded by two entries is one.
    """
    if not isinstance(passed, dict) or not passed.get("call_at"):
        return ""
    callee = passed.get("callee")
    target = ""
    if isinstance(callee, dict):
        target = str(next((v for v in callee.values() if isinstance(v, str) and v), ""))
    argument = passed.get("argument")
    said = f"argument {argument} of the call" if argument is not None else "the call"
    return f"{text}: {said} at {passed['call_at']}" + (f" to {target}" if target else "")


def _floss_artefacts(found: FunctionArtefacts, data: Mapping[str, Any], entry_id: str) -> None:
    for row in data.get("strings") or []:
        if not isinstance(row, dict) or not row.get("string"):
            continue
        address = _hex(row.get("function_rva"))
        virtual = False
        if address is None:
            address = _hex(row.get("function"))
            if address is None:
                continue
            # Made an offset only by the one image base the run read; with no
            # base, or with several, it is kept as FLOSS wrote it.
            bases = found.image_bases
            if len(bases) == 1 and address > bases[0]:
                address -= bases[0]
            else:
                virtual = True
        found.add(address, Artefact("decoded", str(row["string"]), entry_id), virtual=virtual)


def keeps_for_the_map(entry: Any) -> bool:
    """Whether the map reads this entry: a call that decompiles or disassembles, or
    one of the analysis server's tools that tie artefacts to functions."""
    if getattr(entry, "repeated_of", None):
        return False
    tool = str(getattr(entry, "tool", "") or "").lower()
    return (
        "decompil" in tool
        or _lists_code(tool)
        or tool in (_HASH_TOOL, _BLOB_TOOL, _FLOSS_TOOL, _INDEX_TOOL)
    )


# A tool whose name says it disassembles, and one of those whose name says the
# whole function is what it lists.
def _lists_code(tool: str) -> bool:
    return "disassembl" in tool.lower()


def _lists_a_function(tool: str) -> bool:
    return _lists_code(tool) and "function" in tool.lower()


def _listed_at(entry: Any) -> tuple[int | None, list[str]]:
    """The address and the names a listing call was given, from its arguments alone."""
    args = getattr(entry, "args", None) or {}
    address: int | None = None
    for argument in _ADDRESS_ARGUMENTS:
        if argument in args and address is None:
            address = _address_value(args[argument])
    names: list[str] = []
    for argument in _NAME_ARGUMENTS:
        value = str(args.get(argument) or "").strip()
        if value:
            names.append(value)
            generic = _GENERIC_FUNCTION_NAME.fullmatch(value)
            if generic is not None and address is None:
                address = int(generic.group(1), 16)
    return address, names


def _merged(pack: FunctionArtefacts | None, own: FunctionArtefacts) -> FunctionArtefacts:
    """The pack's artefacts and the ones the analyst's own analysis-server calls tied, together.

    An artefact two entries tie to one function stays one per entry: the two
    entries are two citations of it.
    """
    if pack is None:
        return own
    if not own.by_function and not own.indexed:
        return pack
    merged = FunctionArtefacts(
        by_function={k: list(v) for k, v in pack.by_function.items()},
        image_bases=tuple(dict.fromkeys([*pack.image_bases, *own.image_bases])),
        virtual=set(pack.virtual) | set(own.virtual),
        indexed=set(own.indexed or pack.indexed),
        index_entry=own.index_entry if own.indexed else pack.index_entry,
        index_rows=list(own.index_rows if own.indexed else pack.index_rows),
    )
    for key, tied in own.by_function.items():
        merged.by_function.setdefault(key, []).extend(tied)
    return merged


def _same(a: int | None, b: int | None, bases: Sequence[int]) -> bool:
    """Whether two addresses are one function: equal, or apart by an image base the run read.

    With a base known, the two are an offset (below the base) and its virtual
    address (not below it). With none known, only equal addresses are one
    function: the decompiled-not-described check's 64 KiB fallback is a
    guess, and the map does not guess.
    """
    if a is None or b is None:
        return False
    if a == b:
        return True
    low, high = sorted((a, b))
    # An offset and its virtual address: exactly one of the two below the
    # base, and apart by it. Two virtual addresses a base apart are two.
    return any(low < base <= high and high - low == base for base in bases)


def _fold_spellings(visited: list[MapEntry], bases: Sequence[int]) -> list[MapEntry]:
    """``visited`` with an offset and its virtual address made one entry, at the larger address."""
    out: list[MapEntry] = []
    for entry in visited:
        into = next((e for e in out if _same(e.address, entry.address, bases)), None)
        if into is None:
            out.append(entry)
            continue
        if entry.address is not None and into.address is not None:
            into.address = max(into.address, entry.address)
        into.names = tuple(dict.fromkeys([*into.names, *entry.names]))
        into.decompiled = tuple(dict.fromkeys([*into.decompiled, *entry.decompiled]))
        into.listed = tuple(dict.fromkeys([*into.listed, *entry.listed]))
    return out


def _first_sentence(text: str) -> str:
    said = " ".join(str(text or "").split())
    parts = re.split(r"(?<=[.!?])\s+(?=[A-Z0-9`\"'(])", said, maxsplit=1)
    return parts[0] if parts else said


def build_function_map(
    own: Iterable[Any],
    artefacts: FunctionArtefacts | None,
    claims: Iterable[Any],
    image_bases: Sequence[int] = (),
) -> FunctionMap:
    """The map of ``own`` entries, the artefacts tied to functions and the analyst's claims.

    A decompiled function is one ``decompiled_functions`` reads out of the
    entries. A listed one is a disassembly call of a whole function, or one at
    an address that is a function the map already knows. Artefacts join a
    visited function when its address and the artefact's offset are one
    function (``_same``: equal, or apart by an image base the run read). An
    offset and its virtual address are one visited function the same way; with
    no base known, both are kept as written.
    """
    # A call whose answer the conversation had no room for was not read, and a
    # repeat holds a note in place of the answer the earlier entry holds.
    entries = [
        e
        for e in own
        if getattr(e, "ok", True)
        and not answer_not_shown(e)
        and not getattr(e, "repeated_of", None)
    ]
    found = _merged(artefacts, function_artefacts(entries))
    bases = tuple(dict.fromkeys([*image_bases, *found.image_bases, *image_bases_in(entries)]))
    visited: list[MapEntry] = _fold_spellings(
        [
            MapEntry(address=f.address, names=f.names, decompiled=f.entries)
            for f in decompiled_functions(entries)
        ],
        bases,
    )
    known = [e.address for e in visited if e.address is not None] + list(found.by_function)
    for entry in entries:
        tool = str(getattr(entry, "tool", "") or "")
        if not _lists_code(tool):
            continue
        address, names = _listed_at(entry)
        if address is None:
            continue
        if not _lists_a_function(tool) and not any(_same(address, k, bases) for k in known):
            continue
        entry_id = str(getattr(entry, "id", "") or "")
        into = next((e for e in visited if _same(e.address, address, bases)), None)
        if into is None:
            into = MapEntry(address=address, names=tuple(names))
            visited.append(into)
            known.append(address)
        else:
            into.names = tuple(dict.fromkeys([*into.names, *names]))
        if entry_id and entry_id not in into.listed:
            into.listed = (*into.listed, entry_id)

    reached: set[int] = set()
    for entry in visited:
        for key, tied in found.by_function.items():
            if key in found.virtual:
                if entry.address == key:
                    entry.artefacts.extend(tied)
                    reached.add(key)
            elif _same(entry.address, key, bases):
                entry.artefacts.extend(tied)
                reached.add(key)

    said = [
        f"{getattr(c, 'claim', '') or ''} {getattr(c, 'evidence_ref', '') or ''}" for c in claims
    ]
    texts = [str(getattr(c, "claim", "") or "") for c in claims]
    for entry in visited:
        for text, sentence in zip(said, texts, strict=True):
            if _claim_names(text, entry, bases):
                entry.summary = _first_sentence(sentence)
                break

    held: set[int] = set()
    for entry in visited:
        # The spellings ``_same`` joins, looked up rather than compared row by row.
        address = entry.address
        if address is None:
            continue
        for key in (address, *(address - b for b in bases), *(address + b for b in bases)):
            if key in found.indexed and _same(address, key, bases):
                entry.indexed = True
                held.add(key)

    unvisited = sorted(
        ((key, tied) for key, tied in found.by_function.items() if key not in reached),
        key=lambda pair: pair[0],
    )
    return FunctionMap(
        visited=visited,
        unvisited=unvisited,
        image_bases=bases,
        virtual=frozenset(found.virtual),
        indexed=len(found.indexed),
        index_entry=found.index_entry,
        index_unvisited=[row for row in found.index_rows if row[0] not in held],
    )


def _claim_names(text: str, entry: MapEntry, bases: Sequence[int]) -> bool:
    """Whether a claim's text names this visited function.

    By an address written out that is the same function by the map's own rule
    (``_same``: equal, or an offset and its virtual address apart by a base the
    run read; with no base, only equal), by the function's own hex spelling
    written as digits alone, or by a name the decompiler gave it. A name that
    is an ordinary word (``entry``, ``start``) names it only written as code
    or beside a word that says it is a function. No address is guessed.
    """
    if entry.address is not None:
        if any(_same(entry.address, address, bases) for address in _addresses_written(text)):
            return True
        spelled = f"{entry.address:x}"
        if spelled.isdigit() and any(
            run.group(1).lstrip("0") == spelled.lstrip("0") for run in _DIGIT_RUN.finditer(text)
        ):
            return True
    for name in entry.names:
        if _GENERIC_FUNCTION_NAME.fullmatch(name):
            continue
        # A dotted name (``sym.entry``, ``fcn.main``) written whole names it;
        # its last label is read by the same rule as a plain name.
        if "." in name and _written_bare(text, name):
            return True
        last = name.rsplit(".", 1)[-1]
        if len(last) < 3 or _GENERIC_FUNCTION_NAME.fullmatch(last):
            continue
        if _WORD_NAME.fullmatch(last):
            if _named_as_a_function(text, last):
                return True
            continue
        if _written_bare(text, last):
            return True
    return False


def _written_bare(text: str, spelling: str) -> bool:
    """Whether ``text`` writes ``spelling`` as a whole word, as the decompiled check reads a name."""
    return re.search(r"(?<![\w.])" + re.escape(spelling) + r"(?![\w])", text) is not None


# A function name spelled like a word of prose: letters only, at most the first
# a capital ("entry", "Start").
_WORD_NAME = re.compile(r"[A-Za-z][a-z]+")
# The words that say a name beside them is a function's.
_FUNCTION_CUE = (
    r"(?:functions?|routines?|subroutines?|procedures?|methods?|exports?|exported|"
    r"handlers?|callbacks?|symbols?)"
)


def _named_as_a_function(text: str, name: str) -> bool:
    """Whether ``text`` writes the word ``name`` as code or beside a word that says it is a function.

    As code: in backticks or quotes, or with a call's parenthesis after it.
    Beside a cue: the cue straight before it or straight after it
    (``the export entry``, ``the entry function``).
    """
    word = re.escape(name)
    quoted = r"[`'\"]" + word + r"[`'\"]"
    called = r"(?<![\w.])" + word + r"\s*\("
    bare = r"[`'\"]?" + word + r"[`'\"]?"
    before = r"(?i:\b" + _FUNCTION_CUE + r")\s+" + bare + r"(?![\w])"
    after = r"(?<![\w.])" + bare + r"\s+(?i:" + _FUNCTION_CUE + r"\b)"
    return any(re.search(pattern, text) for pattern in (quoted, called, before, after))


def _kinds(artefacts: Sequence[Artefact]) -> list[tuple[str, int, list[str]]]:
    """``(kind, count, entry ids)`` in a fixed order of kinds, for the kinds present.

    The count is of distinct values: a text referred to from two places of a
    function, or an answer two entries recorded, is one artefact, and every
    entry that holds it is cited.
    """
    out: list[tuple[str, int, list[str]]] = []
    for kind in _KIND_ORDER:
        of = [a for a in artefacts if a.kind == kind]
        if of:
            distinct = len({a.value for a in of})
            out.append((kind, distinct, list(dict.fromkeys(a.entry for a in of if a.entry))))
    return out


def _where(address: int | None, names: Sequence[str]) -> str:
    head = hex(address) if address is not None else (names[0] if names else "unnamed")
    shown = [n for n in names if n != head] if address is not None else list(names[1:])
    return f"{head} ({', '.join(shown)})" if shown else head


def _folded(entry: MapEntry) -> str:
    """A bare visit on the "also visited" line: its address, with the names that are not
    a decompiler's generic ``FUN_``/``sub_``/``fcn.`` name."""
    kept = [n for n in entry.names if not _GENERIC_FUNCTION_NAME.fullmatch(n)]
    if entry.address is None:
        return _where(None, kept or list(entry.names))
    return f"{hex(entry.address)} ({', '.join(kept)})" if kept else hex(entry.address)


def _visited_line(entry: MapEntry) -> str:
    parts: list[str] = []
    if entry.decompiled:
        parts.append(f"decompiled in {', '.join(entry.decompiled)}")
    if entry.listed:
        parts.append(f"listed in {', '.join(entry.listed)}")
    kinds = _kinds(entry.artefacts)
    if kinds:
        parts.append(
            "reaches "
            + ", ".join(
                f"{_count(n, *_KIND_WORDS[kind])} ({', '.join(ids)})" for kind, n, ids in kinds
            )
        )
    if entry.summary:
        parts.append(f"summary: {entry.summary}")
    return f"- {_where(entry.address, entry.names)}: {'; '.join(parts)}"


def _unvisited_item(found: FunctionMap, address: int, artefacts: Sequence[Artefact]) -> str:
    if address in found.virtual:
        where = hex(address)
    elif len(found.image_bases) == 1 and address < found.image_bases[0]:
        where = hex(found.image_bases[0] + address)
    else:
        where = f"offset {hex(address)}"
    kinds = _kinds(artefacts)
    counts = ", ".join(_count(n, *_KIND_WORDS[kind]) for kind, n, _ in kinds)
    ids = list(dict.fromkeys(i for _, _, entry_ids in kinds for i in entry_ids))
    return f"{where} ({counts}; {', '.join(ids)})" if ids else f"{where} ({counts})"


def function_map_block(found: FunctionMap, room: int | None = None) -> str:
    """The map as the model reads it, or ``""`` when nothing is visited or tied.

    A head, the coverage line, one line per visited function that reaches an
    artefact or has a summary, one line of the other visited addresses, and one
    line of the functions reaching artefacts that were not visited.

    With a function index, that last line lists the index's rows not visited
    and takes only the room the other lines leave of ``room``, the characters
    the caller derived for the whole block: the ranked rows that fit, then how
    many more there are and where the index is. With no ``room`` it states the
    count, the entry and the tool that serves the index, and no rows.
    """
    if found.empty():
        return ""
    lines = [FUNCTION_MAP_HEAD, f"coverage: {found.coverage()}"]
    said = [e for e in found.visited if e.artefacts or e.summary]
    bare = [e for e in found.visited if not (e.artefacts or e.summary)]
    lines.extend(_visited_line(entry) for entry in said)
    if bare:
        # A visit with nothing but its entry id: the transcript already
        # stamps the id on the listing, so the address is enough here.
        lines.append("also visited: " + ", ".join(_folded(e) for e in bare))
    if found.indexed:
        # With an index, the not-visited line reads the index's rows, as the
        # coverage line does, in the pack's rank order.
        if found.index_unvisited:
            left = None if room is None else room - sum(len(line) + 1 for line in lines)
            lines.append(_index_line(found, left))
    elif found.unvisited:
        lines.append(
            "not visited, reaching artefacts: "
            + "; ".join(_unvisited_item(found, a, tied) for a, tied in found.unvisited)
        )
    return "\n".join(lines)


# Where the whole index is, said after the rows the room left out.
INDEX_ELSEWHERE = "the index is {entry}, served by the analysis server's function_index tool"


def _index_line(found: FunctionMap, room: int | None) -> str:
    """The index's rows not visited, in rank order, in ``room`` characters; ``None``: no rows.

    Every row when they all fit; otherwise the rows that fit, room being kept
    for the last clause at its longest, then "and N more" with where the index
    is. With no room derived, the count, the entry and the tool only.
    """
    rows = found.index_unvisited
    head = f"not visited, holding artefacts in the function index ({found.index_entry}): "
    elsewhere = INDEX_ELSEWHERE.format(entry=found.index_entry)
    if room is None:
        return f"{head}{_count(len(rows), 'row', 'rows')}; {elsewhere}"
    items = [_indexed_item(found, a, n) for a, n in rows]
    whole = head + "; ".join(items)
    if len(whole) <= room:
        return whole
    budget = room - len(f"; and {len(rows)} more; {elsewhere}")
    shown: list[str] = []
    used = len(head)
    for item in items:
        cost = len(item) + (2 if shown else 0)
        if used + cost > budget:
            break
        shown.append(item)
        used += cost
    if not shown:
        return f"{head}{_count(len(rows), 'row', 'rows')}; {elsewhere}"
    return f"{head}{'; '.join(shown)}; and {len(rows) - len(shown)} more; {elsewhere}"


def _indexed_item(found: FunctionMap, address: int, artefacts: int) -> str:
    where = (
        hex(found.image_bases[0] + address)
        if len(found.image_bases) == 1 and address < found.image_bases[0]
        else f"offset {hex(address)}"
    )
    return f"{where} ({_count(artefacts, 'artefact', 'artefacts')})"
