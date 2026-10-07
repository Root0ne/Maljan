"""A function claim checked against the function's own facts.

A claim whose cited evidence is the listing of a function the analyst's own
calls decompiled or disassembled (``validation.decompiled_functions``, and a
disassembly call given the function's address) names calls and strings for
that function. The platform reads the Windows function names and the quoted
string values the claim's own sentence names and looks for each, in this
order:

1. the listing's own text;
2. the function's row in the triage pack's function index
   (``tools.artefact_index``): the imports it calls, the names its hashes
   resolve to, the decoded and plain strings it refers to and the capa rules
   matched in it;
3. the rows of its direct callees, one call deep;
4. the places the run's hash-resolution and decoded-string answers put
   inside it (``agents.function_map.function_artefacts``).

A value any of them holds holds. So does one the claim gives to another
function it names by its start, and one another entry the claim cites holds:
the claim may name it for that entry's subject rather than for the function,
and a question is never asked on a guess. API names are compared without
regard to case, a module written in front (``kernel32.dll!Name``) read off,
and the ANSI and wide spellings read as one name, as the API catalogue
compares them (``analysis.api_capability_db.canonical_name``); strings by the
citation check's own whole-value reading (``EntryTexts``).

A value none of them holds is stated to the analyst, once, through the
validation turn every other question goes through: the claim, the function
and its entries, the index row and the count of callees read, and what the
function's row does hold, in the pack's own words for it. The analyst keeps,
corrects or withdraws the claim; nothing is edited or dropped here.

Nothing is stated where the fact is not whole, and the run record says why,
``no: <reason>``: no index in the run, an index answer not kept whole, a
function the index does not know, a row the pack the analyst was shown left
out, a function the decoder stopped in, and, for an API name, a function or a
callee whose calls the index cannot all name (a call through a register or a
pointer the code fills itself may be the call the claim names).

Linear in the claims, the index rows and the listings' size: the rows are
keyed by offset once, each listing and each row is read into its names and
its text once, and a claim reads only its own functions' rows.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from maljan.pipeline.events import safe_finding_value
from maljan.pipeline.validation import (
    _ADDRESS_ARGUMENTS,
    _CODE_SPAN_RE,
    _GENERIC_FUNCTION_NAME,
    _NAME_ARGUMENTS,
    _QUOTED_SPAN_RE,
    FUNCTION_CLAIM_UNHELD,
    DecompiledFunction,
    EntryTexts,
    _address_value,
    _addresses_written,
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
UNDECODED = "no: the decoder stopped in {address} or one of its callees, so its calls are not whole"
UNDECODED_UNKNOWN = (
    "no: [{entry}] the function index does not say which functions the decoder stopped in"
)
UNNAMED_CALLS = (
    "no: {address} or one of its callees makes calls the index cannot name (through a register "
    "or a pointer the code fills itself), so an API name it does not hold may be one of them"
)
UNNAMED_UNKNOWN = "no: [{entry}] the function index does not count the calls that name nothing"
CALLEES_UNKNOWN = (
    "no: {address} holds no artefact of its own, so the index lists none of its callees and "
    "an API name may be called through one of them"
)

# A Windows function name as written in running text, a module in front read off.
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# A quoted value inside a code span: the span holds the quotes too.
_QUOTED_INSIDE = re.compile(r'"([^"\n]+)"|\'([^\'\n]+)\'|“([^”\n]+)”')

# A JSON escape a value may be written with; a value of escapes and marks alone
# spells no letter or digit, and no text can be said to hold or lack it.
_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|.)")
# A pack line's leading citation: the entry the line, and the lines after it
# up to the next citation, are the pack's words for.
_PACK_LINE_ID = re.compile(r"\s*\[(ev_\d+)\]", re.IGNORECASE)

_CATALOGUE_LOWER: frozenset[str] | None = None


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


def _api_forms(name: str) -> tuple[str, ...]:
    """The spellings an entry's text may hold an API name in: as written, and both A/W forms."""
    key = _api_key(name)
    return tuple(dict.fromkeys([name.lower(), key, f"{key}a", f"{key}w"]))


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
    callee_rows: dict[int, list[int]] = field(default_factory=dict)
    callees: dict[int, list[int]] = field(default_factory=dict)
    unnamed: dict[int, int] | None = None
    undecoded: set[int] | None = None
    shown: set[int] | None = None
    held_by_row: dict[int, _Held] = field(default_factory=dict)
    placed: dict[int, _Held] = field(default_factory=dict)
    run_keys: set[str] = field(default_factory=set)
    run_names: set[str] = field(default_factory=set)
    listings: dict[str, _Held] = field(default_factory=dict)
    entries: EntryTexts = field(default_factory=EntryTexts)
    # Each pack entry's lines as the analyst was shown them, lower-cased.
    pack_lines: dict[str, str] = field(default_factory=dict)
    # Every entry id the run holds text or pack lines for.
    every: set[str] = field(default_factory=set)

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


def _row_held(row: Mapping[str, Any]) -> _Held:
    held = _Held()
    for key in ("imports", "resolved"):
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
    the pack's entries the claims may cite, ``facts_block`` the pack text the
    analyst was shown (a row it left out is not checked against) and
    ``bases`` the image bases the run read.
    """
    from maljan.agents.function_map import function_artefacts, merged_artefacts
    from maljan.tools.artefact_index import row_line

    found = merged_artefacts(artefacts, function_artefacts(entries))
    facts = FunctionFacts(entries=EntryTexts.from_ledger([*pack_entries, *entries]))
    for entry in entries:
        tool = str(getattr(entry, "tool", "") or "").lower()
        if "decompil" not in tool and "disassembl" not in tool:
            continue
        entry_id = str(getattr(entry, "id", "") or "")
        output = str(getattr(entry, "output", "") or "")
        if entry_id and output:
            facts.listings[entry_id.lower()] = _Held(_names_in(output), [output.lower()])
    current = ""
    for line in facts_block.splitlines():
        cited = _PACK_LINE_ID.match(line)
        if cited is not None:
            current = cited.group(1).lower()
        if current:
            facts.pack_lines[current] = f"{facts.pack_lines.get(current, '')}\n{line.lower()}"
    facts.every = set(facts.entries.texts) | set(facts.pack_lines)
    data = getattr(found, "index_data", None)
    if not isinstance(data, Mapping):
        facts.absent = str(getattr(found, "index_unread", "") or "") or NO_INDEX
        return facts
    facts.index_entry = str(getattr(found, "index_entry", "") or "")
    if getattr(found, "index_cut", False):
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

    for row in data.get("rows") or []:
        if not isinstance(row, Mapping):
            continue
        start = _hex(row.get("offset"))
        if start is None:
            continue
        facts.rows[start] = row
        facts.known.add(start)
        held = _row_held(row)
        facts.held_by_row[start] = held
        facts.run_keys |= held.names
        facts.run_names |= {
            str(cell.get("name")).rpartition("!")[2].lower()
            for key in ("imports", "resolved")
            for cell in row.get(key) or []
            if isinstance(cell, Mapping) and cell.get("name")
        }
        listed = [o for o in map(offset_of, row.get("callees") or []) if o is not None]
        facts.callees[start] = listed
        facts.known.update(listed)
        for caller in map(offset_of, row.get("callers") or []):
            if caller is not None:
                facts.known.add(caller)
                facts.callee_rows.setdefault(caller, []).append(start)
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
                facts.run_keys.add(_api_key(value))
                facts.run_names.add(value.lower())
            elif getattr(artefact, "kind", "") in ("text", "decoded"):
                held.texts.append(value.lower())
    return facts


# ---------------------------------------------------------------------------
# What a claim names
# ---------------------------------------------------------------------------


def _inside(spans: Sequence[tuple[int, int]], at: int) -> bool:
    return any(begin <= at < end for begin, end in spans)


def named_values(text: str, run_names: Iterable[str] = ()) -> tuple[list[str], list[str]]:
    """``(API names, string values)`` a claim's sentence names, once each, in order.

    An API name is an identifier the export catalogue or this run's own facts
    know, written with a capital after its first letter or inside a code span
    (``send``), so a word of running text is never read as one. A string is a
    value written in double, single or typographic quotes, or a code span
    that holds such a quoted value, of three characters or more, that a text
    can be said to hold (``validation.decidable``); and an unquoted value
    whose shape makes it one (``validation.literal_values``).
    """
    text = str(text or "")
    known = _catalogue_lower() | {str(name).lower() for name in run_names}
    spans = [(m.start(), m.end()) for m in _CODE_SPAN_RE.finditer(text)]
    apis: list[str] = []
    for match in _IDENTIFIER.finditer(text):
        token = match.group(0)
        if len(token) < 3 or _GENERIC_FUNCTION_NAME.fullmatch(token):
            continue
        if not _is_a_name(token, known):
            continue
        if re.search(r"[A-Z]", token[1:]) or _inside(spans, match.start()):
            if token not in apis:
                apis.append(token)
    keys = {_api_key(name) for name in apis}
    strings: list[str] = []
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
            len(value) < 3
            or not re.search(r"[A-Za-z0-9]", _ESCAPE.sub("", value))
            or not decidable(value)
            or _api_key(value) in keys
            or _GENERIC_FUNCTION_NAME.fullmatch(value)
            or entry_ids_in(value)
        ):
            continue
        if value not in strings:
            strings.append(value)
    for value in literal_values(text):
        if value not in strings:
            strings.append(value)
    return apis, strings


# ---------------------------------------------------------------------------
# The check
# ---------------------------------------------------------------------------


@dataclass
class FunctionClaimCheck:
    """What the check found in one answer.

    ``flagged`` are the claim indexes asked about, ``checked`` the claim
    blocks whose functions' facts were read, and ``not_checked`` each
    function claim no fact could be stated for, ``claim <n>: no: <reason>``.
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


def _held(value: str, api: bool, sources: Sequence[_Held]) -> bool:
    from maljan.agents._indicator_denylists import whole_value_in
    from maljan.utils.written_forms import written_forms

    if api:
        key = _api_key(value)
        return any(key in source.names for source in sources)
    forms = written_forms(value.lower())
    return any(
        whole_value_in(form, text) for source in sources for text in source.texts for form in forms
    )


def _held_by_cited(value: str, api: bool, cited: set[str], facts: FunctionFacts) -> bool:
    """Whether an entry in ``cited`` holds ``value``: its text, or its pack lines as shown."""
    from maljan.agents._indicator_denylists import whole_value_in
    from maljan.utils.written_forms import written_forms

    entries = facts.entries
    forms = _api_forms(value) if api else (value,)
    if any(entries.holds(ref, form) for form in forms for ref in entries.may_hold(form) & cited):
        return True
    lines = [facts.pack_lines[ref] for ref in cited if ref in facts.pack_lines]
    return any(
        whole_value_in(spelled, text)
        for form in forms
        for spelled in written_forms(form.lower())
        for text in lines
    )


def _function_words(function: DecompiledFunction) -> str:
    head = hex(function.address) if function.address is not None else function.names[0]
    entries = ", ".join(safe_finding_value(entry) for entry in function.entries)
    return f"{safe_finding_value(head)} [{entries}]"


def _row_words(row: Mapping[str, Any], entry: str, row_parts: Any) -> str:
    """What a row holds in the pack's own words, or counted when those run past a
    finding row's bound for one value (``events.FINDING_VALUE_LIMIT``)."""
    from maljan.pipeline.events import FINDING_VALUE_LIMIT

    said = str(row_parts(row, entry))
    if len(said) <= FINDING_VALUE_LIMIT:
        return safe_finding_value(said)
    counts = []
    for key, one, many in (
        ("imports", "import", "imports"),
        ("resolved", "resolved name", "resolved names"),
        ("decoded_strings", "decoded string", "decoded strings"),
        ("plain_strings", "plain string", "plain strings"),
        ("capa", "capa rule", "capa rules"),
    ):
        n = len([c for c in row.get(key) or [] if isinstance(c, Mapping)])
        if n:
            counts.append(f"{n} {one if n == 1 else many}")
    callers, callees = len(row.get("callers") or []), len(row.get("callees") or [])
    counted = ", ".join(counts) or "no artefact of its own"
    return safe_finding_value(
        f"{counted} ({safe_finding_value(entry)}); called by {callers}, calls {callees} "
        f"{'function' if callees == 1 else 'functions'}"
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
        apis, strings = named_values(sentence, facts.run_names)
        if facts.absent:
            out.not_checked.append(f"claim {number}: {facts.absent}")
            continue
        listing_ids = {e.lower() for f in about for e in f.entries}
        sources: list[_Held] = [facts.listings[i] for i in listing_ids if i in facts.listings]
        reason = ""
        api_reason = ""
        starts: list[int] = []
        callee_count = 0
        for function in about:
            start = facts.offset(function.address)
            if start is None:
                reason = (
                    NO_ADDRESS.format(name=safe_finding_value(function.names[0]))
                    if function.address is None
                    else NOT_KNOWN.format(address=hex(function.address))
                )
                break
            where = facts.va(start)
            if facts.shown is not None and start in facts.rows and start not in facts.shown:
                reason = ROW_NOT_SHOWN.format(address=where)
                break
            callees = facts.callees.get(start)
            row_callees = facts.callee_rows.get(start, [])
            if facts.undecoded is None:
                reason = UNDECODED_UNKNOWN.format(entry=facts.index_entry)
                break
            if facts.undecoded & {start, *(callees or row_callees)}:
                reason = UNDECODED.format(address=where)
                break
            if not api_reason:
                if facts.unnamed is None:
                    api_reason = UNNAMED_UNKNOWN.format(entry=facts.index_entry)
                elif callees is None:
                    api_reason = CALLEES_UNKNOWN.format(address=where)
                elif any(facts.unnamed.get(o) for o in (start, *callees)):
                    api_reason = UNNAMED_CALLS.format(address=where)
            starts.append(start)
            neighbours = callees if callees is not None else row_callees
            callee_count += len(neighbours)
            for held_at in (start, *neighbours):
                if held_at in facts.held_by_row:
                    sources.append(facts.held_by_row[held_at])
            if start in facts.placed:
                sources.append(facts.placed[start])
        if reason:
            out.not_checked.append(f"claim {number}: {reason}")
            continue
        out.checked += 1
        if api_reason and apis:
            out.not_checked.append(f"claim {number}: {api_reason}")
        # The functions the claim names by their start, beside the ones it cites.
        for address in _addresses_written(sentence):
            other = facts.offset(address)
            if other is not None and other not in starts and other in facts.held_by_row:
                sources.append(facts.held_by_row[other])
        others = cited - listing_ids
        # A string the run holds nowhere is no string a tool recovered: a
        # paraphrase in quotes, or a value no function's facts could hold.
        strings = [value for value in strings if _held_by_cited(value, False, facts.every, facts)]
        unheld = [
            (value, api)
            for value, api in [
                *((a, True) for a in ([] if api_reason else apis)),
                *((s, False) for s in strings),
            ]
            if not _held(value, api, sources) and not _held_by_cited(value, api, others, facts)
        ]
        if not unheld:
            continue
        out.flagged.append(index)
        out.asked += 1
        out.violations.append(
            _question(
                index, number, sentence, about, starts, callee_count, unheld, facts, row_parts
            )
        )
    return out


def _question(
    index: int,
    number: int,
    sentence: str,
    about: Sequence[DecompiledFunction],
    starts: Sequence[int],
    callees: int,
    unheld: Sequence[tuple[str, bool]],
    facts: FunctionFacts,
    row_parts: Any,
) -> Any:
    from maljan.pipeline.validation import Violation

    values = [f'"{safe_finding_value(value)}"' for value, _api in unheld]
    named = values[0] if len(values) == 1 else ", ".join(values[:-1]) + f" and {values[-1]}"
    none = " or ".join(values)
    which = ", ".join(_function_words(f) for f in about)
    entry = f"[{safe_finding_value(facts.index_entry)}]"
    if len(about) == 1:
        head = f"function {which}"
        sources = f"the listing, its index row {entry} and its {callees} callees' rows"
    else:
        head = f"functions {which}"
        sources = f"their listings, their index rows {entry} and their {callees} callees' rows"
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
            f"{sources} hold no {none}; {'; '.join(holds)}. A claim about a function is "
            "published as what that function's code does. Keep the claim if its code shows "
            "it and say where, correct the name or the function it is given to, or withdraw "
            "the claim, with a reason; what you answer stands."
        ),
        path=f"claims[{index}]",
    )
