"""What the report reads a ledger entry's tool as: its declared kind, never its name.

Every reporting consumer that once kept a table of tool names asks here
instead. An entry that recorded the source of its tool when it was written
(``LedgerEntry.source``, carried onto the report's evidence index and the
captured outputs) is read by that source's declaration
(``core.tool_declarations``): its ``kind``, its ``display_name``, the report
sections it declares. Any server that declares a tool of a kind gets the
treatment the kind gets, and a tool that shares a built-in's name but declares
nothing gets nothing from the built-in.

An entry with no recorded source (everything written before sources were) is
read by the tables it was always read by, kept in one marked module
(``reporting.legacy_tool_names``), so a stored run re-renders byte for byte.
This module is the only one that imports it, and only on the branches for an
entry, or a stored record, with no source (``tests/unit/reporting/
test_no_reporting_module_reads_a_tool_by_its_name.py``); functions named
``stored_*`` serve records written before sources and read it whole.

The consumers' kinds are ``core.builtin_declarations.CONSUMER_KINDS``; the
section builders' are ``BUILDER_OF_KIND``.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from functools import cache
from typing import Any

from maljan.analysis.technique_ids import TECHNIQUE_WORD_RE
from maljan.core import declared_reading
from maljan.core.builtin_declarations import BUILDER_OF_KIND, CONSUMER_KINDS
from maljan.core.tool_declarations import SourceRef, ToolDeclarations, ToolFacts
from maljan.reporting import legacy_tool_names as legacy


def tool_of(entry: Any) -> str:
    """The tool an entry, an index row or a captured output names."""
    if isinstance(entry, Mapping):
        return str(entry.get("tool") or entry.get("tool_name") or "")
    return str(getattr(entry, "tool", None) or getattr(entry, "tool_name", None) or "")


def section_tool(section: Any) -> str:
    """The tool a section built from a tool's answers is named after (``tool:<name>``)."""
    origin = str(_field(section, "source") or "").strip()
    return origin.removeprefix("tool:") if origin.startswith("tool:") else ""


def source_of(entry: Any) -> SourceRef | None:
    """The source an entry recorded, or ``None`` for one read by the legacy tables."""
    return ToolDeclarations.source_of(entry)


def stored(entry: Any) -> bool:
    """Whether an entry, index row or captured output carries the facts its entry stored."""
    return declared_reading.has_stored_facts(entry)


def read_by_name(entry: Any) -> bool:
    """Whether an entry is read by the legacy tables: it recorded no source and no facts."""
    return not stored(entry) and source_of(entry) is None


def facts_of(entry: Any, tool: str | None = None) -> ToolFacts | None:
    """The facts an entry's tool declared, as the entry stored them when it was written.

    Read through ``core.declared_reading`` from the record the entry (or the
    index row or captured output it was copied onto) carries, never from the
    reading process's settings. An entry with a source and no record reads as
    an undeclared tool; one with no source and no record by the shipped facts
    of the built-in tool of its exact name, as the report always read it.
    ``tool`` names the tool for that reading in place of the entry's own.

    That legacy reading looks the exact name up, where
    ``declared_reading``'s takes a ``<server>__`` prefix off first: the
    report's tables never took one off, and a stored run re-renders as it did.
    """
    if stored(entry):
        return declared_reading.facts_of(entry)
    if source_of(entry) is None:
        return legacy.builtin_facts(tool if tool is not None else tool_of(entry))
    return None


def kind_free_facts(entry: Any, tool: str | None = None) -> ToolFacts:
    """The facts an entry's tool declared that are read without a kind, whatever its kind.

    :func:`facts_of` for a tool of a kind; for a stored record of no kind,
    the fields it stores that are read without one
    (``declared_reading.kind_free_facts``); an empty declaration for none.
    """
    if stored(entry):
        return declared_reading.kind_free_facts(entry)
    facts = facts_of(entry, tool)
    return facts if facts is not None else ToolFacts.model_construct()


def declared_facts(entry: Any) -> ToolFacts | None:
    """The stored facts of an entry; ``None`` for one read by the legacy tables.

    For a reader that reads declared paths only where a declaration said
    them, and an entry with no source the way it always read it.
    """
    if read_by_name(entry):
        return None
    return facts_of(entry)


@cache
def _builtin_sources() -> frozenset[SourceRef]:
    """The sources the platform ships a declaration for, read once."""
    from maljan.core.builtin_declarations import builtin_server_names, in_process_declarations
    from maljan.core.tool_declarations import shipped_provider_blocks

    refs = {SourceRef("mcp", key) for key in builtin_server_names()}
    refs |= {SourceRef.parse(text) for text in shipped_provider_blocks()}
    refs |= set(in_process_declarations())
    return frozenset(refs)


def from_an_operator_source(entry: Any) -> bool:
    """Whether an entry recorded a source the platform ships no declaration for."""
    ref = source_of(entry)
    return ref is not None and ref not in _builtin_sources()


def row_technique_ids(row: Mapping[str, Any], facts: ToolFacts) -> list[str]:
    """The technique ids one rule row names, where the declaration says, in that order.

    Each declared field is read inside the row: an ``attck`` label gives the
    one id it carries, a ``sigma_tag`` the id its tag spells.
    """
    from maljan.analysis.technique_ids import sigma_technique_ids
    from maljan.core.tool_declarations import select

    out: list[str] = []
    for field in facts.techniques:
        for found in select(row, field.path):
            items = found if isinstance(found, list) else [found]
            if field.format == "sigma_tag":
                out.extend(sigma_technique_ids({"tags": items}))
                continue
            for item in items:
                match = TECHNIQUE_WORD_RE.search(str(item or ""))
                if match:
                    out.append(match.group(0))
    return out


def declared_name(entry: Any) -> str:
    """An entry's tool under the name its source declares it.

    For an entry that recorded its source, the original name its call
    recorded where the request offered the tool renamed, else its own
    (``declared_reading.declared_name``): a ``<server>__`` prefix is never
    taken off by the name alone. An entry with no source keeps its own name.
    """
    if source_of(entry) is None:
        return tool_of(entry)
    return declared_reading.declared_name(entry)


def kind_of(entry: Any, tool: str | None = None) -> str:
    """An entry's declared kind, or ``""`` when its tool declares none.

    With no source, the kind the built-in tool of its name declares.
    """
    facts = facts_of(entry, tool)
    return facts.kind if facts is not None else ""


def is_kind(entry: Any, kind: str) -> bool:
    """Whether an entry's tool is of ``kind`` (by its name's built-in kind with no source)."""
    return kind_of(entry) == kind


def consumer_kinds(consumer: str) -> frozenset[str]:
    """The kinds a reporting consumer reads (``CONSUMER_KINDS``, following ``same_as``)."""
    return frozenset(consumer_kinds_in_order(consumer))


def consumer_kinds_in_order(consumer: str) -> tuple[str, ...]:
    """A consumer's kinds in the order ``CONSUMER_KINDS`` lists them."""
    spec = CONSUMER_KINDS[consumer]
    if "same_as" in spec:
        spec = CONSUMER_KINDS[spec["same_as"]]
    return tuple(spec["kinds"])


def undeclared_code_kind(entry: Any, tool: str | None = None) -> str:
    """The code-listing kind an entry's tool's name says, where its source declares nothing for it.

    The one name reading of a code listing (``core.undeclared_tools``), which
    the agent side reads an undeclared tool by: an entry that recorded its
    source and stored no kind for its tool is a decompiler's listing when its
    name says so, here as in the function map. ``""`` for an entry whose tool
    declares a kind (it keeps that kind) and for one read by the legacy
    tables.
    """
    from maljan.core.undeclared_tools import undeclared_code_kind as named_code_kind

    if read_by_name(entry) or facts_of(entry) is not None:
        return ""
    if tool is not None:
        return named_code_kind(tool)
    return named_code_kind(declared_name(entry))


def code_family_kind(entry: Any) -> str:
    """The kind an entry's code is read as, whatever tool listed it; ``""`` for no code.

    ``decompile`` for any decompiled code, of one function, of a batch or of
    one decompiled afresh (``core.undeclared_tools.DECOMPILE_KINDS``); the
    declared kind of a code listing as instructions. A tool its source
    declares nothing for is read by its name (:func:`undeclared_code_kind`),
    else by its answer: one that lists several functions' code, each naming
    the function it stands under (:func:`_self_named_parts`), is decompiled
    code. An entry read by the legacy tables has none here and is read by
    those tables alone.
    """
    from maljan.core.undeclared_tools import CODE_LISTING_KINDS, DECOMPILE_KINDS

    if read_by_name(entry):
        return ""
    facts = facts_of(entry)
    if facts is not None:
        if facts.kind in DECOMPILE_KINDS:
            return "decompile"
        return facts.kind if facts.kind in CODE_LISTING_KINDS else ""
    named = undeclared_code_kind(entry)
    if named:
        return named
    return "decompile" if _self_named_parts(entry) else ""


def _self_named_parts(entry: Any) -> list[Any]:
    """The functions an undeclared tool's answer lists, when each names the one it stands under.

    A string table, a cross-reference map or a rule's matches keyed by
    address holds other text under each key; a decompiler's batch holds each
    function's own name or its first instruction's address there
    (``core.undeclared_tools.names_itself``).
    """
    from maljan.core.undeclared_tools import code_parts, names_itself

    parts = code_parts(_field(entry, "output"))
    return parts if parts and all(names_itself(part) for part in parts) else []


def reads_code(entry: Any, consumer: str) -> bool:
    """Whether a consumer of a function's code reads this entry.

    By :func:`is_of`, and by the kind the entry's code is read as
    (:func:`code_family_kind`): a batch of decompiled functions is read where
    one decompiled function is.
    """
    if is_of(entry, consumer):
        return True
    kind = code_family_kind(entry)
    return bool(kind) and kind in consumer_kinds(consumer)


def function_parts(entry: Any) -> list[Any]:
    """The functions a batch's answer lists one by one (``core.undeclared_tools.CodePart``).

    For a tool that declares itself a batch of decompiled functions
    (``decompile_batch``), read at the paths its declaration names
    (``values`` ``code``, ``address`` and ``name``, inside ``rows``); for a
    tool its source declares nothing for, only when each function names the
    one it stands under (:func:`_self_named_parts`). ``[]`` for every other
    entry: a declared single decompile is one listing whatever its answer's
    shape, and an entry read by the legacy tables is drawn as it always was.
    """
    from maljan.core.undeclared_tools import code_parts

    if read_by_name(entry):
        return []
    facts = facts_of(entry)
    if facts is None:
        return _self_named_parts(entry)
    if facts.kind != "decompile_batch":
        return []
    values = facts.values
    named = (str(values.get("address", "") or ""), str(values.get("name", "") or ""))
    return code_parts(
        _field(entry, "output"), str(values.get("code", "") or ""), str(facts.rows or ""), named
    )


def part_citation(entry_id: str, part: Any) -> str:
    """How one function of an entry's answer is cited: the entry, then the function.

    The ledger's form for a part of an entry (``ev_0024 (row 0x3868)``): the
    entry id, which a citation resolves by, and in brackets the function's
    address or name, or its place in the answer.
    """
    where = str(part.where)
    reference = where if where.startswith("item ") else f"function {where}"
    return f"{entry_id} ({reference})"


def is_of(entry: Any, consumer: str, tool: str | None = None) -> bool:
    """Whether a consumer reads this entry: by its stored kind, or by its legacy table.

    A tool its source declares nothing for is read by the code-listing kind
    its name says (:func:`undeclared_code_kind`), and by nothing else.
    """
    name = tool if tool is not None else tool_of(entry)
    if stored(entry):
        facts = facts_of(entry)
        if facts is not None:
            return facts.kind in consumer_kinds(consumer)
    elif source_of(entry) is None:
        return legacy.in_table(consumer, name)
    return undeclared_code_kind(entry, tool) in consumer_kinds(consumer)


def rank_in(entry: Any, consumer: str) -> int:
    """Where a consumer that lists tools in an order puts an entry: its kind's place, or last."""
    if not stored(entry) and source_of(entry) is None:
        return stored_rank(consumer, tool_of(entry))
    order = consumer_kinds_in_order(consumer)
    kind = kind_of(entry)
    return order.index(kind) if kind in order else len(order)


def builder_of(entry: Any) -> str | None:
    """The name of the section builder an entry is drawn with, or ``None`` for the generic block."""
    if read_by_name(entry):
        return stored_builder_of(tool_of(entry))
    return BUILDER_OF_KIND.get(kind_of(entry))


def shown_by_name(section: str, output: Any) -> bool | None:
    """Whether a captured output with no source was shown to a composer section, by its name.

    ``None`` for an output that recorded its source, which is read by kind.
    """
    if read_by_name(output):
        return stored_section_hint(section, tool_of(output))
    return None


def looked_at_the_file_by_name(entry: Any) -> bool | None:
    """Whether the report counted an entry with no source as one that looked at the file.

    ``None`` for an entry that recorded its source, which is read by kind.
    """
    if read_by_name(entry):
        return stored_looked_at_the_file(tool_of(entry))
    return None


def hit_of_kind(hit: Mapping[str, Any], kind: str) -> bool:
    """Whether a technique hit came from a tool of ``kind``.

    A hit records its tool's kind when it is projected (``kind``); a hit of a
    report stored before is read by the name it was recorded under.
    """
    recorded = str(hit.get("kind") or "")
    if recorded:
        return recorded == kind
    return str(hit.get("source") or "") in stored_hit_sources(kind)


def stored_hit_sources(kind: str) -> set[str]:
    """The names a stored report's technique hits of ``kind`` were recorded under."""
    return set(legacy.HIT_SOURCES.get(kind, ()))


def recovering_facts(entry: Any) -> ToolFacts | None:
    """The declaration a recovery record reads an entry by, or ``None``.

    By the entry's recorded source; an entry with no source by the built-in
    tool of its name, a server's renamed tool (``analysis__floss``) read
    without its prefix, as before.
    """
    if read_by_name(entry):
        return stored_facts_by_name(tool_of(entry).rsplit("__", 1)[-1])
    return facts_of(entry)


def recovery_tool(entry: Any, facts: ToolFacts) -> tuple[str, str, str]:
    """How a recovery names its tool, as ``(tool, kind, named)``.

    The entry's tool, its declared kind and display name for an entry that
    recorded its source; for one that did not, the tool such a record always
    named and no kind, so it is written as before.
    """
    if read_by_name(entry):
        return stored_tool_of_kind(facts.kind), "", ""
    return tool_of(entry), facts.kind, facts.display_name


def stated_name(entry: Any, facts: ToolFacts) -> str:
    """The name a partial reason gives an entry's tool: its display name, or the stored word."""
    if read_by_name(entry):
        return stored_word_of_kind(facts.kind)
    return facts.display_name or tool_of(entry)


def stored_reputation_counts(rows: Mapping[str, str]) -> tuple[str, str, str]:
    """``(flagged, engines, source)`` of a report stored before reputation records.

    Read from the key/value rows of the section its lookups were drawn in, as
    the report always read them (``core.legacy_reputation``).
    """
    from maljan.core.legacy_reputation import stored_report_counts

    return stored_report_counts(rows)


def stored_builder_of(tool: str) -> str | None:
    """The section builder a source-less entry of ``tool`` was drawn with."""
    return legacy.BUILDERS.get(tool)


def stored_section_hint(section: str, tool: str) -> bool:
    """Whether a source-less captured output of ``tool`` was shown to ``section``."""
    return legacy.section_hinted(section, tool)


def stored_looked_at_the_file(tool: str) -> bool:
    """Whether the report counted a source-less entry of ``tool`` as one that read the file."""
    return legacy.looked_at_the_file(tool)


def stored_facts_by_name(tool: str) -> ToolFacts | None:
    """The shipped facts of the built-in tool named ``tool``, for a source-less entry."""
    return legacy.builtin_facts(tool)


def stored_rank(consumer: str, tool: str) -> int:
    """Where a consumer's fixed order listed ``tool`` (a source-less entry)."""
    return legacy.rank(consumer, tool)


def stored_tool_of_kind(kind: str) -> str:
    """The tool a recovery of ``kind`` stored before kinds were recorded names."""
    return legacy.STORED_TOOL_BY_KIND.get(kind, "")


def stored_word_of_kind(kind: str) -> str:
    """The word a stored record's partial reason names the entries of ``kind`` by."""
    return legacy.STORED_WORD_BY_KIND.get(kind, "")


def recovery_kind(how: Any) -> str:
    """The kind of one recovery: as recorded, or, on a record stored before, by its tool."""
    recorded = str(getattr(how, "kind", "") or "")
    return recorded or stored_recovery_kind(how)


def stored_recovery_kind(how: Any) -> str:
    """The kind a stored recovery with no kind recorded is read as, by the tool it names."""
    return legacy.stored_recovery_kind(tool_of(how))


def recovery_name(how: Any) -> str:
    """The name a recovery is stated under: its recorded display name, else its tool."""
    return str(getattr(how, "named", "") or "") or tool_of(how)


def sweeps_the_strings(row: Any, named: str) -> bool:
    """Whether an entry is the string sweep's.

    By its index row's declared kind when it recorded a source; else by its
    tool's name (``named``: a section's or the corpus's tool), as before.
    """
    if row is not None and not read_by_name(row):
        return is_of(row, "stix_renderer._STRING_SWEEP_TOOLS")
    return is_of({"tool": named}, "stix_renderer._STRING_SWEEP_TOOLS")


def display_name(entry: Any, tool: str | None = None) -> str:
    """The name published text gives an entry's tool: its declared display name, else its name.

    A declaration that names no kind still names the tool
    (:func:`kind_free_facts`), though it declares nothing else.
    """
    name = tool if tool is not None else tool_of(entry)
    return kind_free_facts(entry, name).display_name or name


def section_title(entry: Any) -> str:
    """The title of a section built from an entry's answers by the generic reading.

    An operator's tool is titled by the name its declaration gives it, with
    a kind or without (:func:`display_name`); every other tool by its name,
    as its sections always were, so a stored run and the built-ins draw as
    before.
    """
    plain = tool_of(entry).replace("_", " ").capitalize()
    if not from_an_operator_source(entry):
        return plain
    # The name the stored record gives, with a kind or without; none: its name.
    return declared_reading.named_facts(entry)[0] or plain


def index_by_id(rows: Iterable[Any]) -> dict[str, Any]:
    """A report's evidence index rows by entry id."""
    return {str(_field(row, "id") or ""): row for row in rows or ()}


def section_entry(section: Any, index: Mapping[str, Any]) -> Any:
    """The index row of the entry that opened a tool section, or a source-less stand-in.

    A section built from a tool's answers is named after that tool and cites
    its entries; the first cited row of that tool carries the source the tool
    is read by. A section whose cited rows are not in the index is read as a
    source-less entry of its tool.
    """
    tool = section_tool(section)
    for entry_id in _field(section, "evidence_ids") or ():
        row = index.get(str(entry_id))
        if row is not None and tool_of(row) == tool:
            return row
    return {"tool": tool}


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)
