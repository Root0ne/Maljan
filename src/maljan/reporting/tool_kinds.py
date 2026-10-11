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

The consumers' kinds are ``core.builtin_declarations.CONSUMER_KINDS``; the
section builders' are ``BUILDER_OF_KIND``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from maljan.core.builtin_declarations import BUILDER_OF_KIND, CONSUMER_KINDS
from maljan.core.tool_declarations import SourceRef, ToolDeclarations, ToolFacts, renamed_tool
from maljan.reporting import legacy_tool_names as legacy

_held: list[tuple[Any, ToolDeclarations]] = []

# A technique id as an ATT&CK label carries it, written as ATT&CK writes it.
_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def declarations() -> ToolDeclarations:
    """The declarations in force: built from the process's settings, rebuilt when they change."""
    from maljan.core.config import get_settings

    settings = get_settings()
    if _held and _held[0][0] is settings:
        return _held[0][1]
    built = ToolDeclarations.from_settings(settings)
    _held[:] = [(settings, built)]
    return built


def tool_of(entry: Any) -> str:
    """The tool an entry, an index row or a captured output names."""
    if isinstance(entry, Mapping):
        return str(entry.get("tool") or entry.get("tool_name") or "")
    return str(getattr(entry, "tool", None) or getattr(entry, "tool_name", None) or "")


def source_of(entry: Any) -> SourceRef | None:
    """The source an entry recorded, or ``None`` for one read by the legacy tables."""
    return ToolDeclarations.source_of(entry)


def facts_of(entry: Any, tool: str | None = None) -> ToolFacts | None:
    """The declaration an entry's tool is read by.

    By the entry's recorded source and its tool together; for an entry with no
    source, the shipped declaration of the built-in tool of that name, which
    is what such an entry's tool was. ``tool`` overrides the name read from
    the entry.
    """
    name = tool if tool is not None else tool_of(entry)
    ref = source_of(entry)
    if ref is None:
        return legacy.builtin_facts(name)
    return declarations().declaration_for((ref, name))


def declared_facts(entry: Any) -> ToolFacts | None:
    """The declaration of an entry that recorded its source; ``None`` for one that did not.

    For a reader that reads declared paths only where a declaration said
    them, and an entry with no source the way it always read it.
    """
    if source_of(entry) is None:
        return None
    return declarations().declaration_for((source_of(entry), tool_of(entry)))


def from_a_builtin_source(entry: Any) -> bool:
    """Whether an entry's recorded source is one the platform ships a declaration for."""
    from maljan.core.builtin_declarations import builtin_server_names, in_process_declarations
    from maljan.core.tool_declarations import PROVIDER_BLOCKS

    ref = source_of(entry)
    if ref is None:
        return False
    if ref.kind == "mcp":
        return ref.key in builtin_server_names()
    return str(ref) in PROVIDER_BLOCKS or ref in in_process_declarations()


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
                match = _TECHNIQUE_ID.search(str(item or ""))
                if match:
                    out.append(match.group(0))
    return out


def declared_name(entry: Any) -> str:
    """An entry's tool under the name its server declares it, a renamed tool's prefix off."""
    name = tool_of(entry)
    ref = source_of(entry)
    return renamed_tool(ref.key, name) if ref is not None and ref.kind == "mcp" else name


def kind_of(entry: Any, tool: str | None = None) -> str:
    """An entry's declared kind, or ``""`` when its tool declares none."""
    facts = facts_of(entry, tool)
    return facts.kind if facts is not None else ""


def consumer_kinds(consumer: str) -> frozenset[str]:
    """The kinds a reporting consumer reads (``CONSUMER_KINDS``, following ``same_as``)."""
    return frozenset(consumer_kinds_in_order(consumer))


def consumer_kinds_in_order(consumer: str) -> tuple[str, ...]:
    """A consumer's kinds in the order ``CONSUMER_KINDS`` lists them."""
    spec = CONSUMER_KINDS[consumer]
    if "same_as" in spec:
        spec = CONSUMER_KINDS[spec["same_as"]]
    return tuple(spec["kinds"])


def is_of(entry: Any, consumer: str, tool: str | None = None) -> bool:
    """Whether a consumer reads this entry: by its declared kind, or by its legacy table."""
    name = tool if tool is not None else tool_of(entry)
    if source_of(entry) is None:
        return legacy.in_table(consumer, name)
    return kind_of(entry, name) in consumer_kinds(consumer)


def builder_of(entry: Any) -> str | None:
    """The name of the section builder an entry is drawn with, or ``None`` for the generic block."""
    if source_of(entry) is None:
        return legacy.BUILDERS.get(tool_of(entry))
    return BUILDER_OF_KIND.get(kind_of(entry))


def sources_of_kind(kind: str) -> frozenset[str]:
    """The names the tools of ``kind`` record their technique hits under, legacy ones included.

    A tool's declared corroboration name (``ToolFacts.source``), else its own
    name, for every declared tool of the kind; and the names a stored report's
    hits of that kind carry (``legacy_tool_names.HIT_SOURCES``).
    """
    held = declarations()
    key = (id(held), kind)
    if key not in _sources_memo:
        named = {facts.source or tool for _ref, tool, facts in held.tools_of_kind(kind)}
        if any(other != id(held) for other, _kind in _sources_memo):
            _sources_memo.clear()
        _sources_memo[key] = frozenset(named | set(legacy.HIT_SOURCES.get(kind, ())))
    return _sources_memo[key]


_sources_memo: dict[tuple[int, str], frozenset[str]] = {}


def display_name(entry: Any, tool: str | None = None) -> str:
    """The name published text gives an entry's tool: its declared display name, else its name."""
    name = tool if tool is not None else tool_of(entry)
    facts = facts_of(entry, name)
    return (facts.display_name if facts is not None else "") or name


def index_by_id(rows: Iterable[Any]) -> dict[str, Any]:
    """A report's evidence index rows by entry id."""
    return {str(_field(row, "id") or ""): row for row in rows or ()}


def section_entry(section: Any, index: Mapping[str, Any]) -> Any:
    """The index row of the entry that opened a tool section, or a source-less stand-in.

    A section built from a tool's answers is named after that tool
    (``source`` ``tool:<name>``) and cites its entries; the first cited row of
    that tool carries the source the tool is read by. A section whose cited
    rows are not in the index is read as a source-less entry of its tool.
    """
    origin = str(_field(section, "source") or "")
    tool = origin.removeprefix("tool:") if origin.startswith("tool:") else ""
    for entry_id in _field(section, "evidence_ids") or ():
        row = index.get(str(entry_id))
        if row is not None and tool_of(row) == tool:
            return row
    return {"tool": tool}


def _field(obj: Any, name: str) -> Any:
    return obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)
