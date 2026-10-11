"""How a consumer reads a ledger entry by what its tool declares, never by its name.

The one way the reading half of the platform (evidence summary, evidence
roots, validation, the function map, the triage pack's joins) asks what an
entry's tool is:

* an entry that recorded its source (``LedgerEntry.source``: ``mcp:<key>``,
  ``provider:<id>``, ``sandbox``, ``pack``) is read by the declaration of its
  tool under that source, as the run's settings hold it
  (:class:`~maljan.core.tool_declarations.ToolDeclarations`); a tool its
  source does not declare has no facts, whatever its name, so a user tool that
  shares a built-in's name gets nothing from the built-in;
* an entry with no recorded source (every entry written before sources were
  recorded: the stored runs) is read by the **legacy reading**: the facts the
  platform ships for its bare tool name (the server prefix a name collision
  adds taken off), from the built-in declarations alone, never from today's
  settings. The built-in declarations are exactly the name tables the code
  read before (``builtin_declarations.CONSUMER_KINDS``, held tool by tool by
  ``tests/unit/core/test_every_built_in_declares_what_its_name_tables_say.py``),
  so a stored entry is read as it always was. A consumer table's
  ``legacy_names`` (names it held that no built-in tool has) count for an
  entry with no recorded source only.

A consumer asks :func:`reads_as` (is this entry in the set of kinds a named
consumer reads), :func:`facts_of` (the entry's facts) or :func:`kind_of`.
"""

from __future__ import annotations

import threading
from collections.abc import Iterable, Mapping
from functools import cache
from typing import TYPE_CHECKING, Any

from maljan.core.tool_declarations import ToolDeclarations, ToolFacts

if TYPE_CHECKING:
    from maljan.core.config import Settings

_LOCK = threading.Lock()
# The declarations of the settings object last asked for, held with that object
# so a new settings object (a job's ``install_settings``) builds afresh.
_HELD: list[Any] = [None, None]


def declarations(settings: Settings | None = None) -> ToolDeclarations:
    """The declarations in force: of ``settings``, else of the process's settings.

    Built once per settings object; a job that installs its own settings gets
    its own declarations on the next call.
    """
    if settings is None:
        from maljan.core.config import get_settings

        settings = get_settings()
    with _LOCK:
        if _HELD[0] is not settings:
            _HELD[1] = ToolDeclarations.from_settings(settings)
            _HELD[0] = settings
        return _HELD[1]  # type: ignore[no-any-return]


def forget() -> None:
    """Drop the held declarations (for a caller that changed settings in place)."""
    with _LOCK:
        _HELD[0] = None
        _HELD[1] = None


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def bare_name(tool: Any) -> str:
    """A tool's own name, without the ``<server>__`` a name collision adds."""
    return str(tool or "").rsplit("__", 1)[-1]


def recorded(entry: Any) -> bool:
    """Whether ``entry`` recorded the source its tool is declared under."""
    return ToolDeclarations.source_of(entry) is not None


@cache
def shipped_by_name() -> Mapping[str, ToolFacts]:
    """The facts the platform ships per bare tool name: the legacy reading of a stored entry.

    Every built-in source's declared tools (the built-in servers, the
    provider-owned blocks, the in-process sources). A name two built-in
    sources share carries one kind and one reading in both (held by
    ``tests/unit/core/test_entries_are_read_by_their_declared_kind.py``); the
    first source in that order gives its facts.
    """
    from maljan.core import builtin_declarations as shipped

    out: dict[str, ToolFacts] = {}

    def _take(tool_facts: Mapping[str, Any]) -> None:
        for name, raw in tool_facts.items():
            if name not in out:
                out[name] = raw if isinstance(raw, ToolFacts) else ToolFacts.model_validate(raw)

    for key in shipped.builtin_server_names():
        _take(shipped.server_declaration(key).get("tool_facts") or {})
    for provider in shipped.provider_names():
        _take(shipped.provider_declaration(provider).get("tool_facts") or {})
    for cfg in shipped.in_process_declarations().values():
        _take(cfg.tool_facts)
    return out


def facts_of(entry: Any, *, declared: ToolDeclarations | None = None) -> ToolFacts | None:
    """The facts an entry's tool declares; the legacy reading for an entry with no source.

    ``entry`` is a ledger entry, or a mapping with ``tool`` and, where it
    recorded one, ``source``.
    """
    if recorded(entry):
        return (declared or declarations()).declaration_for(entry)
    return shipped_by_name().get(bare_name(_field(entry, "tool")))


def kind_of(entry: Any, *, declared: ToolDeclarations | None = None) -> str:
    """The kind an entry's tool declares, ``""`` when it declares none."""
    facts = facts_of(entry, declared=declared)
    return facts.kind if facts is not None else ""


def _consumer(consumer: str) -> Mapping[str, Any]:
    from maljan.core.builtin_declarations import CONSUMER_KINDS

    spec = CONSUMER_KINDS[consumer]
    return CONSUMER_KINDS[spec["same_as"]] if "same_as" in spec else spec


@cache
def consumer_kinds(consumer: str) -> frozenset[str]:
    """The kinds a named consumer reads (``builtin_declarations.CONSUMER_KINDS``)."""
    return frozenset(_consumer(consumer)["kinds"])


@cache
def legacy_names(consumer: str) -> frozenset[str]:
    """The names a consumer's table held that no built-in tool has, for stored entries only."""
    return frozenset(_consumer(consumer).get("legacy_names", ()))


def reads_as(entry: Any, consumer: str, *, declared: ToolDeclarations | None = None) -> bool:
    """Whether ``entry``'s tool is of a kind the named consumer reads.

    By the entry's declared kind; an entry with no recorded source by the
    legacy reading, and by the consumer's ``legacy_names``.
    """
    facts = facts_of(entry, declared=declared)
    if facts is not None and facts.kind in consumer_kinds(consumer):
        return True
    return not recorded(entry) and bare_name(_field(entry, "tool")) in legacy_names(consumer)


def tools_of_kinds(
    kinds: Iterable[str], *, declared: ToolDeclarations | None = None, enabled_only: bool = True
) -> list[tuple[str, ToolFacts]]:
    """Every ``(tool name, facts)`` the settings in force declare under any of ``kinds``."""
    held = declared or declarations()
    return [
        (name, facts) for _ref, name, facts in held.tools_of_kind(kinds, enabled_only=enabled_only)
    ]


def kinds_declared_by(source: str, *, declared: ToolDeclarations | None = None) -> frozenset[str]:
    """Every kind ``source``'s declaration names a tool under (``mcp:<key>``, ``provider:<id>``)."""
    held = (declared or declarations()).source(source)
    if held is None:
        return frozenset()
    return frozenset(facts.kind for facts in held.tools.values())
