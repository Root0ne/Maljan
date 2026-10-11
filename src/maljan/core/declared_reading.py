"""How a consumer reads a ledger entry by what its tool declares, never by its name.

The one reader the platform reads an entry's tool by (evidence summary,
evidence roots, validation, the function map, the triage pack's joins). Two
halves:

**The writer** (:func:`facts_record`). When an entry is written with the
source its tool is declared under (``LedgerEntry.source``: ``mcp:<key>``,
``provider:<id>``, ``sandbox``, ``pack``), the tool's declaration under that
source, as the run's settings hold it, is resolved once and stored on the
entry (``LedgerEntry.facts``), versioned and small: ``{"v": 1, "kind": ...}``
and, where set, ``reader``, ``asserts_techniques``, ``source``,
``display_name``, ``rows``, ``places``, ``values``, ``techniques``,
``reputation``, ``words`` and ``report_sections``. ``{"v": 1}`` alone records
that the source declares nothing for the tool.

**The reader** (:func:`facts_of`, :func:`kind_of`, :func:`reads_as`). It reads
the facts the entry stored, never the reading process's settings, so a run
reads the same in the worker, in a later stage and in the API, which renders
without the operator's settings. A tool whose source declared nothing has no
facts, whatever its name: a user tool sharing a built-in's name gets nothing
from the built-in. An entry with no stored facts (every entry written before
facts were recorded: the stored runs) is read by the **legacy reading**: the
facts the platform ships for its bare tool name (the server prefix a name
collision adds taken off), from the built-in declarations alone. Those are the
name tables the code read before (``builtin_declarations.CONSUMER_KINDS``, held
tool by tool by
``tests/unit/core/test_every_built_in_declares_what_its_name_tables_say.py``),
so a stored entry reads as it always did; a consumer table's ``legacy_names``
count for such an entry only.

**Live declarations** (:func:`declarations`) are read only where nothing
persisted depends on the result: by the writer above; by an evidence-only
provider naming the tool its answer is recorded under (a writer too); by the
report step deciding whether the pack already holds that provider's answers
(:func:`kinds_declared_by`), which decides only whether the provider runs; and
by the recorder deciding whether a hash resolution's names are the platform's
own (``platform_owned``) for the job's own scrub, made as the entry is written.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Mapping
from functools import cache, lru_cache
from typing import TYPE_CHECKING, Any

from maljan.core.tool_declarations import ToolDeclarations, ToolFacts

if TYPE_CHECKING:
    from maljan.core.config import Settings

_LOCK = threading.Lock()
# The declarations of the settings object last asked for, held with that object
# so a new settings object (a job's ``install_settings``) builds afresh.
_HELD: list[Any] = [None, None]

# The version of the stored facts' shape, and the fields of ``ToolFacts`` it holds.
FACTS_VERSION = 1
STORED_FACT_FIELDS: tuple[str, ...] = (
    "kind",
    "reader",
    "asserts_techniques",
    "source",
    "display_name",
    "rows",
    "places",
    "values",
    "techniques",
    "reputation",
    "words",
    "report_sections",
)


def declarations(settings: Settings | None = None) -> ToolDeclarations:
    """The live declarations: of ``settings``, else of the process's settings.

    Built once per settings object; a job that installs its own settings gets
    its own declarations on the next call. Read only where nothing persisted
    depends on the result (the module docstring).
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


# ---------------------------------------------------------------------------
# The writer
# ---------------------------------------------------------------------------


def stored_record(facts: ToolFacts | None) -> dict[str, Any]:
    """The stored form of one tool's facts: the version and every field it set."""
    record: dict[str, Any] = {"v": FACTS_VERSION}
    if facts is None:
        return record
    dumped = facts.model_dump(mode="json", exclude_defaults=True, include=set(STORED_FACT_FIELDS))
    dumped["kind"] = facts.kind
    for name in STORED_FACT_FIELDS:
        if name in dumped:
            record[name] = dumped[name]
    return record


def facts_record(
    source: str, tool: str, *, declared: ToolDeclarations | None = None
) -> dict[str, Any] | None:
    """What ``tool`` declares under ``source`` now, in its stored form; ``None`` when unreadable.

    Called once, when the entry is written. Settings that cannot be read store
    nothing, and the entry is then read by the legacy reading.
    """
    try:
        held = declared or declarations()
        return stored_record(held.declaration_for((source, tool)))
    except Exception as exc:  # noqa: BLE001 — a record is never worth a lost entry
        from maljan.core.logger import logger

        logger.debug("declared facts of %s under %s not recorded (%s).", tool, source, exc)
        return None


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------


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


def has_stored_facts(entry: Any) -> bool:
    """Whether ``entry`` stored the facts its tool declared when it was written."""
    held = _field(entry, "facts")
    return isinstance(held, Mapping) and held.get("v") == FACTS_VERSION


@lru_cache(maxsize=4096)
def _parsed(text: str) -> ToolFacts | None:
    held = json.loads(text)
    if "kind" not in held:
        return None
    return ToolFacts.model_validate({k: v for k, v in held.items() if k != "v"})


def facts_of(entry: Any) -> ToolFacts | None:
    """The facts an entry's tool declared, as the entry stored them; the legacy reading else.

    ``entry`` is a ledger entry, or a mapping with ``tool`` and, where it
    stored them, ``facts``. Never reads the reading process's settings.
    """
    if has_stored_facts(entry):
        return _parsed(json.dumps(dict(_field(entry, "facts")), sort_keys=True))
    return shipped_by_name().get(bare_name(_field(entry, "tool")))


def kind_of(entry: Any) -> str:
    """The kind an entry's tool declares, ``""`` when it declares none."""
    facts = facts_of(entry)
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


def reads_as(entry: Any, consumer: str) -> bool:
    """Whether ``entry``'s tool is of a kind the named consumer reads.

    By the entry's stored kind; an entry with no stored facts by the legacy
    reading, and by the consumer's ``legacy_names``.
    """
    facts = facts_of(entry)
    if facts is not None and facts.kind in consumer_kinds(consumer):
        return True
    if has_stored_facts(entry):
        return False
    return bare_name(_field(entry, "tool")) in legacy_names(consumer)


# ---------------------------------------------------------------------------
# Live reads, where nothing persisted depends on the result
# ---------------------------------------------------------------------------


def kinds_declared_by(source: str, *, declared: ToolDeclarations | None = None) -> frozenset[str]:
    """Every kind ``source``'s live declaration names a tool under (``provider:<id>`` …)."""
    held = (declared or declarations()).source(source)
    if held is None:
        return frozenset()
    return frozenset(facts.kind for facts in held.tools.values())
