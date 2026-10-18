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
``reputation``, ``words``, ``report_sections``, ``arguments``, ``holds_strings``,
``function_starts`` and ``discloses_sample``. ``{"v": 1}`` alone records
that the source declares nothing for the tool.

**The reader** (:func:`facts_of`, :func:`kind_of`, :func:`reads_as`). It reads
the facts the entry stored, never the reading process's settings, so a run
reads the same in the worker, in a later stage and in the API, which renders
without the operator's settings. A tool whose source declared nothing has no
facts, whatever its name: a user tool sharing a built-in's name gets nothing
from the built-in. A record of a newer version is read for the fields this
version knows, and one the validators refuse as absent, each with a warning.
An entry with a source and no facts (written before facts were stored, or
whose settings could not be read) reads as an undeclared tool, never by its
name. An entry with no source and no facts (every entry written before sources
were recorded: the stored runs) is read by the **legacy reading**: the
facts the platform ships for its bare tool name (the server prefix a name
collision adds taken off), from the built-in declarations alone. Those are the
name tables the code read before (``builtin_declarations.CONSUMER_KINDS``, held
tool by tool by
``tests/unit/core/test_every_built_in_declares_what_its_name_tables_say.py``),
so a stored entry reads as it always did; a consumer table's ``legacy_names``
count for such an entry only.

The platform's in-process sources (``pack``, ``sandbox``,
``provider:capa_yara``) are declared by built-in data only, so their records
are written from it without the settings, even by a render that builds an
entry.

**Live declarations** (:func:`declarations`) are read only where nothing
persisted depends on the result: by the writer above, for a server or a
provider block; by an evidence-only
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

from maljan.core.tool_declarations import (
    KIND_FREE_FIELDS,
    STRICT_DECLARATIONS,
    ToolDeclarations,
    ToolFacts,
)

if TYPE_CHECKING:
    from maljan.core.config import Settings

_LOCK = threading.Lock()
# The declarations of the settings object last asked for, held with that object
# so a new settings object (a job's ``install_settings``) builds afresh.
_HELD: list[Any] = [None, None, -1]

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
    "arguments",
    "holds_strings",
    "function_starts",
    # Whether the tool sends the sample out of the deployment, read by the
    # run's disclosure block (``analysis.disclosure``) whatever the kind.
    "discloses_sample",
)

# The stored fields read without a kind (``tool_declarations.KIND_FREE_FIELDS``),
# read by :func:`kind_free_facts` whatever the record's kind.
_KIND_FREE_STORED: tuple[str, ...] = tuple(
    name for name in STORED_FACT_FIELDS if name in KIND_FREE_FIELDS
)
# What a tool that declares nothing read without a kind gives.
_NO_FACTS = ToolFacts.model_construct()


def declarations(settings: Settings | None = None) -> ToolDeclarations:
    """The live declarations: of ``settings``, else of the process's settings.

    Built once per settings object; a job that installs its own settings gets
    its own declarations on the next call. Read only where nothing persisted
    depends on the result (the module docstring).
    """
    from maljan.core.tool_declarations import declaration_version

    if settings is None:
        from maljan.core.config import get_settings

        settings = get_settings()
    with _LOCK:
        # A provider that registered its declaration since is read too.
        version = declaration_version()
        if _HELD[0] is not settings or _HELD[2] != version:
            _HELD[1] = ToolDeclarations.from_settings(settings)
            _HELD[0] = settings
            _HELD[2] = version
        return _HELD[1]  # type: ignore[no-any-return]


def forget() -> None:
    """Drop the held declarations (for a caller that changed settings in place)."""
    with _LOCK:
        _HELD[0] = None
        _HELD[1] = None
        _HELD[2] = -1


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


@cache
def _in_process_blocks() -> Mapping[str, Mapping[str, ToolFacts]]:
    from maljan.core.builtin_declarations import in_process_declarations

    return {str(ref): dict(cfg.tool_facts) for ref, cfg in in_process_declarations().items()}


def _in_process_facts(source: str, tool: str) -> dict[str, Any] | None:
    """The stored record of a platform in-process source's tool, from built-in data alone.

    The triage pack, the sandbox report tools and the evidence-only rule
    provider are the platform's own code, declared by built-in data only, so
    their records never need the settings (a render that builds an entry reads
    no settings). ``None`` for any other source.
    """
    held = _in_process_blocks().get(source)
    if held is None:
        return None
    return stored_record(held.get(tool))


def facts_record(
    source: str, tool: str, *, declared: ToolDeclarations | None = None
) -> dict[str, Any] | None:
    """What ``tool`` declares under ``source`` now, in its stored form; ``None`` when unreadable.

    Called once, when the entry is written. Settings that cannot be read store
    nothing, and the entry is then read by the legacy reading.
    """
    try:
        if declared is None:
            shipped = _in_process_facts(source, tool)
            if shipped is not None:
                return shipped
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
    """Whether ``entry`` stored a facts record when it was written."""
    return isinstance(_field(entry, "facts"), Mapping)


def read_by_name(entry: Any) -> bool:
    """Whether ``entry`` is read by the legacy reading: it recorded no source and no facts.

    An entry with a source and no facts (written before facts were stored, or
    whose settings could not be read) reads as an undeclared tool, never by
    its name.
    """
    return not recorded(entry) and not has_stored_facts(entry)


@cache
def _shipped_tools_by_source() -> Mapping[str, frozenset[str]]:
    """Each built-in source, by its recorded text, and the tool names it ships a declaration for.

    The built-in servers (``mcp:<key>``), the provider-owned blocks
    (``provider:<id>``) and the platform's in-process sources, from built-in
    data alone.
    """
    from maljan.core import builtin_declarations as shipped
    from maljan.core.tool_declarations import shipped_provider_blocks

    out: dict[str, frozenset[str]] = {
        f"mcp:{key}": frozenset(shipped.server_declaration(key).get("tool_facts") or {})
        for key in shipped.builtin_server_names()
    }
    for source, path in shipped_provider_blocks().items():
        block = "_".join(path.split(".")[1:])
        out[source] = frozenset(shipped.provider_declaration(block).get("tool_facts") or {})
    for source, tools in _in_process_blocks().items():
        out[source] = frozenset(tools)
    return out


def shipped_under_its_source(entry: Any) -> bool:
    """Whether ``entry``'s tool is one a built-in source ships, under the source it recorded.

    The platform's own name tables (``sample_identity._FORMAT_TOOL_FOR``: which
    of its tools reads a routed format) describe the platform's own tools only: an entry
    is read by one when the source it recorded is a built-in source that
    ships a declaration for its tool (its bare name, the collision prefix
    taken off). An operator's tool of the same name, recorded under the
    operator's server, never is; nor is an entry that recorded no source.
    Read from the entry and built-in data, never the reading process's
    settings.
    """
    source = ToolDeclarations.source_of(entry)
    if source is None:
        return False
    return ships_tool(str(source), _field(entry, "tool"))


def ships_tool(source: str, tool: Any) -> bool:
    """Whether the built-in ``source`` (``mcp:<key>``, ``pack`` …) ships ``tool``.

    By the tool's bare name; ``False`` for a source that is not built-in, and
    for a tool the source ships no declaration for.
    """
    held = _shipped_tools_by_source().get(str(source))
    return held is not None and bare_name(tool) in held


@cache
def _shipped_routed_formats() -> Mapping[tuple[str, str], frozenset[str]]:
    """``(mcp:<key>, tool)`` → the routed formats the platform ships for a built-in's tool."""
    from maljan.core import builtin_declarations as shipped

    out: dict[tuple[str, str], frozenset[str]] = {}
    for key in shipped.builtin_server_names():
        for tool, facts in (shipped.server_declaration(key).get("tool_facts") or {}).items():
            formats = facts.get("routed_formats") if isinstance(facts, Mapping) else None
            if formats:
                out[(f"mcp:{key}", str(tool))] = frozenset(str(f) for f in formats)
    return out


def routed_formats_of(source: str, tool: str) -> frozenset[str]:
    """The routed formats ``source``'s ``tool`` declares it serves; empty when it declares none.

    Read from the live declaration (``ToolFacts.routed_formats``), so an
    operator's server declares them as a built-in does, and an operator's edit
    of a built-in tool's formats, even to none, is in force. A built-in
    server's tool whose live declaration does not set the field (a map an
    earlier release stored whole, before the field existed, or one that leaves
    the tool out) is read with the formats the platform ships for it. The tool
    is the name its server gives it.
    """
    held = declarations().source(str(source))
    facts = held.tools.get(tool) if held is not None else None
    if facts is not None and "routed_formats" in facts.model_fields_set:
        return frozenset(facts.routed_formats)
    return _shipped_routed_formats().get((str(source), tool), frozenset())


@lru_cache(maxsize=4096)
def _parsed(text: str) -> ToolFacts | None:
    """One stored record as facts; ``None`` for one that declares nothing or cannot be read.

    A record of a newer version is read for the fields this version knows, with
    a warning; a record the validators refuse is treated as absent, with a
    warning, and never stops a reader.
    """
    from maljan.core.logger import logger

    held = json.loads(text)
    version = held.get("v")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        logger.warning("declared facts: a record without a version is read as absent.")
        return None
    if version > FACTS_VERSION:
        logger.warning(
            "declared facts: a version %d record is read for the fields version %d knows.",
            version,
            FACTS_VERSION,
        )
    known = {k: v for k, v in held.items() if k in STORED_FACT_FIELDS}
    if not known.get("kind"):
        return None
    try:
        facts = ToolFacts.model_validate(known)
        # A record of no kind (``ToolFacts.kind``) is read as a tool that
        # declares nothing, so every undeclared reading still applies.
        return facts if facts.kind else None
    except ValueError as exc:
        logger.warning("declared facts: a stored record is read as absent (%s).", exc)
        return None


def facts_of(entry: Any) -> ToolFacts | None:
    """The facts an entry's tool declared, as the entry stored them.

    ``entry`` is a ledger entry, or a mapping with ``tool`` and, where it
    recorded them, ``source`` and ``facts``. An entry with no source and no
    facts is read by the legacy reading of its name; one with a source and no
    facts has none. Never reads the reading process's settings.
    """
    held = _field(entry, "facts")
    if isinstance(held, Mapping):
        try:
            text = json.dumps(dict(held), sort_keys=True, default=str)
        except (TypeError, ValueError):
            return None
        return _parsed(text)
    if recorded(entry):
        return None
    return shipped_by_name().get(bare_name(_field(entry, "tool")))


def kind_free_facts(entry: Any) -> ToolFacts:
    """The facts an entry's tool declared that are read without a kind, whatever its kind.

    The one reader of a stored record's kind-free fields
    (``tool_declarations.KIND_FREE_FIELDS`` that the record stores:
    ``display_name``, ``words`` and ``arguments``). For a record of a kind it
    is :func:`facts_of`. A record that names no kind -- a bare
    ``unclassified``, an empty kind, or a kind the validators refuse -- still
    gives these fields, each read on its own so one field this version
    cannot read never costs another; every reader of a kind still reads that
    record as a tool that declares nothing (:func:`facts_of`), so the tool
    keeps each reading an undeclared tool gets. Read from the record the
    entry stored, never from the reading process's settings; a tool with no
    record and no legacy reading gives an empty declaration.
    """
    facts = facts_of(entry)
    if facts is not None:
        return facts
    held = _field(entry, "facts")
    if not isinstance(held, Mapping):
        return _NO_FACTS
    try:
        text = json.dumps(
            {key: held[key] for key in ("v", *_KIND_FREE_STORED) if key in held},
            sort_keys=True,
            default=str,
        )
    except (TypeError, ValueError):
        return _NO_FACTS
    return _kind_free_parsed(text)


@lru_cache(maxsize=4096)
def _kind_free_parsed(text: str) -> ToolFacts:
    held = json.loads(text)
    version = held.get("v")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        return _NO_FACTS
    words = held.get("words")
    if "words" in held:
        held["words"] = (
            [word for word in words if isinstance(word, str)]
            if isinstance(words, list | tuple)
            else []
        )
    # A record already accepted is read leniently, whoever asks.
    token = STRICT_DECLARATIONS.set(False)
    try:
        kept: dict[str, Any] = {}
        for name in _KIND_FREE_STORED:
            if name not in held:
                continue
            try:
                ToolFacts.model_validate({name: held[name]})
            except ValueError:
                continue
            kept[name] = held[name]
        return ToolFacts.model_validate(kept)
    finally:
        STRICT_DECLARATIONS.reset(token)


def named_facts(entry: Any) -> tuple[str, tuple[str, ...]]:
    """The display name and words an entry's tool declared, whatever its kind.

    Read by :func:`kind_free_facts`.
    """
    facts = kind_free_facts(entry)
    return facts.display_name, tuple(facts.words)


def legacy_tool_words(tool: str) -> set[str]:
    """The legacy reading of the words a statement names an entry by: its name's words and
    the words the old table gave a part of it (``legacy_tool_tables.TOOL_WORDS``)."""
    import re

    from maljan.core.legacy_tool_tables import TOOL_WORDS

    words = {part for part in re.split(r"[_\W]+", str(tool).lower()) if len(part) >= 3}
    for part in list(words):
        words.update(TOOL_WORDS.get(part, ()))
    return words


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

    By the entry's stored kind; an entry with no source and no facts by the
    legacy reading, and by the consumer's ``legacy_names``.
    """
    facts = facts_of(entry)
    if facts is not None and facts.kind in consumer_kinds(consumer):
        return True
    if not read_by_name(entry):
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
