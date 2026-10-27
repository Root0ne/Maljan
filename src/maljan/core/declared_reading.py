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
``reads_delay_imports``, ``function_starts``, ``discloses_sample`` and ``effects``.
``{"v": 1}`` alone records that the source declares nothing for the tool. Beside them, under
``hints``, the hints the tool's own MCP server gave it when it was attached
(:func:`with_hints`), which are not a declaration.

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
facts the platform shipped for its bare tool name (the server prefix a name
collision adds taken off), as frozen in one versioned snapshot
(``core.legacy_tool_facts``), never from the declarations shipped now. Those
are the name tables the code read before (``builtin_declarations.CONSUMER_KINDS``,
held tool by tool by
``tests/unit/core/test_every_built_in_declares_what_its_name_tables_say.py``),
so a stored entry reads as it always did, whatever later changes a shipped
declaration; a consumer table's ``legacy_names``, frozen with them, count for
such an entry only.

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
    # Whether the tool's import rows cover the late-bound imports, read by the
    # report's binary facts before it calls an import list complete.
    "reads_delay_imports",
    "function_starts",
    # Whether the tool sends the sample out of the deployment, read by the
    # run's disclosure block (``analysis.disclosure``) whatever the kind.
    "discloses_sample",
    # What a call does beyond answering (``ToolEffects``), read by the run's
    # tool-effects part (``analysis.tool_effects``) whatever the kind.
    "effects",
)

# The key of the stored record that keeps what the tool's own MCP server said
# of it when the tool was attached (its ``annotations``: the hints of
# :data:`SERVER_HINTS`), beside what its source declares. Not a declaration:
# read only by the tool-effects part, for what no declaration says.
HINTS_KEY = "hints"
# The key of the stored record that keeps the name the tool's source declares
# it under, where the request offered it under another (a registry's
# ``<server>__<tool>``). Written only for a call made through that server's own
# handle, which knew the original name; never inferred from the offered name.
DECLARED_NAME_KEY = "declared_name"
# The key of the stored record that names the fields of it that only the
# tool's own server said, for a block that does not trust its server's
# declaration (``core.served_declarations``): dotted, ``kind``,
# ``discloses_sample``, ``effects.network``. Each is the server's statement,
# read as said and never as declared (:func:`declared_only`).
SERVED_KEY = "served"
# The key of the stored record that holds, by dotted field, what the tool's
# untrusted server claims and nothing put in force (a kind whose answer moves
# or reaches outside, ``core.served_declarations``): said as the server's,
# never read as declared.
SERVED_CLAIMS_KEY = "served_claims"
# The MCP tool annotations a server may give, each a yes or no.
SERVER_HINTS: tuple[str, ...] = (
    "readOnlyHint",
    "destructiveHint",
    "idempotentHint",
    "openWorldHint",
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


def tools_in_force(
    source: str, block: Any, listing: Mapping[str, Any] | None = None
) -> Mapping[str, Any]:
    """The tool declarations in force for ``block`` under ``source``: its own, its server's under.

    ``block`` is the settings block the server was started or reached by
    (its ``tool_facts`` as they are in force), and what the server declared
    of its tools when it attached is laid under them as the live declarations
    lay it (``core.served_declarations.with_served``), so it reaches whatever
    reads a block's tools before a call: the call guard's budgets and
    long-running flags, the description tags. The block's own map where
    nothing can be read. With ``listing``, what the server declares in a
    listing nothing has kept yet is laid under in place of what was kept.
    """
    own = dict(getattr(block, "tool_facts", None) or {})
    try:
        from maljan.core.served_declarations import laid_under, with_served
        from maljan.core.tool_declarations import Declared, SourceRef

        declared = Declared.of(SourceRef.parse(str(source)), block, enabled=True)
        if listing is not None:
            return dict(laid_under(declared, listing).tools)
        return dict(with_served(declared).tools)
    except Exception as exc:  # noqa: BLE001 — an unreadable declaration falls back to the block
        from maljan.core.logger import logger

        logger.debug("declarations of %s not read (%s).", source, type(exc).__name__)
        return own


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


def in_process_tools(source: Any) -> Mapping[str, ToolFacts]:
    """The tools a platform in-process source (``pack`` …) declares in force; empty for another.

    Its built-in block's, read as any source's are (:func:`tools_in_force`)
    where something declared them as a server would; an in-process source is
    never listed, so that is its block's own.
    """
    from maljan.core.served_declarations import served

    held = _in_process_blocks().get(str(source))
    if held is None:
        return {}
    if not served(str(source)):
        return held
    from maljan.core.builtin_declarations import in_process_declarations
    from maljan.core.tool_declarations import SourceRef

    return tools_in_force(str(source), in_process_declarations()[SourceRef.parse(str(source))])


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
    source: str,
    tool: str,
    *,
    declared: ToolDeclarations | None = None,
    declared_name: str | None = None,
) -> dict[str, Any] | None:
    """What ``tool`` declares under ``source`` now, in its stored form; ``None`` when unreadable.

    With ``declared_name``, the name the source declares the tool under as
    the request offered it (a renamed tool's own name): that name is looked
    up exactly, no prefix taken off it. Without it, ``tool`` is read as an
    entry's stored name is, a renamed tool's prefix off.

    Called once, when the entry is written. Settings that cannot be read store
    nothing, and the entry is then read by the legacy reading.
    """
    try:
        if declared is None:
            shipped = _in_process_facts(source, declared_name or tool)
            if shipped is not None:
                return shipped
        held = declared or declarations()
        if declared_name:
            record = stored_record(held.declaration_for((source, declared_name), exact=True))
            return _with_served(record, held, source, declared_name)
        record = stored_record(held.declaration_for((source, tool)))
        return _with_served(record, held, source, tool, bare_name(tool))
    except Exception as exc:  # noqa: BLE001 — a record is never worth a lost entry
        from maljan.core.logger import logger

        logger.debug("declared facts of %s under %s not recorded (%s).", tool, source, exc)
        return None


def _with_served(
    record: dict[str, Any], held: ToolDeclarations, source: str, *names: str
) -> dict[str, Any]:
    """``record`` naming the stored fields only the tool's server said (:data:`SERVED_KEY`).

    And what that server claims that nothing put in force (:data:`SERVED_CLAIMS_KEY`).
    """
    said: tuple[str, ...] = ()
    claims: Mapping[str, Any] = {}
    for name in names:
        said = said or held.served_fields_for(source, name)
        claims = claims or held.served_claims_for(source, name)
    stored = [name for name in said if name.partition(".")[0] in STORED_FACT_FIELDS]
    out = dict(record)
    if stored:
        out[SERVED_KEY] = stored
    if claims:
        out[SERVED_CLAIMS_KEY] = dict(claims)
    return out


def served_fields(entry: Any) -> frozenset[str]:
    """The fields of the entry's stored record that only its tool's server said."""
    held = _field(entry, "facts")
    said = held.get(SERVED_KEY) if isinstance(held, Mapping) else None
    if not isinstance(said, list | tuple):
        return frozenset()
    return frozenset(str(name) for name in said if isinstance(name, str))


def declared_only(entry: Any) -> Any:
    """``entry`` as its declaration alone has it: without what only its server said.

    A field a server's untrusted declaration set (:data:`SERVED_KEY`) is its
    statement, never a declaration: a reader that places a call by what it
    declares (the disclosure's rows, the tool-effects part) reads this, and
    says the server's statement apart. The entry itself where nothing was.
    """
    held = _field(entry, "facts")
    if not isinstance(held, Mapping) or not (SERVED_KEY in held or SERVED_CLAIMS_KEY in held):
        return entry
    record = _declared_record(held)
    if isinstance(entry, Mapping):
        return {**entry, "facts": record}
    copy = getattr(entry, "model_copy", None)
    if callable(copy):
        return copy(update={"facts": record})
    return {
        "source": _field(entry, "source"),
        "tool": _field(entry, "tool"),
        "server": _field(entry, "server"),
        "ok": _field(entry, "ok"),
        "args": _field(entry, "args"),
        "facts": record,
    }


def _declared_record(held: Mapping[str, Any]) -> dict[str, Any]:
    """A stored record without what only its tool's server said or claimed."""
    said = held.get(SERVED_KEY)
    names = (
        [str(name) for name in said if isinstance(name, str)]
        if isinstance(said, list | tuple)
        else []
    )
    record = {
        key: value for key, value in held.items() if key not in (SERVED_KEY, SERVED_CLAIMS_KEY)
    }
    for name in names:
        top, _, sub = name.partition(".")
        if not sub:
            record.pop(top, None)
        elif isinstance(record.get(top), Mapping):
            below = {k: v for k, v in record[top].items() if k != sub}
            if below:
                record[top] = below
            else:
                record.pop(top)
    return record


def served_statement(entry: Any) -> dict[str, Any]:
    """What only the entry's tool's server said or claimed of it, by dotted field."""
    said = served_fields(entry)
    held = _field(entry, "facts")
    if not isinstance(held, Mapping):
        return {}
    claimed = held.get(SERVED_CLAIMS_KEY)
    out: dict[str, Any] = (
        {str(name): value for name, value in claimed.items()}
        if isinstance(claimed, Mapping)
        else {}
    )
    for name in sorted(said):
        top, _, sub = name.partition(".")
        value = held.get(top)
        if sub:
            value = value.get(sub) if isinstance(value, Mapping) else None
        if value is not None:
            out[name] = value
    return out


def hints_of_annotations(annotations: Any) -> dict[str, bool]:
    """The hints of :data:`SERVER_HINTS` an MCP tool's ``annotations`` give, as yes or no.

    ``annotations`` is the SDK's object or a mapping; a hint absent, or not a
    yes or no, is not given. ``{}`` for none.
    """
    out: dict[str, bool] = {}
    if annotations is None:
        return out
    for name in SERVER_HINTS:
        value = (
            annotations.get(name)
            if isinstance(annotations, Mapping)
            else getattr(annotations, name, None)
        )
        if isinstance(value, bool):
            out[name] = value
    return out


def with_hints(record: dict[str, Any] | None, hints: Any) -> dict[str, Any] | None:
    """``record`` with the server's hints kept under :data:`HINTS_KEY`; as it was with none.

    A record that could not be written (``None``) keeps no hints: the entry is
    then read as an undeclared tool, which is all the hints could have
    narrowed.
    """
    given = hints_of_annotations(hints)
    if record is None or not given:
        return record
    return {**record, HINTS_KEY: given}


def with_declared_name(
    record: dict[str, Any] | None, tool: str, declared_name: str | None
) -> dict[str, Any] | None:
    """``record`` with the name its source declares ``tool`` under, where that is another one.

    Kept under :data:`DECLARED_NAME_KEY` only for a tool the request offered
    renamed; a record of a tool offered under its own name, and one that could
    not be written (``None``), are as they were.
    """
    if record is None or not declared_name or declared_name == tool:
        return record
    return {**record, DECLARED_NAME_KEY: declared_name}


def declared_name(entry: Any) -> str:
    """The name an entry's tool is declared under by the source it recorded.

    The name its call recorded as the original (:func:`with_declared_name`),
    else the name it was called by. No ``<server>__`` prefix is ever taken off
    the called name: a tool a server natively spells ``<its key>__x``, or one
    nothing declared, is read as itself.
    """
    held = _field(entry, "facts")
    if isinstance(held, Mapping):
        original = held.get(DECLARED_NAME_KEY)
        if isinstance(original, str) and original:
            return original
    return str(_field(entry, "tool") or _field(entry, "tool_name") or "")


def server_hints(entry: Any) -> dict[str, bool]:
    """The hints the entry's tool's own server gave it when attached, as the entry stored them."""
    held = _field(entry, "facts")
    if not isinstance(held, Mapping):
        return {}
    return hints_of_annotations(held.get(HINTS_KEY))


# ---------------------------------------------------------------------------
# The reader
# ---------------------------------------------------------------------------


@cache
def _builtin_blocks() -> Mapping[str, Any]:
    """Each built-in server's block as it ships (``config._builtin_servers``), by its key."""
    from maljan.core.config import _builtin_servers

    return dict(_builtin_servers())


def builtin_tools(key: str) -> Mapping[str, ToolFacts]:
    """What the built-in server ``key`` declares of its tools as it ships; empty for any other key.

    What its block ships, with what its server declared of itself when it
    was last listed laid under it (``core.served_declarations``: kept past
    the process, so it is read before any attach). Read through the block
    the settings in force hold for ``key``, so a built-in pointed elsewhere
    (its sidecar's own container, the block trusting what the server
    declares) reads what the server declared there; through the block it
    ships with only where the settings hold none. A server never listed yet
    declares only what its block ships: the platform's own sidecars ship
    none, so until each is first listed its tools are read as any undeclared
    server's are.
    """
    import dataclasses

    from maljan.core.builtin_declarations import server_declaration
    from maljan.core.served_declarations import with_served
    from maljan.core.tool_declarations import Declared, SourceRef, declaration_version

    shipped_block = _builtin_blocks().get(str(key))
    if shipped_block is None:
        return {}
    block = _block_in_force(str(key)) or shipped_block
    # What the reading depends on: the declarations and how the block reaches
    # its server (its launch identity and its trust), whichever object holds it.
    version = declaration_version()
    signature = (version, *_launch_and_trust(str(key), block, version))
    with _LOCK:
        held = _BUILTIN_TOOLS.get(str(key))
        if held is not None and held[0] == signature:
            return held[1]
    shipped = {
        str(name): raw if isinstance(raw, ToolFacts) else ToolFacts.model_validate(raw)
        for name, raw in (server_declaration(str(key)).get("tool_facts") or {}).items()
    }
    own = Declared.of(SourceRef("mcp", str(key)), block, enabled=True)
    tools = dict(with_served(dataclasses.replace(own, tools=shipped)).tools)
    with _LOCK:
        _BUILTIN_TOOLS[str(key)] = (signature, tools)
        _READS[0] += 1
    return tools


# Each block's launch identity and trust, by the fields they are read from,
# held for one declaration version (:func:`_launch_and_trust`).
_LAUNCHES: dict[tuple[Any, ...], tuple[str, bool]] = {}
_LAUNCHES_AT: list[int] = [-1]


def _launch_and_trust(key: str, block: Any, version: int) -> tuple[str, bool]:
    """``block``'s launch identity and whether it trusts its server, for :func:`builtin_tools`.

    Read from the fields they depend on, so a block changed in place is read
    anew. What a launch's command resolves to on disk (a link's target) is
    read again at each declaration change (a listing, a load of the kept
    declarations: each job's start, the API's reread every few seconds), not
    at every read: a reader asks this for every entry it reads, and a link
    rebuilt under a running process is read at its next change.
    """
    from maljan.core.tool_declarations import launch_identity, trusts_served

    fields = (
        key,
        *(
            repr(getattr(block, name, None))
            for name in ("transport", "command", "args", "cwd", "url", "trusts_served_declaration")
        ),
        "trusts_served_declaration" in (getattr(block, "model_fields_set", None) or set()),
    )
    with _LOCK:
        if _LAUNCHES_AT[0] != version:
            _LAUNCHES.clear()
            _LAUNCHES_AT[0] = version
        held = _LAUNCHES.get(fields)
    if held is not None:
        return held
    held = (launch_identity(block), trusts_served(f"mcp:{key}", block))
    with _LOCK:
        _LAUNCHES[fields] = held
    return held


# The settings a process that installs none reads its built-in blocks through
# (the API, from the stored overrides: :func:`read_through_settings`).
_READ_THROUGH: list[Any] = [None]


def read_through_settings(settings: Any) -> None:
    """Have built-in servers read through the blocks of ``settings`` in this process.

    For a process that never installs its settings (``config.install_settings``,
    which the worker does per job): the API hands over the settings it builds
    from the stored overrides, so a built-in an operator pointed elsewhere is
    read there as in the worker. ``None`` reads the installed settings again.
    """
    with _LOCK:
        _READ_THROUGH[0] = settings


def _block_in_force(key: str) -> Any:
    """The block the settings in force hold for server ``key``; ``None`` where they hold none.

    The settings handed over (:func:`read_through_settings`), else the
    process's installed settings.
    """
    try:
        held = _READ_THROUGH[0]
        if held is None:
            from maljan.core.config import get_settings

            held = get_settings()
        return held.mcp.servers.get(key)
    except Exception:  # noqa: BLE001 — unreadable settings hold no block
        return None


# What each built-in server declares as it ships, held with the declaration
# version, the launch identity and the trust it was read under (:func:`builtin_tools`).
_BUILTIN_TOOLS: dict[str, tuple[tuple[Any, ...], dict[str, ToolFacts]]] = {}
# How many times a built-in server's reading was read anew (:func:`shipped_by_name`).
_READS: list[int] = [0]


# The facts per bare tool name of the declarations in force, held with the
# declaration version they were read at (``tool_declarations.declaration_version``).
_BY_NAME: list[Any] = [-1, None]


def shipped_by_name() -> Mapping[str, ToolFacts]:
    """The facts the platform's own sources declare per bare tool name, as in force now.

    Never the legacy reading of a stored entry, which reads the snapshot
    these gave when it was cut (:func:`legacy_by_name`).

    Every built-in source's declared tools (the built-in servers as each
    declares them, :func:`builtin_tools`; the provider-owned blocks; the
    in-process sources). A name two built-in sources share carries one kind
    and one reading in both (held by
    ``tests/unit/core/test_entries_are_read_by_their_declared_kind.py``); the
    first source in that order gives its facts. Read again whenever what a
    server declares changes.
    """
    from maljan.core import builtin_declarations as shipped
    from maljan.core.tool_declarations import declaration_version

    keys = shipped.builtin_server_names()
    servers: list[Mapping[str, ToolFacts]] = [builtin_tools(key) for key in keys]
    # Held as long as no server's reading was read anew.
    signature = (declaration_version(), _READS[0])
    with _LOCK:
        if _BY_NAME[0] == signature and _BY_NAME[1] is not None:
            return _BY_NAME[1]  # type: ignore[no-any-return]

    out: dict[str, ToolFacts] = {}

    def _take(tool_facts: Mapping[str, Any]) -> None:
        for name, raw in tool_facts.items():
            if name not in out:
                out[name] = raw if isinstance(raw, ToolFacts) else ToolFacts.model_validate(raw)

    for tools in servers:
        _take(tools)
    for provider in shipped.provider_names():
        _take(shipped.provider_declaration(provider).get("tool_facts") or {})
    for cfg in shipped.in_process_declarations().values():
        _take(cfg.tool_facts)
    with _LOCK:
        _BY_NAME[0], _BY_NAME[1] = signature, out
    return out


def legacy_by_name() -> Mapping[str, ToolFacts]:
    """The legacy reading of a stored entry: the facts per bare tool name, frozen.

    What :func:`shipped_by_name` gave when the snapshot was cut
    (``core.legacy_tool_facts``), read for an entry with no source and no
    facts only, so no later change to a shipped declaration changes how a
    stored run reads.
    """
    from maljan.core.legacy_tool_facts import facts_by_name

    return facts_by_name()


@cache
def reader_reference_facts(kind: str) -> ToolFacts | None:
    """The facts a kind's built-in reader code was written for; ``None`` for a kind with none.

    The first tool of ``kind`` in the frozen snapshot (:func:`legacy_by_name`).
    A kind's own reading reads answers in the shape the built-in tool of that
    kind had when that reading was written, which is the shape the snapshot
    froze, so this is the code's reference shape, for a live entry and a
    stored one alike, never the declarations shipped now. Read by
    ``analysis.evidence_roots`` to ask whether a tool is shaped otherwise.
    Once the kind-keyed builders read every answer by its declared values
    (T-418 PR2), nothing needs it.
    """
    return next((facts for facts in legacy_by_name().values() if facts.kind == kind), None)


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
    """Each built-in source, by its recorded text, and the tool names its block ships.

    The built-in servers (``mcp:<key>``), the provider-owned blocks
    (``provider:<id>``) and the platform's in-process sources, from built-in
    data alone: what a block holds, never what its server serves, so an
    operator's removal of a tool a block ships is read against the block
    (``core.served_declarations.laid_under``).
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


def shipped_tools_of(source: str) -> frozenset[str]:
    """The tool names the built-in ``source``'s block ships a declaration for; empty for others."""
    return _shipped_tools_by_source().get(str(source), frozenset())


def shipped_under_its_source(entry: Any) -> bool:
    """Whether ``entry``'s tool is one a built-in source ships, under the source it recorded.

    The platform's own name tables (``sample_identity._FORMAT_TOOL_FOR``: which
    of its tools reads a routed format) describe the platform's own tools only: an entry
    is read by one when the source it recorded is a built-in source that
    ships a declaration for its tool (its bare name, the collision prefix
    taken off). An operator's tool of the same name, recorded under the
    operator's server, never is; nor is an entry that recorded no source.
    Read from the entry, built-in data and what the platform's own servers
    declare of themselves (:func:`builtin_tools`), never the reading
    process's settings.
    """
    source = ToolDeclarations.source_of(entry)
    if source is None:
        return False
    return ships_tool(str(source), _field(entry, "tool"))


def ships_tool(source: str, tool: Any) -> bool:
    """Whether the built-in ``source`` (``mcp:<key>``, ``pack`` …) ships ``tool``.

    By the tool's bare name; ``False`` for a source that is not built-in, and
    for a tool the source declares nothing for: its block ships none, and, for
    a built-in server, its server declares none of itself (:func:`builtin_tools`).
    """
    held = _shipped_tools_by_source().get(str(source))
    if held is None:
        return False
    name = bare_name(tool)
    if name in held:
        return True
    kind, _, key = str(source).partition(":")
    return kind == "mcp" and name in builtin_tools(key)


def _shipped_routed_formats(source: str, tool: str) -> frozenset[str]:
    """The routed formats a built-in server's ``tool`` declares as it ships (``builtin_tools``)."""
    kind, _, key = str(source).partition(":")
    facts = builtin_tools(key).get(tool) if kind == "mcp" else None
    return frozenset(str(f) for f in facts.routed_formats) if facts is not None else frozenset()


def routed_formats_of(source: str, tool: str) -> frozenset[str]:
    """The routed formats ``source``'s ``tool`` declares it serves; empty when it declares none.

    Read from the live declaration (``ToolFacts.routed_formats``), so an
    operator's server declares them as a built-in does, and an operator's edit
    of a built-in tool's formats, even to none, is in force. A built-in
    server's tool whose live declaration does not set the field (a map an
    earlier release stored whole, before the field existed, or one that leaves
    the tool out) is read with the formats it declares as it ships, its own
    server's declaration of itself included. The tool is the name its server
    gives it.
    """
    held = declarations().source(str(source))
    facts = held.tools.get(tool) if held is not None else None
    if facts is not None and "routed_formats" in facts.model_fields_set:
        return frozenset(facts.routed_formats)
    return _shipped_routed_formats(str(source), tool)


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
        # What only the tool's server said is never read as declared.
        try:
            text = json.dumps(_declared_record(held), sort_keys=True, default=str)
        except (TypeError, ValueError):
            return None
        return _parsed(text)
    if recorded(entry):
        return None
    return legacy_by_name().get(bare_name(_field(entry, "tool")))


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
    held = _declared_record(held)
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


def legacy_names(consumer: str) -> frozenset[str]:
    """The names a consumer's table held that no built-in tool has, for stored entries only.

    Frozen with the legacy reading (``core.legacy_tool_facts``), never read
    from the consumer tables shipped now.
    """
    from maljan.core.legacy_tool_facts import legacy_names as frozen

    return frozen(consumer)


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
