"""What a tool is for, read from what it declares, and from its name only when it declares nothing.

A tool declares its role (``ToolFacts.kind``), the tag its description is
shown with (``category``), the argument it takes an address in
(``arguments["address"]``), and its server the prefixes its decompiler writes
before an address (``auto_name_prefixes``) — ``core.tool_declarations``. Every
reader of those facts reads them here, from the declaration, and falls back to
the name heuristics below for a tool that declares nothing: an operator's
server with no declaration yet, or a ledger entry written before facts were
stored (the stored runs, read exactly as they always were).

The heuristics are the platform's one copy of the name tests it read every
tool by before declarations existed. They are words a tool's own name may
carry (``decompile``, ``xref``), never one tool's name, and they apply to an
undeclared tool only.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar
from functools import lru_cache
from typing import Any, NamedTuple

# ---------------------------------------------------------------------------
# Roles, by declared kind
# ---------------------------------------------------------------------------

# A tool that lists a function's decompiled code: one function, a batch, or
# one decompiled afresh.
DECOMPILE_KINDS: frozenset[str] = frozenset({"decompile", "decompile_batch", "decompile_refresh"})
# A tool that lists code as instructions, and of those the one that lists a
# whole function.
CODE_LISTING_KINDS: frozenset[str] = frozenset(
    {"disassembly", "byte_disassembly", "function_disassembly"}
)
FUNCTION_LISTING_KINDS: frozenset[str] = frozenset({"function_disassembly"})
# A tool that reads cross-references.
XREF_KINDS: frozenset[str] = frozenset({"xrefs"})
# A tool whose answer holds the sample's strings as data: read from the file,
# recovered by emulation, decoded statically, listed or searched by a
# disassembler.
STRINGS_KINDS: frozenset[str] = frozenset(
    {
        "strings",
        "emulated_strings",
        "decoded_strings",
        "listing_strings",
        "listing_all_strings",
        "string_search",
    }
)

# ---------------------------------------------------------------------------
# The name heuristics, for a tool that declares nothing
# ---------------------------------------------------------------------------


def _name(tool: Any) -> str:
    return str(tool or "").lower()


def named_as_decompiler(tool: Any) -> bool:
    """Whether an undeclared tool's name says it decompiles."""
    return "decompil" in _name(tool)


def named_as_code_listing(tool: Any) -> bool:
    """Whether an undeclared tool's name says it disassembles."""
    return "disassembl" in _name(tool)


def named_as_function_listing(tool: Any) -> bool:
    """Whether an undeclared tool's name says it disassembles a whole function."""
    return named_as_code_listing(tool) and "function" in _name(tool)


def undeclared_code_kind(tool: Any) -> str:
    """The code-listing kind an undeclared tool's name says it is, ``""`` for none.

    ``decompile`` for a name that says it decompiles, ``function_disassembly``
    for one that says it disassembles a whole function, ``disassembly`` for
    one that says it disassembles. The one reading of a code listing by name:
    the agent side (the function map, the repeat guard) and the report side
    (figures, "Functions examined", the composer's code bundle) read an
    undeclared tool by it alike.
    """
    if named_as_decompiler(tool):
        return "decompile"
    if named_as_function_listing(tool):
        return "function_disassembly"
    if named_as_code_listing(tool):
        return "disassembly"
    return ""


def code_kind(facts: Any, tool: Any) -> str:
    """The code-listing kind of a tool: its declared kind when it is one, else its name's.

    A declared tool keeps its declared kind (``""`` when that is no code
    listing); only a tool that declares nothing is read by its name
    (:func:`undeclared_code_kind`).
    """
    kind = _kind(facts)
    if kind is None:
        return undeclared_code_kind(tool)
    return kind if kind in DECOMPILE_KINDS or kind in CODE_LISTING_KINDS else ""


def named_as_xrefs(tool: Any) -> bool:
    """Whether an undeclared tool's name says it reads cross-references."""
    return "xref" in _name(tool)


def named_as_strings_source(tool: Any) -> bool:
    """Whether an undeclared tool's name says its answer holds strings."""
    return "string" in _name(tool)


def _kind(facts: Any) -> str | None:
    kind = getattr(facts, "kind", None)
    return str(kind) if kind else None


def declares_a_kind(facts: Any) -> bool:
    """Whether a tool's facts name a kind: a tool whose facts name none is read as undeclared.

    A declaration may state a tool's other facts (its display name, budget,
    arguments) with no kind; every reading this module gives an undeclared
    tool still applies to it.
    """
    return _kind(facts) is not None


def decompiles(facts: Any, tool: Any) -> bool:
    """Whether a tool lists decompiled code: by its declared kind, else by its name."""
    kind = _kind(facts)
    return kind in DECOMPILE_KINDS if kind is not None else named_as_decompiler(tool)


def lists_code(facts: Any, tool: Any) -> bool:
    """Whether a tool lists code as instructions: by its declared kind, else by its name."""
    kind = _kind(facts)
    return kind in CODE_LISTING_KINDS if kind is not None else named_as_code_listing(tool)


def lists_a_function(facts: Any, tool: Any) -> bool:
    """Whether a tool disassembles a whole function: by its declared kind, else by its name."""
    kind = _kind(facts)
    return kind in FUNCTION_LISTING_KINDS if kind is not None else named_as_function_listing(tool)


def reads_xrefs(facts: Any, tool: Any) -> bool:
    """Whether a tool reads cross-references: by its declared kind, else by its name."""
    kind = _kind(facts)
    return kind in XREF_KINDS if kind is not None else named_as_xrefs(tool)


def is_strings_source(facts: Any, tool: Any) -> bool:
    """Whether a tool's answer holds the sample's strings: by its declared kind or
    ``holds_strings``, else its name."""
    kind = _kind(facts)
    if kind is None:
        return named_as_strings_source(tool)
    return kind in STRINGS_KINDS or bool(getattr(facts, "holds_strings", False))


# ---------------------------------------------------------------------------
# The tag a description is shown with
# ---------------------------------------------------------------------------

# The tag an undeclared tool's description is shown with, by the first word of
# its name.
_CATEGORY_BY_FIRST_WORD: dict[str, str] = {
    "analyze": "ANALYZE",
    "decompile": "ANALYZE",
    "disassemble": "ANALYZE",
    "detect": "ANALYZE",
    "find": "ANALYZE",
    "diff": "ANALYZE",
    "compare": "ANALYZE",
    "inspect": "ANALYZE",
    "emulate": "ANALYZE",
    "extract": "ANALYZE",
    "list": "LIST",
    "get": "LIST",
    "search": "LIST",
    "batch": "BATCH",
    "bulk": "BATCH",
    "run": "EXEC",
    "rename": "MODIFY",
    "create": "MODIFY",
    "delete": "MODIFY",
    "set": "MODIFY",
    "apply": "MODIFY",
    "modify": "MODIFY",
    "remove": "MODIFY",
    "move": "MODIFY",
    "clear": "MODIFY",
    "convert": "MODIFY",
    "clone": "MODIFY",
    "force": "MODIFY",
    "open": "NAV",
    "close": "NAV",
    "save": "NAV",
    "load": "NAV",
    "switch": "NAV",
    "validate": "CHECK",
    "can": "CHECK",
    "read": "READ",
    "import": "IMPORT",
    "server": "META",
}


def category_tag(tool: str, declared: str = "") -> str:
    """The tag a tool's description is shown with: its declared ``category``, else its name's.

    An undeclared tool is tagged by the first word of its name, and ``TOOL``
    when that word names no category.
    """
    if declared:
        return declared.upper()
    return _CATEGORY_BY_FIRST_WORD.get(str(tool).split("_")[0], "TOOL")


def categories_of(tool_facts: Mapping[str, Any] | None) -> dict[str, str]:
    """``{tool: declared category}`` for each tool of a server block that declares one."""
    return {
        str(name): str(getattr(facts, "category", "") or "")
        for name, facts in (tool_facts or {}).items()
        if getattr(facts, "category", "")
    }


# What a tool's description says after its own text when the tool declares
# itself the aggregate form of other tools of its server
# (``ToolFacts.aggregate_of``), so a model can choose the one call over many.
# Declared tools only; an undeclared tool's description is the server's alone.
# Written once the names a request offers are settled (:func:`with_aggregate_notes`),
# so each tool it names is one the request offers, under the name it offers it.
AGGREGATE_NOTE = "Aggregate form of {tools}: one call answers what many calls of {them} would."


def aggregates_of(tool_facts: Mapping[str, Any] | None) -> dict[str, tuple[str, ...]]:
    """``{tool: the tools it is the aggregate form of}`` for each tool that declares some."""
    return {
        str(name): tuple(getattr(facts, "aggregate_of", ()) or ())
        for name, facts in (tool_facts or {}).items()
        if getattr(facts, "aggregate_of", ())
    }


def aggregate_note(names: Iterable[str]) -> str:
    """The note a description carries for a tool that aggregates ``names``; "" for none."""
    held = [str(name) for name in names if name]
    if not held:
        return ""
    return AGGREGATE_NOTE.format(
        tools=", ".join(f"`{name}`" for name in held), them="it" if len(held) == 1 else "those"
    )


# What a tool's description says after its own text (and its aggregate note)
# when the tool declares what its answer shows and does not show
# (``ToolFacts.shows`` / ``does_not_show``) and ``mcp.answer_scope_notes`` is
# on. Declared tools only, as the aggregate note.
ANSWER_SHOWS_NOTE = "This answer shows: {text}."
ANSWER_DOES_NOT_SHOW_NOTE = "It does not show: {text}."

# The metadata key a tool given a note keeps its own description under, so a
# later settling of the notes (:func:`with_declared_notes`) writes them afresh
# from the tool's own words instead of after the notes it already carries.
OWN_DESCRIPTION_METADATA_KEY = "maljan_own_description"


def answer_scopes_of(tool_facts: Mapping[str, Any] | None) -> dict[str, tuple[str, str]]:
    """``{tool: (shows, does_not_show)}`` for each tool that declares either."""
    out: dict[str, tuple[str, str]] = {}
    for name, facts in (tool_facts or {}).items():
        shows = str(getattr(facts, "shows", "") or "")
        hidden = str(getattr(facts, "does_not_show", "") or "")
        if shows or hidden:
            out[str(name)] = (shows, hidden)
    return out


def answer_scope_note(shows: str, does_not_show: str) -> str:
    """The note a description carries for what its answer shows and does not; "" for none."""
    parts = [
        template.format(text=text.strip().rstrip("."))
        for template, text in (
            (ANSWER_SHOWS_NOTE, shows),
            (ANSWER_DOES_NOT_SHOW_NOTE, does_not_show),
        )
        if text.strip().rstrip(".")
    ]
    return " ".join(parts)


def own_description(tool: Any) -> str:
    """A tool's description as its server wrote it, without the notes the platform added."""
    metadata = getattr(tool, "metadata", None) or {}
    held = metadata.get(OWN_DESCRIPTION_METADATA_KEY)
    return str(held if isinstance(held, str) else getattr(tool, "description", "") or "")


def with_declared_notes(
    tools: Iterable[Any],
    aggregates: Mapping[str, Iterable[str]],
    offered: Mapping[str, str],
    *,
    scopes: Mapping[str, tuple[str, str]] | None = None,
    declared: Callable[[Any], str] | None = None,
) -> list[Any]:
    """``tools``, each with the notes its declaration gives it after its own description.

    ``aggregates`` is the server's :func:`aggregates_of`, by the names the
    server gave its tools; ``offered`` maps each of the server's tools the
    request offers, by that name, to the name it is offered under (a name
    another server took is offered as ``<server>__<name>``). A tool the request
    does not offer is left out of the aggregate note, and a tool none of whose
    aggregated tools is offered carries none. ``scopes`` is the server's
    :func:`answer_scopes_of`, given only while ``mcp.answer_scope_notes`` is
    on; its note follows the aggregate note. ``declared`` reads a tool's own
    name (default: its ``name``).

    The notes are written from the tool's own description
    (:func:`own_description`), so settling them again over a narrower or a
    wider set of offered tools replaces the notes a tool carries rather than
    adding to them, and takes off a note that names nothing offered any more.
    A tool that carries no note and gains none is the same object.
    """
    read = declared or (lambda tool: str(getattr(tool, "name", "") or ""))
    held_scopes = scopes or {}
    out: list[Any] = []
    for tool in tools:
        name = read(tool)
        notes = [
            aggregate_note(offered[n] for n in aggregates.get(name, ()) if n in offered),
            answer_scope_note(*held_scopes[name]) if name in held_scopes else "",
        ]
        note = " ".join(n for n in notes if n)
        metadata = getattr(tool, "metadata", None) or {}
        noted = OWN_DESCRIPTION_METADATA_KEY in metadata
        if note:
            raw = own_description(tool)
            own = " ".join(raw.split())
            described = f"{own} {note}" if own else note
            if not noted or described != getattr(tool, "description", None):
                tool = tool.model_copy(
                    update={
                        "description": described,
                        "metadata": {**metadata, OWN_DESCRIPTION_METADATA_KEY: raw},
                    }
                )
        elif noted:
            kept = {k: v for k, v in metadata.items() if k != OWN_DESCRIPTION_METADATA_KEY}
            tool = tool.model_copy(
                update={"description": own_description(tool), "metadata": kept or None}
            )
        out.append(tool)
    return out


def with_aggregate_notes(
    tools: Iterable[Any],
    aggregates: Mapping[str, Iterable[str]],
    offered: Mapping[str, str],
    *,
    declared: Callable[[Any], str] | None = None,
) -> list[Any]:
    """``tools``, each that declares itself an aggregate with the note after its description.

    :func:`with_declared_notes` with the aggregate notes alone: what a
    provider writes when it attaches, before the agent's whole tool list is
    settled.
    """
    return with_declared_notes(tools, aggregates, offered, declared=declared)


# ---------------------------------------------------------------------------
# Address arguments and auto-names
# ---------------------------------------------------------------------------

# The argument names an undeclared tool's call gives one address under. The
# two lists the platform read them by before declarations (the evidence roots'
# and the decompile reading's) as one; ``start`` is left out, being the first
# row of a page as often as an address.
ADDRESS_ARGUMENTS: tuple[str, ...] = (
    "address",
    "addr",
    "function_address",
    "ea",
    "va",
    "start_address",
    "entry_address",
)


# The words an argument's name says a code or memory address in the binary
# by, read from a positive shape so a network or identity address
# (``ip_address``, ``email_address``, ``remote_addr``, ``address_family``) and
# a bound, a size or a base (``end_address``, ``base_address``) never are. A
# name of these words alone is one (``address``, ``rva``, ``addr_va``);
# ``offset`` is not, being a page's first row as often as a place.
_ADDRESS_WORDS = frozenset({"addr", "address", "ea", "va", "rva", "vaddr"})
# The words that pair with an address word to name the place of code
# (``func_addr``, ``target_address``, ``entry_rva``, ``instruction_address``).
_CODE_PLACE_WORDS = frozenset(
    {
        "code",
        "entry",
        "fn",
        "func",
        "function",
        "insn",
        "instruction",
        "loc",
        "location",
        "routine",
        "start",
        "sub",
        "target",
    }
)
_CAMEL_RE = re.compile(r"([a-z0-9])([A-Z])")
_WORD_SPLIT_RE = re.compile(r"[^a-z0-9]+")


def named_as_address(name: Any) -> bool:
    """Whether an argument's name says it takes a code or memory address in the binary.

    One of :data:`ADDRESS_ARGUMENTS`; a name made only of address words
    (``address``, ``rva``); or a name pairing an address word with words for
    the place of code (``func_addr``, ``targetAddress``, ``entry_rva``), with
    ``name … or`` allowed beside them (``name_or_address``). Any other word
    makes it something else — a network or identity address (``ip``,
    ``email``, ``remote``, ``bind``, ``host``, ``wallet``, ``family``) or a
    bound, a size or a base (``end``, ``base``, ``count``, ``space``). Read
    from the name alone, whatever tool it belongs to.
    """
    text = str(name or "")
    if text.lower() in ADDRESS_ARGUMENTS:
        return True
    words = {w for w in _WORD_SPLIT_RE.split(_CAMEL_RE.sub(r"\1_\2", text).lower()) if w}
    if not words or not (_ADDRESS_WORDS & words):
        return False
    rest = words - _ADDRESS_WORDS
    if not rest:
        return True
    if not rest <= _CODE_PLACE_WORDS | {"name", "or", "of"}:
        return False
    # ``name_or_address``: a symbol's name or its address, both places of code.
    if "name" in rest:
        return "or" in rest
    return bool(_CODE_PLACE_WORDS & rest)


def address_arguments(facts: Any, offered: Iterable[Any] = ()) -> tuple[str, ...]:
    """The arguments a call gives an address in, in the order they are read.

    The one the tool declares for the ``address`` role
    (``ToolFacts.arguments``) first, then :data:`ADDRESS_ARGUMENTS`: a
    declaration names the argument a tool's own name for an address has
    (``offset_va``), and a built-in's declaration does not name every
    argument that takes one (a byte range's ``start_address``), so the shared
    list still follows it. Then each of ``offered`` (the call's own argument
    names, or a tool schema's) that is named for an address
    (:func:`named_as_address`), in its own order: a tool nobody declared
    whose decompiler takes ``name_or_address`` is read as the one that
    declares it.
    """
    declared = getattr(facts, "arguments", None)
    held = str(declared.get("address") or "") if isinstance(declared, Mapping) else ""
    known = ADDRESS_ARGUMENTS if not held else (held, *(n for n in ADDRESS_ARGUMENTS if n != held))
    extra: list[str] = []
    for name in offered:
        text = str(name or "")
        if text and text not in known and text not in extra and named_as_address(text):
            extra.append(text)
    return (*known, *extra) if extra else known


# The prefixes a decompiler writes before an address when it names a function
# itself, as words without their separator: the ones the platform has always
# read (Ghidra's ``FUN_``/``LAB_``/``SUB_``, radare2's ``fcn.``/``loc.``/
# ``func.``/``sub.``, IDA's ``sub_``), which the built-in blocks also declare.
DEFAULT_AUTO_NAME_WORDS: tuple[str, ...] = ("fun", "fcn", "sub", "func", "loc", "lab")


def auto_name_words(declared: Iterable[str] = ()) -> tuple[str, ...]:
    """The default words, then each declared prefix's word (``FUN_`` → ``fun``) not among them."""
    words = list(DEFAULT_AUTO_NAME_WORDS)
    for prefix in declared:
        word = str(prefix).rstrip("_.").lower()
        if word and word.isalnum() and word not in words:
            words.append(word)
    return tuple(words)


@lru_cache(maxsize=64)
def auto_name_pattern(words: tuple[str, ...] = DEFAULT_AUTO_NAME_WORDS) -> re.Pattern[str]:
    """A decompiler's own name for a function: one of ``words``, ``_`` or ``.``, the address."""
    joined = "|".join(re.escape(word) for word in words)
    return re.compile(
        r"(?<![0-9A-Za-z_])(?:" + joined + r")[_.]([0-9a-f]{1,16})(?![0-9a-z_])",
        re.IGNORECASE,
    )


# The pattern of the declarations last asked for, held with them.
_HELD_PATTERN: list[Any] = [None, None]


def declared_auto_name_pattern(settings: Any = None) -> re.Pattern[str]:
    """The auto-name pattern for every prefix an enabled source declares, and the defaults.

    Read from the live declarations (``core.declared_reading.declarations``),
    once per declarations object; settings that cannot be read give the
    defaults' pattern.
    """
    try:
        from maljan.core.config import get_settings
        from maljan.core.declared_reading import declarations

        settings = settings if settings is not None else get_settings()
        held = declarations(settings)
    except Exception:  # noqa: BLE001 — unreadable settings declare nothing more
        return auto_name_pattern()
    if _HELD_PATTERN[0] is held:
        return _HELD_PATTERN[1]  # type: ignore[no-any-return]
    # Only the sources this deployment switches on, and the static provider
    # blocks any agent resolves to: a disabled server's prefix names no
    # function any run can have listed.
    resolved = _resolved_static_providers(settings)
    declared = [
        prefix
        for source in held.sources()
        if source.enabled or (source.source.kind == "provider" and source.source.key in resolved)
        for prefix in source.auto_name_prefixes
    ]
    pattern = auto_name_pattern(auto_name_words(declared))
    _HELD_PATTERN[0], _HELD_PATTERN[1] = held, pattern
    return pattern


def _resolved_static_providers(settings: Any) -> set[str]:
    """The static provider each agent definition resolves to (team, own, or global)."""
    try:
        from maljan.agents.composition import static_provider_id_for

        return {static_provider_id_for(settings, key) for key in settings.agents.definitions} | {
            str(settings.static.provider)
        }
    except Exception:  # noqa: BLE001 — an unreadable team resolves nothing more
        return set()


# ---------------------------------------------------------------------------
# A ledger entry, by the facts it stored
# ---------------------------------------------------------------------------


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


def entry_facts(entry: Any) -> Any:
    """The facts an entry's tool declared, as the entry stored them (``declared_reading.facts_of``).

    An entry written before facts were stored is read by the facts the
    platform ships for its tool's name; an undeclared tool has none.
    """
    from maljan.core.declared_reading import facts_of

    return facts_of(entry)


def entry_decompiles(entry: Any) -> bool:
    """Whether an entry's tool lists decompiled code (:func:`decompiles`)."""
    return decompiles(entry_facts(entry), _field(entry, "tool"))


def entry_lists_code(entry: Any) -> bool:
    """Whether an entry's tool lists code as instructions (:func:`lists_code`)."""
    return lists_code(entry_facts(entry), _field(entry, "tool"))


def entry_lists_a_function(entry: Any) -> bool:
    """Whether an entry's tool disassembles a whole function (:func:`lists_a_function`)."""
    return lists_a_function(entry_facts(entry), _field(entry, "tool"))


def entry_code_kind(entry: Any) -> str:
    """The code-listing kind of an entry's tool (:func:`code_kind`), ``""`` for none."""
    return code_kind(entry_facts(entry), _field(entry, "tool"))


def entry_lists_any_code(entry: Any) -> bool:
    """Whether an entry's tool lists code, decompiled or as instructions."""
    return bool(entry_code_kind(entry))


def entry_is_strings_source(entry: Any) -> bool:
    """Whether an entry's answer holds the sample's strings (:func:`is_strings_source`)."""
    return is_strings_source(entry_facts(entry), _field(entry, "tool"))


def entry_address_arguments(entry: Any) -> tuple[str, ...]:
    """The arguments an entry's call gave an address in (:func:`address_arguments`).

    ``arguments`` is read without a kind, so a record that names none still
    gives its declared address argument (``declared_reading.kind_free_facts``);
    the call's own arguments named for an address follow, for a tool whose
    answer is a code listing only (:func:`entry_lists_any_code`).
    """
    from maljan.core.declared_reading import kind_free_facts

    args = _field(entry, "args")
    offered = args if isinstance(args, Mapping) and entry_lists_any_code(entry) else ()
    return address_arguments(kind_free_facts(entry), offered)


# ---------------------------------------------------------------------------
# A failure an undeclared tool answers in prose
# ---------------------------------------------------------------------------

# What an answer that only says the call failed has the form of, never just
# its first word ("Error handling routine at …", "Failed logins: 0", "Invalid
# signature" and "Not found in …" are data). Only for a tool its source
# declares nothing for, whose server's declared error patterns
# (``MCPServerConfig.error_patterns``) did not already file it.
#
# An error label: a level in brackets (``[ERROR]``, ``[Errno 2]``), an error
# word followed by a colon or a bracket (``Error:``, ``Fatal error:``), or an
# error word naming what it was doing (``Error executing …:``).
_ERROR_LABEL_RE = re.compile(
    r"^(?:\[(?:error|fatal)\]|\[errno\s*-?\d+\]|"
    r"(?:fatal\s+)?(?:error|fatal|exception|failure)\s*[:\]]|"
    r"error\s+(?:executing|calling|running|invoking|loading|opening|reading|processing|parsing)"
    r"\b[^:]*:)",
    re.IGNORECASE,
)
# An exception class's shape: one CamelCase name ending in Error or Exception,
# then a colon (``ValueError: …``, ``pkg.ToolError: …``).
_EXCEPTION_CLASS_RE = re.compile(r"^[A-Za-z_][\w.]*(?:Error|Exception):")
# A failure phrase with its verb.
_FAILURE_PHRASE_RE = re.compile(
    r"^(?:(?:failed|unable|not\s+able)\s+to\s+[a-z]|"
    r"(?:cannot|can\s+not|can't|could\s*n[o']t)\s+[a-z]|"
    r"(?:permission|access)\s+denied\b)",
    re.IGNORECASE,
)
_TRACEBACK_RE = re.compile(r"^traceback \(most recent call last\):", re.IGNORECASE)
# A longer answer is read as an answer: what a failure says in prose fits a line.
PROSE_ERROR_CHARS = 400


def prose_error(text: Any) -> str | None:
    """The message of an answer that only says the call failed, else ``None``.

    The answer must have an error's form, not merely open with an error word:
    a traceback (its last line is the message), or one line of prose no longer
    than :data:`PROSE_ERROR_CHARS` that opens with an error label followed by
    a message (``Error: binary not loaded``, ``[ERROR] …``), an exception
    class's shape (``ValueError: …``) or a failure phrase with its verb
    (``Failed to open file``, ``Cannot find …``). A label followed by a count
    or nothing (``errors: 0``) is data, and so is an answer holding any data —
    a second line, a JSON value, a listing. Conservative by design: what it
    does not recognise stays an answer, as it was.
    """
    said = str(text or "").strip()
    if not said:
        return None
    if _TRACEBACK_RE.match(said):
        last = said.splitlines()[-1].strip()
        return last[:PROSE_ERROR_CHARS] or said[:PROSE_ERROR_CHARS]
    if len(said) > PROSE_ERROR_CHARS or "\n" in said or "\r" in said or said[0] == "{":
        return None
    if _FAILURE_PHRASE_RE.match(said):
        return said
    label = _ERROR_LABEL_RE.match(said)
    if label:
        # The label must be followed by a message: a count or nothing is data.
        return said if re.search(r"[A-Za-z]", said[label.end() :]) else None
    shape = _EXCEPTION_CLASS_RE.match(said)
    if shape:
        # A message of words, never one value (``LastError: ERROR_SUCCESS``).
        rest = said[shape.end() :].strip()
        return said if re.search(r"[A-Za-z]", rest) and re.search(r"\s", rest) else None
    return None


# What a code listing looks like, read from its text: pseudo-C (braces, a
# call's parenthesis, a statement ending in a semicolon at its line's end or
# before a closing brace) or disassembly lines (each line led by an address,
# at most a byte run, a mnemonic and an operand). Each pattern is bounded and
# anchored, so a hostile answer is read in one pass, and prose that merely
# holds numbers ("Found 1234 matches in 4096 files") is no listing.
_CALL_SHAPE_RE = re.compile(r"\w\(")
_STATEMENT_END_RE = re.compile(r";[ \t]*(?:$|\})", re.MULTILINE)
_ASM_LINE_RE = re.compile(
    # A gutter (a disassembler's box-drawing bar, an arrow), a segment's name.
    r"^[ \t│|>*]{0,16}(?:[\w.]{1,32}:)?"
    # The address: written 0x…, six or more hex digits, or four before a colon.
    r"(?:0x[0-9A-Fa-f]{2,16}|[0-9A-Fa-f]{6,16}|[0-9A-Fa-f]{4,5}(?=[ \t]*:))h?"
    r"[ \t]*:?[ \t]+"
    # The instruction's bytes, as one run or as pairs.
    r"(?:(?:[0-9A-Fa-f]{2}[ \t]?){1,16}[ \t]+)?"
    # The mnemonic and the start of an operand.
    r"[A-Za-z]{2,7}(?:\.[A-Za-z]{1,3})?[ \t]+[\w\[$%#-]",
    re.MULTILINE,
)


def holds_code(text: Any) -> bool:
    """Whether ``text`` reads as a code listing: pseudo-C, or two disassembly lines."""
    said = str(text or "")
    if not said.strip():
        return False
    # A listing cut for storage may have lost its closing brace.
    if "{" in said and _CALL_SHAPE_RE.search(said) and _STATEMENT_END_RE.search(said):
        return True
    return sum(1 for _ in zip(range(2), _ASM_LINE_RE.finditer(said), strict=False)) >= 2


# Where a JSON object's string field opens: its name, a colon, a quote.
_STRING_FIELD_RE = re.compile(r'"([^"\\\n]{1,200})"[ \t\r\n]*:[ \t\r\n]*"')
# A JSON string's escapes, undone in the field a cut falls in when the
# decoder cannot read it.
_ESCAPE_RE = re.compile(r"\\(u[0-9a-fA-F]{4}|.)", re.DOTALL)
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f"}
# An escape the cut split: a ``\u`` short of its four digits, or a lone backslash.
_SPLIT_ESCAPE_RE = re.compile(r"\\u[0-9a-fA-F]{0,3}$|(?<!\\)(?:\\\\)*\\$")
# The marks a text cut for storage ends with: the tool-output guardrail's
# (``agents.mcp_client.TRUNCATION_MARKER``) and the marked cut's.
_STORAGE_CUT_MARKS = ("[OUTPUT TRUNCATED]", "…")


def _undo_escape(match: re.Match[str]) -> str:
    said = match.group(1)
    if said.startswith("u") and len(said) == 5:
        return chr(int(said[1:], 16))
    return _ESCAPES.get(said, said)


def _read_to_cut(rest: str) -> str:
    """The text of a JSON string the cut fell in: the cut's mark and a split escape left out."""
    value = rest.rstrip()
    trimmed = True
    while trimmed:
        trimmed = False
        for mark in _STORAGE_CUT_MARKS:
            if value.endswith(mark):
                value = value[: -len(mark)].rstrip()
                trimmed = True
    value = _SPLIT_ESCAPE_RE.sub("", value)
    from json import decoder

    try:
        read, _ = decoder.scanstring(value + '"', 0, False)  # type: ignore[attr-defined]
    except ValueError:
        read = _ESCAPE_RE.sub(_undo_escape, value)
    return str(read)


def _string_fields(text: str) -> tuple[dict[str, str], str | None]:
    """The string fields of a JSON object cut short, each read to its end or to the cut.

    One pass: a field found inside a value already read is skipped, and the
    field the cut falls in is read to the cut (:func:`_read_to_cut`). Returns
    the fields and the name of the one the cut fell in, ``None`` for none.
    """
    from json import decoder

    scanstring = decoder.scanstring  # type: ignore[attr-defined]

    fields: dict[str, str] = {}
    read_to = 0
    for match in _STRING_FIELD_RE.finditer(text):
        if match.start() < read_to:
            continue
        try:
            value, read_to = scanstring(text, match.end(), False)
        except ValueError:
            name = match.group(1)
            fields.setdefault(name, _read_to_cut(text[match.end() :]))
            return fields, name
        fields.setdefault(match.group(1), value)
    return fields, None


# A field name a decompiler or disassembler gives its listing.
_CODE_KEY_RE = re.compile(r"code|decomp|pseudo|source|listing|disas|asm", re.IGNORECASE)

# A disassembly line with no address: a mnemonic alone, with one operand, or
# with operands separated by commas (``push ebp``, ``mov dword ptr [ebp-4], eax``,
# ``retn``). Bounded, anchored to the whole line.
_OPERAND = r"[\w\[\]+\-*:$%#.@?]{1,64}"
_BARE_ASM_LINE_RE = re.compile(
    rf"[ \t]*[A-Za-z]{{2,7}}(?:\.[A-Za-z]{{1,3}})?"
    rf"(?:[ \t]+{_OPERAND}(?:(?:[ \t]+{_OPERAND}){{0,3}}[ \t]*,[ \t]*{_OPERAND}"
    rf"(?:[ \t]+{_OPERAND}){{0,3}}){{0,3}})?[ \t]*"
)
# What only an instruction's operands write: a comma between two operands
# with no space before it, or a memory reference.
_OPERAND_MARK_RE = re.compile(r"\w,[ \t]*[\w\[]|\[\w")


def holds_bare_listing(text: str) -> bool:
    """Whether ``text`` is a disassembly written without addresses.

    Three or more lines of mnemonic-and-operand shape, at least four in five of
    its lines, and an operand mark (two operands joined by a comma, or a
    memory reference) on one of them: prose of short lines is no listing. Read only for a field
    under a code-ish key, where a listing is what the field holds.
    """
    lines = [line for line in text.splitlines() if line.strip()]
    shaped = [line for line in lines if _BARE_ASM_LINE_RE.fullmatch(line)]
    return (
        len(shaped) >= 3
        and len(shaped) * 5 >= len(lines) * 4
        and any(_OPERAND_MARK_RE.search(line) for line in shaped)
    )


def code_strings(document: Any) -> list[tuple[str, str]]:
    """Every string in a JSON document that reads as code, with the key it stands under.

    Walked iteratively, objects and lists at any depth, in document order.
    """
    found: list[tuple[str, str]] = []
    stack: list[tuple[str, Any]] = [("", document)]
    while stack:
        key, value = stack.pop()
        if isinstance(value, str):
            if holds_code(value) or (_CODE_KEY_RE.search(key) and holds_bare_listing(value)):
                found.append((key, value))
        elif isinstance(value, Mapping):
            stack.extend(reversed([(str(k), v) for k, v in value.items()]))
        elif isinstance(value, list):
            stack.extend(reversed([(key, v) for v in value]))
    return found


def _pick_code(found: list[tuple[str, str]]) -> str:
    """The listing among several code strings: the one under a code-ish key, else the longest."""
    if len(found) == 1:
        return found[0][1]
    keyed = [value for key, value in found if _CODE_KEY_RE.search(key)]
    return (keyed or sorted((v for _, v in found), key=len, reverse=True))[0]


def code_listing(answer: Any, path: str = "", rows: str = "") -> tuple[str, bool]:
    """The code a code-listing answer holds, and whether the cut for storage fell in it.

    A JSON object's code is read at the declared path (``ToolFacts.values``
    ``code``, inside the first of the declared ``rows``) when the declaration
    names one and it reads as code; else from the strings that read as code
    (:func:`holds_code`) at any depth: the one, or among several the one
    under a code-ish key, else the longest. A JSON answer holding code that
    no string carries alone is drawn whole, as it always was; a JSON object
    that holds no code anywhere is no listing (a search's hits, a status
    record) and gives ``""``. A JSON list holding no code string, and a plain
    text answer, are drawn whole as before.
    """
    said = str(answer or "").strip()
    if not said:
        return "", False
    if said[0] not in "{[":
        return said, False
    import json

    cut_field: str | None = None
    try:
        document: Any = json.loads(said)
    except ValueError:
        if said[0] != "{":
            return said, False
        # An answer cut for storage is no whole JSON: its string fields are
        # read up to the cut.
        document, cut_field = _string_fields(said)
    if path and isinstance(document, Mapping):
        from maljan.core.tool_declarations import first, select

        found = select(document, rows) if rows else [document]
        held = first(found[0], path) if found else None
        if isinstance(held, str) and (holds_code(held) or holds_bare_listing(held)):
            return held.strip("\n"), cut_field is not None and held == document.get(cut_field)
    strings = code_strings(document)
    if strings:
        picked = _pick_code(strings)
        cut = cut_field is not None and isinstance(document, Mapping)
        return picked.strip("\n"), cut and picked == document.get(cut_field)
    if (
        cut_field is not None
        and _CODE_KEY_RE.search(cut_field)
        and isinstance(document, Mapping)
        and str(document.get(cut_field) or "").strip()
    ):
        # The cut fell in the listing's own field before it showed a code
        # shape: what was read of it is drawn, marked cut.
        return str(document[cut_field]).strip("\n"), True
    if isinstance(document, list) or holds_code(said) or holds_code(_joined_strings(document)):
        return said, False
    return "", False


def _joined_strings(document: Any) -> str:
    """Every string of a JSON document, one per line, walked iteratively in document order."""
    out: list[str] = []
    stack: list[Any] = [document]
    while stack:
        value = stack.pop()
        if isinstance(value, str):
            out.append(value)
        elif isinstance(value, Mapping):
            stack.extend(reversed(list(value.values())))
        elif isinstance(value, list):
            stack.extend(reversed(value))
    return "\n".join(out)


def code_text(answer: Any, path: str = "", rows: str = "") -> str:
    """The code a code-listing answer holds, or ``""`` when it holds none (:func:`code_listing`)."""
    return code_listing(answer, path, rows)[0]


# ---------------------------------------------------------------------------
# An answer that lists several functions' code, one function at a time
# ---------------------------------------------------------------------------


class CodePart(NamedTuple):
    """One function of an answer that lists several functions' code (:func:`code_parts`).

    ``where`` is the function as the answer names it: the key it stands
    under, or the address or name its row gives; ``item <n>`` (1-based) for a
    row that names none. ``cut`` is whether the cut for storage fell inside
    this function's code; ``answer_cut`` is whether the answer was cut for
    storage after it, so the functions it listed later are not shown (set on
    the last function read of a cut answer).
    """

    where: str
    code: str
    cut: bool
    answer_cut: bool = False


# What a function of a batch's answer cut for storage says where it is listed:
# the functions the answer held after the cut are not in the ledger.
ANSWER_CUT_NOTE = "answer cut for storage; later functions not shown"
# A key of an answer keyed by function: an address (``0x`` and hex digits, or
# six hex digits or more, one of them a digit) or a decompiler's own name for
# one (``FUN_00401000``). Four bare digits read as often as a year or a count.
_FUNCTION_KEY_RE = re.compile(r"0x[0-9a-fA-F]{1,16}|(?=[0-9a-fA-F]*\d)[0-9a-fA-F]{6,16}")
_AUTO_NAME_RE = auto_name_pattern()
# A line of a listing that opens with its instruction's address: the address,
# then a mnemonic.
_ADDRESSED_LINE_RE = re.compile(
    r"^[ \t]*(?:0x)?([0-9a-fA-F]{4,16})h?[ \t:]+(?:[0-9a-fA-F]{2}[ \t]+)*[A-Za-z]{2,7}\b",
    re.MULTILINE,
)
# The fields a row of a code list names its function in, in the order read.
_FUNCTION_FIELDS = (
    "address",
    "addr",
    "entry_point",
    "entry",
    "start",
    "ea",
    "function",
    "name",
    "symbol",
)
# How deep a cut answer is read member by member: the answer, a function's
# value or the list of rows, a row, a row's field.
_CUT_READ_DEPTH = 4
_WHITESPACE_RE = re.compile(r"[ \t\r\n]*")
_NO_MEMBER = object()


def _function_key(key: Any) -> bool:
    said = str(key).strip()
    return bool(_FUNCTION_KEY_RE.fullmatch(said) or _AUTO_NAME_RE.fullmatch(said))


def function_address(where: Any) -> int | None:
    """The address a function's key or name writes, or ``None`` for a name that holds none.

    ``0x`` and hex digits, six hex digits or more, or a decompiler's own name
    for a function (``FUN_00401000``, ``fcn.00401000``).
    """
    said = str(where or "").strip()
    named = _AUTO_NAME_RE.fullmatch(said)
    if named is not None:
        return int(named.group(1), 16)
    if _FUNCTION_KEY_RE.fullmatch(said):
        return int(said[2:] if said[:2].lower() == "0x" else said, 16)
    return None


def function_key(where: Any) -> str:
    """One spelling for one function: its address in lower-case hex with no ``0x``, else its name.

    ``0x1360bc03868``, ``1360bc03868`` and ``FUN_1360bc03868`` are one key.
    """
    address = function_address(where)
    return f"{address:x}" if address is not None else str(where or "").strip().lower()


def names_itself(part: CodePart) -> bool:
    """Whether a function's code names the function its key or row names.

    Its address's own decompiler name stands in it (``FUN_00401000`` under
    ``0x401000``), or its first addressed line is at that address. A
    cross-reference list, a string table or a rule's matches keyed by
    address holds other addresses: none of them names its key.
    """
    address = function_address(part.where)
    if address is None:
        return False
    if any(int(m.group(1), 16) == address for m in _AUTO_NAME_RE.finditer(part.code)):
        return True
    first = _ADDRESSED_LINE_RE.search(part.code)
    return first is not None and int(first.group(1), 16) == address


def _part_code(value: Any, path: str = "") -> str:
    """The code one function's value holds: a code string, or the code under a row's code key.

    A row is read at the declared ``path``, else only in its fields named for
    code (``code``, ``decompiled``, ``pseudocode``, ``disassembly`` …): a
    string table's text or a rule's matches are not a function's code.
    """
    if path and isinstance(value, Mapping):
        from maljan.core.tool_declarations import first

        held = first(value, path)
        if isinstance(held, str) and (holds_code(held) or holds_bare_listing(held)):
            return held.strip("\n")
    if isinstance(value, str):
        return value.strip("\n") if holds_code(value) else ""
    if isinstance(value, Mapping):
        found = [(key, text) for key, text in code_strings(value) if _CODE_KEY_RE.search(key)]
        return _pick_code(found).strip("\n") if found else ""
    return ""


def _row_where(row: Any, at: int, named: tuple[str, ...]) -> str:
    """The function a row of a code list names: a declared path, else a field named for one.

    Every ledger id in a name is written out (``utils.written_forms.
    ids_written_out``): a row's name is the tool's text, never a citation.
    """
    from maljan.utils.written_forms import ids_written_out

    if isinstance(row, Mapping):
        from maljan.core.tool_declarations import first

        held = [first(row, path) for path in named if path]
        held.extend(row.get(name) for name in _FUNCTION_FIELDS)
        for value in held:
            if isinstance(value, bool):
                continue
            if isinstance(value, int):
                return f"0x{value:x}"
            if isinstance(value, str) and value.strip():
                return ids_written_out(value.strip()[:120])
    return f"item {at}"


def _filled(value: Any) -> bool:
    return value is not None and value not in ("", [], {})


def _read_cut(text: str, at: int, depth: int, cuts: dict[int, Any]) -> tuple[Any, int, bool]:
    """``(value, end, cut)`` of the JSON value at ``at`` of an answer cut for storage.

    A whole value is read whole; a string the cut fell in is read to the cut
    (:func:`_read_to_cut`); an object or a list the cut fell in is read
    member by member, to ``depth`` levels, its whole members kept and the
    member the cut fell in kept as far as it reads. ``cuts`` records, by the
    id of each container the cut fell in, the key or index of that member.
    Each level reads its text once more than the level above: linear in the
    answer for the fixed depth.
    """
    import json

    try:
        value, end = json.JSONDecoder().raw_decode(text, at)
        return value, end, False
    except ValueError:
        pass
    except RecursionError:
        # Nested deeper than the decoder reads: nothing of it is read.
        return None, len(text), True
    if at >= len(text):
        return None, at, True
    opening = text[at]
    if opening == '"':
        return _read_to_cut(text[at + 1 :]), len(text), True
    if opening not in "{[" or depth <= 0:
        return None, len(text), True
    from json import decoder

    scanstring = decoder.scanstring  # type: ignore[attr-defined]
    keyed = opening == "{"
    container: Any = {} if keyed else []
    pos = at + 1
    while True:
        pos = _WHITESPACE_RE.match(text, pos).end()  # type: ignore[union-attr]
        if pos < len(text) and text[pos] == ("}" if keyed else "]"):
            return container, pos + 1, False
        key: Any = len(container)
        if keyed:
            if pos >= len(text) or text[pos] != '"':
                return container, len(text), True
            try:
                key, pos = scanstring(text, pos + 1, False)
            except ValueError:
                return container, len(text), True
            pos = _WHITESPACE_RE.match(text, pos).end()  # type: ignore[union-attr]
            if pos >= len(text) or text[pos] != ":":
                return container, len(text), True
            pos = _WHITESPACE_RE.match(text, pos + 1).end()  # type: ignore[union-attr]
        if pos >= len(text):
            return container, pos, True
        value, pos, cut = _read_cut(text, pos, depth - 1, cuts)
        if cut:
            if _filled(value):
                if keyed:
                    container[key] = value
                else:
                    container.append(value)
                cuts[id(container)] = key
            return container, len(text), True
        if keyed:
            container[key] = value
        else:
            container.append(value)
        pos = _WHITESPACE_RE.match(text, pos).end()  # type: ignore[union-attr]
        if pos < len(text) and text[pos] == ",":
            pos += 1
            continue
        if pos < len(text) and text[pos] == ("}" if keyed else "]"):
            return container, pos + 1, False
        return container, len(text), True


def code_parts(
    answer: Any, path: str = "", rows: str = "", named: tuple[str, ...] = ()
) -> list[CodePart]:
    """The functions an answer lists code for one by one, in its order; ``[]`` for any other.

    Read by the answer's shape, never by its tool: an object every key of
    which names a function (an address or a decompiler's own name) is one
    function per key, a key whose value holds no code (an error) left out;
    the declared ``rows`` (``ToolFacts.rows``), or a list of rows (the
    answer, or its one list member when no code stands beside it), each
    holding code, is one function per row, named by the declared ``named``
    paths or a field named for a function, else by its place. Two functions
    or more: one is the single listing :func:`code_listing` reads. An answer
    cut for storage is read member by member to the cut: the function the cut
    fell in is marked ``cut``, and the last one read ``answer_cut``. Linear in
    the answer; inside one reading (:func:`code_parts_read`) each answer is
    read once, however many readers ask. An answer nested deeper than the
    decoder reads lists no function.
    """
    key = (str(answer or "").strip(), path, rows, tuple(named))
    held = _PARTS_READ.get()
    if held is not None and key in held:
        return list(held[key])
    parts = _code_parts(*key)
    if held is not None:
        held[key] = parts
    return list(parts)


# The answers read in the reading under way (:func:`code_parts_read`), or
# ``None`` outside one.
_PARTS_READ: ContextVar[
    dict[tuple[str, str, str, tuple[str, ...]], tuple[CodePart, ...]] | None
] = ContextVar("code_parts_read", default=None)


@contextmanager
def code_parts_read() -> Iterator[None]:
    """One reading of a run's answers: :func:`code_parts` reads each answer once inside it.

    A report build (a section's bundle, the ledger's sections, the figures)
    reads each answer under one; what it read is let go when the outermost
    one ends, so a long-lived worker holds no earlier job's answers. A
    reading inside another shares the outer one's.
    """
    if _PARTS_READ.get() is not None:
        yield
        return
    token = _PARTS_READ.set({})
    try:
        yield
    finally:
        _PARTS_READ.reset(token)


def _code_parts(said: str, path: str, rows: str, named: tuple[str, ...]) -> tuple[CodePart, ...]:
    if not said or said[0] not in "{[":
        return ()
    import json

    cuts: dict[int, Any] = {}
    answer_cut = False
    try:
        document: Any = json.loads(said)
    except RecursionError:
        return ()
    except ValueError:
        document, _end, answer_cut = _read_cut(said, 0, _CUT_READ_DEPTH, cuts)
    parts: list[CodePart]
    if isinstance(document, Mapping) and document and all(_function_key(k) for k in document):
        parts = [
            CodePart(str(key).strip(), code, _cut_in(cuts, document, key, value))
            for key, value in document.items()
            if (code := _part_code(value, path))
        ]
    else:
        listed = _listed_rows(document, rows)
        if listed is None:
            return ()
        parts = [
            CodePart(_row_where(row, at, named), code, _cut_in(cuts, listed, at - 1, row))
            for at, row in enumerate(listed, start=1)
            if (code := _part_code(row, path))
        ]
    if len(parts) < 2:
        return ()
    if answer_cut:
        parts[-1] = parts[-1]._replace(answer_cut=True)
    return tuple(parts)


def _listed_rows(document: Any, rows: str) -> list[Any] | None:
    """The rows of a code list: the declared ``rows``, the answer, or its one list member.

    The one list member of an object is its rows only when no code stands
    beside it: an answer holding a function's code and a list of its blocks
    is one listing.
    """
    if rows:
        from maljan.core.tool_declarations import select

        found = select(document, rows)
        if found:
            return found
    if isinstance(document, list):
        return document
    if not isinstance(document, Mapping):
        return None
    members = [key for key, value in document.items() if isinstance(value, list)]
    if len(members) != 1:
        return None
    beside = {key: value for key, value in document.items() if key != members[0]}
    if code_strings(beside):
        return None
    listed = document[members[0]]
    return listed if isinstance(listed, list) else None


def _cut_in(cuts: dict[int, Any], container: Any, member: Any, value: Any) -> bool:
    """Whether the cut for storage fell in one member: its container says so, or the member does."""
    if cuts.get(id(container), _NO_MEMBER) == member:
        return True
    return isinstance(value, Mapping | list) and id(value) in cuts
