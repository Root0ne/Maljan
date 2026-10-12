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
from collections.abc import Iterable, Mapping
from functools import lru_cache
from typing import Any

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


def address_arguments(facts: Any) -> tuple[str, ...]:
    """The arguments a call gives an address in, in the order they are read.

    The one the tool declares for the ``address`` role
    (``ToolFacts.arguments``) first, then :data:`ADDRESS_ARGUMENTS`: a
    declaration names the argument a tool's own name for an address has
    (``offset_va``), and a built-in's declaration does not name every
    argument that takes one (a byte range's ``start_address``), so the shared
    list still follows it.
    """
    declared = getattr(facts, "arguments", None)
    held = str(declared.get("address") or "") if isinstance(declared, Mapping) else ""
    if not held:
        return ADDRESS_ARGUMENTS
    return (held, *(name for name in ADDRESS_ARGUMENTS if name != held))


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
    """The arguments an entry's call gave an address in (:func:`address_arguments`)."""
    return address_arguments(entry_facts(entry))
