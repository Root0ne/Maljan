"""What the platform reads of a program-analysis server's tools, from what the server listed.

A decompiler or a disassembler (a server whose block's ``roles`` hold
:data:`PROGRAM_ROLES`) lists many tools that each read or change the program
it opened. What each one is, is read here from its MCP definition by the same
rules for every such server, never by a server's or a tool's name:

* its **verb**: the first word of its name (the word after ``batch`` or
  ``bulk`` for a batch tool), whose category is the tag an undeclared tool's
  description is shown with (``undeclared_tools.category_tag``). The verb
  gives a generic kind (:func:`program_kind`): a verb that changes the
  program is ``program_edit``, one that opens or loads a program
  ``open_sample``, one that selects an open program ``select_sample``, one
  that closes one ``sample_close``, ``emulate`` is ``emulation``, ``run``
  ``run``, ``import`` ``file_import``, a check ``check``, an analysis
  ``analysis``, a listing or read ``listing``, any other ``utility``; a name
  whose last word is ``status`` is ``status``, whose answer moves. Within a
  verb that does not change the program, the platform's own readings of an
  undeclared tool's name come first, so what a tool nobody declared is read
  as today it is still read as: a name that says it decompiles or
  disassembles is that code listing (``undeclared_tools.undeclared_code_kind``),
  one that says cross-references ``xrefs``, and a listing or read whose name
  says strings ``listing_strings``; a tool of another kind whose name says
  strings holds them (``holds_strings``). No vocabulary of one server's
  tools is kept: a server whose tools are renamed with the same verbs reads
  the same.
* its **arguments**, each by an exact role word: the argument named
  ``program``; the first argument read as a code or memory address of the
  binary (``undeclared_tools.named_as_address``, so a struct's, a range end's,
  a base's or a hash routine's address never is); and, for a tool that opens,
  imports, lists or reads, the argument that names a file (a path's word, or
  a name made only of the words a file is called by; never a category's or
  a folder's path).
* whether it **reads only**: a listing, read or code listing whose name says
  nothing of a state that moves (``current``, ``status``) and that takes no
  file path. This is only a candidate: it is in force only where the block
  says its tools run locally and reach nothing (``default_effects``) and,
  where its ``sample_open`` names the arguments a program is named by, the
  tool takes one (``derived_declarations.lay_under``). A tool that reads
  what no job opened (the programs open on the server, its scripts, its
  project) takes none, so it never answers from an earlier call.
* what it **does beyond answering**, only where its definition says it: the
  ``emulate`` verb runs the sample's code under emulation; a tool that
  requires an argument naming code, a script or a command runs whatever it
  is given, so none of its effects can be declared (``why_undeclared``); and a
  tool that says it submits or uploads and takes a file sends the file's bytes
  (``third_party: bytes``). Everything else is what the block says of its
  tools as a whole (``default_effects``), or undeclared.
* which **tools of the listing it aggregates**: a ``batch`` or ``bulk`` tool
  whose name without that word, in the singular, is another listed tool's
  name (``batch_create_labels`` of ``create_label``). Any other aggregate is
  not read: a name alone does not say which one tool a batch answers many
  calls of.

What is read is kept beside what the server declared, under the same launch
identity and past the process (``core.served_declarations``), and is in force
only for a block whose ``roles`` hold a program role; whatever the block or
its server declares of a tool is in force over it, field by field.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from maljan.core.tool_declarations import EXECUTES_EMULATION, THIRD_PARTY_BYTES, ToolFacts
from maljan.core.undeclared_tools import (
    _CATEGORY_BY_FIRST_WORD,
    named_as_address,
    named_as_strings_source,
    named_as_xrefs,
    undeclared_code_kind,
)

__all__ = [
    "PROGRAM_ROLES",
    "READ_KINDS",
    "RUNS_ANYTHING",
    "program_facts",
    "program_kind",
    "program_readings",
    "reads_a_program",
]

# The roles that say a block's server analyses a program it opened.
PROGRAM_ROLES: frozenset[str] = frozenset({"decompiler", "disassembler"})

# The generic kinds, by what a tool's verb does.
EDIT_KIND = "program_edit"
OPEN_KIND = "open_sample"
SELECT_KIND = "select_sample"
CLOSE_KIND = "sample_close"
EMULATION_KIND = "emulation"
RUN_KIND = "run"
IMPORT_KIND = "file_import"
CHECK_KIND = "check"
ANALYSIS_KIND = "analysis"
LISTING_KIND = "listing"
STRINGS_KIND = "listing_strings"
XREFS_KIND = "xrefs"
STATUS_KIND = "status"
OTHER_KIND = "utility"
# The kind the tool a block's ``sample_open`` names to analyse is read as.
ANALYSE_KIND = "analyse_sample"

# The kinds whose call only reads the opened program, given the rest of the
# read-only rule (:func:`program_facts`).
READ_KINDS: frozenset[str] = frozenset(
    {
        LISTING_KIND,
        STRINGS_KIND,
        XREFS_KIND,
        "decompile",
        "decompile_batch",
        "disassembly",
        "function_disassembly",
    }
)

# The verbs, by their category (``undeclared_tools.category_tag``), whose kind
# the category gives; the verbs a category does not settle are read by word.
_EDIT_CATEGORY = "MODIFY"
_READ_CATEGORIES = frozenset({"LIST", "READ"})
_OPEN_VERBS = frozenset({"open", "load"})
_SELECT_VERBS = frozenset({"switch", "select"})
_CLOSE_VERBS = frozenset({"close"})
# ``save`` writes the program or its project.
_SAVE_VERBS = frozenset({"save"})
_EMULATE_VERBS = frozenset({"emulate"})
_BATCH_WORDS = frozenset({"batch", "bulk"})
# The start of a verb that lists code: it decompiles or disassembles.
_CODE_VERBS = ("decompil", "disassembl")
# The words of a name that say its answer is a state that moves.
_MOVING_WORDS = frozenset({"current", "status"})
# The words of a required argument's name that say it takes code, a script
# or a command to run.
_CODE_WORDS = frozenset({"code", "script", "command", "cmd"})
# The words an argument that names a file is called by; a path's word, or a
# name made only of these.
_PATH_WORDS = frozenset({"path", "filepath", "filename", "pathname"})
_FILE_WORDS = frozenset({"file", "binary", "sample", "executable", "local", "input", "target"})
_FILE_ONLY = frozenset({"file", "binary", "sample", "executable"})
# The argument a program is named by.
PROGRAM_ARGUMENT = "program"

RUNS_ANYTHING: dict[str, str] = {
    "why_undeclared": "it runs whatever script or command it is given, so what it does is "
    "whatever that does"
}


def _words(name: str) -> tuple[str, ...]:
    """A name's words in order: split at ``_``, ``-`` and spaces, camelCase split, lowercased."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", str(name))
    return tuple(part for part in re.split(r"[_\-\s]+", spaced.lower()) if part)


def _before_by(words: tuple[str, ...]) -> tuple[str, ...]:
    """A name's words before ``by``: what it lists, not what it lists them by."""
    return words[: words.index("by")] if "by" in words else words


def _verb(words: tuple[str, ...]) -> tuple[str, bool]:
    """The verb of a name's words, and whether a ``batch`` or ``bulk`` word comes before it."""
    if words and words[0] in _BATCH_WORDS and len(words) > 1:
        return words[1], True
    return (words[0] if words else ""), False


def program_kind(name: str) -> str:
    """The generic kind a program-analysis tool's name gives, by its verb.

    Never empty: a name whose verb says nothing is ``utility``.
    """
    words = _words(name)
    verb, batch = _verb(words)
    category = _CATEGORY_BY_FIRST_WORD.get(verb, "TOOL")
    if category == _EDIT_CATEGORY or verb in _SAVE_VERBS:
        return EDIT_KIND
    if verb in _EMULATE_VERBS:
        return EMULATION_KIND
    if verb in _OPEN_VERBS:
        return OPEN_KIND
    if verb in _SELECT_VERBS:
        return SELECT_KIND
    if verb in _CLOSE_VERBS:
        return CLOSE_KIND
    if category == "IMPORT":
        return IMPORT_KIND
    if category == "EXEC":
        return RUN_KIND
    if words and words[-1] == "status" or category == "META":
        return STATUS_KIND
    # A code listing only where the verb itself decompiles or disassembles:
    # ``use_decompiler`` and ``list_decompilers`` name a decompiler, not code.
    code = undeclared_code_kind(name) if verb.startswith(_CODE_VERBS) else ""
    if code:
        return "decompile_batch" if code == "decompile" and batch else code
    # What a name lists is what comes before ``by``: ``list_data_items_by_xrefs``
    # lists data items, ordered by their references.
    if named_as_xrefs("_".join(_before_by(words))):
        return XREFS_KIND
    if category in _READ_CATEGORIES:
        return STRINGS_KIND if named_as_strings_source(name) else LISTING_KIND
    if category == "ANALYZE":
        return ANALYSIS_KIND
    if category == "CHECK":
        return CHECK_KIND
    return OTHER_KIND


def _properties(input_schema: Any) -> dict[str, Mapping[str, Any]]:
    props = input_schema.get("properties") if isinstance(input_schema, Mapping) else None
    if not isinstance(props, Mapping):
        return {}
    return {str(n): p for n, p in props.items() if isinstance(p, Mapping)}


def _required(input_schema: Any) -> tuple[str, ...]:
    raw = input_schema.get("required") if isinstance(input_schema, Mapping) else None
    return tuple(n for n in (raw if isinstance(raw, list) else []) if isinstance(n, str))


def _names_a_file(name: str) -> bool:
    """Whether an argument's name says it names a file: a path's word, or file words alone."""
    words = set(_words(name))
    if not words:
        return False
    if words & _PATH_WORDS:
        return words <= _PATH_WORDS | _FILE_WORDS
    return bool(words & _FILE_ONLY) and words <= _FILE_WORDS


def _arguments(kind: str, props: Mapping[str, Any], required: tuple[str, ...]) -> dict[str, str]:
    """The roles read of a tool's arguments, each by an exact role word."""
    out: dict[str, str] = {}
    order = sorted(props, key=lambda n: n not in required)
    if PROGRAM_ARGUMENT in props:
        out["program"] = PROGRAM_ARGUMENT
    address = next((n for n in order if named_as_address(n)), "")
    if address:
        out["address"] = address
    if kind != EDIT_KIND:
        path = next((n for n in order if _names_a_file(n)), "")
        if path:
            out["path"] = path
    return out


def _runs_what_it_is_given(props: Mapping[str, Any], required: tuple[str, ...]) -> bool:
    """Whether a required argument's name says it takes code, a script or a command."""
    return any(set(_words(name)) & _CODE_WORDS for name in required if name in props)


def reads_a_program(facts: ToolFacts) -> bool:
    """Whether a reading's kind and arguments say the call only reads the opened program.

    The listing-level half of the read-only rule; :func:`program_facts` marks
    it as ``read_only``, kept only where the block allows it.
    """
    return facts.kind in READ_KINDS and "path" not in facts.arguments


def program_facts(
    definition: Any, listed: Iterable[str] = (), *, sends: bool = False
) -> ToolFacts | None:
    """What one listed tool of a program-analysis server is read as; ``None`` for a nameless one.

    ``listed`` holds the names of the whole listing (for ``aggregate_of``);
    ``sends`` that the tool says it submits or uploads and takes a file
    (``derived_declarations``), so it sends the file's bytes.
    """
    name = str(_get(definition, "name") or "")
    if not name:
        return None
    input_schema = _get(definition, "inputSchema")
    props = _properties(input_schema)
    required = _required(input_schema)
    kind = program_kind(name)
    words = _words(name)
    from maljan.core.undeclared_tools import category_tag

    held: dict[str, Any] = {"kind": kind, "category": category_tag(name).lower()}
    arguments = _arguments(kind, props, required)
    if arguments:
        held["arguments"] = arguments
    if kind not in {STRINGS_KIND} and named_as_strings_source(name) and kind != EDIT_KIND:
        held["holds_strings"] = True
    # A read whose name says it answers a state that moves (``current``,
    # ``status``) answers the same only where it names the program it reads.
    if (
        kind in READ_KINDS
        and "path" not in arguments
        and (not set(words) & _MOVING_WORDS or "program" in arguments)
        and not _runs_what_it_is_given(props, required)
    ):
        held["read_only"] = True
    if _runs_what_it_is_given(props, required):
        held["effects"] = dict(RUNS_ANYTHING)
    elif sends:
        held["effects"] = {"network": True, "third_party": THIRD_PARTY_BYTES}
    elif kind == EMULATION_KIND:
        held["effects"] = {"executes": EXECUTES_EMULATION}
    aggregated = _aggregated(words, set(listed) - {name})
    if aggregated:
        held["aggregate_of"] = [aggregated]
    return ToolFacts.model_validate(held)


def _aggregated(words: tuple[str, ...], others: set[str]) -> str:
    """The listed tool a batch tool aggregates: its name without ``batch``/``bulk``, singular."""
    if not set(words) & _BATCH_WORDS:
        return ""
    rest = [w for w in words if w not in _BATCH_WORDS]
    if not rest or not rest[-1].endswith("s"):
        return ""
    last = rest[-1]
    for singular in (last[:-1], last[:-2] if last.endswith("es") else ""):
        name = "_".join([*rest[:-1], singular]) if singular else ""
        if name in others:
            return name
    return ""


def program_readings(definitions: Iterable[Any], sends: Iterable[str] = ()) -> dict[str, ToolFacts]:
    """What every tool of a listing is read as (:func:`program_facts`), by its listed name."""
    held = list(definitions)
    names = [str(_get(d, "name") or "") for d in held]
    sending = set(sends)
    out: dict[str, ToolFacts] = {}
    for name, definition in zip(names, held, strict=True):
        facts = program_facts(definition, names, sends=name in sending)
        if facts is not None:
            out[name] = facts
    return out


def _get(definition: Any, key: str) -> Any:
    if isinstance(definition, Mapping):
        return definition.get(key)
    return getattr(definition, key, None)
