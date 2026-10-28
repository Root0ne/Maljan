"""What the platform reads of a program-analysis server's tools, from what the server listed.

A decompiler or a disassembler (a server whose block's ``roles`` hold
:data:`PROGRAM_ROLES`) lists many tools that each read or change the program
it opened. What each one is, is read here from its MCP definition by the same
rules for every such server, never by a server's or a tool's name:

* its **verb and object**: the first word of its name (the word after
  ``batch`` or ``bulk`` for a batch tool) and the words after it, before any
  ``by`` (camelCase read as words). The verb's category is the tag an
  undeclared tool's description is shown with. A verb that changes the
  program is ``program_edit`` (``force``/``refresh`` of a decompilation is
  ``decompile_refresh``); one that opens or loads a program ``open_sample``
  (of a project alone ``project_navigation``, from the project's store
  ``project_load``); one that selects an open program ``select_sample``; one
  that closes one ``sample_close``; ``emulate`` ``emulation``; ``run``
  ``run``; ``import`` of a file ``file_import``; a name whose last word is
  ``status`` ``status``, whose answer moves. A verb that decompiles or
  disassembles is the code listing its name says
  (``undeclared_tools.undeclared_code_kind``), and a name that says
  cross-references ``xrefs``. Any other reading verb's object names the
  kind a platform consumer reads, by :data:`OBJECT_KINDS` (``list_imports``
  ``import_listing``, ``get_current_program_info`` ``program_info``,
  ``detect_crypto_constants`` ``crypto_constants`` …); a batch's answer is
  many answers, so its object names none. Else the category gives
  ``check``, ``analysis``, ``listing`` or ``utility``; a tool whose name
  says strings and whose kind is no strings kind holds them
  (``holds_strings``). The object words are the consumers' own, the same
  for every server: a server whose tools say the same with other verbs of
  the same category, or other spellings, reads the same.
* its **arguments**, each by an exact role word: the argument named
  ``program``; the first argument read as a code or memory address of the
  binary (``undeclared_tools.named_as_address``, so a struct's, a range end's,
  a base's or a hash routine's address never is); and, for a tool that opens,
  imports, lists or reads, the argument that names a file (a path's word, or
  a name made only of the words a file is called by; never a category's or
  a folder's path).
* whether it **reads only**: a tool of a listing or reading verb, or a code
  listing or cross-reference reading, whose name says
  nothing of a state that moves (``current``, ``status``) and that takes no
  file path. This is only a candidate: it is in force only where the block
  says its tools run locally and reach nothing (``default_effects``) and,
  where its ``sample_open`` names the arguments a program is named by, the
  tool takes one (``derived_declarations.lay_under``). A tool that reads
  what no job opened (the programs open on the server, its scripts, its
  project) takes none, so it never answers from an earlier call.
* what it **does beyond answering**, only where its definition says it: the
  ``emulate`` verb runs the sample's code under emulation; a ``run`` verb
  (the block's own analysis step aside) and a tool with any argument named
  for code, a script, a command or an expression run whatever they are
  given, so none of their effects can be declared (``why_undeclared``); and a
  tool that takes the file's content, or says it submits, uploads or sends
  and takes a file, sends the file's bytes (``third_party: bytes``).
  Everything else is what the block says of its tools as a whole
  (``default_effects``), or undeclared.
* which **tools of the listing it aggregates** (:func:`_aggregated`): a
  ``batch``, ``bulk`` or ``full`` tool, or one whose object is the plural of
  another's and whose arguments name it, aggregates each listed tool of its
  verb whose object is its own in the singular, or whose object an argument
  of its names (``batch_decompile`` over ``functions`` of
  ``decompile_function``), or else the one tool whose object holds its own.
  A batch that fits several tools no argument tells apart
  (``get_bulk_xrefs``) aggregates none.

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
    "RUNS_UNSAID",
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
# An open of a project, not of a program.
PROJECT_KIND = "project_navigation"


def _singular(word: str) -> str:
    if word.endswith("ies"):
        return word[:-3] + "y"
    if word.endswith(("sses", "shes", "ches", "xes")):
        return word[:-2]
    if word.endswith("s") and not word.endswith("ss"):
        return word[:-1]
    return word


def _stem(*stems: str) -> Any:
    """An object holding a word that starts with one of ``stems`` (``import`` in ``imported``)."""
    return lambda obj, props: any(w.startswith(stems) for w in obj)


def _exactly(*words: str) -> Any:
    """An object that is ``words`` and nothing else: a list of them, never one of them."""
    return lambda obj, props: obj == words


def _holds(*words: str) -> Any:
    """An object that holds every one of ``words``, singular or plural."""
    wanted = {_singular(w) for w in words}
    return lambda obj, props: wanted <= {_singular(w) for w in obj}


def _either(*tests: Any) -> Any:
    return lambda obj, props: any(t(obj, props) for t in tests)


def _names_one_function(obj: tuple[str, ...], props: Mapping[str, Any]) -> bool:
    """An object headed ``function`` whose arguments name one function: its address or name."""
    if not obj or _singular(obj[0]) != "function":
        return False
    return any(named_as_address(n) or set(_words(n)) <= {"function", "name", "func"} for n in props)


# How a verb reads, for the object it names: one that lists or reads (the
# ``LIST`` and ``READ`` categories, and the reading verbs a category does not
# hold), one that analyses or checks, and any verb at all.
_LISTING = "listing"
_SEARCHING = "searching"
_ANALYSING = "analysing"
_ANALYZING = "analyzing"
_ANY = "any"
# The verbs that read beside those the categories hold; a search's answer is
# hits, not the list a consumer reads by kind.
_READING_VERBS = frozenset({"show", "fetch", "dump", "enumerate", "view", "display", "print"})
_ANALYSING_VERBS = frozenset({"scan", "examine", "audit", "verify", "check", "validate"})
# Of those, the verbs that analyse rather than check.
_EXAMINING_VERBS = frozenset({"scan", "examine", "audit"})

# The kinds the platform's own consumers read (``builtin_declarations.CONSUMER_KINDS``,
# ``reporting.evidence_bundles._SECTION_KINDS``, the evidence roots and the
# image range), each with how a verb reads it and the object words that name
# it, in the order they are tried. The same for every server: a word here is
# the consumer's, never one tool's.
OBJECT_KINDS: tuple[tuple[str, Any, str], ...] = (
    (_LISTING, _stem("import"), "import_listing"),
    (_LISTING, _stem("export"), "export_listing"),
    (_LISTING, _stem("segment", "section"), "segments"),
    (_LISTING, _exactly("functions"), "function_list"),
    (_LISTING, _exactly("methods"), "method_list"),
    (_LISTING, _exactly("strings"), STRINGS_KIND),
    (_SEARCHING, _exactly("strings"), "string_search"),
    (_ANY, _stem("caller"), "callers"),
    (_ANY, _stem("callee"), "callees"),
    (
        _ANY,
        _either(_holds("program", "info"), _holds("binary", "info"), _holds("file", "info")),
        "program_info",
    ),
    (_ANY, _holds("call", "chain"), "call_chains"),
    (_ANY, _holds("crypto", "constant"), "crypto_constants"),
    (_ANY, _either(_holds("dataflow"), _holds("data", "flow")), "dataflow"),
    (_ANY, _stem("ioc"), "iocs_with_context"),
    (_ANY, _stem("behavior", "behaviour"), "behaviour_scan"),
    (_ANY, _holds("anti", "analysis"), "anti_analysis_scan"),
    (_ANY, _holds("documentation", "completeness"), "documentation_completeness"),
    (_ANALYSING, _holds("completeness"), "documentation_completeness"),
    (_ANALYZING, _names_one_function, "function_analysis"),
)


def _reads_as(verb: str, category: str) -> set[str]:
    """How a verb reads the object it names (:data:`OBJECT_KINDS`)."""
    out = {_ANY}
    if (category in _READ_CATEGORIES and verb != "search") or verb in _READING_VERBS:
        out.add(_LISTING)
    if verb == "search":
        out.add(_SEARCHING)
    if category in ("ANALYZE", "CHECK") or verb in _ANALYSING_VERBS:
        out.add(_ANALYSING)
    if category == "ANALYZE" or verb in _EXAMINING_VERBS:
        out.add(_ANALYZING)
    return out


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
# The words an object names a decompilation by (never ``decompiler``, the tool).
_DECOMPILATION = frozenset({"decompile", "decompilation", "decompiled"})
# The verbs that run what they are given, beside the ``EXEC`` category's.
_RUN_VERBS = frozenset({"exec", "execute", "eval", "evaluate", "invoke", "interpret"})
# What an open's object names: a program or a file, a project, and the words
# between them (``load_program_from_project``).
_PROGRAM_WORDS = frozenset({"program", "programs", "file", "binary", "sample"})
_PROJECT_WORDS = frozenset({"project", "projects", "workspace"})
_LINKING_WORDS = frozenset({"from", "in", "into", "of", "to", "the"})
_BATCH_WORDS = frozenset({"batch", "bulk"})
# The words that say a tool answers many calls of another in one.
_AGGREGATE_WORDS = _BATCH_WORDS | {"full"}
# The start of a verb that lists code: it decompiles or disassembles.
_CODE_VERBS = ("decompil", "disassembl")
# The words of a name that say its answer is a state that moves.
_MOVING_WORDS = frozenset({"current", "status"})
# The words of an argument's name that say it takes code, a script or a
# command to run, whatever the tool's verb and whatever other words the name
# holds (``user_script``, ``hook_code``, ``asm_code``), but for a name whose
# other words are all generic property words, which name a property of the
# code, never code (``code_style``, ``script_type``, ``command_count``).
_CODE_WORDS = frozenset({"code", "script", "command", "cmd", "python", "js", "lua"})
_PROPERTY_WORDS = frozenset(
    {
        "style",
        "type",
        "kind",
        "mode",
        "format",
        "language",
        "lang",
        "id",
        "count",
        "limit",
        "offset",
        "page",
        "size",
    }
)
# The words that say code only for a verb that runs or evaluates
# (``eval_expr(expression)``, ``exec_python(source)``; ``search_strings(query)``
# searches), with the words that may carry them (``source_text``); and an
# expression a tool evaluates as a condition or a filter, for any verb
# (``condition_expression``).
_RUN_ONLY_CODE_WORDS = frozenset({"source", "query", "expression", "expr"})
_CODE_CARRIER_WORDS = frozenset({"name", "text", "body", "inline", "string"})
_EVALUATED_EXPRESSION_WORDS = frozenset({"condition", "filter", "eval", "predicate", "guard"})
# The words an argument that names a file is called by; a path's word, or a
# name made only of these.
_PATH_WORDS = frozenset({"path", "filepath", "filename", "pathname"})
_FILE_WORDS = frozenset({"file", "binary", "sample", "executable", "local", "input", "target"})
_FILE_ONLY = frozenset({"file", "binary", "sample", "executable"})
# The kinds a strings reader reads by kind.
_STRINGS_KINDS = frozenset({STRINGS_KIND, "string_search"})
# The argument a program is named by.
PROGRAM_ARGUMENT = "program"

RUNS_ANYTHING: dict[str, str] = {
    "why_undeclared": "it runs whatever script or command it is given, so what it does is "
    "whatever that does"
}
# What a ``run`` verb with no such argument is read as: what it runs is not
# said. The block's own analysis step (its ``sample_open``) is read as the
# block says instead (``derived_declarations._in_block``).
RUNS_UNSAID: dict[str, str] = {
    "why_undeclared": "it runs what it is asked to run, and its definition does not say what"
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


def _object(words: tuple[str, ...]) -> tuple[str, ...]:
    """What a name's verb acts on: its words after the verb (and a batch word), before ``by``."""
    rest = _before_by(words)
    at = 2 if rest and rest[0] in _BATCH_WORDS and len(rest) > 1 else 1
    return tuple(w for w in rest[at:] if w not in _BATCH_WORDS)


def _object_kind(verb: str, category: str, obj: tuple[str, ...], props: Mapping[str, Any]) -> str:
    """The consumer kind a reading verb's object names (:data:`OBJECT_KINDS`); ``""`` for none."""
    reads = _reads_as(verb, category)
    for how, test, kind in OBJECT_KINDS:
        if how in reads and test(obj, props):
            return kind
    return ""


def _decompiles_again(verb: str, obj: tuple[str, ...]) -> bool:
    """Whether a verb redoes a decompilation: a verb on one, or ``re`` and the code verb."""
    if verb.startswith("re") and verb[2:].startswith("decompil"):
        return True
    return not verb.startswith(_CODE_VERBS) and bool(obj) and obj[0] in _DECOMPILATION


def program_kind(name: str, props: Mapping[str, Any] | None = None) -> str:
    """The generic kind a program-analysis tool's name gives, by its verb and its object.

    ``props`` are its arguments, which say whether it names one function.
    Never empty: a name whose verb says nothing is ``utility``.
    """
    held_props: Mapping[str, Any] = props or {}
    words = _words(name)
    verb, batch = _verb(words)
    obj = _object(words)
    category = _CATEGORY_BY_FIRST_WORD.get(verb, "TOOL")
    if _decompiles_again(verb, obj):
        return "decompile_refresh"
    if category == _EDIT_CATEGORY or verb in _SAVE_VERBS:
        return EDIT_KIND
    if verb in _EMULATE_VERBS:
        return EMULATION_KIND
    if verb in _OPEN_VERBS:
        # A program from the project's store, a project, or a file or program.
        held = set(obj) - _LINKING_WORDS
        if "project" in held and held & _PROGRAM_WORDS:
            return "project_load"
        if held and held <= _PROJECT_WORDS:
            return PROJECT_KIND
        return OPEN_KIND
    if verb in _SELECT_VERBS:
        return SELECT_KIND
    if verb in _CLOSE_VERBS:
        return CLOSE_KIND
    if category == "IMPORT":
        named_file = bool(obj) and set(obj) <= _FILE_WORDS and bool(set(obj) & _FILE_ONLY)
        return IMPORT_KIND if named_file else "import"
    if category == "EXEC" or verb in _RUN_VERBS:
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
    # A batch's answer is many answers, not the one a consumer reads by kind.
    named = "" if batch else _object_kind(verb, category, obj, held_props)
    if named:
        return named
    if category in _READ_CATEGORIES:
        return LISTING_KIND
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


def _runs_what_it_is_given(
    props: Mapping[str, Any], required: tuple[str, ...], *, runs: bool = False
) -> bool:
    """Whether an argument's name says it takes code, a script, a command or an expression.

    Any argument, required or not, fail closed: a name holding a code word
    (:data:`_CODE_WORDS`) unless its other words are all property words
    (:data:`_PROPERTY_WORDS`); for a verb that runs or evaluates (``runs``), a
    name made of a source, a query or an expression and the words that carry
    them; for any verb, an expression evaluated as a condition or a filter.
    """
    for name in props:
        words = set(_words(name))
        if words & _CODE_WORDS:
            others = words - _CODE_WORDS
            if not others or not others <= _PROPERTY_WORDS:
                return True
            continue
        if words & {"expression", "expr"} and words & _EVALUATED_EXPRESSION_WORDS:
            return True
        if (
            runs
            and words & _RUN_ONLY_CODE_WORDS
            and words <= (_RUN_ONLY_CODE_WORDS | _CODE_CARRIER_WORDS)
        ):
            return True
    return False


def takes_content(props: Mapping[str, Any]) -> bool:
    """Whether an argument takes the file's content, by the disclosure reading's one rule.

    ``derived_declarations.takes_content``: there is no second copy of it.
    """
    from maljan.core.derived_declarations import takes_content as reads_content

    return reads_content(props.items())


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
    ``sends`` that the tool says it submits, uploads or sends and takes a file
    (``derived_declarations``), so it sends the file's bytes, as one that
    takes the file's content does (:func:`takes_content`). A ``run`` verb, or
    an argument naming code to run, runs whatever it is given
    (:data:`RUNS_ANYTHING`), unless the block's ``sample_open`` names it as
    its analysis step (``derived_declarations._in_block``).
    """
    name = str(_get(definition, "name") or "")
    if not name:
        return None
    input_schema = _get(definition, "inputSchema")
    props = _properties(input_schema)
    required = _required(input_schema)
    kind = program_kind(name, props)
    words = _words(name)
    verb, _batch = _verb(words)
    runs = _CATEGORY_BY_FIRST_WORD.get(verb) == "EXEC" or verb in _RUN_VERBS
    # The tag an undeclared tool is shown with, by its first word, however
    # the name is spelt (``listImports`` as ``list_imports``).
    category = _CATEGORY_BY_FIRST_WORD.get(words[0] if words else "", "TOOL").lower()
    held: dict[str, Any] = {"kind": kind, "category": category}
    arguments = _arguments(kind, props, required)
    if arguments:
        held["arguments"] = arguments
    if kind not in _STRINGS_KINDS and named_as_strings_source(name) and kind != EDIT_KIND:
        held["holds_strings"] = True
    # A read whose name says it answers a state that moves (``current``,
    # ``status``) answers the same only where it names the program it reads.
    if (
        (kind in READ_KINDS or _reads_by_verb(words))
        and "path" not in arguments
        and (not set(words) & _MOVING_WORDS or "program" in arguments)
        and not _runs_what_it_is_given(props, required, runs=runs)
    ):
        held["read_only"] = True
    if _runs_what_it_is_given(props, required, runs=runs):
        held["effects"] = dict(RUNS_ANYTHING)
        held.pop("read_only", None)
    elif kind == RUN_KIND:
        held["effects"] = dict(RUNS_UNSAID)
        held.pop("read_only", None)
    elif sends or takes_content(props):
        held["effects"] = {"network": True, "third_party": THIRD_PARTY_BYTES}
    elif kind == EMULATION_KIND:
        held["effects"] = {"executes": EXECUTES_EMULATION}
    aggregated = _aggregated(name, props, [n for n in listed if n != name])
    if aggregated:
        held["aggregate_of"] = aggregated
    return ToolFacts.model_validate(held)


def _reads_by_verb(words: tuple[str, ...]) -> bool:
    """Whether a name's verb lists or reads, by its category (``undeclared_tools.category_tag``)."""
    verb, _batch = _verb(words)
    return _CATEGORY_BY_FIRST_WORD.get(verb, "TOOL") in _READ_CATEGORIES


def _aggregated(name: str, props: Mapping[str, Any], listed: Iterable[str]) -> list[str]:
    """The listed tools a batch tool aggregates, read from its verb, object and arguments.

    A tool is a batch tool when its name holds ``batch``, ``bulk`` or ``full``,
    or its object is the plural of another tool's of the same verb and one of
    its arguments names that object. It aggregates each listed tool of its
    verb (one with no such word) whose object is its own in the singular; or
    whose object, or a word of it where its own names none, an argument of
    its names in the plural (``batch_decompile`` over ``functions`` of
    ``decompile_function``); or, failing those, the one tool whose object
    holds all of its own.
    """
    words = _words(name)
    verb, _batch = _verb(words)
    if verb in _BATCH_WORDS:
        return []
    obj = tuple(_singular(w) for w in _object(words) if w != "full")
    others: list[tuple[str, tuple[str, ...]]] = []
    for other in listed:
        theirs = _words(other)
        if set(theirs) & _AGGREGATE_WORDS or _verb(theirs)[0] != verb:
            continue
        others.append((other, tuple(_singular(w) for w in _object(theirs))))
    argued = {_singular(w) for n in props for w in [n.lower()]}
    argued |= {"_".join(_singular(w) for w in _words(n)) for n in props}
    is_batch = bool(set(words) & _AGGREGATE_WORDS)
    if not is_batch:
        plural = _object(words)
        if not plural or plural[-1] == _singular(plural[-1]):
            return []
        if not any(set(_words(n)) & {plural[-1], _singular(plural[-1])} for n in props):
            return []
    held = [o for o, theirs in others if theirs == obj]
    if held:
        return held
    if not is_batch:
        return []
    held = [o for o, theirs in others if "_".join(theirs) in argued]
    if not held and not obj:
        held = [o for o, theirs in others if set(theirs) & argued]
    if held:
        return held
    wider = [o for o, theirs in others if obj and set(obj) < set(theirs)]
    return wider if len(wider) == 1 else []


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
