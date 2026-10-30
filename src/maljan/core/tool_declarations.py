"""What a tool server and each of its tools say about themselves, as data.

Every fact the core needs about a tool is declared here, on the server's own
settings block, never written in code against a tool's name: which of its tools
opens a sample, where it sees the job's sample, how its plain-text answers say
"error", what roles the server plays, the workflow text shown with its tools,
the environment names it cannot run without, and, per tool, what kind of fact
the answer is and where in the answer its rows, places, technique ids and
reputation counts sit.

The declaration lives in three places, all with this one schema:

* the built-in servers' and providers' blocks
  (``maljan.core.builtin_declarations``), shipped so that every current
  behaviour is the default;
* an operator's own server in ``mcp.servers`` (the same fields, edited in the
  console's server editor or the settings catalogue);
* the platform's in-process tool sources (the triage pack, the sandbox report
  tools, the evidence-only rule provider), declared the same way.

One merge rule applies to a built-in block: a declaration field the stored
block never set takes the built-in's value; a field the operator set, even to
an empty value, is kept as set (:func:`fill_declaration`). A save stores a
built-in's field only where it differs from the shipped value at the time of
the save (:func:`strip_declaration_defaults`), so a value written equal to the
shipped one is not recorded and follows later releases. A built-in's tool
declarations (``tool_facts``) follow the same rule one tool at a time: what is
stored is each tool's change over the shipped declaration of that tool (only
the fields that differ; ``null`` for a shipped tool an operator removed; the
whole declaration of a tool the block does not ship), and what is in force is
the shipped map with those changes over it (:func:`merge_tool_facts`,
:func:`tool_facts_changes`). A tool an operator never changed keeps following
later releases, and a tool shipped after the save appears. A server that is
not a built-in starts from nothing and inherits nothing: its stored map is its
whole map.

The read API (:class:`ToolDeclarations`, :func:`declaration_for`,
:func:`tools_of_kind`, :func:`servers_with_role`) resolves a ledger entry by the
source the entry recorded when it was written (``LedgerEntry.source``:
``mcp:<key>``, ``provider:<id>``, ``sandbox``, ``pack``) and its tool name
together. An entry with no recorded source (every entry written before sources
were recorded) resolves to nothing and is read by the legacy readers; nothing
is ever looked up by a bare tool name, an agent's name or today's settings.

Vocabulary values (a tool's ``kind``, a server's ``roles``, the names of place
and value fields, a technique ``format``, a ``reader`` id, a ``category``) are
an open set: any lowercase word of letters, digits and underscores is accepted,
so a new kind of tool needs no code change to be declared. The values the
built-ins use are listed in ``apps/docs/content/docs/configuration.mdx``.

Field paths (``rows``, ``places``, ``values``, technique and reputation paths)
are JSON-pointer-like: ``/`` separated keys, ``~0`` for ``~``, ``~1`` for ``/``
and ``~2`` for ``*`` inside a key, ``*`` for every item of a list or every value
of an object at that level, ``**`` for any depth (zero or more levels) and
``**N`` for at most N levels, at most once in a path and never in a path read
inside a row. :func:`select` reads one in time linear in the size of the answer.

Regular expressions an operator declares (error patterns, reputation text
patterns) are compiled and run by RE2 (``google-re2``), which matches in time
linear in the answer whatever the pattern; a pattern RE2 cannot compile (a
back-reference, a lookaround) is refused when it is saved.
"""

from __future__ import annotations

import contextvars
import hashlib
import json
import os
import posixpath
import re
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from functools import lru_cache, partial
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig, Settings

# An open vocabulary value: a lowercase word. Shape-checked, never a closed list.
VOCABULARY_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_VOCABULARY_RE = re.compile(VOCABULARY_PATTERN)
# An environment variable name, as a POSIX shell spells one.
ENV_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"
_ENV_NAME_RE = re.compile(ENV_NAME_PATTERN)
# A tool's argument name: an identifier, as a JSON schema property is written.
_ARGUMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$")
# A routed sample format's name, as the routing writes it (``pe``, ``mach-o``);
# read with ``fullmatch``, so no trailing newline passes.
_ROUTED_FORMAT_RE = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}")
# The separator a registry joins a server key and a tool name with when two
# servers offer the same name; a declared tool name may not hold it.
RENAMED_TOOL_SEPARATOR = "__"

# The two path wildcards, ``*`` and ``**``; ``**N`` bounds the depth.
EVERY = "*"
_ANY_DEPTH_RE = re.compile(r"^\*\*(\d{0,4})$")


def _word(value: str, what: str) -> str:
    if not _VOCABULARY_RE.match(value):
        raise ValueError(
            f"{what} {value!r} is not a vocabulary word: lowercase letters, digits and "
            "underscores, starting with a letter, at most 64 characters"
        )
    return value


def _words(values: Iterable[str], what: str) -> list[str]:
    return [_word(v, what) for v in values]


def check_tool_name(value: str, what: str = "tool name") -> str:
    """A declared tool name: not empty and without surrounding blanks.

    A name may hold ``__`` (a server's own tool may be called ``get__thing``);
    only a name that starts with its own server's key and ``__``, which is how
    a renamed tool is spelled, is refused, by :func:`check_own_prefix` where
    the server's key is known.
    """
    if not value or value != value.strip():
        raise ValueError(f"{what} {value!r} must be a tool's name, not empty or padded")
    return value


# A character that would break the one line a scope text is shown on: a line
# break or another control character, the Unicode line breaks (NEL, LINE
# SEPARATOR, PARAGRAPH SEPARATOR) included.
_SCOPE_BREAK = re.compile(r"[\x00-\x1f\x7f\x85\u2028\u2029]")


def check_scope_text(value: str, what: str = "shows") -> str:
    """What a tool's answer shows or does not show (``ToolFacts.shows``): one line of text.

    Kept as written, as ``display_name`` is (the note it gives a description
    is trimmed where it is written). A line break or another control
    character is refused in an operator's edit (``STRICT_DECLARATIONS``); a
    text already accepted is read with each run of them and of blanks as one
    space, with a warning. No length is imposed: the text is the operator's.
    """
    if not _SCOPE_BREAK.search(value):
        return value
    if STRICT_DECLARATIONS.get():
        raise ValueError(f"{what} is one line of text, without line breaks or control characters")
    read = " ".join(_SCOPE_BREAK.sub(" ", value).split())
    _warn_scope_breaks(what)
    return read


def _warn_scope_breaks(what: str) -> None:
    marker = (f"scope {what}", ())
    if marker in _WARNED:
        return
    if len(_WARNED) >= _WARNED_MAX:
        _WARNED.clear()
    _WARNED.add(marker)
    from maljan.core.logger import logger

    logger.warning(
        "A tool declaration's %s holds line breaks or control characters; each run of them "
        "is read as one space and the rest is kept.",
        loggable_names([what]),
    )


def check_own_prefix(server: str, names: Iterable[str]) -> None:
    """Refuse a declared tool name spelled as a renamed tool of ``server``.

    A registry renames a tool two servers both offer to
    ``<server key>__<tool>``; a declaration under that spelling would be read
    as the declaration of the tool ``<tool>``, so it is written under the
    tool's own name instead.
    """
    prefix = f"{server}{RENAMED_TOOL_SEPARATOR}"
    for name in names:
        if name.startswith(prefix):
            raise ValueError(
                f"tool {name!r} is spelled as {server!r}'s renamed tool "
                f"{name[len(prefix) :]!r}; declare it under its own name"
            )


def renamed_tool(server: str, tool: str) -> str:
    """``tool`` as ``server`` offers it: the name after ``<server>__`` when it is spelled so.

    The separator is read only right after the known server key, so a tool
    whose own name holds ``__`` keeps it.
    """
    prefix = f"{server}{RENAMED_TOOL_SEPARATOR}"
    return tool[len(prefix) :] if tool.startswith(prefix) else tool


# ---------------------------------------------------------------------------
# Field paths
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Deep:
    """A ``**`` segment: descend any number of levels, or at most ``bound``."""

    bound: int | None


def _segment(raw: str) -> str | _Deep:
    deep = _ANY_DEPTH_RE.match(raw)
    if deep:
        return _Deep(int(deep.group(1)) if deep.group(1) else None)
    if raw == EVERY:
        return EVERY
    return raw.replace("~2", "*").replace("~1", "/").replace("~0", "~")


def parse_path(path: str, *, in_row: bool = False) -> tuple[str | _Deep, ...]:
    """The segments of a declared field path, or ``ValueError`` saying what is wrong.

    ``""`` is no path (nothing declared). Every other path starts with ``/``.
    ``in_row`` paths are read once per row and may not hold ``**``: a row nested
    in another would be walked twice, and the read would no longer be linear.
    """
    if path == "":
        return ()
    if not path.startswith("/"):
        raise ValueError(f"field path {path!r} must start with '/'")
    segments = tuple(_segment(part) for part in path[1:].split("/"))
    deep = sum(1 for part in segments if isinstance(part, _Deep))
    if deep > 1:
        raise ValueError(f"field path {path!r} may hold '**' once, and holds it {deep} times")
    if deep and in_row:
        raise ValueError(f"field path {path!r} is read inside a row and may not hold '**'")
    return segments


def _children(node: Any) -> Iterator[Any]:
    if isinstance(node, Mapping):
        yield from node.values()
    elif isinstance(node, list | tuple):
        yield from node


def _step(node: Any, segment: str) -> Iterator[Any]:
    if segment == EVERY:
        yield from _children(node)
    elif isinstance(node, Mapping):
        if segment in node:
            yield node[segment]
    elif isinstance(node, list | tuple) and segment.isdigit():
        index = int(segment)
        if index < len(node):
            yield node[index]


def _walk(nodes: Iterable[Any], segments: Sequence[Any]) -> list[Any]:
    current = list(nodes)
    for segment in segments:
        current = [found for node in current for found in _step(node, segment)]
    return current


def _subtree(node: Any, bound: int | None) -> list[Any]:
    """Every node under ``node`` within ``bound`` levels, itself first, in document order."""
    out: list[Any] = []
    stack: list[tuple[Any, int]] = [(node, 0)]
    while stack:
        current, depth = stack.pop()
        out.append(current)
        if bound is None or depth < bound:
            stack.extend((child, depth + 1) for child in reversed(list(_children(current))))
    return out


def select(document: Any, path: str | Sequence[Any]) -> list[Any]:
    """Every value ``path`` names in ``document``, in document order.

    A path that names nothing gives ``[]``; ``""`` gives ``[]`` too (nothing is
    declared). With ``**`` the nodes under the part before it are each visited
    once, so the read is linear in the size of the document.
    """
    segments = parse_path(path) if isinstance(path, str) else tuple(path)
    if not segments:
        return []
    cut = next((i for i, s in enumerate(segments) if isinstance(s, _Deep)), None)
    if cut is None:
        return _walk([document], segments)
    deep = segments[cut]
    assert isinstance(deep, _Deep)
    roots = _walk([document], segments[:cut])
    rest = segments[cut + 1 :]
    under = [node for root in roots for node in _subtree(root, deep.bound)]
    return _walk(under, rest) if rest else under


def first(document: Any, path: str) -> Any:
    """The first value ``path`` names in ``document``, or ``None``."""
    found = select(document, path)
    return found[0] if found else None


def _check_path(value: str, *, in_row: bool = False) -> str:
    parse_path(value, in_row=in_row)
    return value


# ---------------------------------------------------------------------------
# Patterns: RE2, linear in the answer whatever the pattern
# ---------------------------------------------------------------------------


@lru_cache(maxsize=4096)
def compile_pattern(pattern: str) -> Any:
    """``pattern`` compiled by RE2, or ``ValueError`` saying why RE2 refuses it."""
    import re2

    # A refused pattern is answered with the reason below, not written to the
    # process's standard error by the engine as well.
    options = re2.Options()
    options.log_errors = False
    try:
        return re2.compile(pattern, options)
    except Exception as exc:  # noqa: BLE001 — RE2 raises its own error type
        detail = str(exc.args[0] if exc.args else exc)
        if detail.startswith("b'") or detail.startswith('b"'):
            detail = detail[2:-1]
        raise ValueError(
            f"{pattern!r} is not a pattern the platform can run in linear time ({detail}); "
            "back-references and lookarounds are not available"
        ) from exc


def _check_regex(value: str, what: str) -> str:
    try:
        compile_pattern(value)
    except ValueError as exc:
        raise ValueError(f"{what}: {exc}") from exc
    return value


def search_pattern(pattern: str, text: str) -> Any:
    """The first match of ``pattern`` anywhere in ``text``, or ``None``."""
    return compile_pattern(pattern).search(text)


def fullmatch_pattern(pattern: str, text: str) -> Any:
    """``pattern`` held against the whole of ``text``, or ``None``."""
    return compile_pattern(pattern).fullmatch(text)


def message_lines(text: str) -> str:
    """An error message as the platform files it: each line stripped, blank lines dropped."""
    return "\n".join(line.strip() for line in str(text).splitlines() if line.strip())


# ---------------------------------------------------------------------------
# The schema
# ---------------------------------------------------------------------------

# Where an error pattern is held: a tool's own answer, or the message of the
# MCP protocol error the client reports in place of an answer.
ERROR_TARGETS: tuple[str, ...] = ("answer", "protocol_error")
# The placeholder a remediation names the job's sample path with.
SAMPLE_PATH_PLACEHOLDER = "{sample_path}"


class ErrorPattern(BaseModel):
    """One way a server's answer says "error" instead of answering.

    How it is applied, in order:

    * the text is the tool's answer (``applies_to`` holding ``answer``) or the
      message of the MCP protocol error the client reports in its place
      (``protocol_error``), stripped of surrounding blanks;
    * a text holding a line break never matches a pattern that is not
      ``multiline``;
    * ``match`` is held against the *whole* text (a full match, never a line
      inside one: a listing of the sample's own strings can hold any sentence,
      and a string the sample carries is not the tool failing);
    * the error message is the text, or the group ``message_group`` names, each
      line stripped and blank lines dropped (:func:`message_lines`);
    * ``code`` is the error code the entry is filed under (``tool_failed``,
      ``bad_argument`` …), and the remediation is ``remediation_with_path``
      with ``{sample_path}`` replaced by the path the server can open for the
      job's sample where that is known, else ``remediation`` (empty: none);
    * ``tools`` names the tools it applies to, empty for every tool of the
      server.

    Patterns are compiled and run by RE2, in time linear in the text.
    """

    model_config = ConfigDict(frozen=True)

    match: str
    code: str = "tool_failed"
    remediation: str = ""
    remediation_with_path: str = ""
    tools: tuple[str, ...] = ()
    applies_to: tuple[str, ...] = ("answer",)
    multiline: bool = False
    message_group: str = ""

    @field_validator("match")
    @classmethod
    def _match_compiles(cls, value: str) -> str:
        if not value:
            raise ValueError("an error pattern needs a match")
        return _check_regex(value, "error pattern")

    @field_validator("code")
    @classmethod
    def _code_is_a_word(cls, value: str) -> str:
        return _word(value, "error code")

    @field_validator("tools")
    @classmethod
    def _tools_are_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(check_tool_name(v, "error pattern tool") for v in value)

    @field_validator("applies_to")
    @classmethod
    def _targets_are_known(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value:
            raise ValueError("applies_to names at least one of: " + ", ".join(ERROR_TARGETS))
        for target in value:
            if target not in ERROR_TARGETS:
                raise ValueError(
                    f"applies_to {target!r} is not one of: " + ", ".join(ERROR_TARGETS)
                )
        return value

    @model_validator(mode="after")
    def _the_message_group_is_in_the_pattern(self) -> ErrorPattern:
        if self.message_group and self.message_group not in (
            compile_pattern(self.match).groupindex
        ):
            raise ValueError(f"message_group {self.message_group!r} is not a group of the match")
        if self.remediation_with_path and SAMPLE_PATH_PLACEHOLDER not in self.remediation_with_path:
            raise ValueError(f"remediation_with_path needs {SAMPLE_PATH_PLACEHOLDER}")
        return self

    def matches(self, tool: str, text: str, *, target: str = "answer") -> bool:
        """Whether ``text`` from ``tool`` is this error, by the rules above."""
        return self.message(tool, text, target=target) is not None

    def message(self, tool: str, text: str, *, target: str = "answer") -> str | None:
        """The error message ``text`` files under, or ``None`` when it is not this error."""
        if target not in self.applies_to or (self.tools and tool not in self.tools):
            return None
        text = str(text).strip()
        if "\n" in text and not self.multiline:
            return None
        found = fullmatch_pattern(self.match, text)
        if found is None:
            return None
        said = found.group(self.message_group) if self.message_group else text
        # An optional group that took part in no match is no message: the whole text stands.
        return message_lines(text if said is None else said)

    def remediation_for(self, sample_path: str | None) -> str:
        """The remediation, naming ``sample_path`` where the pattern has a form for it."""
        if sample_path and self.remediation_with_path:
            return self.remediation_with_path.replace(SAMPLE_PATH_PLACEHOLDER, sample_path)
        return self.remediation


# The word that names no kind, read as an empty kind (``ToolFacts.kind``).
NO_KIND = "unclassified"

# The fields of a tool declaration, split by whether they are read without a
# kind. A kind-free field is read from the live declaration whatever the kind
# (the guard's budget, a call's argument roles, the tag a description is shown
# with, the words and name a tool is given, whether it discloses the sample,
# the routed formats and the runtimes it serves, what a call does beyond
# answering, the tools of its server it is the aggregate form of, what its
# answer shows and does not show).
# A kind-dependent field is read only through the kind (an answer's rows and
# the paths inside them, its techniques and reputation, a reader of its shape,
# the report sections it is shown to, where it names the files it wrote): a
# declaration that names no kind may not set one, since it would be read by
# nothing. The one place the split is written; the console's tool-declaration
# box reads it, with each field's default, from the served settings schema
# (:func:`declaration_fields`).
KIND_FREE_FIELDS: tuple[str, ...] = (
    "display_name",
    "category",
    "words",
    "timeout_seconds",
    "long_running",
    "memory_peak_mb",
    "discloses_sample",
    "read_only",
    "arguments",
    "routed_formats",
    "runtimes",
    "effects",
    "aggregate_of",
    "shows",
    "does_not_show",
)
KIND_DEPENDENT_FIELDS: tuple[str, ...] = (
    "asserts_techniques",
    "source",
    "holds_strings",
    "reads_delay_imports",
    "rows",
    "places",
    "values",
    "techniques",
    "reputation",
    "reader",
    "report_sections",
    "function_starts",
    "outputs",
)

# Whether a tool declaration is read as an operator's edit being saved. The
# rules above (no unknown key, no empty declaration, no field a kind would be
# needed to read) hold for what an operator types now: a save sets this for
# the declarations it adds or changes, and the console's box applies the same
# rules. Everything already accepted -- stored settings, shipped blocks, a
# runtime provider's declaration, an import -- is read leniently instead: what
# this version cannot read is left out with one warning, and the rest is kept,
# so one unknown key never costs a declaration, a settings build or a job.
STRICT_DECLARATIONS: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "strict_declarations", default=False
)


@contextmanager
def strict_declarations() -> Iterator[None]:
    """Read tool declarations inside this block as an operator's new edit (strictly)."""
    token = STRICT_DECLARATIONS.set(True)
    try:
        yield
    finally:
        STRICT_DECLARATIONS.reset(token)


# One line of a log naming a key an operator typed: line breaks and other
# control characters written out, each name and the list bounded, so a key
# can never forge a record or flood a collector.
_LOG_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_LOG_NAME_CHARS = 64
_LOG_NAMES = 20


def loggable_text(text: str) -> str:
    """``text`` with every control character written out, so it shows as one line."""
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return _LOG_CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def loggable_names(names: Iterable[Any]) -> str:
    """``names`` as one sanitised, bounded log text."""
    held = [str(name) for name in names]
    shown = []
    for name in held[:_LOG_NAMES]:
        if not name:
            # An empty name, shown as such rather than as nothing at all.
            shown.append('""')
            continue
        text = loggable_text(name)
        shown.append(text[:_LOG_NAME_CHARS] + ("…" if len(text) > _LOG_NAME_CHARS else ""))
    more = len(held) - len(shown)
    return ", ".join(shown) + (f" and {more} more" if more > 0 else "")


# What has already been warned about, so a settings object built per request
# does not repeat the same line; bounded, and cleared when full.
_WARNED: set[tuple[str, tuple[str, ...]]] = set()
_WARNED_MAX = 1024


def _warn_left_out(where: str, names: Iterable[str]) -> None:
    held = tuple(sorted(str(name) for name in names))
    marker = (where, held)
    if marker in _WARNED:
        return
    if len(_WARNED) >= _WARNED_MAX:
        _WARNED.clear()
    _WARNED.add(marker)
    from maljan.core.logger import logger

    logger.warning(
        "A tool declaration (%s) holds fields this version does not read; they are left "
        "out and the rest is kept: %s",
        loggable_names([where]),
        loggable_names(held),
    )


def _field_default(name: str) -> Any:
    return ToolFacts.model_fields[name].get_default(call_default_factory=True)


# How a yes-or-no field's value is read: pydantic's lax rule (``0``, ``"no"``,
# ``"off"``, ``"false"`` … are false), as the model reads it.
_YES_OR_NO = TypeAdapter(bool)


def is_set(name: str, value: Any) -> bool:
    """Whether a declaration's field ``name`` says something: its value is not the default.

    The one rule for "set", everywhere a declaration is read, saved or shown
    in the console's box. A yes-or-no field is compared as the model reads
    it (``0``, ``"false"``, ``"no"``, ``"off"`` are its default, ``False``);
    a value the model cannot read as one is set (and refused by the model).
    Every other field is compared as written, keys in any order.
    """
    default = _field_default(name)
    if isinstance(default, bool):
        try:
            return _YES_OR_NO.validate_python(value) is not default
        except ValidationError:
            return True
    return not _same(value, default)


def _set_fields(raw: Mapping[str, Any]) -> dict[str, Any]:
    """The keys of a raw declaration that say something: unknown ones, and known ones set."""
    fields = ToolFacts.model_fields
    out: dict[str, Any] = {}
    for key, value in raw.items():
        if key in fields and not is_set(key, value):
            continue
        out[str(key)] = value
    return out


def _same(left: Any, right: Any) -> bool:
    try:
        return json.dumps(left, sort_keys=True, default=str) == json.dumps(
            right, sort_keys=True, default=str
        )
    except (TypeError, ValueError):
        return bool(left == right)


def lenient_declaration(raw: Mapping[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """``raw`` without what this version cannot read, and the names left out.

    Unknown keys are left out; with no kind at all (absent or empty) the
    fields read only through a kind are left out too, so the tool is read as
    one that declares no kind. ``unclassified`` with a kind-dependent field is
    the ordinary kind word it always was (:func:`reads_no_kind`), and keeps
    them. Everything else is kept as written, and validated as ever.
    """
    fields = ToolFacts.model_fields
    left_out = [str(key) for key in raw if key not in fields]
    kept = {key: value for key, value in raw.items() if key in fields}
    if kept.get("kind") in (None, ""):
        for name in KIND_DEPENDENT_FIELDS:
            if name in kept and is_set(name, kept[name]):
                left_out.append(name)
                kept.pop(name)
    return kept, left_out


def kind_free_changes(value: Any) -> dict[str, dict[str, Any]]:
    """Per tool, the kind-dependent fields a stored declaration sets with no kind of its own.

    A change an operator stored over a declaration whose kind comes from
    elsewhere (``reputation: {rank: 30}`` over a lookup read from its server's
    listing, ``core.derived_declarations``): the lenient reading leaves such
    fields out of the tool's declaration (:func:`lenient_declaration`), and
    they are kept here instead, to be laid over the kind once one is in force
    (``derived_declarations.lay_under``). Never in an operator's edit, which
    is checked strictly.
    """
    if STRICT_DECLARATIONS.get() or not isinstance(value, Mapping):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for tool, raw in value.items():
        if not isinstance(raw, Mapping) or raw.get("kind") not in (None, ""):
            continue
        if reads_no_kind(raw):
            continue
        held = {
            name: _copy(raw[name])
            for name in KIND_DEPENDENT_FIELDS
            if name in raw and is_set(name, raw[name])
        }
        if held:
            out[str(tool)] = held
    return out


def reads_no_kind(raw: Mapping[str, Any]) -> bool:
    """Whether ``unclassified`` in ``raw`` names no kind: only when no kind-dependent field is set.

    The one rule for the word, everywhere a declaration is read or saved. A
    declaration of ``unclassified`` that sets rows, places, techniques or any
    other field read only through a kind keeps it as an ordinary kind word,
    read exactly as it always was; alone, or with kind-free fields only, it
    names no kind.
    """
    if raw.get("kind") != NO_KIND:
        return False
    return not any(name in raw and is_set(name, raw[name]) for name in KIND_DEPENDENT_FIELDS)


def declaration_fields() -> dict[str, Any]:
    """The split of a tool declaration's fields as the settings schema serves it.

    The word that names no kind, and each kind-free and kind-dependent field
    with its default as JSON: what the console's tool-declaration box needs
    to apply :func:`reads_no_kind` and the edit rules exactly as the API
    does, a field counting as set only when it differs from its default
    (:func:`is_set`: a yes-or-no field, one whose default is ``false``, read
    as the model reads it).
    """
    defaults = ToolFacts.model_construct().model_dump(mode="json")
    return {
        "no_kind": NO_KIND,
        "kind_free": {name: defaults[name] for name in KIND_FREE_FIELDS},
        "kind_dependent": {name: defaults[name] for name in KIND_DEPENDENT_FIELDS},
    }


def lenient_declarations(
    value: Mapping[str, Any], where: str = ""
) -> tuple[dict[str, Any], dict[str, list[str]]]:
    """A map of tool declarations read leniently: each tool's, and what each left out.

    A declaration that is not a mapping is kept for the model to refuse as
    ever. Each tool that left something out is warned about once.
    """
    out: dict[str, Any] = {}
    notes: dict[str, list[str]] = {}
    for tool, raw in value.items():
        if not isinstance(raw, Mapping):
            out[tool] = raw
            continue
        kept, left_out = lenient_declaration(raw)
        out[tool] = kept
        if left_out:
            notes[str(tool)] = left_out
            _warn_left_out(f"{where}{tool}", left_out)
    return out, notes


def _normal(raw: Any) -> str | None:
    """A raw declaration's meaning, as compared between a save and what was there."""
    if not isinstance(raw, Mapping):
        return None
    return json.dumps(_set_fields(raw), sort_keys=True, default=str)


def _aggregated(raw: Any) -> tuple[str, ...]:
    """The names a declaration's ``aggregate_of`` holds, read or as written; () for none."""
    if isinstance(raw, ToolFacts):
        return raw.aggregate_of
    value = raw.get("aggregate_of") if isinstance(raw, Mapping) else None
    if not isinstance(value, list | tuple):
        return ()
    return tuple(name for name in value if isinstance(name, str))


def aggregate_reference_errors(
    tool_facts: Mapping[str, Any],
    tools: Iterable[str] | None = None,
    *,
    only: Iterable[str] | None = None,
) -> dict[str, str]:
    """The refusals of each ``aggregate_of`` in ``tool_facts`` naming no tool of its server.

    A name is a tool of the server when the server declares it (a key of
    ``tool_facts``) or its allow-list names it (``tools``; ``None``, every
    tool the server serves, names none here: a served list is known only
    from a live handshake). A tool is not the aggregate form of itself, nor
    of a tool that declares itself the aggregate form of it. ``only`` limits
    the check to those tools' declarations. Keys are ``<tool>.aggregate_of``.
    """
    known = {str(name) for name in tool_facts} | {str(name) for name in tools or ()}
    wanted = None if only is None else {str(name) for name in only}
    errors: dict[str, str] = {}
    for tool, raw in tool_facts.items():
        if wanted is not None and str(tool) not in wanted:
            continue
        names = _aggregated(raw)
        if str(tool) in names:
            errors[f"{tool}.aggregate_of"] = "a tool is not the aggregate form of itself"
            continue
        unknown = [name for name in names if name not in known]
        if unknown:
            errors[f"{tool}.aggregate_of"] = (
                f"aggregate_of names {', '.join(repr(n) for n in unknown)}, which "
                f"{'is' if len(unknown) == 1 else 'are'} not a tool of this server; declare "
                "each in tool_facts (e.g. its category)"
            )
            continue
        mutual = _mutual(tool_facts, str(tool), names)
        if mutual:
            errors[f"{tool}.aggregate_of"] = (
                f"aggregate_of names {', '.join(repr(n) for n in mutual)}, which "
                f"{'declares' if len(mutual) == 1 else 'declare'} itself the aggregate form of "
                f"{str(tool)!r}; of two tools, only one is the aggregate form of the other"
            )
    return errors


def _mutual(tool_facts: Mapping[str, Any], tool: str, names: Iterable[str]) -> list[str]:
    """The tools among ``names`` that declare themselves the aggregate form of ``tool``."""
    return [name for name in names if tool in _aggregated(tool_facts.get(name))]


def known_aggregates(
    tool_facts: dict[str, ToolFacts], tools: Iterable[str] | None = None, where: str = ""
) -> dict[str, ToolFacts]:
    """``tool_facts`` with each ``aggregate_of`` holding only tools of its server.

    Read leniently, as everything already accepted is: a name that is no tool
    of the server (:func:`aggregate_reference_errors`), such as a tool an
    operator later removed, or one that declares itself the aggregate form of
    this tool in turn, is left out with one warning, and the rest of the
    declaration is kept. In an operator's edit (``STRICT_DECLARATIONS``) the
    reference is refused instead.
    """
    errors = aggregate_reference_errors(tool_facts, tools)
    if not errors:
        return tool_facts
    if STRICT_DECLARATIONS.get():
        raise ValueError("; ".join(f"tool_facts.{key}: {msg}" for key, msg in errors.items()))
    known = {str(name) for name in tool_facts} | {str(name) for name in tools or ()}
    out = dict(tool_facts)
    for key in errors:
        tool = key.removesuffix(".aggregate_of")
        facts = out[tool]
        mutual = set(_mutual(tool_facts, tool, facts.aggregate_of))
        kept = tuple(
            name
            for name in facts.aggregate_of
            if name in known and name != tool and name not in mutual
        )
        out[tool] = facts.model_copy(update={"aggregate_of": kept})
        _warn_unknown_aggregates(f"{where}{tool}", [n for n in facts.aggregate_of if n not in kept])
    return out


def _warn_unknown_aggregates(where: str, names: Iterable[str]) -> None:
    held = tuple(sorted(str(name) for name in names))
    marker = (f"aggregate_of {where}", held)
    if marker in _WARNED:
        return
    if len(_WARNED) >= _WARNED_MAX:
        _WARNED.clear()
    _WARNED.add(marker)
    from maljan.core.logger import logger

    logger.warning(
        "A tool declaration (%s) names, as tools it is the aggregate form of, names that are "
        "no tool of its server or that name it back; they are left out and the rest is kept: %s",
        loggable_names([where]),
        loggable_names(held),
    )


def changed_declaration_errors(
    incoming: Mapping[str, Any],
    before: Iterable[Mapping[str, Any] | None] = (),
    *,
    tools: Iterable[str] | None = None,
) -> dict[str, str]:
    """The strict refusals of the tool declarations in ``incoming`` that a save adds or changes.

    A tool's declaration is unchanged when it says what one of ``before``
    (the stored map, the shipped one) says for that tool, as written or as
    it is read leniently (what the console showed); an unchanged one is
    never refused, so a save that leaves a stored entry alone is never
    blocked by it. Each other one is validated strictly, its ``aggregate_of``
    against the tools of the server: the map's own and ``tools``, the
    server's allow-list (:func:`aggregate_reference_errors`). Keys are
    ``<tool>`` or ``<tool>.<field>``.
    """
    held = [b for b in before if isinstance(b, Mapping)]
    errors: dict[str, str] = {}
    changed: list[str] = []
    for tool, raw in incoming.items():
        said = _normal(raw)
        if said is not None:
            candidates = []
            for old in held:
                previous = old.get(tool)
                if not isinstance(previous, Mapping):
                    continue
                candidates.append(_normal(previous))
                kept, _left = lenient_declaration(previous)
                try:
                    read = ToolFacts.model_validate(kept).model_dump(mode="json")
                except (ValidationError, ValueError):
                    continue
                candidates.append(_normal(read))
            if said in candidates:
                continue
        with strict_declarations():
            try:
                ToolFacts.model_validate(raw)
            except ValidationError as exc:
                for err in exc.errors():
                    loc = ".".join(str(part) for part in err["loc"])
                    errors[f"{tool}.{loc}" if loc else str(tool)] = err["msg"]
                continue
        changed.append(str(tool))
    if changed:
        errors.update(aggregate_reference_errors(incoming, tools, only=changed))
    return errors


class TechniqueField(BaseModel):
    """Where an answer names ATT&CK technique ids, and how they are written.

    ``format`` names the reader: ``attck`` for a bare id or a decorated label
    (``Defense Evasion::Obfuscated Files or Information [T1027]``), as
    ``analysis.technique_ids.technique_ids_in`` reads one; ``sigma_tag`` for a
    Sigma tag (``attack.t1055.012``). Open vocabulary.
    """

    model_config = ConfigDict(frozen=True)

    path: str
    format: str = "attck"

    @field_validator("path")
    @classmethod
    def _path_parses(cls, value: str) -> str:
        if not value:
            raise ValueError("a technique field needs a path")
        return _check_path(value)

    @field_validator("format")
    @classmethod
    def _format_is_a_word(cls, value: str) -> str:
        return _word(value, "technique format")


class ReputationFacts(BaseModel):
    """Where a reputation answer holds its counts, labels, dates and link.

    ``service`` is the name the answer is attributed to (empty: the tool's
    ``display_name``, else the server key). ``stats`` names the object of
    engine counts; ``malicious``, ``suspicious`` and ``total`` the counts (an
    empty ``total`` is the sum of ``stats``' whole-number values). ``labels``
    are the paths of the threat labels, in the order they are read;
    ``detections`` the list of per-engine result labels; ``engines`` the engine
    count the service gives beside them. ``first_seen``, ``last_seen`` and
    ``link`` are paths tried in order, the first that names a value giving it
    (a date as an ISO-8601 text or whole seconds since the epoch, a link as an
    ``http(s)`` URL). ``summary`` is the path of the service's own sentence
    about the sample in a JSON answer; an answer written in prose is its own
    summary.
    ``text_patterns`` read an answer written in prose: regular expressions with
    a ``malicious`` group and optionally ``total`` and ``suspicious`` groups,
    each *searched* for anywhere in the answer, the first pattern that finds a
    match giving the counts. ``rank`` orders the lookups the triage pack may
    ask: the lowest rank first, lookups of one rank in the order their servers
    are configured.
    """

    model_config = ConfigDict(frozen=True)

    service: str = ""
    stats: str = ""
    malicious: str = ""
    suspicious: str = ""
    total: str = ""
    labels: tuple[str, ...] = ()
    detections: str = ""
    engines: str = ""
    first_seen: tuple[str, ...] = ()
    last_seen: tuple[str, ...] = ()
    link: tuple[str, ...] = ()
    summary: str = ""
    text_patterns: tuple[str, ...] = ()
    rank: int = Field(default=100, ge=0)

    @field_validator(
        "stats", "malicious", "suspicious", "total", "detections", "engines", "summary"
    )
    @classmethod
    def _paths_parse(cls, value: str) -> str:
        return _check_path(value)

    @field_validator("labels", "first_seen", "last_seen", "link")
    @classmethod
    def _path_lists_parse(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_check_path(v) for v in value)

    @field_validator("text_patterns")
    @classmethod
    def _text_patterns_name_their_count(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for pattern in value:
            _check_regex(pattern, "reputation text pattern")
            if "malicious" not in compile_pattern(pattern).groupindex:
                raise ValueError(
                    f"reputation text pattern {pattern!r} needs a group named 'malicious'"
                )
        return value

    def counts_in_text(self, text: str) -> tuple[int, int | None, int | None] | None:
        """``(malicious, total, suspicious)`` from the first text pattern that finds them.

        ``None`` when no pattern finds a match; a group a pattern does not
        have, or one that took part in no match, gives ``None``.
        """
        for pattern in self.text_patterns:
            found = search_pattern(pattern, text)
            if found is not None and found.group("malicious") is not None:
                groups = compile_pattern(pattern).groupindex

                def _group(name: str, held: Any = found, named: Any = groups) -> int | None:
                    value = held.group(name) if name in named else None
                    return int(value) if value else None

                return int(found.group("malicious")), _group("total"), _group("suspicious")
        return None


# What a tool's call does with the sample's code (``ToolEffects.executes``):
# nothing, or runs it natively on its server's host, under an emulator, or in a
# sandbox. Empty: the declaration does not say.
EXECUTES_NO = "no"
EXECUTES_NATIVE = "native"
EXECUTES_EMULATION = "emulation"
EXECUTES_SANDBOX = "sandbox"
EXECUTION_MODES: tuple[str, ...] = (
    EXECUTES_NO,
    EXECUTES_NATIVE,
    EXECUTES_EMULATION,
    EXECUTES_SANDBOX,
)
# What of the sample a call sends to a third party (``ToolEffects.third_party``):
# nothing, its hash, or its bytes. Empty: the declaration does not say.
THIRD_PARTY_NO = "no"
THIRD_PARTY_HASH = "hash"
THIRD_PARTY_BYTES = "bytes"
THIRD_PARTY_SENDS: tuple[str, ...] = (THIRD_PARTY_NO, THIRD_PARTY_HASH, THIRD_PARTY_BYTES)
# Where a tool's call reaches a network, when it reaches one only in a named
# way (``ToolEffects.network``, beside ``true`` and ``false``):
# ``on_refresh``: only to fetch or refresh reference data the tool keeps (a
# technique catalogue, model weights), never with anything of the sample;
# ``case_store``: the configured case-memory store, wherever it is, which the
# disclosure's case-memory row places;
# ``operator_sandbox``: the operator's own sandbox service the tool's server
# fronts (its API), which is not a third party.
NETWORK_ON_REFRESH = "on_refresh"
NETWORK_CASE_STORE = "case_store"
NETWORK_OPERATOR_SANDBOX = "operator_sandbox"
NETWORK_MODES: tuple[str, ...] = (
    NETWORK_ON_REFRESH,
    NETWORK_CASE_STORE,
    NETWORK_OPERATOR_SANDBOX,
)
# The network answers that carry nothing of the sample out.
_CLOSED_NETWORKS: tuple[bool | str, ...] = (False, NETWORK_ON_REFRESH, NETWORK_CASE_STORE)
# The declaration fields merged one level deeper, sub-field by sub-field
# (:func:`merge_tool_facts`, :func:`tool_facts_changes`): an operator's change of
# one sub-field keeps the shipped value of every other, and a later release's
# correction of another still reaches the tool. ``null`` clears the field.
SUBFIELD_MERGED: tuple[str, ...] = ("effects",)


class ToolEffects(BaseModel):
    """What one tool's call does beyond answering, as its declaration says.

    ``executes`` says whether the call runs the sample's code, and how
    (:data:`EXECUTION_MODES`); ``network`` whether the tool itself reaches a
    network service beyond its own server (a lookup, a submission, a fetch),
    ``true`` or ``false``, or one of :data:`NETWORK_MODES` where it reaches
    one only in that named way; ``third_party`` what of the sample it sends to
    a third party (:data:`THIRD_PARTY_SENDS`). Each left unset (``""``,
    ``None``) is not declared, and is said to be undeclared, never taken as
    "no"; ``why_undeclared`` says why one is left unset, where the platform
    cannot vouch for it (a tool that runs whatever script it is given), and
    ``when`` the condition under which a declared effect happens, where it
    happens only under one (an analysis level). ``offline_without_credentials``
    says the tool answers from this machine when it is handed no credentials,
    reaching its third party only where it is given them (left unset, it is
    not declared); an offline rehearsal keeps such a server and names it. The
    sample's bytes going out are ``ToolFacts.discloses_sample`` as well:
    either one declares it, and the run's disclosure block reads the same
    rule (``analysis.tool_effects.sends_sample_bytes``); a tool whose network
    is ``operator_sandbox`` hands them to the operator's own sandbox.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    executes: str = ""
    network: bool | str | None = None
    third_party: str = ""
    why_undeclared: str = ""
    when: str = ""
    offline_without_credentials: bool | None = None

    def with_bytes_sent(self) -> ToolEffects:
        """These effects with the sample's bytes sent out: ``third_party`` ``bytes``, and a
        network that carries them (``true`` unless it already names the operator's sandbox)."""
        network = True if self.network is None or self.network in _CLOSED_NETWORKS else self.network
        return self.model_copy(update={"third_party": THIRD_PARTY_BYTES, "network": network})

    @field_validator("network")
    @classmethod
    def _a_known_network(cls, value: bool | str | None) -> bool | str | None:
        if isinstance(value, str) and value not in NETWORK_MODES:
            raise ValueError(
                f"effects.network {value!r} is not true, false or one of: "
                + ", ".join(NETWORK_MODES)
            )
        return value

    @field_validator("executes")
    @classmethod
    def _a_known_mode(cls, value: str) -> str:
        if value and value not in EXECUTION_MODES:
            raise ValueError(
                f"effects.executes {value!r} is not one of: " + ", ".join(EXECUTION_MODES)
            )
        return value

    @field_validator("third_party")
    @classmethod
    def _a_known_send(cls, value: str) -> str:
        if value and value not in THIRD_PARTY_SENDS:
            raise ValueError(
                f"effects.third_party {value!r} is not one of: " + ", ".join(THIRD_PARTY_SENDS)
            )
        return value


class ToolFacts(BaseModel):
    """What one tool's answer is, and where its facts sit in it.

    ``kind`` says what kind of fact the answer is (open vocabulary; the
    built-ins' kinds are as fine as the tables the core reads them by).
    ``asserts_techniques`` marks a tool whose technique id is a statement about
    this sample (a rule that matched it), and ``source`` the name a
    corroboration row gives it (``sigma`` for both Sigma tools).
    ``long_running`` marks a tool whose work grows with the sample and has no
    wall clock of its own; ``timeout_seconds`` is the budget the tool itself
    keeps and ``memory_peak_mb`` its measured peak, where known.
    ``discloses_sample`` marks a tool that sends the sample, or its bytes, out
    of the deployment. ``read_only`` marks a tool that changes nothing and
    answers an identical call the same (read-only or idempotent): a revision
    that repeats an identical call of an earlier round is answered from that
    round's entry. ``holds_strings`` marks a tool whose answer holds the
    sample's strings as data though its kind is not a strings kind (a report
    that anchors strings to the functions referring to them).
    ``reads_delay_imports`` marks a format tool whose import rows cover the
    imports the format binds late: the PE delay-load table, or, for a format
    that keeps its late-bound imports in the one table the tool reads (ELF),
    that table. A read of a tool that declares it, or whose answer
    carries a ``delay_imports`` list, can be the binary's complete import list.

    ``rows`` is the path of the answer's rows; ``places`` names, per kind of
    place (``offset``, ``rva``, ``address``, ``addresses``, ``call_site``,
    ``function``, ``pid``, ``command_line`` …), the path inside a row that
    holds one; ``values`` names, per kind of value (``text``, ``rule``,
    ``namespace``, ``value`` …), the path inside a row that holds one.
    ``techniques`` lists where the answer names technique ids. ``reputation``
    is set on a reputation lookup. ``function_starts`` is the path of the
    answer's list of function start addresses (offsets from the image base),
    read for an answer of kind ``function_list`` or ``capability_rules``
    (the triage pack's function index and the readings of an image with no
    function table of its own). ``arguments`` names, per role (``path``,
    ``hash``, ``address``, ``program``, ``command_lines`` …), the argument a
    call gives it in.

    ``reader`` names a reader of an answer *shape* the paths cannot express
    (``emulated_strings_with_call_sites``, ``flow_table`` …; empty: the generic
    reading of the paths); never a tool's name. ``report_sections`` lists the
    report sections whose writer is shown this tool's answers, ``words`` the
    words a statement may use to name this tool's entry, ``display_name`` the
    name published text gives the tool, and ``category`` the tag its
    description is shown with. ``routed_formats`` lists the routed sample
    formats a format-specific tool serves (``pe_info`` serves ``pe``): when the
    tool cannot answer on its server, a sample of another known format loses
    nothing by it, and its unavailability is not recorded for that sample.
    ``runtimes`` names the code runtimes a runtime-specific tool reads
    (``dotnet``, ``go``), in the words an identification answer gives as its
    ``runtime`` value: a pack step of the tool runs only where such an answer
    names one of them (``core.pack_steps.server_steps``). ``outputs`` is the
    path of the answer that names each file the tool wrote, as its server
    names it: a pack step of the tool takes each one into the job's artefact
    store (``core.pack_steps.PackStep.outputs``).
    ``effects`` says what a call does beyond answering (:class:`ToolEffects`):
    whether it runs the sample's code, reaches the network, or sends the
    sample's hash or bytes to a third party. ``aggregate_of`` names the tools
    of the same server this tool is the aggregate (combined) form of: one call
    answers what many calls of those would (a decompilation of many functions
    at once, a whole-program graph that combines per-function ones). The tool
    is shown to the model as such (``undeclared_tools.with_aggregate_notes``),
    so it can choose the one call over the many; each name is a tool of the
    same server (:func:`aggregate_reference_errors`). ``shows`` and
    ``does_not_show`` say, in a few words of the operator's, what the tool's
    answer shows and what it does not show (a reputation lookup shows what
    others reported of the sample and not its behaviour): shown in the console
    and the docs, and after the tool's description only while
    ``mcp.answer_scope_notes`` is on (``undeclared_tools.answer_scope_note``).
    Each is one line of text (:func:`check_scope_text`).
    """

    # A key this model does not know is refused in an operator's edit
    # (``STRICT_DECLARATIONS``): a misspelt ``kind`` would otherwise save as a
    # declaration of nothing. Anything already accepted is read leniently by
    # the validator below, which leaves such a key out with a warning.
    model_config = ConfigDict(frozen=True, extra="forbid")

    kind: str = ""
    asserts_techniques: bool = False
    source: str = ""
    long_running: bool = False
    timeout_seconds: float | None = Field(default=None, gt=0)
    memory_peak_mb: int | None = Field(default=None, gt=0)
    discloses_sample: bool = False
    read_only: bool = False
    holds_strings: bool = False
    reads_delay_imports: bool = False
    rows: str = ""
    places: dict[str, str] = Field(default_factory=dict)
    values: dict[str, str] = Field(default_factory=dict)
    techniques: tuple[TechniqueField, ...] = ()
    reputation: ReputationFacts | None = None
    function_starts: str = ""
    arguments: dict[str, str] = Field(default_factory=dict)
    reader: str = ""
    report_sections: tuple[str, ...] = ()
    words: tuple[str, ...] = ()
    display_name: str = ""
    category: str = ""
    routed_formats: tuple[str, ...] = ()
    runtimes: tuple[str, ...] = ()
    outputs: str = ""
    effects: ToolEffects | None = None
    aggregate_of: tuple[str, ...] = ()
    shows: str = ""
    does_not_show: str = ""

    @model_validator(mode="before")
    @classmethod
    def _read_what_this_version_reads(cls, data: Any) -> Any:
        """Outside an operator's edit, leave out what this version cannot read, with a warning.

        In every read, ``unclassified`` names no kind only when the
        declaration sets no kind-dependent field (:func:`reads_no_kind`).
        """
        if not isinstance(data, Mapping):
            return data
        if reads_no_kind(data):
            data = {**data, "kind": ""}
        if STRICT_DECLARATIONS.get():
            return data
        kept, left_out = lenient_declaration(data)
        if left_out:
            _warn_left_out("a tool", left_out)
        return kept

    @field_validator("kind")
    @classmethod
    def _kind_is_a_word(cls, value: str) -> str:
        # No kind declares the tool's other facts and leaves it read as a tool
        # of no kind: every reading of an undeclared tool still applies to it.
        # ``unclassified`` alone was made empty above (``reads_no_kind``); with
        # a kind-dependent field it is an ordinary kind word, as it always was.
        if value == "":
            return ""
        return _word(value, "tool kind")

    @field_validator("source", "reader", "category")
    @classmethod
    def _optional_word(cls, value: str, info: Any) -> str:
        return _word(value, info.field_name) if value else value

    @field_validator("rows", "function_starts", "outputs")
    @classmethod
    def _rows_parse(cls, value: str) -> str:
        return _check_path(value)

    @field_validator("places", "values")
    @classmethod
    def _row_paths_parse(cls, value: dict[str, str], info: Any) -> dict[str, str]:
        for name, path in value.items():
            _word(name, f"{info.field_name} name")
            if not path:
                raise ValueError(f"{info.field_name}.{name} needs a path")
            _check_path(path, in_row=True)
        return value

    @field_validator("arguments")
    @classmethod
    def _argument_roles_are_words(cls, value: dict[str, str]) -> dict[str, str]:
        for role, name in value.items():
            _word(role, "argument role")
            if not _ARGUMENT_RE.match(name or ""):
                raise ValueError(f"arguments.{role} {name!r} is not an argument name")
        return value

    @field_validator("report_sections")
    @classmethod
    def _sections_are_words(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_words(value, "report section"))

    @field_validator("runtimes")
    @classmethod
    def _runtimes_are_words(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(_words(value, "runtime"))

    @field_validator("routed_formats")
    @classmethod
    def _formats_are_known_routed_formats(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        # A name the router never gives a sample would drop the tool's reason
        # for every sample, without a word: each name is one it gives. And a
        # tool's routed formats are the known formats it serves, so the label
        # of a sample of no known format (``unknown``) is not one of them.
        from maljan.extractors.sample_identity import UNKNOWN_FORMAT, routed_formats

        known = tuple(name for name in routed_formats() if name != UNKNOWN_FORMAT)
        for name in value:
            if not _ROUTED_FORMAT_RE.fullmatch(name):
                raise ValueError(
                    f"routed format {name!r} is not a format name: lowercase letters, digits "
                    "and . _ + -, starting with a letter or a digit, at most 64 characters"
                )
            if name == UNKNOWN_FORMAT:
                raise ValueError(
                    f"routed format {name!r} is the label of a sample of no known format; a "
                    "tool's routed formats are the known formats it serves"
                )
            if name not in known:
                raise ValueError(
                    f"routed format {name!r} is not one the router gives a sample; one of: "
                    + ", ".join(known)
                )
        return value

    @field_validator("aggregate_of")
    @classmethod
    def _aggregated_tools_are_names(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        names = tuple(check_tool_name(v, "aggregate_of tool") for v in value)
        repeated = sorted({name for name in names if names.count(name) > 1})
        if repeated:
            raise ValueError(f"aggregate_of names {', '.join(repeated)} more than once")
        return names

    @field_validator("shows", "does_not_show")
    @classmethod
    def _scope_is_one_line(cls, value: str, info: Any) -> str:
        return check_scope_text(value, info.field_name)

    @model_validator(mode="after")
    def _a_source_is_an_asserting_tool_s(self) -> ToolFacts:
        if self.asserts_techniques and not self.techniques:
            raise ValueError("asserts_techniques needs techniques: where the answer names them")
        if self.source and not self.asserts_techniques:
            raise ValueError("source names a corroborating tool; set asserts_techniques")
        if (self.places or self.values) and not self.rows:
            raise ValueError("places and values are read inside rows; declare rows")
        effects = self.effects
        if effects is not None and self.discloses_sample:
            # A tick of ``discloses_sample`` (an operator's, over a shipped
            # tool's effects) is the explicit word: the sample's bytes go out,
            # so the effects say so, field by field, and are never refused for
            # what the tick overrides.
            lifted = effects.with_bytes_sent()
            if lifted != effects:
                object.__setattr__(self, "effects", lifted)
        elif effects is not None and STRICT_DECLARATIONS.get():
            # Refused in an operator's edit only; a record already accepted is
            # read with the cautious answer (``analysis.tool_effects``).
            sends = effects.third_party in (THIRD_PARTY_HASH, THIRD_PARTY_BYTES)
            if sends and effects.network in _CLOSED_NETWORKS:
                raise ValueError(
                    "a tool that sends the sample or its hash out reaches the network with it; "
                    "effects.network cannot be false, on_refresh or case_store"
                )
        if not self.kind and STRICT_DECLARATIONS.get():
            held = self.model_dump(exclude_defaults=True)
            held.pop("kind", None)
            if not held:
                raise ValueError(
                    "a tool declaration names its kind or at least one of: "
                    + ", ".join(KIND_FREE_FIELDS)
                )
            needing = [name for name in KIND_DEPENDENT_FIELDS if name in held]
            if needing:
                pointer = (
                    "; to rank or name a reputation server's lookups, set the server's "
                    "reputation_service.rank or reputation_service.name instead"
                    if "reputation" in needing
                    else ""
                )
                raise ValueError(
                    f"{', '.join(needing)} are read only through a kind; declare the kind" + pointer
                )
        return self

    def row_values(self, answer: Any) -> list[dict[str, list[Any]]]:
        """Each row of ``answer`` as ``{place or value name: [what its path names]}``."""
        out: list[dict[str, list[Any]]] = []
        for row in select(answer, self.rows):
            read: dict[str, list[Any]] = {}
            for name, path in {**self.places, **self.values}.items():
                read[name] = select(row, path)
            out.append(read)
        return out


# The placeholder a bootstrap body names the deployment's family by.
FAMILY_PLACEHOLDER = "{family}"


def _with_family(value: Any, family: str) -> Any:
    if isinstance(value, str):
        return value.replace(FAMILY_PLACEHOLDER, family)
    if isinstance(value, Mapping):
        return {k: _with_family(v, family) for k, v in value.items()}
    if isinstance(value, list):
        return [_with_family(v, family) for v in value]
    return value


# The counts of a reputation record a server-level threshold may read: the
# ones ``enrichment.declared.REPUTATION_RECORD_COUNTS`` stores.
REPUTATION_THRESHOLD_FIELDS: tuple[str, ...] = ("malicious", "suspicious", "total", "engines")


class ReputationThreshold(BaseModel):
    """A count of a reputation record at or above ``at_least`` marks the indicator malicious."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: str
    at_least: float

    @field_validator("field")
    @classmethod
    def _a_count(cls, value: str) -> str:
        if value not in REPUTATION_THRESHOLD_FIELDS:
            raise ValueError(
                f"malicious_when field {value!r} is not one of "
                + ", ".join(REPUTATION_THRESHOLD_FIELDS)
            )
        return value


class ReputationService(BaseModel):
    """What a reputation service's server says of its lookups as a whole.

    Server-level, never per tool: ``name`` is the service its lookups' answers
    are attributed to and the name published text gives them; ``rank`` the
    rank the triage pack asks them at (``ReputationFacts.rank``). Laid under
    each reputation lookup read from the server's listing
    (``core.derived_declarations``); a lookup a block or its server declares
    keeps what it declares.

    For post-verdict enrichment, which asks the server about a report's
    indicators as a source of its own (``api.enrichment_reputation_servers``):
    ``rate_limit_seconds`` is the pause after each question (``None``: the
    slowest pace any shipped enrichment source declares), and
    ``malicious_when`` the counts of its record that mark an indicator
    malicious, each ``{field, at_least}`` over ``malicious``, ``suspicious``,
    ``total`` or ``engines`` (empty: the record carries no verdict, and an
    indicator is never marked by it).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    name: str = ""
    rank: int | None = Field(default=None, ge=0)
    rate_limit_seconds: float | None = Field(default=None, ge=0)
    malicious_when: tuple[ReputationThreshold, ...] = ()

    @field_validator("name")
    @classmethod
    def _one_line(cls, value: str) -> str:
        if any(not ch.isprintable() for ch in value):
            raise ValueError("reputation_service.name is one line of printable text")
        return value.strip()


class CredentialBootstrap(BaseModel):
    """How a server's credential is obtained by one request, with no person in between.

    One ``POST`` of ``body`` (JSON, every ``{family}`` replaced by ``family``,
    the name this deployment registers under) to ``url``, an https URL; the
    credential is the text at ``token_json_path`` in the JSON answer and must
    start with ``token_prefix``. ``facts`` name the answer's other values the
    console shows the operator (an id, a handle), by path; ``note`` is what the
    operator is told before pressing the button. The URL is the declaration's
    alone: the route that performs it takes no URL from its caller.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    url: str
    body: dict[str, Any] = Field(default_factory=dict)
    token_json_path: str
    token_prefix: str = ""
    family: str = ""
    facts: dict[str, str] = Field(default_factory=dict)
    note: str = ""

    @field_validator("url")
    @classmethod
    def _https_only(cls, value: str) -> str:
        from urllib.parse import urlparse

        parsed = urlparse(value)
        if parsed.scheme != "https" or not parsed.hostname:
            raise ValueError("credential_bootstrap.url must be an https URL naming its host")
        if "@" in parsed.netloc:
            raise ValueError("credential_bootstrap.url may not hold a user name or password")
        return value

    @field_validator("token_json_path")
    @classmethod
    def _a_path(cls, value: str) -> str:
        if not value:
            raise ValueError("credential_bootstrap.token_json_path names where the token sits")
        parse_path(value)
        return value

    @field_validator("facts")
    @classmethod
    def _fact_paths(cls, value: dict[str, str]) -> dict[str, str]:
        for name, path in value.items():
            _word(name, "credential_bootstrap fact")
            parse_path(path)
        return value

    @model_validator(mode="after")
    def _no_fact_reads_the_token(self) -> CredentialBootstrap:
        """A fact is shown to the operator and audited, so none may name the token's path."""
        token = parse_path(self.token_json_path)
        for name, path in self.facts.items():
            if parse_path(path) == token:
                raise ValueError(
                    f"credential_bootstrap.facts.{name} reads token_json_path; a fact is shown "
                    "and audited, the token never is"
                )
        return self

    def request_body(self) -> dict[str, Any]:
        """The JSON body sent: ``body`` with the family written in."""
        return dict(_with_family(self.body, self.family))


# The fields of ``MCPServerConfig`` that are its declaration, in the order the
# docs list them. ``sample_open`` came first (its own model in ``config``).
DECLARATION_FIELDS: tuple[str, ...] = (
    "sample_open",
    "sample_mount",
    "work_dir",
    "error_patterns",
    "roles",
    "prompt_fragment",
    "required_env_allow",
    "variable_names",
    "reads_staged_sample",
    "platform_owned",
    "trusts_served_declaration",
    "auto_name_prefixes",
    "reference_urls",
    "tool_facts",
    "credential_bootstrap",
    "launcher_depth",
    "prepass_tools",
    "reputation_service",
    "data_label_prefixes",
    "default_effects",
    "analyse_effects",
)
# The declaration fields a settings snapshot records only where an operator
# set them (the shipped values are named by a digest instead).
SNAPSHOT_DIGESTED_FIELDS: tuple[str, ...] = tuple(
    f for f in DECLARATION_FIELDS if f != "sample_open"
)
# The placeholders a reference URL template may name.
REFERENCE_PLACEHOLDERS: tuple[str, ...] = ("{sha256}", "{md5}", "{sha1}")


# The role a server declares to say it is a sandbox source: its tools answer
# with what a run did, so a proposal may read their rows as a sandbox's
# (``core.declaration_proposals``). A word in ``roles`` like any other.
SANDBOX_ROLE = "sandbox"


def check_roles(value: list[str]) -> list[str]:
    return _words(value, "server role")


def check_env_names(value: list[str]) -> list[str]:
    for name in value:
        if not _ENV_NAME_RE.match(name):
            raise ValueError(f"{name!r} is not an environment variable name")
    return value


def check_mount(value: str) -> str:
    """An absolute path inside the server, written plainly, or empty."""
    if not value:
        return value
    if not value.startswith("/"):
        raise ValueError(
            f"sample_mount {value!r} must be an absolute path inside the server, or empty "
            "when the server reads the worker's own filesystem"
        )
    if any(part == ".." for part in value.split("/")):
        raise ValueError(f"sample_mount {value!r} may not hold a '..' segment")
    return posixpath.normpath(value)


def check_work_dir(value: str) -> str:
    """One directory name under the worker's samples directory, or empty."""
    if value and (value in (".", "..") or "/" in value or "\\" in value):
        raise ValueError(f"work_dir {value!r} is one directory name, not a path")
    return value


def check_auto_name_prefixes(value: list[str]) -> list[str]:
    for prefix in value:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*[_.]", prefix):
            raise ValueError(
                f"auto_name_prefixes {prefix!r} is letters and digits ending in '_' or '.', "
                "as a decompiler writes before the address (FUN_, fcn.)"
            )
    return value


def check_data_label_prefixes(value: list[str]) -> list[str]:
    for prefix in value:
        if not re.fullmatch(r"[A-Za-z][A-Za-z0-9]*[_.]", prefix):
            raise ValueError(
                f"data_label_prefixes {prefix!r} is letters and digits ending in '_' or '.', "
                "as a decompiler writes before the address of a datum it names (DAT_)"
            )
    return value


def check_reference_urls(value: list[str]) -> list[str]:
    for template in value:
        if not template.startswith("https://"):
            raise ValueError(f"reference URL {template!r} must start with https://")
        if not any(p in template for p in REFERENCE_PLACEHOLDERS):
            raise ValueError(
                f"reference URL {template!r} names none of: " + ", ".join(REFERENCE_PLACEHOLDERS)
            )
    return value


# A part of a declared ``prompt_fragment`` shown only while another server's
# tools are in the request: ``{{attached:<server key>|<while attached>|<otherwise>}}``.
# A branch holds no ``|``, ``{`` or ``}``, so parts never nest.
ATTACHED_OPENING = "{{attached:"
ATTACHED_PART = re.compile(r"\{\{attached:([A-Za-z0-9_.-]+)\|([^|{}]*)\|([^|{}]*)\}\}")
# The tool families that are not a registry server's key (``agents.prompt_fragments``:
# a role's own provider, the job's sandbox report, the team's ``ask_`` tools); a
# part may not name one.
RESERVED_FAMILIES: frozenset[str] = frozenset({"provider", "sandbox", "team"})


def check_fragment_template(value: str) -> str:
    """A ``prompt_fragment`` whose every ``{{attached:…}}`` part reads, or ``ValueError``.

    Each opening must begin a whole part (a server key, two branches, no ``|``,
    ``{`` or ``}`` inside a branch, so no part nests in another), and the key
    must be a server's, not a reserved family name.
    """
    if ATTACHED_OPENING not in value:
        return value
    parts = list(ATTACHED_PART.finditer(value))
    if len(parts) != value.count(ATTACHED_OPENING):
        raise ValueError(
            "prompt_fragment holds an {{attached:...}} part that does not read: write "
            "{{attached:<server key>|<text while attached>|<text otherwise>}}, with no |, { "
            "or } inside either text and no part inside another"
        )
    for part in parts:
        if part.group(1) in RESERVED_FAMILIES:
            raise ValueError(
                f"prompt_fragment's {{{{attached:{part.group(1)}|...}}}} names a reserved "
                f"family, not a tool server's key: use the key of a server in mcp.servers"
            )
    return value


def check_tool_facts_keys(value: dict[str, Any]) -> dict[str, Any]:
    for name in value:
        check_tool_name(name, "tool_facts key")
    return value


# ---------------------------------------------------------------------------
# The merge rule
# ---------------------------------------------------------------------------


def _copy_node(value: Any, pending: list[tuple[Any, Any]]) -> Any:
    """One node of :func:`_copy`: a leaf as it is, a container empty and queued to fill."""
    if isinstance(value, BaseModel):
        return value.model_copy(deep=True)
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        pending.append((value, out))
        return out
    if isinstance(value, list):
        items: list[Any] = []
        pending.append((value, items))
        return items
    return value


def _copy(value: Any) -> Any:
    """A copy of ``value``'s dicts and lists, at any depth.

    Walked with an explicit stack rather than by recursion, so stored
    declaration data nested however deep is copied, never refused with a
    ``RecursionError``. Time linear in the value.
    """
    pending: list[tuple[Any, Any]] = []
    root = _copy_node(value, pending)
    while pending:
        source, target = pending.pop()
        if isinstance(source, dict):
            for key, item in source.items():
                target[key] = _copy_node(item, pending)
        else:
            for item in source:
                target.append(_copy_node(item, pending))
    return root


def fill_declaration(stored: MCPServerConfig, default: MCPServerConfig) -> MCPServerConfig:
    """``stored`` with every declaration field it never set taken from ``default``.

    A field the stored block set, to anything (empty included), is kept as set:
    an operator who cleared a built-in's prompt fragment meant it. A filled
    field stays unset, so the block keeps following the built-in's value and a
    save that strips it (:func:`strip_declaration_defaults`) stores nothing.
    ``model_fields_set`` is a merge aid only: a ``model_dump`` and
    ``model_validate`` round trip marks every field set, so no consumer may
    read an operator's intent from it.
    """
    for name in DECLARATION_FIELDS:
        if name not in stored.model_fields_set:
            object.__setattr__(stored, name, _copy(getattr(default, name)))
    return stored


# A stored map of a block's tool declarations that holds its changes over what
# the block ships (:func:`tool_facts_changes`) says so under this key. No tool
# can be named by it (a tool's name is never empty, :func:`check_tool_name`), so
# the mark never stands for a tool. A map without it was written whole by an
# earlier release and is read whole, exactly as that release read it: a shipped
# tool it does not name was removed. Nothing guesses the form from the shape.
CHANGES_MARK = ""
CHANGES_FORM = "changes"


def holds_changes(stored: Any) -> bool:
    """Whether a stored map of tool declarations is marked as its changes over what ships."""
    return isinstance(stored, Mapping) and stored.get(CHANGES_MARK) == CHANGES_FORM


def without_mark(stored: Mapping[str, Any]) -> dict[str, Any]:
    """``stored`` without its mark: the tools it names and what it says of each."""
    if holds_changes(stored):
        return {tool: held for tool, held in stored.items() if tool != CHANGES_MARK}
    return dict(stored)


def with_mark(changes: Mapping[str, Any]) -> dict[str, Any]:
    """``changes`` marked as a block's changes over what it ships, the form a save stores.

    The mark always wins: an entry under the mark's key is never a tool, so
    whatever ``changes`` holds there is left out rather than written over it.
    """
    return {
        CHANGES_MARK: CHANGES_FORM,
        **{tool: held for tool, held in without_mark(changes).items() if tool != CHANGES_MARK},
    }


def unreadable_map(stored: Any) -> bool:
    """Whether a stored map of tool declarations has a form no release writes.

    The mark's key names no tool (:func:`check_tool_name`), so a map holding
    it with anything but :data:`CHANGES_FORM` is neither a map of changes nor
    a whole map: which tools it means cannot be known. Such a map, and a
    value that is not a map at all, is read as absent: the shipped
    declarations are in force (:func:`stored_in_force`).
    """
    if not isinstance(stored, Mapping):
        return True
    return CHANGES_MARK in stored and stored[CHANGES_MARK] != CHANGES_FORM


def refused_tool_names(sent: Mapping[str, Any]) -> list[str]:
    """The names a sent map of tool declarations holds that no tool can have, in order.

    Every key but the mark itself (:func:`holds_changes`) is a tool's name
    and is checked as one (:func:`check_tool_name`); the mark's key holding
    anything else is refused too. Time linear in the map.
    """
    marked = holds_changes(sent)
    out: list[str] = []
    for tool in sent:
        if marked and tool == CHANGES_MARK:
            continue
        if not isinstance(tool, str):
            out.append(str(tool))
            continue
        try:
            check_tool_name(tool)
        except ValueError:
            out.append(tool)
    return out


def refused_names_message(names: Iterable[str]) -> str:
    """One refusal naming each refused tool name, an empty one shown visibly."""
    shown = ", ".join(repr(name) for name in names)
    return f"tool_facts key {shown} must be a tool's name, not empty or padded"


def own_prefixed_names(sent: Mapping[str, Any], server: str) -> list[str]:
    """The names a sent map of tool server ``server`` spells as its renamed tools, in order.

    The mark of a marked map (:func:`holds_changes`) is no tool and is
    skipped; ``server`` empty (a block that is no tool server) names none.
    Time linear in the map.
    """
    if not server:
        return []
    marked = holds_changes(sent)
    out: list[str] = []
    for tool in sent:
        if not isinstance(tool, str) or (marked and tool == CHANGES_MARK):
            continue
        try:
            check_own_prefix(server, [tool])
        except ValueError:
            out.append(tool)
    return out


def sent_names_refusal(sent: Mapping[str, Any], kept: Iterable[str] = (), server: str = "") -> str:
    """The refusal of the tool names a sent map holds that no tool can have, or ``""``.

    Every key of the map as sent is read, whatever its value (``null``
    included), before the map is merged over what ships: a name no tool can
    have (:func:`refused_tool_names`) and, for the map of tool server
    ``server``, a name spelled as its renamed tool (:func:`own_prefixed_names`).
    A name in ``kept`` is sent back with its stored change exactly as stored
    (:func:`kept_stored_changes`), is not this save's edit, and is not
    refused. Time linear in the map.
    """
    held = set(kept)
    names = [name for name in refused_tool_names(sent) if name not in held]
    if names:
        return refused_names_message(names)
    prefixed = [name for name in own_prefixed_names(sent, server) if name not in held]
    if prefixed:
        try:
            check_own_prefix(server, prefixed)
        except ValueError as exc:
            return str(exc)
    return ""


# The declaration fields the last release that stored a tool map whole knew:
# the frozen record's defaults
# (``apps/api/alembic/versions/20261012000000_shipped_tool_declarations.json``,
# held equal by a test). Frozen, because no later release stores a map whole.
WHOLE_MAP_FIELDS: frozenset[str] = frozenset(
    {
        "arguments",
        "asserts_techniques",
        "category",
        "discloses_sample",
        "display_name",
        "holds_strings",
        "kind",
        "long_running",
        "memory_peak_mb",
        "places",
        "reader",
        "report_sections",
        "reputation",
        "rows",
        "source",
        "techniques",
        "timeout_seconds",
        "values",
        "words",
    }
)

# The declaration fields no release that stored a tool map whole knew: every
# ``ToolFacts`` field but those, so a field added later is one at once
# (``read_only``, ``function_starts``, ``routed_formats``, ``effects``, ...).
# Such a map leaves them out because it predates them, never to clear them, so
# for a tool the block ships each one it leaves out follows the shipped
# declaration, merged per field as :func:`merge_tool_facts` merges a change: a
# value the map sets is the operator's and wins.
FIELDS_AFTER_WHOLE_MAPS: tuple[str, ...] = tuple(
    name for name in ToolFacts.model_fields if name not in WHOLE_MAP_FIELDS
)


def _with_later_fields(held: Any, shipped: Any) -> Any:
    """A whole map's declaration of a shipped tool, with the later fields it leaves out shipped."""
    if not isinstance(held, Mapping) or not isinstance(shipped, Mapping):
        return held
    later: dict[str, Any] = {}
    for name in FIELDS_AFTER_WHOLE_MAPS:
        if name not in shipped:
            continue
        below, above = shipped[name], held.get(name)
        if name not in held:
            later[name] = _copy(below)
        elif name in SUBFIELD_MERGED and isinstance(below, Mapping) and isinstance(above, Mapping):
            # Merged sub-field by sub-field, as :func:`merge_tool_facts` merges it.
            later[name] = {**_copy(dict(below)), **_copy(dict(above))}
    return {**held, **later} if later else held


def whole_as_changes(whole: Mapping[str, Any], shipped: Mapping[str, Any]) -> dict[str, Any]:
    """A map stored whole, as the changes over ``shipped`` that put the same in force.

    Read whole, a shipped tool the map does not name was removed (``None``),
    and a field a shipped tool's declaration leaves out is at its default,
    not at the shipped value, except a field no release that stored a map
    whole knew (:data:`FIELDS_AFTER_WHOLE_MAPS`), which follows the shipped
    value. Time linear in the two maps.
    """
    unset = ToolFacts.model_construct().model_dump(mode="json")
    filled = {
        tool: {**unset, **_with_later_fields(held, shipped[tool])}
        if tool in shipped and isinstance(held, Mapping)
        else held
        for tool, held in without_mark(whole).items()
    }
    return tool_facts_changes(filled, shipped)


def stored_changes(stored: Mapping[str, Any], shipped: Mapping[str, Any]) -> dict[str, Any]:
    """What a stored map changes of ``shipped``, per tool, whichever form it was stored in."""
    if holds_changes(stored):
        return without_mark(stored)
    return whole_as_changes(stored, shipped)


def _refused_leniently(raw: Any) -> bool:
    """Whether the model refuses ``raw`` as a stored declaration is read (leniently).

    What the lenient read leaves out is left out first (:func:`lenient_declaration`),
    so the check itself warns of nothing; the read that builds the settings does.
    """
    token = STRICT_DECLARATIONS.set(False)
    try:
        ToolFacts.model_validate(lenient_declaration(raw)[0] if isinstance(raw, Mapping) else raw)
    except (ValidationError, ValueError):
        return True
    finally:
        STRICT_DECLARATIONS.reset(token)
    return False


def _refused_tool(tool: Any, held: Any, server: str = "") -> bool:
    """Whether the model refuses a stored tool: its name, or its declaration read leniently.

    ``server`` is the key of the tool server the block belongs to, if it is
    one: a name spelled as that server's renamed tool is refused there
    (:func:`check_own_prefix`).
    """
    return _refused_name(tool, server) or _refused_leniently(held)


def _refused_name(tool: Any, server: str = "") -> bool:
    """Whether no tool (of tool server ``server``, if given) can be named ``tool``."""
    if not isinstance(tool, str):
        return True
    try:
        check_tool_name(tool)
        if server:
            check_own_prefix(server, [tool])
    except ValueError:
        return True
    return False


def _warn_refused_changes(where: str, tools: Iterable[str]) -> None:
    held = tuple(sorted(str(tool) for tool in tools))
    marker = (f"refused:{where}", held)
    if marker in _WARNED:
        return
    if len(_WARNED) >= _WARNED_MAX:
        _WARNED.clear()
    _WARNED.add(marker)
    from maljan.core.logger import logger

    logger.warning(
        "A stored change of a tool declaration (%s) does not validate over the declarations "
        "this release ships; the change is left out, and the tool is in force as shipped, "
        "or not at all where this release ships none for it: %s",
        loggable_names([where]),
        loggable_names(held),
    )


def _warn_unreadable_map(where: str) -> None:
    marker = (f"unreadable:{where}", ())
    if marker in _WARNED:
        return
    if len(_WARNED) >= _WARNED_MAX:
        _WARNED.clear()
    _WARNED.add(marker)
    from maljan.core.logger import logger

    logger.warning(
        "A stored map of tool declarations (%s) has a form no release writes; it is left "
        "out, and the declarations this release ships are in force",
        loggable_names([where]),
    )


def stored_in_force(
    shipped: Mapping[str, Any], stored: Any, where: str = "", server: str = ""
) -> tuple[dict[str, Any], list[str]]:
    """What a stored map of a block's tool declarations puts in force, and the changes refused.

    A map marked as changes (:func:`holds_changes`) is merged over
    ``shipped`` one tool at a time (:func:`merge_tool_facts`). A map without
    the mark was stored whole by an earlier release and is in force as
    stored, as it was then, but for the fields that release did not know
    (:data:`FIELDS_AFTER_WHOLE_MAPS`), which a shipped tool it names takes
    from the shipped declaration where it leaves them out. Either way, each
    tool the stored map names is read as the model reads a stored
    declaration (leniently); one the model refuses (its name, or a field it
    sets that needs one this release no longer ships, also for a tool this
    release no longer ships at all) is left out: the tool is in force as
    shipped, or not at all where nothing ships for it, its name is returned,
    and one warning names it. ``server`` is the block's tool-server key, if
    it is one, under which a name spelled as its renamed tool is refused
    (:func:`check_own_prefix`). A stored value
    whose form no release writes (:func:`unreadable_map`) is read as absent:
    what ships is in force, the mark's key is returned for the whole map, and
    one warning says so. So no stored map of tool declarations ever stops the
    settings from being built. Time linear in the two maps.
    """
    if unreadable_map(stored):
        _warn_unreadable_map(where)
        return _copy(dict(shipped)), [CHANGES_MARK]
    removals: list[str] = []
    if holds_changes(stored):
        named = without_mark(stored)
        in_force = merge_tool_facts(shipped, named)
        # A removal of a tool the block does not ship stays a removal: the
        # tool is read from what its server lists, and the operator took it
        # out of that reading (``MCPServerConfig.removed_tools``).
        removals = [str(t) for t, change in named.items() if change is None and t not in shipped]
    else:
        named = dict(stored)
        in_force = {
            tool: _copy(_with_later_fields(held, shipped.get(tool))) for tool, held in named.items()
        }
    refused = [
        tool for tool in named if tool in in_force and _refused_tool(tool, in_force[tool], server)
    ]
    for tool in refused:
        if isinstance(shipped.get(tool), Mapping):
            in_force[tool] = _copy(shipped[tool])
        else:
            in_force.pop(tool, None)
    if refused:
        _warn_refused_changes(where, refused)
    for tool in removals:
        if not _refused_name(tool, server):
            in_force[tool] = None
    return in_force, [str(tool) for tool in refused]


def kept_stored_changes(
    incoming: Mapping[str, Any], stored: Any, shipped: Mapping[str, Any], server: str = ""
) -> dict[str, Any]:
    """The tools a save sends back with their refused stored change exactly as stored.

    ``incoming`` is a save's changes per tool (:func:`stored_changes`),
    ``stored`` the map stored for the block. A tool whose stored change this
    release refuses (:func:`stored_in_force`) and that the save names with
    that very change is not the save's edit: it is kept as stored, out of
    every check, so a stored change never blocks an unrelated edit of its
    block and is never dropped by one. A stored map whose form no release
    writes (:func:`unreadable_map`) keeps nothing: it is not in force, and
    what a save sends is read on its own. Time linear in the maps.
    """
    if unreadable_map(stored):
        return {}
    refused = stored_in_force(shipped, stored, server=server)[1]
    held = stored_changes(stored, shipped)
    # A refused name stored as ``null`` removes nothing and is never in force,
    # so it is not among the refused changes above; sent back as stored, it
    # is not this save's edit either, and is kept as stored like them.
    removed = [
        tool
        for tool, change in held.items()
        if change is None and tool not in shipped and _refused_name(tool, server)
    ]
    return {
        tool: _copy(held[tool])
        for tool in [*refused, *removed]
        if tool in incoming and tool in held and _same(incoming[tool], held[tool])
    }


def sent_in_force(shipped: Mapping[str, Any], sent: Mapping[str, Any]) -> dict[str, Any]:
    """What a map of a block's tool declarations a client sends puts in force.

    The one reading of a sent map, on every path that takes one: marked as
    changes (:func:`holds_changes`), its changes over ``shipped``; without
    the mark, the whole map, as an earlier release read it (a shipped tool it
    does not name is removed). Time linear in the two maps.
    """
    return merge_tool_facts(shipped, stored_changes(sent, shipped))


def merge_tool_facts(shipped: Mapping[str, Any], stored: Mapping[str, Any]) -> dict[str, Any]:
    """The tool declarations in force: ``shipped`` with the ``stored`` changes over it, per tool.

    ``stored`` is a block's tool declarations as a save writes them
    (:func:`tool_facts_changes`): per tool, the fields that differ from the
    shipped declaration of that tool, which replace those fields; ``None``
    for a shipped tool the operator removed, which is left out; the whole
    declaration of a tool ``shipped`` does not declare. A shipped tool the
    stored map does not name is in force as shipped, so a correction a later
    release ships reaches it, and so does a tool shipped after the save. With
    nothing shipped (a server that is not a built-in) the stored map is the
    whole map. A change that is not a mapping is kept for the model to read
    or refuse as ever. The mark of a stored map (:data:`CHANGES_MARK`) is
    not a tool and is not read as one. Time linear in the two maps.
    """
    stored = without_mark(stored)
    out: dict[str, Any] = {}
    for tool, facts in shipped.items():
        if tool not in stored:
            out[tool] = _copy(facts)
            continue
        change = stored[tool]
        if change is None:
            continue
        if isinstance(change, Mapping) and isinstance(facts, Mapping):
            merged = {**_copy(dict(facts)), **_copy(dict(change))}
            for name in SUBFIELD_MERGED:
                below, above = facts.get(name), change.get(name)
                if isinstance(below, Mapping) and isinstance(above, Mapping):
                    merged[name] = {**_copy(dict(below)), **_copy(dict(above))}
            out[tool] = merged
        else:
            out[tool] = _copy(change)
    for tool, change in stored.items():
        if tool not in shipped and change is not None:
            out[tool] = _copy(change)
    return out


def tool_facts_changes(in_force: Mapping[str, Any], shipped: Mapping[str, Any]) -> dict[str, Any]:
    """What ``in_force`` changes of ``shipped``, per tool: how a block's declarations are stored.

    The inverse of :func:`merge_tool_facts`: a tool declared as shipped is
    not named; a shipped tool ``in_force`` declares otherwise names only the
    fields that differ (keys in any order, as :func:`_same` compares them); a
    shipped tool ``in_force`` lacks is ``None``; a tool ``shipped`` does not
    declare is named whole. A field ``in_force`` leaves out of a shipped
    tool's declaration follows the shipped value, as on load. Time linear in
    the two maps.
    """
    out: dict[str, Any] = {}
    for tool, facts in shipped.items():
        if tool not in in_force:
            out[tool] = None
            continue
        held = in_force[tool]
        if isinstance(held, Mapping) and isinstance(facts, Mapping):
            changed = {
                str(name): _copy(value)
                for name, value in held.items()
                if name not in facts or not _same(value, facts[name])
            }
            for name in SUBFIELD_MERGED:
                below, above = facts.get(name), changed.get(name)
                if isinstance(below, Mapping) and isinstance(above, Mapping):
                    sub = {
                        str(key): _copy(value)
                        for key, value in above.items()
                        if key not in below or not _same(value, below[key])
                    }
                    if sub:
                        changed[name] = sub
                    else:
                        changed.pop(name)
            if changed:
                out[tool] = changed
        elif not _same(held, facts):
            out[tool] = _copy(held)
    for tool, held in in_force.items():
        if tool not in shipped:
            out[tool] = _copy(held)
    return out


def strip_declaration_defaults(dumped: dict[str, Any], default: MCPServerConfig) -> dict[str, Any]:
    """A built-in's stored row without the declaration fields equal to its default.

    The tool-server map is stored whole on every save, so a row that carried
    each default would freeze the built-in's declaration at the day of the
    save and a later release could never correct it. A value that differs
    from the default, an empty one included, is the operator's and is stored;
    a value equal to the shipped one at the time of the save is not recorded,
    and follows later releases. The tool declarations are stored one tool at
    a time, as their changes over the shipped ones (:func:`tool_facts_changes`)
    marked as such (:func:`with_mark`), and not at all when no tool differs.
    """
    reference = default.model_dump(mode="json")
    out: dict[str, Any] = {}
    for key, value in dumped.items():
        if key == "tool_facts" and isinstance(value, Mapping):
            changes = tool_facts_changes(value, reference.get(key) or {})
            if changes:
                out[key] = with_mark(changes)
        elif key not in DECLARATION_FIELDS or value != reference.get(key):
            out[key] = value
    return out


# The fields of a tool's declaration added after digests were first recorded,
# left out of a block's digest where a tool leaves them at their default, so
# adding one moves no digest of a block whose tools do not set it.
DIGEST_OMITS_AT_DEFAULT: tuple[str, ...] = (
    "aggregate_of",
    "shows",
    "does_not_show",
    "runtimes",
    "outputs",
)


def _digested_tools(tool_facts: Any) -> Any:
    if not isinstance(tool_facts, Mapping):
        return tool_facts
    return {
        tool: {
            key: value
            for key, value in facts.items()
            if not (key in DIGEST_OMITS_AT_DEFAULT and not is_set(key, value))
        }
        if isinstance(facts, Mapping)
        else facts
        for tool, facts in tool_facts.items()
    }


# The declaration fields added after digests were first recorded that a block
# leaves empty, left out of its digest so adding one moves no digest.
_DIGEST_OMITS_WHEN_EMPTY: tuple[str, ...] = ("data_label_prefixes",)


def declaration_digest(cfg: Any) -> str:
    """A short digest of one block's whole declaration, as it is in force."""
    dumped = cfg.model_dump(mode="json") if isinstance(cfg, BaseModel) else dict(cfg)
    # A field a block leaves unset (``None``) is left out, so a field added to
    # the declaration later moves no digest of a block that does not set it;
    # so is a block's trust in its server's own declaration when it is off.
    body = {
        name: dumped.get(name)
        for name in DECLARATION_FIELDS
        if dumped.get(name) is not None
        and not (name == "trusts_served_declaration" and dumped.get(name) is False)
        and not (name in _DIGEST_OMITS_WHEN_EMPTY and not dumped.get(name))
    }
    if "tool_facts" in body:
        body["tool_facts"] = _digested_tools(body["tool_facts"])
    text = json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# The read API
# ---------------------------------------------------------------------------

SourceKind = Literal["mcp", "provider", "sandbox", "pack"]


@dataclass(frozen=True)
class SourceRef:
    """Where a tool comes from: a tool server, a provider, or the platform."""

    kind: SourceKind
    key: str = ""

    def __str__(self) -> str:
        return f"{self.kind}:{self.key}" if self.key else self.kind

    @classmethod
    def parse(cls, text: str) -> SourceRef:
        """``mcp:<key>``, ``provider:<id>``, ``sandbox`` or ``pack``."""
        kind, _, key = text.partition(":")
        if kind in ("mcp", "provider") and key:
            return cls(kind, key)  # type: ignore[arg-type]
        if kind in ("sandbox", "pack") and not key:
            return cls(kind)  # type: ignore[arg-type]
        raise ValueError(f"{text!r} is not a source: mcp:<key>, provider:<id>, sandbox or pack")


SANDBOX = SourceRef("sandbox")
PACK = SourceRef("pack")

# The provider-owned server blocks registered at runtime, by the source their
# declarations are read under, at their dotted path in the settings
# (:func:`register_provider_block`). The shipped ones are declaration data
# (``builtin_declarations.provider_block_paths``); :func:`provider_blocks` is
# the one list of both that the read API, the run snapshot and anything else
# that walks the blocks use.
_REGISTERED_PROVIDER_BLOCKS: dict[str, str] = {}
# The settings mapping of the tool servers' blocks, and the one of the
# third-party providers' blocks, each entry read under ``provider:<id>``.
SERVER_BLOCKS_PATH = "mcp.servers"
PROVIDER_BLOCKS_PATH = "providers"
_BLOCK_PATH_RE = re.compile(r"[a-z_][a-z0-9_]*(?:\.[a-z_][a-z0-9_]*)*")


def shipped_provider_blocks() -> dict[str, str]:
    """The shipped provider-owned blocks' dotted paths, by source text: built-in data alone."""
    from maljan.core.builtin_declarations import provider_block_paths

    return provider_block_paths()


def provider_blocks() -> dict[str, str]:
    """Every provider-owned block's dotted path, by source text: the shipped ones, then
    each one a provider registered (:func:`register_provider_block`)."""
    blocks = shipped_provider_blocks()
    for source, path in _REGISTERED_PROVIDER_BLOCKS.items():
        blocks.setdefault(source, path)
    return blocks


def _settings_block_class(path: str) -> type[BaseModel] | None:
    """The settings model class at a dotted ``path`` of :class:`Settings`, ``None`` for none.

    Walked through the settings model's declared fields, so no settings are
    built; a step into a mapping of models (``providers``) names one of its
    entries, and a step through anything else (a scalar) is no place.
    """
    from typing import get_args, get_origin

    from maljan.core.config import Settings

    def model_in(annotation: Any) -> type[BaseModel] | None:
        return next(
            (
                c
                for c in (annotation, *get_args(annotation))
                if isinstance(c, type) and issubclass(c, BaseModel)
            ),
            None,
        )

    node: type[BaseModel] | None = Settings
    entry: type[BaseModel] | None = None
    for part in path.split("."):
        if entry is not None:
            # The step after a mapping names one of its entries.
            node, entry = entry, None
            continue
        held = node.model_fields.get(part) if node is not None else None
        if held is None:
            return None
        annotation = held.annotation
        if get_origin(annotation) is dict:
            entry = model_in(get_args(annotation)[-1])
            if entry is None:
                return None
            node = None
            continue
        node = model_in(annotation)
    return None if entry is not None else node


def _overlaps(path: str, other: str) -> bool:
    """Whether two dotted paths name one block, or one holds the other."""
    return path == other or path.startswith(other + ".") or other.startswith(path + ".")


def register_provider_block(source: str, path: str) -> None:
    """Read ``source``'s declaration (``provider:<id>``) from the settings block at ``path``.

    How a provider whose settings hold a server block of its own declares its
    tools the way the built-ins do (its class's ``declaration_block``,
    ``providers.registry``). Refused, with the reason, at registration:
    a path that is not dotted words; another path for a shipped source (it
    keeps its shipped block); a path where the settings model holds no server
    block (a place with tool declarations); and a path that is, holds or sits
    inside another source's block, shipped or registered, so two sources never
    read one block.
    """
    ref = SourceRef.parse(source)
    if ref.kind != "provider":
        raise ValueError(f"{source!r} is not a provider source: provider:<id>")
    if not _BLOCK_PATH_RE.fullmatch(str(path or "")):
        raise ValueError(f"{path!r} is not a settings path: dotted lowercase words")
    shipped = shipped_provider_blocks().get(str(ref))
    if shipped is not None:
        if shipped != path:
            raise ValueError(f"{source!r} is declared by its shipped block {shipped!r}")
        return
    for other, held in provider_blocks().items():
        if other != str(ref) and _overlaps(path, held):
            raise ValueError(
                f"{path!r} is {other!r}'s block {held!r} or overlaps it; "
                f"{source!r} needs a settings block of its own"
            )
    # A tool server's block is read under its own source (``mcp:<key>``), and
    # ``providers.<id>`` under ``provider:<id>``.
    if _overlaps(path, SERVER_BLOCKS_PATH):
        raise ValueError(
            f"{path!r} is a tool server's block or holds one, read under that server's own "
            f"source; {source!r} needs a settings block of its own"
        )
    own = f"{PROVIDER_BLOCKS_PATH}.{ref.key}"
    if _overlaps(path, PROVIDER_BLOCKS_PATH) and path != own:
        raise ValueError(
            f"{path!r} is not {source!r}'s block in {PROVIDER_BLOCKS_PATH}; its block there "
            f"is {own!r}"
        )
    place = _settings_block_class(path)
    if place is None or "tool_facts" not in place.model_fields:
        raise ValueError(
            f"{path!r} is no server block in the settings, so {source!r} would declare "
            "nothing there; name a block the settings hold, or declare through the "
            "provider class's declaration hook"
        )
    if _REGISTERED_PROVIDER_BLOCKS.get(str(ref)) != path:
        _REGISTERED_PROVIDER_BLOCKS[str(ref)] = path
        _DECLARATION_VERSION[0] += 1


def forget_provider_block(source: str) -> None:
    """Stop reading a registered provider's block (the provider was taken out)."""
    if _REGISTERED_PROVIDER_BLOCKS.pop(str(source), None) is not None:
        _DECLARATION_VERSION[0] += 1


def block_at(settings: Any, path: str) -> Any:
    """The settings block at a dotted ``path``; a step into a mapping names one of its entries.

    Raises ``AttributeError`` for a step the settings do not hold, an entry a
    mapping lacks included.
    """
    node = settings
    for part in path.split("."):
        if isinstance(node, Mapping):
            if part not in node:
                raise AttributeError(part)
            node = node[part]
        else:
            node = getattr(node, part)
    return node


# The (source, registered path) pairs whose unread ``providers`` entry was logged.
_UNREAD_ENTRIES_NOTED: set[tuple[str, str]] = set()


def elsewhere_declared(provider: str) -> str:
    """The block path ``provider``'s class registered other than ``providers.<id>``, else ``""``.

    Such a provider declares its tools in that block, so its entry in
    ``providers`` would never be read.
    """
    held = _REGISTERED_PROVIDER_BLOCKS.get(f"provider:{provider}", "")
    return "" if held in ("", f"{PROVIDER_BLOCKS_PATH}.{provider}") else held


def provider_block(settings: Any, provider: str) -> Any:
    """The third-party provider ``provider``'s own server block (``providers.<id>``), or ``None``.

    Where such a provider reads how its server is reached; its declaration is
    read from the same block (:func:`provider_declarations`).
    """
    held = getattr(settings, PROVIDER_BLOCKS_PATH, None)
    return held.get(provider) if isinstance(held, Mapping) else None


# The (source, path) pairs whose missing block was logged in this process.
_MISSING_BLOCKS_NOTED: set[tuple[str, str]] = set()


def provider_block_at(settings: Any, source: str, path: str) -> Any:
    """The block ``source`` declares its tools in, or ``None`` where the settings hold none.

    A shipped block is always there, and registration refuses a path the
    settings model does not hold; a settings object that still lacks the
    block (one built otherwise) declares nothing, logged once per source and
    path in the process.
    """
    try:
        return block_at(settings, path)
    except AttributeError:
        if (source, path) not in _MISSING_BLOCKS_NOTED:
            _MISSING_BLOCKS_NOTED.add((source, path))
            from maljan.core.logger import logger

            logger.warning("Provider block for %s is not in the settings (%s).", source, path)
        return None


# The declarations providers registered at runtime give for their own tools, by
# the source those tools are recorded under (``provider:<id>``): each a reader
# of the settings that answers the provider's declaration (an object or mapping
# with the declaration fields of ``MCPServerConfig``), or ``None`` for none.
# The provider blocks (:func:`provider_blocks`) are read the same way; a runtime
# provider extends either set through ``providers.registry`` (its class's
# ``declaration`` hook or ``declaration_block``), never by editing a table.
_RUNTIME_PROVIDER_DECLARATIONS: dict[str, Callable[[Any], Any]] = {}
# Bumped by every registration, so held declarations are rebuilt after one.
_DECLARATION_VERSION = [0]


def register_provider_declaration(source: str, read: Callable[[Any], Any]) -> None:
    """Read ``source``'s declaration (``provider:<id>``) with ``read(settings)`` from now on.

    A source of :func:`provider_blocks` keeps its block: those providers are
    declared by their settings blocks.
    """
    ref = SourceRef.parse(source)
    if ref.kind != "provider":
        raise ValueError(f"{source!r} is not a provider source: provider:<id>")
    _RUNTIME_PROVIDER_DECLARATIONS[str(ref)] = read
    _DECLARATION_VERSION[0] += 1


def forget_provider_declaration(source: str) -> None:
    """Stop reading a runtime provider's declaration (the provider was taken out)."""
    if _RUNTIME_PROVIDER_DECLARATIONS.pop(str(source), None) is not None:
        _DECLARATION_VERSION[0] += 1


def declaration_version() -> int:
    """How many times the runtime declarations changed in this process.

    A runtime provider's registration, and a server's own declaration of its
    tools read when it was listed (``core.served_declarations``).
    """
    return _DECLARATION_VERSION[0]


def bump_declaration_version() -> None:
    """Have held declarations rebuilt: a runtime declaration changed in this process."""
    _DECLARATION_VERSION[0] += 1


def provider_declarations(settings: Any) -> dict[str, Any]:
    """Every provider's declaration block under ``settings``, by source text.

    The provider blocks (:func:`provider_blocks`: the shipped ones, then each
    registered one the settings hold) first, then each runtime provider's own
    (:func:`register_provider_declaration`) that answers one; a reader that
    fails declares nothing, and is logged.
    """
    from maljan.core.logger import logger

    shipped = shipped_provider_blocks()
    blocks: dict[str, Any] = {}
    readers: dict[str, Callable[[Any], Any]] = {}
    for text, path in provider_blocks().items():
        if text in shipped:
            blocks[text] = block_at(settings, path)
        else:
            readers[text] = partial(provider_block_at, source=text, path=path)
    # A third-party provider's own block in ``providers`` comes before its
    # class's declaration hook: the operator's block, as a shipped one is.
    # A provider whose class registered another block keeps that one, and the
    # unread entry is said once (a save refuses it: ``elsewhere_declared``).
    for key in getattr(settings, PROVIDER_BLOCKS_PATH, None) or {}:
        text = f"provider:{key}"
        if text in shipped:
            continue
        other = elsewhere_declared(key)
        if other:
            if (text, other) not in _UNREAD_ENTRIES_NOTED:
                _UNREAD_ENTRIES_NOTED.add((text, other))
                logger.warning(
                    "Provider block %s.%s is not read: %s declares its tools in %s.",
                    PROVIDER_BLOCKS_PATH,
                    key,
                    text,
                    other,
                )
            continue
        readers.setdefault(text, partial(provider_block, provider=key))
    for text, read in list(_RUNTIME_PROVIDER_DECLARATIONS.items()):
        readers.setdefault(text, read)
    for text, read in readers.items():
        if text in blocks:
            continue
        try:
            block = read(settings)
        except Exception as exc:  # noqa: BLE001 — one provider never hides the others
            logger.warning(
                "Provider declaration for %s was not read (%s).", text, type(exc).__name__
            )
            continue
        if isinstance(block, Mapping):
            from maljan.core.config import MCPServerConfig

            try:
                block = MCPServerConfig.model_validate(dict(block))
            except ValueError as exc:
                logger.warning(
                    "Provider declaration for %s does not read (%s).", text, type(exc).__name__
                )
                continue
        if block is not None:
            blocks[text] = block
    return blocks


def _platform_release() -> str:
    """The installed platform's version, ``""`` where the package records none."""
    try:
        from importlib.metadata import version

        return version("maljan")
    except Exception:  # noqa: BLE001 — a checkout run without the package installed
        return ""


# The release a trusted block's kept declarations hold for: the platform's
# version and the generation of what the platform's own servers declare of
# themselves, raised whenever a release changes that (T-418 PR6: the runtime
# an identification answer names, the runtimes a tool reads, the files it
# writes), so a server listed by an earlier release is listed again.
SERVED_DECLARATIONS_GENERATION = 2
KEPT_DECLARATIONS_RELEASE = f"{_platform_release()}+{SERVED_DECLARATIONS_GENERATION}"


def launch_identity(cfg: Any) -> str:
    """A short digest of how a block starts or reaches its server; ``""`` for a block of none.

    Its transport, command, arguments, working directory and address, and,
    for a block that trusts what its server declares, the release that
    declaration is kept for (:data:`KEPT_DECLARATIONS_RELEASE`): a server's
    own declaration is kept under it, so a block pointed at another server,
    or read by another release, stops reading what was declared before. The command is read as
    the file it runs (:func:`_launched_file`), so two names of one program in
    one directory (``bin/python`` and its link ``bin/python3``) start the same
    server.
    """
    held = {
        name: getattr(cfg, name, None)
        for name in ("transport", "command", "args", "cwd", "url")
        if getattr(cfg, name, None) not in (None, "", [], ())
    }
    if not held:
        return ""
    if getattr(cfg, "trusts_served_declaration", False) is True:
        # What a block that trusts its server's declaration keeps of it is
        # kept for this release alone: a release reads none kept by another,
        # so its server is listed again before any run reads its tools.
        held["kept_for"] = KEPT_DECLARATIONS_RELEASE
    command = held.get("command")
    if isinstance(command, str):
        held["command"] = _launched_file(command)
    text = json.dumps(held, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _launched_file(command: str) -> str:
    """``command`` as the file it runs: its directory, and the file its links end at.

    A command that names no file here (a bare name found on the path, a path
    on another host) is read as written. The directory is kept: a link to the
    same program elsewhere (another virtual environment) runs it with other
    surroundings, and is another launch. The whole target is kept, so two
    links in one directory to different programs stay two launches.
    """
    try:
        path = Path(command)
        if not path.is_absolute() or not path.is_file():
            return command
        return f"{path.parent}|{os.path.realpath(path)}"
    except (OSError, ValueError):
        return command


# The shipped launches, held with the interpreter file they were read for: a
# built-in sidecar is started by this process's own interpreter, so they are
# read again if what that interpreter's path resolves to changes (a virtual
# environment rebuilt under a running process).
_SHIPPED_LAUNCHES: list[Any] = [None, {}]


def _shipped_launches() -> dict[str, str]:
    """The launch identity of each built-in server block that ships trusting its server."""
    import sys

    from maljan.core.config import _builtin_servers

    interpreter = _launched_file(sys.executable)
    if _SHIPPED_LAUNCHES[0] != interpreter:
        _SHIPPED_LAUNCHES[1] = {
            f"mcp:{key}": launch_identity(cfg)
            for key, cfg in _builtin_servers().items()
            if getattr(cfg, "trusts_served_declaration", False) is True
        }
        _SHIPPED_LAUNCHES[0] = interpreter
    return dict(_SHIPPED_LAUNCHES[1])


def shipped_launch(source: Any) -> str:
    """The launch identity the built-in ``source`` ships with on this host; ``""`` for none."""
    return _shipped_launches().get(str(source), "")


# How a block starts or reaches its server, as :func:`granted_launch` reads it.
_LAUNCH_FIELDS: tuple[str, ...] = ("transport", "command", "args", "cwd", "url")


def granted_launch(cfg: Any) -> str:
    """A short digest of how a block starts or reaches its server, as written; ``""`` for none.

    What an operator's trust in a server's own declaration is recorded with
    (``trust_granted_for``): the block's transport, command, arguments,
    working directory and address exactly as the block writes them. No file
    is resolved and no release is read, so a grant reads alike on every host
    and after every upgrade, and holds until the block is pointed elsewhere.
    """
    held = {
        name: getattr(cfg, name, None)
        for name in _LAUNCH_FIELDS
        if getattr(cfg, name, None) not in (None, "", [], ())
    }
    if not held:
        return ""
    text = json.dumps(held, sort_keys=True, default=str)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _at_shipped_launch(source: Any, cfg: Any) -> bool:
    """Whether ``cfg`` starts or reaches the server the built-in ``source`` ships trusting."""
    shipped = shipped_launch(source)
    if not shipped:
        return False
    trusting = {name: getattr(cfg, name, None) for name in _LAUNCH_FIELDS}
    trusting["trusts_served_declaration"] = True
    return launch_identity(SimpleNamespace(**trusting)) == shipped


def trusts_served(source: Any, cfg: Any) -> bool:
    """Whether ``cfg``, the block of ``source``, trusts what its server declares of its tools.

    Its ``trusts_served_declaration``. The trust a built-in block ships with
    holds only while the block still starts or reaches the server it shipped
    with (the same :func:`launch_identity`). Elsewhere a trust an operator
    granted from the console holds only for the launch it was granted for
    (``trust_granted_for``, :func:`granted_launch`), so pointing the block at
    another server withdraws it; with no grant recorded, a block pointed away
    from a built-in's server trusts it only where the flag was set in the
    block itself (a configuration file), and a server an operator added
    trusts it by its flag.
    """
    if getattr(cfg, "trusts_served_declaration", False) is not True:
        return False
    shipped = _shipped_launches().get(str(source))
    if shipped is not None and launch_identity(cfg) == shipped:
        return True
    granted = getattr(cfg, "trust_granted_for", None)
    if granted:
        return bool(granted == granted_launch(cfg))
    if shipped is None:
        return True
    return "trusts_served_declaration" in (getattr(cfg, "model_fields_set", None) or set())


def settled_trust(source: Any, cfg: Any, sent: Any) -> dict[str, Any]:
    """What a save records of ``cfg``'s trust in its server's own declaration.

    ``cfg`` is the block as saved, a built-in's fields it leaves out filled
    from what it ships, and ``sent`` the ``trust_granted_for`` the edit sent.
    The console serves a trusted block with the launch its trust holds for
    (:func:`shown_trust`), and sends an operator's tick as ``""``:

    * at the server a built-in ships trusting, the shipped trust holds and no
      grant is recorded;
    * elsewhere, a trust sent with ``""`` or with this launch's grant is the
      operator's and is recorded with this launch;
    * a trust sent with the grant of another launch is a trusted block
      pointed elsewhere in this edit: it is withdrawn, never carried over (a
      built-in's flag is left to what it ships, which holds only at its
      shipped server; any other block's is turned off);
    * a trust sent with no grant (``None``: a shipped default posted back, an
      older client, a script) records none, and is read as ever: a built-in
      pointed elsewhere does not trust its server.

    Returns the two fields to store; ``trust_granted_for`` is ``None`` for none.
    """
    flag = getattr(cfg, "trusts_served_declaration", False) is True
    if not flag or _at_shipped_launch(source, cfg):
        return {"trusts_served_declaration": flag, "trust_granted_for": None}
    if sent is None:
        return {"trusts_served_declaration": True, "trust_granted_for": None}
    here = granted_launch(cfg)
    if here and sent in ("", here):
        return {"trusts_served_declaration": True, "trust_granted_for": here}
    return {
        "trusts_served_declaration": bool(shipped_launch(source)),
        "trust_granted_for": None,
    }


def shown_trust(source: Any, cfg: Any) -> dict[str, Any]:
    """The trust of ``cfg`` as the console shows it: in force, with the launch it holds for.

    ``trusts_served_declaration`` is whether the block trusts its server's
    declaration now (:func:`trusts_served`), never a shipped value a block
    pointed elsewhere no longer holds; ``trust_granted_for`` is the launch a
    trust in force holds for (:func:`granted_launch`), which an unchanged
    save sends back and :func:`settled_trust` reads.
    """
    trusted = trusts_served(source, cfg)
    return {
        "trusts_served_declaration": trusted,
        "trust_granted_for": (granted_launch(cfg) or None) if trusted else None,
    }


@dataclass(frozen=True)
class Declared:
    """One source's whole declaration, read from its settings block or built-in data."""

    source: SourceRef
    label: str = ""
    enabled: bool = True
    sample_open: Any = None
    sample_mount: str = ""
    work_dir: str = ""
    error_patterns: tuple[ErrorPattern, ...] = ()
    roles: tuple[str, ...] = ()
    prompt_fragment: str = ""
    required_env_allow: tuple[str, ...] = ()
    variable_names: tuple[str, ...] = ()
    reads_staged_sample: bool = False
    platform_owned: bool = False
    auto_name_prefixes: tuple[str, ...] = ()
    data_label_prefixes: tuple[str, ...] = ()
    reference_urls: tuple[str, ...] = ()
    tools: Mapping[str, ToolFacts] = field(default_factory=dict)
    # The tools the block removed that it does not ship (``removed_tools``):
    # nothing its server lists is read of them.
    removed: frozenset[str] = frozenset()
    # Per tool, the kind-dependent fields the block sets with no kind of its
    # own (``kind_free_changes``), laid over the kind its listing's reading
    # puts in force.
    kind_free: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    # What a reputation service's server says of its lookups as a whole
    # (``ReputationService``), laid under the lookups read from its listing.
    reputation_service: ReputationService | None = None
    # What the block says of its tools as a whole (``default_effects``) and of
    # its analysis tool (``analyse_effects``), laid under each tool's effects
    # (``derived_declarations.with_server_effects``).
    default_effects: ToolEffects | None = None
    analyse_effects: ToolEffects | None = None
    # Whether the server's own declaration of its tools is read as the block's
    # (``trusts_served_declaration``), and the block's launch identity, which
    # a server's declaration is kept under (``core.served_declarations``).
    trusts_served: bool = False
    launch: str = ""
    # Per tool, the fields of its declaration in force that only its server
    # said, for a block that does not trust it: stored with each entry, and
    # read as the server's own statement (``core.declared_reading``).
    served_fields: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    # Per tool, what its untrusted server claims and nothing puts in force (a
    # kind whose answer moves or reaches outside): stored with each entry and
    # said as the server's, read only by a reader that applies it to be more
    # careful (``agents.tool_pinning``).
    served_claims: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)

    @classmethod
    def of(cls, source: SourceRef, cfg: Any, *, enabled: bool, label: str = "") -> Declared:
        copied = cfg.model_copy(deep=True) if isinstance(cfg, BaseModel) else cfg
        return cls(
            source=source,
            label=label or str(getattr(copied, "label", "") or source.key or source.kind),
            enabled=enabled,
            sample_open=getattr(copied, "sample_open", None),
            sample_mount=str(getattr(copied, "sample_mount", "") or ""),
            work_dir=str(getattr(copied, "work_dir", "") or ""),
            error_patterns=tuple(getattr(copied, "error_patterns", ()) or ()),
            roles=tuple(getattr(copied, "roles", ()) or ()),
            prompt_fragment=str(getattr(copied, "prompt_fragment", "") or ""),
            required_env_allow=tuple(getattr(copied, "required_env_allow", ()) or ()),
            variable_names=tuple(getattr(copied, "variable_names", ()) or ()),
            reads_staged_sample=bool(getattr(copied, "reads_staged_sample", False)),
            platform_owned=bool(getattr(copied, "platform_owned", False)),
            auto_name_prefixes=tuple(getattr(copied, "auto_name_prefixes", ()) or ()),
            data_label_prefixes=tuple(getattr(copied, "data_label_prefixes", ()) or ()),
            reference_urls=tuple(getattr(copied, "reference_urls", ()) or ()),
            tools=dict(getattr(copied, "tool_facts", {}) or {}),
            removed=frozenset(getattr(copied, "removed_tools", None) or ()),
            reputation_service=getattr(copied, "reputation_service", None),
            default_effects=getattr(copied, "default_effects", None),
            analyse_effects=getattr(copied, "analyse_effects", None),
            kind_free=dict(getattr(copied, "kind_free_changes", None) or {}),
            trusts_served=trusts_served(source, cfg),
            launch=launch_identity(copied),
        )


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


class ToolDeclarations:
    """Every source's declaration for one settings object, resolved by source and tool.

    Built from the effective settings: every server of ``mcp.servers``, the
    static providers' own blocks (``static.ghidra``, ``static.r2``; the
    ``generic_mcp`` provider reads the server it names), the CAPE provider's
    MCP block (``provider:cape2``), and the platform's in-process sources
    (``pack``, ``sandbox``, ``provider:capa_yara``), whose declarations are
    built-in data only: their answers are the platform's own code. Under each
    server's and provider's block, what the server itself declared of its
    tools when it was last listed (``core.served_declarations``).
    """

    def __init__(self, sources: Iterable[Declared]) -> None:
        self._sources: dict[SourceRef, Declared] = {d.source: d for d in sources}

    @classmethod
    def from_settings(cls, settings: Settings, *, served: bool = True) -> ToolDeclarations:
        """``settings``' declarations; with ``served``, each server's own laid under its block's.

        Without ``served``, the blocks alone: what the settings put in force,
        whichever servers this process has attached (a run's recorded digests).
        """
        from maljan.core.builtin_declarations import in_process_declarations

        selected = selected_static_providers(settings)
        sources: list[Declared] = []
        for key, cfg in settings.mcp.servers.items():
            sources.append(Declared.of(SourceRef("mcp", key), cfg, enabled=bool(cfg.enabled)))
        selected.add(str(settings.sandbox.provider))
        for text, block in provider_declarations(settings).items():
            ref = SourceRef.parse(text)
            sources.append(Declared.of(ref, block, enabled=ref.key in selected))
        for source, cfg in in_process_declarations().items():
            enabled = source.kind != "provider" or source.key in selected
            sources.append(Declared.of(source, cfg, enabled=enabled))
        if not served:
            return cls(sources)
        # What each server declared of its own tools when it was last listed,
        # under what its block puts in force (``core.served_declarations``).
        from maljan.core.served_declarations import with_served

        return cls(with_served(declared) for declared in sources)

    def sources(self, *, enabled_only: bool = False) -> list[Declared]:
        return [d for d in self._sources.values() if d.enabled or not enabled_only]

    def source(self, ref: SourceRef | str) -> Declared | None:
        return self._sources.get(SourceRef.parse(ref) if isinstance(ref, str) else ref)

    @staticmethod
    def source_of(entry: Any) -> SourceRef | None:
        """The source a ledger entry recorded when it was written, or ``None``.

        Only the recorded ``source`` decides: an entry written before sources
        were recorded, or one whose recorded source does not parse, has none,
        and is read by the legacy readers. A server, an agent or a tool name
        is never read for it.
        """
        recorded = _field(entry, "source")
        if not recorded:
            return None
        try:
            return SourceRef.parse(str(recorded))
        except ValueError:
            return None

    def declaration_for(self, entry: Any, *, exact: bool = False) -> ToolFacts | None:
        """The declaration of one tool, by its source and its name together.

        ``entry`` is a ledger entry (or a mapping with ``source`` and ``tool``),
        or a ``(source, tool)`` pair whose source is a :class:`SourceRef` or its
        text (``mcp:analysis``). A tool server's tool renamed with its own
        server's prefix (``knowledge__capabilities``) is read without that
        prefix; no other prefix is taken off. With ``exact`` the name is the
        declared one already (a tool recorded with the name its server
        declares it under) and nothing is taken off it.
        """
        if isinstance(entry, tuple):
            raw, tool = entry
            ref: SourceRef | None = SourceRef.parse(raw) if isinstance(raw, str) else raw
        else:
            ref = self.source_of(entry)
            tool = str(_field(entry, "tool") or "")
        if ref is None:
            return None
        held = self._sources.get(ref)
        if held is None:
            return None
        if tool in held.tools:
            return held.tools[tool]
        if ref.kind == "mcp" and not exact:
            return held.tools.get(renamed_tool(ref.key, tool))
        return None

    def served_fields_for(self, source: SourceRef | str, tool: str) -> tuple[str, ...]:
        """The fields of ``tool``'s declaration under ``source`` that only its server said.

        Empty for a block that trusts its server's declaration, and for every
        field the block itself declares (:attr:`Declared.served_fields`).
        """
        held = self.source(source)
        return tuple(held.served_fields.get(tool, ())) if held is not None else ()

    def served_claims_for(self, source: SourceRef | str, tool: str) -> Mapping[str, Any]:
        """What ``tool``'s untrusted server under ``source`` claims that nothing put in force."""
        held = self.source(source)
        return dict(held.served_claims.get(tool, {})) if held is not None else {}

    def tools_of_kind(
        self, kind: str | Iterable[str], *, enabled_only: bool = False
    ) -> list[tuple[SourceRef, str, ToolFacts]]:
        """Every declared tool of ``kind`` (or of any of several), as ``(source, tool, facts)``."""
        kinds = {kind} if isinstance(kind, str) else set(kind)
        return [
            (d.source, name, facts)
            for d in self.sources(enabled_only=enabled_only)
            for name, facts in d.tools.items()
            if facts.kind in kinds
        ]

    def servers_with_role(self, role: str, *, enabled_only: bool = False) -> list[SourceRef]:
        """Every source that declares ``role``."""
        return [d.source for d in self.sources(enabled_only=enabled_only) if role in d.roles]

    def digests(self) -> dict[str, str]:
        """Per source, a short digest of its declaration as it is in force."""
        return {
            str(d.source): declaration_digest(
                {
                    "sample_open": d.sample_open.model_dump(mode="json")
                    if isinstance(d.sample_open, BaseModel)
                    else d.sample_open,
                    "sample_mount": d.sample_mount,
                    "work_dir": d.work_dir,
                    "error_patterns": [p.model_dump(mode="json") for p in d.error_patterns],
                    "roles": list(d.roles),
                    "prompt_fragment": d.prompt_fragment,
                    "required_env_allow": list(d.required_env_allow),
                    "variable_names": list(d.variable_names),
                    "reads_staged_sample": d.reads_staged_sample,
                    "platform_owned": d.platform_owned,
                    "auto_name_prefixes": list(d.auto_name_prefixes),
                    "data_label_prefixes": list(d.data_label_prefixes),
                    "reference_urls": list(d.reference_urls),
                    "tool_facts": {n: f.model_dump(mode="json") for n, f in d.tools.items()},
                    # Named only where set, so a block that does not set it
                    # keeps the digest it had before the field existed.
                    **({"trusts_served_declaration": True} if d.trusts_served else {}),
                }
            )
            for d in self._sources.values()
        }


def selected_static_providers(settings: Settings) -> set[str]:
    """The static providers this deployment selects: the global one, any agent's and any team's.

    A team's choice outranks its members' own at run time, so it is selected too.
    """
    chosen = {str(settings.static.provider)}
    for definition in settings.agents.definitions.values():
        if definition.enabled and definition.static_provider:
            chosen.add(str(definition.static_provider))
    for team in settings.agents.profiles.values():
        if team.static_provider:
            chosen.add(str(team.static_provider))
    return chosen


def _declarations(settings: Settings | None) -> ToolDeclarations:
    if settings is None:
        from maljan.core.config import get_settings

        settings = get_settings()
    return ToolDeclarations.from_settings(settings)


def declaration_for(entry: Any, *, settings: Settings | None = None) -> ToolFacts | None:
    """The declaration of a ledger entry's tool (see :meth:`ToolDeclarations.declaration_for`)."""
    return _declarations(settings).declaration_for(entry)


def tools_of_kind(
    kind: str | Iterable[str], *, settings: Settings | None = None, enabled_only: bool = False
) -> list[tuple[SourceRef, str, ToolFacts]]:
    """Every declared tool of ``kind`` (see :meth:`ToolDeclarations.tools_of_kind`)."""
    return _declarations(settings).tools_of_kind(kind, enabled_only=enabled_only)


def servers_with_role(
    role: str, *, settings: Settings | None = None, enabled_only: bool = False
) -> list[SourceRef]:
    """Every source declaring ``role`` (see :meth:`ToolDeclarations.servers_with_role`)."""
    return _declarations(settings).servers_with_role(role, enabled_only=enabled_only)
