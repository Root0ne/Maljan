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
shipped one is not recorded and follows later releases. A server that is not a
built-in starts from nothing and inherits nothing.

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

import hashlib
import json
import posixpath
import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from functools import lru_cache
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

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
# The separator a registry joins a server key and a tool name with when two
# servers offer the same name; a declared tool name may not hold it.
RENAMED_TOOL_SEPARATOR = "__"

# The two path wildcards; ``**N`` bounds the depth.
EVERY = "*"
ANY_DEPTH = "**"
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
        return message_lines(found.group(self.message_group) if self.message_group else text)

    def remediation_for(self, sample_path: str | None) -> str:
        """The remediation, naming ``sample_path`` where the pattern has a form for it."""
        if sample_path and self.remediation_with_path:
            return self.remediation_with_path.replace(SAMPLE_PATH_PLACEHOLDER, sample_path)
        return self.remediation


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
    about the sample; empty, an answer written in prose is its own summary.
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
            if found is not None:
                groups = compile_pattern(pattern).groupindex

                def _group(name: str, held: Any = found, named: Any = groups) -> int | None:
                    value = held.group(name) if name in named else None
                    return int(value) if value else None

                return int(found.group("malicious")), _group("total"), _group("suspicious")
        return None


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
    of the deployment. ``holds_strings`` marks a tool whose answer holds the
    sample's strings as data though its kind is not a strings kind (a report
    that anchors strings to the functions referring to them).

    ``rows`` is the path of the answer's rows; ``places`` names, per kind of
    place (``offset``, ``rva``, ``address``, ``addresses``, ``call_site``,
    ``function``, ``pid``, ``command_line`` …), the path inside a row that
    holds one; ``values`` names, per kind of value (``text``, ``rule``,
    ``namespace``, ``value`` …), the path inside a row that holds one.
    ``techniques`` lists where the answer names technique ids. ``reputation``
    is set on a reputation lookup. ``arguments`` names, per role (``path``,
    ``hash``, ``address``, ``program``, ``command_lines`` …), the argument a
    call gives it in.

    ``reader`` names a reader of an answer *shape* the paths cannot express
    (``emulated_strings_with_call_sites``, ``flow_table`` …; empty: the generic
    reading of the paths); never a tool's name. ``report_sections`` lists the
    report sections whose writer is shown this tool's answers, ``words`` the
    words a statement may use to name this tool's entry, ``display_name`` the
    name published text gives the tool, and ``category`` the tag its
    description is shown with.
    """

    model_config = ConfigDict(frozen=True)

    kind: str
    asserts_techniques: bool = False
    source: str = ""
    long_running: bool = False
    timeout_seconds: float | None = Field(default=None, gt=0)
    memory_peak_mb: int | None = Field(default=None, gt=0)
    discloses_sample: bool = False
    holds_strings: bool = False
    rows: str = ""
    places: dict[str, str] = Field(default_factory=dict)
    values: dict[str, str] = Field(default_factory=dict)
    techniques: tuple[TechniqueField, ...] = ()
    reputation: ReputationFacts | None = None
    arguments: dict[str, str] = Field(default_factory=dict)
    reader: str = ""
    report_sections: tuple[str, ...] = ()
    words: tuple[str, ...] = ()
    display_name: str = ""
    category: str = ""

    @field_validator("kind")
    @classmethod
    def _kind_is_a_word(cls, value: str) -> str:
        return _word(value, "tool kind")

    @field_validator("source", "reader", "category")
    @classmethod
    def _optional_word(cls, value: str, info: Any) -> str:
        return _word(value, info.field_name) if value else value

    @field_validator("rows")
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

    @model_validator(mode="after")
    def _a_source_is_an_asserting_tool_s(self) -> ToolFacts:
        if self.asserts_techniques and not self.techniques:
            raise ValueError("asserts_techniques needs techniques: where the answer names them")
        if self.source and not self.asserts_techniques:
            raise ValueError("source names a corroborating tool; set asserts_techniques")
        if (self.places or self.values) and not self.rows:
            raise ValueError("places and values are read inside rows; declare rows")
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
    "auto_name_prefixes",
    "reference_urls",
    "tool_facts",
    "credential_bootstrap",
)
# The declaration fields a settings snapshot records only where an operator
# set them (the shipped values are named by a digest instead).
SNAPSHOT_DIGESTED_FIELDS: tuple[str, ...] = tuple(
    f for f in DECLARATION_FIELDS if f != "sample_open"
)
# The placeholders a reference URL template may name.
REFERENCE_PLACEHOLDERS: tuple[str, ...] = ("{sha256}", "{md5}", "{sha1}")


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


def _copy(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return value.model_copy(deep=True)
    if isinstance(value, dict):
        return {k: _copy(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_copy(v) for v in value]
    return value


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


def strip_declaration_defaults(dumped: dict[str, Any], default: MCPServerConfig) -> dict[str, Any]:
    """A built-in's stored row without the declaration fields equal to its default.

    The tool-server map is stored whole on every save, so a row that carried
    each default would freeze the built-in's declaration at the day of the
    save and a later release could never correct it. A value that differs
    from the default, an empty one included, is the operator's and is stored;
    a value equal to the shipped one at the time of the save is not recorded,
    and follows later releases.
    """
    reference = default.model_dump(mode="json")
    return {
        key: value
        for key, value in dumped.items()
        if key not in DECLARATION_FIELDS or value != reference.get(key)
    }


def declaration_digest(cfg: Any) -> str:
    """A short digest of one block's whole declaration, as it is in force."""
    dumped = cfg.model_dump(mode="json") if isinstance(cfg, BaseModel) else dict(cfg)
    # A field a block leaves unset (``None``) is left out, so a field added to
    # the declaration later moves no digest of a block that does not set it.
    body = {name: dumped.get(name) for name in DECLARATION_FIELDS if dumped.get(name) is not None}
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

# The provider-owned server blocks, by the source their declarations are read
# under, at their dotted path in the settings. The one table of them: the read
# API, the run snapshot and anything else that walks the blocks use it.
PROVIDER_BLOCKS: dict[str, str] = {
    "provider:ghidra": "static.ghidra",
    "provider:r2": "static.r2",
    "provider:cape2": "sandbox.cape2.mcp",
}


def block_at(settings: Any, path: str) -> Any:
    """The settings block at a dotted ``path``."""
    node = settings
    for part in path.split("."):
        node = getattr(node, part)
    return node


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
    reference_urls: tuple[str, ...] = ()
    tools: Mapping[str, ToolFacts] = field(default_factory=dict)

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
            reference_urls=tuple(getattr(copied, "reference_urls", ()) or ()),
            tools=dict(getattr(copied, "tool_facts", {}) or {}),
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
    built-in data only: their answers are the platform's own code.
    """

    def __init__(self, sources: Iterable[Declared]) -> None:
        self._sources: dict[SourceRef, Declared] = {d.source: d for d in sources}

    @classmethod
    def from_settings(cls, settings: Settings) -> ToolDeclarations:
        from maljan.core.builtin_declarations import in_process_declarations

        selected = selected_static_providers(settings)
        sources: list[Declared] = []
        for key, cfg in settings.mcp.servers.items():
            sources.append(Declared.of(SourceRef("mcp", key), cfg, enabled=bool(cfg.enabled)))
        selected.add(str(settings.sandbox.provider))
        for text, path in PROVIDER_BLOCKS.items():
            ref = SourceRef.parse(text)
            sources.append(Declared.of(ref, block_at(settings, path), enabled=ref.key in selected))
        for source, cfg in in_process_declarations().items():
            enabled = source.kind != "provider" or source.key in selected
            sources.append(Declared.of(source, cfg, enabled=enabled))
        return cls(sources)

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

    def declaration_for(self, entry: Any) -> ToolFacts | None:
        """The declaration of one tool, by its source and its name together.

        ``entry`` is a ledger entry (or a mapping with ``source`` and ``tool``),
        or a ``(source, tool)`` pair whose source is a :class:`SourceRef` or its
        text (``mcp:analysis``). A tool server's tool renamed with its own
        server's prefix (``knowledge__capabilities``) is read without that
        prefix; no other prefix is taken off.
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
        if ref.kind == "mcp":
            return held.tools.get(renamed_tool(ref.key, tool))
        return None

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
                    "reference_urls": list(d.reference_urls),
                    "tool_facts": {n: f.model_dump(mode="json") for n, f in d.tools.items()},
                }
            )
            for d in self._sources.values()
        }


def selected_static_providers(settings: Settings) -> set[str]:
    """The static providers this deployment selects: the global one and any agent's own."""
    chosen = {str(settings.static.provider)}
    for definition in settings.agents.definitions.values():
        if definition.enabled and definition.static_provider:
            chosen.add(str(definition.static_provider))
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
