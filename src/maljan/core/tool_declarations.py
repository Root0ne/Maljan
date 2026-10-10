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
an empty value, is kept as set (:func:`fill_declaration`). A server that is
not a built-in starts from nothing and inherits nothing, so a user tool that
shares a built-in tool's name never takes the built-in's declaration.

The read API (:class:`ToolDeclarations`, :func:`declaration_for`,
:func:`tools_of_kind`, :func:`servers_with_role`) resolves a ledger entry by
its source and tool together. The source is the server key for a tool server,
``pack`` for the triage pack, ``sandbox`` for the platform's sandbox report
tools and ``provider:<id>`` for a static provider's own tools; a bare tool name
is never looked up on its own.

Vocabulary values (a tool's ``kind``, a server's ``roles``, the names of place
and value fields, a technique ``format``, a ``reader`` id) are an open set:
any lowercase word of letters, digits and underscores is accepted, so a new
kind of tool needs no code change to be declared. The values the built-ins use
are listed in ``apps/docs/content/docs/configuration.mdx``.

Field paths (``rows``, ``places``, ``values``, technique and reputation paths)
are JSON-pointer-like: ``/`` separated keys, ``~0`` for ``~`` and ``~1`` for
``/`` inside a key, ``*`` for every item of a list or every value of an object
at that level, and ``**`` for any depth (zero or more levels), at most once in
a path and never in a path read inside a row. :func:`select` reads one in time
linear in the size of the answer.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

if TYPE_CHECKING:
    from maljan.core.config import MCPServerConfig, Settings

# An open vocabulary value: a lowercase word. Shape-checked, never a closed list.
VOCABULARY_PATTERN = r"^[a-z][a-z0-9_]{0,63}$"
_VOCABULARY_RE = re.compile(VOCABULARY_PATTERN)
# An environment variable name, as a POSIX shell spells one.
ENV_NAME_PATTERN = r"^[A-Za-z_][A-Za-z0-9_]*$"
_ENV_NAME_RE = re.compile(ENV_NAME_PATTERN)

# The two path wildcards.
EVERY = "*"
ANY_DEPTH = "**"


def _word(value: str, what: str) -> str:
    if not _VOCABULARY_RE.match(value):
        raise ValueError(
            f"{what} {value!r} is not a vocabulary word: lowercase letters, digits and "
            "underscores, starting with a letter, at most 64 characters"
        )
    return value


def _words(values: Iterable[str], what: str) -> list[str]:
    return [_word(v, what) for v in values]


# ---------------------------------------------------------------------------
# Field paths
# ---------------------------------------------------------------------------


def parse_path(path: str, *, in_row: bool = False) -> tuple[str, ...]:
    """The segments of a declared field path, or ``ValueError`` saying what is wrong.

    ``""`` is no path (nothing declared). Every other path starts with ``/``.
    ``in_row`` paths are read once per row and may not hold ``**``: a row nested
    in another would be walked twice, and the read would no longer be linear.
    """
    if path == "":
        return ()
    if not path.startswith("/"):
        raise ValueError(f"field path {path!r} must start with '/'")
    segments = tuple(part.replace("~1", "/").replace("~0", "~") for part in path[1:].split("/"))
    deep = sum(1 for part in segments if part == ANY_DEPTH)
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


def _walk(nodes: Iterable[Any], segments: Sequence[str]) -> list[Any]:
    current = list(nodes)
    for segment in segments:
        current = [found for node in current for found in _step(node, segment)]
    return current


def _subtree(node: Any) -> list[Any]:
    """Every node under ``node``, itself first, in document order, without recursion."""
    out: list[Any] = []
    stack = [node]
    while stack:
        current = stack.pop()
        out.append(current)
        stack.extend(reversed(list(_children(current))))
    return out


def select(document: Any, path: str | Sequence[str]) -> list[Any]:
    """Every value ``path`` names in ``document``, in document order.

    A path that names nothing gives ``[]``; ``""`` gives ``[]`` too (nothing is
    declared). With ``**`` the nodes under the part before it are each visited
    once, so the read is linear in the size of the document.
    """
    segments = parse_path(path) if isinstance(path, str) else tuple(path)
    if not segments:
        return []
    if ANY_DEPTH not in segments:
        return _walk([document], segments)
    cut = segments.index(ANY_DEPTH)
    roots = _walk([document], segments[:cut])
    rest = segments[cut + 1 :]
    under = [node for root in roots for node in _subtree(root)]
    return _walk(under, rest) if rest else under


def first(document: Any, path: str) -> Any:
    """The first value ``path`` names in ``document``, or ``None``."""
    found = select(document, path)
    return found[0] if found else None


def _check_path(value: str, *, in_row: bool = False) -> str:
    parse_path(value, in_row=in_row)
    return value


def _check_regex(value: str, what: str) -> str:
    try:
        re.compile(value)
    except re.error as exc:
        raise ValueError(f"{what} {value!r} is not a valid regular expression ({exc})") from exc
    return value


# ---------------------------------------------------------------------------
# The schema
# ---------------------------------------------------------------------------


class ErrorPattern(BaseModel):
    """One way a server's plain-text answer says "error" instead of answering.

    ``match`` is a regular expression held against the *whole* answer, never a
    line inside one: a listing of the sample's own strings can hold any
    sentence, and a string the sample carries is not the tool failing. ``code``
    is the error code the entry is filed under (``tool_failed``,
    ``bad_argument`` …); ``remediation`` what would make the call succeed, or
    empty; ``tools`` the tools it applies to, empty for every tool of the
    server.
    """

    match: str
    code: str = "tool_failed"
    remediation: str = ""
    tools: list[str] = Field(default_factory=list)

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

    def matches(self, tool: str, answer: str) -> bool:
        """Whether ``answer`` from ``tool`` is this error."""
        if self.tools and tool not in self.tools:
            return False
        return re.fullmatch(self.match, answer) is not None


class TechniqueField(BaseModel):
    """Where an answer names ATT&CK technique ids, and how they are written.

    ``format`` names the reader: ``attck`` for a bare id or a decorated label
    (``Defense Evasion::Obfuscated Files or Information [T1027]``), as
    ``analysis.technique_ids.technique_ids_in`` reads one; ``sigma_tag`` for a
    Sigma tag (``attack.t1055.012``). Open vocabulary.
    """

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
    """Where a reputation answer holds its counts and labels.

    ``service`` is the name the answer is attributed to (empty: the server
    key). ``stats`` names the object of engine counts; ``malicious`` and
    ``total`` the two counts (an empty ``total`` is the sum of ``stats``'
    whole-number values). ``labels`` are the paths of the threat labels, in the
    order they are read; ``detections`` the list of per-engine result labels;
    ``engines`` the engine count the service gives beside them.
    ``text_pattern`` reads an answer written in prose: a regular expression
    with a ``malicious`` group and optionally a ``total`` group.
    """

    service: str = ""
    stats: str = ""
    malicious: str = ""
    total: str = ""
    labels: list[str] = Field(default_factory=list)
    detections: str = ""
    engines: str = ""
    text_pattern: str = ""

    @field_validator("stats", "malicious", "total", "detections", "engines")
    @classmethod
    def _paths_parse(cls, value: str) -> str:
        return _check_path(value)

    @field_validator("labels")
    @classmethod
    def _label_paths_parse(cls, value: list[str]) -> list[str]:
        return [_check_path(v) for v in value]

    @field_validator("text_pattern")
    @classmethod
    def _text_pattern_names_its_count(cls, value: str) -> str:
        if not value:
            return value
        _check_regex(value, "reputation text pattern")
        if "malicious" not in re.compile(value).groupindex:
            raise ValueError("a reputation text pattern needs a group named 'malicious'")
        return value


class ToolFacts(BaseModel):
    """What one tool's answer is, and where its facts sit in it.

    ``kind`` says what kind of fact the answer is (open vocabulary: ``strings``,
    ``decoded_strings``, ``rule_match``, ``decompile``, ``disassembly``,
    ``xrefs``, ``callers``, ``callees``, ``function_list``, ``reputation``,
    ``sandbox_report``, ``pcap`` …). ``asserts_techniques`` marks a tool whose
    technique id is a statement about this sample (a rule that matched it), and
    ``source`` the name a corroboration row gives it (``sigma`` for both Sigma
    tools). ``long_running`` marks a tool whose work grows with the sample and
    has no wall clock of its own.

    ``rows`` is the path of the answer's rows; ``places`` names, per kind of
    place (``offset``, ``rva``, ``address``, ``addresses``, ``call_site``,
    ``function``, ``pid`` …), the path inside a row that holds one; ``values``
    names, per kind of value (``text``, ``rule``, ``namespace``, ``value`` …),
    the path inside a row that holds one. ``techniques`` lists where the answer
    names technique ids. ``reputation`` is set on a reputation lookup.
    ``arguments`` names, per role (``path``, ``hash``, ``address``, ``name`` …),
    the argument a call gives it in. ``reader`` names a reader a consumer keeps
    for an answer shape the paths cannot express (empty: the generic reading of
    the paths). ``report_sections`` lists the report sections whose writer is
    shown this tool's answers, and ``words`` the words a statement may use to
    name this tool's entry.
    """

    kind: str
    asserts_techniques: bool = False
    source: str = ""
    long_running: bool = False
    rows: str = ""
    places: dict[str, str] = Field(default_factory=dict)
    values: dict[str, str] = Field(default_factory=dict)
    techniques: list[TechniqueField] = Field(default_factory=list)
    reputation: ReputationFacts | None = None
    arguments: dict[str, str] = Field(default_factory=dict)
    reader: str = ""
    report_sections: list[str] = Field(default_factory=list)
    words: list[str] = Field(default_factory=list)

    @field_validator("kind")
    @classmethod
    def _kind_is_a_word(cls, value: str) -> str:
        return _word(value, "tool kind")

    @field_validator("source", "reader")
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
            if not name:
                raise ValueError(f"arguments.{role} needs an argument name")
        return value

    @field_validator("report_sections")
    @classmethod
    def _sections_are_words(cls, value: list[str]) -> list[str]:
        return _words(value, "report section")

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


# The fields of ``MCPServerConfig`` that are its declaration, in the order the
# docs list them. ``sample_open`` came first (its own model in ``config``).
DECLARATION_FIELDS: tuple[str, ...] = (
    "sample_open",
    "sample_mount",
    "error_patterns",
    "roles",
    "prompt_fragment",
    "required_env_allow",
    "reads_staged_sample",
    "tool_facts",
)


def check_roles(value: list[str]) -> list[str]:
    return _words(value, "server role")


def check_env_names(value: list[str]) -> list[str]:
    for name in value:
        if not _ENV_NAME_RE.match(name):
            raise ValueError(f"{name!r} is not an environment variable name")
    return value


def check_mount(value: str) -> str:
    if value and not value.startswith("/"):
        raise ValueError(
            f"sample_mount {value!r} must be an absolute path inside the server, or empty "
            "when the server reads the worker's own filesystem"
        )
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
    from the default, an empty one included, is the operator's and is stored.
    """
    reference = default.model_dump(mode="json")
    return {
        key: value
        for key, value in dumped.items()
        if key not in DECLARATION_FIELDS or value != reference.get(key)
    }


# ---------------------------------------------------------------------------
# The read API
# ---------------------------------------------------------------------------

SourceKind = Literal["mcp", "provider", "sandbox", "pack"]

# The ledger's name for the triage pack, which records every step with this
# server and this agent (``pipeline.triage_pack``).
PACK_LEDGER_NAME = "pipeline"
# The agent the evidence-only rule provider records its entries under
# (``providers.static.capa_yara.ledger_entries``), with no server.
EVIDENCE_PROVIDER_AGENT = "capa_yara"


@dataclass(frozen=True)
class SourceRef:
    """Where a tool comes from: a tool server, a static provider, or the platform."""

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


@dataclass(frozen=True)
class Declared:
    """One source's whole declaration, read from its settings block or built-in data."""

    source: SourceRef
    label: str = ""
    enabled: bool = True
    sample_open: Any = None
    sample_mount: str = ""
    error_patterns: tuple[ErrorPattern, ...] = ()
    roles: tuple[str, ...] = ()
    prompt_fragment: str = ""
    required_env_allow: tuple[str, ...] = ()
    reads_staged_sample: bool = False
    tools: Mapping[str, ToolFacts] = field(default_factory=dict)

    @classmethod
    def of(cls, source: SourceRef, cfg: Any, *, enabled: bool, label: str = "") -> Declared:
        return cls(
            source=source,
            label=label or str(getattr(cfg, "label", "") or source.key or source.kind),
            enabled=enabled,
            sample_open=getattr(cfg, "sample_open", None),
            sample_mount=str(getattr(cfg, "sample_mount", "") or ""),
            error_patterns=tuple(getattr(cfg, "error_patterns", ()) or ()),
            roles=tuple(getattr(cfg, "roles", ()) or ()),
            prompt_fragment=str(getattr(cfg, "prompt_fragment", "") or ""),
            required_env_allow=tuple(getattr(cfg, "required_env_allow", ()) or ()),
            reads_staged_sample=bool(getattr(cfg, "reads_staged_sample", False)),
            tools=dict(getattr(cfg, "tool_facts", {}) or {}),
        )


def _field(entry: Any, name: str) -> Any:
    if isinstance(entry, Mapping):
        return entry.get(name)
    return getattr(entry, name, None)


class ToolDeclarations:
    """Every source's declaration for one settings object, resolved by source and tool.

    Built from the effective settings: every server of ``mcp.servers``, the
    static providers' own blocks (``static.ghidra``, ``static.r2``; the
    ``generic_mcp`` provider reads the server it names), and the platform's
    in-process sources (``pack``, ``sandbox``, ``provider:capa_yara``), whose
    declarations are built-in data only: their answers are the platform's own
    code.
    """

    def __init__(self, sources: Iterable[Declared]) -> None:
        self._sources: dict[SourceRef, Declared] = {d.source: d for d in sources}

    @classmethod
    def from_settings(cls, settings: Settings) -> ToolDeclarations:
        from maljan.core.builtin_declarations import in_process_declarations

        selected = _selected_providers(settings)
        sources: list[Declared] = []
        for key, cfg in settings.mcp.servers.items():
            sources.append(Declared.of(SourceRef("mcp", key), cfg, enabled=bool(cfg.enabled)))
        static = settings.static
        for provider, cfg in (("ghidra", static.ghidra), ("r2", static.r2)):
            sources.append(
                Declared.of(SourceRef("provider", provider), cfg, enabled=provider in selected)
            )
        generic = settings.mcp.servers.get(static.generic.server or "")
        if generic is not None:
            sources.append(
                Declared.of(
                    SourceRef("provider", "generic_mcp"),
                    generic,
                    enabled="generic_mcp" in selected,
                )
            )
        for source, cfg in in_process_declarations().items():
            enabled = source.kind != "provider" or source.key in selected
            sources.append(Declared.of(source, cfg, enabled=enabled))
        return cls(sources)

    def sources(self, *, enabled_only: bool = False) -> list[Declared]:
        return [d for d in self._sources.values() if d.enabled or not enabled_only]

    def source(self, ref: SourceRef | str) -> Declared | None:
        return self._sources.get(SourceRef.parse(ref) if isinstance(ref, str) else ref)

    def source_of(self, entry: Any, *, provider: str | None = None) -> SourceRef | None:
        """The source a ledger entry's tool came from.

        A named server is that server (the triage pack's own name, with its own
        agent, is the pack). An entry with no server came from the
        evidence-only provider (by its agent), from ``provider`` (the static
        provider of the agent that made the call) when that provider declares
        the tool, else from the platform's sandbox report tools when they do.
        """
        server = _field(entry, "server")
        tool = str(_field(entry, "tool") or "")
        if server:
            if server == PACK_LEDGER_NAME and _field(entry, "agent") == PACK_LEDGER_NAME:
                return PACK
            return SourceRef("mcp", str(server))
        if _field(entry, "agent") == EVIDENCE_PROVIDER_AGENT:
            return SourceRef("provider", EVIDENCE_PROVIDER_AGENT)
        if provider:
            ref = SourceRef("provider", provider)
            held = self._sources.get(ref)
            if held is not None and tool in held.tools:
                return ref
        sandbox = self._sources.get(SANDBOX)
        if sandbox is not None and tool in sandbox.tools:
            return SANDBOX
        return SourceRef("provider", provider) if provider else None

    def declaration_for(self, entry: Any, *, provider: str | None = None) -> ToolFacts | None:
        """The declaration of one tool, by its source and its name together.

        ``entry`` is a ledger entry (or a mapping with ``server``, ``agent`` and
        ``tool``), or a ``(source, tool)`` pair whose source is a
        :class:`SourceRef` or its text (``mcp:analysis``). A tool server's tool
        renamed with its own server's prefix (``knowledge__capabilities``) is
        read without that prefix; no other prefix is taken off.
        """
        if isinstance(entry, tuple):
            raw, tool = entry
            ref: SourceRef | None = SourceRef.parse(raw) if isinstance(raw, str) else raw
        else:
            ref = self.source_of(entry, provider=provider)
            tool = str(_field(entry, "tool") or "")
        if ref is None:
            return None
        held = self._sources.get(ref)
        if held is None:
            return None
        if ref.kind == "mcp" and tool.startswith(f"{ref.key}__"):
            tool = tool[len(ref.key) + 2 :]
        return held.tools.get(tool)

    def tools_of_kind(
        self, kind: str, *, enabled_only: bool = False
    ) -> list[tuple[SourceRef, str, ToolFacts]]:
        """Every declared tool of ``kind``, as ``(source, tool, declaration)``."""
        return [
            (d.source, name, facts)
            for d in self.sources(enabled_only=enabled_only)
            for name, facts in d.tools.items()
            if facts.kind == kind
        ]

    def servers_with_role(self, role: str, *, enabled_only: bool = False) -> list[SourceRef]:
        """Every source that declares ``role``."""
        return [d.source for d in self.sources(enabled_only=enabled_only) if role in d.roles]


def _selected_providers(settings: Settings) -> set[str]:
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


def declaration_for(
    entry: Any, *, settings: Settings | None = None, provider: str | None = None
) -> ToolFacts | None:
    """The declaration of a ledger entry's tool (see :meth:`ToolDeclarations.declaration_for`)."""
    return _declarations(settings).declaration_for(entry, provider=provider)


def tools_of_kind(
    kind: str, *, settings: Settings | None = None, enabled_only: bool = False
) -> list[tuple[SourceRef, str, ToolFacts]]:
    """Every declared tool of ``kind`` (see :meth:`ToolDeclarations.tools_of_kind`)."""
    return _declarations(settings).tools_of_kind(kind, enabled_only=enabled_only)


def servers_with_role(
    role: str, *, settings: Settings | None = None, enabled_only: bool = False
) -> list[SourceRef]:
    """Every source declaring ``role`` (see :meth:`ToolDeclarations.servers_with_role`)."""
    return _declarations(settings).servers_with_role(role, enabled_only=enabled_only)
