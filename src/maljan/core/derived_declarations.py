"""What the platform reads of a tool nobody declared, from what its server listed.

A tool's declaration (``core.tool_declarations.ToolFacts``) comes from its
block (an operator's stored declaration, what the platform ships for its own
sources) and from what its server declares of itself
(``core.served_declarations``). What is read here comes from the parts of a
tool's MCP definition every server fills, by the same rules for every server
and never by a server's or a tool's name:

* the ``inputSchema``: which argument takes the sample's hash, an indicator
  (a domain, an address, a URL), a path or a file, the file's content as
  bytes, or the id of a submission, an analysis, a task or a request, by the
  words of each argument's name and its schema ``format`` and
  ``contentEncoding``, one level of nested objects included;
* the MCP ``annotations``, read as MCP defines them: ``readOnlyHint`` (the
  tool does not change its environment; MCP's default is that it does),
  ``destructiveHint`` and ``openWorldHint`` (it reaches outside its server;
  MCP's default is that it does). Read-only says nothing of what a tool
  sends, so it never excuses sending;
* the words of the tool's name and description that say it submits or
  uploads something.

Two readings come of it, and each has its own reach:

* **Disclosure** (:func:`discloses`), read for every server and every tool,
  one its server declares under ``_meta`` included. A tool that takes the
  file's content as bytes sends them, unless it is marked both read-only and
  closed (``openWorldHint`` false); a tool that takes a path or a file sends
  the file it opens, unless it is marked closed, and always when it says it
  submits or uploads. Either is ``discloses_sample``: the run's disclosure
  names the upload, as for a declared tool. When the definition leaves it
  open, the reading is that the tool sends.
* **A reputation service's tools** (:func:`service_facts`), read only for a
  block whose ``roles`` hold ``reputation`` (the operator's statement, or the
  catalog's for a server it ships, that the server is a service outside the
  deployment that reports on samples and indicators), and only for a tool its
  server does not declare. A tool that sends the file, or that is not marked
  read-only, or is marked destructive, is a submission (``submission``); only
  a tool marked read-only and not destructive is read as asking: one that
  takes the id of a submission is that submission's status
  (``submission_status``), one that requires the sample's hash a reputation
  lookup (``kind: reputation``, the argument it takes the hash in, its answer
  read by its shape, :data:`~maljan.core.reputation.SHAPE_READER`), one that
  requires an indicator a report on it (``indicator_report``). Each says what
  it sends: a lookup by the hash or by a submission's id sends the hash
  (``third_party: hash``), a report on an indicator nothing of the sample
  (``third_party: no``), and a submission that sends the file hands it to the
  service, whose sandboxes may run it (``executes: sandbox``). Every one
  reaches the network, unless its server marks it closed. What the block says
  of the service as a whole (``reputation_service``: its name and rank) is
  laid under each lookup read so.

Whatever a block or its server declares of a tool is in force over what is
read here, field by field (:func:`lay_under`), with two exceptions that keep
the platform careful: the disclosure reading is dropped only where the block
itself (an operator's declaration, or what the platform ships) says what the
tool sends, or where a server the block trusts declares the tool; never on a
server's untrusted word.

What is read is kept with what the server declared, under the same launch
identity and past the process (``core.served_declarations``), so the readers
that decide before a server attaches (the pack's reputation lookup, the
capability binding) read it as they read a server's own declaration.

Everything read is the server's data: schemas are walked once and to a fixed
depth, no text of a description is kept, and the result is a declaration the
model validates.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from maljan.core.logger import logger
from maljan.core.reputation import (
    HASH_ARGUMENT,
    INDICATOR_ROLE_WORDS,
    NETWORK_INDICATOR_ARGUMENTS,
    REPUTATION_ROLE,
    SHAPE_READER,
)
from maljan.core.tool_declarations import (
    EXECUTES_NO,
    EXECUTES_SANDBOX,
    THIRD_PARTY_BYTES,
    THIRD_PARTY_HASH,
    THIRD_PARTY_NO,
    ToolFacts,
    check_tool_name,
)

__all__ = [
    "DERIVED_SHOWS",
    "closed_by_hints",
    "closes_the_world",
    "derived_facts_of",
    "derived_tool_facts",
    "discloses",
    "lay_under",
    "program_arguments",
    "program_readings_of",
    "service_facts",
    "takes_content",
    "with_server_effects",
]

# The kinds a reputation service's tools are read as.
REPUTATION = "reputation"
INDICATOR_REPORT = "indicator_report"
SUBMISSION = "submission"
SUBMISSION_STATUS = "submission_status"

# What a reputation lookup read here shows and does not show, in the words a
# declared lookup says it in, for any service.
DERIVED_SHOWS: dict[str, str] = {
    "shows": "what the service holds for the hash: its engines' detections and file details",
    "does_not_show": (
        "this run's own analysis of the sample; an unknown hash or no detections is no "
        "evidence that the file is clean"
    ),
}

# The words of an argument's name that say it takes the file's content as bytes.
_CONTENT_WORDS = frozenset({"content", "contents", "bytes", "base64", "b64", "blob", "payload"})
# The schema ``format`` and ``contentEncoding`` values that say the same.
_CONTENT_FORMATS = frozenset({"byte", "binary", "base64"})
# The schema types the file's content cannot be sent in.
_NOT_CONTENT_TYPES = frozenset({"integer", "number", "boolean"})
# The words that say content only beside a file's word (``file_data``,
# ``sample_body``): alone they are any data.
_CONTENT_WITH_A_FILE_WORDS = frozenset({"data", "body"})
# The words of an argument's name that say it takes the sample's hash.
_HASH_WORDS = frozenset({"hash", "digest", "sha256", "sha1", "md5"})
# The words and formats that say an argument names a file to open: a path,
# or a name made only of the words a file is called by (``file``,
# ``local_file``, ``sample``).
_PATH_WORDS = frozenset({"path", "paths", "filepath", "filepaths", "filename", "pathname"})
_PATH_FORMATS = frozenset({"path", "file-path", "filepath", "uri-reference"})
_FILE_WORDS = frozenset({"file", "files", "sample", "samples", "binary", "executable"})
_FILE_NAME_WORDS = _FILE_WORDS | frozenset({"local", "input", "target", "the", "to", "scan"})
# The words of an argument's name, beside ``id``, that say it names a
# submission or the work done on one.
_JOB_WORDS = frozenset(
    {"analysis", "submission", "task", "job", "request", "run", "operation", "receipt"}
)
# The words of a tool's name or description that say it hands something over.
_SUBMIT_WORDS = frozenset({"submit", "submits", "submitted", "upload", "uploads", "uploaded"})
# The words that say a tool submits or uploads itself, now: a name's verb, and
# a description's present tense (``uploads the file``, ``submit a hash``);
# never a past ``submitted``, which names what others did.
_SUBMIT_VERBS = frozenset({"submit", "upload"})
_SUBMIT_NOW_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:submit|submits|upload|uploads)(?![A-Za-z0-9])", re.IGNORECASE
)
_SUBMIT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?:submit|submits|submitted|upload|uploads|uploaded)(?![A-Za-z0-9])",
    re.IGNORECASE,
)
# How deep into nested objects an input schema's arguments are read, how many
# of them at most, and how many local references one argument's schema may
# follow.
_NESTED_DEPTH = 2
_MAX_ARGUMENTS = 512
_MAX_REFERENCES = 32
# The members of a schema that are each a schema the argument may take.
_ALTERNATIVES = ("anyOf", "oneOf", "allOf")


def _get(definition: Any, key: str) -> Any:
    if isinstance(definition, Mapping):
        return definition.get(key)
    return getattr(definition, key, None)


def _plain(value: Any) -> Mapping[str, Any]:
    """An MCP ``ToolAnnotations`` (or a mapping of it) as a mapping; empty for anything else."""
    if isinstance(value, Mapping):
        return value
    dump = getattr(value, "model_dump", None)
    if callable(dump):
        try:
            held = dump(by_alias=True)
        except Exception:  # noqa: BLE001 — a hint sent oddly says nothing
            return {}
        return held if isinstance(held, Mapping) else {}
    return {}


def _tokens(name: str) -> frozenset[str]:
    """A name's words: split at ``_``, ``-`` and spaces, camelCase split, lowercased."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)
    return frozenset(part for part in re.split(r"[_\-\s]+", spaced.lower()) if part)


def _declares_itself(definition: Any) -> bool:
    """Whether the definition declares the tool under its ``_meta``."""
    from maljan.tools.declared_facts import FACTS_META_KEY

    meta = _get(definition, "_meta")
    if meta is None:
        meta = _get(definition, "meta")
    return isinstance(meta, Mapping) and meta.get(FACTS_META_KEY) is not None


def _properties(input_schema: Any) -> dict[str, Mapping[str, Any]]:
    """The top-level arguments of an input schema, by name, in its order."""
    props = input_schema.get("properties") if isinstance(input_schema, Mapping) else None
    if not isinstance(props, Mapping):
        return {}
    return {str(name): prop for name, prop in props.items() if isinstance(prop, Mapping)}


def _resolved(root: Any, schema: Any, seen: set[str]) -> Mapping[str, Any] | None:
    """``schema`` with a local ``$ref`` (``#/$defs/…``, ``#/definitions/…``) followed in ``root``.

    ``None`` for a reference that is not local, does not resolve, or was
    followed already for this argument (a cycle), and past
    :data:`_MAX_REFERENCES` references.
    """
    held = schema
    while isinstance(held, Mapping) and isinstance(held.get("$ref"), str):
        ref = str(held["$ref"])
        if ref in seen or len(seen) >= _MAX_REFERENCES or not ref.startswith("#/"):
            return None
        seen.add(ref)
        node: Any = root
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            node = node.get(part) if isinstance(node, Mapping) else None
        held = node
    return held if isinstance(held, Mapping) else None


def _forms(root: Any, schema: Any, seen: set[str]) -> list[Mapping[str, Any]]:
    """Every schema an argument may take: itself, its alternatives and its items, resolved."""
    out: list[Mapping[str, Any]] = []
    stack = [schema]
    while stack and len(out) < _MAX_ARGUMENTS:
        held = _resolved(root, stack.pop(), seen)
        if held is None:
            continue
        out.append(held)
        for key in _ALTERNATIVES:
            members = held.get(key)
            if isinstance(members, list):
                stack.extend(m for m in members if isinstance(m, Mapping))
        items = held.get("items")
        if isinstance(items, Mapping):
            stack.append(items)
    return out


def _all_properties(input_schema: Any) -> list[tuple[str, Mapping[str, Any]]]:
    """Every argument, by its name and each schema it may take, at most :data:`_MAX_ARGUMENTS`.

    Local references are followed from the root schema, each argument's at
    most once (a cycle ends there); ``anyOf``, ``oneOf`` and ``allOf`` members
    and array items are read as the argument's own schemas; nested objects'
    arguments are read to :data:`_NESTED_DEPTH`.
    """
    root = input_schema
    out: list[tuple[str, Mapping[str, Any]]] = []
    level: list[Any] = [input_schema]
    for _depth in range(_NESTED_DEPTH):
        below: list[Any] = []
        for schema in level:
            for form in _forms(root, schema, set()):
                for name, prop in _properties(form).items():
                    for held in _forms(root, prop, set()):
                        if len(out) >= _MAX_ARGUMENTS:
                            return out
                        out.append((name, held))
                        below.append(held)
        level = below
    return out


def _takes_content(name: str, prop: Mapping[str, Any]) -> bool:
    """Whether an argument takes the file's content: the one rule, for every reading.

    Its schema's ``format`` or ``contentEncoding`` says bytes; or its name is
    named for content (or data or a body beside a file's word), unless its
    schema types it a number or a flag, which cannot carry the file
    (``max_scan_bytes``).
    """
    if any(
        isinstance(prop.get(key), str) and str(prop.get(key)).lower() in _CONTENT_FORMATS
        for key in ("format", "contentEncoding")
    ):
        return True
    if str(prop.get("type") or "").lower() in _NOT_CONTENT_TYPES:
        return False
    tokens = _tokens(name)
    if tokens & _CONTENT_WORDS:
        return True
    return bool(tokens & _CONTENT_WITH_A_FILE_WORDS and tokens & _FILE_WORDS)


def takes_content(arguments: Iterable[tuple[str, Mapping[str, Any]]]) -> bool:
    """Whether any of ``arguments`` (name, schema) takes the file's content."""
    return any(_takes_content(name, prop) for name, prop in arguments)


def _is_hash(name: str) -> bool:
    lowered = name.lower()
    return bool(_tokens(name) & _HASH_WORDS) or any(a in lowered for a in ("sha256", "sha1", "md5"))


def _takes_path(name: str, prop: Mapping[str, Any]) -> bool:
    """Whether an argument names a file to open: a path's word or format wins over a hash's."""
    tokens = _tokens(name)
    fmt = str(prop.get("format") or "").lower()
    if tokens & _PATH_WORDS or fmt in _PATH_FORMATS:
        return True
    if _is_hash(name):
        return False
    return bool(tokens & _FILE_WORDS) and tokens <= _FILE_NAME_WORDS


def _roles(input_schema: Any) -> tuple[dict[str, str], tuple[str, ...]]:
    """Each indicator role an argument is read as, ``{role: argument}``, and those required.

    The first argument of each role, a required one before an optional one;
    an argument is read as one role at most, the hash first.
    """
    props = _properties(input_schema)
    raw = input_schema.get("required") if isinstance(input_schema, Mapping) else None
    required = tuple(n for n in (raw if isinstance(raw, list) else []) if isinstance(n, str))
    found: dict[str, str] = {}
    for name in sorted(props, key=lambda n: n not in required):
        if _is_hash(name) and not _takes_path(name, props[name]):
            found.setdefault(HASH_ARGUMENT, name)
            continue
        tokens = _tokens(name)
        fmt = str(props[name].get("format") or "").lower()
        for role, (words, formats) in INDICATOR_ROLE_WORDS.items():
            if tokens & words or fmt in formats:
                found.setdefault(role, name)
                break
    return found, required


def _job_id(props: Mapping[str, Mapping[str, Any]]) -> str:
    """The argument that names a submission or its work by an id; ``""`` for none."""
    for name in props:
        tokens = _tokens(name)
        if "id" in tokens and tokens & _JOB_WORDS:
            return name
    return ""


@dataclass(frozen=True)
class _Listed:
    """What one listed tool's definition says, read once: its hints, arguments and words."""

    name: str
    hints: Mapping[str, Any]
    arguments: tuple[tuple[str, Mapping[str, Any]], ...]
    props: Mapping[str, Mapping[str, Any]]
    roles: Mapping[str, str]
    required: tuple[str, ...]
    says_submit: bool
    says_it_submits_now: bool
    declares_itself: bool

    @property
    def read_only(self) -> bool:
        return self.hints.get("readOnlyHint") is True

    @property
    def closed(self) -> bool:
        return self.hints.get("openWorldHint") is False


def _listed(definition: Any) -> _Listed:
    """One definition read once (each argument's schema forms walked one time)."""
    name = str(_get(definition, "name") or "")
    description = _get(definition, "description")
    text = description if isinstance(description, str) else ""
    words = _tokens(name)
    input_schema = _get(definition, "inputSchema")
    roles, required = _roles(input_schema)
    return _Listed(
        name=name,
        hints=_plain(_get(definition, "annotations")),
        arguments=tuple(_all_properties(input_schema)),
        props=_properties(input_schema),
        roles=roles,
        required=required,
        says_submit=bool(words & _SUBMIT_WORDS or _SUBMIT_RE.search(text)),
        says_it_submits_now=bool(words & _SUBMIT_VERBS or _SUBMIT_NOW_RE.search(text)),
        declares_itself=_declares_itself(definition),
    )


def _discloses(tool: _Listed, *, trusted: bool = False) -> bool:
    if not tool.read_only and tool.says_it_submits_now:
        return True
    if any(_takes_content(name, prop) for name, prop in tool.arguments) and not (
        trusted and tool.read_only and tool.closed and not tool.says_submit
    ):
        return True
    if any(_takes_path(name, prop) for name, prop in tool.arguments):
        return not tool.closed or tool.says_submit
    return False


def discloses(definition: Any, *, trusted: bool = False) -> bool:
    """Whether a listed tool is read as sending the sample's file out (``discloses_sample``).

    It takes the file's content as bytes, unless its server is trusted
    (``trusted``: the block trusts what the server declares) and marks it
    both read-only and closed: an untrusted server's own hints never lift
    the reading of bytes it takes; or it takes a path or a file, unless it
    is marked closed. A tool that says it submits or uploads and takes
    either always does, whatever its hints. One that is not marked read-only
    and says it submits or uploads now (its name's words ``submit`` or
    ``upload``, or its description's ``submit``, ``submits``, ``upload`` or
    ``uploads``; never a past ``submitted`` or ``uploaded``, which names what
    others did) does whatever it takes, since it may hand over the sample by
    an id or a hash the rule cannot see. Read-only alone never excuses
    sending: it says the tool changes nothing, not that it sends nothing.
    """
    return _discloses(_listed(definition), trusted=trusted)


def _writes(hints: Mapping[str, Any]) -> bool:
    """Whether a tool is a write tool: not marked read-only, or marked destructive."""
    return hints.get("readOnlyHint") is not True or hints.get("destructiveHint") is True


def _service(tool: _Listed, *, trusted: bool = False) -> dict[str, Any]:
    network: dict[str, Any] = {} if tool.hints.get("openWorldHint") is False else {"network": True}
    if _discloses(tool, trusted=trusted):
        return {
            "kind": SUBMISSION,
            "discloses_sample": True,
            "effects": {"executes": EXECUTES_SANDBOX, **network},
        }
    if _writes(tool.hints):
        return {"kind": SUBMISSION, **({"effects": network} if network else {})}
    hash_argument = tool.roles.get(HASH_ARGUMENT, "")
    if _job_id(tool.props) and hash_argument not in tool.required:
        return {
            "kind": SUBMISSION_STATUS,
            "effects": {"executes": EXECUTES_NO, **network, "third_party": THIRD_PARTY_HASH},
        }
    if hash_argument and hash_argument in tool.required:
        return {
            "kind": REPUTATION,
            "arguments": {HASH_ARGUMENT: hash_argument},
            "reader": SHAPE_READER,
            **DERIVED_SHOWS,
            "effects": {"executes": EXECUTES_NO, **network, "third_party": THIRD_PARTY_HASH},
        }
    roles = tool.roles
    if any(roles[role] in tool.required for role in NETWORK_INDICATOR_ARGUMENTS if role in roles):
        return {
            "kind": INDICATOR_REPORT,
            "effects": {"executes": EXECUTES_NO, **network, "third_party": THIRD_PARTY_NO},
        }
    return {}


def service_facts(definition: Any, *, trusted: bool = False) -> dict[str, Any]:
    """What a reputation service's listed tool is read as: its kind, argument and effects.

    Empty for a tool none of the readings fits. Read only for a block whose
    ``roles`` hold ``reputation`` (:func:`lay_under`); ``trusted`` as
    :func:`discloses` reads it.
    """
    return _service(_listed(definition), trusted=trusted)


def _facts(tool: _Listed, *, trusted: bool = False) -> ToolFacts | None:
    held = {} if tool.declares_itself else _service(tool, trusted=trusted)
    if not held and _discloses(tool, trusted=trusted):
        held = {"discloses_sample": True}
    return ToolFacts.model_validate(held) if held else None


def derived_facts_of(definition: Any, *, trusted: bool = False) -> ToolFacts | None:
    """Everything read of one listed tool, as a declaration; ``None`` for nothing read.

    The disclosure reading always; the reputation service's reading only for
    a tool its server does not declare under ``_meta``. :func:`lay_under`
    keeps of it what the block lets it read.
    """
    return _facts(_listed(definition), trusted=trusted)


def derived_readings(
    definitions: Iterable[Any], where: str = ""
) -> tuple[dict[str, ToolFacts], dict[str, ToolFacts]]:
    """What is read of every tool of a listing, and what of it a trusted server's hints lift.

    The first map is the reading of every tool, by the name it is listed
    under; the second, for each tool whose disclosure only its server's own
    hints could lift (bytes it takes, marked read-only and closed), the
    reading a block that trusts its server keeps instead (empty for nothing
    read). Each definition is read once. A definition whose name no tool can
    have, and one nothing is read of, are left out; one that cannot be read
    is read as sending the sample (``discloses_sample``), with a warning.
    """
    out: dict[str, ToolFacts] = {}
    lifted: dict[str, ToolFacts] = {}
    for definition in definitions:
        name = str(_get(definition, "name") or "")
        try:
            check_tool_name(name)
        except ValueError:
            continue
        try:
            tool = _listed(definition)
            facts = _facts(tool)
            if _discloses(tool) and not _discloses(tool, trusted=True):
                lifted[name] = _facts(tool, trusted=True) or ToolFacts()
        except Exception as exc:  # noqa: BLE001 — one odd definition is read cautiously
            logger.warning(
                "Tool %s%s was not read (%s); it is read as sending the sample.",
                where,
                name,
                type(exc).__name__,
            )
            facts = ToolFacts(discloses_sample=True)
            lifted.pop(name, None)
        if facts is not None:
            out[name] = facts
    return out, lifted


def derived_tool_facts(definitions: Iterable[Any], where: str = "") -> dict[str, ToolFacts]:
    """What is read of every tool of a listing, by its listed name (:func:`derived_readings`)."""
    return derived_readings(definitions, where)[0]


def program_readings_of(definitions: Iterable[Any], where: str = "") -> dict[str, ToolFacts]:
    """What every tool of a listing is read as on a program-analysis server, by its listed name.

    ``core.program_reading``, for every tool its server does not declare
    under ``_meta``; a tool that says it submits, uploads or sends now and
    takes a path or the file's content is read as sending its bytes, whatever
    its server's hints say. A definition whose name
    no tool can have is left out; one that cannot be read is left out, with
    a warning (its disclosure is read by :func:`derived_readings`).
    """
    from maljan.core.program_reading import program_facts

    held: list[tuple[str, Any]] = []
    for definition in definitions:
        name = str(_get(definition, "name") or "")
        try:
            check_tool_name(name)
        except ValueError:
            continue
        held.append((name, definition))
    names = [name for name, _definition in held]
    out: dict[str, ToolFacts] = {}
    for name, definition in held:
        try:
            tool = _listed(definition)
            if tool.declares_itself:
                continue
            # As the disclosure reading has it: a tool that says it submits,
            # uploads or sends now discloses unless it is marked read-only,
            # and whatever its hints say when it takes a path, the file's
            # content, an id or a hash (``discloses``).
            says = tool.says_it_submits_now or _says_it_sends(definition)
            # The file's content, read by the one rule the disclosure reads it
            # by, every schema form and nested object included: it is sent.
            content = takes_content(tool.arguments)
            sends = says and (
                not tool.read_only
                or any(
                    _takes_path(n, p) or _takes_content(n, p) or _is_hash(n) or _names_an_id(n)
                    for n, p in tool.arguments
                )
            )
            facts = program_facts(definition, names, sends=sends or content)
        except Exception as exc:  # noqa: BLE001 — one odd definition costs its own reading
            logger.warning(
                "Tool %s%s was not read as a program tool (%s).", where, name, type(exc).__name__
            )
            continue
        if facts is not None:
            out[name] = facts
    return out


def closed_by_hints(definitions: Iterable[Any]) -> dict[str, ToolFacts]:
    """The tools of a listing whose disclosure only their server's own hints could lift.

    Each takes the file's content as bytes and is marked read-only and
    closed: read as sending it from any server, and from one its block trusts
    read as the reading given here (:func:`lay_under`).
    """
    return derived_readings(definitions)[1]


def _set(facts: ToolFacts) -> dict[str, Any]:
    from maljan.core.served_declarations import _set_fields

    return _set_fields(facts)


def _says_what_it_sends(facts: ToolFacts | None) -> bool:
    """Whether a declaration says what its tool sends: ``discloses_sample`` or its third party."""
    if facts is None:
        return False
    fields = _set(facts)
    effects = fields.get("effects")
    return "discloses_sample" in fields or (
        isinstance(effects, Mapping) and "third_party" in effects
    )


def _said_of_reputation(*declared: ToolFacts | None) -> dict[str, Any]:
    """The ``reputation`` fields the first declaration holding one sets, and no default.

    A declaration merged field by field holds its ``reputation`` whole, every
    field marked set; what it said is read from the declaration it came from.
    """
    for facts in declared:
        rep = facts.reputation if facts is not None else None
        if rep is not None:
            own = set(rep.model_fields_set) & set(rep.model_dump(exclude_defaults=True))
            own |= {"rank"} & set(rep.model_fields_set)
            return rep.model_dump(mode="json", include=own)
    return {}


def _with_service(
    facts: ToolFacts, service: Any, said: Mapping[str, Any] | None = None
) -> ToolFacts:
    """A lookup with what its block says of the service as a whole laid under it.

    The service's name as its display name and the service its answers are
    attributed to, and its rank, each only where the lookup's declaration
    says none (``said``: the ``reputation`` fields it sets): a declared
    ``reputation`` block keeps every field it sets.
    """
    if service is None:
        return facts
    name = str(getattr(service, "name", "") or "")
    rank = getattr(service, "rank", None)
    held = _set(facts)
    said = dict(said if said is not None else _said_of_reputation(facts))
    if name and not held.get("display_name") and not said.get("service"):
        held["display_name"] = name
        said["service"] = name
    if rank is not None and "rank" not in said:
        said["rank"] = rank
    if said:
        held["reputation"] = said
    try:
        return ToolFacts.model_validate(held)
    except ValueError:
        # A reading the service's name or rank cannot join is kept as read.
        return facts


def lay_under(
    tools: Mapping[str, ToolFacts],
    derived: Mapping[str, ToolFacts],
    removed: Iterable[str] = (),
    *,
    roles: Iterable[str] = (),
    own: Mapping[str, ToolFacts] | None = None,
    trusted_server: Iterable[str] = (),
    service: Any = None,
    closed: Mapping[str, ToolFacts] | None = None,
    kind_free: Mapping[str, Mapping[str, Any]] | None = None,
    program: Mapping[str, ToolFacts] | None = None,
    default_effects: Any = None,
    sample_open: Any = None,
) -> dict[str, ToolFacts]:
    """``tools`` with what was read of each listed tool laid under, field by field.

    ``tools`` are the tools in force (the block's, with its server's
    declaration laid under); ``own`` the block's own (an operator's
    declaration, what the platform ships), ``tools`` where not given;
    ``trusted_server`` the tools a server the block trusts declares itself.
    For a block whose ``roles`` hold ``reputation``, all of the reading, with
    ``service`` (``reputation_service``) under each lookup; for any other, the
    disclosure reading alone. A tool in ``removed`` stays out. The disclosure
    reading is dropped only for a tool ``own`` says what it sends of, or one a
    trusted server declares; a tool of ``closed`` (:func:`closed_by_hints`,
    given only for a block that trusts its server) is read as given there.
    Whatever else is in force is over the reading. ``kind_free`` are the
    kind-dependent fields the block stored for a tool with no kind of its own
    (``tool_declarations.kind_free_changes``): laid over the reading once it
    puts a kind in force, a ``reputation`` change field by field.

    For a block whose ``roles`` hold a program role
    (``program_reading.PROGRAM_ROLES``), ``program`` is what each listed tool
    is read as on a program-analysis server, laid under the rest of the
    reading (:func:`_in_block`: the tools its ``sample_open`` names are read
    as opening, selecting, analysing and closing a program, and a read is
    read-only only where the block allows it). Where the block says what its
    tools send as a whole (``default_effects`` with a ``third_party``), the
    disclosure reading is dropped as for a tool the block declares, but for
    a tool the reading says sends the file's bytes by itself.
    """
    from maljan.core.program_reading import PROGRAM_ROLES
    from maljan.core.reputation import is_lookup
    from maljan.core.served_declarations import _over

    gone = set(removed)
    vouched = set(trusted_server)
    lifted = dict(closed or {})
    block = tools if own is None else own
    is_service = REPUTATION_ROLE in set(roles)
    programs = dict(program or {}) if PROGRAM_ROLES & set(roles) else {}
    says_for_all = bool(getattr(default_effects, "third_party", ""))
    out = dict(tools)
    for tool in dict.fromkeys([*derived, *programs, *(program or {})]):
        if tool in gone:
            # A removal takes what the block says of the tool away, never that
            # it sends the sample: that reading stays, and nothing else.
            sending = _still_sends(derived.get(tool), (program or {}).get(tool))
            if sending is not None:
                out[tool] = sending
            continue
        if tool not in derived and tool not in programs:
            continue
        facts = lifted.get(tool, derived.get(tool))
        reading: ToolFacts | None = facts
        if facts is not None and (not is_service or tool in vouched):
            reading = ToolFacts(discloses_sample=True) if facts.discloses_sample else None
        as_program = programs.get(tool)
        if as_program is not None and tool not in vouched:
            as_program = _in_block(as_program, tool, default_effects, sample_open)
            reading = as_program if reading is None else _over(reading, as_program)
        if (
            reading is not None
            and reading.discloses_sample
            and (
                tool in vouched
                or _says_what_it_sends(block.get(tool))
                or (says_for_all and _stays_local(as_program))
            )
        ):
            kept = {k: v for k, v in _set(reading).items() if k != "discloses_sample"}
            reading = ToolFacts.model_validate(kept) if kept else None
        if reading is None or not _set(reading):
            continue
        held = out.get(tool)
        if held is not None and reading.reader and _says_how_to_read(held):
            # A lookup whose declaration says where its answer holds its
            # facts, or names its reader, is read as declared.
            kept = {k: v for k, v in _set(reading).items() if k != "reader"}
            reading = ToolFacts.model_validate(kept) if kept else None
            if reading is None:
                continue
        merged = reading if held is None else _over(held, reading)
        said = _said_of_reputation(block.get(tool), reading)
        stored = (kind_free or {}).get(tool)
        if stored and merged.kind:
            merged, said = _with_kind_free(merged, said, stored)
        if is_service and tool not in vouched and is_lookup(merged):
            # What the block itself said of the lookup's reputation, never the
            # merged facts: a merge marks every field of it as said.
            merged = _with_service(merged, service, said)
        out[tool] = merged
    return out


# What a tool's name or description says when it sends something away now.
_SENDS_RE = re.compile(r"(?<![A-Za-z0-9])(?:send|sends)(?![A-Za-z0-9])", re.IGNORECASE)


def _names_an_id(name: str) -> bool:
    """Whether an argument's name says it takes an id (``task_id``, ``id``)."""
    return "id" in _tokens(name)


def _says_it_sends(definition: Any) -> bool:
    """Whether a tool's name or description says it sends something away now."""
    name = str(_get(definition, "name") or "")
    description = _get(definition, "description")
    text = description if isinstance(description, str) else ""
    return bool(_tokens(name) & {"send", "sends"} or _SENDS_RE.search(text))


def _stays_local(facts: ToolFacts | None) -> bool:
    """Whether a program reading lets the block's statement lift its path reading.

    Only a path the tool opens or reads where it runs: a tool read as sending
    the file's bytes by itself (its content as bytes, or it says it submits,
    uploads or sends) never, nor one of a kind that says nothing of what it
    does with the file (``utility``) or runs what it is given (``run``).
    """
    from maljan.core.program_reading import OTHER_KIND, RUN_KIND

    if facts is None or _sends_by_itself(facts):
        return False
    if facts.effects is not None and facts.effects.why_undeclared:
        # It runs what it is given: what it does with the file is not known.
        return False
    return facts.kind not in (OTHER_KIND, RUN_KIND)


def _still_sends(*readings: ToolFacts | None) -> ToolFacts | None:
    """What a removed tool is still read as: sending the sample's bytes, where a reading says so."""
    if not any(r is not None and (r.discloses_sample or _sends_by_itself(r)) for r in readings):
        return None
    return ToolFacts.model_validate(
        {"discloses_sample": True, "effects": {"network": True, "third_party": THIRD_PARTY_BYTES}}
    )


def _sends_by_itself(facts: ToolFacts | None) -> bool:
    """Whether a program reading says its tool sends the file's bytes by itself."""
    effects = facts.effects if facts is not None else None
    return effects is not None and effects.third_party == THIRD_PARTY_BYTES


# The kind each tool a block's ``sample_open`` names is read as.
_SAMPLE_OPEN_KINDS: tuple[tuple[str, str], ...] = (
    ("open_tool", "open_sample"),
    ("select_tool", "select_sample"),
    ("analyse_tool", "analyse_sample"),
    ("close_tool", "sample_close"),
)


def closes_the_world(effects: Any) -> bool:
    """Whether a block's ``default_effects`` say its tools run nothing and reach no network."""
    return (
        effects is not None
        and getattr(effects, "executes", "") == EXECUTES_NO
        and getattr(effects, "network", None) is False
    )


def program_arguments(sample_open: Any) -> frozenset[str]:
    """The arguments a block's ``sample_open`` says a program is named by; empty for none."""
    if sample_open is None:
        return frozenset()
    named = [
        str(getattr(sample_open, "select_argument", "") or ""),
        str(getattr(sample_open, "analyse_argument", "") or ""),
        *(str(a) for a in getattr(sample_open, "program_arguments", None) or ()),
    ]
    return frozenset(a for a in named if a)


def _in_block(facts: ToolFacts, tool: str, default_effects: Any, sample_open: Any) -> ToolFacts:
    """A program reading as the block reads it: its ``sample_open`` tools, its read-only rule.

    A tool the block's ``sample_open`` names to open, select, analyse or close
    a program is read as that. A read is read-only only where the block's
    ``default_effects`` say its tools run nothing and reach no network, and,
    where its ``sample_open`` names the arguments a program is named by
    (:func:`program_arguments`), the tool takes one: a tool of such a server
    that names no program reads what every job shares (the programs open on
    it, its scripts, its project), which another job may change.
    """
    held = _set(facts)
    for field_name, kind in _SAMPLE_OPEN_KINDS:
        if tool and str(getattr(sample_open, field_name, "") or "") == tool:
            held["kind"] = kind
            held.pop("read_only", None)
            from maljan.core.program_reading import RUNS_UNSAID

            if held.get("effects") == RUNS_UNSAID:
                # The block's own step, not whatever a caller hands a ``run``
                # verb; a tool that takes code to run keeps saying so.
                held.pop("effects", None)
            break
    if held.get("read_only"):
        named = program_arguments(sample_open)
        program = str((held.get("arguments") or {}).get("program") or "")
        if not closes_the_world(default_effects) or (named and program not in named):
            held.pop("read_only", None)
    try:
        return ToolFacts.model_validate(held)
    except ValueError:
        return facts


def with_server_effects(
    tools: Mapping[str, ToolFacts],
    default_effects: Any = None,
    analyse_effects: Any = None,
    sample_open: Any = None,
    *,
    listed: Iterable[str] | None = None,
) -> dict[str, ToolFacts]:
    """``tools`` with what the block says of its tools as a whole laid under each one's effects.

    With ``listed``, only under the tools its server listed: a tool nothing
    has listed has not said whether it does otherwise.

    ``default_effects`` under every tool's own ``effects``, sub-field by
    sub-field, so a tool that says otherwise (it emulates, it sends the
    file's bytes) keeps what it says; ``analyse_effects`` over them for the
    tool the block's ``sample_open`` names to analyse. A tool whose effects
    say they cannot be declared (``why_undeclared``: it runs whatever it is
    given) takes none of it, and a tool read as sending the sample sends its
    bytes whatever the statement says.
    """
    if default_effects is None and analyse_effects is None:
        return dict(tools)
    analyse = str(getattr(sample_open, "analyse_tool", "") or "")
    base = _effects_set(default_effects)
    out: dict[str, ToolFacts] = {}
    seen = None if listed is None else set(listed)
    for name, facts in tools.items():
        own = _effects_set(facts.effects)
        if own.get("why_undeclared") or (seen is not None and name not in seen):
            out[name] = facts
            continue
        under = dict(base)
        if name == analyse and analyse_effects is not None:
            under.update(_effects_set(analyse_effects))
        if not under:
            out[name] = facts
            continue
        held = _set(facts)
        held["effects"] = {**under, **own}
        try:
            merged = ToolFacts.model_validate(held)
        except ValueError:
            out[name] = facts
            continue
        if merged.discloses_sample and merged.effects is not None:
            merged = merged.model_copy(update={"effects": merged.effects.with_bytes_sent()})
        out[name] = merged
    return out


def _effects_set(effects: Any) -> dict[str, Any]:
    """The sub-fields an effects statement sets."""
    if effects is None:
        return {}
    own = set(effects.model_fields_set)
    own.update(effects.model_dump(exclude_defaults=True))
    return dict(effects.model_dump(mode="json", include=own))


def _with_kind_free(
    facts: ToolFacts, said: Mapping[str, Any], stored: Mapping[str, Any]
) -> tuple[ToolFacts, dict[str, Any]]:
    """``facts`` with the block's kind-free change laid over, and its ``reputation`` said.

    A ``reputation`` change is merged into what was said of it field by
    field; any other field replaces the reading's. A change the model refuses
    over this kind leaves ``facts`` as they were.
    """
    held = _set(facts)
    now = dict(said)
    for name, value in stored.items():
        if name == "reputation" and isinstance(value, Mapping):
            now.update(value)
            held["reputation"] = dict(now)
        else:
            held[name] = value
    if held.get("reputation") and "reader" in held and declares_paths_of(held["reputation"]):
        # A change that names where the answer holds its facts is read by them.
        held.pop("reader")
    if (held.get("places") or held.get("values")) and not held.get("rows"):
        # A change of where a row's facts sit, over a kind whose reading names
        # no rows, is read inside the rows its kind's own reader reads
        # (``declared_reading.reader_reference_facts``), as the change was made.
        from maljan.core.declared_reading import reader_reference_facts

        reference = reader_reference_facts(str(held.get("kind") or ""))
        if reference is not None and reference.rows:
            held["rows"] = reference.rows
            for part in ("places", "values"):
                if not held.get(part) and getattr(reference, part):
                    held[part] = dict(getattr(reference, part))
    try:
        return ToolFacts.model_validate(held), now
    except ValueError:
        return facts, dict(said)


def declares_paths_of(raw: Mapping[str, Any]) -> bool:
    """Whether a ``reputation`` mapping names a path or a pattern."""
    from maljan.core.reputation import declares_paths
    from maljan.core.tool_declarations import ReputationFacts

    try:
        return declares_paths(ReputationFacts.model_validate(dict(raw)))
    except ValueError:
        return False


def _says_how_to_read(facts: ToolFacts) -> bool:
    """Whether a declaration says how its answer is read: a path or pattern, or a reader."""
    from maljan.core.reputation import declares_paths

    return declares_paths(facts.reputation) or "reader" in _set(facts)
