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
  ``contentEncoding``, nested objects at any depth included (a schema too
  large to read whole, or with a reference that cannot be followed, is read
  as taking a path or the file's content wherever what was left unread
  could);
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
  requires an indicator a report on it (``indicator_report``, with the
  argument it requires each indicator in: ``domain``, ``ip``, ``url``). Each says what
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

import itertools
import re
import unicodedata
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any
from urllib.parse import unquote

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
# How many of an input schema's schemas are read at most (nested objects at any
# depth), how many may wait to be read, and how many local references one
# argument's schema may follow.
_MAX_ARGUMENTS = 512
_MAX_REFERENCES = 32
# The members of a schema that are each a schema the argument may take: lists
# of them, single ones, and the map of them ``dependentSchemas`` holds.
_ALTERNATIVES = ("anyOf", "oneOf", "allOf")
_SAME_ARGUMENT_LISTS = (*_ALTERNATIVES, "prefixItems")
_SAME_ARGUMENT_ONES = ("additionalItems", "contains", "if", "then", "else", "unevaluatedItems")
# The members of an object schema that are schemas of the arguments it takes
# under names it does not list.
_UNLISTED_ARGUMENTS = ("additionalProperties", "unevaluatedProperties")
# Every member that holds a schema or a map of them.
_HOLDERS = (
    *_SAME_ARGUMENT_ONES,
    *_UNLISTED_ARGUMENTS,
    "properties",
    "patternProperties",
    "dependentSchemas",
    "dependencies",
)
# The keywords that may hold a mapping or a flag and are read, or say nothing
# of what an argument takes (annotations, a flag on a value's range, the
# definitions references name, what an argument is not); a vendor's ``x-``
# keywords are annotations too.
_KNOWN_KEYWORDS = frozenset(
    {
        *_HOLDERS,
        *_SAME_ARGUMENT_LISTS,
        "items",
        "not",
        "title",
        "description",
        "default",
        "examples",
        "example",
        "const",
        "enum",
        "format",
        "contentEncoding",
        "contentMediaType",
        "$comment",
        "deprecated",
        "readOnly",
        "writeOnly",
        "nullable",
        "uniqueItems",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "required",
        "dependentRequired",
        "$schema",
        "$id",
        "$anchor",
        "$dynamicAnchor",
        "$vocabulary",
        "$defs",
        "definitions",
    }
)
# A reference's keys. A ``$dynamicRef`` is resolved by the scope it is
# evaluated in, which a listing does not show, so it is never followed.
_REF = "$ref"
_DYNAMIC_REF = "$dynamicRef"
# A ``patternProperties`` pattern that names one argument (``^path$``).
_LITERAL_PATTERN = re.compile(r"\^(\w+)\$")
# The types that hold no path and no bytes.
_NO_FILE_TYPES = frozenset({"integer", "number", "boolean", "null"})
# A ``true`` schema: any value.
_ANY: Mapping[str, Any] = MappingProxyType({})
# A schema a form holds: its argument's name, the schema (``None`` for a value
# that is no schema), whether it starts an argument, and whether that argument
# has no name of its own.
_Child = tuple[str | None, Mapping[str, Any] | None, bool, bool]


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
    """A name's words: NFKC-normalised (a full-width ``ｐａｔｈ`` is ``path``), split at
    ``_``, ``-`` and spaces, camelCase split, lowercased."""
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", unicodedata.normalize("NFKC", name))
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


def _foreign(name: str) -> bool:
    """Whether a name cannot be read as written, even NFKC-normalised (a Cyrillic ``a``).

    It holds a control, format or combining mark (Unicode categories ``C*``
    and ``M*``: a zero-width joiner hides between the letters of ``path``),
    or any character outside ASCII; either way it could name a path or the
    file's content in a look-alike spelling.
    """
    normal = unicodedata.normalize("NFKC", name)
    return any(ord(c) > 127 or unicodedata.category(c)[0] in "CM" for c in normal)


class _Unresolved(Exception):
    """A reference that is not local, names nothing in the schema that holds it, or an
    ambiguous anchor."""


def _resource(schema: Mapping[str, Any], root: Any) -> bool:
    """Whether a schema below the root is an embedded resource (its own ``$id``, no fragment)."""
    own = schema.get("$id")
    return schema is not root and isinstance(own, str) and not own.startswith("#")


class _References:
    """One schema's local references, each looked up once: ``#``, a JSON pointer, an anchor."""

    def __init__(self, root: Any) -> None:
        self.root = root
        self.found: dict[str, tuple[Mapping[str, Any] | None, bool]] = {}
        self.anchors: dict[str, Any] | None = None
        self.ambiguous: set[str] = set()
        self.rests: dict[int, Mapping[str, Any] | None] = {}

    def target(self, ref: str) -> tuple[Mapping[str, Any], bool]:
        """The schema ``ref`` names, and whether it lies inside an embedded resource.

        :class:`_Unresolved` for none.
        """
        if ref not in self.found:
            held, inside = self._lookup(ref)
            self.found[ref] = (held if isinstance(held, Mapping) else None, inside)
        found, inside = self.found[ref]
        if found is None:
            raise _Unresolved
        return found, inside

    def rest(self, schema: Mapping[str, Any]) -> Mapping[str, Any] | None:
        """A schema's own keywords beside its references and its ``$id``; ``None`` for none.

        The walk carries the scope the ``$id`` opens beside it.
        """
        key = id(schema)
        if key not in self.rests:
            rest = {k: v for k, v in schema.items() if k not in (_REF, _DYNAMIC_REF, "$id")}
            self.rests[key] = rest or None
        return self.rests[key]

    def _lookup(self, ref: str) -> tuple[Any, bool]:
        if not ref.startswith("#"):
            return None, False
        pointer = unquote(ref[1:])
        if not pointer:
            return self.root, False
        if not pointer.startswith("/"):
            anchors = self._anchored()
            return (None if pointer in self.ambiguous else anchors.get(pointer)), False
        node: Any = self.root
        inside = False
        for part in pointer[1:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            # A step through a schema with an ``$id`` of its own enters that
            # resource; its own ``$id`` the walk reads where it lands.
            inside = inside or (isinstance(node, Mapping) and _resource(node, self.root))
            if isinstance(node, Mapping):
                node = node.get(part)
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                return None, inside
        return node, inside

    def _anchored(self) -> dict[str, Any]:
        """Every ``$anchor`` (and a draft-07 ``$id`` of ``#name``) in the schema, read once.

        An anchor defined more than once, or inside an embedded resource (a
        schema below the root with an ``$id`` of its own that is not a
        fragment), is :attr:`ambiguous`: which schema it names is not read.
        """
        if self.anchors is None:
            self.anchors = {}
            # (node, whether it is inside an embedded resource).
            stack: list[tuple[Any, bool]] = [(self.root, False)]
            while stack:
                node, embedded = stack.pop()
                if isinstance(node, Mapping):
                    own = node.get("$id")
                    if node is not self.root and isinstance(own, str) and not own.startswith("#"):
                        embedded = True
                    names = [node.get("$anchor")]
                    if isinstance(own, str) and own.startswith("#") and len(own) > 1:
                        names.append(own[1:])
                    for anchor in names:
                        if not isinstance(anchor, str):
                            continue
                        if embedded or anchor in self.anchors:
                            self.ambiguous.add(anchor)
                        self.anchors[anchor] = node
                    stack.extend((value, embedded) for value in node.values())
                elif isinstance(node, list):
                    stack.extend((value, embedded) for value in node)
        return self.anchors


def _nested(form: Mapping[str, Any]) -> bool:
    """Whether a schema holds further schemas: a reference, alternatives, items or arguments."""
    return (
        isinstance(form.get(_REF), str)
        or isinstance(form.get(_DYNAMIC_REF), str)
        or any(isinstance(form.get(key), list) for key in _SAME_ARGUMENT_LISTS)
        or isinstance(form.get("items"), (Mapping, list))
        or any(isinstance(form.get(key), Mapping) for key in _HOLDERS)
    )


def _could_carry(name: str | None, schema: Any) -> bool:
    """Whether a schema the walk left unread could take a path or the file's content.

    One that holds further schemas could; a leaf could as its argument's name
    and schema say (:func:`_takes_content`, :func:`_takes_path`), or where its
    name cannot be read as written (:func:`_foreign`); a leaf of the root
    schema itself is no argument.
    """
    if not isinstance(schema, Mapping):
        return False
    if _nested(schema):
        return True
    return name is not None and (
        _takes_content(name, schema) or _takes_path(name, schema) or _foreign(name)
    )


def _no_file(schema: Mapping[str, Any]) -> bool:
    """Whether a schema's own type says it holds no path and no bytes, and it holds nothing more."""
    held = schema.get("type")
    types = [held] if isinstance(held, str) else held if isinstance(held, list) else []
    return (
        bool(types)
        and all(isinstance(t, str) and t.lower() in _NO_FILE_TYPES for t in types)
        and not _nested(schema)
    )


def _member(value: Any) -> Mapping[str, Any] | None:
    """A schema as a mapping: ``true`` (any value) as an empty one; ``None`` for one that is not."""
    if isinstance(value, Mapping):
        return value
    return _ANY if value is True else None


def _names_beside(form: Mapping[str, Any]) -> Iterator[str]:
    """The argument names a form gives outside ``properties``.

    Each name ``required`` lists, each in a list ``dependentRequired`` or
    ``dependencies`` holds, and the ``const`` or ``enum`` names
    ``propertyNames`` allows.
    """
    lists: list[Any] = [form.get("required")]
    for key in ("dependentRequired", "dependencies"):
        held = form.get(key)
        if isinstance(held, Mapping):
            lists.extend(held.values())
    names = form.get("propertyNames")
    if isinstance(names, Mapping):
        lists.append([names.get("const")])
        lists.append(names.get("enum"))
    for held in lists:
        if isinstance(held, list):
            yield from (value for value in held if isinstance(value, str))


def _children(form: Mapping[str, Any], name: str | None) -> Iterator[_Child]:
    """The schemas a form holds, each with the argument it belongs to and how it is named.

    Its alternatives, items (``items``, ``prefixItems``, ``additionalItems``,
    ``contains``, ``unevaluatedItems``), conditional branches (``if``,
    ``then``, ``else``), ``dependentSchemas`` and the schemas of
    ``dependencies`` (never its lists of names) are the same argument's
    schemas; each of its ``properties`` is an argument of its own, and so is
    each of its ``patternProperties``, named by a pattern that is an anchored
    literal (``^path$``) and otherwise unnamed, as its
    ``additionalProperties`` and ``unevaluatedProperties`` are. ``not`` says
    what an argument is not, and is not read. A ``true`` schema is any value
    (an empty schema), a ``false`` one none; any other value where a schema
    belongs is yielded as ``None``, which the walk cannot read, and so is a
    mapping or a flag under a keyword not in :data:`_KNOWN_KEYWORDS` nor a
    vendor's ``x-`` one. The values of a free-form map
    (``additionalProperties`` or ``unevaluatedProperties`` of ``true`` or
    ``{}``) are read by their object's name instead. Each argument the form
    names only outside ``properties`` (:func:`_names_beside`) is one of its
    own, of any value.
    """

    def one(
        child_name: str | None, value: Any, starts: bool, unnamed: bool, free_form: bool = False
    ) -> Iterator[_Child]:
        if value is not False:
            member = _member(value)
            # The values of a free-form map (``additionalProperties`` or
            # ``unevaluatedProperties`` of ``true`` or ``{}``) are read by
            # their object's name. This is looser than a map typed
            # ``{"type": "string"}``, which fails closed: a ``dict[str, Any]``
            # argument is listed exactly so (pydantic), and an untyped map's
            # object name is what an operator reads; reading it as sending
            # would mark every such tool so. A pattern's values never are.
            yield child_name, member, starts, unnamed and not (free_form and member == {})

    props = form.get("properties")
    listed: Mapping[str, Any] = props if isinstance(props, Mapping) else {}

    for key in _SAME_ARGUMENT_LISTS:
        if key in form:
            members = form[key]
            if not isinstance(members, list):
                yield name, None, False, False
                continue
            for member in members:
                yield from one(name, member, False, False)
    if "items" in form:
        items = form["items"]
        for member in items if isinstance(items, list) else [items]:
            yield from one(name, member, False, False)
    for key in _SAME_ARGUMENT_ONES:
        if key in form:
            yield from one(name, form[key], False, False)
    for key in ("dependentSchemas", "dependencies", "properties", "patternProperties"):
        if key not in form:
            continue
        held = form[key]
        if not isinstance(held, Mapping):
            yield name, None, False, False
            continue
        for key_name, value in held.items():
            if key == "dependencies":
                # A list names the arguments one requires (read below).
                if not isinstance(value, list):
                    yield from one(name, value, False, False)
            elif key == "dependentSchemas":
                yield from one(name, value, False, False)
            elif key == "properties":
                yield from one(str(key_name), value, True, False)
            else:
                literal = _LITERAL_PATTERN.fullmatch(str(key_name))
                if literal:
                    yield from one(literal.group(1), value, True, False)
                else:
                    yield from one(name or "", value, True, True)
    for key in _UNLISTED_ARGUMENTS:
        if key in form:
            yield from one(name or "", form[key], True, True, free_form=True)
    # An argument named only where the form requires it, or where its names
    # are listed, takes any value under that name.
    for named in _names_beside(form):
        if named not in listed:
            yield named, _ANY, True, False
    # A keyword the walk does not know that holds a schema or a map of them
    # could hold an argument it cannot read.
    for key, value in form.items():
        if (
            isinstance(value, (Mapping, bool))
            and key not in _KNOWN_KEYWORDS
            and not str(key).startswith("x-")
        ):
            yield name, None, False, False


def _carries(child_name: str | None, child: Mapping[str, Any] | None, unnamed: bool) -> bool:
    """Whether a child schema left unread, or one the walk cannot read, could carry the file.

    One that is no schema could; an argument with no name of its own could,
    unless its own type says it holds no path and no bytes (:func:`_no_file`):
    there is no name for the name rules to clear it by.
    """
    if child is None:
        return True
    if unnamed and not _no_file(child):
        return True
    return _could_carry(child_name, child)


def _walk(input_schema: Any) -> tuple[list[tuple[str, Mapping[str, Any]]], bool]:
    """Every argument, by its name and each schema it may take, and whether the rest could carry.

    Nested objects are read at any depth (:func:`_children`). Local
    references (``#``, a JSON pointer, percent-escaped or not, an
    ``$anchor``) are followed from the root schema, each looked up once, and
    a reference's sibling keywords are read beside its target; each chain of
    references is at most :data:`_MAX_REFERENCES` long and follows each at
    most once (a cycle ends there). Each schema is read once for each
    argument it belongs to, and its own arguments are taken from it once, so
    the walk is linear in the schema's size; it reads at most
    :data:`_MAX_ARGUMENTS` schemas, with at most as many waiting.

    The second value says the reading fails closed: the walk stopped at a cap
    and something it left unread could take a path or the file's content
    (:func:`_could_carry`); or a reference could not be followed (not local,
    naming nothing, an ambiguous anchor, a ``$dynamicRef``, or one inside an
    embedded resource, which resolves against that resource's ``$id``; an
    argument's name is kept among the arguments, so the name rules still read
    it); or a value where a schema belongs is no schema; or an
    argument with no name of its own (:func:`_children`) has a schema whose
    type does not say it holds no path and no bytes (:func:`_carries`).
    """
    refs = _References(input_schema)
    out: list[tuple[str, Mapping[str, Any]]] = []
    # (argument name, schema, the references its chain followed so far,
    # whether it lies inside an embedded resource).
    waiting: list[tuple[str | None, Any, set[str], bool]] = [(None, input_schema, set(), False)]
    seen_forms: set[tuple[str | None, int]] = set()
    expanded: set[int] = set()
    read = 0
    unread = False

    def stopped(*rest: Iterable[tuple[str | None, Any]]) -> tuple[list[Any], bool]:
        left = itertools.chain(((n, s) for n, s, _chain, _in in waiting), *rest)
        return out, unread or any(_could_carry(n, s) for n, s in left)

    while waiting:
        if read >= _MAX_ARGUMENTS:
            return stopped()
        name, schema, chain, embedded = waiting.pop()
        if not isinstance(schema, Mapping):
            continue
        embedded = embedded or _resource(schema, input_schema)
        ref, dynamic = schema.get(_REF), schema.get(_DYNAMIC_REF)
        if isinstance(ref, str) or isinstance(dynamic, str):
            rest = refs.rest(schema)
            ahead: list[tuple[str | None, Any, set[str], bool]] = []
            if rest is not None:
                ahead.append((name, rest, set(chain), embedded))
            if isinstance(dynamic, str) or (isinstance(ref, str) and ref not in chain):
                # A reference resolved against an embedded resource's own
                # ``$id``, or by the scope it is evaluated in, is not read.
                try:
                    if isinstance(dynamic, str) or embedded:
                        raise _Unresolved
                    if len(chain) >= _MAX_REFERENCES:
                        unread = True
                    else:
                        chain.add(str(ref))
                        target, inside = refs.target(str(ref))
                        ahead.append((name, target, chain, inside))
                except _Unresolved:
                    read += 1
                    if name is not None:
                        out.append((name, rest or {}))
                    unread = True
            for at, item in enumerate(ahead):
                if len(waiting) >= _MAX_ARGUMENTS:
                    return stopped((n, s) for n, s, _chain, _in in ahead[at:])
                waiting.append(item)
            continue
        if (name, id(schema)) in seen_forms:
            continue
        seen_forms.add((name, id(schema)))
        read += 1
        if name is not None:
            out.append((name, schema))
        opens = id(schema) not in expanded
        expanded.add(id(schema))
        children = _children(schema, name)
        for child_name, child, starts, unnamed in children:
            if starts and not opens:
                continue
            if child is None or unnamed:
                unread = unread or _carries(child_name, child, unnamed)
                if child is None:
                    continue
            if len(waiting) >= _MAX_ARGUMENTS:
                rest_children = itertools.chain([(child_name, child, starts, unnamed)], children)
                return out, unread or any(
                    _carries(n, s, u) for n, s, st, u in rest_children if opens or not st
                ) or any(_could_carry(n, s) for n, s, _chain, _in in waiting)
            # A chain of references gets its own budget down each branch.
            waiting.append((child_name, child, set() if starts else set(chain), embedded))
    return out, unread


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
    # Whether the walk stopped at a cap with something unread that could take
    # a path or the file's content (``_walk``): the tool is read as sending.
    unread: bool
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
    arguments, unread = _walk(input_schema)
    return _Listed(
        name=name,
        hints=_plain(_get(definition, "annotations")),
        arguments=tuple(arguments),
        unread=unread,
        props=_properties(input_schema),
        roles=roles,
        required=required,
        says_submit=bool(words & _SUBMIT_WORDS or _SUBMIT_RE.search(text)),
        says_it_submits_now=bool(words & _SUBMIT_VERBS or _SUBMIT_NOW_RE.search(text)),
        declares_itself=_declares_itself(definition),
    )


def _discloses(tool: _Listed, *, trusted: bool = False) -> bool:
    if tool.unread:
        return True
    # A name an untrusted server spells with letters its words cannot be read
    # by could name a path or the file's content (``_foreign``).
    if not trusted and any(_foreign(name) for name, _prop in tool.arguments):
        return True
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
    Arguments are read at any depth of nested objects; a schema too large
    to read whole, whose unread rest could take a path or the file's
    content, or an argument whose reference cannot be followed, is read as
    sending, whatever its hints; so is an untrusted server's argument whose
    name holds letters outside ASCII even NFKC-normalised.
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
    # The indicator each required argument takes, so a caller that asks about
    # one (post-verdict enrichment, the disclosure's count of what a call
    # carried) knows which argument to give it in.
    indicators = {
        role: roles[role]
        for role in NETWORK_INDICATOR_ARGUMENTS
        if role in roles and roles[role] in tool.required
    }
    if indicators:
        return {
            "kind": INDICATOR_REPORT,
            "arguments": indicators,
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
            # A schema read only in part, whose unread rest could take the
            # file, is read as taking it (``_walk``).
            content = takes_content(tool.arguments) or tool.unread
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
