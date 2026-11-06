"""The annotation of one MCP tool argument, read off the JSON schema its server declared.

A property whose schema is a plain type (``{"type": "integer", ...}`` with
nothing that gives it more shape) is annotated with the Python type for it,
exactly as it always was, so a simple tool is offered what it always was.

Every other form builds too: a type list, ``nullable``, ``anyOf`` / ``oneOf``
/ ``allOf``, ``enum``, ``const``, a nested object, an array with ``items``,
``additionalProperties``, a local ``$ref`` and a property with no type at
all. Such a property is offered the server's own schema with every local
``$ref`` (``#``, ``#/$defs/...``, ``#/definitions/...``, any JSON pointer into
the tool's schema) written out in place, and is checked here only for the
Python shape of its value; the server checks the rest. A reference that would
repeat one it is already inside stands as the bare type of what it names, so a
recursive schema is written out once and never loops; one that cannot be
resolved (a remote one, an ``#anchor``) leaves the value unconstrained. A
keyword that is not a schema and still holds a ``$ref`` once the rest is
written out (``examples``, ``const``, an ``x-`` extension) is left out, so no
reference reaches the model's client.

The server is not trusted to be well-formed. A property whose written-out
schema passes :data:`MAX_NODES` nodes, :data:`MAX_DEPTH` levels or
:data:`MAX_BYTES` bytes, or is not a valid Draft 2020-12 schema, raises
:class:`UnusableSchema`, and its caller offers it as the plain type it was
offered before (:func:`plain_type`); every other property keeps its schema.
"""

from __future__ import annotations

import functools
import json
import operator
from collections.abc import Mapping
from typing import Annotated, Any
from urllib.parse import unquote

PLAIN_TYPES: dict[str, Any] = {
    "string": str,
    "integer": int,
    "number": float,
    "boolean": bool,
    "array": list,
    "object": dict,
}

# Keywords that give a property more shape than its ``"type"`` says.
STRUCTURAL = frozenset(
    {
        "$ref",
        "anyOf",
        "oneOf",
        "allOf",
        "not",
        "properties",
        "additionalProperties",
        "patternProperties",
        "items",
        "prefixItems",
        "enum",
        "const",
        "nullable",
    }
)

# How much of one property's schema is written out before it is offered as its
# plain type instead: a schema whose references fan out (``a0 = anyOf[a1, a1]``
# and so on) doubles at every level.
MAX_NODES = 2000
MAX_DEPTH = 32
MAX_BYTES = 64 * 1024

# Keywords whose value is a schema, a list of schemas, or a map of them.
_SCHEMA_KEYS = frozenset(
    {
        "items",
        "additionalItems",
        "additionalProperties",
        "unevaluatedItems",
        "unevaluatedProperties",
        "contains",
        "propertyNames",
        "contentSchema",
        "not",
        "if",
        "then",
        "else",
    }
)
_SCHEMA_LIST_KEYS = frozenset({"anyOf", "oneOf", "allOf", "prefixItems", "items"})
# ``dependencies`` maps a name to a schema or to a list of names; only a schema
# is written out.
_SCHEMA_MAP_KEYS = frozenset(
    {"properties", "patternProperties", "dependentSchemas", "dependencies"}
)
# Definitions are only what a reference points into; once every reference is
# written out in place they say nothing more.
_DEFINITION_KEYS = frozenset({"$defs", "definitions"})

_MISSING = object()


class UnusableSchema(ValueError):
    """A property schema that cannot be offered as written; its plain type stands."""


def is_plain(field: Any) -> bool:
    """Whether ``field`` is a single stated type and nothing that gives it more shape."""
    return (
        isinstance(field, Mapping)
        and isinstance(field.get("type"), str)
        and not STRUCTURAL.intersection(field)
    )


def plain_type(field: Any) -> Any:
    """The annotation a property was given before any other form was read: its ``type`` alone."""
    stated = field.get("type", "string") if isinstance(field, Mapping) else "string"
    return PLAIN_TYPES.get(stated, Any) if isinstance(stated, str) else Any


def holds_ref(value: Any) -> bool:
    """Whether a ``$ref`` key appears anywhere in ``value``."""
    if isinstance(value, Mapping):
        return "$ref" in value or any(holds_ref(v) for v in value.values())
    if isinstance(value, list):
        return any(holds_ref(v) for v in value)
    return False


def _stated_names(stated: Any) -> list[str] | None:
    """A ``type`` as its list of names; ``None`` when it is neither a name nor a list of distinct ones."""
    if isinstance(stated, str):
        return [stated]
    if (
        isinstance(stated, list)
        and stated
        and all(isinstance(n, str) for n in stated)
        and len(set(stated)) == len(stated)
    ):
        return list(stated)
    return None


def _stand_in(target: Mapping[str, Any]) -> dict[str, Any]:
    """The schema a reference stands as where it would repeat one it is inside."""
    names = _stated_names(target.get("type"))
    if names is None:
        return {}
    return {"type": names[0] if len(names) == 1 else names}


def _union(types: list[Any]) -> Any:
    """The union of ``types``; ``Any`` when one of them is."""
    if not types or any(t is Any for t in types):
        return Any
    unique = list(dict.fromkeys(types))
    return functools.reduce(operator.or_, unique)


def _value_type(value: Any) -> Any:
    if value is None:
        return type(None)
    for kind in (bool, int, float, str, list, dict):
        if isinstance(value, kind):
            return kind
    return Any


def _named_type(name: str) -> Any:
    return type(None) if name == "null" else PLAIN_TYPES.get(name, Any)


class _Reader:
    """Reads the properties of one tool schema, each local reference's shape once."""

    def __init__(self, root: Any) -> None:
        self.root = root
        self.nodes = 0
        self.shapes: dict[str, Any] = {}

    def _visit(self, depth: int) -> None:
        self.nodes += 1
        if self.nodes > MAX_NODES:
            raise UnusableSchema(f"over {MAX_NODES} nodes once its references are written out")
        if depth > MAX_DEPTH:
            raise UnusableSchema(f"nested over {MAX_DEPTH} levels deep")

    def target(self, ref: str) -> Any:
        """What the local reference ``ref`` names, or ``_MISSING``.

        Only ``#`` and a JSON pointer (``#/...``) are read; an anchor
        (``#name``) and anything outside this schema are not.
        """
        if ref == "#":
            return self.root
        if not ref.startswith("#/"):
            return _MISSING
        found = self.root
        for raw in ref[2:].split("/"):
            part = unquote(raw).replace("~1", "/").replace("~0", "~")
            if isinstance(found, Mapping) and part in found:
                found = found[part]
            elif isinstance(found, list) and part.isdigit() and len(part) < 10:
                index = int(part)
                if index >= len(found):
                    return _MISSING
                found = found[index]
            else:
                return _MISSING
        return found

    def resolved(self, schema: Any, depth: int = 0, inside: frozenset[str] = frozenset()) -> Any:
        """``schema`` with every local ``$ref`` written out in place; ``schema`` is not changed."""
        if not isinstance(schema, Mapping):
            return schema
        self._visit(depth)
        ref = schema.get("$ref")
        # A ``$ref`` that is not a string names nothing and is left out.
        rest = {k: v for k, v in schema.items() if k != "$ref"}
        if isinstance(ref, str):
            own = self.resolved(rest, depth, inside)
            target = self.target(ref)
            if not isinstance(target, Mapping):
                return own
            if ref in inside:
                return {**_stand_in(target), **own}
            return {**self.resolved(target, depth + 1, inside | {ref}), **own}
        out: dict[str, Any] = {}
        for key, value in rest.items():
            if key in _DEFINITION_KEYS:
                continue
            if key in _SCHEMA_LIST_KEYS and isinstance(value, list):
                out[key] = [self.resolved(v, depth + 1, inside) for v in value]
            elif key in _SCHEMA_MAP_KEYS and isinstance(value, Mapping):
                out[key] = {
                    name: self.resolved(v, depth + 1, inside) if isinstance(v, Mapping) else v
                    for name, v in value.items()
                }
            elif key in _SCHEMA_KEYS:
                out[key] = self.resolved(value, depth + 1, inside)
            elif not holds_ref(value):
                out[key] = value
        return out

    def shape(self, schema: Any, depth: int = 0, inside: frozenset[str] = frozenset()) -> Any:
        """The Python shape a value of ``schema`` has; ``Any`` where the schema does not say."""
        if not isinstance(schema, Mapping):
            return Any
        if depth > MAX_DEPTH:
            raise UnusableSchema(f"nested over {MAX_DEPTH} levels deep")
        ref = schema.get("$ref")
        if isinstance(ref, str):
            if ref in self.shapes:
                return self.shapes[ref]
            target = self.target(ref)
            if not isinstance(target, Mapping) or ref in inside:
                return Any
            found = self.shape(target, depth + 1, inside | {ref})
            self.shapes[ref] = found
            return found
        found = self._stated_shape(schema, depth, inside)
        if schema.get("nullable") is True and found is not Any:
            found = found | None
        return found

    def _stated_shape(self, schema: Mapping[str, Any], depth: int, inside: frozenset[str]) -> Any:
        if "type" in schema:
            names = _stated_names(schema["type"])
            return Any if names is None else _union([_named_type(n) for n in names])
        for key in ("anyOf", "oneOf"):
            branches = schema.get(key)
            if isinstance(branches, list) and branches:
                return _union([self.shape(b, depth + 1, inside) for b in branches])
        branches = schema.get("allOf")
        if isinstance(branches, list) and branches:
            # Every branch holds at once: the one shape they agree on, if any.
            said = {self.shape(b, depth + 1, inside) for b in branches} - {Any}
            return said.pop() if len(said) == 1 else Any
        listed = schema.get("enum")
        if isinstance(listed, list) and listed:
            return _union([_value_type(v) for v in listed])
        if "const" in schema:
            return _value_type(schema["const"])
        if any(k in schema for k in ("properties", "additionalProperties", "patternProperties")):
            return dict
        if any(k in schema for k in ("items", "prefixItems")):
            return list
        return Any


def offered_schema(field: Any, root: Any) -> Any:
    """``field`` written out for the model, or :class:`UnusableSchema`."""
    from jsonschema import Draft202012Validator
    from jsonschema.exceptions import SchemaError

    written = _Reader(root).resolved(field)
    if len(json.dumps(written, default=str)) > MAX_BYTES:
        raise UnusableSchema(f"over {MAX_BYTES} bytes once its references are written out")
    try:
        Draft202012Validator.check_schema(written)
    except SchemaError as exc:
        raise UnusableSchema(f"not a valid Draft 2020-12 schema: {exc.message}") from exc
    return written


def annotation(field: Any, root: Any, *, optional: bool) -> Any:
    """The annotation of a property that is not plain, in the tool schema ``root``.

    It checks the value's Python shape and offers ``field`` written out
    (:func:`offered_schema`). An optional one also takes ``None``, as a plain
    optional property does, so an explicit ``null`` is tolerated here and left
    to the null rules (``agents.null_arguments``) and the transport. Raises
    :class:`UnusableSchema` for a schema that cannot be offered.
    """
    from pydantic import WithJsonSchema

    written = offered_schema(field, root)
    shape = _Reader(root).shape(field)
    if optional and shape is not Any:
        shape = shape | None
    return Annotated[shape, WithJsonSchema(written)]
