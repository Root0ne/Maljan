"""A ``null`` a tool's own schema does not allow, read as the argument left out.

A model that fills every optional argument of a call it makes writes ``null``
for the ones it has nothing to say about: ``{"address": "0x401000",
"program": null, "timeout": null}``. A server whose schema types ``timeout``
as an integer with no ``null`` in it refused the whole call, and the model lost
a call it had made correctly in every way that mattered. Leaving an optional
argument out is what that ``null`` means, so at the tool boundary of every tool
server it is read as exactly that.

What decides it is the schema the server declared, never the tool's name:

* a field that is **required** keeps its ``null`` and is refused as before;
* a field that **admits null** keeps an explicit ``null``: its ``type``
  includes ``"null"``, it says ``"nullable": true`` (OpenAPI 3.0), an
  ``anyOf``/``oneOf`` branch admits it, or nothing in its schema rules ``null``
  out. What this does not read (``allOf``, a ``$ref`` standing for the field's
  type) never rules ``null`` out, so such a field keeps its ``null``;
* any other optional field given ``null`` is **dropped**: the argument model
  removes it before it validates, so the field takes its declared default
  exactly as if the call had left it out, and what is sent, recorded and
  compared for a repeat is the same as for that call.

Nested objects follow the same rule where the schema describes them: an
object property with its own ``properties``, also behind a local ``$ref`` into
``$defs`` (or ``definitions``), and the object branch of an
``anyOf``/``oneOf``. Each definition is compiled once, so a recursive schema
costs its size; one walk over the arguments decides a call.

Nothing is hidden. A call's ledger entry names, by path segments, each field
dropped (``LedgerEntry.args_nulls_dropped``) and each top-level ``null`` the
tool's transport does not send although the schema admits it
(``LedgerEntry.args_nulls_withheld``: an MCP server is never sent a top-level
``null`` for an optional argument, so it applies its own default); the
``tool_call_started`` event names both. A withheld field is never sent and is
recorded as its default, exactly as a call that left it out is recorded. A
call with neither is recorded as it always was.
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from functools import cache
from typing import Any

# One field's rule: whether its ``null`` is dropped, and the rule for the
# object it holds, where its schema describes one. A recursive schema gives a
# rule that holds itself.
NullRule = Mapping[str, tuple[bool, "NullRule | None"]]

# Where a tool's argument model keeps its :class:`NullRules`.
RULES_ATTRIBUTE = "__maljan_null_rules__"

# The key the boundary hands its :class:`CallNulls` to the tool's recording
# wrapper under. Only a value of that type is taken; anything else under this
# key (a model can write any key) is left where it is, as an argument.
DROPPED_KEY = "__maljan_nulls_dropped__"

Path = tuple[str, ...]


@dataclass(frozen=True)
class NullRules:
    """What one tool does with a ``null``.

    ``dropped`` is the rule its argument model applies while it validates;
    ``withheld`` the optional top-level fields that admit ``null`` and whose
    explicit ``null`` the tool's transport does not send.
    """

    dropped: NullRule | None = None
    withheld: frozenset[str] = frozenset()

    def __bool__(self) -> bool:
        return bool(self.dropped) or bool(self.withheld)


@dataclass(frozen=True)
class CallNulls:
    """The fields of one call whose ``null`` was dropped or withheld, by path segments.

    Made only by the boundary (:func:`noting_class`): no tool call's arguments,
    which are JSON, can hold one.
    """

    dropped: tuple[Path, ...] = ()
    withheld: tuple[Path, ...] = ()

    def __bool__(self) -> bool:
        return bool(self.dropped) or bool(self.withheld)


NO_NULLS = CallNulls()

# The recorder of the call being made, and that call's nulls.
_CURRENT: ContextVar[tuple[Any, CallNulls]] = ContextVar(
    "maljan_call_nulls", default=(None, NO_NULLS)
)


def admits_null(schema: Any) -> bool:
    """Whether a JSON schema allows ``null``: nothing in it that this reads rules ``null`` out.

    A schema that is not an object (``true``, or a value nobody can read), one
    that states no type, and a keyword this does not read (``allOf``, ``$ref``)
    admit it, so a field this cannot read keeps the ``null`` it was given.
    """
    if not isinstance(schema, Mapping):
        return True
    if schema.get("nullable") is True:
        return True
    stated = schema.get("type")
    if stated is not None:
        types = stated if isinstance(stated, list) else [stated]
        if "null" not in types:
            return False
    listed = schema.get("enum")
    if isinstance(listed, list) and None not in listed:
        return False
    if "const" in schema and schema["const"] is not None:
        return False
    for key in ("anyOf", "oneOf"):
        branches = schema.get(key)
        if isinstance(branches, list) and branches and not any(map(admits_null, branches)):
            return False
    return True


class _Compiler:
    """Compiles an object schema's rule, each local definition once."""

    def __init__(self, root: Mapping[str, Any]) -> None:
        defs: dict[str, Any] = {}
        for key in ("definitions", "$defs"):
            found = root.get(key)
            if isinstance(found, Mapping):
                defs.update({f"#/{key}/{name}": value for name, value in found.items()})
        self.defs = defs
        self.compiled: dict[str, dict[str, Any]] = {}

    def object_rule(self, schema: Any) -> NullRule | None:
        """The rule for the object ``schema`` describes, or ``None`` when it describes none."""
        if not isinstance(schema, Mapping):
            return None
        ref = schema.get("$ref")
        if isinstance(ref, str):
            return self._ref_rule(ref)
        properties = schema.get("properties")
        if isinstance(properties, Mapping):
            return self._properties_rule(schema, properties, {})
        for key in ("anyOf", "oneOf"):
            branches = schema.get(key)
            if isinstance(branches, list):
                described = [r for r in map(self.object_rule, branches) if r is not None]
                if len(described) == 1:
                    return described[0]
        return None

    def _ref_rule(self, ref: str) -> NullRule | None:
        if ref in self.compiled:
            return self.compiled[ref]
        target = self.defs.get(ref)
        if not isinstance(target, Mapping):
            return None
        properties = target.get("properties")
        if not isinstance(properties, Mapping):
            return None
        # Held before it is filled, so a definition that holds itself reads
        # back this same rule rather than compiling again.
        rule: dict[str, Any] = {}
        self.compiled[ref] = rule
        return self._properties_rule(target, properties, rule)

    def _properties_rule(
        self, schema: Mapping[str, Any], properties: Mapping[str, Any], rule: dict[str, Any]
    ) -> NullRule:
        required = schema.get("required")
        needed = set(required) if isinstance(required, list) else set()
        for name, field in properties.items():
            dropped = name not in needed and not admits_null(field)
            nested = self.object_rule(field)
            # ``is not None``: a definition that holds itself is still empty
            # while its own fields compile, and is a rule all the same.
            if dropped or nested is not None:
                rule[str(name)] = (dropped, nested)
        return rule


def schema_rules(schema: Any, *, withholds_admitted_nulls: bool = False) -> NullRules:
    """The rules for a tool whose arguments a JSON object schema declares.

    ``withholds_admitted_nulls`` says the tool's transport does not send an
    optional top-level argument whose value is ``null``.
    """
    if not isinstance(schema, Mapping):
        return NullRules()
    properties = schema.get("properties")
    if not isinstance(properties, Mapping):
        return NullRules()
    compiler = _Compiler(schema)
    dropped = compiler._properties_rule(schema, properties, {})
    withheld: frozenset[str] = frozenset()
    if withholds_admitted_nulls:
        required = schema.get("required")
        needed = set(required) if isinstance(required, list) else set()
        withheld = frozenset(
            str(name)
            for name, field in properties.items()
            if name not in needed and admits_null(field)
        )
    return NullRules(dropped or None, withheld)


def params_rules(params: Sequence[Mapping[str, Any]]) -> NullRules:
    """The rules for a REST tool's parameter list (``name``, ``type``, ``required``).

    A parameter list has no way to say a parameter admits ``null``, so every
    optional parameter given one is dropped.
    """
    rule = {
        str(p["name"]): (True, None)
        for p in params
        if isinstance(p, Mapping) and "name" in p and not p.get("required", False)
    }
    return NullRules(rule or None)


def drop_unset_nulls(args: Any, rule: NullRule | None) -> tuple[Any, tuple[Path, ...]]:
    """``(arguments, dropped)``: ``args`` without the ``null`` fields ``rule`` drops.

    Each field dropped is named by its path segments (``("options", "depth")``).
    ``args`` comes back as the same object when nothing was dropped, and is
    never changed in place.
    """
    if not rule or not isinstance(args, dict):
        return args, ()
    dropped: list[Path] = []
    return _drop(args, rule, (), dropped), tuple(dropped)


def _drop(
    args: dict[str, Any], rule: NullRule, prefix: Path, dropped: list[Path]
) -> dict[str, Any]:
    kept: dict[str, Any] | None = None
    for name, value in args.items():
        field = rule.get(name)
        if field is None:
            continue
        leave_out, nested = field
        if value is None:
            if leave_out:
                if kept is None:
                    kept = dict(args)
                del kept[name]
                dropped.append((*prefix, name))
        elif nested and isinstance(value, dict):
            inner = _drop(value, nested, (*prefix, name), dropped)
            if inner is not value:
                if kept is None:
                    kept = dict(args)
                kept[name] = inner
    return args if kept is None else kept


def call_nulls(args: Any, rules: NullRules) -> CallNulls:
    """The nulls of one call's arguments as the model gave them, under ``rules``."""
    if not rules or not isinstance(args, dict):
        return NO_NULLS
    dropped = drop_unset_nulls(args, rules.dropped)[1]
    withheld = tuple((name,) for name in args if name in rules.withheld and args[name] is None)
    return CallNulls(dropped, withheld) if dropped or withheld else NO_NULLS


def validators(rule: NullRule | None) -> dict[str, Any]:
    """The ``__validators__`` for ``create_model`` that drop ``rule``'s fields.

    A model validator run before the fields are read, so a field dropped takes
    its declared default and the JSON schema the model is offered is the same
    as without it.
    """
    if not rule:
        return {}
    from pydantic import model_validator

    def leave_out_unset_nulls(cls: Any, data: Any) -> Any:
        return drop_unset_nulls(data, rule)[0]

    return {"leave_out_unset_nulls": model_validator(mode="before")(leave_out_unset_nulls)}


def argument_model(name: str, fields: Mapping[str, Any], rules: NullRules) -> Any:
    """A tool's argument model, carrying ``rules``. A tool without any is built exactly as it was."""
    from pydantic import create_model

    model = create_model(name, __validators__=validators(rules.dropped) or None, **fields)  # type: ignore[call-overload]
    if rules:
        model.__maljan_null_rules__ = rules  # type: ignore[attr-defined]  # RULES_ATTRIBUTE
    return model


def without_fields(rules: NullRules, hidden: Sequence[str]) -> NullRules:
    """``rules`` for a model with the top-level fields ``hidden`` taken out of it."""
    if not hidden or not rules:
        return rules
    gone = set(hidden)
    dropped = {k: v for k, v in (rules.dropped or {}).items() if k not in gone}
    return NullRules(dropped or None, rules.withheld - gone)


def rules_of(model: Any) -> NullRules:
    """The :class:`NullRules` an argument model carries; empty ones for a model without."""
    rules = getattr(model, RULES_ATTRIBUTE, None)
    return rules if isinstance(rules, NullRules) else NullRules()


@cache
def noting_class(base: type) -> type:
    """``base``, naming the nulls of each call its argument model's rules find.

    The boundary of every recorded tool (``agents.evidence_recorder``). The
    arguments are validated exactly as before; what changes is that the
    :class:`CallNulls` read off the call as the model wrote it are handed to
    the tool's own function under :data:`DROPPED_KEY`, which takes them off
    before anything reads the call.
    """

    class _NotesUnsetNulls(base):  # type: ignore[misc, valid-type]
        def _parse_input(self, tool_input: Any, tool_call_id: Any) -> Any:
            found = call_nulls(tool_input, rules_of(self.args_schema))
            parsed = super()._parse_input(tool_input, tool_call_id)
            if isinstance(parsed, dict):
                parsed = {**parsed, DROPPED_KEY: found}
            return parsed

    _NotesUnsetNulls.__name__ = _NotesUnsetNulls.__qualname__ = f"{base.__name__}NotingNulls"
    return _NotesUnsetNulls


def take_call_nulls(kwargs: dict[str, Any], rules: NullRules) -> CallNulls:
    """The :class:`CallNulls` the boundary put in ``kwargs``, taken off; none otherwise.

    Only a value the boundary made is taken, and only the fields ``rules``
    name are kept from it; anything else under :data:`DROPPED_KEY` stays in
    ``kwargs`` as the argument it is.
    """
    found = kwargs.get(DROPPED_KEY)
    if not isinstance(found, CallNulls):
        return NO_NULLS
    del kwargs[DROPPED_KEY]
    withheld = tuple(p for p in found.withheld if len(p) == 1 and p[0] in rules.withheld)
    return CallNulls(found.dropped, withheld) if found.dropped or withheld else NO_NULLS


@contextmanager
def nulls_of_call(recorder: Any, nulls: CallNulls) -> Iterator[None]:
    """For the length of one call ``recorder`` files: that call's nulls.

    Set for every call of a tool with rules, none included, so a call made
    inside another (an agent asked by a tool) never reads the outer call's.
    """
    token = _CURRENT.set((recorder, nulls))
    try:
        yield
    finally:
        _CURRENT.reset(token)


def current_call_nulls(recorder: Any) -> CallNulls:
    """The nulls of the call ``recorder`` is filing, as :func:`nulls_of_call` set them."""
    holder, nulls = _CURRENT.get()
    return nulls if holder is recorder else NO_NULLS
