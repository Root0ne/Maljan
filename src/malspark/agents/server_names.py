"""An argument a server names what a pydantic field cannot be named, kept under the server's name.

A tool's argument model is a pydantic model with one field per argument, and
a server may name an argument what no field can be named: ``model_config``
(pydantic's own configuration), a name with a leading underscore (a private
attribute, so the argument was neither offered nor sent), a ``BaseModel``
member or a name in its ``model_`` namespace (``model_dump``, ``schema``,
``json``), a Python keyword or a name that is not an identifier (``class``,
``a-b``, ``1x``), and a keyword of the tool's own call (``self``, ``config``,
``run_manager``). One such name crashed the build of the whole tool, or lost
the argument without a word.

Such an argument is given an internal field name (:func:`field_names`) and
keeps the server's name as its alias. The model reads the server's name, and
also the field's own; the model is offered the server's name
(:class:`ServerNamedTool`); and a call's arguments are named by the server's
names (:func:`to_server_names`) wherever a call is read: what the server is
sent, what the ledger records, cites and compares for a repeat, and the
arguments a guard narrows, pins or fills. Every other argument is a field of
its own name, exactly as before.
"""

from __future__ import annotations

import functools
import inspect
import keyword
from collections.abc import Iterable
from typing import Annotated, Any

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, create_model

# The prefix of every internal field name. No ``BaseModel`` member, keyword or
# call keyword starts with it, so a name made from it is never reserved.
_PREFIX = "arg"


@functools.cache
def _call_keywords() -> frozenset[str]:
    """The named parameters of a tool's own call, which an argument would collide with."""
    named = set()
    for method in (StructuredTool._run, StructuredTool._arun):
        for parameter in inspect.signature(method).parameters.values():
            if parameter.kind not in (parameter.VAR_POSITIONAL, parameter.VAR_KEYWORD):
                named.add(parameter.name)
    return frozenset(named)


def reserved(name: str) -> bool:
    """Whether ``name`` cannot be the name of an argument model's field."""
    return (
        not name.isidentifier()
        or keyword.iskeyword(name)
        or name.startswith(("_", "model_"))
        or hasattr(BaseModel, name)
        or name in _call_keywords()
    )


def _identifier(name: str) -> str:
    """``arg_`` and ``name`` with each character an identifier cannot hold as ``_``."""
    kept = "".join(c if f"a{c}".isidentifier() else "_" for c in name).strip("_")
    return f"{_PREFIX}_{kept}" if kept else _PREFIX


def field_names(names: Iterable[str]) -> dict[str, str]:
    """Each server name of ``names`` with the name of the field that holds it.

    A name that is not reserved is its own field name; a reserved one is given
    one no other argument of the tool is named or given.
    """
    given = list(names)
    taken = set(given)
    fields: dict[str, str] = {}
    for name in given:
        if not reserved(name):
            fields[name] = name
            continue
        base = _identifier(name)
        candidate, count = base, 1
        while candidate in taken:
            count += 1
            candidate = f"{base}_{count}"
        taken.add(candidate)
        fields[name] = candidate
    return fields


def server_named(fields: Iterable[Any]) -> bool:
    """Whether a field of an argument model's ``create_model`` definitions has an alias."""
    from pydantic.fields import FieldInfo

    return any(
        isinstance(spec, tuple) and isinstance(spec[-1], FieldInfo) and spec[-1].alias is not None
        for spec in fields
    )


# What an argument model with an aliased field validates by: the server's name
# the model writes, and the field's own name a rebuilt tool hands on.
BY_EITHER_NAME = ConfigDict(validate_by_alias=True, validate_by_name=True)


def _aliases(model: Any) -> dict[str, str]:
    fields = getattr(model, "model_fields", None)
    if not isinstance(fields, dict):
        return {}
    return {name: f.alias for name, f in fields.items() if f.alias is not None and f.alias != name}


def server_names(model: Any) -> tuple[str, ...]:
    """The arguments of the argument model ``model`` by the server's names, in its order."""
    fields = getattr(model, "model_fields", None)
    if not isinstance(fields, dict):
        return ()
    aliases = _aliases(model)
    return tuple(str(aliases.get(name, name)) for name in fields)


def to_server_names(model: Any, kwargs: dict[str, Any]) -> dict[str, Any]:
    """``kwargs`` of a call with each field of ``model`` named by the server's name.

    The one place a call's arguments turn from the fields that held them into
    what the server is sent, so what is sent, recorded, cited and compared for
    a repeat names the same arguments. A name that is already the server's, or
    that is no field's, is kept; ``kwargs`` comes back as it was when ``model``
    holds no argument apart from its server name.
    """
    aliases = _aliases(model)
    if not aliases:
        return kwargs
    return {aliases.get(name, name): value for name, value in kwargs.items()}


def _with_aliases(offered: type[BaseModel], aliases: dict[str, str]) -> type[BaseModel]:
    """``offered`` with each of its fields ``aliases`` names offered under its alias."""
    fields: dict[str, Any] = {}
    for name, field in offered.model_fields.items():
        annotation = (
            Annotated[field.annotation, *field.metadata] if field.metadata else field.annotation
        )
        stated: dict[str, Any] = {"description": field.description}
        if field.default_factory is not None:
            stated["default_factory"] = field.default_factory
        else:
            stated["default"] = field.default
        if name in aliases:
            stated["alias"] = aliases[name]
        fields[name] = (annotation, Field(**stated))
    named = create_model(  # type: ignore[call-overload]
        offered.__name__,
        __config__=ConfigDict(arbitrary_types_allowed=True, **BY_EITHER_NAME),
        __doc__=offered.__doc__,
        **fields,
    )
    # The cache LangChain gives the schema it offers, so a tool bound every
    # turn writes its JSON schema once; a LangChain without it writes it each
    # time, as pydantic does.
    from langchain_core.tools import base as tools_base

    cache = getattr(tools_base, "_patch_json_schema_cache", None)
    if cache is not None:
        cache(named)
    return named  # type: ignore[no-any-return]


class ServerNamedTool(StructuredTool):
    """A structured tool whose model is offered each argument under the server's name.

    The schema a model is offered for a call is a copy of the argument model
    that keeps each field's type and description but not its alias, so an
    argument held under an internal field name would be offered under that
    name. Here it is offered under the server's. A tool with no such argument
    is offered exactly what a structured tool is.
    """

    _server_named: Any = PrivateAttr(default=None)

    def to_server_names(self, kwargs: dict[str, Any]) -> dict[str, Any]:
        """``kwargs`` of a call to this tool by the server's names (:func:`to_server_names`)."""
        return to_server_names(self.args_schema, kwargs)

    @property
    def tool_call_schema(self) -> Any:
        offered = super().tool_call_schema
        aliases = _aliases(self.args_schema)
        if not aliases or not isinstance(offered, type) or not issubclass(offered, BaseModel):
            return offered
        held = self._server_named
        if held is not None and held[0] is offered:
            return held[1]
        named = _with_aliases(offered, aliases)
        self._server_named = (offered, named)
        return named
