"""Every leaf of the core Settings model, described for a generic UI.

The walk is a pure function of the pydantic models: field names, types,
defaults, Literal choices, numeric bounds and SecretStr-ness come from the
model; titles, descriptions and when a change applies come from
``settings_annotations``. A test refuses a leaf without an annotation, so a
new field cannot be added to config.py without also being explained.
"""

from __future__ import annotations

import types
import typing
from dataclasses import asdict, dataclass
from typing import Any, Literal, get_args, get_origin

from pydantic import BaseModel, SecretStr
from pydantic.fields import FieldInfo

from maljan.core.config import Settings
from maljan.core.settings_annotations import ANNOTATIONS, GROUP_ORDER, group_for

FieldType = Literal["bool", "int", "float", "str", "secret", "enum", "list", "dict", "json"]
Applies = Literal["next_job", "live", "restart"]

# Field names that are secrets although typed as plain str.
_SECRET_NAMES = {"auth_token", "api_key", "cape2_api_token"}


@dataclass(frozen=True)
class Leaf:
    path: str
    annotation: Any
    default: Any
    field: FieldInfo


@dataclass(frozen=True)
class CatalogEntry:
    key: str
    namespace: str
    path: str
    type: FieldType
    default: Any
    nullable: bool
    choices: list[str] | None
    minimum: float | None
    maximum: float | None
    secret: bool
    group: str
    title: str
    description: str
    applies: Applies
    editable: bool
    reason: str | None
    probe: str | None
    # Conditional visibility: {settings key: values of that key which reveal this
    # entry}. The UI filters on the staged-or-current value; the API never
    # hides anything, because a hidden setting is still an effective setting.
    applies_when: dict[str, list[str]] | None = None
    # Rank within the group; lower first, ties broken by path. Provider
    # selectors use -1 so the switch sits above the fields it governs.
    order: int = 0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _unwrap_optional(tp: Any) -> tuple[Any, bool]:
    origin = get_origin(tp)
    if origin in (typing.Union, types.UnionType):
        args = [a for a in get_args(tp) if a is not type(None)]
        if len(args) == 1:
            return args[0], True
    return tp, False


def _is_model(tp: Any) -> bool:
    return isinstance(tp, type) and issubclass(tp, BaseModel)


def _walk(model: type[BaseModel], prefix: str, defaults: Any) -> list[Leaf]:
    out: list[Leaf] = []
    for name, field in model.model_fields.items():
        tp, _ = _unwrap_optional(field.annotation)
        path = f"{prefix}{name}"
        default = getattr(defaults, name) if defaults is not None else None
        if _is_model(tp):
            out.extend(_walk(tp, path + ".", default))
        else:
            out.append(Leaf(path=path, annotation=field.annotation, default=default, field=field))
    return out


def core_leaves() -> list[Leaf]:
    """Leaves of ``Settings`` with the *code* defaults (env ignored)."""
    defaults = Settings.model_construct()  # no env, no validation: declared defaults only
    # model_construct leaves nested models unbuilt; build them from their own defaults
    for name, field in Settings.model_fields.items():
        tp, _ = _unwrap_optional(field.annotation)
        if _is_model(tp) and not isinstance(getattr(defaults, name, None), BaseModel):
            object.__setattr__(defaults, name, tp())
    return _walk(Settings, "", defaults)


def _field_type(leaf: Leaf) -> tuple[FieldType, list[str] | None, bool]:
    tp, nullable = _unwrap_optional(leaf.annotation)
    name = leaf.path.rsplit(".", 1)[-1]
    if tp is SecretStr or name in _SECRET_NAMES:
        return "secret", None, nullable
    if get_origin(tp) is Literal:
        return "enum", [str(a) for a in get_args(tp)], nullable
    if tp is bool:
        return "bool", None, nullable
    if tp is int:
        return "int", None, nullable
    if tp is float:
        return "float", None, nullable
    if tp is str:
        return "str", None, nullable
    origin = get_origin(tp)
    if origin in (list, set, tuple):
        return "list", None, nullable
    if origin is dict:
        _, val = get_args(tp) or (None, None)
        return ("json" if _is_model(val) else "dict"), None, nullable
    return "json", None, nullable


def _bounds(field: FieldInfo) -> tuple[float | None, float | None]:
    lo = hi = None
    for meta in field.metadata:
        if hasattr(meta, "ge") or hasattr(meta, "gt"):
            lo = getattr(meta, "ge", getattr(meta, "gt", lo))
        if hasattr(meta, "le") or hasattr(meta, "lt"):
            hi = getattr(meta, "le", getattr(meta, "lt", hi))
    return lo, hi


def _json_default(value: Any) -> Any:
    if isinstance(value, SecretStr):
        return None
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, dict):
        return {k: _json_default(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_json_default(v) for v in value]
    return value


def core_catalog() -> list[CatalogEntry]:
    """Every leaf of ``Settings``, annotated where ``settings_annotations`` covers it.

    A leaf with no entry yet in ``ANNOTATIONS`` (a setting added in one commit
    and annotated in the next, e.g. the provider-layer migration) falls back to
    its dotted path as the title and an empty description instead of raising —
    this is called at import time by the worker to build its secret-redaction
    list, and ``secret`` is derived from the field's own type/name below, not
    from the annotation, so an unannotated credential field is still redacted.
    """
    entries: list[CatalogEntry] = []
    for leaf in core_leaves():
        ann = ANNOTATIONS.get(leaf.path)
        ftype, choices, nullable = _field_type(leaf)
        lo, hi = _bounds(leaf.field)
        entries.append(
            CatalogEntry(
                key=f"core.{leaf.path}",
                namespace="core",
                path=leaf.path,
                type=ftype,
                default=_json_default(leaf.default),
                nullable=nullable,
                choices=choices,
                minimum=lo,
                maximum=hi,
                secret=ftype == "secret",
                group=(ann.get("group") if ann else None) or group_for(leaf.path),
                title=ann["title"] if ann else leaf.path,
                description=ann["description"] if ann else "",
                applies=(ann.get("applies", "next_job") if ann else "next_job"),
                editable=True,
                reason=None,
                probe=ann.get("probe") if ann else None,
                applies_when=(ann.get("applies_when") if ann else None),
                order=(ann.get("order", 0) if ann else 0),
            )
        )
    order = {g: i for i, (g, _) in enumerate(GROUP_ORDER)}
    entries.sort(key=lambda e: (order[e.group], e.order, e.path))
    return entries
