"""Every leaf of the core Settings model, described for a generic UI.

The walk is a pure function of the pydantic models: field names, types,
defaults, Literal choices, numeric bounds and SecretStr-ness come from the
model; titles, descriptions and when a change applies come from
``settings_annotations``. A test refuses a leaf without an annotation, so a
new field cannot be added to config.py without also being explained.
"""

from __future__ import annotations

import re
import types
import typing
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from functools import lru_cache
from typing import Any, Literal, get_args, get_origin

from pydantic import BaseModel, SecretStr
from pydantic.fields import FieldInfo

from maljan.core.config import Settings
from maljan.core.settings_annotations import ANNOTATIONS, GROUP_ORDER, group_for

FieldType = Literal["bool", "int", "float", "str", "secret", "enum", "list", "dict", "json"]
Applies = Literal["next_job", "live", "restart"]
ChoicesFrom = Literal[
    "static_providers",
    "sandbox_providers",
    "mcp_servers",
    "agent_roles",
    "profiles",
    "memory_backends",
    "llm_providers",
    "sandbox_report_readers",
]
Editor = Literal[
    "server_map",
    "rest_sandbox",
    "agent_definitions",
    "stages",
    "tool_facts",
    "pack_steps",
    "plugin_allow_list",
    "enrichment_sources",
    "report_formats",
]

# Field names that are secrets although typed as plain str.
_SECRET_NAMES = {"auth_token", "api_key"}


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
    # A choice list the API fills in when it serialises the catalog: registry
    # ids, or the keys of ``mcp.servers`` as they currently stand. The core
    # catalog cannot compute these — it is a pure function of the models and
    # the effective settings are not in scope here — and the web must never
    # compute them either, or two places decide what a valid provider is.
    choices_from: ChoicesFrom | None = None
    # A composite editor renders this leaf instead of the type's widget.
    editor: Editor | None = None
    # Heading inside the group; None sits at the top of the group.
    subgroup: str | None = None
    # Folded into the group's closed "Advanced" disclosure.
    advanced: bool = False
    # For the tool-server map alone: the environment names each built-in is
    # started with whatever the stored registry says, so the editor can draw
    # them as fixed rather than as lines an admin may delete and the API then
    # puts back. Filled by the API as it serialises the catalog, for the same
    # reason ``choices`` is: the rule lives in ``REQUIRED_ENV_ALLOW`` and a
    # second copy of it in the console is a copy that drifts.
    required_env: dict[str, list[str]] | None = None
    # The short phrase each choice declares for the console to show beside it
    # (a registry's own labels), keyed by choice; ``None`` when none declares one.
    choice_labels: dict[str, str] | None = None
    # For a provider selector, filled by the API from each registered
    # provider's own declaration: the title the console shows for a choice,
    # its one-line description, and the facts the console reads about it
    # (credential keys, hosted or run locally, its connection test, whether an
    # agent may give it an endpoint of its own, its effort setting).
    choice_titles: dict[str, str] | None = None
    choice_descriptions: dict[str, str] | None = None
    choice_facts: dict[str, dict[str, Any]] | None = None
    # For the tool-server map: the keys of the built-in servers and the keys no
    # operator's server may take, served so the console never keeps a copy.
    builtin_servers: list[str] | None = None
    reserved_servers: list[str] | None = None
    # For the agent definitions: per capability a seeded definition references
    # (``ToolRef(kind="capability")``), the servers it stands for
    # (``agents.composition.capability_servers``), served so the console draws
    # a capability reference with the servers it reaches, never a copy of the rule.
    capability_servers: dict[str, list[str]] | None = None
    # For the agent definitions: the input slices a definition may name in its
    # ``data_sources`` (``config.DATA_SOURCES``), served so the console offers
    # exactly what the settings model accepts.
    data_source_choices: list[str] | None = None
    # For the tool-server map: the agent keys a server may be bound to, the
    # effective definition map's keys, so the console offers every agent of
    # the roster rather than a fixed list.
    agent_keys: list[str] | None = None
    # The seeded definition keys, which stay known whatever a save does to the
    # stored map, so the console can tell which agents a staged definition
    # edit leaves bindable (``server_map._definition_keys``). Served on the
    # agent definitions' entry too: every one of them is built in, and the
    # settings model refuses an edit to any but its ``enabled`` switch.
    builtin_agent_keys: list[str] | None = None
    # For the agent definitions: the built-ins whose ``enabled`` switch the
    # settings model refuses to change (``config.ALWAYS_ENABLED_AGENTS``).
    always_enabled_agent_keys: list[str] | None = None
    # For the triage pack's steps: what a declared step may say
    # (``core.pack_steps.step_vocabulary``): its fields with their types and
    # defaults, the placeholders an argument template may name and the rule a
    # template is read by, the routed formats, the renderers and the shipped
    # steps, served so the console's step editor keeps no copy of any of them.
    pack_step_vocabulary: dict[str, Any] | None = None
    # A change to this setting asks for the admin's current password again
    # (the API's sign-in policy: the login lockout, the trusted proxies, the
    # token lifetimes), so a stolen session cannot weaken it on its own.
    needs_current_password: bool = False

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
        tp, nullable = _unwrap_optional(field.annotation)
        path = f"{prefix}{name}"
        default = getattr(defaults, name) if defaults is not None else None
        # A model that may be absent is one value: its fields are valid only
        # together, so it is one leaf rather than a key per field.
        if _is_model(tp) and not nullable:
            out.extend(_walk(tp, path + ".", default))
        else:
            out.append(Leaf(path=path, annotation=field.annotation, default=default, field=field))
    return out


def core_leaves() -> list[Leaf]:
    """Leaves of ``Settings`` with the *code* defaults (env ignored).

    Beside the declared fields: the settings of each memory backend an
    installed package registered with a settings model, under ``memory.<id>.``,
    so the catalogue lists and the store saves them like any other key.
    """
    defaults = Settings.model_construct()  # no env, no validation: declared defaults only
    # model_construct leaves nested models unbuilt; build them from their own defaults
    for name, field in Settings.model_fields.items():
        tp, _ = _unwrap_optional(field.annotation)
        if _is_model(tp) and not isinstance(getattr(defaults, name, None), BaseModel):
            object.__setattr__(defaults, name, tp())
    leaves = _walk(Settings, "", defaults)
    for backend_id, backend in _undeclared_memory_backends().items():
        model = backend.settings_model
        if model is not None:
            leaves.extend(_walk(model, f"memory.{backend_id}.", model()))
    for provider_id, model in _undeclared_llm_providers().items():
        leaves.extend(_walk(model, f"llm.{provider_id}.", model()))
    return leaves


def _undeclared_llm_providers() -> dict[str, Any]:
    """Registered LLM providers whose settings are not a declared field of ``llm``."""
    from maljan.llm.provider_base import undeclared_settings_models

    return undeclared_settings_models()


def _undeclared_memory_backends() -> dict[str, Any]:
    """Registered memory backends whose settings are not a declared field of ``memory``."""
    from maljan.core.config import MemoryConfig
    from maljan.memory.store_factory import registered_backends

    return {
        backend_id: backend
        for backend_id, backend in registered_backends().items()
        if backend_id not in MemoryConfig.model_fields
    }


def _annotation(path: str, undeclared: Mapping[str, Any] | None = None) -> Any:
    """``path``'s annotation: the shared table's, else the one its memory backend (the
    shipped Qdrant one included) or LLM provider declares for its own settings' leaves."""
    found = ANNOTATIONS.get(path)
    if found is not None:
        return found
    if path.startswith("llm."):
        provider_id, _, leaf = path[len("llm.") :].partition(".")
        providers = _undeclared_llm_providers() if undeclared is None else undeclared
        if leaf and provider_id in providers:
            from maljan.llm.provider_base import facts_of

            return facts_of(provider_id).settings_annotations.get(leaf)
        return None
    if not path.startswith("memory."):
        return found
    backend_id, _, leaf = path[len("memory.") :].partition(".")
    from maljan.memory.store_factory import registered_backends

    backend = registered_backends().get(backend_id)
    return backend.annotations.get(leaf) if backend is not None and leaf else None


# The registry sources an installed plugin adds to, by the kind of plugin.
PLUGIN_CHOICE_KINDS: dict[str, str] = {
    "llm_providers": "llm",
    "static_providers": "static",
    "sandbox_providers": "sandbox",
    "memory_backends": "memory",
}


def _registry_choices(source: str | None) -> list[str] | None:
    """The choices a core registry holds for ``source``, or ``None`` when it is not one.

    Shipped and in-process ids only: a plugin's id is offered from its
    package metadata and the stored allow-list (``maljan.core.plugins``),
    never because this process happens to have loaded it.
    """
    from maljan.core.plugins import loaded_names

    kind = PLUGIN_CHOICE_KINDS.get(str(source))
    plugin_ids = loaded_names(kind) if kind else set()
    if source == "memory_backends":
        from maljan.memory.store_factory import memory_backends

        return [i for i in memory_backends() if i not in plugin_ids]
    if source == "llm_providers":
        from maljan.llm.provider_base import provider_names

        return [i for i in provider_names() if i not in plugin_ids]
    if source == "sandbox_report_readers":
        from maljan.providers.sandbox.readers import choosable_reader_ids

        return choosable_reader_ids()
    if source in ("static_providers", "sandbox_providers"):
        from maljan.providers.registry import (
            sandbox_provider_class,
            sandbox_provider_ids,
            static_provider_class,
            static_provider_ids,
        )

        static = source == "static_providers"
        ids = static_provider_ids() if static else sandbox_provider_ids()
        cls_of = static_provider_class if static else sandbox_provider_class
        # In the order each provider declares, then by id.
        return sorted(
            (i for i in ids if i not in plugin_ids),
            key=lambda i: (getattr(cls_of(i), "choice_order", 100), i),
        )
    return None


def _registry_labels(source: str | None) -> dict[str, str] | None:
    """The labels a core registry's choices declare for ``source``, or ``None``."""
    if source == "memory_backends":
        from maljan.memory.store_factory import registered_backends

        labels = {key: b.label for key, b in registered_backends().items() if b.label}
        return labels or None
    return None


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
        # A list of objects (a server's error patterns) is edited as JSON; the
        # list widget is one string per line.
        items = get_args(tp)
        return ("json" if items and _is_model(items[0]) else "list"), None, nullable
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
    undeclared = _undeclared_llm_providers()
    for leaf in core_leaves():
        ann = _annotation(leaf.path, undeclared)
        ftype, choices, nullable = _field_type(leaf)
        # A str leaf whose choices a core registry holds is an enum of them.
        registry = _registry_choices(ann.get("choices_from") if ann else None)
        if registry is not None and ftype == "str":
            ftype, choices = "enum", registry
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
                choices_from=(ann.get("choices_from") if ann else None),
                choice_labels=_registry_labels(ann.get("choices_from") if ann else None),
                editor=(ann.get("editor") if ann else None),
                subgroup=(ann.get("subgroup") if ann else None),
                advanced=bool(ann.get("advanced", False)) if ann else False,
            )
        )
    order = {g: i for i, (g, _) in enumerate(GROUP_ORDER)}
    entries.sort(key=lambda e: (order[e.group], e.order, e.path))
    return entries


# An authorization scheme in front of a header's secret: the secret is what
# follows it.
_SCHEME_PREFIX = ("bearer ", "basic ", "token ")
# The last word of a mapping key that names a credential *value* — a tool
# server's ``VT_API_KEY``, ``DB_PASSWORD``, ``GITLAB_PAT``, an ``Authorization``
# header, a ``SESSION_COOKIE``, a ``JWT``, an ``AUTH`` — optionally followed by
# ``value``. An allow-list on the last word: a key that ends in anything else is
# a setting about the credential (``TOKEN_TTL``, ``PASSWORD_POLICY``,
# ``SECRET_MANAGER``, ``AUTH_MODE``, ``COOKIE_SECURE``), not the credential. The
# words are whole, so ``author``, ``authority`` and ``oauth`` are none of them.
# A last word that ends in a password word is one too, its owner written run
# together with it (``PGPASSWORD``, ``MYSQLPASSWD``). A key such as
# ``SECRET_KEY_BASE`` is missed, which costs less than masking a setting's word
# in every report. ``PWD`` is not on the list: in a tool server's environment it
# is the shell's working directory.
_CREDENTIAL_LAST_WORDS = frozenset(
    {
        "password",
        "passwd",
        "passphrase",
        "pass",
        "secret",
        "key",
        "apikey",
        "token",
        "pat",
        "credential",
        "credentials",
        "authorization",
        "bearer",
        "auth",
        "cookie",
        "cookies",
        "jwt",
    }
)
# The password words a last word may end in, run together with its owner.
_PASSWORD_ENDINGS = ("password", "passwd")
# A value that is a number, a switch or the name of an authorization scheme is
# a setting whatever its key says (``AUTH=basic``, ``AUTH=disabled``).
_NOT_A_SECRET_VALUE = frozenset(
    {
        "true",
        "false",
        "yes",
        "no",
        "on",
        "off",
        "none",
        "null",
        "enabled",
        "disabled",
        "required",
        "optional",
        "anonymous",
        "basic",
        "bearer",
        "digest",
        "negotiate",
        "ntlm",
        "kerberos",
        "oauth",
        "oauth2",
    }
)
# The generic REST sandbox's JSONPath maps: each value says where a response
# keeps a field, not what the field holds. Never read for secrets. Its
# ``submit_fields`` and ``extra_fields`` are form fields sent with every
# submission and are read like any other mapping.
_FIELD_MAPS = frozenset({"field_names", "channels"})


def names_a_credential_value(key: str) -> bool:
    """Whether a mapping key names a credential value rather than a setting about one."""
    import re

    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(key))
    words = [word for word in re.split(r"[^a-z0-9]+", spaced.lower()) if word]
    if len(words) > 1 and words[-1] == "value":
        words = words[:-1]
    return bool(words) and (
        words[-1] in _CREDENTIAL_LAST_WORDS or words[-1].endswith(_PASSWORD_ENDINGS)
    )


# The query keys a service URL carries a credential under, beside every key
# ``names_a_credential_value`` reads as one.
_CREDENTIAL_QUERY_KEYS = frozenset({"api_key", "apikey", "access_token", "token", "key"})


def _reads_as_a_credential(value: str) -> bool:
    """Whether ``value`` has a credential's shape by the event scrub's own rules."""
    try:
        from maljan.pipeline.events import _looks_like_a_credential

        return bool(_looks_like_a_credential(value, whole=True))
    except Exception:  # noqa: BLE001 — unread, the value is kept as a secret
        return True


# A run of backslashes, colons and token openers (``settings_masking.TOKEN_OPENERS``).
_ESCAPE_OR_OPENER_RUN = re.compile(r"[\\:\"'(<\[{]+")


def _bare_secrets(address: str) -> list[str]:
    """The credentials an address written with no scheme carries (``bare_userinfo``).

    Its password, read from its userinfo rather than by a URL parser, which
    refuses a password holding a bracket: everything after the first ``:``,
    and also what follows the last one, where a word before a mailbox's
    colon stands in front of a user name (``to:user:pw@host:8080``). A token
    alone in its user name slot where it has a token's shape or holds an
    opener no user name holds (``p"ss@h:8080``), then also what follows its
    last opener where that has a token's shape. Where the userinfo holds a
    backslash, each run between backslashes, openers and colons that has a
    token's shape, so a password JSON text escapes is registered as it is
    written unescaped too (``p\\<token>@h:8080``), while a domain account
    (``CORP\\Administrator@dc01:389``) registers nothing. And each query
    value whose key names a credential, as in a URL with a scheme.
    """
    from maljan.core.settings_masking import TOKEN_OPENERS, bare_userinfo

    parts = bare_userinfo(address)
    if parts is None:
        return []
    head, tail = parts
    found: list[str] = []
    if ":" in head:
        found.extend(
            dict.fromkeys(p for p in (head.partition(":")[2], head.rpartition(":")[2]) if p)
        )
    else:
        last_opener = max(head.rfind(opener) for opener in TOKEN_OPENERS)
        if last_opener >= 0 or _reads_as_a_credential(head):
            found.append(head)
        after = head[last_opener + 1 :]
        if 0 <= last_opener and after and _reads_as_a_credential(after):
            found.append(after)
    if "\\" in head:
        # A backslash, as JSON text escapes one, may stand beside the password
        # (``p\\<token>``): each run between backslashes, openers and colons
        # that has a token's shape is registered too.
        seen = set(found)
        for piece in _ESCAPE_OR_OPENER_RUN.split(head):
            if piece and piece not in seen and _reads_as_a_credential(piece):
                seen.add(piece)
                found.append(piece)
    found.extend(_url_secrets("//host" + tail[len(tail.split("?", 1)[0]) :]))
    return found


def _url_secrets(url: str) -> list[str]:
    """The credentials a configured URL carries: its password of any length, a token
    written alone in its username slot, and each query value whose key names a credential."""
    from urllib.parse import parse_qsl, urlsplit

    try:
        parts = urlsplit(url)
        password, username = parts.password, parts.username
        query = parse_qsl(parts.query, keep_blank_values=False)
        query += parse_qsl(parts.fragment, keep_blank_values=False)
    except ValueError:
        return []
    found: list[str] = []
    if password:
        found.append(password)
    elif username and "@" in parts.netloc and _reads_as_a_credential(username):
        # Userinfo with no password is a token when it has a token's shape,
        # the way an MCP or a Git service URL carries one. An ordinary user
        # name (``administrator``, ``git``) is not, and registered it would be
        # masked in every event that names it.
        found.append(username)
    for key, value in query:
        if value and (names_a_credential_value(key) or key.lower() in _CREDENTIAL_QUERY_KEYS):
            found.append(value)
    return found


def snapshot_hidden_paths(settings: BaseModel) -> tuple[list[str], list[str]]:
    """``(secret leaves, tool-server blocks)`` of a settings instance, by dotted path.

    A secret leaf is what this catalogue types as a secret (a ``SecretStr``,
    or a field named in ``_SECRET_NAMES``) wherever it sits, a model inside a
    mapping included (each tool server's ``auth_token`` under
    ``mcp.servers``). A tool-server block is every ``MCPServerConfig``
    (``mcp.servers.<key>``, ``static.ghidra``, ``static.r2``,
    ``sandbox.cape2.mcp``): its ``env`` map is where a server's own
    credential is written and no type marks it, and its arguments and address
    can carry one (``settings_masking.masked_server``). The paths are those of
    ``model_dump``, the form the run settings snapshot is read from
    (``settings_overrides.public_snapshot``).
    """
    from maljan.core.config import MCPServerConfig

    secrets: list[str] = []
    servers: list[str] = []

    def _walk(value: Any, path: str) -> None:
        if isinstance(value, BaseModel):
            if isinstance(value, MCPServerConfig):
                servers.append(path.removesuffix("."))
            for key, field in type(value).model_fields.items():
                tp, _ = _unwrap_optional(field.annotation)
                if tp is SecretStr or key in _SECRET_NAMES:
                    secrets.append(f"{path}{key}")
                else:
                    _walk(getattr(value, key, None), f"{path}{key}.")
        elif isinstance(value, Mapping):
            for key, item in value.items():
                _walk(item, f"{path}{key}.")

    _walk(settings, "")
    return secrets, servers


def _names_an_identifier(field: FieldInfo) -> bool:
    """Whether the model constrains ``field`` to a name (a stage's ``key``): its value is
    held to a pattern, so it is an identifier the settings refer to, never a credential."""
    return any(getattr(meta, "pattern", None) for meta in field.metadata)


def _field_reading(name: str, field: FieldInfo) -> tuple[Any, bool, bool]:
    """``(annotation, secret, identifier)`` of a declared field, as the model reads it.

    Secret where the catalogue types it so (a ``SecretStr``, a name in
    ``_SECRET_NAMES``), and where its name names a credential unless the model
    holds it to a name pattern: a stage's ``key`` is the stage's name.
    """
    tp, _ = _unwrap_optional(field.annotation)
    identifier = _names_an_identifier(field)
    secret = (
        tp is SecretStr
        or name in _SECRET_NAMES
        or (names_a_credential_value(name) and not identifier)
    )
    return field.annotation, secret, identifier


def _member_reading(declared: Any, key: str) -> tuple[Any, bool | None, bool]:
    """``(annotation, secret, identifier)`` of entry ``key`` of a mapping ``declared`` types.

    A model's declared field is read as the model reads it
    (:func:`_field_reading`); an entry of a typed map takes the map's value
    type. ``secret`` is ``None`` where nothing declares the entry (a key a
    model keeps as an extra, a plugin's block, an ``env`` or ``headers``
    entry): it is then read by its name (``names_a_credential_value``).
    """
    tp, _ = _unwrap_optional(declared)
    if get_origin(tp) is typing.Annotated:
        tp = get_args(tp)[0]
    if _is_model(tp):
        field = tp.model_fields.get(key)
        return _field_reading(key, field) if field is not None else (None, None, False)
    if get_origin(tp) in (dict, Mapping) and len(get_args(tp)) == 2:
        return get_args(tp)[1], None, False
    return None, None, False


def _item_annotation(declared: Any) -> Any:
    """The item type of a list, tuple or set ``declared`` types, else ``None``."""
    tp, _ = _unwrap_optional(declared)
    args = get_args(tp)
    return args[0] if get_origin(tp) in (list, tuple, set, frozenset) and args else None


@lru_cache(maxsize=1024)
def _stored_key_reading(key: str) -> tuple[Any, bool | None, bool]:
    """How a stored row is read: a catalogue key (``core.<path>``) as the model declares
    ``<path>``, a key no model declares (a plugin's block) by its name."""
    if not key.startswith("core."):
        return None, None, False
    reading: tuple[Any, bool | None, bool] = (Settings, None, False)
    for part in key.removeprefix("core.").split("."):
        if reading[0] is None:
            return None, None, False
        reading = _member_reading(reading[0], part)
    return reading


def _identifiers(value: Any) -> list[str]:
    """The names a declared identifier field holds: one, or each of a list of them."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple):
        return [item for item in value if isinstance(item, str)]
    return []


# How ``configured_secret_values`` reads a source passed to it: a plain map as a
# map of stored rows (``SettingsService.load_overrides``), each key a catalogue
# key where it is one (:func:`_stored_key_reading`), any other key by its name.
_STORED_ROWS = object()


def configured_secret_values(*sources: Any) -> set[str]:
    """Every secret-kind value the given settings hold, as the platform would send it.

    What is secret is this catalogue's own secret kind — a ``SecretStr``, or a
    field named in ``_SECRET_NAMES`` — plus the password inside a service URL
    (``database_url``, ``redis_url``) and an entry of a mapping whose key names
    a credential (a tool server's ``env`` or ``headers``). A header value that
    begins with an authorization scheme contributes what follows the scheme as
    well. Nothing else is collected: a field or a key that merely mentions a
    credential (``max_tokens``, ``AUTH_MODE``, ``TOKEN_LIMIT``) holds no secret
    (``names_a_credential_value``), and the REST sandbox's JSONPath maps are not
    read. A stored map is read as the model declares it, so a field the model
    holds to a name pattern (a stage's ``key``) is no credential, and a name
    the settings give something (a mapping key: a server, an agent, a profile;
    a stage's key; a setting's own name) is never returned, wherever it stands
    (T-506). The scrub masks these values by exact value
    (``pipeline.events.remember_secret_values``).
    """
    from maljan.core.settings_masking import bare_addresses

    found: set[str] = set()
    names: set[str] = set()
    # What the catalogue types a secret (a ``SecretStr``, a field named in
    # ``_SECRET_NAMES``): held whatever it reads as, a name included.
    typed: set[str] = set()

    def _add(value: str, exact: bool = False) -> None:
        text = str(value or "")
        if not text.strip() or text.strip().isdigit():
            return
        if text.strip().lower() in _NOT_A_SECRET_VALUE:
            return
        into = typed if exact else found
        into.add(text)
        lowered = text.lower()
        for scheme in _SCHEME_PREFIX:
            if lowered.startswith(scheme) and text[len(scheme) :].strip():
                into.add(text[len(scheme) :].strip())

    def _walk(
        value: Any, name: str, named_secret: bool, declared: Any = None, exact: bool = False
    ) -> None:
        if isinstance(value, SecretStr):
            _add(value.get_secret_value(), exact=True)
        elif isinstance(value, BaseModel):
            fields = dict(type(value).model_fields)
            for key, field in fields.items():
                names.add(key)
                if key in _FIELD_MAPS:
                    continue
                item = getattr(value, key, None)
                if isinstance(item, str) and _names_an_identifier(field):
                    names.add(item)
                named = key in _SECRET_NAMES
                _walk(item, key, named, field.annotation, exact=named)
            # A model that keeps extra keys holds blocks no field declares: a
            # plugin's ``llm.<id>`` or ``memory.<id>`` settings, read with its
            # own settings model or kept as stored. Their keys are read as a
            # field's are, so a plugin's credential is scrubbed like a shipped one.
            for key, item in (getattr(value, "__pydantic_extra__", None) or {}).items():
                name = str(key)
                names.add(name)
                _walk(
                    item,
                    name,
                    name in _SECRET_NAMES or names_a_credential_value(name),
                    exact=name in _SECRET_NAMES,
                )
        elif isinstance(value, dict):
            # A stored map is read as the model declares it (a stored row by
            # its catalogue key): a declared field is a secret only where the
            # model reads it as one, so a stage's ``key`` is its name, never a
            # credential. An entry nothing declares is read by its name.
            for key, item in value.items():
                text = str(key)
                names.add(text)
                names.update(text.split("."))
                if declared is _STORED_ROWS:
                    annotation, declared_secret, identifier = _stored_key_reading(text)
                else:
                    annotation, declared_secret, identifier = _member_reading(declared, text)
                if identifier:
                    names.update(_identifiers(item))
                if declared_secret is None:
                    held = names_a_credential_value(text)
                else:
                    held = declared_secret
                exact = text in _SECRET_NAMES or (
                    declared_secret is not None and _unwrap_optional(annotation)[0] is SecretStr
                )
                _walk(item, text, held, annotation, exact=exact)
        elif isinstance(value, list | tuple | set):
            for item in value:
                _walk(item, name, named_secret, _item_annotation(declared), exact)
        elif isinstance(value, str):
            if named_secret:
                _add(value, exact)
            else:
                if "://" in value:
                    for secret in _url_secrets(value):
                        _add(secret)
                # Each word that is an address written with no scheme is read
                # as one with it (``settings_masking.bare_addresses``); the
                # rest of a free-text value holds no address.
                for address in bare_addresses(value):
                    for secret in _bare_secrets(address):
                        _add(secret)

    for source in sources:
        _walk(source, "", False, _STORED_ROWS)
    # A name the settings give something (a server, an agent, a profile, a
    # stage, a setting) is never a credential, wherever a key misreads it;
    # what the catalogue types a secret is one whatever it reads as.
    return (found - names) | typed


def _kept_as_a_secret(text: str) -> bool:
    """Whether ``text`` is a value to mask, by ``configured_secret_values``'s own rules.

    Blank, a number and a switch (``true``, ``off``) are settings whatever
    their key says.
    """
    stripped = text.strip()
    return bool(stripped) and not stripped.isdigit() and stripped.lower() not in _NOT_A_SECRET_VALUE


def _userinfo_forms(text: str) -> list[str]:
    """The ``user:password`` userinfo of each address ``text`` carries, as written and decoded.

    A URL with a scheme and an address written with no scheme
    (``settings_masking.bare_addresses``) alike; a user name alone is not
    one (``configured_secret_values`` reads a token there by its shape).
    """
    from urllib.parse import unquote, urlsplit

    from maljan.core.settings_masking import bare_addresses, bare_userinfo, url_spans

    found: list[str] = []
    for start, end in url_spans(text) if "://" in text else []:
        try:
            netloc = urlsplit(text[start:end]).netloc
        except ValueError:
            continue
        userinfo = netloc.rpartition("@")[0]
        if ":" in userinfo:
            found.extend(dict.fromkeys((userinfo, unquote(userinfo))))
    for address in bare_addresses(text):
        parts = bare_userinfo(address)
        if parts is not None and ":" in parts[0]:
            found.extend(dict.fromkeys((parts[0], unquote(parts[0]))))
    return found


def shown_secret_values(*sources: Any) -> set[str]:
    """Every value the given settings hold that no reader may see in shown text (T-482).

    What the event scrub masks by value (:func:`configured_secret_values`:
    every ``SecretStr``, a field named in ``_SECRET_NAMES``, a mapping entry
    whose key names a credential, the password and credential-named query
    values of every stored URL), and beside it the ``user:password`` userinfo
    of every stored address as one value, so its encoded forms are found
    whole. A tool server's ``env`` entry is one only where its name names a
    credential (``UPSTREAM_TOKEN``): a bind address or a home directory there
    is no secret by value, though the snapshot and the console still hide
    every ``env`` value where it stands (``settings_masking.masked_server``).
    ``sources`` are settings models or stored override maps
    (``SettingsService.load_overrides``, where a source's ``api_key`` and a
    server's ``env`` sit in plain maps);
    nothing is read by a tool's or a source's name. The values are returned,
    never logged. Without recursion, so a stored value nested at any depth is read.
    """
    found = configured_secret_values(*sources)
    stack: list[Any] = list(sources)
    while stack:
        value = stack.pop()
        if isinstance(value, SecretStr):
            continue
        if isinstance(value, BaseModel):
            items: list[tuple[Any, Any]] = [
                (key, getattr(value, key, None))
                for key in type(value).model_fields
                if key not in _FIELD_MAPS
            ]
            items.extend((getattr(value, "__pydantic_extra__", None) or {}).items())
        elif isinstance(value, Mapping):
            items = list(value.items())
        elif isinstance(value, list | tuple | set | frozenset):
            stack.extend(value)
            continue
        elif isinstance(value, str):
            found.update(form for form in _userinfo_forms(value) if _kept_as_a_secret(form))
            continue
        else:
            continue
        stack.extend(item for _key, item in items)
    return found
