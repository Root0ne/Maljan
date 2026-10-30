"""What an admin may write into ``core.mcp.servers``, and where its tokens go.

The registry is one catalog leaf holding a whole map, so the settings
service's per-key checks (editable, secret, type) cannot see inside it. These
are the checks that belong inside: the key is a slug and not one of the names
the code reserves, every entry validates as an ``MCPServerConfig``, and a
built-in is disabled rather than deleted.

The tokens are the interesting part. The map is stored as one *non-secret*
JSONB row, so a token left inside it would sit in the database in clear text
beside values the UI echoes back. It is therefore split out on the way in and
put back on the way out: ``split_server_secrets`` returns the map to store and
the tokens to encrypt, ``SettingsService.save`` writes one ``is_secret`` row
per server, and ``merge_server_secrets`` folds them back in when the effective
overrides are assembled. The value an operator sees is always the mask, and
the mask coming back in an unchanged PATCH means exactly that — unchanged —
rather than a token whose literal characters are ten asterisks.
"""

from __future__ import annotations

import json
import re
from typing import Any

from maljan.core.config import (
    BUILTIN_SERVER_KEYS,
    RESERVED_SERVER_KEYS,
    SERVER_KEY_PATTERN,
    MCPServerConfig,
    _builtin_definitions,
    _builtin_servers,
    builtin_env_allow,
)
from maljan.core.settings_overrides import (
    SERVER_MAP_PATH,
    server_entry_in_force,
    shipped_tool_facts,
    shipped_tools,
)
from maljan.core.tool_declarations import (
    changed_declaration_errors,
    check_own_prefix,
    fill_declaration,
    holds_changes,
    kept_stored_changes,
    merge_tool_facts,
    sent_names_refusal,
    settled_trust,
    shown_trust,
    stored_changes,
    strip_declaration_defaults,
    with_mark,
    without_mark,
)
from pydantic import ValidationError

SERVER_MAP_KEY = "core.mcp.servers"
# What a set token looks like from outside. Identical to pydantic's own
# SecretStr JSON rendering, so a value read out of a snapshot and one read out
# of this endpoint say the same thing. This is the one place the mask is
# defined; ``settings_probes.py`` imports it rather than keeping its own copy.
TOKEN_MASK = "**********"

_KEY_RE = re.compile(SERVER_KEY_PATTERN)


def _definition_keys(stored: dict[str, Any] | None) -> set[str]:
    """Every agent a server may be bound to, from the map the operator has.

    A server's ``agents`` list used to be a Literal of four roles; it is now a
    list of definition keys, so what is valid depends on settings the operator
    can change in the same session. The stored ``core.agents.definitions``
    override wins where it exists, and the built-in seeds supply the rest —
    the same layering ``AgentsConfig`` itself does on load.
    """
    keys = set(_builtin_definitions())
    definitions = (stored or {}).get("core.agents.definitions")
    if isinstance(definitions, dict):
        keys |= {str(k) for k in definitions}
    return keys


def server_token_key(server: str) -> str:
    """The settings key one server's token is stored under.

    Deliberately shaped like a catalog key without being one: the catalog is a
    static list and cannot contain a name an operator invents at runtime, so
    ``SettingsService`` handles these rows itself rather than through
    ``check_keys``. Nothing else in the system may write a key of this shape.
    """
    return f"{SERVER_MAP_KEY}.{server}.auth_token"


# The suffix of the row one server's ``env`` map is stored under, encrypted.
SERVER_ENV_SUFFIX = ".env"


def server_env_key(server: str) -> str:
    """The settings key one server's ``env`` map is stored under, as :func:`server_token_key`.

    The ``env`` map is where a server's own credentials live (an API key the
    sidecar reads from its environment), so it is kept out of the map's clear
    row like the token: one encrypted row per server holding its whole map.
    """
    return f"{SERVER_MAP_KEY}.{server}{SERVER_ENV_SUFFIX}"


def split_server_env(servers: Any) -> tuple[Any, dict[str, str | None]]:
    """The validated map without its ``env`` values, and each server's env to encrypt.

    The second element says, for every server of the map, what its env row
    holds after the save: the JSON of a non-empty ``env`` map, or ``None`` for
    no row. An empty ``env`` stays in the map as written, so the stored map and
    what :func:`merge_server_secrets` folds back together read exactly as the
    map that went in.
    """
    if not isinstance(servers, dict):
        return servers, {}
    out: dict[str, Any] = {}
    envs: dict[str, str | None] = {}
    for name, entry in servers.items():
        env = entry.get("env") if isinstance(entry, dict) else None
        if isinstance(env, dict) and env:
            out[name] = {k: v for k, v in entry.items() if k != "env"}
            envs[name] = json.dumps(env, sort_keys=True)
        else:
            out[name] = entry
            envs[name] = None
    return out, envs


def env_of_row(row_value: Any) -> dict[str, Any] | None:
    """A server's env map from its decrypted row, or ``None`` when it is not one."""
    try:
        env = json.loads(str(row_value))
    except ValueError:
        return None
    return env if isinstance(env, dict) else None


# The fields of a stored entry its trust in its server's own declaration is read from.
_TRUST_FIELDS = (
    "transport",
    "command",
    "args",
    "cwd",
    "url",
    "env",
    "env_allow",
    "trusts_served_declaration",
    "trust_granted_for",
)


def shown_trust_of(key: str, entry: Any) -> dict[str, Any]:
    """A stored entry's trust in its server's own declaration as the console shows it.

    In force (``tool_declarations.shown_trust``): a built-in pointed at
    another server shows no trust its shipped value no longer gives it, and a
    trusted entry carries the launch its trust holds for, which a save of the
    entry unchanged sends back (``tool_declarations.settled_trust``). An entry
    that trusts nothing and never set the flag is shown without it, so a save
    of it unchanged stores no flag and the block keeps following what ships.
    Empty for an entry that does not read as a block (shown as stored).
    """
    if not isinstance(entry, dict):
        return {}
    held = {name: entry[name] for name in _TRUST_FIELDS if name in entry}
    try:
        cfg = MCPServerConfig.model_validate(held)
    except ValidationError:
        return {}
    builtin = _builtin_servers().get(key)
    if builtin is not None:
        fill_declaration(cfg, builtin)
    shown = shown_trust(f"mcp:{key}", cfg)
    if shown["trust_granted_for"] is None:
        shown.pop("trust_granted_for")
    if not shown["trusts_served_declaration"] and "trusts_served_declaration" not in entry:
        shown.pop("trusts_served_declaration")
    return shown


class ServerMapError(Exception):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def validate_server_map(
    value: Any,
    *,
    stored: dict[str, Any] | None = None,
    stored_settings: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Return the map to store, or raise with one message per offending key."""
    errors: dict[str, str] = {}
    if not isinstance(value, dict):
        raise ServerMapError({"": "the server map must be an object keyed by server name"})

    out: dict[str, Any] = {}
    builtins = _builtin_servers()
    for key, entry in value.items():
        if not _KEY_RE.match(str(key)):
            errors[str(key)] = (
                "a server name is lowercase, starts with a letter, and is at most 32 "
                "characters of letters, digits, '-' or '_'"
            )
            continue
        known = set(stored or {}) | set(BUILTIN_SERVER_KEYS)
        if key in RESERVED_SERVER_KEYS and key not in BUILTIN_SERVER_KEYS and key not in known:
            errors[key] = f"{key!r} is reserved for a provider-owned server"
            continue
        if not isinstance(entry, dict):
            errors[key] = "a server entry must be an object"
            continue
        roles = _definition_keys(stored_settings)
        for role in entry.get("agents") or []:
            if role not in roles:
                errors[f"{key}.agents"] = (
                    f"{role!r} is not a known agent; expected one of {', '.join(sorted(roles))}"
                )
        # The entry's tool declarations are its changes over what the server
        # ships, one tool at a time (``tool_declarations.tool_facts_changes``):
        # they are checked and validated as they are in force. The ones this
        # save adds or changes are an operator's edit and are held to the
        # strict rules; one it leaves as stored or shipped is read as it always
        # was (leniently, below), so a stored entry never blocks an unrelated
        # save.
        facts_in = entry.get("tool_facts")
        stored_facts: Any = None
        kept: dict[str, Any] = {}
        if isinstance(facts_in, dict):
            shipped = shipped_tool_facts(f"{SERVER_MAP_PATH}.{key}")
            stored_entry = (stored or {}).get(key)
            stored_facts = (
                stored_entry.get("tool_facts") if isinstance(stored_entry, dict) else None
            )
            stored_in_force = (
                server_entry_in_force(key, stored_entry)["tool_facts"]
                if isinstance(stored_facts, dict)
                else None
            )
            # A sent map is read as every path reads one
            # (``tool_declarations.sent_in_force``): marked, as the entry's
            # changes over what the server ships, so a shipped tool it leaves
            # out stays as shipped and only ``null`` removes one; without the
            # mark, whole, as an earlier release read it. A map sent back
            # exactly as stored therefore says what the stored one says. A
            # tool sent with its stored change exactly as stored, where this
            # release refuses that change, is not this save's edit: it is kept
            # as stored and left out of every check (``kept_stored_changes``).
            incoming = stored_changes(facts_in, shipped)
            kept = kept_stored_changes(incoming, stored_facts, shipped, server=key)
            # Every name of the map as sent is checked before it is merged,
            # which drops a ``null`` entry: a refused name sent as ``null`` is
            # refused here, naming the entry, as on a provider leaf.
            refusal = sent_names_refusal(facts_in, kept, server=key)
            if refusal:
                errors[f"{key}.tool_facts"] = refusal
                continue
            in_force = merge_tool_facts(
                shipped, {tool: change for tool, change in incoming.items() if tool not in kept}
            )
            entry = {**entry, "tool_facts": in_force}
            before: list[Any] = [stored_in_force, shipped]
            # An ``aggregate_of`` names a tool the map declares or the entry's
            # allow-list in force names: sent, else stored, else shipped, as a load reads it.
            if "tools" in entry:
                listed = entry.get("tools")
            elif isinstance(stored_entry, dict) and "tools" in stored_entry:
                listed = stored_entry.get("tools")
            else:
                listed = shipped_tools(f"{SERVER_MAP_PATH}.{key}")
            refused = changed_declaration_errors(
                in_force, before, tools=listed if isinstance(listed, list) else None
            )
            if refused:
                for path, message in refused.items():
                    errors[f"{key}.tool_facts.{path}"] = message
                continue
        try:
            # The token is validated and stored separately (``split_server_secrets``);
            # blanking it here keeps it out of the JSON row under every path.
            model = MCPServerConfig.model_validate({**entry, "auth_token": ""})
        except ValidationError as exc:
            for err in exc.errors():
                errors[f"{key}." + ".".join(str(p) for p in err["loc"])] = err["msg"]
            continue
        try:
            check_own_prefix(key, model.tool_facts)
            for pattern in model.error_patterns:
                check_own_prefix(key, pattern.tools)
        except ValueError as exc:
            errors[f"{key}.tool_facts"] = str(exc)
            continue
        if model.transport == "stdio" and not model.command:
            errors[f"{key}.command"] = "a stdio server needs a command to launch"
        if model.transport != "stdio" and not model.url:
            errors[f"{key}.url"] = "an http server needs a URL"
        builtin = builtins.get(key)
        if builtin is not None:
            # A declaration field the entry left out is the built-in's, as on
            # load; one equal to the built-in's is then not stored, so the row
            # keeps following the shipped declaration and only an operator's
            # own value (an empty one included) is written down.
            fill_declaration(model, builtin)
        dumped = model.model_dump(mode="json")
        dumped.pop("auth_token", None)
        # The trust in the server's own declaration is the operator's only where
        # they gave it, and only for the server the block points at
        # (``tool_declarations.settled_trust``): a shipped trust posted back by a
        # block pointed elsewhere, or a granted one carried through a repoint,
        # is never stored as a grant.
        dumped.update(settled_trust(f"mcp:{key}", model, entry.get("trust_granted_for")))
        if builtin is not None:
            dumped = strip_declaration_defaults(dumped, builtin)
        if not dumped.get("trust_granted_for"):
            dumped.pop("trust_granted_for", None)
        if isinstance(facts_in, dict):
            if facts_in == stored_facts and holds_changes(stored_facts):
                # Sent back as stored: stored as it was, a change this release
                # leaves out of what is in force (``stored_in_force``) included,
                # so an unrelated save never drops the operator's change.
                dumped["tool_facts"] = stored_facts
            else:
                # Stored marked as changes (a server that ships nothing: its
                # whole map), with each tool kept as stored put back as it was.
                changes = without_mark(dumped.get("tool_facts") or {})
                changes.update(kept)
                if changes:
                    dumped["tool_facts"] = with_mark(changes)
        if key in BUILTIN_SERVER_KEYS:
            # The row an operator saves is the one every later load starts
            # from, so the names the sidecar cannot run without are written
            # into it rather than left for the settings model to repair on each
            # read (``builtin_env_allow``). What the editor shows afterwards is
            # then what the sidecar is really started with. A shipped default
            # that is not required — the threat-intel API keys — stays removed
            # once an admin has taken it out.
            dumped["env_allow"] = builtin_env_allow(key, dumped.get("env_allow") or [])
        out[key] = dumped

    if errors:
        raise ServerMapError(errors)

    # A built-in the body left out is re-seeded rather than removed: the
    # settings model would put it back on the next load anyway, and a stored
    # map missing it would silently discard the operator's own edits to it.
    for key, default in builtins.items():
        if key not in out:
            entry = default.model_dump(mode="json")
            entry.pop("auth_token", None)
            entry.pop("trust_granted_for", None)
            out[key] = strip_declaration_defaults(entry, default)
    return out


def split_server_secrets(
    value: Any,
    *,
    stored: dict[str, Any] | None = None,
    stored_settings: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, str | None]]:
    """Validate the map, and separate the tokens from what gets stored in it.

    The second element is an *instruction set*, not a state: a server appears
    in it only when the incoming entry actually said something about its
    token. A non-empty string means "store this"; ``None`` (from an explicit
    ``null`` or an empty string) means "delete the row"; the mask means "leave
    it alone", and so does an entry that never mentions ``auth_token`` at all.
    That distinction is what lets the editor round-trip a masked value without
    overwriting the real one with ten asterisks.
    """
    value = _keep_masked_env(value, stored)
    cleaned = validate_server_map(value, stored=stored, stored_settings=stored_settings)
    tokens: dict[str, str | None] = {}
    for key, entry in (value or {}).items():
        if not isinstance(entry, dict) or "auth_token" not in entry:
            continue
        token = entry["auth_token"]
        if token == TOKEN_MASK:
            continue
        tokens[key] = str(token) if token else None
    return cleaned, tokens


def _keep_masked_env(value: Any, stored: dict[str, Any] | None) -> Any:
    """An ``env`` value that arrives as the mask keeps whatever is stored.

    The JSON export masks every ``env`` value (that map is where a
    server's own credential lives), so importing the document back must not
    write ten asterisks into the variable. A mask with nothing stored behind
    it is dropped rather than stored -- it names a value this deployment never
    had.
    """
    if not isinstance(value, dict):
        return value
    out: dict[str, Any] = {}
    for name, entry in value.items():
        env = entry.get("env") if isinstance(entry, dict) else None
        if not isinstance(env, dict) or TOKEN_MASK not in env.values():
            out[name] = entry
            continue
        stored_entry = (stored or {}).get(name)
        stored_env = stored_entry.get("env") if isinstance(stored_entry, dict) else {}
        stored_env = stored_env if isinstance(stored_env, dict) else {}
        kept = {
            var: (stored_env.get(var) if item == TOKEN_MASK else item)
            for var, item in env.items()
            if item != TOKEN_MASK or var in stored_env
        }
        out[name] = {**entry, "env": kept}
    return out


def merge_server_secrets(overrides: dict[str, Any]) -> dict[str, Any]:
    """Fold the per-server token and env rows back into the map, and drop them.

    Done here rather than by letting both key shapes reach ``nest()``: that
    function walks a flat mapping in iteration order, so a ``core.mcp.servers``
    entry arriving after ``core.mcp.servers.x.auth_token`` would overwrite the
    token instead of merging with it. Making the merge explicit makes it
    order-independent, which is the only version of this that is safe.
    """
    prefix = f"{SERVER_MAP_KEY}."
    token_keys = [k for k in overrides if k.startswith(prefix) and k.endswith(".auth_token")]
    env_keys = [k for k in overrides if k.startswith(prefix) and k.endswith(SERVER_ENV_SUFFIX)]
    out = {k: v for k, v in overrides.items() if k not in token_keys and k not in env_keys}
    servers = out.get(SERVER_MAP_KEY)
    if not isinstance(servers, dict):
        return out
    merged = {name: dict(entry) for name, entry in servers.items() if isinstance(entry, dict)}
    # A mask carried inside the composite is a placeholder, never a credential:
    # it must not reach a job as the literal bearer token.
    for entry in merged.values():
        if entry.get("auth_token") == TOKEN_MASK:
            entry.pop("auth_token", None)
    for key in token_keys:
        name = key[len(prefix) : -len(".auth_token")]
        if name in merged:
            merged[name]["auth_token"] = overrides[key]
        # A row whose server is gone is simply dropped: `save` deletes these,
        # and a stale one must never resurrect a server that is not in the map.
    for key in env_keys:
        name = key[len(prefix) : -len(SERVER_ENV_SUFFIX)]
        env = env_of_row(overrides[key])
        if name in merged and env is not None:
            # The encrypted row is the server's env; a map written before the
            # rows existed may still carry one in clear, and the row wins.
            merged[name]["env"] = env
    out[SERVER_MAP_KEY] = merged
    return out
