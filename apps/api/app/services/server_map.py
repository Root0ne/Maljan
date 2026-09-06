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

import re
from typing import Any, get_args

from maljan.core.config import (
    BUILTIN_SERVER_KEYS,
    RESERVED_SERVER_KEYS,
    SERVER_KEY_PATTERN,
    AgentRole,
    MCPServerConfig,
    _builtin_servers,
)
from pydantic import ValidationError

SERVER_MAP_KEY = "core.mcp.servers"
# What a set token looks like from outside. Identical to pydantic's own
# SecretStr JSON rendering, so a value read out of a snapshot and one read out
# of this endpoint say the same thing. This is the one place the mask is
# defined; ``settings_probes.py`` imports it rather than keeping its own copy.
TOKEN_MASK = "**********"

_KEY_RE = re.compile(SERVER_KEY_PATTERN)
_ROLES = set(get_args(AgentRole))


def server_token_key(server: str) -> str:
    """The settings key one server's token is stored under.

    Deliberately shaped like a catalog key without being one: the catalog is a
    static list and cannot contain a name an operator invents at runtime, so
    ``SettingsService`` handles these rows itself rather than through
    ``check_keys``. Nothing else in the system may write a key of this shape.
    """
    return f"{SERVER_MAP_KEY}.{server}.auth_token"


class ServerMapError(Exception):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


def validate_server_map(value: Any, *, stored: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return the map to store, or raise with one message per offending key."""
    errors: dict[str, str] = {}
    if not isinstance(value, dict):
        raise ServerMapError({"": "the server map must be an object keyed by server name"})

    out: dict[str, Any] = {}
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
        for role in entry.get("agents") or []:
            if role not in _ROLES:
                errors[f"{key}.agents"] = (
                    f"{role!r} is not an analyst; expected one of {', '.join(sorted(_ROLES))}"
                )
        try:
            # The token is validated and stored separately (``split_server_secrets``);
            # blanking it here keeps it out of the JSON row under every path.
            model = MCPServerConfig.model_validate({**entry, "auth_token": ""})
        except ValidationError as exc:
            for err in exc.errors():
                errors[f"{key}." + ".".join(str(p) for p in err["loc"])] = err["msg"]
            continue
        if model.transport == "stdio" and not model.command:
            errors[f"{key}.command"] = "a stdio server needs a command to launch"
        if model.transport != "stdio" and not model.url:
            errors[f"{key}.url"] = "an http server needs a URL"
        dumped = model.model_dump(mode="json")
        dumped.pop("auth_token", None)
        out[key] = dumped

    if errors:
        raise ServerMapError(errors)

    # A built-in the body left out is re-seeded rather than removed: the
    # settings model would put it back on the next load anyway, and a stored
    # map missing it would silently discard the operator's own edits to it.
    for key, default in _builtin_servers().items():
        if key not in out:
            entry = default.model_dump(mode="json")
            entry.pop("auth_token", None)
            out[key] = entry
    return out


def split_server_secrets(
    value: Any, *, stored: dict[str, Any] | None = None
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
    cleaned = validate_server_map(value, stored=stored)
    tokens: dict[str, str | None] = {}
    for key, entry in (value or {}).items():
        if not isinstance(entry, dict) or "auth_token" not in entry:
            continue
        token = entry["auth_token"]
        if token == TOKEN_MASK:
            continue
        tokens[key] = str(token) if token else None
    return cleaned, tokens


def merge_server_secrets(overrides: dict[str, Any]) -> dict[str, Any]:
    """Fold the per-server token rows back into the map, and drop them.

    Done here rather than by letting both key shapes reach ``nest()``: that
    function walks a flat mapping in iteration order, so a ``core.mcp.servers``
    entry arriving after ``core.mcp.servers.x.auth_token`` would overwrite the
    token instead of merging with it. Making the merge explicit makes it
    order-independent, which is the only version of this that is safe.
    """
    prefix = f"{SERVER_MAP_KEY}."
    token_keys = [k for k in overrides if k.startswith(prefix) and k.endswith(".auth_token")]
    if not token_keys:
        return overrides
    out = {k: v for k, v in overrides.items() if k not in token_keys}
    servers = out.get(SERVER_MAP_KEY)
    if not isinstance(servers, dict):
        return out
    merged = {name: dict(entry) for name, entry in servers.items() if isinstance(entry, dict)}
    for key in token_keys:
        name = key[len(prefix) : -len(".auth_token")]
        if name in merged:
            merged[name]["auth_token"] = overrides[key]
        # A row whose server is gone is simply dropped: `save` deletes these,
        # and a stale one must never resurrect a server that is not in the map.
    out[SERVER_MAP_KEY] = merged
    return out
