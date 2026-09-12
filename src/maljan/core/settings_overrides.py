"""Build the application's core settings from the store and defaults only.

Overrides are dotted paths (``llm.openai.base_url``). ``build_settings`` nests
them and passes them to ``Settings(**nested)`` with the module-level
``STORE_ONLY`` flag set, which drops the environment, ``.env``, and secrets
directory sources for that one construction (see
``maljan.core.config.Settings.settings_customise_sources``). Precedence is
therefore ``UI > default`` — the environment is no longer a layer for the
application. The bare ``Settings()`` constructor is unaffected by this
module and stays environment- and dotenv-capable; it is a documented library
behaviour, relied on by the legacy one-shot environment import.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel

from maljan.core.config import STORE_ONLY, Settings

CORE_NS = "core"
API_NS = "api"
Source = Literal["ui", "default"]


def split_key(key: str) -> tuple[str, str]:
    ns, sep, path = key.partition(".")
    if not sep or ns not in (CORE_NS, API_NS) or not path:
        raise ValueError(f"settings key must be '<core|api>.<path>', got {key!r}")
    return ns, path


def nest(flat: Mapping[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in flat.items():
        cursor = out
        parts = key.split(".")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
            if not isinstance(cursor, dict):
                raise ValueError(f"{key!r} descends into a non-mapping at {part!r}")
        cursor[parts[-1]] = value
    return out


def flatten(obj: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """Nested mapping -> dotted keys. Every mapping is structure; see flatten_leaves."""
    out: dict[str, Any] = {}
    for k, v in obj.items():
        path = f"{prefix}{k}"
        if isinstance(v, Mapping):
            out.update(flatten(v, path + "."))
        else:
            out[path] = v
    return out


def flatten_leaves(model: BaseModel, leaf_keys: Iterable[str]) -> dict[str, Any]:
    """Values for exactly ``leaf_keys`` from a model instance, JSON-serialisable.

    Nested models are walked attribute by attribute; a leaf that is itself a
    mapping (``llm.agents``, ``react_agent_timeout_overrides``) is returned
    whole, which is what ``flatten`` alone would not do.
    """
    dumped = model.model_dump(mode="json")
    out: dict[str, Any] = {}
    for key in leaf_keys:
        cursor: Any = dumped
        for part in key.split("."):
            cursor = cursor[part]
        out[key] = cursor
    return out


def build_settings(core_overrides: Mapping[str, Any]) -> Settings:
    """The application's core settings: ``core_overrides`` over model defaults.

    Store-only: the environment, ``.env``, and any secrets directory are
    never consulted, regardless of what is set in the process. This is the
    only construction path the application (API, worker) may use — see
    ``tests/unit/test_no_bare_settings_in_app.py``.
    """
    token = STORE_ONLY.set(True)
    try:
        return Settings(**nest(core_overrides))
    finally:
        STORE_ONLY.reset(token)


def effective_source(*, overridden: bool) -> Source:
    return "ui" if overridden else "default"


# ``mcp.servers.<key>.env.<VAR>`` after flattening: an open-ended mapping an
# admin fills in, and the natural place for a server's own credential (a token
# a sidecar reads from its environment).
_SERVER_ENV_VALUE = re.compile(r"^mcp\.servers\.[^.]+\.env\.")


def public_snapshot(settings: Settings, secret_keys: Iterable[str]) -> dict[str, Any]:
    """The settings as they ran, with nothing in them a reader may not see.

    ``secret_keys`` names the leaves typed as secrets. To those this adds
    the one place a credential can live without being typed as one: a
    server's ``env`` map. This snapshot reaches the job owner
    through ``run_summary.settings_snapshot``, so every value under such a map
    is masked. The variable names stay -- an operator debugging a server needs
    to see what it was handed -- and only the values go.
    """
    secrets = set(secret_keys)
    snap = flatten(settings.model_dump(mode="json"))
    for key in list(snap):
        if key in secrets or _SERVER_ENV_VALUE.match(key):
            snap[key] = "***" if snap[key] else None
    return snap


# Everything between "://" and the LAST "@" before the path is userinfo. Greedy
# on purpose: a password may itself contain "@" or ":" and the username may be
# empty (redis://:password@host is the usual Redis AUTH shape).
_CREDENTIAL_IN_URL = re.compile(r"(://)[^\s/@]*(?:@[^\s/@]*)*@")


def redact_url(text: str) -> str:
    """Mask any ``scheme://user:pass@`` credential in ``text`` before it is shown.

    Applied to free text (a driver's error message, a config value echoed
    back), not only to values known to be URLs.
    """
    return _CREDENTIAL_IN_URL.sub(r"\1***@", text)
