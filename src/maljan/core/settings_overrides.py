"""Layer database overrides over the environment.

Overrides are dotted paths (``llm.openai.base_url``). ``build_settings`` nests
them and passes them to ``Settings(**nested)``; pydantic-settings deep-merges
init kwargs with the environment and dotenv sources, so an overridden
``llm.openai.base_url`` keeps an ``LLM__OPENAI__API_KEY`` from ``.env``
(verified against the real model on 2026-09-02). Precedence is therefore
``UI > env > default`` with no code of its own.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any, Literal

from pydantic import BaseModel

from maljan.core.config import Settings

CORE_NS = "core"
API_NS = "api"
Source = Literal["ui", "env", "default"]


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
    return Settings(**nest(core_overrides))


def effective_source(*, overridden: bool, env_value: Any, default_value: Any) -> Source:
    if overridden:
        return "ui"
    return "env" if env_value != default_value else "default"


def public_snapshot(settings: Settings, secret_keys: Iterable[str]) -> dict[str, Any]:
    secrets = set(secret_keys)
    snap = flatten(settings.model_dump(mode="json"))
    for key in list(snap):
        if key in secrets:
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
