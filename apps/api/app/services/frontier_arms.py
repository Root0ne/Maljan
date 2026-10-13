"""Where a frontier comparison arm's API key is stored, and how it travels.

``core.llm.frontier.arms`` is one catalog leaf holding a whole map of arms,
each with its own endpoint, pricing -- and its own bearer credential. The map
is stored as a single *non-secret* JSONB row, so a key left inside it sits in
the database in clear text beside values the UI echoes back; the legacy import
wrote exactly that (walkthrough finding W3).

The keys are therefore split out on the way in and folded back on the way out
(``nested_secrets.NestedSecretMap``), the same way ``server_map`` handles
``core.mcp.servers.<name>.auth_token``: ``split_arm_secrets`` returns the map
to store and the keys to encrypt, ``SettingsService.save`` writes one
``is_secret`` row per arm, and ``merge_arm_secrets`` puts them back when the
effective overrides are assembled.
"""

from __future__ import annotations

from typing import Any

from app.services.nested_secrets import NestedSecretMap

ARMS_KEY = "core.llm.frontier.arms"
ARMS = NestedSecretMap(ARMS_KEY, "api_key")


def arm_key_key(arm: str) -> str:
    """The settings key one arm's API key is stored under."""
    return ARMS.row_key(arm)


def split_arm_secrets(
    value: Any, *, stored: dict[str, Any] | None = None
) -> tuple[Any, dict[str, str | None]]:
    """Separate the per-arm API keys from the map that gets stored (``NestedSecretMap.split``)."""
    return ARMS.split(value, stored=stored)


def merge_arm_secrets(overrides: dict[str, Any]) -> dict[str, Any]:
    """Fold the per-arm key rows back into the map, and drop them (``NestedSecretMap.merge``)."""
    return ARMS.merge(overrides)


def masked_arms(stored_map: dict[str, Any], rows: dict[str, Any]) -> dict[str, Any]:
    """The map as the UI may see it: every key a mask, never a value."""
    return ARMS.masked(stored_map, rows)
