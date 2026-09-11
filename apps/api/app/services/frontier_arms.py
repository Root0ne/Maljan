"""Where a frontier comparison arm's API key is stored, and how it travels.

``core.llm.frontier.arms`` is one catalog leaf holding a whole map of arms,
each with its own endpoint, pricing -- and its own bearer credential. The map
is stored as a single *non-secret* JSONB row, so a key left inside it sits in
the database in clear text beside values the UI echoes back; the legacy import
wrote exactly that (walkthrough finding W3).

The keys are therefore split out on the way in and folded back on the way out,
the same way ``server_map`` handles ``core.mcp.servers.<name>.auth_token``:
``split_arm_secrets`` returns the map to store and the keys to encrypt,
``SettingsService.save`` writes one ``is_secret`` row per arm, and
``merge_arm_secrets`` puts them back when the effective overrides are
assembled. The composite row never holds a key; what an operator sees is
always the mask, and the mask coming back in an unchanged edit means
"unchanged" rather than a credential whose literal characters are ten
asterisks.
"""

from __future__ import annotations

from typing import Any

from app.services.server_map import TOKEN_MASK

ARMS_KEY = "core.llm.frontier.arms"
_SUFFIX = ".api_key"


def arm_key_key(arm: str) -> str:
    """The settings key one arm's API key is stored under.

    Shaped like a catalog key without being one: the catalog is a static list
    and cannot contain an arm name an operator invents at runtime, so
    ``SettingsService`` writes these rows itself rather than through
    ``check_keys``. Nothing else in the system may write a key of this shape.
    """
    return f"{ARMS_KEY}.{arm}{_SUFFIX}"


def split_arm_secrets(value: Any) -> tuple[Any, dict[str, str | None]]:
    """Separate the per-arm API keys from the map that gets stored.

    The second element is an *instruction set*, not a state: an arm appears in
    it only when the incoming entry actually said something about its key. A
    non-empty string means "store this"; ``None`` (from an explicit ``null``
    or an empty string) means "delete the row"; the mask means "leave it
    alone", and so does an entry that never mentions ``api_key`` at all.
    """
    if not isinstance(value, dict):
        return value, {}
    cleaned: dict[str, Any] = {}
    keys: dict[str, str | None] = {}
    for name, entry in value.items():
        if not isinstance(entry, dict):
            cleaned[name] = entry
            continue
        stripped = {k: v for k, v in entry.items() if k != "api_key"}
        cleaned[name] = stripped
        if "api_key" not in entry:
            continue
        api_key = entry["api_key"]
        if api_key == TOKEN_MASK:
            continue
        keys[str(name)] = str(api_key) if api_key else None
    return cleaned, keys


def merge_arm_secrets(overrides: dict[str, Any]) -> dict[str, Any]:
    """Fold the per-arm key rows back into the map, and drop them.

    Done here rather than by letting both key shapes reach ``nest()``: that
    function walks a flat mapping in iteration order, so a
    ``core.llm.frontier.arms`` entry arriving after
    ``core.llm.frontier.arms.x.api_key`` would overwrite the key instead of
    merging with it. Making the merge explicit makes it order-independent,
    which is the only version of this that is safe.
    """
    prefix = f"{ARMS_KEY}."
    key_rows = [k for k in overrides if k.startswith(prefix) and k.endswith(_SUFFIX)]
    if not key_rows:
        return overrides
    out = {k: v for k, v in overrides.items() if k not in key_rows}
    arms = out.get(ARMS_KEY)
    if not isinstance(arms, dict):
        return out
    merged = {name: dict(entry) for name, entry in arms.items() if isinstance(entry, dict)}
    for key in key_rows:
        name = key[len(prefix) : -len(_SUFFIX)]
        if name in merged:
            merged[name]["api_key"] = overrides[key]
        # A row whose arm is gone is simply dropped: ``save`` deletes these,
        # and a stale one must never resurrect an arm that is not in the map.
    out[ARMS_KEY] = merged
    return out


def masked_arms(stored_map: dict[str, Any], rows: dict[str, Any]) -> dict[str, Any]:
    """The map as the UI may see it: every key a mask, never a value."""
    out: dict[str, Any] = {}
    for name, entry in stored_map.items():
        if not isinstance(entry, dict):
            out[name] = entry
            continue
        shown = {k: v for k, v in entry.items() if k != "api_key"}
        shown["api_key"] = TOKEN_MASK if arm_key_key(name) in rows else None
        out[name] = shown
    return out
