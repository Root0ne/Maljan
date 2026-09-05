"""What an admin may write into the two agent maps, and what a job may pick.

Shaped after ``server_map.py``: one leaf holds a whole map, so the settings
service's per-key checks cannot see inside it, and these are the checks that
belong inside. No secrets live here — a prompt is operator text, not a
credential — so there is no split/merge half, which is the one way this module
is simpler than its sibling.
"""

from __future__ import annotations

from typing import Any

from maljan.core.config import _builtin_definitions, _builtin_profiles

AGENT_DEFINITIONS_KEY = "core.agents.definitions"
AGENT_PROFILES_KEY = "core.agents.profiles"
AGENT_PROFILE_KEY = "core.agents.profile"


def effective_profiles(overrides: dict[str, Any]) -> dict[str, Any]:
    """The profile map as it stands: the stored one over the built-in seeds."""
    out = {name: p.model_dump(mode="json") for name, p in _builtin_profiles().items()}
    stored = overrides.get(AGENT_PROFILES_KEY)
    if isinstance(stored, dict):
        out.update({str(k): v for k, v in stored.items()})
    return out


def effective_definitions(overrides: dict[str, Any]) -> dict[str, Any]:
    """The definition map as it stands: the stored one over the built-in seeds."""
    out = {name: d.model_dump(mode="json") for name, d in _builtin_definitions().items()}
    stored = overrides.get(AGENT_DEFINITIONS_KEY)
    if isinstance(stored, dict):
        out.update({str(k): v for k, v in stored.items()})
    return out
