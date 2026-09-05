"""What an admin may write into the two agent maps, and what a job may pick.

Shaped after ``server_map.py``: one leaf holds a whole map, so the settings
service's per-key checks cannot see inside it, and these are the checks that
belong inside. No secrets live here — a prompt is operator text, not a
credential — so there is no split/merge half, which is the one way this module
is simpler than its sibling.
"""

from __future__ import annotations

import re
from typing import Any

from maljan.core.config import (
    AGENT_KEY_PATTERN,
    BUILTIN_PROFILES,
    AgentDefinition,
    ProfileDefinition,
    Settings,
    _builtin_definitions,
    _builtin_profiles,
)
from pydantic import ValidationError

AGENT_DEFINITIONS_KEY = "core.agents.definitions"
AGENT_PROFILES_KEY = "core.agents.profiles"
AGENT_PROFILE_KEY = "core.agents.profile"

_KEY_RE = re.compile(AGENT_KEY_PATTERN)
_KEY_RULE = (
    "an agent name is lowercase, starts with a letter, and is at most 32 "
    "characters of letters, digits, '-' or '_'"
)


class AgentMapError(Exception):
    def __init__(self, errors: dict[str, str]) -> None:
        super().__init__("; ".join(f"{k}: {v}" for k, v in errors.items()))
        self.errors = errors


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


def _server_allow_lists(overrides: dict[str, Any]) -> dict[str, list[str] | None]:
    """Each effective server's allow-list, so a tool reference can be checked.

    ``None`` for a server that exposes its whole manifest: a name against one of
    those is checked at resolution and degrades there, because what it offers is
    only knowable from a live handshake.
    """
    servers = Settings().mcp.servers
    out: dict[str, list[str] | None] = {
        name: (list(cfg.tools) if cfg.tools is not None else None) for name, cfg in servers.items()
    }
    stored = overrides.get("core.mcp.servers")
    if isinstance(stored, dict):
        for name, entry in stored.items():
            if isinstance(entry, dict):
                tools = entry.get("tools")
                out[str(name)] = list(tools) if isinstance(tools, list) else None
    return out


def validate_definitions(
    value: Any, *, servers: dict[str, list[str] | None] | None = None
) -> dict[str, Any]:
    """Return the definition map to store, or raise with one message per offender."""
    from maljan.providers.registry import static_provider_ids

    if not isinstance(value, dict):
        raise AgentMapError({"": "the definition map must be an object keyed by agent name"})

    allow_lists = servers if servers is not None else {}
    provider_ids = set(static_provider_ids())
    errors: dict[str, str] = {}
    out: dict[str, Any] = {}
    seeds = {name: d.model_dump(mode="json") for name, d in _builtin_definitions().items()}

    for key, entry in value.items():
        name = str(key)
        if not _KEY_RE.match(name):
            errors[name] = _KEY_RULE
            continue
        if not isinstance(entry, dict):
            errors[name] = "an agent entry must be an object"
            continue
        seed = seeds.get(name)
        # Fill in the seed's own values for whatever a built-in override left
        # out, exactly as ``AgentsConfig._merge_builtin_definition_defaults``
        # does at the Settings layer: an operator writing
        # ``{"role": "dynamic", "enabled": False}`` means "flip enabled",
        # not "also blank out the label", and without this the identity
        # check below would see a bare-default label and refuse an edit the
        # operator never made.
        candidate = {**seed, **entry} if seed is not None else entry
        try:
            model = AgentDefinition.model_validate(candidate)
        except ValidationError as exc:
            for err in exc.errors():
                errors[f"{name}." + ".".join(str(p) for p in err["loc"])] = err["msg"]
            continue
        dumped = model.model_dump(mode="json")

        if seed is not None:
            comparable, expected = dict(dumped), dict(seed)
            if name != "judge":
                comparable.pop("enabled", None)
                expected.pop("enabled", None)
            if comparable != expected:
                errors[name] = f"{name!r} is built in; clone it to change it"
                continue

        # Spec §3.1: the judge cannot be cloned, so ``role: "judge"`` belongs
        # to the built-in key alone — the same rule ``AgentsConfig`` applies.
        if model.role == "judge" and name != "judge":
            errors[name] = f"{name!r}: only the built-in judge may have role judge"
            continue
        if model.role == "generic" and not (model.prompt or "").strip():
            errors[f"{name}.prompt"] = "a generic agent needs a prompt"
        if model.static_provider and model.static_provider not in provider_ids:
            errors[f"{name}.static_provider"] = (
                f"unknown static provider {model.static_provider!r}. "
                f"Available: {', '.join(sorted(provider_ids))}"
            )
        has_provider_ref = any(ref.kind == "provider" for ref in model.tools)
        if has_provider_ref and model.role != "generic":
            errors[name] = (
                f"{name!r}: provider tool references are only valid on generic "
                "definitions; built-in roles open their provider themselves"
            )
            continue
        for ref in model.tools:
            if ref.kind != "mcp":
                continue
            server = str(ref.server)
            if server not in allow_lists:
                errors[f"{name}.tools"] = f"unknown mcp server {server!r}"
                break
            allowed = allow_lists[server]
            if ref.name is not None and allowed is not None and ref.name not in allowed:
                errors[f"{name}.tools"] = (
                    f"{ref.name!r} is not allowed on server {server!r}; tick it there first"
                )
                break
        out[name] = dumped

    if errors:
        raise AgentMapError(errors)

    # A built-in the body left out is re-seeded rather than removed, exactly as
    # the settings model would do on the next load.
    for name, seed in seeds.items():
        out.setdefault(name, seed)
    return out


def validate_profiles(
    value: Any, *, definitions: dict[str, Any], active: str = "default"
) -> dict[str, Any]:
    """Return the profile map to store, or raise with one message per offender.

    ``active`` is the profile that would actually run if this PATCH is
    accepted — the staged ``core.agents.profile`` if the PATCH sets one, else
    the stored one, else ``"default"``. It is what lets a built-in profile
    keep a disabled member while some other profile is the one selected,
    exactly as ``AgentsConfig`` allows: disabling a member of ``default`` is
    harmless as long as ``default`` itself is not the profile that will run.
    """
    if not isinstance(value, dict):
        raise AgentMapError({"": "the profile map must be an object keyed by profile name"})

    errors: dict[str, str] = {}
    out: dict[str, Any] = {}
    seeds = {name: p.model_dump(mode="json") for name, p in _builtin_profiles().items()}

    for key, entry in value.items():
        name = str(key)
        if not _KEY_RE.match(name):
            errors[name] = _KEY_RULE
            continue
        if not isinstance(entry, dict):
            errors[name] = "a profile entry must be an object"
            continue
        try:
            model = ProfileDefinition.model_validate(entry)
        except ValidationError as exc:
            for err in exc.errors():
                errors[f"{name}." + ".".join(str(p) for p in err["loc"])] = err["msg"]
            continue
        dumped = model.model_dump(mode="json")

        seed = seeds.get(name)
        if seed is not None and dumped != seed:
            errors[name] = f"{name!r} is built in; clone it to change it"
            continue

        if not model.analysts:
            errors[name] = "a profile needs at least one analyst"
            continue
        seen: set[str] = set()
        for analyst in model.analysts:
            if analyst in seen:
                errors[name] = f"lists {analyst!r} twice"
                break
            seen.add(analyst)
            definition = definitions.get(analyst)
            if definition is None:
                errors[name] = f"lists unknown analyst {analyst!r}"
                break
            if definition.get("role") == "judge":
                errors[name] = f"lists {analyst!r}: the judge cannot be an analyst"
                break
            exempt = name in BUILTIN_PROFILES and name != active
            if not exempt and definition.get("enabled") is False:
                errors[name] = f"lists disabled analyst {analyst!r}"
                break
        out[name] = dumped

    if errors:
        raise AgentMapError(errors)
    for name, seed in seeds.items():
        out.setdefault(name, seed)
    return out


def validate_agent_map(changes: dict[str, Any], stored: dict[str, Any]) -> dict[str, Any]:
    """Validate whichever of the three agent keys this PATCH touches, together.

    Together, because they are three views of one decision: a PATCH that adds a
    definition, builds a profile from it and makes that profile active is one
    coherent change, and validating the parts separately would reject it on
    whichever part arrived first. What is not in ``changes`` is taken from
    ``stored``, so patching a profile alone still sees the definitions saved
    last week.

    ``null`` means the same thing it means everywhere else in this settings
    system: drop the override, leaving the built-in seeds — which is why
    clearing the definitions while a stored profile still names one of them is
    an error rather than a silently broken profile.
    """
    out = {key: changes[key] for key in changes}

    definitions_raw = changes.get(AGENT_DEFINITIONS_KEY, ...)
    if definitions_raw is ...:
        definitions_raw = stored.get(AGENT_DEFINITIONS_KEY) or {}
    elif definitions_raw is None:
        definitions_raw = {}
    definitions = validate_definitions(definitions_raw, servers=_server_allow_lists(stored))
    if AGENT_DEFINITIONS_KEY in changes and changes[AGENT_DEFINITIONS_KEY] is not None:
        out[AGENT_DEFINITIONS_KEY] = definitions

    profiles_raw = changes.get(AGENT_PROFILES_KEY, ...)
    if profiles_raw is ...:
        profiles_raw = stored.get(AGENT_PROFILES_KEY) or {}
    elif profiles_raw is None:
        profiles_raw = {}

    # The profile that would actually run if this PATCH is accepted: the
    # staged value wins, then the stored one, then "default" -- the same
    # order ``AgentsConfig.profile`` itself resolves. Computed before
    # ``validate_profiles`` runs, because the disabled-analyst exemption for
    # a built-in profile depends on whether it is this profile.
    active = changes.get(AGENT_PROFILE_KEY, ...)
    if active is ... or active is None:
        active = stored.get(AGENT_PROFILE_KEY) or "default"
    active = str(active)

    profiles = validate_profiles(profiles_raw, definitions=definitions, active=active)
    if AGENT_PROFILES_KEY in changes and changes[AGENT_PROFILES_KEY] is not None:
        out[AGENT_PROFILES_KEY] = profiles

    if active not in profiles:
        raise AgentMapError(
            {
                AGENT_PROFILE_KEY: (
                    f"unknown profile {str(active)!r}. Available: {', '.join(sorted(profiles))}"
                )
            }
        )
    return out
