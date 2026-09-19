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
    PROMPT_ROLES,
    PROVIDER_REFERENCE_RULE,
    REPORTER_AGENT_KEY,
    AgentDefinition,
    ProfileDefinition,
    _builtin_definitions,
    _builtin_profiles,
    _without_the_empty_builtin_tool_list,
    agent_reference_problems,
    convert_builtin_profile_document,
)
from maljan.core.settings_overrides import build_settings
from maljan.pipeline.conditions import validate_condition
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


def _qualified(leaf: str, errors: dict[str, str]) -> dict[str, str]:
    """Every error key rooted at the settings leaf it belongs to.

    These used to come out relative -- ``uiaudit_gen.prompt``
    where the server map returns ``core.mcp.servers.Bad Key`` -- so the editor,
    which routes a nested error to a card by the ``core.agents.definitions.
    <key>.<field>`` prefix, could not find the card the message belonged to and
    fell back to a generic banner. The two maps now speak the same shape. The
    empty key, which a map that is not an object at all reports under, becomes
    the leaf itself: the whole setting is what is wrong.
    """
    return {f"{leaf}.{key}" if key else leaf: message for key, message in errors.items()}


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
    servers = build_settings({}).mcp.servers
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
        raise AgentMapError(
            _qualified(
                AGENT_DEFINITIONS_KEY,
                {"": "the definition map must be an object keyed by agent name"},
            )
        )

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
        #
        # ``_without_the_empty_builtin_tool_list`` is part of that same merge
        # and was missing here, which is the whole of the console defect the
        # audit found: a database written before the tool sidecars holds
        # ``tools: []`` on every built-in, the Settings layer reads that as
        # "not set" and the seed's tools apply, and this layer read it as an
        # edit. Every save touching the agent map was then refused with
        # "'judge' is built in; clone it to change it" on the four built-ins
        # whose seed has tools -- reporter's is empty, so it alone passed.
        candidate = (
            {**seed, **_without_the_empty_builtin_tool_list(entry)} if seed is not None else entry
        )
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
        if model.role in PROMPT_ROLES and not (model.prompt or "").strip():
            errors[f"{name}.prompt"] = f"a {model.role} agent needs a prompt"
        if model.static_provider and model.static_provider not in provider_ids:
            errors[f"{name}.static_provider"] = (
                f"unknown static provider {model.static_provider!r}. "
                f"Available: {', '.join(sorted(provider_ids))}"
            )
        has_provider_ref = any(ref.kind == "provider" for ref in model.tools)
        if has_provider_ref and model.role not in PROMPT_ROLES:
            errors[name] = f"{name!r}: {PROVIDER_REFERENCE_RULE}"
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

    # A built-in the body left out is re-seeded rather than removed, exactly as
    # the settings model would do on the next load.
    for name, seed in seeds.items():
        out.setdefault(name, seed)

    # An agent reference points into the map, so it is checked against the map
    # as it will be stored, seeds included, once every entry has a shape.
    if not errors:
        typed = {name: AgentDefinition.model_validate(entry) for name, entry in out.items()}
        for name, definition in typed.items():
            problems = agent_reference_problems(name, definition, typed)
            if problems:
                errors[f"{name}.tools"] = f"{name!r}: {problems[0]}"

    if errors:
        raise AgentMapError(_qualified(AGENT_DEFINITIONS_KEY, errors))
    return out


def validate_stage_conditions(profile: str, entry: Any) -> dict[str, str]:
    """Every stage of ``entry`` whose ``when`` does not parse, keyed by field.

    Run against the raw body, before ``ProfileDefinition`` sees it.
    ``StageDefinition`` refuses a bad condition too, but it reports it as
    ``stages.3`` with pydantic's wrapper text around it, and the editor routes
    a message to a card by ``<profile>.stages.<key>.<field>``. Checking here
    first is what puts the message under the box the operator typed it into.
    """
    errors: dict[str, str] = {}
    stages = entry.get("stages") if isinstance(entry, dict) else None
    if not isinstance(stages, list):
        return errors
    for index, stage in enumerate(stages):
        if not isinstance(stage, dict):
            continue
        key = str(stage.get("key") or index)
        problems = validate_condition(str(stage.get("when") or ""))
        if problems:
            errors[f"{profile}.stages.{key}.when"] = problems[0]
    return errors


def validate_stage_handovers(profile: str, entry: Any) -> dict[str, str]:
    """Every debate in ``entry`` that has no single stage to hand over to.

    Run against the raw body, before ``ProfileDefinition`` sees it, for the
    reason the condition pre-pass is: the model refuses the same team, but it
    refuses it with one message about the whole profile, and the editor routes
    a message to a stage card by ``<profile>.stages.<key>.<field>``.
    """
    errors: dict[str, str] = {}
    stages = entry.get("stages") if isinstance(entry, dict) else None
    if not isinstance(stages, list):
        return errors
    typed = [s for s in stages if isinstance(s, dict)]

    def heads(stage: dict) -> int:
        if stage.get("kind") == "analysis" and stage.get("mode") == "parallel":
            return len(stage.get("agents") or [])
        return 1

    for index, stage in enumerate(typed):
        if stage.get("kind") != "debate":
            continue
        key = str(stage.get("key") or index)
        fed = [s for s in typed if key in (s.get("depends_on") or [])]
        total = sum(heads(s) for s in fed)
        if total <= 1:
            continue
        names = ", ".join(str(s.get("key") or "?") for s in fed)
        errors[f"{profile}.stages.{key}.depends_on"] = (
            f"this debate hands over to {total} nodes ({names}); a debate hands over to "
            "exactly one stage, and not to a parallel analysis stage with more than one agent"
        )
    return errors


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
        raise AgentMapError(
            _qualified(
                AGENT_PROFILES_KEY,
                {"": "the profile map must be an object keyed by profile name"},
            )
        )

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
        shape_errors = {
            **validate_stage_conditions(name, entry),
            **validate_stage_handovers(name, entry),
        }
        if shape_errors:
            errors.update(shape_errors)
            continue
        try:
            model = ProfileDefinition.model_validate(convert_builtin_profile_document(name, entry))
        except ValidationError as exc:
            for err in exc.errors():
                location = ".".join(str(p) for p in err["loc"])
                errors[f"{name}.{location}" if location else name] = err["msg"]
            continue
        # ``ProfileDefinition`` clears ``derived_from_analysts`` when the
        # stages are no longer the plain conversion of the analyst list, so the
        # dump is what gets stored and a PATCH that edits a migrated team's
        # stages stops it being re-derived over — whether it came from the
        # console, a script or an imported document.
        dumped = model.model_dump(mode="json")

        seed = seeds.get(name)
        if seed is not None:
            # A built-in profile's stages may differ from the seed's in the
            # two fields an operator legitimately tunes; everything else about
            # it is the architecture, and the settings model refuses the rest.
            comparable = {**dumped, "stages": _stage_identity(dumped.get("stages"))}
            expected = {**seed, "stages": _stage_identity(seed.get("stages"))}
            for field in ("exclude_servers", "analysts", "derived_from_analysts"):
                comparable.pop(field, None)
                expected.pop(field, None)
            if comparable != expected:
                errors[name] = f"{name!r} is built in; clone it to change it"
                continue

        stage_errors = _stage_member_errors(name, model, definitions, active)
        if stage_errors:
            errors.update(stage_errors)
            continue
        out[name] = dumped

    if errors:
        raise AgentMapError(_qualified(AGENT_PROFILES_KEY, errors))
    for name, seed in seeds.items():
        out.setdefault(name, seed)
    return out


def _stage_identity(stages: Any) -> Any:
    """A built-in's stages with the two operator-editable fields removed."""
    if not isinstance(stages, list):
        return stages
    return [
        {k: v for k, v in stage.items() if k not in ("debate", "builtin_tools")}
        if isinstance(stage, dict)
        else stage
        for stage in stages
    ]


def _stage_member_errors(
    name: str, model: ProfileDefinition, definitions: dict[str, Any], active: str
) -> dict[str, str]:
    """Whether every agent a stage names exists, may run, and fits the kind.

    The same rules ``AgentsConfig._check_profile_members`` applies, reported per
    stage instead of as the first ``ValueError`` the model raised: an operator
    editing a team of seven stages needs to know which card is wrong.
    """
    errors: dict[str, str] = {}
    exempt = name in BUILTIN_PROFILES and name != active
    for stage in model.stages:
        field = f"{name}.stages.{stage.key}"
        for agent in stage.agents:
            definition = definitions.get(agent)
            if definition is None:
                errors[f"{field}.agents"] = f"unknown agent {agent!r}"
                break
            role = definition.get("role")
            if stage.kind == "analysis" and role in ("judge", "report"):
                errors[f"{field}.agents"] = f"{agent!r} has role {role!r} and cannot be an analyst"
                break
            if not exempt and definition.get("enabled") is False:
                errors[f"{field}.agents"] = f"{agent!r} is disabled"
                break
        if f"{field}.agents" in errors:
            continue
        if stage.kind == "verdict":
            judge = definitions.get(stage.agents[0]) if stage.agents else None
            if len(stage.agents) != 1 or judge is None or judge.get("role") != "judge":
                errors[f"{field}.agents"] = "a verdict stage names exactly one judge definition"
        elif stage.kind == "report" and stage.agents != [REPORTER_AGENT_KEY]:
            errors[f"{field}.agents"] = f"a report stage is run by {REPORTER_AGENT_KEY!r}"
        elif stage.kind == "debate" and stage.agents:
            errors[f"{field}.agents"] = (
                "a debate stage names no agent; it argues over the analysis stages upstream of it"
            )
        elif stage.kind == "triage" and stage.agents:
            errors[f"{field}.agents"] = "a triage stage names no agent; the pipeline runs it"
    return errors


STATIC_PROVIDER_KEY = "core.static.provider"


def _effective_static_provider(overrides: dict[str, Any]) -> str:
    """The static provider a run would open, from the store or the default."""
    stored = overrides.get(STATIC_PROVIDER_KEY)
    if isinstance(stored, str) and stored:
        return stored
    return str(build_settings({}).static.provider)


def profile_warnings(
    profiles: dict[str, Any],
    *,
    definitions: dict[str, Any],
    overrides: dict[str, Any],
) -> dict[str, str]:
    """What is worth saying about a team that is nonetheless legal to save.

    One rule so far, and it is the one `deep_static` needs: an agent given a
    `provider` tool reference is given the tools of whichever static provider
    the deployment configured, and when that provider is `none` the reference
    resolves to nothing. The stage still runs, and its prompt still asks it to
    open a decompiler, so what comes out is a confident ungrounded answer
    rather than a visible failure.

    Two degrees of it, because they are different problems. An agent whose
    *whole* tool list is the provider has nothing at all to call. One that also
    holds a tool server keeps that server and loses only the decompiler — which
    is `deep_static`'s reverser, and still worth saying, because the prompt is
    written around a decompiler it will not have.

    A warning rather than a refusal, deliberately. A team validated against a
    runtime provider setting is a team that cannot be saved before the provider
    is configured, and the order an operator does those two things in is
    theirs. Keyed by the same dotted path the errors use, so the console draws
    it on the stage card the operator is looking at.
    """
    provider = _effective_static_provider(overrides)
    if provider != "none":
        return {}

    warnings: dict[str, str] = {}
    for name, entry in (profiles or {}).items():
        if not isinstance(entry, dict):
            continue
        # A team may force a provider of its own, in which case the global
        # setting is not what its members open.
        if entry.get("static_provider") not in (None, "none"):
            continue
        for stage in entry.get("stages") or []:
            if not isinstance(stage, dict) or stage.get("kind") != "analysis":
                continue
            agents = [a for a in (stage.get("agents") or []) if isinstance(a, str)]
            affected = [a for a in agents if _reads_the_static_provider(definitions.get(a))]
            if not affected:
                continue
            toolless = all(_only_provider_tools(definitions.get(a)) for a in affected)
            path = f"{AGENT_PROFILES_KEY}.{name}.stages.{stage.get('key', '')}"
            members = ", ".join(affected)
            consequence = (
                "The stage will run with no tools at all."
                if toolless and len(affected) == len(agents)
                else "The stage will run without the decompiler its prompt asks for."
            )
            warnings[path] = (
                f"{members} reads the static provider's tools, and this deployment's "
                f"static provider is 'none'. {consequence} Choose a static provider, "
                "or give the agents a tool server of their own."
            )
    return warnings


def _agent_tools_and_provider(definition: Any) -> tuple[list[dict[str, Any]], Any] | None:
    """One definition's tool list and its own provider override, or ``None``."""
    if isinstance(definition, AgentDefinition):
        return [ref.model_dump() for ref in definition.tools], definition.static_provider
    if isinstance(definition, dict):
        tools = definition.get("tools")
        return (
            [t for t in tools if isinstance(t, dict)] if isinstance(tools, list) else []
        ), definition.get("static_provider")
    return None


def _reads_the_static_provider(definition: Any) -> bool:
    """An agent that was given the tools of whatever provider is configured."""
    pair = _agent_tools_and_provider(definition)
    if pair is None:
        return False
    tools, own_provider = pair
    if own_provider not in (None, "none"):
        return False
    return any(t.get("kind") == "provider" for t in tools)


def _only_provider_tools(definition: Any) -> bool:
    """An agent whose entire tool list is its static provider."""
    pair = _agent_tools_and_provider(definition)
    if pair is None:
        return False
    tools, _ = pair
    if not tools:
        return False
    return {t.get("kind") for t in tools} == {"provider"}


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
