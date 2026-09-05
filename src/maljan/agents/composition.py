"""What one agent definition actually resolves to, for a given job.

One function answers "what prompt, what tools, what LLM, what static provider
does agent ``<key>`` get" — the graph, the container, the worker's mirror step
and the settings probe all call it, so a probe cannot report one answer and a
run produce another. That is the whole point of the module: before this, the
answer was spread across three analyst classes and could only be discovered by
running a job.

Two halves of an agent's tools live in two places on purpose:

* the *registry* half — servers bound by ``MCPServerConfig.agents`` and the
  explicit ``ToolRef``s of the definition — is composed here, because nothing
  else knows about ``ToolRef``;
* the *provider* half of a built-in role stays inside that role's class
  (``StaticAnalyst._initialize_mcp_client`` and friends), because opening
  Ghidra is a per-sample act with a job context, and pulling it into
  resolution would make the settings probe launch a decompiler.

A ``generic`` agent has no class of its own to open a provider, so an explicit
``ToolRef(kind="provider")`` is the one way it gets provider tools, and that
path *is* resolved here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from maljan.core.config import AgentDefinition, ProfileDefinition, Settings, ToolRef
from maljan.core.logger import logger

if TYPE_CHECKING:
    from langchain_core.tools import BaseTool


@dataclass(frozen=True)
class ResolvedAgent:
    """Everything an agent needs, decided once per job and never re-derived.

    ``degradation_reasons`` are this agent's own — a referenced tool that is
    not there, a server that would not open. They are additive: the run
    summary reads ``container.server_degradation_reasons()``, which is the
    registry's union across every agent in the job.
    """

    key: str
    role: str
    prompt: str
    tools: list[BaseTool]
    static_provider_id: str
    llm: Any | None
    degradation_reasons: tuple[str, ...] = ()


def active_profile(settings: Settings) -> ProfileDefinition:
    """The profile this job runs. ``AgentsConfig`` guarantees it exists."""
    return settings.agents.profiles[settings.agents.profile]


def analyst_keys(settings: Settings) -> list[str]:
    """The ordered analyst keys of the active profile.

    The single topology source: the builder, the negotiation and revision
    nodes, the judge node and the run summary all read this list, so a profile
    change moves all of them together or none of them.
    """
    return list(active_profile(settings).analysts)


def current_analyst_keys() -> list[str]:
    """``analyst_keys`` for the process-wide settings.

    For the two consumers that have no container to ask — ``ttp_cascade``'s
    ``is_consensus`` and ``run_summary``'s per-layer ordering — both of which
    run inside a job whose settings the worker has already installed.
    """
    from maljan.core.config import get_settings

    return analyst_keys(get_settings())


def static_provider_id_for(settings: Settings, key: str) -> str:
    """The static provider id agent ``key`` reads, falling back to the global one."""
    definition = settings.agents.definitions.get(key)
    if definition is not None and definition.static_provider:
        return str(definition.static_provider)
    return str(settings.static.provider)


def builtin_prompt(role: str, container: Any, static_provider_id: str) -> str:
    """The prompt a built-in role has always sent.

    ``static`` is assembled — HEAD + the *agent's own* static provider's
    fragment + TAIL — which is what makes a clone on radare2 meaningful: the
    same assembly, a different middle.

    ``dynamic`` is the frozen CAPE2 assembly, not the configured sandbox's.
    This analyst has never read the configured provider for its prompt (the
    default is ``mock``, whose fragment is empty), there is no per-agent
    sandbox provider to vary, and assembling from the configured one here
    would change the default profile's dynamic prompt on the day this landed.
    """
    if role == "static":
        from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL

        provider = container.get_static_provider(static_provider_id)
        return _ISR_HEAD + str(provider.prompt_fragment()) + _ISR_TAIL
    if role == "dynamic":
        from maljan.agents.dynamic_analyst import _ISR_SYSTEM as DYNAMIC_SYSTEM

        return DYNAMIC_SYSTEM
    if role == "network":
        from maljan.agents.network_analyst import _ISR_SYSTEM as NETWORK_SYSTEM

        return NETWORK_SYSTEM
    if role == "judge":
        from maljan.agents.judge_agent import JUDGE_VERDICT_SYSTEM

        return JUDGE_VERDICT_SYSTEM
    raise ValueError(f"no built-in prompt for role {role!r}: give the definition a prompt")


def _definition(settings: Settings, key: str) -> AgentDefinition:
    definition = settings.agents.definitions.get(key)
    if definition is None:
        available = ", ".join(sorted(settings.agents.definitions)) or "(none)"
        raise KeyError(f"No agent definition named {key!r}. Available: {available}")
    return definition


def _dedupe(tools: list[BaseTool]) -> list[BaseTool]:
    """First occurrence of each tool name wins, order preserved.

    B's collision prefixing has already run by the time a tool reaches here, so
    two tools with the same name really are the same tool arriving twice — a
    server both bound by ``agents`` and named by a ``ToolRef``.
    """
    seen: set[str] = set()
    out: list[BaseTool] = []
    for tool in tools:
        name = str(getattr(tool, "name", ""))
        if name in seen:
            continue
        seen.add(name)
        out.append(tool)
    return out


def _provider_tools(container: Any, definition: AgentDefinition, provider_id: str) -> list[Any]:
    """The agent's static provider's tools, for a definition that asked for them.

    Gated on ``role == "generic"`` in addition to the ``AgentsConfig``
    validator that already refuses a provider reference on a built-in role:
    a built-in role opens its own provider lazily, inside its own class
    (``StaticAnalyst._initialize_mcp_client`` and friends), so resolution
    must never open one itself — spec §4. The validator is the primary
    defence; this is defence in depth for a definition that reached here by
    some other path than validated ``Settings``.
    """
    if definition.role != "generic":
        return []
    if not any(ref.kind == "provider" for ref in definition.tools):
        return []
    from maljan.providers.base import StaticJobContext

    provider = container.get_static_provider(provider_id)
    if not provider.capabilities.provides_tools:
        logger.info("Static provider '%s' exposes no tools.", provider.id)
        return []
    provider.open(StaticJobContext())
    return list(provider.select_tools(provider.get_tools(), None))


def _mcp_refs(definition: AgentDefinition) -> list[ToolRef]:
    return [ref for ref in definition.tools if ref.kind == "mcp"]


def _agent_llm(container: Any, key: str) -> Any:
    """The agent's model, or None on a mock container.

    A mock container (``ServiceContainer(settings, mock=True)``) builds no LLM
    registry and ``get_agent_llm`` raises there; the agent probe resolves on
    such a container on purpose, so resolution never asks it for a model.
    """
    if getattr(container, "mock", False):
        return None
    return container.get_agent_llm(key)


def resolve_agent(key: str, container: Any, job_key: str = "job") -> ResolvedAgent:
    """Everything agent ``key`` gets under this container's settings."""
    settings: Settings = container.config
    definition = _definition(settings, key)
    provider_id = static_provider_id_for(settings, key)
    prompt = definition.prompt
    if prompt is None:
        prompt = builtin_prompt(definition.role, container, provider_id)

    reasons: list[str] = []
    tools: list[Any] = list(_provider_tools(container, definition, provider_id))
    registry = container.get_server_registry()
    bound, bound_reasons = registry.tools_for(key, job_key)
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(definition):
        referenced, ref_reasons = registry.tools_for_ref(ref, job_key)
        tools.extend(referenced)
        reasons.extend(ref_reasons)

    return ResolvedAgent(
        key=key,
        role=definition.role,
        prompt=prompt,
        tools=_dedupe(tools),
        static_provider_id=provider_id,
        llm=_agent_llm(container, key),
        degradation_reasons=tuple(dict.fromkeys(reasons)),
    )


async def aresolve_agent(key: str, container: Any, job_key: str = "job") -> ResolvedAgent:
    """``resolve_agent``, attaching on the caller's own loop.

    For a caller already inside an event loop — the judge's node and the
    settings probe — where handing the attach to the shared agent loop would
    bind a transport to a loop other than the one that awaits its tool calls.
    """
    settings: Settings = container.config
    definition = _definition(settings, key)
    provider_id = static_provider_id_for(settings, key)
    prompt = definition.prompt
    if prompt is None:
        prompt = builtin_prompt(definition.role, container, provider_id)

    reasons: list[str] = []
    tools: list[Any] = list(_provider_tools(container, definition, provider_id))
    registry = container.get_server_registry()
    bound, bound_reasons = await registry.atools_for(key, job_key)
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(definition):
        referenced, ref_reasons = await registry.atools_for_ref(ref, job_key)
        tools.extend(referenced)
        reasons.extend(ref_reasons)

    return ResolvedAgent(
        key=key,
        role=definition.role,
        prompt=prompt,
        tools=_dedupe(tools),
        static_provider_id=provider_id,
        llm=_agent_llm(container, key),
        degradation_reasons=tuple(dict.fromkeys(reasons)),
    )
