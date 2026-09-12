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

``ToolRef(kind="sandbox")`` is the third half and the simplest: the job's
sandbox report is already on the container, so the tools over it are closures
built here with nothing to open and nothing that can hang.
"""

from __future__ import annotations

import asyncio
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
    """The static provider id agent ``key`` reads, falling back to the global one.

    The active profile wins over both. ``measurement`` forces ``none`` across
    every member, which is what makes it a baseline rather than a profile that
    merely happens to have no tool servers today.
    """
    forced = active_profile(settings).static_provider
    if forced:
        return str(forced)
    definition = settings.agents.definitions.get(key)
    if definition is not None and definition.static_provider:
        return str(definition.static_provider)
    return str(settings.static.provider)


def sample_format(container: Any) -> tuple[str, str]:
    """The ``(file_type, platform)`` of the job's sample, as the container knows it.

    ``app.arun`` puts the routing answer on the container before the graph
    runs, which is the one place both the pipeline and every lazily built
    agent can read it from. A container that was never told — the settings
    probe, a test — answers ``("unknown", "unknown")`` and gets the neutral
    fragment.
    """
    fmt = getattr(container, "sample_format", None)
    if not isinstance(fmt, tuple) or len(fmt) != 2:
        return "unknown", "unknown"
    return str(fmt[0] or "unknown"), str(fmt[1] or "unknown")


def builtin_prompt(role: str, container: Any, static_provider_id: str) -> str:
    """The prompt a built-in role sends for this job's sample.

    Every analyst assembles the same way: HEAD, then the sample's format
    fragment, then the provider fragment where the role has one, then TAIL.
    The head says what the role does, the format fragment says what artefacts
    exist on this sample, and the provider fragment says what tools are on the
    other end — so handing the same agent an APK, or attaching radare2, each
    changes one part and nothing else.

    ``static`` reads the *agent's own* static provider, which is what makes a
    clone on radare2 meaningful.

    ``dynamic`` uses the CAPE2 fragment, not the configured sandbox's. This
    analyst has never read the configured provider for its prompt (the default
    is ``mock``, whose fragment is empty) and there is no per-agent sandbox
    provider to vary.
    """
    from maljan.agents.prompt_fragments import format_fragment

    fragment = format_fragment(*sample_format(container))
    if role == "static":
        from maljan.agents.static_analyst import _ISR_HEAD, _ISR_TAIL

        provider = container.get_static_provider(static_provider_id)
        return _ISR_HEAD + fragment + "\n\n" + str(provider.prompt_fragment()) + _ISR_TAIL
    if role == "dynamic":
        from maljan.agents.dynamic_analyst import _DYN_HEAD, _DYN_TAIL
        from maljan.providers.sandbox.cape2 import CAPE2SandboxProvider

        return _DYN_HEAD + fragment + "\n\n" + CAPE2SandboxProvider.CAPE_PROMPT_FRAGMENT + _DYN_TAIL
    if role == "network":
        from maljan.agents.network_analyst import _NET_HEAD, _NET_TAIL

        return _NET_HEAD + fragment + _NET_TAIL
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
    return list(provider.get_tools())


def _sandbox_tools(container: Any, definition: AgentDefinition) -> list[Any]:
    """The job's sandbox-report tools, for a definition that asked for them.

    In-process, so unlike the provider half there is nothing to open and
    nothing that can hang: the report is already on the container and the tools
    are closures over it. Any role may ask — ``dynamic`` is the obvious one,
    but a judge cross-checking an analyst's claim about a dropped file wants
    the same lookup, and there is no reason to make it read the whole report to
    get it.
    """
    if not any(ref.kind == "sandbox" for ref in definition.tools):
        return []
    if active_profile(container.config).exclude_sandbox_tools:
        return []
    from maljan.providers.sandbox_tools import sandbox_tools

    return list(sandbox_tools(container))


def _claim_in_process_tools(
    incoming: list[Any], source: str, tools: list[Any], seen: dict[str, str]
) -> None:
    """Put an in-process half into ``tools`` and record what it claimed.

    Two halves come through here: the static provider's tools and the sandbox
    report's. Both are first, so neither renames anything; recording their
    names under the source's own id is what makes a later server's identically
    named tool take the prefix rather than vanish into ``_dedupe``.
    """
    for tool in incoming:
        name = str(getattr(tool, "name", ""))
        if name in seen:
            continue
        seen[name] = source
        tools.append(tool)


def _mcp_refs(settings: Settings, definition: AgentDefinition) -> list[ToolRef]:
    """The definition's server references, minus the ones the profile excludes."""
    excluded = set(active_profile(settings).exclude_servers)
    return [
        ref for ref in definition.tools if ref.kind == "mcp" and str(ref.server) not in excluded
    ]


def _excluded_servers(settings: Settings) -> str:
    """``ServerRegistry``'s ``exclude`` argument for the active profile.

    The registry takes one name, not a list — it grew for the one case of an
    analyst that must not see its own provider's server. A profile excluding
    several is expressed as a comma-joined value that ``handles_for`` splits;
    see ``ServerRegistry.handles_for``.
    """
    return ",".join(active_profile(settings).exclude_servers)


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
    # One ``seen`` map across every half, so B's collision rule holds over the
    # agent's whole tool set: a referenced server's tool whose name a bound
    # server already claimed arrives as ``<server>__<tool>`` instead of being
    # dropped as a duplicate of a tool it has nothing to do with.
    seen: dict[str, str] = {}
    tools: list[Any] = []
    _claim_in_process_tools(
        _provider_tools(container, definition, provider_id),
        f"provider:{provider_id}",
        tools,
        seen,
    )
    _claim_in_process_tools(_sandbox_tools(container, definition), "sandbox", tools, seen)
    registry = container.get_server_registry()
    bound, bound_reasons = registry.tools_for(
        key, job_key, exclude=_excluded_servers(settings), seen=seen
    )
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(settings, definition):
        referenced, ref_reasons = registry.tools_for_ref(ref, job_key, seen=seen)
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
    seen: dict[str, str] = {}
    tools: list[Any] = []
    # The provider handshake is synchronous — for Ghidra it hands ``initialize``
    # to the shared agent loop and blocks on the result — so it runs off this
    # loop. Awaited callers (the judge's node, the settings probe) keep serving
    # everything else, and the probe's ``asyncio.wait`` budget can actually
    # preempt a wedged provider.
    _claim_in_process_tools(
        await asyncio.to_thread(_provider_tools, container, definition, provider_id),
        f"provider:{provider_id}",
        tools,
        seen,
    )
    _claim_in_process_tools(_sandbox_tools(container, definition), "sandbox", tools, seen)
    registry = container.get_server_registry()
    bound, bound_reasons = await registry.atools_for(
        key, job_key, exclude=_excluded_servers(settings), seen=seen
    )
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(settings, definition):
        referenced, ref_reasons = await registry.atools_for_ref(ref, job_key, seen=seen)
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
