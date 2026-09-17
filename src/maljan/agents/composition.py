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

``ToolRef(kind="agent")`` is the fourth: another agent of the same job, as a
tool named ``ask_<key>``. Built here as a closure over the container and the
two keys (``agents.delegation``), it opens nothing at resolution time; the
callee is resolved when it is first asked, through the container, like any
stage agent.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
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
    # Where each tool server was handed the sample, for the servers that were
    # handed it at all (``agents.sample_staging``). Empty on the common case:
    # every server is a local stdio sidecar reading the same filesystem the
    # worker does. An analyst passes this to ``pin_paths`` so a tool call goes
    # out with the path its own server can open.
    path_by_server: dict[str, str] = field(default_factory=dict)


def active_profile(settings: Settings) -> ProfileDefinition:
    """The profile this job runs. ``AgentsConfig`` guarantees it exists."""
    return settings.agents.profiles[settings.agents.profile]


def display_name(settings: Settings, key: str) -> str:
    """The label an operator gave this agent, or its key when they gave none.

    The label lives on the definition, which only an admin can read through
    the settings endpoint. Every place that puts a name in front of a reader
    asks here instead, so a non-admin watching a run sees the same name the
    operator typed rather than the registry key the name was meant to replace.
    """
    definition = settings.agents.definitions.get(key)
    return str(getattr(definition, "label", "") or key)


def analyst_keys(settings: Settings) -> list[str]:
    """Every analysis-stage agent of the active profile, in stage order.

    The single topology source: the negotiation and revision nodes, the judge
    node and the run summary all read this list, so a profile change moves all
    of them together or none of them. The builder reads the stages themselves —
    it is the one caller that needs to know which stage an agent belongs to.
    """
    return list(active_profile(settings).analysis_agents)


def stages(settings: Settings) -> list[Any]:
    """The active profile's stages, in the order it declares them."""
    return list(active_profile(settings).stages)


def stage_for_agent(settings: Settings, key: str) -> Any | None:
    """The stage agent ``key`` belongs to, or ``None`` if no stage names it."""
    for stage in active_profile(settings).stages:
        if key in stage.agents:
            return stage
    return None


def current_analyst_keys() -> list[str]:
    """``analyst_keys`` for the process-wide settings.

    For the consumers that have no container to ask — ``run_summary``'s
    per-source ordering, the judge node's claimless-analyst check — all of
    which run inside a job whose settings the worker has already installed.
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


def _agent_tools(container: Any, definition: AgentDefinition, key: str) -> list[Any]:
    """The ``ask_<agent>`` tools, one per agent reference on the definition.

    In-process like the sandbox tools, and only bound where the definition
    asks: an agent with no agent reference has no way to ask anyone, which is
    what keeps the default profile's analysts exactly what they were.

    A profile that excludes every server excludes this one too. ``*`` is the
    measurement baseline's way of saying "nothing to call", and an agent that
    could still hand its task to a colleague with tools would call through it.
    """
    refs = [ref for ref in definition.tools if ref.kind == "agent" and ref.agent]
    if not refs:
        return []
    from maljan.core.config import ALL_SERVERS

    if ALL_SERVERS in _withheld_servers(container.config, key):
        return []
    from maljan.agents.delegation import ask_tool

    return [ask_tool(container, key, str(ref.agent)) for ref in refs]


def _claim_in_process_tools(
    incoming: list[Any], source: str, tools: list[Any], seen: dict[str, str]
) -> None:
    """Put an in-process half into ``tools`` and record what it claimed.

    Three halves come through here: the static provider's tools, the sandbox
    report's and the team's ``ask_<agent>`` tools. All are first, so none
    renames anything; recording their names under the source's own id is what
    makes a later server's identically named tool take the prefix rather than
    vanish into ``_dedupe``.
    """
    for tool in incoming:
        name = str(getattr(tool, "name", ""))
        if name in seen:
            continue
        seen[name] = source
        tools.append(tool)


def _withheld_servers(settings: Settings, key: str) -> set[str]:
    """Every server agent ``key`` may not reach, under the active profile.

    Two sources, and they stack. The profile's own ``exclude_servers`` is the
    tool-free baseline's lever and applies to every member. A stage's
    ``builtin_tools=False`` is the narrower one: it withholds every built-in
    server from that stage's agents only, so a triage stage can be made to
    read what it was handed instead of going looking, without cloning the
    definitions it runs.
    """
    from maljan.core.config import BUILTIN_SERVER_KEYS

    excluded = set(active_profile(settings).exclude_servers)
    stage = stage_for_agent(settings, key)
    if stage is not None and not stage.builtin_tools:
        excluded.update(BUILTIN_SERVER_KEYS)
    return excluded


def _mcp_refs(settings: Settings, definition: AgentDefinition, key: str) -> list[ToolRef]:
    """The definition's server references, minus the ones the profile excludes."""
    from maljan.core.config import ALL_SERVERS

    excluded = _withheld_servers(settings, key)
    if ALL_SERVERS in excluded:
        return []
    return [
        ref for ref in definition.tools if ref.kind == "mcp" and str(ref.server) not in excluded
    ]


def mcp_refs_for(settings: Settings, key: str) -> list[ToolRef]:
    """Agent ``key``'s server references under the active profile, or ``[]``.

    The built-in analysts and the judge attach their own tools rather than
    reading a ``ResolvedAgent``, so they need the same answer resolution
    computes; exporting it here is what keeps the two from disagreeing about
    what a definition asked for.
    """
    definition = settings.agents.definitions.get(key)
    if definition is None:
        return []
    return _mcp_refs(settings, definition, key)


def servers_bound_to(settings: Settings, key: str) -> set[str]:
    """Every server agent ``key`` can reach under the active profile.

    Two binding mechanisms, and both count. A definition's
    ``ToolRef(kind="mcp")`` is one; ``core.mcp.servers.<server>.agents``
    naming the agent is the other, and it is the one the shipped map uses for
    ``network``, ``threatintel`` and every other role-bound server. Reading
    only the first said a stage-less specialist brought nothing with it.

    Narrowed by what the profile withholds from this agent, because a server
    it cannot resolve is not one it brings.
    """
    from maljan.core.config import ALL_SERVERS

    withheld = _withheld_servers(settings, key)
    if ALL_SERVERS in withheld:
        return set()
    bound = {str(ref.server) for ref in mcp_refs_for(settings, key)}
    bound |= {
        str(name)
        for name, server in settings.mcp.servers.items()
        if server.enabled and key in server.agents and str(name) not in withheld
    }
    return bound


def servers_withheld_from(
    settings: Settings,
    caller_key: str,
    callee_key: str,
    also: frozenset[str] = frozenset(),
) -> list[str]:
    """The servers ``callee_key`` brings that ``caller_key``'s own stage may not reach.

    A callee's effective tool set is what it is bound to — by its own
    definition and by the server map alike, see ``servers_bound_to`` —
    narrowed by the tool policy of the stage doing the asking: a stage with
    ``builtin_tools=False`` is told to read what it was handed, and an ask
    that came back with a ``knowledge`` lookup or a ``network`` query would
    have gone around it.

    Reported rather than applied, because the callee is one cached instance
    per job: narrowing the instance for one ask would narrow it for whoever
    asks next, and for its own stage. The delegation refuses the ask instead,
    in words the model reads.
    """
    from maljan.core.config import ALL_SERVERS

    # ``also`` is what the stage that started the chain withholds, carried down
    # by the delegation. Without it the policy stops at the first callee: a
    # specialist that no stage names withholds nothing of its own, so the ask
    # it makes in turn would reach exactly what the stage was told not to.
    withheld = _withheld_servers(settings, caller_key) | set(also)
    if not withheld:
        return []
    brought = servers_bound_to(settings, callee_key)
    if ALL_SERVERS in withheld:
        return sorted(brought)
    return sorted(brought & withheld)


def _excluded_servers(settings: Settings, key: str = "") -> str:
    """``ServerRegistry``'s ``exclude`` argument for one agent under this profile.

    The registry takes one name, not a list — it grew for the one case of an
    analyst that must not see its own provider's server. A profile excluding
    several is expressed as a comma-joined value that ``handles_for`` splits,
    and ``*`` among them means every server; see ``ServerRegistry.for_agent``.
    """
    return ",".join(sorted(_withheld_servers(settings, key)))


def _agent_llm(container: Any, key: str) -> Any:
    """The agent's model, or None on a mock container.

    A mock container (``ServiceContainer(settings, mock=True)``) builds no LLM
    registry and ``get_agent_llm`` raises there; the agent probe resolves on
    such a container on purpose, so resolution never asks it for a model.
    """
    if getattr(container, "mock", False):
        return None
    return container.get_agent_llm(key)


def _staging_inputs(container: Any) -> tuple[str | None, str]:
    """The job's sample path and digest, as ``app.arun`` left them on the container.

    Resolution has neither the graph state nor a job argument carrying these,
    for the same reason it has neither the sample format nor the sandbox
    report: agents are built lazily, from nodes that do not all carry the
    state. A container that was never told stages nothing.
    """
    path = getattr(container, "sample_path", None)
    digest = str(getattr(container, "sample_sha256", "") or "")
    return (str(path) if path else None), digest


async def _astage(
    registry: Any, container: Any, tools: list[Any], job_key: str
) -> tuple[dict[str, str], list[str]]:
    """Upload the sample to every bound server that wants it. Never raises.

    The registry is handed in rather than asked of the container: the
    synchronous caller below holds the container's cache lock while it waits
    for this coroutine, so a guarded getter reached from here would wait for a
    lock that only the blocked caller can release.

    Staging records its own failures on the registry, which is the union
    across every agent in the job; this agent's own reasons are the ones that
    appeared while *it* was staging, so the slice is taken rather than the
    whole list — an agent must not report a failure another agent caused.
    """
    sample_path, digest = _staging_inputs(container)
    if not sample_path:
        return {}, []
    from maljan.agents.sample_staging import stage_for_agent

    before = len(registry.degradation_reasons)
    try:
        staged = await stage_for_agent(registry, tools, sample_path, sha256=digest, job_id=job_key)
    except Exception as exc:  # noqa: BLE001 — staging never fails a run
        logger.warning("sample staging skipped for job %s: %s", job_key, exc)
        return {}, []
    return dict(staged), list(registry.degradation_reasons[before:])


def _has_remote_server(registry: Any, tools: list[Any]) -> bool:
    """Whether any server behind ``tools`` is reached over a network.

    Only such a server is ever staged to, and the answer is a property of the
    configuration alone — no transport is touched, nothing is awaited. Asking
    it here, on the caller's own thread, is what keeps a deployment whose
    servers are all local subprocesses from handing the agent loop a
    coroutine, and waiting on it, for an answer that is always ``{}``.
    """
    from maljan.agents.sample_staging import REMOTE_TRANSPORTS
    from maljan.agents.tool_pinning import server_of

    for key in dict.fromkeys(server_of(tool) for tool in tools):
        if not key:
            continue
        try:
            handle = registry.get(key)
        except Exception:  # noqa: BLE001 — a tool from a server that is gone
            continue
        transport = str(getattr(handle.config, "transport", "stdio") or "stdio").lower()
        if transport in REMOTE_TRANSPORTS:
            return True
    return False


def _stage(container: Any, tools: list[Any], job_key: str) -> tuple[dict[str, str], list[str]]:
    """``_astage`` for the synchronous resolver, on the shared agent loop.

    The same loop the handles were opened on, which is the loop their
    transports are bound to: uploading on any other one is the cross-loop
    failure ``ServerHandle`` exists to avoid.

    Both questions that can be answered without a transport are answered
    first, on this thread: a job with no sample stages nothing, and neither
    does a deployment whose servers are all local.
    """
    sample_path, _ = _staging_inputs(container)
    if not sample_path:
        return {}, []
    registry = container.get_server_registry()
    if not _has_remote_server(registry, tools):
        return {}, []
    from maljan.agents.base_agent import run_coro_blocking

    try:
        staged, reasons = run_coro_blocking(
            _astage(registry, container, tools, job_key),
            hard_timeout=120.0,
            label="sample-staging",
        )
    except Exception as exc:  # noqa: BLE001 — staging never fails a run
        logger.warning("sample staging skipped for job %s: %s", job_key, exc)
        return {}, []
    return dict(staged or {}), list(reasons or [])


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
    _claim_in_process_tools(_agent_tools(container, definition, key), "team", tools, seen)
    registry = container.get_server_registry()
    bound, bound_reasons = registry.tools_for(
        key, job_key, exclude=_excluded_servers(settings, key), seen=seen
    )
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(settings, definition, key):
        referenced, ref_reasons = registry.tools_for_ref(ref, job_key, seen=seen)
        tools.extend(referenced)
        reasons.extend(ref_reasons)

    deduped = _dedupe(tools)
    staged, staging_reasons = _stage(container, deduped, job_key)
    reasons.extend(staging_reasons)
    return ResolvedAgent(
        key=key,
        role=definition.role,
        prompt=prompt,
        tools=deduped,
        static_provider_id=provider_id,
        llm=_agent_llm(container, key),
        degradation_reasons=tuple(dict.fromkeys(reasons)),
        path_by_server=staged,
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
    _claim_in_process_tools(_agent_tools(container, definition, key), "team", tools, seen)
    registry = container.get_server_registry()
    bound, bound_reasons = await registry.atools_for(
        key, job_key, exclude=_excluded_servers(settings, key), seen=seen
    )
    tools.extend(bound)
    reasons.extend(bound_reasons)
    for ref in _mcp_refs(settings, definition, key):
        referenced, ref_reasons = await registry.atools_for_ref(ref, job_key, seen=seen)
        tools.extend(referenced)
        reasons.extend(ref_reasons)

    deduped = _dedupe(tools)
    staged, staging_reasons = await _astage(
        container.get_server_registry(), container, deduped, job_key
    )
    reasons.extend(staging_reasons)
    return ResolvedAgent(
        key=key,
        role=definition.role,
        prompt=prompt,
        tools=deduped,
        static_provider_id=provider_id,
        llm=_agent_llm(container, key),
        degradation_reasons=tuple(dict.fromkeys(reasons)),
        path_by_server=staged,
    )
