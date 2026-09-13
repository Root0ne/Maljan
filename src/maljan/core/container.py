"""ServiceContainer — Dependency Injection / Composition Root.

Wires together all registries, loaders, and provides factory methods for
creating agents and LLM instances. Replaces scattered global state and
``_is_mock_mode()`` checks with a single, testable container.

Caching:
    LLM instances, agent instances, and loaded sample data are all cached so
    that repeated calls during the negotiation loop do not incur redundant
    object creation or I/O. Every getter is guarded by a single re-entrant
    lock so concurrent LangGraph fan-out nodes cannot double-build the cache.

Heterogeneous Model Ensemble:
    ``get_agent_llm(agent_name)`` returns a per-agent LLM instance using the
    ``LLMConfig.agents`` overrides. Agents without overrides fall back to the
    global expert LLM.

LangSmith Observability:
    When ``Settings.langchain_tracing_v2`` is true, ``_configure_langsmith()``
    sets the env vars LangChain reads automatically.

Sandbox Backend:
    ``get_sandbox_provider()`` builds the configured ``SandboxProvider`` from
    the registry (``mock`` when the container's own ``mock`` flag is set) and
    caches it for the lifetime of the container.
"""

from __future__ import annotations

import asyncio
import os
import threading
import weakref
from typing import TYPE_CHECKING, Any, cast

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.registry import AgentRegistry
from maljan.core.config import Settings
from maljan.core.exceptions import ConfigurationError
from maljan.core.logger import logger
from maljan.core.token_ledger import TokenLedger
from maljan.core.truncation_ledger import TruncationLedger
from maljan.llm.registry import LLMProviderRegistry
from maljan.loaders.file_loader import FileDataLoader
from maljan.parsers.registry import ParserRegistry
from maljan.schemas.evidence import EvidenceCounter

if TYPE_CHECKING:
    from maljan.agents.base_agent import BaseAnalyst
    from maljan.analysis.function_summarizer import FunctionSummarizer
    from maljan.loaders.binary_chunker import TextChunk
    from maljan.memory.long_term_memory import MemoryStore
    from maljan.pipeline.events import EventSink
    from maljan.providers.base import SandboxProvider, StaticProvider
    from maljan.providers.servers import ServerRegistry


# Per-closer budget in ``aclose``. Each toolkit is already bounded internally;
# this is the second fence, because a teardown that hangs holds the whole job
# open and — with ``max_jobs = 1`` — every job after it.
#
# It has to be strictly larger than what a single handle's close can take, or
# this fence cancels the handle's own abandonment handling mid-flight and the
# child is never reaped: ``ServerHandle`` spends at most 14s routing the close
# and 4s reaping, and the numbers are kept coherent there (see the budget
# table at the top of ``providers/servers.py``).
_ACLOSE_BUDGET = 20.0

# The synchronous sweep's budget. Larger than ``_ACLOSE_BUDGET`` because it
# closes every synchronously-opened handle in one call, each with its own
# 20s bound — and because it runs in an executor, so the time it spends is a
# worker thread's, not the event loop's.
_CLOSE_ALL_BUDGET = 45.0


# Every container that still exists, so a retired agent loop can invalidate the
# clients that were built on it. Weak, so a finished job's container is gone.
_LIVE_CONTAINERS: weakref.WeakSet[ServiceContainer] = weakref.WeakSet()
_RETIREMENT_HOOK_REGISTERED = threading.Event()


def _drop_llm_caches_on_retirement(loop: object) -> None:
    """Forget every cached chat model when an agent loop is retired.

    A LangChain chat model lazily builds an httpx async pool bound to the loop
    that first awaits it — the single-loop invariant ``base_agent`` documents.
    After a retirement those pools belong to a loop nothing will run again, and
    reusing one on the fresh loop parks on a future that can never complete, so
    the caches are emptied and the next call rebuilds. Which loop a given model
    was bound to is not knowable from here, so all of them go: rebuilding is
    cheap and a stale one is a hang.

    Deliberately narrow: agents, providers and server handles are *not* dropped
    here. Handles are handled at their own site (``providers.servers``), and an
    agent holds only a reference to the model it was built with, which its next
    call refreshes through ``get_agent_llm``.
    """
    for container in list(_LIVE_CONTAINERS):
        with container._lock:
            container._expert_llm_cache = None
            container._judge_llm_cache = None
            container._agent_llm_cache.clear()


def _register_retirement_hook() -> None:
    """Subscribe once to agent-loop retirements. Imported late to avoid a cycle."""
    if _RETIREMENT_HOOK_REGISTERED.is_set():
        return
    from maljan.agents.base_agent import on_agent_loop_retired

    on_agent_loop_retired(_drop_llm_caches_on_retirement)
    _RETIREMENT_HOOK_REGISTERED.set()


class ServiceContainer:
    """Central service locator that manages all subsystem lifecycles."""

    def __init__(
        self,
        config: Settings,
        mock: bool = False,
        samples_dir: str = "data/samples",
        event_sink: EventSink | None = None,
    ) -> None:
        self.config = config
        self.mock = mock
        # Progress feed for the live transcript UI. ``None`` outside the API
        # worker (CLI, tests), which makes every emit a no-op — see
        # maljan.pipeline.events.
        self.event_sink = event_sink

        self.agent_registry = AgentRegistry()
        self.parser_registry = ParserRegistry()

        self._llm_registry: LLMProviderRegistry | None = None
        if not mock:
            self._llm_registry = LLMProviderRegistry(config)

        from maljan.core.paths import resolve_data

        self.loader = FileDataLoader(
            samples_dir=str(resolve_data(samples_dir)),
            parser_registry=self.parser_registry,
            chunking_config=config.chunking,
        )

        # Re-entrant lock guarding every cache. RLock so that a helper holding
        # the lock can recursively call another guarded getter (e.g. agent
        # creation may call get_agent_llm()).
        self._lock = threading.RLock()

        # --- Caches ---
        self._expert_llm_cache: BaseChatModel | None = None
        self._judge_llm_cache: BaseChatModel | None = None
        self._agent_llm_cache: dict[str, BaseChatModel] = {}
        self._agent_cache: dict[str, BaseAnalyst] = {}
        self._judge_agent_cache: dict[str, Any] = {}
        self._data_cache: dict[tuple[str, str], str] = {}
        self._memory_store_cache: MemoryStore | None = None
        self._sandbox_provider_cache: SandboxProvider | None = None
        self._static_provider_cache: dict[str, StaticProvider] = {}
        self._server_registry_cache: ServerRegistry | None = None
        self._function_summarizer_cache: FunctionSummarizer | None = None
        self._narrative_agent_cache: Any | None = None
        self._report_composer_cache: Any | None = None
        self._samples_dir = str(resolve_data(samples_dir))

        # The job sample's ``(file_type, platform)``, set by ``app.arun`` once
        # routing has answered and read by ``composition.builtin_prompt`` when
        # it assembles an agent's format fragment. It lives here rather than in
        # the graph state because agents are built lazily, by this container,
        # from nodes that do not all carry the state.
        self.sample_format: tuple[str, str] = ("unknown", "unknown")

        # The job's sandbox report, set by ``app.arun`` for the same reason
        # ``sample_format`` is: the sandbox tool set
        # (``providers.sandbox_tools``) is built during agent resolution, which
        # happens in nodes that do not all carry the graph state. ``None``
        # outside a job, and the tools then say so rather than answering empty.
        self.sandbox_report: dict[str, Any] | None = None

        # The job's sample, for the one step that needs the bytes rather than
        # a report: staging the sample to a tool server that does not share
        # this filesystem (``agents.sample_staging``). Both ``None``/empty
        # outside a job, and staging is then a no-op.
        self.sample_path: str | None = None
        self.sample_sha256: str = ""

        # Per-run LLM token/cost ledger (findings-log §4 Item 1). Agents and the
        # judge add each call's usage; the judge node snapshots it into RunSummary.
        self._token_ledger = TokenLedger()

        # Per-run truncation ledger (pitfall P6). Same lifecycle as the token
        # ledger: written to at every bound, snapshotted by the judge node.
        # Truncation is designed into this pipeline and has never been counted.
        self._truncation_ledger = TruncationLedger()

        # Per-job source of evidence-ledger ids. One counter for the whole job
        # so ``ev_0007`` names one tool call rather than one per agent.
        self._evidence_counter = EvidenceCounter()

        _LIVE_CONTAINERS.add(self)
        _register_retirement_hook()

        from maljan.agents.composition import analyst_keys

        logger.info(
            "ServiceContainer initialized (mock=%s, profile=%s, analysts=%s, parsers=%s)",
            mock,
            config.agents.profile,
            analyst_keys(config),
            self.parser_registry.list_parsers(),
        )

        self._configure_langsmith()

    @property
    def is_mock(self) -> bool:
        return self.mock

    # ------------------------------------------------------------------
    # LLM accessors
    # ------------------------------------------------------------------

    def _expert_token_cap(self) -> dict[str, Any]:
        """``max_tokens`` kwargs for analyst-role models, or ``{}`` when unset.

        The analyst path was the only unbounded LLM call in the system while
        judge/narrative/composer were all capped. MEASURED:
        a 19-tool-call static loop produced a forced-synthesis call that ran 19+
        minutes against its 25-minute wall clock. Mirrors ``get_judge_llm``.
        """
        cap = getattr(self.config.llm, "expert_max_tokens", 0) or 0
        return {"max_tokens": cap} if cap > 0 else {}

    def get_expert_llm(self) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        with self._lock:
            if self._expert_llm_cache is None:
                self._expert_llm_cache = self._llm_registry.build_model(
                    role="expert", **self._expert_token_cap()
                )
            return self._expert_llm_cache

    def get_judge_llm(self) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        with self._lock:
            if self._judge_llm_cache is None:
                # Bound the verdict generation so a degenerate decode can't
                # consume the full wall-clock timeout (see LLMConfig.judge_max_tokens).
                extra: dict[str, Any] = {}
                cap = self.config.llm.judge_max_tokens
                if cap and cap > 0:
                    extra["max_tokens"] = cap
                # Through the per-agent path so a configured
                # ``llm.agents.judge`` decides provider/model/temperature the
                # same way it does for an analyst; with no such entry the
                # judge role picks the model exactly as before. An entry that
                # sets provider and model but no temperature therefore runs at
                # the per-agent default of 0.1 rather than the role's 0.0 —
                # deliberate (the entry is an analyst-shaped override and is
                # read as one), and said out loud in the setting's help text.
                self._judge_llm_cache = self._llm_registry.build_model_for_agent(
                    "judge", fallback_role="judge", **extra
                )
            return self._judge_llm_cache

    def get_agent_llm(self, agent_name: str) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        with self._lock:
            cached = self._agent_llm_cache.get(agent_name)
            if cached is None:
                # Analysts share the expert budget cap — this is the path the
                # static/dynamic/network ReAct loops and their forced-synthesis
                # fallback actually use.
                cached = self._llm_registry.build_model_for_agent(
                    agent_name, **self._expert_token_cap()
                )
                self._agent_llm_cache[agent_name] = cached
            return cached

    # ------------------------------------------------------------------
    # Memory / sandbox / agent accessors
    # ------------------------------------------------------------------

    def get_memory_store(self) -> MemoryStore:
        with self._lock:
            if self._memory_store_cache is None:
                backend = self.config.memory.backend
                if backend == "qdrant":
                    from maljan.memory.qdrant_store import QdrantStore

                    self._memory_store_cache = QdrantStore(
                        url=self.config.memory.qdrant_url,
                        collection=self.config.memory.qdrant_collection,
                        api_key=(
                            self.config.memory.qdrant_api_key.get_secret_value()
                            if self.config.memory.qdrant_api_key
                            else None
                        ),
                    )
                    logger.info(
                        "LTM backend: QdrantStore (url=%s, collection=%s)",
                        self.config.memory.qdrant_url,
                        self.config.memory.qdrant_collection,
                    )
                else:
                    from maljan.memory.in_memory_store import InMemoryStore

                    self._memory_store_cache = InMemoryStore()
                    logger.info("LTM backend: InMemoryStore (in-process, non-persistent).")
            return self._memory_store_cache

    def get_sandbox_provider(self) -> SandboxProvider:
        """The configured sandbox adapter, or the mock one in mock mode.

        ``mock=True`` is the container's own switch (the CLI's ``--mock``, the
        API's mock jobs) and outranks the setting, exactly as it did when this
        method built clients directly.
        """
        with self._lock:
            if self._sandbox_provider_cache is not None:
                return self._sandbox_provider_cache
            from maljan.providers.registry import get_sandbox_provider as build

            cfg = self.config
            if self.mock and cfg.sandbox.provider != "mock":
                cfg = cfg.model_copy(deep=True)
                cfg.sandbox.provider = "mock"
            provider = build(cfg)
            fixtures = getattr(provider, "fixtures_dir", None)
            if fixtures is not None:
                provider.fixtures_dir = self._samples_dir  # type: ignore[attr-defined]
            logger.info("Sandbox provider: %s.", provider.id)
            self._sandbox_provider_cache = provider
            return provider

    def get_static_provider(self, provider_id: str | None = None) -> StaticProvider:
        """The static provider for ``provider_id``, or the globally configured one.

        Cached per id rather than once, because a profile may hold two static
        analysts on two providers and each needs its own object: the providers
        are stateful (an open decompiler session, a loaded program), and
        sharing one between two analysts would have them fighting over which
        binary is loaded. ``get_static_provider()`` with no argument is the
        pre-existing call and returns exactly what it always did.
        """
        wanted = str(provider_id or self.config.static.provider)
        with self._lock:
            cached = self._static_provider_cache.get(wanted)
            if cached is None:
                from maljan.providers.registry import get_static_provider as build

                cfg = self.config
                if wanted != str(cfg.static.provider):
                    # The registry builds from ``cfg.static.provider``; a
                    # per-agent provider is that same construction against a
                    # copy, so no provider needs to learn a second entry point.
                    cfg = cfg.model_copy(deep=True)
                    cfg.static.provider = wanted  # type: ignore[assignment]
                cached = build(cfg)
                logger.info("Static provider: %s.", cached.id)
                self._static_provider_cache[wanted] = cached
            return cached

    def get_server_registry(self) -> ServerRegistry:
        """The tool servers this job may attach, built from the job's settings.

        One registry per container, and the container is per job, so a stdio
        server's subprocess lives for exactly one analysis and is closed by
        ``aclose`` at the end of it — the same lifetime the static and sandbox
        providers already have.
        """
        with self._lock:
            if self._server_registry_cache is None:
                from maljan.providers.servers import ServerRegistry

                self._server_registry_cache = ServerRegistry(self.config)
                logger.info(
                    "Tool servers: %s.",
                    ", ".join(sorted(self.config.mcp.servers)) or "(none)",
                )
            return self._server_registry_cache

    def server_degradation_reasons(self) -> list[str]:
        """Tool servers that could not be attached this job, or an empty list.

        Reads the *cached* registry only: a job that never attached a tool
        server has nothing to report and must not build a registry here to
        discover that.
        """
        registry = self._server_registry_cache
        return list(registry.degradation_reasons) if registry is not None else []

    def get_token_ledger(self) -> TokenLedger:
        """Return the per-run LLM token/cost ledger (findings-log §4 Item 1)."""
        return self._token_ledger

    def get_truncation_ledger(self) -> TruncationLedger:
        """Return the per-run truncation ledger (pitfall P6)."""
        return self._truncation_ledger

    def get_evidence_counter(self) -> EvidenceCounter:
        """Return the per-job counter that issues evidence-ledger ids."""
        return self._evidence_counter

    def drain_all_judge_evidence(self) -> list[Any]:
        """Every entry the judge agents gathered, drained from each cached role.

        The judge is cached per role and the roles are different objects: the
        negotiation node mediates on ``expert`` and the verdict runs on
        ``judge``. Only ``mediate`` reaches a tool loop, so a node that drained
        one instance by name drained the wrong one and the mediation's calls
        were never written down. Draining every cached role removes the
        question of which instance recorded what, and it is safe to call twice
        because a drain leaves nothing behind.
        """
        with self._lock:
            judges = list(self._judge_agent_cache.values())
        entries: list[Any] = []
        for judge in judges:
            drain = getattr(judge, "drain_evidence_entries", None)
            if drain is None:
                continue
            try:
                entries.extend(drain())
            except Exception as exc:  # noqa: BLE001 — a ledger read never fails a run
                logger.debug("evidence drain skipped for a judge agent: %s", exc)
        entries.sort(key=lambda entry: getattr(entry, "seq", 0))
        return entries

    # ------------------------------------------------------------------
    # Composition accessors
    # ------------------------------------------------------------------

    def active_profile(self) -> Any:
        """The ``ProfileDefinition`` this job runs."""
        from maljan.agents.composition import active_profile

        return active_profile(self.config)

    def analyst_keys(self) -> list[str]:
        """The ordered analyst keys of the active profile.

        The topology source for the builder, the negotiation and revision
        nodes, the judge node and the worker's roster announcement — all of
        them read the profile through this one call, because a profile that
        half the pipeline believes in is worse than no profile.
        """
        from maljan.agents.composition import analyst_keys

        return analyst_keys(self.config)

    def agent_role(self, key: str) -> str:
        """The role definition ``key`` plays: what the code may branch on.

        A clone of the static analyst runs under its own key, so ``key ==
        "static"`` stopped being the question anything should ask; this is the
        question they meant.
        """
        definition = self.config.agents.definitions.get(key)
        if definition is None:
            available = ", ".join(sorted(self.config.agents.definitions)) or "(none)"
            raise KeyError(f"No agent definition named {key!r}. Available: {available}")
        return str(definition.role)

    def get_agent(self, name: str) -> BaseAnalyst:
        """The agent definition ``name`` names, instantiated and wired.

        A built-in role runs its own class under the definition's key — a clone
        ``static_r2`` is a ``StaticAnalyst`` named ``static_r2`` — because
        those classes carry the provider-specific ISR extraction the goldens
        pin. A ``generic`` role runs ``ConfigurableAnalyst``. Both get the
        per-run ledgers, a way back to this container, and their
        ``ResolvedAgent``, so nothing below re-derives a prompt or a tool set.
        """
        with self._lock:
            cached = self._agent_cache.get(name)
            if cached is not None:
                return cached

            from maljan.agents.composition import resolve_agent
            from maljan.agents.configurable_analyst import ConfigurableAnalyst

            role = self.agent_role(name)
            resolved = resolve_agent(name, self)
            llm = cast(BaseChatModel, resolved.llm)
            if role == "generic":
                agent: BaseAnalyst = ConfigurableAnalyst(name, resolved, llm)
            else:
                agent = self.agent_registry.create(role, llm)
                # The class is chosen by role; the *identity* is the key. Every
                # per-agent lookup downstream — timeout overrides, LLM
                # overrides, ISR agent_id, the graph node name — reads
                # ``agent.name``, so this one assignment is what makes a clone
                # a separate participant rather than a second copy of its source.
                agent.name = name
                # The base class already childed the logger with the role's
                # own name at construction time; re-child only when the key
                # differs from the role, or a default-profile agent would log
                # as ``...static.static`` instead of ``...static``.
                if name != role:
                    agent.logger = agent.logger.getChild(name.lower())
            agent.token_ledger = getattr(self, "_token_ledger", None)
            agent.truncation_ledger = getattr(self, "_truncation_ledger", None)
            agent.evidence_counter = getattr(self, "_evidence_counter", None)
            # Hand the agent a way back to this container. The static analyst
            # used to construct a *whole new* ServiceContainer on every failed
            # MCP init — per chunk, so up to ten of them per run.
            agent._container = self
            agent._resolved = resolved
            self._agent_cache[name] = agent
            return agent

    def get_judge_agent(self, role: str = "judge") -> Any:
        with self._lock:
            cached = self._judge_agent_cache.get(role)
            if cached is None:
                from maljan.agents.judge_agent import JudgeAgent

                llm = self.get_judge_llm() if role == "judge" else self.get_expert_llm()
                cached = JudgeAgent(
                    llm=llm,
                    # Without this the judge's structured-output capability
                    # check fell back to ``ChatOpenAI._llm_type`` and misread
                    # every provider — see _supports_structured_output.
                    config=self.config,
                )
                cached.token_ledger = getattr(self, "_token_ledger", None)
                cached.truncation_ledger = getattr(self, "_truncation_ledger", None)
                cached.evidence_counter = getattr(self, "_evidence_counter", None)
                # Hand the judge a way back to this container, the same way
                # ``get_agent`` does above. Without this, ``_server_registry()``
                # always read ``None`` and the judge ran with zero threat-intel
                # tools in production, silently — the guard on the caller is
                # ``if self.tools: return``, so a degraded judge looked exactly
                # like a healthy one that had already attached.
                cached._container = self
                self._judge_agent_cache[role] = cached
            return cached

    async def aclose(self) -> None:
        """Release everything this container handed out. Never raises.

        Correct only because the container is built **per job**
        (``MaljanApp.__init__`` -> ``run_analysis``): closing cached agents at
        job end is safe precisely because no later job will reuse them. If
        agent caching is ever hoisted to process scope, this silently breaks
        the *next* run rather than this one — so hoist the caching and this
        method together, or not at all.

        The two halves close on different loops, and that asymmetry is not
        incidental: the analysts entered their toolkits on the shared agent
        loop via ``_run_coro_blocking``, while the judge entered its own with a
        plain ``await`` on the graph's loop. Each stack has to unwind where it
        was wound.
        """
        with self._lock:
            analysts = list(self._agent_cache.values())
            judges = list(self._judge_agent_cache.values())
            self._agent_cache.clear()
            self._judge_agent_cache.clear()

        # Every close is individually bounded *and* the whole set is bounded
        # again by the caller, because teardown that can hang is teardown that
        # blocks the next job — with ``max_jobs = 1`` that means all of them.
        for agent in analysts:
            try:
                await asyncio.wait_for(agent.close_tools(), timeout=_ACLOSE_BUDGET)
            except TimeoutError:
                logger.warning("Closing tools for %s timed out; abandoning.", agent.name)
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Closing agent tools failed (non-fatal): %s", exc)

        for judge in judges:
            closer = getattr(judge, "aclose", None)
            if closer is None:
                continue
            try:
                await asyncio.wait_for(closer(), timeout=_ACLOSE_BUDGET)
            except TimeoutError:
                logger.warning("Closing judge tools timed out; abandoning.")
            except Exception as exc:  # noqa: BLE001
                logger.warning("Closing judge tools failed (non-fatal): %s", exc)

        # The static/sandbox providers may hold a subprocess or an HTTP pool of
        # their own (a CAPE REST client, an MCP stdio child); release them here
        # too, alongside the agents' and judges' toolkits above.
        #
        # M6 (final review): close the *cached* provider, never
        # ``get_static_provider()``/``get_sandbox_provider()`` — those build
        # one on demand, so a job that never touched a provider built one
        # here for the sole purpose of closing it, and a misconfigured
        # ``provider`` id turned a harmless teardown into a
        # ``ProviderConfigurationError`` landing in this warning handler.
        for provider in list(self._static_provider_cache.values()):
            try:
                provider.close()
            except Exception as exc:  # noqa: BLE001 — teardown never raises
                logger.warning("Static provider '%s' did not close cleanly: %s", provider.id, exc)

        if self._sandbox_provider_cache is not None:
            try:
                self._sandbox_provider_cache.close()
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Closing sandbox provider failed (non-fatal): %s", exc)

        # Same rule as the providers above: close the *cached* registry, never
        # ``get_server_registry()`` — a job that never attached a tool server
        # must not build one here for the sole purpose of closing it.
        if self._server_registry_cache is not None:
            registry = self._server_registry_cache
            # ``close_all`` is synchronous and blocks its thread: each handle
            # it closes hands the toolkit's exit stack to the agent loop and
            # waits for it. Run on the loop thread, that blocks the loop — and
            # a blocked loop cannot fire the worker's 60s fence, which is
            # precisely the way a teardown outlasts a budget nobody can
            # enforce. In an executor it costs a worker thread instead, and
            # every fence above stays live.
            loop = asyncio.get_running_loop()
            try:
                await asyncio.wait_for(
                    loop.run_in_executor(None, registry.close_all), timeout=_CLOSE_ALL_BUDGET
                )
            except TimeoutError:
                logger.warning(
                    "The synchronous tool-server sweep exceeded %.0fs; leaving it to "
                    "finish in its thread and closing whatever is still attached.",
                    _CLOSE_ALL_BUDGET,
                )
            except Exception as exc:  # noqa: BLE001 — teardown never propagates
                logger.warning("Closing the tool-server registry failed (non-fatal): %s", exc)
            # A handle ``aopen`` attached is unwound on the loop that
            # opened it (``ServerHandle.aclose`` routes it there) rather than
            # through the synchronous sweep, which skips it. Read from the
            # registry rather than from the sweep's return value, so a sweep
            # that was abandoned above still leaves nothing attached. Normally
            # a no-op: ``JudgeAgent.aclose`` has closed these already, and this
            # only fires when the judge raised before reaching its own aclose.
            for handle in registry.still_open():
                try:
                    await asyncio.wait_for(handle.aclose(), timeout=_ACLOSE_BUDGET)
                except TimeoutError:
                    logger.warning(
                        "Closing async-opened mcp server '%s' timed out; abandoning.",
                        handle.name,
                    )
                except Exception as exc:  # noqa: BLE001 — teardown never propagates
                    logger.warning(
                        "Closing async-opened mcp server '%s' failed (non-fatal): %s",
                        handle.name,
                        exc,
                    )

        # The sample's parsed text and the per-job caches. Not a leak
        # on their own — the container dies with the job — but dropping them
        # here means a worker that is *not* recycled starts the next job with a
        # clean floor rather than one job's residue.
        with self._lock:
            self._data_cache.clear()
            self._function_summarizer_cache = None
            self._narrative_agent_cache = None
            self._report_composer_cache = None
            self._server_registry_cache = None

    def get_narrative_agent(self) -> Any | None:
        """Return the singleton NarrativeAgent or ``None`` in mock mode.

        Reuses ``get_judge_llm()`` — the judge LLM is already configured for
        structured-output prompts so no new provider build is needed. Callers
        receive ``None`` in mock mode and must fall back to the deterministic
        narrative template.
        """
        if self.is_mock:
            return None
        with self._lock:
            if self._narrative_agent_cache is None:
                from maljan.reporting.narrative_agent import NarrativeAgent

                llm = self.get_judge_llm()
                max_tokens = self.config.reporting.narrative_max_tokens
                self._narrative_agent_cache = NarrativeAgent(
                    llm=llm,
                    max_input_tokens=max_tokens,
                    token_ledger=getattr(self, "_token_ledger", None),
                )
            return self._narrative_agent_cache

    def get_report_composer(self) -> Any | None:
        """Return the singleton section-wise ReportComposer, or ``None``.

        ``None`` in mock mode or when ``composer_enabled`` is
        off (callers then simply skip the professional spine). Reuses the judge
        LLM like the NarrativeAgent.
        """
        if self.is_mock or not self.config.reporting.composer_enabled:
            return None
        with self._lock:
            if getattr(self, "_report_composer_cache", None) is None:
                from maljan.reporting.composer import ReportComposer

                rc = self.config.reporting
                self._report_composer_cache = ReportComposer(
                    llm=self.get_judge_llm(),
                    section_max_tokens=rc.composer_section_max_tokens,
                    per_section_timeout=rc.composer_per_section_timeout,
                    token_ledger=getattr(self, "_token_ledger", None),
                )
            return self._report_composer_cache

    # ------------------------------------------------------------------
    # Data loading
    # ------------------------------------------------------------------

    def load_data(self, sample_id: str, data_type: str) -> str:
        key = (sample_id, data_type)
        with self._lock:
            cached = self._data_cache.get(key)
            if cached is None:
                cached = self.loader.load(sample_id, data_type)
                self._data_cache[key] = cached
            return cached

    def load_chunked(self, sample_id: str, data_type: str) -> list[TextChunk]:
        """Return a list of TextChunk objects for a sample and data type.

        Re-uses the parsed-text cache when available; chunking itself is cheap
        and stateless so the chunk list is not cached.
        """
        key = (sample_id, data_type)
        with self._lock:
            cached_text = self._data_cache.get(key)
        if cached_text is not None:
            return self.loader.chunk_text(data_type, cached_text)
        return self.loader.load_chunked(sample_id, data_type)

    def load_sandbox_data_for_agent(
        self, agent_name: str, sandbox_report: dict[str, Any]
    ) -> list[TextChunk]:
        """Parse and chunk sandbox report data for a specific agent.

        The slice an agent gets follows its *role*, not its key: a clone of the
        static analyst runs ``StaticAnalyst``, which is written against the
        report's ``target`` block, so it must be handed that block under
        whatever key the operator gave it. The chunker still keys on the agent's
        own name, which is what the loader's ``data_type`` means.
        """
        import json

        role = self.agent_role(agent_name)

        if role == "static":
            target = sandbox_report.get("target", {})
            text = json.dumps(target, indent=2, default=str)
        elif role == "network":
            network = sandbox_report.get("network", {})
            try:
                parser = self.parser_registry.create("network")
                text = parser.parse(network)
            except KeyError:
                text = json.dumps(network, indent=2, default=str)
        elif role == "dynamic":
            try:
                parser = self.parser_registry.create("dynamic")
                text = parser.parse(sandbox_report)
            except KeyError:
                text = json.dumps(sandbox_report, indent=2, default=str)
        else:
            text = json.dumps(sandbox_report, indent=2, default=str)

        return self.loader.chunk_text(agent_name, text)

    def get_function_summarizer(self) -> FunctionSummarizer | None:
        if not self.config.preprocessing.use_function_summarizer:
            return None
        with self._lock:
            if self._function_summarizer_cache is None:
                from maljan.analysis.function_summarizer import FunctionSummarizer

                if self._llm_registry is None:
                    raise ConfigurationError("Cannot build FunctionSummarizer LLM in mock mode.")
                summarizer_llm = self._llm_registry.build_model(
                    role="expert",
                    provider_override=self.config.preprocessing.summarizer_provider,
                    model_override=self.config.preprocessing.summarizer_model,
                )
                self._function_summarizer_cache = FunctionSummarizer(
                    llm=summarizer_llm,
                    max_summary_words=self.config.preprocessing.summarizer_max_words,
                )
                logger.info(
                    "FunctionSummarizer initialized (%s / %s, max_words=%d).",
                    self.config.preprocessing.summarizer_provider,
                    self.config.preprocessing.summarizer_model,
                    self.config.preprocessing.summarizer_max_words,
                )
            return self._function_summarizer_cache

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _configure_langsmith(self) -> None:
        """Propagate LangSmith tracing config into the OS environment."""
        if not self.config.langchain_tracing_v2:
            logger.debug("LangSmith tracing disabled (langchain_tracing_v2=False).")
            return

        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_PROJECT"] = self.config.langchain_project

        api_key = self.config.langchain_api_key
        if api_key:
            secret_value = (
                api_key.get_secret_value() if hasattr(api_key, "get_secret_value") else str(api_key)
            )
            os.environ["LANGCHAIN_API_KEY"] = secret_value
            # No part of the key reaches the log: a fragment narrows a brute
            # force and is enough to confirm a key found elsewhere.
            logger.info(
                "LangSmith tracing enabled (project=%s).",
                self.config.langchain_project,
            )
        else:
            logger.warning(
                "LangSmith tracing enabled (project=%s) but no API key provided. "
                "Set LANGCHAIN_API_KEY in .env to authenticate with LangSmith.",
                self.config.langchain_project,
            )
