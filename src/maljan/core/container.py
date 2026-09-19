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
import uuid
import weakref
from contextlib import suppress
from typing import TYPE_CHECKING, Any, cast

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.registry import AgentRegistry
from maljan.agents.run_evidence_corpus import RunEvidenceCorpus
from maljan.core.config import PROMPT_ROLES, REPORTER_AGENT_KEY, Settings
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
    """Forget the retired loop's cached chat models.

    A LangChain chat model lazily builds an httpx async pool bound to the loop
    that first awaits it — the single-loop invariant ``base_agent`` documents.
    After a retirement those pools belong to a loop nothing will run again, and
    reusing one on the fresh loop parks on a future that can never complete, so
    that loop's partition is dropped and the next call rebuilds.

    Two partitions go, not all of them: the retired loop's own, and the
    ``None`` partition, whose models are used by the analyst tool loop — which
    is the loop being retired. Every other loop's models are still bound to a
    loop that is still running, and discarding them would throw away exactly
    the precision ``PerLoopModels`` was added for.

    Deliberately narrow: providers and server handles are *not* dropped here.
    Handles are handled at their own site (``providers.servers``), and an
    analyst holds only a reference to the model it was built with, which its
    next call refreshes through ``get_agent_llm``. The narrative agent and the
    report composer are dropped, because unlike an analyst they hold their
    model for their whole lifetime and never ask for it again.
    """
    from maljan.llm.openai_provider import clear_shared_httpx_clients

    for container in list(_LIVE_CONTAINERS):
        with container._lock:
            for cache in (
                container._expert_llm_cache,
                container._judge_llm_cache,
                container._reporter_llm_cache,
                container._summarizer_llm_cache,
                container._agent_llm_cache,
            ):
                cache.drop(loop)
                cache.drop(None)
            container._function_summarizer_cache = None
            container._narrative_agent_cache = None
            container._report_composer_cache = None
    # Dropping the models is not enough on its own: ``langchain_openai``
    # caches its httpx clients with an ``lru_cache`` keyed on the endpoint, so
    # a rebuilt model was handed the same pool, still bound to the retired
    # loop, and the rebuild cleared nothing. Models this provider builds now
    # own their pools, and this clears any that were built elsewhere.
    clear_shared_httpx_clients()


def _swap_healed_llm(replaced: object, healed: object) -> None:
    """Put the self-healed model where the one it replaced was cached.

    The 400 self-heal rebuilds a model without the llama.cpp extras the
    endpoint rejected. The model that raised is of no further use against that
    endpoint, and the container hands out one model per loop for the life of a
    job, so leaving it cached means every later caller reaches the endpoint
    through a wrapper that has already had to heal once.
    """
    for container in list(_LIVE_CONTAINERS):
        with container._lock:
            for cache in (
                container._expert_llm_cache,
                container._judge_llm_cache,
                container._reporter_llm_cache,
                container._summarizer_llm_cache,
                container._agent_llm_cache,
            ):
                cache.replace(replaced, healed)


def _register_retirement_hook() -> None:
    """Subscribe once to agent-loop retirements. Imported late to avoid a cycle."""
    if _RETIREMENT_HOOK_REGISTERED.is_set():
        return
    from maljan.agents.base_agent import on_agent_loop_retired
    from maljan.llm.openai_provider import on_model_healed

    on_agent_loop_retired(_drop_llm_caches_on_retirement)
    on_model_healed(_swap_healed_llm)
    _RETIREMENT_HOOK_REGISTERED.set()


def _current_loop() -> Any | None:
    """The event loop the caller is running on, or ``None`` outside one."""
    try:
        return asyncio.get_running_loop()
    except RuntimeError:
        return None


class PerLoopModels:
    """Chat models, partitioned by the event loop that will use them.

    A model's httpx connection pool belongs to the first event loop that awaits
    it, and this process makes LLM calls on two — the shared agent loop and the
    worker's own. One model handed to both fails inside httpx with "bound to a
    different event loop", which the openai SDK reports as a bare
    ``APIConnectionError("Connection error.")``.

    Keyed on the loop *object*, weakly, rather than on ``id(loop)``: CPython
    reuses the address of a collected loop, so an id key silently hands a fresh
    loop the dead one's model — measured, not feared, in the first version of
    this. A weak key cannot be confused with its successor and lets a finished
    loop's models go on their own.

    ``None`` is a partition of its own: a synchronous caller has no loop to be
    keyed by, and the model it builds is used by the analyst tool loop, which
    runs on the shared agent loop and nowhere else.
    """

    def __init__(self) -> None:
        self._by_loop: weakref.WeakKeyDictionary[Any, dict[str, Any]] = weakref.WeakKeyDictionary()
        self._without_loop: dict[str, Any] = {}

    def _slot(self, loop: Any | None) -> dict[str, Any]:
        if loop is None:
            return self._without_loop
        slot = self._by_loop.get(loop)
        if slot is None:
            slot = {}
            self._by_loop[loop] = slot
        return slot

    def lookup(self, loop: Any | None, name: str = "") -> Any | None:
        """The model cached for this loop under this name, or ``None``.

        Not called ``get``: a plain ``dict`` answers ``get(loop, name)`` with
        ``name`` itself, so a stand-in that was a dict returned the agent's
        name as its model and the failure read as nonsense rather than as a
        missing partition.
        """
        return self._slot(loop).get(name)

    def put(self, loop: Any | None, name: str, value: Any) -> None:
        self._slot(loop)[name] = value

    def replace(self, old: Any, new: Any) -> int:
        """Swap one cached model for another wherever it is held.

        For the 400 self-heal: the model that raised is never usable against
        that endpoint again, so leaving it in the cache means every later
        caller starts from the wrapper that has already healed once. Returns
        how many slots were swapped, which is what a test can assert on.
        """
        swapped = 0
        for slot in [self._without_loop, *self._by_loop.values()]:
            for name, value in list(slot.items()):
                if value is old:
                    slot[name] = new
                    swapped += 1
        return swapped

    def clear(self) -> None:
        self._by_loop = weakref.WeakKeyDictionary()
        self._without_loop = {}

    def drop(self, loop: Any | None) -> None:
        """Forget one loop's partition, leaving every other loop's alone."""
        if loop is None:
            self._without_loop = {}
            return
        with suppress(KeyError, TypeError):
            del self._by_loop[loop]

    def __len__(self) -> int:
        return len(self._without_loop) + sum(len(slot) for slot in self._by_loop.values())


class ServiceContainer:
    """Central service locator that manages all subsystem lifecycles."""

    def __init__(
        self,
        config: Settings,
        mock: bool = False,
        samples_dir: str = "data/samples",
        event_sink: EventSink | None = None,
        job_id: str = "",
    ) -> None:
        self.config = config
        self.mock = mock
        # The identity of the job this container serves, as the caller that
        # queued it knows it. Empty for the CLI and for tests, which run one
        # analysis per process and have no such id to give.
        self.job_id = str(job_id or "")
        # What ``job_key`` answers when nothing gave it one. Composed here, so
        # it belongs to this container and therefore to one run: the key names
        # the directory a tool server stages in, and a value derived from the
        # process alone would have a second run that drew the same pid — after
        # a recycle, ordinary in a container with a small ``pid_max`` — inherit
        # the first run's uploads, carved payloads and capture.
        self._run_key = f"cli-{os.getpid()}-{uuid.uuid4().hex[:8]}"
        # Progress feed for the live transcript UI. ``None`` outside the API
        # worker (CLI, tests), which makes every emit a no-op — see
        # maljan.pipeline.events.
        self.event_sink = event_sink
        # The stages that have already announced their end on this run. A
        # stage's end is announced by whichever node runs after everything in
        # it is done, and for a terminal fan-out or a terminal debate that is
        # every one of its own nodes — so the announcement has to be claimed
        # rather than simply made. Guarded by a lock because a parallel
        # analysis stage's agents run in LangGraph worker threads.
        self._finished_stages: set[str] = set()
        self._finished_stages_lock = threading.Lock()

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
        # Every chat-model cache is keyed by the event loop the caller is on
        # (see ``PerLoopModels``). A model's httpx pool belongs to the first loop
        # that awaits it, and this process runs LLM calls on two loops — the
        # shared agent loop and the worker's own — so one cached model handed
        # to both is the "bound to a different event loop" failure that cost
        # the judge its first verdict request and the narrative round its
        # first attempt on every run.
        self._expert_llm_cache = PerLoopModels()
        self._judge_llm_cache = PerLoopModels()
        self._reporter_llm_cache = PerLoopModels()
        self._summarizer_llm_cache = PerLoopModels()
        self._agent_llm_cache = PerLoopModels()
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

        # What this run SAW, as opposed to what its ledger keeps. The evidence
        # byte budget blanks an entry after the model has read it, so a
        # grounding check over the stored ledger told a judge that a C2 a tool
        # really returned appears nowhere. In memory, per job, dropped with
        # this container; never in the graph state and never persisted.
        self._evidence_corpus: RunEvidenceCorpus | None = RunEvidenceCorpus(
            int(getattr(config.reporting, "evidence_corpus_bytes", 0) or 0)
        )

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
        self._announce_index_retry()

    @property
    def is_mock(self) -> bool:
        return self.mock

    def claim_stage_finished(self, key: str) -> bool:
        """Claim the right to announce ``key`` finished, once per run.

        Returns ``True`` to the first caller for a stage and ``False`` to every
        caller after it. Three shapes reach here more than once for the same
        stage: a terminal parallel analysis stage with no barrier and a
        terminal debate, whose own nodes all end at the same time and all see
        the finished state, and the report node's closing rollup, which exists
        to repair a run whose stages crashed before they could announce
        themselves. The console draws one row per stage, so the second and
        third announcements are noise at best and a duplicated row at worst.
        """
        with self._finished_stages_lock:
            if key in self._finished_stages:
                return False
            self._finished_stages.add(key)
            return True

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
        loop = _current_loop()
        with self._lock:
            cached = self._expert_llm_cache.lookup(loop)
            if cached is None:
                cached = self._llm_registry.build_model(role="expert", **self._expert_token_cap())
                self._expert_llm_cache.put(loop, "", cached)
            return cached

    def get_judge_llm(self) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._judge_llm_cache.lookup(loop)
            if cached is None:
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
                cached = self._llm_registry.build_model_for_agent(
                    "judge", fallback_role="judge", **extra
                )
                self._judge_llm_cache.put(loop, "", cached)
            return cached

    def get_reporter_llm(self) -> BaseChatModel:
        """The model the report stage's narrative and composer rounds run on.

        Through the per-agent path, like the judge: a configured
        ``llm.agents.reporter`` decides provider, model and temperature, and
        with no such entry the judge role picks the model exactly as it did
        when the report had no definition of its own to be configured through.
        """
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._reporter_llm_cache.lookup(loop)
            if cached is None:
                extra: dict[str, Any] = {}
                cap = self.config.llm.judge_max_tokens
                if cap and cap > 0:
                    extra["max_tokens"] = cap
                cached = self._llm_registry.build_model_for_agent(
                    REPORTER_AGENT_KEY, fallback_role="judge", **extra
                )
                self._reporter_llm_cache.put(loop, "", cached)
            return cached

    def get_summarizer_llm(self) -> BaseChatModel:
        """The model the function summariser runs on, per loop like the rest.

        It has its own provider/model overrides, so it is its own accessor
        rather than the expert one with arguments; what it shares with the
        others is that its pool belongs to the loop that first awaits it.
        """
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build FunctionSummarizer LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._summarizer_llm_cache.lookup(loop)
            if cached is None:
                cached = self._llm_registry.build_model(
                    role="expert",
                    provider_override=self.config.preprocessing.summarizer_provider,
                    model_override=self.config.preprocessing.summarizer_model,
                )
                self._summarizer_llm_cache.put(loop, "", cached)
            return cached

    def get_agent_llm(self, agent_name: str) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        loop = _current_loop()
        with self._lock:
            cached = self._agent_llm_cache.lookup(loop, agent_name)
            if cached is None:
                # Analysts share the expert budget cap — this is the path the
                # static/dynamic/network ReAct loops and their forced-synthesis
                # fallback actually use.
                cached = self._llm_registry.build_model_for_agent(
                    agent_name, **self._expert_token_cap()
                )
                self._agent_llm_cache.put(loop, agent_name, cached)
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

        It carries this job's truncation ledger, so every toolkit it opens
        records its guardrail decisions where the run summary reads them.
        """
        with self._lock:
            if self._server_registry_cache is None:
                from maljan.providers.servers import ServerRegistry

                self._server_registry_cache = ServerRegistry(
                    self.config, truncation_ledger=self._truncation_ledger
                )
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

    def get_evidence_corpus(self) -> RunEvidenceCorpus | None:
        """Return the per-job record of what the run's tools answered, or ``None``.

        ``None`` once the container is closed. Every reader takes that as "no
        corpus", which is the answer that makes an absence a note rather than a
        reason to remove something.
        """
        return self._evidence_corpus

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

    def drain_all_judge_budget_records(self) -> list[dict[str, Any]]:
        """Every budget row the judge agents' loops left, from each cached role.

        Drained beside the ledger and for the same reason: the judge is cached
        per role, only some of those instances run a tool loop, and a meter
        that is never drained reports nothing for the one loop with a hard
        wall-clock timeout.
        """
        with self._lock:
            judges = list(self._judge_agent_cache.values())
        rows: list[dict[str, Any]] = []
        for judge in judges:
            drain = getattr(judge, "drain_budget_records", None)
            if drain is None:
                continue
            try:
                rows.extend(drain() or [])
            except Exception as exc:  # noqa: BLE001 — the meter never fails a run
                logger.debug("budget drain skipped for a judge agent: %s", exc)
        return rows

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

    def job_key(self) -> str:
        """The job identity handed to every resolver and every handle.

        One key per job: the handles' same-job short circuit compares it, so a
        container that answered differently for two of its agents would close
        and reopen every server between them.

        A caller with no job id of its own — the command line, a probe, a
        script — gets one per run. The key names the directory a tool server
        stages in, and the constant it used to be meant two ``maljan`` runs on
        one machine writing into one directory, each able to name the other's
        upload and carved payloads by their paths. One per run rather than one
        per process, because a pid comes round again: this is fixed for the
        life of the container, different for the next one, and the run that
        composed it removes it (``MaljanApp.aclose``).
        """
        return self.job_id or self._run_key

    def get_agent(self, name: str) -> BaseAnalyst:
        """The agent definition ``name`` names, instantiated and wired.

        A built-in role runs its own class under the definition's key — a clone
        ``static_r2`` is a ``StaticAnalyst`` named ``static_r2`` — because
        those classes carry the provider-specific ISR extraction the goldens
        pin. A ``generic`` or ``lead`` role runs ``ConfigurableAnalyst``. Both get the
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
            resolved = resolve_agent(name, self, self.job_key())
            llm = cast(BaseChatModel, resolved.llm)
            if role in PROMPT_ROLES:
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
            # Every attach in this job asks for the same key, so a handle
            # already open for it is reused rather than torn down and reopened.
            agent._job_id = self.job_key()
            agent.token_ledger = getattr(self, "_token_ledger", None)
            agent.truncation_ledger = getattr(self, "_truncation_ledger", None)
            agent.evidence_counter = getattr(self, "_evidence_counter", None)
            agent.evidence_corpus = getattr(self, "_evidence_corpus", None)
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
                cached._job_id = self.job_key()
                cached.token_ledger = getattr(self, "_token_ledger", None)
                cached.truncation_ledger = getattr(self, "_truncation_ledger", None)
                cached.evidence_counter = getattr(self, "_evidence_counter", None)
                cached.evidence_corpus = getattr(self, "_evidence_corpus", None)
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

        # Last, and after the servers above are closed: what this run staged,
        # carved and fetched. Here rather than in one caller, because every
        # caller that has no worker behind it reaches teardown through this
        # method — the command line, a settings probe, a script — and each of
        # them would otherwise leave a directory of live malware for the TTL.
        # The worker removes it again in a ``finally`` of its own, and a
        # removal of what is already gone does nothing.
        try:
            from maljan.tools import staging

            staging.remove_job_staging(self.job_key())
        except Exception as exc:  # noqa: BLE001 — teardown never propagates
            logger.warning("Removing this run's staging failed (non-fatal): %s", exc)

        # And what this run saw, which is the other thing it held that outlives
        # nothing. Dropping the container already frees it; this drops it here
        # so a caller that keeps the container object alive after closing it —
        # a test harness, a script reading a result off it — does not keep a
        # run's whole tool output with it. Every reader of the corpus runs
        # before teardown: the run summary is built in the judge node and the
        # export's second-source test in the report node, both inside the run.
        #
        # ``None`` rather than an empty corpus. An empty one reports itself
        # complete, so anything grounding after teardown would be told the
        # evidence was whole — a sentinel that fails open on the one rule this
        # whole thread exists to protect. No corpus reads as no corpus.
        self._evidence_corpus = None

    def get_narrative_agent(self) -> Any | None:
        """Return the singleton NarrativeAgent or ``None`` in mock mode.

        Reuses ``get_judge_llm()`` — the judge LLM is already configured for
        structured-output prompts so no new provider build is needed. Callers
        receive ``None`` in mock mode and must fall back to the deterministic
        narrative template.

        One instance per container, holding the model it was built with, which
        is the shape the per-loop model store exists to avoid. It is safe
        because of the call site rather than because of this cache: the report
        node is the only caller and it runs on one loop. A second caller on
        another loop would need this to be per-loop as well.
        """
        if self.is_mock:
            return None
        with self._lock:
            if self._narrative_agent_cache is None:
                from maljan.reporting.narrative_agent import NarrativeAgent

                llm = self.get_reporter_llm()
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
        off (callers then simply skip the professional spine). Runs on the
        reporter's model like the NarrativeAgent, and pins it for the same
        reason and under the same condition: the report node is the one
        caller, on one loop.
        """
        if self.is_mock or not self.config.reporting.composer_enabled:
            return None
        with self._lock:
            if getattr(self, "_report_composer_cache", None) is None:
                from maljan.reporting.composer import ReportComposer

                rc = self.config.reporting
                self._report_composer_cache = ReportComposer(
                    llm=self.get_reporter_llm(),
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

    def load_data_for_agent(
        self,
        agent_name: str,
        *,
        file_hash: str,
        sandbox_report: dict[str, Any] | None = None,
        sample_path: str | None = None,
    ) -> list[TextChunk]:
        """The input text agent ``agent_name`` is handed, as chunks.

        Driven by ``AgentDefinition.data_sources``. An empty list means the
        slice the agent's *role* used to get, which is spelled out in
        ``_legacy_role_data`` below and is what every definition written before
        stages relies on: a static analyst read the sandbox report's ``target``
        block when there was one and the parsed sample otherwise, a dynamic
        analyst read the behaviour log, a network analyst the network block,
        and a generic agent read the sample plus the whole report.

        A non-empty list is taken literally and in order, which is the point of
        the field: a clone of the static analyst can be pointed at the network
        block without also becoming a network analyst.
        """
        definition = self.config.agents.definitions.get(agent_name)
        sources = list(definition.data_sources) if definition is not None else []
        if not sources:
            return self._legacy_role_data(agent_name, file_hash, sandbox_report)

        chunks: list[TextChunk] = []
        for source in sources:
            chunks.extend(
                self._data_source_chunks(agent_name, source, file_hash, sandbox_report, sample_path)
            )
        return chunks

    def _data_source_chunks(
        self,
        agent_name: str,
        source: str,
        file_hash: str,
        sandbox_report: dict[str, Any] | None,
        sample_path: str | None,
    ) -> list[TextChunk]:
        """One vocabulary entry, resolved. A source with nothing behind it is empty.

        Empty rather than a placeholder: an agent that asked for the sandbox
        network block on a sample that was never detonated has no network
        block, and the no-data guard in the analyst node is the right place for
        that to be reported once, not once per source.
        """
        if source == "sample.path":
            path = sample_path or ""
            if not path:
                return []
            return self.loader.chunk_text(agent_name, f"analysis_file_path: {path}")
        if source == "sample.chunks":
            return self.load_chunked(file_hash, agent_name)
        if not sandbox_report:
            return []
        return self._sandbox_slice(agent_name, source, sandbox_report)

    def _sandbox_slice(
        self, agent_name: str, source: str, sandbox_report: dict[str, Any]
    ) -> list[TextChunk]:
        import json

        if source == "sandbox.target":
            return self.loader.chunk_text(
                agent_name, json.dumps(sandbox_report.get("target", {}), indent=2, default=str)
            )
        if source == "sandbox.network":
            network = sandbox_report.get("network", {})
            try:
                text = self.parser_registry.create("network").parse(network)
            except KeyError:
                text = json.dumps(network, indent=2, default=str)
            return self.loader.chunk_text(agent_name, text)
        if source == "sandbox.behavior":
            try:
                text = self.parser_registry.create("dynamic").parse(sandbox_report)
            except KeyError:
                text = json.dumps(sandbox_report, indent=2, default=str)
            return self.loader.chunk_text(agent_name, text)
        return self.loader.chunk_text(agent_name, json.dumps(sandbox_report, indent=2, default=str))

    def _legacy_role_data(
        self, agent_name: str, file_hash: str, sandbox_report: dict[str, Any] | None
    ) -> list[TextChunk]:
        """What the agent's role read before ``data_sources`` existed.

        Kept as one branch rather than expressed as a default source list,
        because it is not a list: the static role's slice *depends on whether a
        sandbox report exists*, and writing that as ``["sandbox.target",
        "sample.chunks"]`` would hand a detonated sample both instead of one.
        """
        role = self.agent_role(agent_name)
        if role in PROMPT_ROLES:
            static_context = self.load_chunked(file_hash, agent_name)
            sandbox_chunks: list[TextChunk] = []
            if sandbox_report:
                sandbox_chunks = self._sandbox_slice(agent_name, "sandbox.full", sandbox_report)
            return [*static_context, *sandbox_chunks]
        if sandbox_report:
            slice_name = {
                "static": "sandbox.target",
                "network": "sandbox.network",
                "dynamic": "sandbox.behavior",
            }.get(role, "sandbox.full")
            return self._sandbox_slice(agent_name, slice_name, sandbox_report)
        return self.load_chunked(file_hash, agent_name)

    def get_function_summarizer(self) -> FunctionSummarizer | None:
        if not self.config.preprocessing.use_function_summarizer:
            return None
        with self._lock:
            if self._function_summarizer_cache is None:
                from maljan.analysis.function_summarizer import FunctionSummarizer

                if self._llm_registry is None:
                    raise ConfigurationError("Cannot build FunctionSummarizer LLM in mock mode.")
                summarizer_llm = self.get_summarizer_llm()
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

    def _announce_index_retry(self) -> None:
        """Put ``validation.index_retry_seconds`` where every consumer can read it.

        The knowledge sidecar is the process where an ATT&CK index build
        actually happens, and it reads the setting out of its own environment
        (``env_allow`` carries the name). This is the one place that puts it
        there, beside the tracing values: the container is what builds the
        sidecar registry, so a sidecar started from any entry point that has a
        container — a script, a test harness, the API — reads the deployment's
        number rather than the module default. It used to be announced from
        ``MaljanApp.arun``, which is one entry point of several.
        """
        from maljan.tools import knowledge as knowledge_tools

        seconds = int(getattr(getattr(self.config, "validation", None), "index_retry_seconds", 900))
        os.environ[knowledge_tools.INDEX_RETRY_ENV] = str(seconds)
        knowledge_tools.set_index_retry_after(seconds)

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
