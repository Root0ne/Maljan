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
    ``get_sandbox_client()`` returns the configured sandbox client (mock,
    cape2) and caches it for the lifetime of the container.
"""

from __future__ import annotations

import asyncio
import os
import threading
from typing import TYPE_CHECKING, Any

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

if TYPE_CHECKING:
    from maljan.agents.base_agent import BaseAnalyst
    from maljan.analysis.function_summarizer import FunctionSummarizer
    from maljan.analysis.sigma_layer import SigmaLayer
    from maljan.analysis.yara_layer import YaraLayer
    from maljan.loaders.binary_chunker import TextChunk
    from maljan.loaders.sandbox_client import SandboxClient
    from maljan.memory.long_term_memory import MemoryStore
    from maljan.pipeline.events import EventSink


# Per-closer budget in ``aclose``. Each toolkit is already bounded internally;
# this is the second fence, because a teardown that hangs holds the whole job
# open and — with ``max_jobs = 1`` — every job after it.
_ACLOSE_BUDGET = 20.0


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
        self._sandbox_client_cache: SandboxClient | None = None
        self._yara_layer_cache: YaraLayer | None = None
        self._sigma_layer_cache: SigmaLayer | None = None
        self._function_summarizer_cache: FunctionSummarizer | None = None
        self._narrative_agent_cache: Any | None = None
        self._report_composer_cache: Any | None = None
        self._samples_dir = str(resolve_data(samples_dir))

        # Per-run LLM token/cost ledger (findings-log §4 Item 1). Agents and the
        # judge add each call's usage; the judge node snapshots it into RunSummary.
        self._token_ledger = TokenLedger()

        # Per-run truncation ledger (pitfall P6). Same lifecycle as the token
        # ledger: written to at every bound, snapshotted by the judge node.
        # Truncation is designed into this pipeline and has never been counted.
        self._truncation_ledger = TruncationLedger()

        logger.info(
            "ServiceContainer initialized (mock=%s, agents=%s, parsers=%s)",
            mock,
            self.agent_registry.list_agents(),
            self.parser_registry.list_parsers(),
        )

        self._configure_langsmith()

    @property
    def is_mock(self) -> bool:
        return self.mock

    # ------------------------------------------------------------------
    # LLM accessors
    # ------------------------------------------------------------------

    def _expert_token_cap(self) -> dict[str, int]:
        """``max_tokens`` kwargs for analyst-role models, or ``{}`` when unset.

        Audit 2026-07-26 (Ö3): the analyst path was the only unbounded LLM call
        in the system while judge/narrative/composer were all capped. MEASURED:
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
                extra: dict[str, int] = {}
                cap = self.config.llm.judge_max_tokens
                if cap and cap > 0:
                    extra["max_tokens"] = cap
                self._judge_llm_cache = self._llm_registry.build_model(role="judge", **extra)
            return self._judge_llm_cache

    def get_agent_llm(self, agent_name: str) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        with self._lock:
            cached = self._agent_llm_cache.get(agent_name)
            if cached is None:
                # Analysts share the expert budget cap — this is the path the
                # static/dynamic/network ReAct loops and their forced-synthesis
                # fallback actually use (audit 2026-07-26, Ö3).
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

    def get_sandbox_client(self) -> SandboxClient:
        with self._lock:
            if self._sandbox_client_cache is not None:
                return self._sandbox_client_cache

            if self.mock:
                from maljan.loaders.mock_sandbox_client import MockSandboxClient

                self._sandbox_client_cache = MockSandboxClient(fixtures_dir=self._samples_dir)
                logger.info(
                    "Sandbox backend: MockSandboxClient (mock=True, fixtures_dir=%s).",
                    self._samples_dir,
                )
                return self._sandbox_client_cache

            backend = self.config.sandbox.provider
            if backend == "cape2":
                from maljan.loaders.cape2_client import CAPEv2Client

                self._sandbox_client_cache = CAPEv2Client(
                    base_url=self.config.sandbox.cape2.base_url,
                    api_token=self.config.sandbox.cape2.api_token,
                )
                logger.info(
                    "Sandbox backend: CAPEv2Client (url=%s).",
                    self.config.sandbox.cape2.base_url,
                )
            else:
                from maljan.loaders.mock_sandbox_client import MockSandboxClient

                self._sandbox_client_cache = MockSandboxClient(fixtures_dir=self._samples_dir)
                logger.info(
                    "Sandbox backend: MockSandboxClient (fixtures_dir=%s).",
                    self._samples_dir,
                )
            return self._sandbox_client_cache

    def get_token_ledger(self) -> TokenLedger:
        """Return the per-run LLM token/cost ledger (findings-log §4 Item 1)."""
        return self._token_ledger

    def get_truncation_ledger(self) -> TruncationLedger:
        """Return the per-run truncation ledger (pitfall P6)."""
        return self._truncation_ledger

    def get_agent(self, name: str) -> BaseAnalyst:
        with self._lock:
            cached = self._agent_cache.get(name)
            if cached is None:
                cached = self.agent_registry.create(name, self.get_agent_llm(name))
                # Wire the per-run token ledger so the agent's LLM calls are tallied.
                cached.token_ledger = getattr(self, "_token_ledger", None)
                cached.truncation_ledger = getattr(self, "_truncation_ledger", None)
                # Hand the agent a way back to this container. The static
                # analyst used to construct a *whole new* ServiceContainer on
                # every failed MCP init — per chunk, so up to ten of them per
                # run, each rebuilding the Sigma and YARA layers.
                cached._container = self
                self._agent_cache[name] = cached
            return cached

    def get_judge_agent(self, role: str = "judge") -> Any:
        with self._lock:
            cached = self._judge_agent_cache.get(role)
            if cached is None:
                from maljan.agents.judge_agent import JudgeAgent

                llm = self.get_judge_llm() if role == "judge" else self.get_expert_llm()
                cached = JudgeAgent(
                    llm=llm,
                    category_backend=self.config.preprocessing.category_inference_backend,
                    # Without this the judge's structured-output capability
                    # check fell back to ``ChatOpenAI._llm_type`` and misread
                    # every provider — see _supports_structured_output.
                    config=self.config,
                )
                cached.token_ledger = getattr(self, "_token_ledger", None)
                cached.truncation_ledger = getattr(self, "_truncation_ledger", None)
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

        # The sample's parsed text and the per-job analysis layers. Not a leak
        # on their own — the container dies with the job — but dropping them
        # here means a worker that is *not* recycled starts the next job with a
        # clean floor rather than one job's residue.
        with self._lock:
            self._data_cache.clear()
            self._yara_layer_cache = None
            self._sigma_layer_cache = None
            self._function_summarizer_cache = None
            self._narrative_agent_cache = None
            self._report_composer_cache = None

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

        Reshaping Phase 4. ``None`` in mock mode or when ``composer_enabled`` is
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
        """Parse and chunk sandbox report data for a specific agent."""
        import json

        if agent_name == "static":
            target = sandbox_report.get("target", {})
            text = json.dumps(target, indent=2, default=str)
        elif agent_name == "network":
            network = sandbox_report.get("network", {})
            try:
                parser = self.parser_registry.create("network")
                text = parser.parse(network)
            except KeyError:
                text = json.dumps(network, indent=2, default=str)
        elif agent_name == "dynamic":
            try:
                parser = self.parser_registry.create("dynamic")
                text = parser.parse(sandbox_report)
            except KeyError:
                text = json.dumps(sandbox_report, indent=2, default=str)
        else:
            text = json.dumps(sandbox_report, indent=2, default=str)

        return self.loader.chunk_text(agent_name, text)

    # ------------------------------------------------------------------
    # Deterministic layers
    # ------------------------------------------------------------------

    def get_yara_layer(self) -> YaraLayer:
        with self._lock:
            if self._yara_layer_cache is None:
                from maljan.analysis.yara_layer import YaraLayer

                self._yara_layer_cache = YaraLayer.from_default_rules()
            return self._yara_layer_cache

    def get_sigma_layer(self) -> SigmaLayer:
        with self._lock:
            if self._sigma_layer_cache is None:
                from maljan.analysis.sigma_layer import SigmaLayer
                from maljan.core.paths import resolve_data

                rules_dir = resolve_data(self.config.analysis.sigma_rules_dir)
                self._sigma_layer_cache = SigmaLayer.from_rules_dir(rules_dir)
                logger.info(
                    "SigmaLayer initialized: %d rules loaded from %s.",
                    self._sigma_layer_cache.rule_count,
                    rules_dir,
                )
            return self._sigma_layer_cache

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
            logger.info(  # nosemgrep
                "LangSmith tracing enabled (project=%s, api_key=***%s).",
                self.config.langchain_project,
                secret_value[-4:] if len(secret_value) >= 4 else "****",
            )
        else:
            logger.warning(
                "LangSmith tracing enabled (project=%s) but no API key provided. "
                "Set LANGCHAIN_API_KEY in .env to authenticate with LangSmith.",
                self.config.langchain_project,
            )
