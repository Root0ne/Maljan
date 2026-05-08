"""ServiceContainer - Dependency Injection / Composition Root.

Wires together all registries, loaders, and provides factory methods
for creating agents and LLM instances. Replaces scattered global state
and `_is_mock_mode()` checks with a single, testable container.

Caching: LLM instances, agent instances, and loaded sample data are all
cached so that repeated calls during the negotiation loop do not incur
redundant object creation or I/O.

Heterogeneous Model Ensemble:
  get_agent_llm(agent_name) returns a per-agent LLM instance using
  LLMConfig.agents overrides. When an agent has a dedicated config entry,
  a distinct model/provider is used for that agent. This ensures that
  different expert agents use different model families, reducing echo chamber
  risk per the unanimous research finding (ReConcile + Wu et al.).
  Agents without overrides fall back to the global expert LLM.

LangSmith Observability (Phase 8.1):
  When Settings.langchain_tracing_v2 is True, _configure_langsmith() sets
  the OS environment variables that LangChain reads automatically:
    LANGCHAIN_TRACING_V2  = "true"
    LANGCHAIN_API_KEY     = Settings.langchain_api_key
    LANGCHAIN_PROJECT     = Settings.langchain_project
  All LLM calls, negotiation rounds, ISR constructions, and TTP mappings
  become visible in the LangSmith dashboard with full trace trees.
  Enable via .env: LANGCHAIN_TRACING_V2=true LANGCHAIN_API_KEY=ls_xxx

Phase 6 (CAPEv2 Sandbox):
  get_sandbox_client() returns a SandboxClient-protocol object based on
  Settings.sandbox.backend:
    "mock"  -> MockSandboxClient(fixtures_dir=samples_dir)  [default]
    "cape2" -> CAPEv2Client(url, token)                     [requires httpx + CAPEv2]
  The client is cached so all pipeline components share the same instance.
  Pass it to FileDataLoader.load_from_sandbox() to analyse live samples.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.registry import AgentRegistry
from maljan.core.config import Settings
from maljan.core.logger import logger
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


class ServiceContainer:
    """Central service locator that manages all subsystem lifecycles.

    Usage:
        container = ServiceContainer(config=settings, mock=True)
        agents = container.agent_registry.list_agents()
        llm = container.get_expert_llm()
        agent = container.get_agent("static")
        data = container.load_data("abc123", "static")
    """

    def __init__(
        self,
        config: Settings,
        mock: bool = False,
        samples_dir: str = "data/samples",
    ) -> None:
        self.config = config
        self.mock = mock

        # Initialize registries (triggers auto-discovery)
        self.agent_registry = AgentRegistry()
        self.parser_registry = ParserRegistry()

        # LLM provider registry (None in mock mode)
        self._llm_registry: LLMProviderRegistry | None = None
        if not mock:
            self._llm_registry = LLMProviderRegistry(config)

        # Data loader
        self.loader = FileDataLoader(
            samples_dir=samples_dir,
            parser_registry=self.parser_registry,
        )

        # --- Caches ---
        # Global LLM instances (one per role, built lazily)
        self._expert_llm_cache: BaseChatModel | None = None
        self._judge_llm_cache: BaseChatModel | None = None
        # Per-agent LLM instances (built lazily, keyed by agent_name)
        self._agent_llm_cache: dict[str, BaseChatModel] = {}
        # Agent instances (one per registered name, built lazily)
        self._agent_cache: dict[str, BaseAnalyst] = {}
        # Loaded and parsed data (keyed by (sample_id, data_type))
        self._data_cache: dict[tuple[str, str], str] = {}
        # Phase 5: Long-term memory store (built lazily)
        self._memory_store_cache: MemoryStore | None = None
        # Phase 6: Sandbox client (built lazily)
        self._sandbox_client_cache: SandboxClient | None = None
        # TODO-1: YARA Layer 0 (built lazily)
        self._yara_layer_cache: YaraLayer | None = None
        # TODO-B: Sigma Layer 0 (built lazily)
        self._sigma_layer_cache: SigmaLayer | None = None
        # TODO-D: FunctionSummarizer (built lazily)
        self._function_summarizer_cache: FunctionSummarizer | None = None
        self._samples_dir = samples_dir

        logger.info(
            "ServiceContainer initialized (mock=%s, agents=%s, parsers=%s)",
            mock,
            self.agent_registry.list_agents(),
            self.parser_registry.list_parsers(),
        )

        # Phase 8.1: Configure LangSmith tracing if enabled
        self._configure_langsmith()

    @property
    def is_mock(self) -> bool:
        """Whether the container is in mock mode."""
        return self.mock

    def get_expert_llm(self) -> BaseChatModel:
        """Build and return a cached expert-role LLM instance."""
        if self._llm_registry is None:
            raise RuntimeError("Cannot build LLM in mock mode.")
        if self._expert_llm_cache is None:
            self._expert_llm_cache = self._llm_registry.build_model(role="expert")
        return self._expert_llm_cache

    def get_judge_llm(self) -> BaseChatModel:
        """Build and return a cached judge-role LLM instance."""
        if self._llm_registry is None:
            raise RuntimeError("Cannot build LLM in mock mode.")
        if self._judge_llm_cache is None:
            self._judge_llm_cache = self._llm_registry.build_model(role="judge")
        return self._judge_llm_cache

    def get_agent_llm(self, agent_name: str) -> BaseChatModel:
        """Build and return a cached per-agent LLM instance.

        Delegates to LLMProviderRegistry.build_model_for_agent() which checks
        LLMConfig.agents for a named override. When an override exists, a
        dedicated LLM (potentially different provider/model) is built for that
        agent. When no override exists, falls back to the global expert LLM.

        The result is cached per agent_name so repeated calls (e.g. across
        revision rounds) never rebuild the client unnecessarily.

        Args:
            agent_name: Agent registry key (e.g. "static", "dynamic", "network").

        Returns:
            Cached BaseChatModel for the given agent.
        """
        if self._llm_registry is None:
            raise RuntimeError("Cannot build LLM in mock mode.")
        if agent_name not in self._agent_llm_cache:
            self._agent_llm_cache[agent_name] = self._llm_registry.build_model_for_agent(agent_name)
        return self._agent_llm_cache[agent_name]

    def get_memory_store(self) -> MemoryStore:
        """Return the long-term memory store instance (Phase 5).

        Builds and caches a MemoryStore backend based on
        Settings.memory.backend:
          - "memory" (default): InMemoryStore — no external dependencies.
          - "qdrant": QdrantStore — requires qdrant-client + running Qdrant.

        The instance is cached so all components within a single analysis
        session share the same store. This ensures that cases stored during
        one pipeline run are immediately visible to subsequent retrievals in
        the same process.

        Returns:
            A MemoryStore-protocol-compliant object (InMemoryStore or
            QdrantStore).
        """
        if self._memory_store_cache is None:
            backend = self.config.memory.backend
            if backend == "qdrant":
                from maljan.memory.qdrant_store import QdrantStore

                self._memory_store_cache = QdrantStore(
                    url=self.config.memory.qdrant_url,
                    collection=self.config.memory.qdrant_collection,
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
        """Return the sandbox client instance (Phase 6).

        Builds and caches a SandboxClient backend based on
        Settings.sandbox.backend:
          - "mock"  (default): MockSandboxClient — no external dependencies,
            loads fixture JSON files from the samples directory.
          - "cape2": CAPEv2Client — submits samples to a live CAPEv2 instance
            via REST API. Requires uv add httpx and a running CAPEv2 server.

        The instance is cached so all pipeline components share the same client
        within a single analysis session.

        Returns:
            A SandboxClient-protocol-compliant object (MockSandboxClient or
            CAPEv2Client).
        """
        if self._sandbox_client_cache is None:
            if self.mock:
                from maljan.loaders.mock_sandbox_client import MockSandboxClient

                self._sandbox_client_cache = MockSandboxClient(
                    fixtures_dir=self._samples_dir,
                )
                logger.info(
                    "Sandbox backend: MockSandboxClient (mock=True, fixtures_dir=%s).",
                    self._samples_dir,
                )
                return self._sandbox_client_cache

            backend = self.config.sandbox.backend
            if backend == "cape2":
                from maljan.loaders.cape2_client import CAPEv2Client

                self._sandbox_client_cache = CAPEv2Client(
                    base_url=self.config.sandbox.cape2_base_url,
                    api_token=self.config.sandbox.cape2_api_token,
                )
                logger.info(
                    "Sandbox backend: CAPEv2Client (url=%s).",
                    self.config.sandbox.cape2_base_url,
                )
            elif backend == "triage":
                from maljan.loaders.triage_client import TriageClient

                self._sandbox_client_cache = TriageClient(
                    api_token=self.config.sandbox.triage_api_token,
                    base_url=self.config.sandbox.triage_base_url,
                    timeout=self.config.sandbox.triage_timeout_seconds,
                )
                logger.info(
                    "Sandbox backend: TriageClient (url=%s).",
                    self.config.sandbox.triage_base_url,
                )
            else:
                from maljan.loaders.mock_sandbox_client import MockSandboxClient

                self._sandbox_client_cache = MockSandboxClient(
                    fixtures_dir=self._samples_dir,
                )
                logger.info(
                    "Sandbox backend: MockSandboxClient (fixtures_dir=%s).",
                    self._samples_dir,
                )
        return self._sandbox_client_cache

    def get_agent(self, name: str) -> BaseAnalyst:
        """Return a cached agent instance for the given name.

        Agents are instantiated once and reused across all negotiation rounds,
        avoiding repeated object creation and LLM client initialization.

        Uses get_agent_llm() so each agent receives its own dedicated LLM
        instance when a per-agent config override is defined.
        """
        if name not in self._agent_cache:
            self._agent_cache[name] = self.agent_registry.create(name, self.get_agent_llm(name))
        return self._agent_cache[name]

    def load_data(self, sample_id: str, data_type: str) -> str:
        """Return cached parsed data for a sample and data type.

        The first call reads and parses the file; subsequent calls return
        the cached result, eliminating repeated disk I/O during revision rounds.
        """
        key = (sample_id, data_type)
        if key not in self._data_cache:
            self._data_cache[key] = self.loader.load(sample_id, data_type)
        return self._data_cache[key]

    def load_chunked(self, sample_id: str, data_type: str) -> list[TextChunk]:
        """Return a list of TextChunk objects for a sample and data type.

        Delegates to FileDataLoader.load_chunked() which uses the BinaryChunker
        configured from Settings.chunking. When the parsed text fits within the
        token limit (skip_if_fits=True), returns a single-element list so the
        analyst node takes the fast single-text path with zero overhead.

        The chunk list is NOT cached — each call re-evaluates the chunker. This
        is intentional: the chunker is stateless and cheap (no I/O), and caching
        chunk objects would complicate memory management.

        Args:
            sample_id: Hash or identifier for the sample.
            data_type: Domain type (e.g. \"static\", \"dynamic\", \"network\").

        Returns:
            Ordered list of TextChunk objects (at least one element).
        """

        # Re-use cached parsed text if available, then chunk.
        # This avoids double file I/O: load_data fills the cache, chunker re-splits.
        key = (sample_id, data_type)
        if key in self._data_cache:
            text = self._data_cache[key]
            return self.loader._chunker.chunk(data_type, text)

        # First access — load, cache, then chunk.
        return self.loader.load_chunked(sample_id, data_type)

    def load_sandbox_data_for_agent(
        self, agent_name: str, sandbox_report: dict[str, Any]
    ) -> list[TextChunk]:
        """Parse and chunk sandbox report data for a specific agent.

        Distributes the normalized Triage report fields to the appropriate
        agent parser:
          - "static"  -> target metadata (sha256, md5, name, size)
          - "dynamic" -> behavior + signatures + network indicators
          - "network" -> network section only (dns, http, tcp, hosts, domains)

        Args:
            agent_name:     Agent registry key ("static", "dynamic", "network").
            sandbox_report: Normalized report dict from TriageClient.

        Returns:
            List of TextChunk objects ready for the agent.
        """
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

        return self.loader._chunker.chunk(agent_name, text)

    def get_yara_layer(self) -> YaraLayer:
        """Return the cached YaraLayer instance (Layer 0).

        Loads rules from data/yara_ttp_rules.yaml on first call; subsequent
        calls return the cached instance.

        Returns:
            YaraLayer instance. Returns an empty-rules layer (no-op) if the
            rules file is not found, ensuring graceful degradation.
        """
        if self._yara_layer_cache is None:
            from maljan.analysis.yara_layer import YaraLayer

            self._yara_layer_cache = YaraLayer.from_default_rules()
        return self._yara_layer_cache

    def get_sigma_layer(self) -> SigmaLayer:
        """Return the cached SigmaLayer instance (TODO-B / Sigma Layer 0).

        Loads Sigma rules from Settings.analysis.sigma_rules_dir on first call.
        Subsequent calls return the cached singleton.

        Returns:
            SigmaLayer instance. Returns an empty-rules layer (no-op) if the
            rules directory is not found, ensuring graceful degradation.
        """
        if self._sigma_layer_cache is None:
            from pathlib import Path

            from maljan.analysis.sigma_layer import SigmaLayer

            rules_dir = Path(self.config.analysis.sigma_rules_dir)
            self._sigma_layer_cache = SigmaLayer.from_rules_dir(rules_dir)
            logger.info(
                "SigmaLayer initialized: %d rules loaded from %s.",
                self._sigma_layer_cache.rule_count,
                rules_dir,
            )
        return self._sigma_layer_cache

    def get_function_summarizer(self) -> FunctionSummarizer | None:
        """Return the FunctionSummarizer instance or None if disabled.

        Builds and caches the summarizer based on
        Settings.preprocessing.use_function_summarizer.
        When disabled (default), returns None and the pipeline is unaffected.

        Returns:
            FunctionSummarizer instance when enabled, None when disabled.
        """
        if not self.config.preprocessing.use_function_summarizer:
            return None
        if self._function_summarizer_cache is None:
            from maljan.analysis.function_summarizer import FunctionSummarizer

            if self._llm_registry is None:
                raise RuntimeError("Cannot build FunctionSummarizer LLM in mock mode.")
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
        """Configure LangSmith tracing by setting OS environment variables.

        Phase 8.1 implementation. LangChain reads tracing configuration from
        OS environment variables at import time and on each chain invocation.
        This method propagates the Settings values into the OS environment so
        that all subsequent LLM calls, chain invocations, and agent runs are
        automatically traced to the LangSmith project.

        Called once during ServiceContainer.__init__(). Idempotent: calling
        it again with the same config has no observable side-effect.

        When langchain_tracing_v2 is False (default), this method is a no-op
        and no environment variables are modified — preserving full isolation
        in test environments that do not set the tracing flag.

        Environment variables set:
            LANGCHAIN_TRACING_V2: "true" when tracing is enabled.
            LANGCHAIN_API_KEY:    LangSmith API key (only when provided).
            LANGCHAIN_PROJECT:    LangSmith project name (default: "maljan").
        """
        if not self.config.langchain_tracing_v2:
            logger.debug("LangSmith tracing disabled (langchain_tracing_v2=False).")
            return

        os.environ["LANGCHAIN_TRACING_V2"] = "true"
        os.environ["LANGCHAIN_PROJECT"] = self.config.langchain_project

        if self.config.langchain_api_key:
            os.environ["LANGCHAIN_API_KEY"] = self.config.langchain_api_key
            logger.info(
                "LangSmith tracing enabled (project=%s, api_key=***%s).",
                self.config.langchain_project,
                self.config.langchain_api_key[-4:],  # log only last 4 chars
            )
        else:
            logger.warning(
                "LangSmith tracing enabled (project=%s) but no API key provided. "
                "Set LANGCHAIN_API_KEY in .env to authenticate with LangSmith.",
                self.config.langchain_project,
            )
