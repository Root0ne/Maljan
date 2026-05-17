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
    cape2, triage) and caches it for the lifetime of the container.
"""

from __future__ import annotations

import os
import threading
from typing import TYPE_CHECKING, Any

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.registry import AgentRegistry
from maljan.core.config import Settings
from maljan.core.exceptions import ConfigurationError
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
    """Central service locator that manages all subsystem lifecycles."""

    def __init__(
        self,
        config: Settings,
        mock: bool = False,
        samples_dir: str = "data/samples",
    ) -> None:
        self.config = config
        self.mock = mock

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
        self._samples_dir = str(resolve_data(samples_dir))

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

    def get_expert_llm(self) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        with self._lock:
            if self._expert_llm_cache is None:
                self._expert_llm_cache = self._llm_registry.build_model(role="expert")
            return self._expert_llm_cache

    def get_judge_llm(self) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        with self._lock:
            if self._judge_llm_cache is None:
                self._judge_llm_cache = self._llm_registry.build_model(role="judge")
            return self._judge_llm_cache

    def get_agent_llm(self, agent_name: str) -> BaseChatModel:
        if self._llm_registry is None:
            raise ConfigurationError("Cannot build LLM in mock mode.")
        with self._lock:
            cached = self._agent_llm_cache.get(agent_name)
            if cached is None:
                cached = self._llm_registry.build_model_for_agent(agent_name)
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

                self._sandbox_client_cache = MockSandboxClient(fixtures_dir=self._samples_dir)
                logger.info(
                    "Sandbox backend: MockSandboxClient (fixtures_dir=%s).",
                    self._samples_dir,
                )
            return self._sandbox_client_cache

    def get_agent(self, name: str) -> BaseAnalyst:
        with self._lock:
            cached = self._agent_cache.get(name)
            if cached is None:
                cached = self.agent_registry.create(name, self.get_agent_llm(name))
                self._agent_cache[name] = cached
            return cached

    def get_judge_agent(self, role: str = "judge") -> Any:
        with self._lock:
            cached = self._judge_agent_cache.get(role)
            if cached is None:
                from maljan.agents.judge_agent import JudgeAgent

                llm = self.get_judge_llm() if role == "judge" else self.get_expert_llm()
                cached = JudgeAgent(llm=llm)
                self._judge_agent_cache[role] = cached
            return cached

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
                self._narrative_agent_cache = NarrativeAgent(llm=llm, max_input_tokens=max_tokens)
            return self._narrative_agent_cache

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
