"""ServiceContainer - Dependency Injection / Composition Root.

Wires together all registries, loaders, and provides factory methods
for creating agents and LLM instances. Replaces scattered global state
and `_is_mock_mode()` checks with a single, testable container.
"""

from __future__ import annotations

from langchain_core.language_models.chat_models import BaseChatModel

from maljan.agents.registry import AgentRegistry
from maljan.core.config import Settings
from maljan.core.logger import logger
from maljan.llm.registry import LLMProviderRegistry
from maljan.loaders.file_loader import FileDataLoader
from maljan.parsers.registry import ParserRegistry


class ServiceContainer:
    """Central service locator that manages all subsystem lifecycles.

    Usage:
        container = ServiceContainer(config=settings, mock=True)
        agents = container.agent_registry.list_agents()
        llm = container.get_expert_llm()
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

        logger.info(
            f"ServiceContainer initialized "
            f"(mock={mock}, agents={self.agent_registry.list_agents()}, "
            f"parsers={self.parser_registry.list_parsers()})"
        )

    @property
    def is_mock(self) -> bool:
        """Whether the container is in mock mode."""
        return self.mock

    def get_expert_llm(self) -> BaseChatModel:
        """Build and return an expert-role LLM instance."""
        if self._llm_registry is None:
            raise RuntimeError("Cannot build LLM in mock mode.")
        return self._llm_registry.build_model(role="expert")

    def get_judge_llm(self) -> BaseChatModel:
        """Build and return a judge-role LLM instance."""
        if self._llm_registry is None:
            raise RuntimeError("Cannot build LLM in mock mode.")
        return self._llm_registry.build_model(role="judge")
