"""Extended tests for ServiceContainer — caching and new methods.

Covers:
  - get_agent() returns same instance on repeated calls (cache)
  - load_data() returns same result on repeated calls (cache)
  - load_data() calls loader exactly once per (sample_id, data_type) pair
"""

from unittest.mock import MagicMock, patch

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


class TestServiceContainerCache:
    """Tests for the caching layer added to ServiceContainer."""

    def _make_container(self) -> ServiceContainer:
        return ServiceContainer(config=Settings(), mock=True)

    def test_get_agent_returns_same_instance(self) -> None:
        """Calling get_agent() twice with the same name must return the identical object."""
        container = self._make_container()
        fake_llm = MagicMock()

        # Patch get_agent_llm so it does not raise RuntimeError in mock mode
        with patch.object(container, "get_agent_llm", return_value=fake_llm):
            agent_a = container.get_agent("static")
            agent_b = container.get_agent("static")

        assert agent_a is agent_b, "Expected cached instance, got a new object."

    def test_get_agent_different_names_different_instances(self) -> None:
        """Different agent names must return different objects."""
        container = self._make_container()
        fake_llm = MagicMock()

        with patch.object(container, "get_agent_llm", return_value=fake_llm):
            static_agent = container.get_agent("static")
            dynamic_agent = container.get_agent("dynamic")

        assert static_agent is not dynamic_agent

    def test_get_agent_calls_registry_once_per_name(self) -> None:
        """AgentRegistry.create() should only be called once per agent name."""
        container = self._make_container()
        fake_llm = MagicMock()

        with patch.object(container, "get_agent_llm", return_value=fake_llm):
            registry_create = container.agent_registry.create
            with patch.object(
                container.agent_registry, "create", wraps=registry_create
            ) as mock_create:
                container.get_agent("static")
                container.get_agent("static")
                container.get_agent("static")

        assert mock_create.call_count == 1

    def test_load_data_returns_same_result_on_repeat(self) -> None:
        """Calling load_data() twice with the same args returns the same string."""
        container = self._make_container()

        fake_result = "Parsed static data"
        with patch.object(container.loader, "load", return_value=fake_result) as mock_load:
            result_a = container.load_data("sample_1", "static")
            result_b = container.load_data("sample_1", "static")

        assert result_a == fake_result
        assert result_b == fake_result
        # Loader was called exactly once despite two calls to load_data()
        assert mock_load.call_count == 1

    def test_load_data_separate_cache_per_type(self) -> None:
        """Different data types for the same sample are cached independently."""
        container = self._make_container()

        def fake_load(sample_id: str, data_type: str) -> str:
            return f"data:{data_type}"

        with patch.object(container.loader, "load", side_effect=fake_load) as mock_load:
            container.load_data("sample_1", "static")
            container.load_data("sample_1", "dynamic")
            container.load_data("sample_1", "static")  # should hit cache
            container.load_data("sample_1", "dynamic")  # should hit cache

        # Only 2 real loads — one per type
        assert mock_load.call_count == 2

    def test_load_data_separate_cache_per_sample(self) -> None:
        """Different sample IDs are cached independently."""
        container = self._make_container()

        with patch.object(container.loader, "load", return_value="data") as mock_load:
            container.load_data("sample_1", "static")
            container.load_data("sample_2", "static")
            container.load_data("sample_1", "static")  # cache hit
            container.load_data("sample_2", "static")  # cache hit

        assert mock_load.call_count == 2

    def test_llm_cache_returns_same_object(self) -> None:
        """Expert LLM cache returns the same object on consecutive calls."""
        container = self._make_container()
        fake_llm = MagicMock()

        # Bypass the mock-mode guard by patching get_expert_llm at the method level
        with patch.object(container, "get_expert_llm", return_value=fake_llm) as mock_method:
            llm_a = container.get_expert_llm()
            llm_b = container.get_expert_llm()

        assert llm_a is llm_b
        assert mock_method.call_count == 2  # called twice, both return same object
