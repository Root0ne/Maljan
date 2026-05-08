"""Tests for the ServiceContainer DI system."""

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


class TestServiceContainer:
    """Tests for ServiceContainer mock/real mode."""

    def test_container_initializes_in_mock_mode(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        assert container.is_mock is True
        assert len(container.agent_registry.list_agents()) >= 3
        assert len(container.parser_registry.list_parsers()) >= 3

    def test_container_raises_on_llm_in_mock_mode(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        with pytest.raises(RuntimeError, match="mock"):
            container.get_expert_llm()

    def test_container_raises_on_judge_llm_in_mock_mode(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        with pytest.raises(RuntimeError, match="mock"):
            container.get_judge_llm()

    def test_container_agent_registry_creates_agents_in_mock(self) -> None:
        """Agents can still be listed/inspected in mock mode."""
        container = ServiceContainer(config=Settings(), mock=True)
        agents = container.agent_registry.list_agents()
        assert isinstance(agents, list)
        assert len(agents) > 0

    def test_load_sandbox_data_for_agent(self) -> None:
        """load_sandbox_data_for_agent distributes report fields correctly."""
        container = ServiceContainer(config=Settings(), mock=True)
        report = {
            "target": {"file": {"sha256": "abc123", "name": "test.exe"}},
            "behavior": {"processes": [], "apistats": {}},
            "network": {
                "dns": [{"request": "evil.com"}],
                "http": [],
                "tcp": [],
                "hosts": [],
                "domains": [],
            },
            "signatures": [],
            "ttp_tags": [],
        }

        static_chunks = container.load_sandbox_data_for_agent("static", report)
        assert len(static_chunks) >= 1
        assert "abc123" in static_chunks[0].content

        dynamic_chunks = container.load_sandbox_data_for_agent("dynamic", report)
        assert len(dynamic_chunks) >= 1

        network_chunks = container.load_sandbox_data_for_agent("network", report)
        assert len(network_chunks) >= 1
        assert "evil.com" in network_chunks[0].content
