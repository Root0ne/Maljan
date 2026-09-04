"""Tests for the ServiceContainer DI system."""

from unittest.mock import MagicMock

import pytest

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.core.exceptions import ConfigurationError


class TestServiceContainer:
    """Tests for ServiceContainer mock/real mode."""

    def test_container_initializes_in_mock_mode(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        assert container.is_mock is True
        assert len(container.agent_registry.list_agents()) >= 3
        assert len(container.parser_registry.list_parsers()) >= 3

    def test_container_raises_on_llm_in_mock_mode(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        with pytest.raises(ConfigurationError, match="mock"):
            container.get_expert_llm()

    def test_container_raises_on_judge_llm_in_mock_mode(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        with pytest.raises(ConfigurationError, match="mock"):
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


class TestAcloseNeverBuildsAProviderJustToCloseIt:
    """M6 (final review): both teardown calls used to go through the
    ``get_*_provider()`` builders, so a job that never touched a provider
    built one at shutdown anyway — and a misconfigured ``provider`` id
    turned a harmless teardown into a ``ProviderConfigurationError`` landing
    in the aclose warning handler instead of just doing nothing."""

    @pytest.mark.asyncio
    async def test_a_job_that_never_touched_a_provider_builds_none_at_teardown(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        # A misconfigured id: if aclose() called get_static_provider() or
        # get_sandbox_provider() (which build-on-demand and cache), this
        # would raise ProviderConfigurationError from inside the registry.
        container.config.static.provider = "not-a-real-provider"  # type: ignore[assignment]
        container.config.sandbox.provider = "also-not-real"  # type: ignore[assignment]
        assert container._static_provider_cache is None
        assert container._sandbox_provider_cache is None

        await container.aclose()  # must not raise

        assert container._static_provider_cache is None
        assert container._sandbox_provider_cache is None

    @pytest.mark.asyncio
    async def test_a_provider_that_was_built_is_still_closed(self) -> None:
        container = ServiceContainer(config=Settings(), mock=True)
        static_provider = MagicMock()
        sandbox_provider = MagicMock()
        container._static_provider_cache = static_provider
        container._sandbox_provider_cache = sandbox_provider

        await container.aclose()

        static_provider.close.assert_called_once()
        sandbox_provider.close.assert_called_once()
