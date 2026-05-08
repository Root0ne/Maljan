"""Tests for the Registry Pattern implementations."""

import pytest

from maljan.agents.registry import AgentRegistry
from maljan.parsers.registry import ParserRegistry


class TestAgentRegistry:
    """Tests for AgentRegistry auto-discovery and CRUD."""

    def test_registry_discovers_built_in_agents(self) -> None:
        registry = AgentRegistry()
        agents = registry.list_agents()
        assert "static" in agents
        assert "dynamic" in agents
        assert "network" in agents

    def test_registry_list_returns_stable_order(self) -> None:
        registry = AgentRegistry()
        agents1 = registry.list_agents()
        agents2 = registry.list_agents()
        assert agents1 == agents2

    def test_get_class_returns_correct_type(self) -> None:
        from maljan.agents.static_analyst import StaticAnalyst

        registry = AgentRegistry()
        cls = registry.get_class("static")
        assert cls is StaticAnalyst

    def test_get_class_unknown_raises_key_error(self) -> None:
        registry = AgentRegistry()
        with pytest.raises(KeyError, match="nonexistent_agent"):
            registry.get_class("nonexistent_agent")


class TestParserRegistry:
    """Tests for ParserRegistry auto-discovery and CRUD."""

    def test_registry_discovers_built_in_parsers(self) -> None:
        registry = ParserRegistry()
        parsers = registry.list_parsers()
        assert "static" in parsers
        assert "dynamic" in parsers
        assert "network" in parsers

    def test_create_returns_instance(self) -> None:
        from maljan.parsers.static_parser import StaticParser

        registry = ParserRegistry()
        parser = registry.create("static")
        assert isinstance(parser, StaticParser)

    def test_create_unknown_raises_key_error(self) -> None:
        registry = ParserRegistry()
        with pytest.raises(KeyError):
            registry.create("nonexistent")

