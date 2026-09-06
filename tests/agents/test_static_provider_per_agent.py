"""A static analyst reads the provider its definition names, not the global one."""

from __future__ import annotations

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


def _container(**agents) -> ServiceContainer:
    return ServiceContainer(Settings(_env_file=None, agents=agents), mock=True)


def test_the_built_in_static_analyst_reads_the_globally_configured_provider():
    container = _container()
    agent = container.get_agent("static")
    assert agent._provider() is container.get_static_provider()
    assert agent._provider().id == "ghidra"


def test_a_clone_reads_its_own_provider():
    container = _container(
        definitions={"static_r2": {"role": "static", "static_provider": "r2"}},
        profiles={"two": {"analysts": ["static", "static_r2"]}},
        profile="two",
    )
    clone = container.get_agent("static_r2")
    assert clone._provider().id == "r2"
    assert clone._provider() is not container.get_agent("static")._provider()


def test_an_analyst_without_a_container_still_falls_back_to_the_global_provider():
    """Standalone use (tests, scripts) keeps working with no container at all."""
    from maljan.agents.static_analyst import StaticAnalyst

    agent = StaticAnalyst(llm=None, name="static")  # type: ignore[arg-type]
    assert agent._provider().id == "ghidra"
