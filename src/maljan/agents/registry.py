"""Agent registry with auto-discovery via decorator.

Usage:
    @register_agent("static")
    class StaticAnalyst(BaseAnalyst):
        ...

The registry is module-level. When agent modules are imported (via
`discover_agents()`), the decorator fires and registers each class.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

from maljan.core.logger import logger

if TYPE_CHECKING:
    from langchain_core.language_models.chat_models import BaseChatModel

    from maljan.agents.base_agent import BaseAnalyst

# Module-level registry dict: agent_name -> (class, enabled).
_AGENT_REGISTRY: dict[str, tuple[type[BaseAnalyst], bool]] = {}
# Re-entrant: discover_agents() acquires the lock and then imports agent
# modules; each module's @register_agent decorator re-enters the same lock.
_REGISTRY_LOCK = threading.RLock()
_DISCOVERY_DONE = False


def register_agent(name: str, enabled: bool = True):  # type: ignore[no-untyped-def]
    """Decorator that registers an analyst class under the given name.

    Example:
        @register_agent("memory")
        class MemoryAnalyst(BaseAnalyst): ...

        @register_agent("experimental", enabled=False)
        class ExperimentalAnalyst(BaseAnalyst): ...
    """

    def decorator(cls: type[BaseAnalyst]) -> type[BaseAnalyst]:
        with _REGISTRY_LOCK:
            if name in _AGENT_REGISTRY:
                logger.debug("Agent '%s' re-registered (overwriting).", name)
            _AGENT_REGISTRY[name] = (cls, enabled)
        return cls

    return decorator


def discover_agents() -> None:
    """Import all built-in agent modules once to trigger @register_agent."""
    global _DISCOVERY_DONE
    if _DISCOVERY_DONE:
        return
    with _REGISTRY_LOCK:
        if _DISCOVERY_DONE:
            return
        import maljan.agents.dynamic_analyst  # noqa: F401
        import maljan.agents.network_analyst  # noqa: F401
        import maljan.agents.static_analyst  # noqa: F401

        _DISCOVERY_DONE = True


class AgentRegistry:
    """Provides access to registered analyst classes."""

    def __init__(self) -> None:
        discover_agents()

    def list_agents(self, include_disabled: bool = False) -> list[str]:
        """Returns names of registered expert agents.

        By default only enabled agents are returned. Pass include_disabled=True
        to see all registered agents.
        """
        if include_disabled:
            return list(_AGENT_REGISTRY.keys())
        return [name for name, (_, enabled) in _AGENT_REGISTRY.items() if enabled]

    def get_class(self, name: str) -> type[BaseAnalyst]:
        """Returns the class registered under the given name."""
        if name not in _AGENT_REGISTRY:
            available = ", ".join(_AGENT_REGISTRY.keys()) or "(none)"
            raise KeyError(f"No agent registered as '{name}'. Available: {available}")
        return _AGENT_REGISTRY[name][0]

    def create(self, name: str, llm: BaseChatModel) -> BaseAnalyst:
        """Instantiate a registered agent with the given LLM."""
        cls = self.get_class(name)
        return cls(llm=llm, name=name)
