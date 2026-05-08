"""Parser registry with auto-discovery via decorator.

Usage:
    @register_parser("static")
    class StaticParser(BaseParser):
        ...
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.parsers.base_parser import BaseParser

# Module-level registry dict: data_type -> class
_PARSER_REGISTRY: dict[str, type[BaseParser]] = {}


def register_parser(name: str):  # type: ignore[no-untyped-def]
    """Decorator that registers a parser class under the given data type name."""

    def decorator(cls: type[BaseParser]) -> type[BaseParser]:
        if name in _PARSER_REGISTRY:
            logger.warning(f"Parser '{name}' is being re-registered (overwriting).")
        _PARSER_REGISTRY[name] = cls
        return cls

    return decorator


def discover_parsers() -> None:
    """Import all built-in parser modules to trigger @register_parser decorators."""
    import maljan.parsers.dynamic_parser  # noqa: F401
    import maljan.parsers.network_parser  # noqa: F401
    import maljan.parsers.static_parser  # noqa: F401


class ParserRegistry:
    """Provides access to registered parser classes."""

    def __init__(self) -> None:
        discover_parsers()

    def list_parsers(self) -> list[str]:
        """Returns names of all registered parsers."""
        return list(_PARSER_REGISTRY.keys())

    def get_class(self, name: str) -> type[BaseParser]:
        """Returns the parser class registered under the given name."""
        if name not in _PARSER_REGISTRY:
            available = ", ".join(_PARSER_REGISTRY.keys()) or "(none)"
            raise KeyError(f"No parser registered as '{name}'. Available: {available}")
        return _PARSER_REGISTRY[name]

    def create(self, name: str) -> BaseParser:
        """Instantiate a registered parser."""
        cls = self.get_class(name)
        return cls()

