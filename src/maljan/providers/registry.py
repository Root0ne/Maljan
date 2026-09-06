"""Provider registry with auto-discovery via decorator.

Same pattern as ``maljan.llm.registry``: a module-level dict, a decorator, and
one discovery import. The id functions are the project's single provider
vocabulary — the settings ``Literal`` choices, the API enum, the job override
and (in sub-project C) the profile references all read them, and a test refuses
any drift between them.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.providers.errors import ProviderConfigurationError

if TYPE_CHECKING:
    from maljan.core.config import Settings
    from maljan.providers.base import SandboxProvider, StaticProvider

_STATIC_REGISTRY: dict[str, type] = {}
_SANDBOX_REGISTRY: dict[str, type] = {}
_LOCK = threading.RLock()
_DISCOVERY_DONE = False


def register_static_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            if name in _STATIC_REGISTRY:
                logger.debug("Static provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            _STATIC_REGISTRY[name] = cls
        return cls

    return decorator


def register_sandbox_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            if name in _SANDBOX_REGISTRY:
                logger.debug("Sandbox provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            _SANDBOX_REGISTRY[name] = cls
        return cls

    return decorator


def discover_providers() -> None:
    """Import the built-in adapters once to trigger their decorators."""
    global _DISCOVERY_DONE
    if _DISCOVERY_DONE:
        return
    with _LOCK:
        if _DISCOVERY_DONE:
            return
        import maljan.providers.sandbox.cape2  # noqa: F401
        import maljan.providers.sandbox.mock  # noqa: F401
        import maljan.providers.sandbox.triage  # noqa: F401
        import maljan.providers.sandbox.upload  # noqa: F401
        import maljan.providers.static.capa_yara  # noqa: F401
        import maljan.providers.static.generic_mcp  # noqa: F401
        import maljan.providers.static.ghidra  # noqa: F401
        import maljan.providers.static.null  # noqa: F401
        import maljan.providers.static.r2  # noqa: F401

        _DISCOVERY_DONE = True


def static_provider_ids() -> list[str]:
    discover_providers()
    return sorted(_STATIC_REGISTRY)


def sandbox_provider_ids() -> list[str]:
    discover_providers()
    return sorted(_SANDBOX_REGISTRY)


def _build(registry: dict[str, type], name: str, cfg: Any, kind: str) -> Any:
    cls = registry.get(name)
    if cls is None:
        available = ", ".join(sorted(registry)) or "(none)"
        raise ProviderConfigurationError(
            f"Unknown {kind} provider: {name!r}. Available: {available}"
        )
    return cls.from_settings(cfg)  # type: ignore[attr-defined]


def get_static_provider(cfg: Settings) -> StaticProvider:
    discover_providers()
    return _build(_STATIC_REGISTRY, str(cfg.static.provider), cfg, "static")  # type: ignore[no-any-return]


def get_sandbox_provider(cfg: Settings) -> SandboxProvider:
    discover_providers()
    return _build(_SANDBOX_REGISTRY, str(cfg.sandbox.provider), cfg, "sandbox")  # type: ignore[no-any-return]
