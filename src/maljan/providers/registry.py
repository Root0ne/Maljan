"""Provider registry with auto-discovery via decorator.

Same pattern as ``maljan.llm.registry``: a module-level dict, a decorator, and
one discovery import. The id functions are the project's single provider
vocabulary — the settings ``Literal`` choices, the API enum, the job override
and the profile references all read them, and a test refuses
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
# Bumped by every registration, so a reading of the registry can be kept until it changes.
_VERSION = [0]
_NAMES_HELD: list[object] = [None, frozenset()]


def _declare(name: str, cls: type) -> None:
    """Read the provider's own declaration of its tools: its settings block, else its hook.

    Under ``provider:<name>``, the source its tools are recorded under. A
    class that names a ``declaration_block`` (a dotted settings path holding a
    server block) joins the provider blocks and is read there as the built-ins
    are (``core.tool_declarations.provider_blocks``); a class whose
    ``declaration`` hook answers ``None`` declares nothing, and a provider
    whose block is one of the provider blocks keeps that block.
    """
    from maljan.core.tool_declarations import (
        register_provider_block,
        register_provider_declaration,
    )

    block = str(getattr(cls, "declaration_block", "") or "")
    if block:
        register_provider_block(f"provider:{name}", block)
    hook = getattr(cls, "declaration", None)
    if callable(hook):
        register_provider_declaration(f"provider:{name}", hook)


def register_static_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            if name in _STATIC_REGISTRY:
                logger.debug("Static provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            _STATIC_REGISTRY[name] = cls
            _VERSION[0] += 1
            _declare(name, cls)
        return cls

    return decorator


def register_sandbox_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            if name in _SANDBOX_REGISTRY:
                logger.debug("Sandbox provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            _SANDBOX_REGISTRY[name] = cls
            _VERSION[0] += 1
            _declare(name, cls)
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
        import maljan.providers.sandbox.rest  # noqa: F401
        import maljan.providers.sandbox.triage  # noqa: F401
        import maljan.providers.sandbox.upload  # noqa: F401
        from maljan.providers.static import import_built_ins

        import_built_ins()

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


def forget_static_provider(name: str) -> None:
    """Take the static provider registered as ``name`` out of the registry (a runtime one)."""
    from maljan.core.tool_declarations import forget_provider_block, forget_provider_declaration

    with _LOCK:
        if _STATIC_REGISTRY.pop(name, None) is not None:
            _VERSION[0] += 1
            if name not in _SANDBOX_REGISTRY:
                forget_provider_declaration(f"provider:{name}")
                forget_provider_block(f"provider:{name}")


def registered_variable_names() -> frozenset[str]:
    """The non-secret variable names the providers registered so far declare (``variable_names``).

    Read from the registered classes only, without importing the built-ins:
    those declare theirs in the shipped declarations.
    """
    with _LOCK:
        version = _VERSION[0]
        if _NAMES_HELD[0] == version:
            return _NAMES_HELD[1]  # type: ignore[return-value]
        classes = list(_STATIC_REGISTRY.values()) + list(_SANDBOX_REGISTRY.values())
        names: set[str] = set()
        for cls in classes:
            names.update(str(name) for name in getattr(cls, "variable_names", ()) or ())
        held = frozenset(names)
        _NAMES_HELD[0], _NAMES_HELD[1] = version, held
        return held


def registered_static_provider(name: str) -> type[StaticProvider] | None:
    """The static provider class registered as ``name``, or ``None`` for no such one."""
    discover_providers()
    return _STATIC_REGISTRY.get(str(name or ""))  # type: ignore[return-value]


def static_provider_class(name: str) -> type[StaticProvider]:
    """The registered static provider class ``name`` names."""
    discover_providers()
    cls = _STATIC_REGISTRY.get(name)
    if cls is None:
        raise ProviderConfigurationError(f"Unknown static provider: {name!r}")
    return cls  # type: ignore[return-value]


def sandbox_provider_class(name: str) -> type[SandboxProvider]:
    """The registered sandbox provider class ``name`` names."""
    discover_providers()
    cls = _SANDBOX_REGISTRY.get(name)
    if cls is None:
        raise ProviderConfigurationError(f"Unknown sandbox provider: {name!r}")
    return cls  # type: ignore[return-value]


def _block_enabled(cfg: Settings, source: str) -> bool:
    """Whether the server block a provider's declaration names is switched on."""
    from maljan.core.tool_declarations import provider_block_at, provider_blocks

    kind, _, key = source.partition(":")
    blocks = provider_blocks()
    if kind == "mcp":
        block: Any = cfg.mcp.servers.get(key)
    elif source in blocks:
        block = provider_block_at(cfg, source, blocks[source])
    else:
        return True
    return block is None or bool(getattr(block, "enabled", True))


def mirror_work_dirs(cfg: Settings, *, selected_only: bool = True) -> tuple[str, ...]:
    """The directories the worker copies a sample into under these settings.

    Each static provider's ``mirror_spec().work_subdir`` (built from ``cfg``,
    which does no I/O) where the provider needs a mirror; with
    ``selected_only``, only the providers the settings select (the global one
    and any agent's own) and whose block is switched on. A server's declared
    ``work_dir`` counts only through the provider that copies into it, so a
    name no provider writes to is never swept, cleared or exported. A provider
    whose construction fails contributes nothing and is logged. A tool server
    that declares a ``sample_mount`` is copied for whatever agent its tools
    are bound to, so its ``work_dir`` (or the shared default) counts while it
    is switched on, or always without ``selected_only``.
    """
    from maljan.core.tool_declarations import selected_static_providers

    discover_providers()
    selected = selected_static_providers(cfg)
    names: dict[str, None] = {}
    for provider_id, cls in sorted(_STATIC_REGISTRY.items()):
        if selected_only and provider_id not in selected:
            continue
        try:
            provider = cls.from_settings(cfg)  # type: ignore[attr-defined]
            if not provider.capabilities.needs_sample_mirror:
                continue
            if selected_only and (
                provider.switched_off() or not _block_enabled(cfg, str(provider.declaration_source))
            ):
                continue
            spec = provider.mirror_spec()
        except Exception as exc:  # noqa: BLE001 - one provider never hides the others
            logger.warning(
                "Static provider '%s' did not say where it mirrors a sample (%s).",
                provider_id,
                type(exc).__name__,
            )
            continue
        if spec is not None and spec.work_subdir:
            names.setdefault(spec.work_subdir, None)
    from maljan.providers.base import MirrorSpec

    for server in (getattr(getattr(cfg, "mcp", None), "servers", None) or {}).values():
        if not str(getattr(server, "sample_mount", "") or ""):
            continue
        if selected_only and not getattr(server, "enabled", True):
            continue
        names.setdefault(MirrorSpec.of(server).work_subdir, None)
    return tuple(names)


def get_static_provider(cfg: Settings) -> StaticProvider:
    discover_providers()
    return _build(_STATIC_REGISTRY, str(cfg.static.provider), cfg, "static")  # type: ignore[no-any-return]


def get_sandbox_provider(cfg: Settings) -> SandboxProvider:
    discover_providers()
    return _build(_SANDBOX_REGISTRY, str(cfg.sandbox.provider), cfg, "sandbox")  # type: ignore[no-any-return]
