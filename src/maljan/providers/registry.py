"""Provider registry with auto-discovery via decorator.

Same pattern as ``maljan.llm.registry``: a module-level dict, a decorator, and
one discovery import. The id functions are the project's single provider
vocabulary — the settings ``Literal`` choices, the API enum, the job override
and the profile references all read them, and a test refuses
any drift between them.

Beside the built-in adapters, an installed package adds a provider through
the ``maljan.static_providers`` or ``maljan.sandbox_providers`` entry-point
group; it is loaded only while the plugin allow-list names it
(``maljan.core.plugins``).
"""

from __future__ import annotations

import inspect
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger
from maljan.core.plugins import (
    InstalledPlugin,
    PluginRefused,
    PluginRegistry,
    describe,
    reconcile,
    registration_refusal,
    unavailable_reason,
    usable_list,
)
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
# The ids the built-in adapters registered, by kind, once they are imported.
_BUILT_IN: dict[str, frozenset[str]] = {}


def _declare(name: str, cls: type) -> None:
    """Read the provider's own declaration of its tools: its settings block, else its hook.

    Under ``provider:<name>``, the source its tools are recorded under. A
    class that names a ``declaration_block`` (a dotted settings path holding a
    server block) joins the provider blocks and is read there as the built-ins
    are (``core.tool_declarations.provider_blocks``); a class whose
    ``declaration`` hook answers ``None`` declares nothing, and a provider
    whose block is one of the provider blocks keeps that block. A block
    path registration refuses (no server block in the settings, or another
    source's block) raises here, with the reason.
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


def _refuse_a_plugin_registration(kind: str, name: str, cls: type, current: Any) -> None:
    """Refuse what a loading plugin may not register: a built-in id, or another name."""
    refusal = registration_refusal(
        kind, name, cls, current, lambda: _BUILT_IN.get(kind, frozenset())
    )
    if refusal:
        raise PluginRefused(refusal)


def register_static_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            _refuse_a_plugin_registration("static", name, cls, _STATIC_REGISTRY.get(name))
            if name in _STATIC_REGISTRY:
                logger.debug("Static provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            # Declared first: a block registration refuses is raised before
            # the provider is registered, so none is half there.
            _declare(name, cls)
            _STATIC_REGISTRY[name] = cls
            _VERSION[0] += 1
        return cls

    return decorator


def register_sandbox_provider(name: str):  # type: ignore[no-untyped-def]
    def decorator(cls: type) -> type:
        with _LOCK:
            _refuse_a_plugin_registration("sandbox", name, cls, _SANDBOX_REGISTRY.get(name))
            if name in _SANDBOX_REGISTRY:
                logger.debug("Sandbox provider '%s' re-registered (overwriting).", name)
            cls.id = name  # type: ignore[attr-defined]
            # Declared first: a block registration refuses is raised before
            # the provider is registered, so none is half there.
            _declare(name, cls)
            _SANDBOX_REGISTRY[name] = cls
            _VERSION[0] += 1
        return cls

    return decorator


def _shipped(cls: object) -> bool:
    return str(getattr(cls, "__module__", "")).startswith("maljan.")


def _import_built_ins() -> None:
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

        _BUILT_IN["static"] = frozenset(k for k, c in _STATIC_REGISTRY.items() if _shipped(c))
        _BUILT_IN["sandbox"] = frozenset(k for k, c in _SANDBOX_REGISTRY.items() if _shipped(c))
        _DISCOVERY_DONE = True


def discover_providers() -> None:
    """Import the built-in adapters once to trigger their decorators.

    No plugin is loaded here: a process loads the allowed plugins when it is
    told to, with the list to load by (``load_plugins``).
    """
    _import_built_ins()


def load_plugins(allowed: Any) -> None:
    """Bring the static and sandbox provider plugins in line with the allow-list ``allowed``.

    The plugins of the ``maljan.static_providers`` and
    ``maljan.sandbox_providers`` entry-point groups it names are loaded once
    each, and one it no longer names is withdrawn
    (``maljan.core.plugins.load_allowed``).
    """
    entries = usable_list(allowed)
    reconcile(_STATIC_PLUGINS, entries)
    reconcile(_SANDBOX_PLUGINS, entries)


def plugin_registry(kind: str) -> PluginRegistry:
    """How the ``static`` or ``sandbox`` registry takes and gives back plugins."""
    return _STATIC_PLUGINS if kind == "static" else _SANDBOX_PLUGINS


def built_in_ids(kind: str) -> frozenset[str]:
    """The ids the built-in adapters of ``kind`` (``static`` or ``sandbox``) register."""
    _import_built_ins()
    return _BUILT_IN.get(kind, frozenset())


def _plugin_registrar(kind: str) -> Callable[[InstalledPlugin, object], None]:
    def register(plugin: InstalledPlugin, loaded: object) -> None:
        """Register the class a plugin's entry point named, under the plugin's name."""
        from maljan.providers.base import SandboxProvider, StaticProvider

        base: type = StaticProvider if kind == "static" else SandboxProvider
        if not (isinstance(loaded, type) and issubclass(loaded, base)):
            raise PluginRefused(
                f"its entry point names {describe(loaded)}, which is not a subclass of "
                f"maljan.providers.base.{base.__name__}"
            )
        if inspect.isabstract(loaded):
            missing = ", ".join(sorted(getattr(loaded, "__abstractmethods__", ()) or ()))
            raise PluginRefused(f"{describe(loaded)} leaves abstract methods unwritten ({missing})")
        registry = _STATIC_REGISTRY if kind == "static" else _SANDBOX_REGISTRY
        if registry.get(plugin.name) is not loaded:
            decorate = register_static_provider if kind == "static" else register_sandbox_provider
            decorate(plugin.name)(loaded)

    return register


def _registered_in(registry: dict[str, type]) -> Callable[[], list[str]]:
    def registered() -> list[str]:
        _import_built_ins()
        return list(registry)

    return registered


_STATIC_PLUGINS = PluginRegistry(
    kind="static",
    builtin=lambda: built_in_ids("static"),
    registered=_registered_in(_STATIC_REGISTRY),
    register=_plugin_registrar("static"),
    withdraw=lambda name: forget_static_provider(name),
)
_SANDBOX_PLUGINS = PluginRegistry(
    kind="sandbox",
    builtin=lambda: built_in_ids("sandbox"),
    registered=_registered_in(_SANDBOX_REGISTRY),
    register=_plugin_registrar("sandbox"),
    withdraw=lambda name: forget_sandbox_provider(name),
)


def static_provider_ids() -> list[str]:
    discover_providers()
    return sorted(_STATIC_REGISTRY)


def sandbox_provider_ids() -> list[str]:
    discover_providers()
    return sorted(_SANDBOX_REGISTRY)


def _unknown(registry: dict[str, type], name: str, kind: str) -> str:
    """Why ``name`` names no registered provider of ``kind``, with the registered ids."""
    available = ", ".join(sorted(registry)) or "(none)"
    said = f"Unknown {kind} provider: {name!r}. Available: {available}"
    reason = unavailable_reason(kind, str(name or ""))
    return f"{said}; {reason}" if reason else said


def _build(registry: dict[str, type], name: str, cfg: Any, kind: str) -> Any:
    cls = registry.get(name)
    if cls is None:
        raise ProviderConfigurationError(_unknown(registry, name, kind))
    return cls.from_settings(cfg)  # type: ignore[attr-defined]


def forget_static_provider(name: str) -> None:
    """Take the static provider registered as ``name`` out of the registry (a runtime one)."""
    _forget(_STATIC_REGISTRY, _SANDBOX_REGISTRY, name)


def forget_sandbox_provider(name: str) -> None:
    """Take the sandbox provider registered as ``name`` out of the registry (a runtime one)."""
    _forget(_SANDBOX_REGISTRY, _STATIC_REGISTRY, name)


def _forget(registry: dict[str, type], other: dict[str, type], name: str) -> None:
    from maljan.core.tool_declarations import forget_provider_block, forget_provider_declaration

    with _LOCK:
        if registry.pop(name, None) is not None:
            _VERSION[0] += 1
            if name not in other:
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
        raise ProviderConfigurationError(_unknown(_STATIC_REGISTRY, name, "static"))
    return cls  # type: ignore[return-value]


def sandbox_provider_class(name: str) -> type[SandboxProvider]:
    """The registered sandbox provider class ``name`` names."""
    discover_providers()
    cls = _SANDBOX_REGISTRY.get(name)
    if cls is None:
        raise ProviderConfigurationError(_unknown(_SANDBOX_REGISTRY, name, "sandbox"))
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
