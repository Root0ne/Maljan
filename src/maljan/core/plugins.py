"""Provider plugins from installed packages: judged from their metadata, loaded only when allowed.

An installed package adds a provider through an entry point in the group of
its kind:

* ``llm``: ``maljan.llm_providers``, naming a subclass of
  ``maljan.llm.provider_base.LLMProvider`` with a ``build_model`` method;
* ``static``: ``maljan.static_providers``, naming a subclass of
  ``maljan.providers.base.StaticProvider``;
* ``sandbox``: ``maljan.sandbox_providers``, naming a subclass of
  ``maljan.providers.base.SandboxProvider``;
* ``memory``: ``maljan.memory_backends``, naming a callable that calls
  ``maljan.memory.store_factory.register_memory_backend`` for the backend.

The entry point's name is the provider id the plugin adds, so a plugin is
known by name without importing anything. Listing, the provider choices and
every check of a saved provider id read package metadata only
(:func:`installed`, :func:`listing`, :func:`accepted_names`,
:func:`id_refusal`): a provider id is a shipped one, or an installed plugin of
its kind that the allow-list in question names.

A plugin is loaded only while the allow-list names it, as ``<kind>:<name>``
(the ``plugins.allowed`` setting, empty by default). The allow-list holds names
only, never a path or a module. Nothing loads a plugin by reading a registry:
a process loads the allowed plugins when it is told to, with the list to load
by (:func:`load_allowed`). The analysis worker does it as a job starts, with
the list the job's own settings carry, so a running job keeps the plugins it
started with; the API does it only where it runs a plugin's own code, off its
event loop. Each load is logged with the plugin's distribution and version; a
plugin that fails to import or is no provider of its kind is recorded with the
reason, and the process goes on without it. Every shipped provider is
registered before any plugin is imported, the loader never registers a plugin
under a shipped id, and a registration a plugin makes while it loads under any
name but its own is refused. A plugin the list no longer names is withdrawn
from its registry at the next load; its code stays imported in that process
until the process restarts.
"""

from __future__ import annotations

import re
import threading
from collections.abc import Callable, Collection, Iterable, Mapping
from contextvars import ContextVar
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator

from maljan.core.logger import logger

# Each kind of plugin and the entry-point group its packages declare it in.
PLUGIN_GROUPS: dict[str, str] = {
    "llm": "maljan.llm_providers",
    "static": "maljan.static_providers",
    "sandbox": "maljan.sandbox_providers",
    "memory": "maljan.memory_backends",
}

KIND_TITLES: dict[str, str] = {
    "llm": "LLM providers",
    "static": "Static analysis providers",
    "sandbox": "Sandbox providers",
    "memory": "Memory backends",
}

# The setting that holds the allow-list.
ALLOW_LIST_PATH = "plugins.allowed"
ALLOW_LIST_KEY = f"core.{ALLOW_LIST_PATH}"

NAME_RULE = "lowercase letters, digits, '_' and '-', starting with a letter, at most 64 characters"
_NAME = r"[a-z][a-z0-9_-]{0,63}"
# Both are matched whole (``fullmatch``): a trailing newline is not a name.
_NAME_RE = re.compile(_NAME)
_ENTRY_RE = re.compile(rf"(?P<kind>{'|'.join(PLUGIN_GROUPS)}):(?P<name>{_NAME})")


class PluginRefused(Exception):
    """A plugin that is not loaded, and why: the reason is the exception's text."""


def accepted_hint(kind: str) -> str:
    """The clause a refused provider id carries, naming the allow-list."""
    return (
        f"an installed {kind} plugin is accepted once the plugin allow-list "
        f"({ALLOW_LIST_KEY}) names it as {kind}:<name>"
    )


def _shown(item: Any) -> str:
    """A refused entry as a message quotes it: whole when short, else its start and its length."""
    text = repr(item)
    return text if len(text) <= 80 else f"{text[:60]}... ({len(text)} characters)"


def is_plugin_name(name: Any) -> bool:
    """Whether ``name`` can be a plugin's provider id: matched whole, so no trailing newline."""
    return isinstance(name, str) and _NAME_RE.fullmatch(name) is not None


def allow_list_problem(value: Any) -> str:
    """Why ``value`` cannot be the allow-list; ``""`` when it can (``None`` is an empty one)."""
    if value is None:
        return ""
    if not isinstance(value, list | tuple):
        return "the plugin allow-list is a list of names, each written <kind>:<name>"
    seen: set[str] = set()
    for item in value:
        if not isinstance(item, str) or _ENTRY_RE.fullmatch(item) is None:
            return (
                f"{_shown(item)} is not a plugin name: write <kind>:<name>, the kind one of "
                f"{', '.join(PLUGIN_GROUPS)} and the name {NAME_RULE}"
            )
        if item in seen:
            return f"{_shown(item)} is named twice"
        seen.add(item)
    return ""


class PluginsConfig(BaseModel):
    """The installed provider plugins this deployment loads (``maljan.core.plugins``)."""

    # One entry per plugin to load, written ``<kind>:<name>``: the kind
    # (``llm``, ``static``, ``sandbox`` or ``memory``) and the name of the
    # plugin's entry point, which is the provider id it adds. Names only,
    # never a path or a module. Empty, the default: no installed plugin is
    # loaded, whatever is installed.
    allowed: list[str] = Field(default_factory=list)

    @field_validator("allowed", mode="before")
    @classmethod
    def _names_only(cls, value: Any) -> Any:
        problem = allow_list_problem(value) if value is not None else ""
        if problem:
            raise ValueError(problem)
        return value


def parse_entry(item: Any) -> tuple[str, str] | None:
    """``(kind, name)`` for an allow-list entry, or ``None`` for one that is not."""
    match = _ENTRY_RE.fullmatch(item) if isinstance(item, str) else None
    return (match["kind"], match["name"]) if match else None


@dataclass(frozen=True)
class InstalledPlugin:
    """One installed entry point of a plugin group, read from its package's metadata.

    Nothing of the package is imported to know it: ``point`` is loaded only
    once the allow-list names the plugin.
    """

    kind: str
    name: str
    distribution: str
    version: str
    point: Any = field(default=None, compare=False, repr=False)

    @property
    def entry(self) -> str:
        """The plugin as the allow-list names it."""
        return f"{self.kind}:{self.name}"

    @property
    def source(self) -> str:
        """The package it comes from, as a log line names it."""
        return f"{self.distribution or 'an unnamed package'} {self.version or '(no version)'}"


# ``absent``: allowed, and no installed package declares it.
PluginState = Literal["loaded", "failed", "refused", "absent"]


@dataclass
class PluginRecord:
    """What this process made of one allowed plugin when it was told to load it.

    ``provider`` is the object the plugin's entry point named, once loaded:
    whatever the provider declares about itself (its settings model among
    it) is read from there.
    """

    plugin: InstalledPlugin | None
    state: PluginState
    error: str = ""
    provider: Any = None


@dataclass(frozen=True)
class PluginRegistry:
    """How one provider registry takes and gives back the plugins of its kind.

    ``builtin`` answers the shipped ids, importing shipped code only;
    ``registered`` every id registered now, in the registry's own order
    (importing shipped code only, never a plugin); ``register`` adds the
    object a plugin's entry point named under the plugin's name and raises
    ``PluginRefused`` for an object that is no provider of the kind;
    ``withdraw`` takes an id out of the registry again.
    """

    kind: str
    builtin: Callable[[], Collection[str]]
    registered: Callable[[], list[str]]
    register: Callable[[InstalledPlugin, Any], None]
    withdraw: Callable[[str], None]


@dataclass
class _ProcessState:
    # The stored allow-list as this process last read it: what a check that
    # is handed no list of its own judges by. Loading never follows it.
    allowed: frozenset[str] = frozenset()
    records: dict[str, dict[str, PluginRecord]] = field(
        default_factory=lambda: {kind: {} for kind in PLUGIN_GROUPS}
    )
    said: set[str] = field(default_factory=set)


_STATE = _ProcessState()
# Bumped by every plugin loaded or withdrawn, so a reading of the registries
# (the settings catalogue) can be kept until they change; never reset.
_REGISTRY_CHANGES = [0]
_ALLOW_LOCK = threading.Lock()
# Held by a load alone: nothing that reads a registry or judges an id waits on it.
_LOAD_LOCK = threading.RLock()
# The plugin whose entry point is being loaded in this context, if any.
_LOADING: ContextVar[InstalledPlugin | None] = ContextVar("maljan_plugin_loading", default=None)


def _say_once(marker: str, message: str, *args: Any) -> None:
    if marker in _STATE.said:
        return
    _STATE.said.add(marker)
    logger.warning(message, *args)


def install_allow_list(value: Any) -> None:
    """Make ``value`` the stored allow-list this process judges an id by when handed none.

    Called with the stored value wherever the settings store is read, and with
    the settings a worker installs for a job. It loads and withdraws nothing:
    loading follows only the list :func:`load_allowed` is handed. A value the
    settings model refuses is judged as an empty list, and the refusal is
    logged.
    """
    problem = allow_list_problem(value)
    if problem:
        _say_once(
            f"refused:{problem}",
            "The stored plugin allow-list is refused (%s); no installed plugin is loaded "
            "until it is fixed.",
            problem,
        )
        entries: frozenset[str] = frozenset()
    else:
        entries = frozenset(value or ())
    with _ALLOW_LOCK:
        if entries == _STATE.allowed:
            return
        _STATE.allowed = entries
    # The count only: each plugin is named where it is loaded, and the list
    # itself is read from the settings store, which CodeQL treats as secret.
    logger.info("The stored plugin allow-list names %d plugin(s).", len(entries))


def allow_list() -> frozenset[str]:
    """The stored allow-list as this process last read it."""
    return _STATE.allowed


def usable_list(value: Any) -> list[str]:
    """``value`` as an allow-list to load or judge by; a list the model refuses is an empty one."""
    if allow_list_problem(value) or not value:
        return []
    return list(value)


def allowed_names(kind: str, allowed: Iterable[Any] | None = None) -> set[str]:
    """The names an allow-list holds for ``kind``: ``allowed``, else the stored one."""
    entries = _STATE.allowed if allowed is None else allowed
    out: set[str] = set()
    for item in entries:
        parsed = parse_entry(item)
        if parsed is not None and parsed[0] == kind:
            out.add(parsed[1])
    return out


def _entry_points(group: str) -> list[Any]:
    return list(entry_points(group=group))


def _distribution_name(dist: Any) -> str:
    if dist is None:
        return ""
    name = getattr(dist, "name", None)
    if not name:
        try:
            name = dist.metadata["Name"]
        except Exception:  # noqa: BLE001 — a package without a readable name is shown without one
            name = ""
    return str(name or "")


def installed(kind: str) -> list[InstalledPlugin]:
    """Every installed entry point of ``kind``'s group, from package metadata; none imported."""
    out: list[InstalledPlugin] = []
    for point in _entry_points(PLUGIN_GROUPS[kind]):
        dist = getattr(point, "dist", None)
        out.append(
            InstalledPlugin(
                kind=kind,
                name=str(point.name),
                distribution=_distribution_name(dist),
                version=str(getattr(dist, "version", "") or ""),
                point=point,
            )
        )
    return sorted(out, key=lambda plugin: (plugin.name, plugin.distribution))


def _by_name(found: Iterable[InstalledPlugin]) -> dict[str, list[InstalledPlugin]]:
    out: dict[str, list[InstalledPlugin]] = {}
    for plugin in found:
        out.setdefault(plugin.name, []).append(plugin)
    return out


def _refusal(
    plugin: InstalledPlugin,
    alike: list[InstalledPlugin],
    builtin: Collection[str],
    taken: Collection[str] = (),
) -> str:
    """Why ``plugin`` is never loaded, known without importing it; ``""`` when it may be."""
    if not is_plugin_name(plugin.name):
        return f"its name is not a provider id ({NAME_RULE})"
    if plugin.name in builtin:
        return (
            f"{plugin.name!r} is a built-in {plugin.kind} provider, and the loader never "
            "registers a plugin under a built-in id"
        )
    if len(alike) > 1:
        sources = " and ".join(other.source for other in alike)
        return f"two installed packages declare it ({sources}); uninstall one"
    if plugin.name in taken:
        return f"{plugin.name!r} is already registered in this process"
    return ""


def accepted_names(kind: str, allowed: Iterable[Any] | None = None) -> set[str]:
    """The plugin names of ``kind`` a provider id may be saved as: allowed, installed, loadable.

    Read from package metadata; nothing is imported. ``allowed`` is the
    allow-list to judge by (the one a save leaves), else the stored one.
    """
    wanted = allowed_names(kind, allowed)
    if not wanted:
        return set()
    found = _by_name(installed(kind))
    return {
        name
        for name in wanted
        if name in found and not _refusal(found[name][0], found[name], builtin=())
    }


def plugin_refusal(kind: str, name: str, allowed: Iterable[Any] | None = None) -> str | None:
    """Why ``name`` is no acceptable plugin of ``kind`` under ``allowed``, read from metadata.

    ``""`` when it is accepted; ``None`` when no plugin is involved (no
    installed package declares the name and the list does not name it);
    otherwise a clause that gives the cause: a refusal of the plugin itself,
    a list that does not name it, or an entry no package declares.
    """
    name = str(name or "")
    alike = [plugin for plugin in installed(kind) if plugin.name == name]
    listed = name in allowed_names(kind, allowed)
    if not alike:
        if listed:
            return (
                f"it is on the plugin allow-list ({ALLOW_LIST_KEY}), but no installed package "
                "declares it"
            )
        return None
    refused = _refusal(alike[0], alike, builtin=())
    if refused:
        return f"it is an installed plugin that is never loaded: {refused}"
    if not listed:
        return (
            f"it is an installed plugin that the plugin allow-list ({ALLOW_LIST_KEY}) does "
            f"not name; allow {kind}:{name} to load it"
        )
    return ""


def loaded_names(kind: str) -> set[str]:
    """The ids of ``kind`` this process registered from plugins."""
    return {name for name, record in _STATE.records[kind].items() if record.state == "loaded"}


def unloaded_plugin(kind: str, name: Any) -> bool:
    """Whether ``name`` is an installed plugin of ``kind`` that this process has not registered.

    Read from package metadata. A check that reads such a plugin's own facts
    (its settings model, whether it takes a per-agent address or an effort)
    cannot run here, and is left to the process that loads it: the worker as
    a job starts, whose check is final.
    """
    if not is_plugin_name(name) or name in _registry(kind).registered():
        return False
    return any(plugin.name == name for plugin in installed(kind))


def shipped_ids(kind: str) -> list[str]:
    """The ids of ``kind`` registered by Maljan's own code and in-process code, in registry order.

    Every registered id but the ones this process loaded from plugins; a
    plugin's id is judged by its metadata and an allow-list instead, never by
    what this process happens to have loaded. Imports shipped code only.
    """
    plugin_ids = loaded_names(kind)
    return [name for name in _registry(kind).registered() if name not in plugin_ids]


def id_refusal(kind: str, value: Any, allowed: Iterable[Any] | None = None) -> str:
    """Why ``value`` cannot be saved as a provider id of ``kind``; ``""`` when it can.

    Accepted: a shipped id, or an installed plugin of the kind that
    ``allowed`` (the list a save leaves; the stored one when ``None``) names
    and nothing refuses. Read from package metadata; no plugin is imported. A
    refusal is a clause that gives the plugin's own cause where one applies,
    else names the allow-list.
    """
    if value in shipped_ids(kind):
        return ""
    if not isinstance(value, str):
        return accepted_hint(kind)
    refused = plugin_refusal(kind, value, allowed)
    if refused == "":
        return ""
    return refused or accepted_hint(kind)


def registration_refusal(
    kind: str,
    name: str,
    obj: Any,
    current: Any,
    builtin: Callable[[], Collection[str]],
) -> str:
    """Why a registration made while a plugin loads is refused; ``""`` when it is not.

    Outside a plugin's load nothing is refused. Inside it, a plugin registers
    the one provider its entry point names: never a built-in id and never
    another name. Registering the object already registered is no change.
    """
    plugin = _LOADING.get()
    if plugin is None or obj is current:
        return ""
    if name in builtin():
        return (
            f"plugin {plugin.entry} registers the built-in {kind} provider {name!r}; a "
            "plugin never registers under a built-in id"
        )
    if (kind, name) != (plugin.kind, plugin.name):
        return (
            f"plugin {plugin.entry} registers the {kind} provider {name!r}; a plugin "
            "registers only the provider its entry point names"
        )
    return ""


def describe(obj: Any) -> str:
    """What an entry point named, in the words a refusal uses."""
    if isinstance(obj, type):
        return f"the class {obj.__module__}.{obj.__qualname__}"
    if callable(obj):
        module = getattr(obj, "__module__", "") or ""
        qualname = getattr(obj, "__qualname__", "") or type(obj).__name__
        return f"the callable {module}.{qualname}" if module else f"the callable {qualname}"
    return f"an object of type {type(obj).__name__}"


def _reason(exc: BaseException) -> str:
    if isinstance(exc, PluginRefused):
        return str(exc)
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _import_every_built_in() -> None:
    """Register every kind's shipped providers, so none registers while a plugin loads."""
    for kind in PLUGIN_GROUPS:
        _registry(kind).builtin()


def settled(allowed: Any, kinds: Iterable[str] | None = None) -> bool:
    """Whether loading by ``allowed`` would change nothing in this process for ``kinds``.

    Each allowed plugin of those kinds is tried already and no plugin this
    process loaded has left the list. Nothing is imported or read from
    package metadata to answer.
    """
    entries = usable_list(allowed)
    for kind in kinds or PLUGIN_GROUPS:
        if allowed_names(kind, entries) != set(_STATE.records[kind]):
            return False
    return True


def load_allowed(allowed: Any, kinds: Iterable[str] | None = None) -> None:
    """Bring this process's registries of ``kinds`` (all when ``None``) in line with ``allowed``.

    Each allowed, installed plugin not tried yet is loaded once: a failure or
    a refusal is recorded with its reason and logged, and the process goes on
    without it. A plugin the list no longer names is withdrawn, and its record
    dropped, so allowing it again tries it again. A list the settings model
    refuses is an empty one. Cheap when nothing changed.
    """
    entries = usable_list(allowed)
    for kind in kinds or PLUGIN_GROUPS:
        reconcile(_registry(kind), entries)


def reconcile(registry: PluginRegistry, allowed: Iterable[Any]) -> None:
    """Bring ``registry`` in line with the allow-list ``allowed``; see :func:`load_allowed`."""
    kind = registry.kind
    wanted = allowed_names(kind, list(allowed))
    if wanted == set(_STATE.records[kind]):
        return
    with _LOAD_LOCK:
        _reconcile(registry, wanted)


def named_settled(allowed: Any, entries: Iterable[str]) -> bool:
    """Whether :func:`load_named` would change nothing: each of ``entries`` that ``allowed``
    names is tried, and no plugin this process loaded has left ``allowed``."""
    listed = usable_list(allowed)
    for kind, names in _named(listed, entries).items():
        if names - set(_STATE.records[kind]):
            return False
    for kind in PLUGIN_GROUPS:
        if not set(_STATE.records[kind]) <= allowed_names(kind, listed):
            return False
    return True


def _named(listed: list[str], entries: Iterable[str]) -> dict[str, set[str]]:
    """``entries`` that ``listed`` names too, as names by kind."""
    held = set(listed)
    out: dict[str, set[str]] = {}
    for entry in entries:
        parsed = parse_entry(entry)
        if parsed is not None and entry in held:
            out.setdefault(parsed[0], set()).add(parsed[1])
    return out


def load_named(allowed: Any, entries: Iterable[str]) -> None:
    """Load the plugins ``entries`` names (``<kind>:<name>``) that ``allowed`` names too.

    Each is loaded once, as :func:`load_allowed` loads it, and no other plugin
    is loaded; a plugin this process loaded that ``allowed`` no longer names
    is withdrawn, which imports nothing. For a process that loads a plugin
    only where it runs that plugin's own code.
    """
    listed = usable_list(allowed)
    wanted = _named(listed, entries)
    for kind in PLUGIN_GROUPS:
        registry = _registry(kind)
        keep = allowed_names(kind, listed)
        pending = wanted.get(kind, set()) - set(_STATE.records[kind])
        if not pending and set(_STATE.records[kind]) <= keep:
            continue
        with _LOAD_LOCK:
            _withdraw(registry, keep)
            _load_pending(registry, wanted.get(kind, set()) - set(_STATE.records[kind]))


def _reconcile(registry: PluginRegistry, wanted: set[str]) -> None:
    _withdraw(registry, wanted)
    _load_pending(registry, wanted - set(_STATE.records[registry.kind]))


def _withdraw(registry: PluginRegistry, wanted: set[str]) -> None:
    """Withdraw each plugin of ``registry``'s kind this process loaded that is not in ``wanted``."""
    kind = registry.kind
    records = _STATE.records[kind]
    for name in [name for name in records if name not in wanted]:
        record = records.pop(name)
        if record.state != "loaded" or record.plugin is None:
            continue
        registry.withdraw(name)
        _REGISTRY_CHANGES[0] += 1
        logger.warning(
            "Plugin %s from %s is no longer on the allow-list and is withdrawn from the %s; "
            "its code stays imported in this process until the process restarts.",
            record.plugin.entry,
            record.plugin.source,
            KIND_TITLES[kind],
        )


def _load_pending(registry: PluginRegistry, names: set[str]) -> None:
    """Load each of ``names`` (allowed plugins of ``registry``'s kind not tried yet), once."""
    kind = registry.kind
    records = _STATE.records[kind]
    pending = sorted(names - set(records))
    if not pending:
        return
    # Every kind's shipped providers register first, so a plugin that imports
    # a shipped module of another kind never has that module's own
    # registrations refused as its own.
    _import_every_built_in()
    builtin = set(registry.builtin())
    found = _by_name(installed(kind))
    for name in pending:
        alike = found.get(name, [])
        if not alike:
            records[name] = PluginRecord(None, "absent", "no installed package declares it")
            logger.warning(
                "Plugin %s is on the allow-list, but no installed package declares it.",
                f"{kind}:{name}",
            )
            continue
        plugin = alike[0]
        refusal = _refusal(plugin, alike, builtin, set(registry.registered()))
        if refusal:
            records[name] = PluginRecord(plugin, "refused", refusal)
            logger.warning(
                "Plugin %s from %s is not loaded: %s.", plugin.entry, plugin.source, refusal
            )
            continue
        records[name] = _load(registry, plugin)


def _load(registry: PluginRegistry, plugin: InstalledPlugin) -> PluginRecord:
    token = _LOADING.set(plugin)
    try:
        provider = plugin.point.load()
        registry.register(plugin, provider)
    except (Exception, SystemExit) as exc:  # noqa: BLE001 — a broken plugin never stops the process
        reason = _reason(exc)
        # Whatever it registered of itself before it failed goes with it.
        if plugin.name in set(registry.registered()):
            registry.withdraw(plugin.name)
        logger.warning(
            "Plugin %s from %s failed to load and is left out; this process goes on without "
            "it (%s).",
            plugin.entry,
            plugin.source,
            reason,
        )
        return PluginRecord(plugin, "failed", reason)
    finally:
        _LOADING.reset(token)
    _REGISTRY_CHANGES[0] += 1
    logger.info("Loaded plugin %s from %s.", plugin.entry, plugin.source)
    return PluginRecord(plugin, "loaded", provider=provider)


def records(kind: str) -> dict[str, PluginRecord]:
    """What this process made of each allowed plugin of ``kind`` it was told to load, by name."""
    return dict(_STATE.records[kind])


def failures(kind: str) -> dict[str, str]:
    """Each allowed plugin of ``kind`` this process did not load, with the reason."""
    return {
        name: record.error
        for name, record in _STATE.records[kind].items()
        if record.state != "loaded"
    }


def registry_changes() -> int:
    """A number that moves whenever a plugin is loaded or withdrawn in this process."""
    return _REGISTRY_CHANGES[0]


def unavailable_reason(kind: str, name: str) -> str:
    """Why the provider id ``name`` of ``kind`` is not registered, when a plugin explains it.

    A clause about the id (``"it is ..."``): a plugin this process did not
    load, with the reason; otherwise what the metadata and the stored
    allow-list say of it (:func:`plugin_refusal`). ``""`` when no plugin is
    involved, or when the plugin is allowed and installed and simply not
    loaded here.
    """
    record = _STATE.records[kind].get(name)
    if record is not None and record.state != "loaded":
        return f"it is a plugin that was not loaded ({record.error})"
    return plugin_refusal(kind, name) or ""


def _registry(kind: str) -> PluginRegistry:
    """The registry of ``kind``, as it takes and gives back plugins; imports shipped code only."""
    if kind == "llm":
        from maljan.llm.registry import PLUGINS as llm_plugins

        return llm_plugins
    if kind == "memory":
        from maljan.memory.store_factory import PLUGINS as memory_plugins

        return memory_plugins
    from maljan.providers.registry import plugin_registry

    return plugin_registry(kind)


def listing(allowed: Iterable[Any] | None = None) -> list[dict[str, Any]]:
    """Every installed plugin per kind, for the console; read from package metadata.

    No plugin is imported to be listed. Each row names the plugin, its
    distribution and version, whether ``allowed`` (the stored allow-list; the
    one this process last read when ``None``) names it, and what the metadata
    says of it wherever it runs: ``refused`` with the reason, else ``allowed``
    or ``not_allowed``. ``process_state`` and ``process_error`` are what this
    process made of it when it loaded it for itself (``loaded``, ``failed`` or
    ``refused``), empty when it never did. Each kind also names the allowed
    names no installed package declares.
    """
    entries = (
        _STATE.allowed
        if allowed is None
        else frozenset(item for item in allowed if isinstance(item, str))
    )
    out: list[dict[str, Any]] = []
    for kind, group in PLUGIN_GROUPS.items():
        found = installed(kind)
        alike = _by_name(found)
        builtin = set(_registry(kind).builtin())
        tried = _STATE.records[kind]
        rows: list[dict[str, Any]] = []
        for plugin in found:
            is_allowed = plugin.entry in entries
            refusal = _refusal(plugin, alike[plugin.name], builtin)
            state = "refused" if refusal else ("allowed" if is_allowed else "not_allowed")
            record = tried.get(plugin.name)
            here = record is not None and record.plugin == plugin
            rows.append(
                {
                    "name": plugin.name,
                    "entry": plugin.entry,
                    "distribution": plugin.distribution,
                    "version": plugin.version,
                    "allowed": is_allowed,
                    "state": state,
                    "error": refusal,
                    "process_state": record.state if here and record else "",
                    "process_error": record.error if here and record else "",
                }
            )
        absent = sorted(name for name in allowed_names(kind, entries) if name not in alike)
        out.append(
            {
                "kind": kind,
                "group": group,
                "title": KIND_TITLES[kind],
                "plugins": rows,
                "allowed_absent": absent,
            }
        )
    return out


def selections(core: Mapping[str, Any]) -> list[tuple[str, str, str]]:
    """Every provider id ``core`` (stored core overrides, dotted paths) selects, with its kind.

    ``(settings key, kind, id)`` for ``llm.provider``, ``static.provider``,
    ``sandbox.provider``, ``memory.backend``, each agent definition's and
    each team's ``static_provider`` and each per-agent model entry's provider and its
    fallbacks' providers. A key not stored selects its shipped default, which
    no plugin is.
    """
    out: list[tuple[str, str, str]] = []
    for path, kind in (
        ("llm.provider", "llm"),
        ("static.provider", "static"),
        ("sandbox.provider", "sandbox"),
        ("memory.backend", "memory"),
    ):
        value = core.get(path)
        if isinstance(value, str) and value:
            name = value.strip().lower() if kind == "memory" else value
            out.append((f"core.{path}", kind, name))
    for path in ("agents.definitions", "agents.profiles"):
        held = core.get(path)
        if not isinstance(held, Mapping):
            continue
        for name, entry in held.items():
            if isinstance(entry, Mapping) and isinstance(entry.get("static_provider"), str):
                key = f"core.{path}.{name}.static_provider"
                out.append((key, "static", str(entry["static_provider"])))
    entries = core.get("llm.agents")
    if isinstance(entries, Mapping):
        for agent, entry in entries.items():
            if not isinstance(entry, Mapping):
                continue
            # An entry holding only its ceilings selects no provider.
            if isinstance(entry.get("provider"), str) and entry["provider"]:
                out.append((f"core.llm.agents.{agent}.provider", "llm", str(entry["provider"])))
            for position, fallback in enumerate(entry.get("fallbacks") or []):
                if isinstance(fallback, Mapping) and isinstance(fallback.get("provider"), str):
                    key = f"core.llm.agents.{agent}.fallbacks.{position}.provider"
                    out.append((key, "llm", str(fallback["provider"])))
    return out


def dropped_selections(before: Any, after: Any, core_after: Mapping[str, Any]) -> dict[str, str]:
    """The provider ids a save leaves selecting a plugin the same save drops from the list.

    ``before`` and ``after`` are the stored allow-list and the one the save
    leaves; ``core_after`` the core overrides it leaves. Each selection of a
    dropped plugin is named under its own key, and the list's key names them
    all. A shipped id is never a dropped plugin.
    """
    before_entries = {parse_entry(item) for item in usable_list(before)} - {None}
    after_entries = {parse_entry(item) for item in usable_list(after)} - {None}
    dropped = before_entries - after_entries
    if not dropped:
        return {}
    shipped: dict[str, set[str]] = {}
    errors: dict[str, str] = {}
    for key, kind, name in selections(core_after):
        if (kind, name) not in dropped:
            continue
        if name in shipped.setdefault(kind, set(shipped_ids(kind))):
            continue
        errors[key] = (
            f"selects {kind}:{name}, which this save drops from the plugin allow-list; "
            "select another provider in the same save, or keep the plugin allowed"
        )
    if errors:
        errors[ALLOW_LIST_KEY] = (
            "this save drops a plugin that a provider id still selects: "
            + ", ".join(sorted(errors))
        )
    return errors
