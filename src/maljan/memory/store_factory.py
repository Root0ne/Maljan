"""The one place a long-term-memory store is built from the settings.

Every caller that needs the configured store asks here: the analysis
container, the enrichment worker, the API's purge, ``/health``, the
function-hash attribution steps and the command line. None of them names a
backend. A backend registers under the id ``memory.backend`` selects, with
the builder that makes its store and, when it has settings, the model they
are read with: they live under ``memory.<id>.*``, the catalogue lists them,
and the settings store saves them like any other key. What a backend cannot
do it says through the ``MemoryStore`` interface (``function_hash_store``
answering ``None``), and every caller degrades the same way for it.

Registration reaches every process (API, analysis worker, enrichment worker,
command line) through this module: the shipped backends register as it is
imported, and an installed package adds its own through the
``maljan.memory_backends`` entry-point group, loaded here on first use. An
entry point names a callable that calls ``register_memory_backend``.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from maljan.core.config import QdrantMemoryConfig
from maljan.core.exceptions import MemoryStoreError
from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import FunctionHashIndex, MemoryStore

MemoryBackendBuilder = Callable[[Any], "MemoryStore"]
ENTRY_POINT_GROUP = "maljan.memory_backends"


class MemoryBackendNotConfiguredError(MemoryStoreError):
    """``memory.backend`` names no backend this process can build.

    ``unavailable`` is true when a package declared that backend and failed to
    load (``reason`` says how); false when nothing registered the id at all.
    """

    def __init__(self, backend: str, reason: str, *, unavailable: bool) -> None:
        super().__init__(reason)
        self.backend = backend
        self.reason = reason
        self.unavailable = unavailable


@dataclass(frozen=True)
class MemoryBackend:
    """One registered backend: its builder, and the settings it reads.

    ``settings_model`` is the model ``memory.<id>`` is read with (``None``: the
    backend has no settings). ``annotations`` describes its leaves for the
    catalogue, keyed by the leaf's path under ``memory.<id>.`` (``"url"``),
    each a ``settings_annotations.Annotation``. ``label`` is the short phrase
    the console shows beside the id (``"in-process"``); empty shows the id alone.
    ``probe_label`` names its connection test in the console; empty shows a
    generic one.
    """

    id: str
    build: MemoryBackendBuilder
    settings_model: type[BaseModel] | None = None
    annotations: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    label: str = ""
    probe_label: str = ""


_BACKENDS: dict[str, MemoryBackend] = {}
# Entry points that failed to load, by entry-point name (the backend id it
# registers, by convention), with the reason.
_UNAVAILABLE: dict[str, str] = {}
_LOAD_LOCK = threading.Lock()
_entry_points_loaded = False


def _key(backend_id: Any) -> str:
    return str(backend_id or "").strip().lower()


def register_memory_backend(
    backend_id: str,
    builder: MemoryBackendBuilder,
    *,
    settings_model: type[BaseModel] | None = None,
    annotations: Mapping[str, Mapping[str, Any]] | None = None,
    label: str = "",
    probe_label: str = "",
) -> None:
    """Make ``backend_id`` a value ``memory.backend`` can select.

    ``builder`` takes the memory configuration and returns a ``MemoryStore``;
    it reads its own settings with ``backend_settings(memory, backend_id)``.
    Registering an id again replaces it. A package's entry point is best named
    after the id it registers: a failure to load is then reported against that
    id alone, where otherwise any selected id nothing registered is reported
    unavailable with every failure's reason.
    """
    key = _key(backend_id)
    if not key:
        raise ValueError("a memory backend needs a non-empty id")
    _BACKENDS[key] = MemoryBackend(
        key,
        builder,
        settings_model,
        dict(annotations or {}),
        str(label or "").strip(),
        str(probe_label or "").strip(),
    )
    forget_built_stores()


def _load_entry_points() -> None:
    """Run every installed ``maljan.memory_backends`` entry point, once per process."""
    global _entry_points_loaded
    if _entry_points_loaded:
        return
    with _LOAD_LOCK:
        if _entry_points_loaded:
            return
        _entry_points_loaded = True
        for point in entry_points(group=ENTRY_POINT_GROUP):
            try:
                loaded = point.load()
                if callable(loaded):
                    loaded()
            except Exception as exc:  # noqa: BLE001 — one broken package never stops the rest
                reason = f"{type(exc).__name__}: {exc}".strip()
                _UNAVAILABLE[_key(point.name)] = reason
                logger.warning(
                    "memory backend entry point %r failed to load (%s).", point.name, exc
                )


def registered_backends() -> dict[str, MemoryBackend]:
    """Every registered backend by id, in registration order."""
    _load_entry_points()
    return dict(_BACKENDS)


def unavailable_backends() -> dict[str, str]:
    """Backends a package declared that failed to load, each with the reason."""
    _load_entry_points()
    return dict(_UNAVAILABLE)


def memory_backends() -> tuple[str, ...]:
    """The backend ids ``memory.backend`` can select, in registration order."""
    return tuple(registered_backends())


def _memory_config(settings_or_memory: Any) -> Any:
    """The memory configuration, given either the whole settings or the memory block."""
    return getattr(settings_or_memory, "memory", settings_or_memory)


def configured_backend(settings_or_memory: Any) -> str:
    """The backend id the settings select, normalised; empty when none is set."""
    return _key(getattr(_memory_config(settings_or_memory), "backend", ""))


def backend_settings(settings_or_memory: Any, backend_id: str) -> Any:
    """``memory.<backend_id>``: the backend's own settings, or ``None`` when it has none."""
    return getattr(_memory_config(settings_or_memory), _key(backend_id), None)


def _backend(settings_or_memory: Any) -> MemoryBackend:
    backend = configured_backend(settings_or_memory)
    found = registered_backends().get(backend)
    if found is not None:
        return found
    # The entry point that failed is matched by name when it carries the
    # backend's id; any other failed package may be the one that registers
    # this id, so the selected id is unavailable whenever one failed.
    broken = _UNAVAILABLE.get(backend)
    failures = [broken] if broken is not None else list(_UNAVAILABLE.values())
    if failures:
        raise MemoryBackendNotConfiguredError(
            backend,
            f"memory backend {backend!r} is unavailable: a backend package failed to load "
            f"({'; '.join(failures)})",
            unavailable=True,
        )
    known = ", ".join(_BACKENDS) or "none"
    raise MemoryBackendNotConfiguredError(
        backend,
        f"memory.backend {backend!r} is not a registered memory backend (known: {known})",
        unavailable=False,
    )


def build_memory_store(settings_or_memory: Any) -> MemoryStore:
    """The configured long-term-memory store.

    Raises ``MemoryBackendNotConfiguredError`` when ``memory.backend`` names no
    registered backend, and ``MemoryStoreError`` when the builder returns an
    object without the ``MemoryStore`` interface; a backend's own construction
    errors (a missing client library, say) propagate as the backend raised them.
    """
    from maljan.memory.long_term_memory import MemoryStore

    memory = _memory_config(settings_or_memory)
    backend = _backend(memory)
    store = backend.build(memory)
    if not isinstance(store, MemoryStore):
        missing = [
            name
            for name in (
                "store",
                "retrieve",
                "count",
                "clear",
                "purge_low_quality",
                "readiness",
                "function_hash_store",
                "close",
            )
            if not callable(getattr(store, name, None))
        ]
        raise MemoryStoreError(
            f"memory backend {backend.id!r} built {type(store).__name__}, which lacks "
            f"the MemoryStore interface ({', '.join(missing) or 'unknown'}); "
            "derive it from maljan.memory.long_term_memory.MemoryStoreDefaults"
        )
    return store


def _settings_fingerprint(memory: Any, backend_id: str) -> str:
    """A digest of the backend's own settings, secrets included, for keying a cache."""
    own = backend_settings(memory, backend_id)
    dumped = own.model_dump() if isinstance(own, BaseModel) else own

    def plain(value: Any) -> Any:
        return value.get_secret_value() if hasattr(value, "get_secret_value") else str(value)

    text = json.dumps(dumped, default=plain, sort_keys=True)
    return hashlib.sha256(f"{backend_id}\0{text}".encode()).hexdigest()


# One store per backend id, with the fingerprint of the settings it was
# built from; a settings change replaces (and closes) it.
_FUNCTION_HASH_STORES: dict[str, tuple[str, FunctionHashIndex | None]] = {}
_FUNCTION_HASH_LOCK = threading.Lock()
# How many holders each handed-out store has (``acquire_function_hash_store``),
# by ``id``; a held store keeps its entry, so the id cannot be reused meanwhile.
_LEASES: dict[int, int] = {}
# Stores a settings change replaced while someone still held them: closed when
# the last holder releases, never under a running job.
_RETIRED: dict[int, Any] = {}


def _retire(store: Any) -> Any:
    """Under the lock: the store to close now, or ``None`` when it is still held."""
    if store is None:
        return None
    if _LEASES.get(id(store)):
        _RETIRED[id(store)] = store
        return None
    return store


def build_function_hash_store(settings_or_memory: Any) -> FunctionHashIndex | None:
    """The configured backend's function-hash store, or ``None`` when it keeps none.

    Built once per backend and settings, and handed out again: three steps of
    every run ask for it, and each build opens a client.
    """
    return _function_hash_store(settings_or_memory, hold=False)


def _function_hash_store(settings_or_memory: Any, *, hold: bool) -> FunctionHashIndex | None:
    """The cached store for the settings, built when they changed; with ``hold``
    the hold is counted in the same locked section, so no replacement can
    close the store between handing it out and counting its holder."""
    memory = _memory_config(settings_or_memory)
    backend = _backend(memory)
    fingerprint = _settings_fingerprint(memory, backend.id)
    superseded = None
    with _FUNCTION_HASH_LOCK:
        held = _FUNCTION_HASH_STORES.get(backend.id)
        if held is not None and held[0] == fingerprint:
            store = held[1]
        else:
            store = build_memory_store(memory).function_hash_store()
            _FUNCTION_HASH_STORES[backend.id] = (fingerprint, store)
            superseded = _retire(held[1]) if held is not None else None
        if hold and store is not None:
            _LEASES[id(store)] = _LEASES.get(id(store), 0) + 1
    _close(superseded)
    return store


def acquire_function_hash_store(settings_or_memory: Any) -> FunctionHashIndex | None:
    """``build_function_hash_store``, held until ``release_function_hash_store``.

    A store a settings change replaces is closed only once every holder has
    released it, so a job keeps reading and writing the store it started with.
    """
    return _function_hash_store(settings_or_memory, hold=True)


def release_function_hash_store(store: Any) -> None:
    """Let go of a store from ``acquire_function_hash_store``; the last holder of a
    replaced store closes it. ``None`` is a no-op."""
    if store is None:
        return
    with _FUNCTION_HASH_LOCK:
        left = _LEASES.get(id(store), 0) - 1
        if left > 0:
            _LEASES[id(store)] = left
            return
        _LEASES.pop(id(store), None)
        retired = _RETIRED.pop(id(store), None)
    _close(retired)


@contextmanager
def leased_function_hash_store(settings_or_memory: Any) -> Iterator[FunctionHashIndex | None]:
    """The function-hash store, held for the ``with`` block."""
    store = acquire_function_hash_store(settings_or_memory)
    try:
        yield store
    finally:
        release_function_hash_store(store)


def _close(store: Any) -> None:
    """Close a function-hash store that offers ``close``; closing never fails the caller."""
    if store is None:
        return
    close = getattr(store, "close", None)
    if callable(close):
        try:
            close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("closing a superseded function-hash store: %s", exc)


def forget_built_stores() -> None:
    """Drop every cached function-hash store, so the next ask builds afresh."""
    with _FUNCTION_HASH_LOCK:
        now = [_retire(store) for _fingerprint, store in _FUNCTION_HASH_STORES.values()]
        _FUNCTION_HASH_STORES.clear()
    for store in now:
        _close(store)


# ---------------------------------------------------------------------------
# The shipped backends
# ---------------------------------------------------------------------------


def _secret(value: Any) -> str | None:
    """A configured secret as the plain string a client takes, or ``None`` when unset."""
    if value is None:
        return None
    plain = value.get_secret_value() if hasattr(value, "get_secret_value") else str(value)
    return plain or None


def _build_in_process(memory: Any) -> MemoryStore:
    from maljan.memory.in_memory_store import InMemoryStore

    return InMemoryStore()


def _build_qdrant(memory: Any) -> MemoryStore:
    from maljan.memory.qdrant_store import QdrantStore

    own = backend_settings(memory, "qdrant") or QdrantMemoryConfig()
    return QdrantStore(
        url=own.url,
        collection=own.collection,
        api_key=_secret(own.api_key),
        function_hash_collection=own.function_hash_collection or None,
    )


register_memory_backend("memory", _build_in_process, label="in-process")
register_memory_backend(
    "qdrant", _build_qdrant, settings_model=QdrantMemoryConfig, probe_label="Test Qdrant"
)
