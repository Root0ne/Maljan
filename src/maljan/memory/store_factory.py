"""The one place a long-term-memory store is built from the settings.

Every caller that needs the configured store asks here: the analysis
container, the enrichment worker, the API's purge, ``/health``, the
function-hash attribution steps and the command line. None of them names a
backend. A backend registers a builder under the id ``memory.backend``
selects; what a backend cannot do it says through the ``MemoryStore``
interface (``function_hash_store`` answering ``None``), and every caller
degrades the same way for it.

Adding a backend is one ``register_memory_backend`` call with a builder that
reads its own settings off the memory configuration.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from maljan.core.exceptions import MemoryStoreError

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import FunctionHashIndex, MemoryStore

MemoryBackendBuilder = Callable[[Any], "MemoryStore"]


class MemoryBackendNotConfiguredError(MemoryStoreError):
    """``memory.backend`` names no registered backend (or is empty)."""


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

    return QdrantStore(
        url=memory.qdrant_url,
        collection=memory.qdrant_collection,
        api_key=_secret(memory.qdrant_api_key),
        function_hash_collection=memory.qdrant_function_hash_collection or None,
    )


_BACKENDS: dict[str, MemoryBackendBuilder] = {
    "memory": _build_in_process,
    "qdrant": _build_qdrant,
}


def register_memory_backend(backend_id: str, builder: MemoryBackendBuilder) -> None:
    """Make ``backend_id`` a value ``memory.backend`` can select.

    ``builder`` takes the memory configuration and returns a ``MemoryStore``.
    Registering an id again replaces its builder.
    """
    key = str(backend_id or "").strip().lower()
    if not key:
        raise ValueError("a memory backend needs a non-empty id")
    _BACKENDS[key] = builder


def memory_backends() -> tuple[str, ...]:
    """The backend ids ``memory.backend`` can select, in registration order."""
    return tuple(_BACKENDS)


def _memory_config(settings_or_memory: Any) -> Any:
    """The memory configuration, given either the whole settings or the memory block."""
    return getattr(settings_or_memory, "memory", settings_or_memory)


def configured_backend(settings_or_memory: Any) -> str:
    """The backend id the settings select, normalised; empty when none is set."""
    memory = _memory_config(settings_or_memory)
    return str(getattr(memory, "backend", "") or "").strip().lower()


def build_memory_store(settings_or_memory: Any) -> MemoryStore:
    """The configured long-term-memory store.

    Raises ``MemoryBackendNotConfiguredError`` when ``memory.backend`` names
    no registered backend; a backend's own construction errors (a missing
    client library, say) propagate as the backend raised them.
    """
    memory = _memory_config(settings_or_memory)
    backend = configured_backend(memory)
    builder = _BACKENDS.get(backend)
    if builder is None:
        known = ", ".join(_BACKENDS) or "none"
        raise MemoryBackendNotConfiguredError(
            f"memory.backend {backend!r} is not a registered memory backend (known: {known})"
        )
    return builder(memory)


def build_function_hash_store(settings_or_memory: Any) -> FunctionHashIndex | None:
    """The configured backend's function-hash store, or ``None`` when it keeps none."""
    return build_memory_store(settings_or_memory).function_hash_store()
