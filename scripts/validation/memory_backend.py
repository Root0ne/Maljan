"""A third long-term-memory backend, registered in-process the way a package registers one.

``validation_kv`` keeps its cases in a dict keyed by sample id, for the life
of the process, and keeps no function hashes (``function_hash_store()`` is
``None``). It is registered through the product's own registry
(``memory.store_factory.register_memory_backend``), so every reader of the
registry — the settings build, the catalogue's choices, the connection test,
``/health`` — meets it exactly as it would meet an installed backend.
"""

from __future__ import annotations

import re
import threading
from typing import Any

BACKEND_ID = "validation_kv"
PROBE_LABEL = "Test validation store"
_WORD = re.compile(r"[a-z0-9]+")


def _words(text: str) -> set[str]:
    return set(_WORD.findall(str(text or "").lower()))


class ValidationKVStore:
    """A dict of cases by sample id; retrieval ranks by shared words."""

    def __init__(self) -> None:
        self._cases: dict[str, Any] = {}
        self._lock = threading.Lock()
        # Every ``store`` call, in order: the sample id each wrote.
        self.writes: list[str] = []

    def store(self, case: Any) -> None:
        with self._lock:
            self._cases[str(case.sample_id)] = case
            self.writes.append(str(case.sample_id))

    def retrieve(
        self, query: str, top_k: int = 3, exclude_sample_id: str | None = None
    ) -> list[Any]:
        wanted = _words(query)
        if not wanted:
            return []
        with self._lock:
            held = [
                case
                for sample_id, case in self._cases.items()
                if not exclude_sample_id or sample_id != exclude_sample_id
            ]
        held.sort(key=lambda case: len(wanted & _words(case.summary_text)), reverse=True)
        return held[:top_k]

    def count(self) -> int:
        with self._lock:
            return len(self._cases)

    def clear(self) -> None:
        with self._lock:
            self._cases.clear()

    def purge_low_quality(self, **_kwargs: Any) -> int:
        return 0

    def readiness(self) -> str:
        return f"validation store holding {self.count()} case(s)"

    def function_hash_store(self) -> Any:
        return None

    def close(self) -> None:
        """Nothing to release: the cases outlive a build, as a server's would."""


# One store for the process, so a second run reads what the first wrote.
STORE = ValidationKVStore()


def _build(_memory: Any) -> ValidationKVStore:
    return STORE


def register() -> ValidationKVStore:
    """Register ``validation_kv`` with the product's registry; answer the one store."""
    from maljan.memory.store_factory import register_memory_backend

    register_memory_backend(BACKEND_ID, _build, label="validation", probe_label=PROBE_LABEL)
    return STORE


def unregister() -> None:
    """Take ``validation_kv`` out of the registry again."""
    from maljan.memory import store_factory

    store_factory._BACKENDS.pop(BACKEND_ID, None)
    store_factory.forget_built_stores()
