"""Memory and intelligence retrieval subsystem for Maljan.

Modules:
  ATT&CK Index:
    - attck_loader:    Downloads and parses MITRE ATT&CK STIX 2.1 bundle.
    - attck_index:     In-memory TF-IDF index over ATT&CK technique descriptions.
    - attck_validator: The shared ATT&CK index, and the id-exists lookup over it.

  Long-Term Memory:
    - long_term_memory: StoredCase dataclass, MemoryStore Protocol, build_stored_case().
    - in_memory_store:  InMemoryStore -- pure-Python cosine similarity, zero dependencies.
    - qdrant_store:     QdrantStore -- production Qdrant backend (requires qdrant-client).
    - store_factory:    build_memory_store() -- the one place every caller builds the
                        store memory.backend selects; register_memory_backend() adds one.
"""

from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import MemoryStore, StoredCase, build_stored_case

__all__ = [
    "InMemoryStore",
    "MemoryStore",
    "StoredCase",
    "build_stored_case",
]
