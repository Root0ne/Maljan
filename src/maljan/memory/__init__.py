"""Memory and intelligence retrieval subsystem for Maljan.

Modules:
  ATT&CK Index (Phase 4):
    - attck_loader:    Downloads and parses MITRE ATT&CK STIX 2.1 bundle.
    - attck_index:     In-memory TF-IDF index over ATT&CK technique descriptions.
    - attck_validator: Validates proposed TTP IDs against the authoritative ATT&CK dataset.
    - ttp_validation:  TTPValidationSummary dataclass and helpers.

  Long-Term Memory (Phase 5):
    - long_term_memory: StoredCase dataclass, MemoryStore Protocol, build_stored_case().
    - in_memory_store:  InMemoryStore -- pure-Python cosine similarity, zero dependencies.
    - qdrant_store:     QdrantStore stub -- production Qdrant backend (requires qdrant-client).
"""

from maljan.memory.in_memory_store import InMemoryStore
from maljan.memory.long_term_memory import MemoryStore, StoredCase, build_stored_case

__all__ = [
    "InMemoryStore",
    "MemoryStore",
    "StoredCase",
    "build_stored_case",
]
