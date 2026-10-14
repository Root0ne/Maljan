"""Doubles for the chunk tests: a room, a chunk, and a container whose loading is its own code.

The container is a ``MagicMock`` with ``ServiceContainer``'s data-loading
methods bound to it over a real chunker, so what it hands an analyst is what a
run's container hands it, and its truncation ledger is a real one.
"""

from __future__ import annotations

import threading
from types import MethodType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

from maljan.core.config import ChunkingConfig
from maljan.core.container import ServiceContainer
from maljan.core.truncation_ledger import TruncationLedger
from maljan.loaders.binary_chunker import BinaryChunker, ChunkStrategy, TextChunk


def _room(chars: int | None) -> Any:
    return lambda _text: chars


def _chunk(content: str, index: int = 0, total: int = 1) -> TextChunk:
    return TextChunk(
        index=index,
        total=total,
        strategy=ChunkStrategy.SLIDING_WINDOW,
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain="triage",
    )


def _container(
    *,
    role: str = "network",
    sample: str = "",
    network: str | None = None,
    config: ChunkingConfig | None = None,
    sources: list[str] | None = None,
    buildable: bool = True,
) -> Any:
    """A double whose data loading is the container's own code over a real chunker."""
    chunking = config or ChunkingConfig(overlap_tokens=0)
    chunker = BinaryChunker(chunking)
    container = MagicMock()
    container.config.chunking = chunking
    container.config.agents.definitions = (
        {"agent": SimpleNamespace(data_sources=sources)} if sources else {}
    )
    container._lock = threading.RLock()
    container._data_cache = {}
    container._first_pass_chunk_chars = {}
    container._truncation_ledger = TruncationLedger()
    container.agent_role.return_value = role
    container.loader.chunk_text.side_effect = lambda name, text, room=None: chunker.chunk(
        name, text, room=room
    )
    container.loader.load_chunked.side_effect = lambda _h, name, room=None: chunker.chunk(
        name, sample, room=room
    )
    if network is None:
        container.parser_registry.create.side_effect = KeyError("no parser in this double")
    else:
        container.parser_registry.create.return_value.parse.return_value = network
    if not buildable:
        container.get_agent.side_effect = RuntimeError("no model")
    for name in (
        "load_chunked",
        "load_data_for_agent",
        "_data_source_chunks",
        "_sandbox_slice",
        "_legacy_role_data",
    ):
        setattr(container, name, MethodType(getattr(ServiceContainer, name), container))
    return container


def _rows(container: Any) -> list[dict[str, Any]]:
    return list(container._truncation_ledger.snapshot()["input_split_unknown_window"])
