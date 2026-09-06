"""The path a static analyst is shown is the path its own provider mirrored.

Task 9 made the mirror per provider and pointed each agent's tool wrapper at
its own copy, but the prompt chunk — the thing the model actually reads and
hands ``load_program`` — still carried the global provider's path for every
static-role agent. With two static analysts on two providers the second one
was told to open a file its tools do not point at.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import MagicMock

from maljan.loaders.binary_chunker import TextChunk
from maljan.pipeline.nodes import _augment_static_chunks_with_path


def _chunk(content: str) -> TextChunk:
    return TextChunk(
        index=0,
        total=1,
        strategy=None,  # type: ignore[arg-type]
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain="static",
    )


_STATE: dict[str, Any] = {
    "file_hash": "abc123",
    "static_sample_path": "/data/samples/.work/abc123.exe",
    "static_sample_paths": {
        "ghidra": "/data/samples/.work/abc123.exe",
        "r2": "/host/work/abc123.exe",
    },
}


def test_the_chunk_carries_the_agents_own_providers_path():
    head = _chunk(json.dumps({"file": {"sha256": "abc123"}}))
    augmented = _augment_static_chunks_with_path(
        [head],
        _STATE,  # type: ignore[arg-type]
        provider_id="r2",
    )
    assert json.loads(augmented[0].content)["analysis_file_path"] == "/host/work/abc123.exe"


def test_a_provider_with_no_mirror_of_its_own_falls_back_to_the_global_path():
    head = _chunk(json.dumps({"file": {"sha256": "abc123"}}))
    augmented = _augment_static_chunks_with_path(
        [head],
        _STATE,  # type: ignore[arg-type]
        provider_id="capa_yara",
    )
    assert (
        json.loads(augmented[0].content)["analysis_file_path"] == "/data/samples/.work/abc123.exe"
    )


def test_the_node_shows_a_clone_on_r2_the_r2_mirror():
    """Through the real node factory, the way a two-provider profile runs."""
    from maljan.pipeline.nodes import make_analyst_node

    agent = MagicMock()
    agent._resolved.static_provider_id = "r2"
    agent.safe_analyze_isr.return_value = MagicMock(
        model_dump=lambda **kw: {}, findings=[], summary=""
    )

    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda t, d: None
    container.get_agent.return_value = agent
    container.agent_role.return_value = "static"
    container.load_chunked.return_value = [_chunk(json.dumps({"file": {"sha256": "abc123"}}))]
    container.config.llm.view_decomposition_views = 0

    node = make_analyst_node("static_r2", container)
    node(dict(_STATE, sample_path="/tmp/abc123.exe"))  # type: ignore[arg-type]

    shown = agent.safe_analyze_isr.call_args[0][0]
    assert "/host/work/abc123.exe" in shown
    assert "/data/samples/.work/abc123.exe" not in shown
    assert agent._analysis_file_path == "/host/work/abc123.exe"
