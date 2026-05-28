"""Wave 6 GHIDRA-DELIVERY-01 regression tests (2026-05-28).

Three layers exercise the static-analyst path delivery:
  1. ``_augment_static_chunks_with_path`` splices ``analysis_file_path``
     into the chunk JSON when the worker recorded a container-visible
     mirror via ``state['static_sample_path']``.
  2. ``_extract_load_hint`` lifts that field to a dedicated ``LOAD THIS
     BINARY FIRST`` line in the static analyst's human turn.
  3. End-to-end: a chunk-with-no-path passes through unchanged so the
     legacy raw-bytes / metadata-only flow still works.
"""

from __future__ import annotations

import json

from maljan.agents.static_analyst import _extract_load_hint
from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.pipeline.nodes import _augment_static_chunks_with_path

_FAKE_STRATEGY = ChunkStrategy.SLIDING_WINDOW


def _chunk(content: str) -> TextChunk:
    return TextChunk(
        index=0,
        total=1,
        strategy=_FAKE_STRATEGY,
        content=content,
        char_count=len(content),
        token_estimate=len(content) // 4,
        domain="static",
    )


class TestAugmentStaticChunksWithPath:
    """``_augment_static_chunks_with_path`` injects the container path."""

    def test_injects_path_into_json_chunk(self) -> None:
        target = {
            "file": {"sha256": "a" * 64, "name": "evil.apk", "size": 1024},
        }
        chunks = [_chunk(json.dumps(target))]
        state = {
            "static_sample_path": "/data/samples/a" + "a" * 63 + ".apk",
        }
        out = _augment_static_chunks_with_path(chunks, state)  # type: ignore[arg-type]
        assert len(out) == 1
        parsed = json.loads(out[0].content)
        assert parsed["analysis_file_path"] == state["static_sample_path"]
        # Original keys preserved.
        assert parsed["file"]["sha256"] == "a" * 64

    def test_noop_when_state_path_missing(self) -> None:
        chunks = [_chunk(json.dumps({"file": {"sha256": "b" * 64}}))]
        state: dict = {}
        out = _augment_static_chunks_with_path(chunks, state)  # type: ignore[arg-type]
        assert out is chunks  # same object — short-circuit

    def test_noop_on_non_json_chunk(self) -> None:
        chunks = [_chunk("raw decompile output that is not JSON")]
        state = {"static_sample_path": "/data/samples/x.exe"}
        out = _augment_static_chunks_with_path(chunks, state)  # type: ignore[arg-type]
        # Returned the original list unchanged.
        assert out[0].content == "raw decompile output that is not JSON"

    def test_noop_on_empty_chunks(self) -> None:
        state = {"static_sample_path": "/data/samples/x.exe"}
        out = _augment_static_chunks_with_path([], state)  # type: ignore[arg-type]
        assert out == []

    def test_keeps_tail_chunks(self) -> None:
        head = _chunk(json.dumps({"file": {"sha256": "c" * 64}}))
        tail = _chunk("tail chunk")
        chunks = [head, tail]
        state = {"static_sample_path": "/data/samples/tail.exe"}
        out = _augment_static_chunks_with_path(chunks, state)  # type: ignore[arg-type]
        assert len(out) == 2
        assert out[1] is tail  # tail untouched


class TestExtractLoadHint:
    """``_extract_load_hint`` formats the human-turn LOAD line."""

    def test_returns_load_line_when_path_present(self) -> None:
        data = json.dumps(
            {"file": {"sha256": "d" * 64}, "analysis_file_path": "/data/samples/d.apk"}
        )
        hint = _extract_load_hint(data)
        assert "LOAD THIS BINARY FIRST" in hint
        assert 'load_program(file="/data/samples/d.apk")' in hint

    def test_returns_empty_when_path_missing(self) -> None:
        data = json.dumps({"file": {"sha256": "e" * 64}})
        assert _extract_load_hint(data) == ""

    def test_returns_empty_on_non_json_data(self) -> None:
        assert _extract_load_hint("raw bytes here") == ""

    def test_returns_empty_on_empty_input(self) -> None:
        assert _extract_load_hint("") == ""

    def test_returns_empty_when_path_field_is_not_a_string(self) -> None:
        data = json.dumps({"analysis_file_path": 123})
        assert _extract_load_hint(data) == ""
