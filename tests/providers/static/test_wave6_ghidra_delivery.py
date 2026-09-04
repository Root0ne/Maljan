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

from maljan.agents.static_analyst import (
    _extract_analysis_path,
    _extract_host_path,
    _extract_load_hint,
    _extract_sample_hash,
)
from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk
from maljan.pipeline.nodes import (
    _MAX_SYNTH_CHUNK_CHARS,
    _augment_static_chunks_with_path,
    _compact_static_summary,
)
from maljan.reporting.models import ImportRow, PESection, StaticAnalysis, StringIOC

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


_PLACEHOLDER = "No static data available for sample " + "f" * 64 + "."


def _static(n_imports: int = 3, n_strings: int = 2) -> StaticAnalysis:
    return StaticAnalysis(
        sections=[
            PESection(name=".text", virtual_address="0x1000", entropy=6.1),
            PESection(name=".data", virtual_address="0x5000", entropy=3.2),
        ],
        imports=[
            ImportRow(
                dll="WS2_32.dll",
                function=f"fn_{i}",
                is_suspicious=(i % 2 == 0),
                category="network" if i % 2 == 0 else None,
            )
            for i in range(n_imports)
        ],
        interesting_strings=[
            StringIOC(value=f"http://evil{i}.example", kind="url") for i in range(n_strings)
        ],
        packer_hint=None,
        obfuscation_indicators=[],
    )


class TestSynthesizedPlaceholderChunk:
    """Ghidra-path fix (2026-07-12): the file-loader placeholder chunk is
    replaced by a synthesized JSON chunk carrying the container path, so the
    LLM never has to guess (job 60df48cb hallucinated /home/user/data/bin.<sha>)."""

    _STATE = {
        "static_sample_path": "/data/samples/" + "f" * 64 + ".exe",
        "sample_path": "/app/data/samples/.tmp/" + "f" * 64 + ".exe",
        "file_hash": "f" * 64,
    }

    def test_synthesizes_json_for_placeholder_chunk(self) -> None:
        chunks = [_chunk(_PLACEHOLDER)]
        out = _augment_static_chunks_with_path(
            chunks,
            self._STATE,  # type: ignore[arg-type]
            static=_static(),
        )
        assert len(out) == 1
        parsed = json.loads(out[0].content)
        assert parsed["analysis_file_path"] == self._STATE["static_sample_path"]
        assert parsed["host_sample_path"] == self._STATE["sample_path"]
        assert parsed["sha256"] == "f" * 64
        assert parsed["static_summary"]["imports"]
        # Chunk metadata rebuilt for the new content.
        assert out[0].char_count == len(out[0].content)
        assert out[0].token_estimate == len(out[0].content) // 4

    def test_placeholder_minimal_json_when_static_none(self) -> None:
        chunks = [_chunk(_PLACEHOLDER)]
        out = _augment_static_chunks_with_path(
            chunks,
            self._STATE,  # type: ignore[arg-type]
            static=None,
        )
        parsed = json.loads(out[0].content)
        assert parsed["analysis_file_path"] == self._STATE["static_sample_path"]
        assert parsed["static_summary"] is None
        assert "note" in parsed

    def test_placeholder_noop_without_static_sample_path(self) -> None:
        chunks = [_chunk(_PLACEHOLDER)]
        state: dict = {}
        out = _augment_static_chunks_with_path(chunks, state, static=_static())  # type: ignore[arg-type]
        assert out is chunks

    def test_non_placeholder_non_json_noop_even_with_static(self) -> None:
        chunks = [_chunk("raw decompile output that is not JSON")]
        out = _augment_static_chunks_with_path(
            chunks,
            self._STATE,  # type: ignore[arg-type]
            static=_static(),
        )
        assert out[0].content == "raw decompile output that is not JSON"

    def test_static_summary_caps(self) -> None:
        summary = _compact_static_summary(_static(n_imports=200, n_strings=100))
        assert len(summary["imports"]) == 60
        # Suspicious imports sort first, so all 100 suspicious rows that fit
        # the cap must be suspicious.
        assert all(row["is_suspicious"] for row in summary["imports"])
        assert summary["imports_truncated"] == 140
        assert len(summary["interesting_strings"]) == 40
        assert summary["strings_truncated"] == 60
        assert summary["embedded_resources_count"] == 0
        assert len(json.dumps(summary)) < _MAX_SYNTH_CHUNK_CHARS

    def test_extractors_fire_on_synthesized_chunk(self) -> None:
        chunks = [_chunk(_PLACEHOLDER)]
        out = _augment_static_chunks_with_path(
            chunks,
            self._STATE,  # type: ignore[arg-type]
            static=_static(),
        )
        data = out[0].content
        hint = _extract_load_hint(data)
        assert "LOAD THIS BINARY FIRST" in hint
        assert self._STATE["static_sample_path"] in hint
        assert _extract_analysis_path(data) == self._STATE["static_sample_path"]
        assert _extract_host_path(data) == self._STATE["sample_path"]
        assert _extract_sample_hash(data) == "f" * 64


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
