"""A data source of an agent definition may declare where it is cut into chunks.

``chunk_boundary`` maps a source in ``data_sources`` to a pattern for the start
of a unit. Absent, a source is cut as it always was (the built-in boundary of
its domain, else a window), and a definition that names none dumps as before.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from maljan.core.config import AgentDefinition, ChunkingConfig
from maljan.loaders.binary_chunker import (
    BOUNDARY,
    CHUNK_CHARS,
    SIZED_BY,
    SIZED_BY_ROOM,
    BinaryChunker,
    ChunkStrategy,
    within_the_room,
)

UNIT = "@@ unit {n} @@\n" + "body line of the unit\n" * 4


def _text(units: int = 12) -> str:
    return "".join(UNIT.format(n=n) for n in range(units))


def _chunker() -> BinaryChunker:
    return BinaryChunker(ChunkingConfig(max_tokens_per_chunk=100, overlap_tokens=0))


class TestTheChunkerCutsAtTheDeclaredBoundary:
    def test_every_chunk_opens_at_a_unit_start(self) -> None:
        chunks = _chunker().chunk("custom", _text(), boundary=r"^@@ unit \d+ @@")

        assert len(chunks) > 1
        assert all(chunk.content.startswith("@@ unit ") for chunk in chunks)
        assert {chunk.strategy for chunk in chunks} == {ChunkStrategy.DECLARED_BOUNDARY}
        assert all(chunk.metadata[BOUNDARY] == r"^@@ unit \d+ @@" for chunk in chunks)

    def test_no_unit_is_split_while_it_fits_a_chunk(self) -> None:
        chunks = _chunker().chunk("custom", _text(), boundary=r"^@@ unit \d+ @@")

        for chunk in chunks:
            assert chunk.content.count("@@ unit") == chunk.content.count("body line") // 4

    def test_without_a_declaration_a_custom_domain_is_cut_by_a_window_as_before(self) -> None:
        chunks = _chunker().chunk("custom", _text())

        assert {chunk.strategy for chunk in chunks} == {ChunkStrategy.SLIDING_WINDOW}
        assert all(BOUNDARY not in chunk.metadata for chunk in chunks)

    def test_a_text_the_pattern_never_matches_falls_back_to_the_window(self) -> None:
        chunks = _chunker().chunk("custom", _text(), boundary=r"^NOTHING HERE")

        assert {chunk.strategy for chunk in chunks} == {ChunkStrategy.SLIDING_WINDOW}

    def test_a_declaration_replaces_the_domains_built_in_boundary(self) -> None:
        text = "".join(f"PID: {n}\n" + "x\n" * 150 for n in range(6))

        built_in = _chunker().chunk("dynamic", text)
        declared = _chunker().chunk("dynamic", text, boundary=r"^PID: \d+")

        assert {chunk.strategy for chunk in built_in} == {ChunkStrategy.API_SEQUENCE}
        assert {chunk.strategy for chunk in declared} == {ChunkStrategy.DECLARED_BOUNDARY}

    def test_a_later_cut_of_a_chunk_is_made_at_the_same_boundary(self) -> None:
        config = ChunkingConfig(max_tokens_per_chunk=None, overlap_tokens=0)
        chunker = BinaryChunker(config)
        boundary = r"^@@ unit \d+ @@"
        small = chunker.chunk("custom", _text(1), boundary=boundary)[0]
        big = chunker.chunk("custom", _text(30), boundary=boundary)[0]
        big.metadata.update({SIZED_BY: SIZED_BY_ROOM, CHUNK_CHARS: len(big.content) // 3})

        cut = within_the_room([small, big], config)

        assert len(cut) > 2
        assert all(piece.content.startswith("@@ unit ") for piece in cut)


class TestTheDeclarationIsChecked:
    def _definition(self, **fields: object) -> AgentDefinition:
        base = {"role": "generic", "data_sources": ["sandbox.behavior"]}
        return AgentDefinition.model_validate({**base, **fields})

    def test_a_pattern_for_a_listed_source_is_kept(self) -> None:
        definition = self._definition(chunk_boundary={"sandbox.behavior": r"^PID: \d+"})

        assert definition.chunk_boundary == {"sandbox.behavior": r"^PID: \d+"}
        assert definition.model_dump()["chunk_boundary"] == {"sandbox.behavior": r"^PID: \d+"}

    def test_a_definition_with_none_dumps_without_the_key(self) -> None:
        assert "chunk_boundary" not in self._definition().model_dump()

    def test_a_source_the_agent_does_not_list_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="not in this agent's data_sources"):
            self._definition(chunk_boundary={"sandbox.network": "^Flow"})

    def test_a_pattern_that_does_not_compile_is_refused(self) -> None:
        with pytest.raises(ValidationError, match="is not a pattern"):
            self._definition(chunk_boundary={"sandbox.behavior": "("})

    def test_a_pattern_that_matches_the_empty_text_is_refused(self) -> None:
        for pattern in ("", "x*", "^"):
            with pytest.raises(ValidationError, match="matches the empty text"):
                self._definition(chunk_boundary={"sandbox.behavior": pattern})


class TestTheContainerHandsTheDeclarationToTheChunker:
    def _chunks(self, **definition: object) -> list:
        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        base = {"role": "generic", "prompt": "Read the log.", "data_sources": ["sandbox.target"]}
        settings = Settings(
            _env_file=None,
            agents={"definitions": {"reader": {**base, **definition}}},
            chunking={"max_tokens_per_chunk": 100, "overlap_tokens": 0},
        )
        container = ServiceContainer(settings, mock=True)
        report = {"target": {"file": {"name": "x"}, "log": _text(40)}}
        return container.load_data_for_agent("reader", file_hash="abc", sandbox_report=report)

    def test_a_slice_is_cut_where_its_definition_declares(self) -> None:
        chunks = self._chunks(chunk_boundary={"sandbox.target": r"@@ unit \d+ @@"})

        assert len(chunks) > 1
        assert {chunk.strategy for chunk in chunks} == {ChunkStrategy.DECLARED_BOUNDARY}

    def test_a_definition_with_none_is_cut_as_before(self) -> None:
        chunks = self._chunks()

        assert len(chunks) > 1
        assert {chunk.strategy for chunk in chunks} == {ChunkStrategy.SLIDING_WINDOW}


class TestThePatternRunsUnderRE2:
    def test_a_group_in_the_pattern_adds_no_text_to_a_chunk(self) -> None:
        text = "".join(f"sub_{n:03d} start\n" + "line of the body\n" * 6 for n in range(20))

        chunks = _chunker().chunk("custom", text, boundary=r"^(sub)_\d+")

        assert len(chunks) > 1
        assert all(chunk.content.startswith("sub_") for chunk in chunks)
        assert "".join(chunk.content for chunk in chunks).count("sub_") == 20

    def test_a_catastrophic_pattern_runs_in_linear_time(self) -> None:
        import time

        text = ("a" * 60 + "!\n") * 200
        began = time.monotonic()
        _chunker().chunk("custom", text, boundary=r"^(a+)+$")

        assert time.monotonic() - began < 5

    def test_a_lookaround_is_refused_when_the_definition_is_saved(self) -> None:
        with pytest.raises(ValidationError, match="linear time"):
            AgentDefinition.model_validate(
                {
                    "role": "generic",
                    "data_sources": ["sandbox.behavior"],
                    "chunk_boundary": {"sandbox.behavior": r"(?=^PID)"},
                }
            )
