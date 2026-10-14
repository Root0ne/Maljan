"""A revision whose agent cannot be built chunks at the size its first analysis measured.

The revision paths ask for the agent's room by its name; an agent that cannot
be built has none to give. The chunk size its first analysis sized from the
window is kept by the container and used in place of the unknown-window size.
A room the revision does measure wins. With no first size the shipped size
splits, and the run says so.

Every value is synthetic.
"""

from __future__ import annotations

from maljan.pipeline.nodes import _build_revision_context
from tests.unit._chunking_doubles import _container, _room, _rows


class TestARevisionChunksAtTheFirstAnalysisSize:
    def test_an_agent_that_cannot_be_built_revises_at_the_first_size(self) -> None:
        container = _container(role="triage", sample="r" * 250_000, buildable=False)
        container.load_data_for_agent("triage", file_hash="abc", room=_room(100_000))

        state = {"file_hash": "abc", "reports": {"triage": "the first answer"}}
        context = _build_revision_context(state, container, "triage")

        again = container.load_chunked("abc", "triage", room=_room(None))
        assert [c.char_count for c in again] == [100_000, 100_000, 50_000]
        assert "chunks=3" in context
        assert _rows(container) == []

    def test_a_room_the_revision_measures_wins(self) -> None:
        container = _container(role="triage", sample="r" * 250_000)
        container.load_data_for_agent("triage", file_hash="abc", room=_room(100_000))
        again = container.load_chunked("abc", "triage", room=_room(200_000))
        assert [c.char_count for c in again] == [200_000, 50_000]

    def test_with_no_first_size_the_shipped_size_splits_and_is_stated(self) -> None:
        container = _container(role="triage", sample="r" * 200_000, buildable=False)
        state = {"file_hash": "abc", "reports": {"triage": "the first answer"}}
        _build_revision_context(state, container, "triage")
        assert [row["chunks"] for row in _rows(container)] == [3]
