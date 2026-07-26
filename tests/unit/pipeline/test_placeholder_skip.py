"""The "no data" path has to be reachable, and only for the analysts it fits.

``file_loader`` does not return nothing when a sample has no data for a layer.
It returns the sentence ``"No dynamic data available for sample <sha>."`` — a
truthy string that chunks into exactly one chunk, so the analyst node's
``if not chunks`` skip never fired. Two consequences, both live for months:

* The pipeline paid for a full MCP connection attempt and an LLM call to
  analyse that one sentence, on every run without a sandbox.
* The network analyst reported the sentence back as its sole "evidence-backed
  claim" — visible in the UI, in the transcript, and in the stored report.

``TestTheStaticAnalystIsNotDisabledByTheFix`` is the important one, and it is
here because writing this fix the obvious way breaks the pipeline's primary
analyst. Fixing it at the loader looks right and is wrong — static's real head
chunk is *synthesized* precisely because the loader returned that placeholder.
Fixing it in the node but applying it to every analyst is also wrong, more
subtly: when the sample cannot be mirrored for the Ghidra container, static is
*meant* to fall back to a metadata-only prompt, and the skip would delete it.
Both traps were found by these tests rather than in production.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from unittest.mock import MagicMock

from maljan.pipeline.nodes import _is_placeholder_only


@dataclass
class _Chunk:
    content: str
    index: int = 0
    total: int = 1

    def to_prompt_header(self) -> str:
        return f"[chunk {self.index + 1}/{self.total}]"


class TestThePlaceholderIsRecognised:
    def test_the_loader_sentence_matches(self) -> None:
        for layer in ("dynamic", "network", "static"):
            chunk = _Chunk(content=f"No {layer} data available for sample abc123.")
            assert _is_placeholder_only([chunk]) is True

    def test_leading_whitespace_does_not_hide_it(self) -> None:
        assert _is_placeholder_only([_Chunk(content="\n  No network data available for x.")])

    def test_real_analysis_data_never_matches(self) -> None:
        assert not _is_placeholder_only([_Chunk(content="PE32 executable, 3 sections, .text")])
        assert not _is_placeholder_only(
            [_Chunk(content="Registry: HKCU\\Run\\evil — no network data was captured later")]
        )

    def test_multiple_chunks_are_never_a_placeholder(self) -> None:
        """Real data that merely opens with the phrase must survive."""
        chunks = [
            _Chunk(content="No dynamic data available for sample abc.", index=0, total=2),
            _Chunk(content="...but here is a full behaviour trace.", index=1, total=2),
        ]
        assert _is_placeholder_only(chunks) is False

    def test_empty_input_is_not_a_placeholder(self) -> None:
        """``not chunks`` already covers this; the guard must not double-count."""
        assert _is_placeholder_only([]) is False


class TestTheStaticAnalystIsNotDisabledByTheFix:
    """The reason the guard lives in the node, and exempts static outright.

    Static reaches the analyst *through* this placeholder on every live run:
    production has no ``data/samples/static/<sha>.json``, so the loader returns
    the sentence and ``_augment_static_chunks_with_path`` replaces it with a
    synthesized head chunk carrying the sample path and PE summary.

    But that replacement only happens when ``static_sample_path`` is set, and it
    is ``None`` whenever mirroring the sample for the Ghidra container fails —
    at which point the static analyst is *supposed* to fall back to a
    metadata-only prompt. Skipping it would silently delete the primary analyst
    on exactly the runs that most need whatever it can still say. Hence the
    exemption, and hence this test.
    """

    def test_static_is_exempt_even_when_augmentation_did_not_fire(self) -> None:
        placeholder = [_Chunk(content="No static data available for sample abc123.")]
        assert _is_placeholder_only(placeholder, "static") is False
        # The same chunk, for any other analyst, is a skip.
        assert _is_placeholder_only(placeholder, "dynamic") is True
        assert _is_placeholder_only(placeholder, "network") is True

    def test_the_augmented_static_chunk_is_not_a_placeholder_either(self) -> None:
        from maljan.loaders.binary_chunker import TextChunk
        from maljan.pipeline.nodes import _augment_static_chunks_with_path

        head = TextChunk(
            index=0,
            total=1,
            strategy=None,  # type: ignore[arg-type]
            content="No static data available for sample abc123.",
            char_count=42,
            token_estimate=10,
            domain="static",
        )
        augmented = _augment_static_chunks_with_path(
            [head],
            {"file_hash": "abc123", "static_sample_path": "/samples/abc123.exe"},  # type: ignore[arg-type]
        )

        assert augmented, "augmentation must produce a chunk"
        assert "/samples/abc123.exe" in augmented[0].content
        assert _is_placeholder_only(augmented, "static") is False


class TestTheNodeSkipsInsteadOfAnalysing:
    def test_a_placeholder_only_analyst_emits_no_data_and_never_calls_the_llm(self) -> None:
        """End to end through the real node factory, with a mock container."""
        from maljan.pipeline.nodes import make_analyst_node

        agent = MagicMock()
        agent.safe_analyze_isr = MagicMock(
            side_effect=AssertionError("the LLM must not be called for a placeholder")
        )

        events: list[tuple[str, dict[str, Any]]] = []
        container = MagicMock()
        container.is_mock = False
        container.event_sink = lambda t, d: events.append((t, d))
        container.get_agent.return_value = agent
        container.load_chunked.return_value = [
            _Chunk(content="No network data available for sample abc123.")
        ]

        node = make_analyst_node("network", container)
        result = node({"file_hash": "abc123", "sample_path": "/s/abc123.exe"})

        agent.safe_analyze_isr.assert_not_called()
        assert "no network data available" in result["reports"]["network"].lower()
        statuses = [d.get("status") for t, d in events if t == "agent_message"]
        assert "no_data" in statuses
