"""tests/unit/analysis/test_function_summarizer.py — FunctionSummarizer birim testleri.

Mock LLM kullanilir — real LLM cagrisi yapilmaz.

Kapsam (8 test):
  - summarize_chunk() normal davranis
  - summarize_chunk() LLM hatasi -> graceful degradation
  - summarize_chunks() tek chunk
  - summarize_chunks() cok chunk -> merge
  - summarize_chunks() bos liste
  - _merge_summaries() LLM hatasi -> concat fallback
  - FunctionSummarizer init
  - Maksimum kelime limiti uyumu (satirsal dogrulama)
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.analysis.function_summarizer import SUMMARY_CUT_NOTE, FunctionSummarizer

# ---------------------------------------------------------------------------
# Mock LLM factory
# ---------------------------------------------------------------------------


def _make_mock_llm(response_text: str = "This function performs process injection.") -> MagicMock:
    """BaseChatModel mock'u olusturur."""
    mock_response = MagicMock()
    mock_response.content = response_text

    mock_llm = MagicMock()
    mock_llm.invoke.return_value = mock_response
    return mock_llm


def _make_failing_llm() -> MagicMock:
    """Her invoke() cagrisinda RuntimeError atan mock LLM."""
    mock_llm = MagicMock()
    mock_llm.invoke.side_effect = RuntimeError("LLM connection failed")
    return mock_llm


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


class TestFunctionSummarizerInit:
    def test_init_stores_llm(self) -> None:
        llm = _make_mock_llm()
        summarizer = FunctionSummarizer(llm=llm, max_summary_words=100)
        assert summarizer._llm is llm

    def test_init_stores_max_words(self) -> None:
        llm = _make_mock_llm()
        summarizer = FunctionSummarizer(llm=llm, max_summary_words=200)
        assert summarizer._max_words == 200


class TestSummarizeChunk:
    def test_returns_string(self) -> None:
        llm = _make_mock_llm("Summary text.")
        summarizer = FunctionSummarizer(llm=llm)
        result = summarizer.summarize_chunk("int main() { ... }")
        assert isinstance(result, str)

    def test_llm_invoked_once(self) -> None:
        llm = _make_mock_llm()
        summarizer = FunctionSummarizer(llm=llm)
        summarizer.summarize_chunk("some decompiled code")
        assert llm.invoke.call_count == 1

    def test_graceful_degradation_on_llm_error(self) -> None:
        llm = _make_failing_llm()
        summarizer = FunctionSummarizer(llm=llm, max_summary_words=50)
        code_chunk = "VirtualAllocEx(hProcess, ...)"
        result = summarizer.summarize_chunk(code_chunk)
        # Hata durumunda exception atilmamali, bir string donmeli
        assert isinstance(result, str)
        assert len(result) > 0

    def test_a_chunk_the_window_holds_is_sent_whole(self) -> None:
        llm = _make_mock_llm("summary")
        summarizer = FunctionSummarizer(llm=llm, room_chars=lambda: 1_000_000)
        summarizer.summarize_chunk("A" * 20_000)
        call_args = llm.invoke.call_args[0][0]
        full_prompt = " ".join(str(m.content) for m in call_args)
        assert "A" * 20_000 in full_prompt

    def test_a_chunk_past_the_window_is_shortened_and_says_so(self) -> None:
        llm = _make_mock_llm("summary")
        summarizer = FunctionSummarizer(llm=llm, room_chars=lambda: 8_000)
        summarizer.summarize_chunk("A" * 20_000)
        call_args = llm.invoke.call_args[0][0]
        full_prompt = " ".join(str(m.content) for m in call_args)
        assert "A" * 20_000 not in full_prompt
        assert "NOTE: only the first" in full_prompt and "…" in full_prompt

    def test_with_no_window_the_chunk_is_whole(self) -> None:
        llm = _make_mock_llm("summary")
        FunctionSummarizer(llm=llm).summarize_chunk("A" * 20_000)
        full_prompt = " ".join(str(m.content) for m in llm.invoke.call_args[0][0])
        assert "A" * 20_000 in full_prompt


class TestSummarizeChunks:
    def test_empty_list_returns_empty_string(self) -> None:
        llm = _make_mock_llm()
        summarizer = FunctionSummarizer(llm=llm)
        result = summarizer.summarize_chunks([])
        assert result == ""

    def test_single_chunk_calls_summarize_chunk_once(self) -> None:
        llm = _make_mock_llm("Single summary.")
        summarizer = FunctionSummarizer(llm=llm)
        result = summarizer.summarize_chunks(["chunk1"])
        assert isinstance(result, str)
        assert llm.invoke.call_count == 1

    def test_multiple_chunks_all_summarized(self) -> None:
        call_count = 0

        def side_effect(messages):
            nonlocal call_count
            call_count += 1
            m = MagicMock()
            m.content = f"Summary {call_count}"
            return m

        llm = MagicMock()
        llm.invoke.side_effect = side_effect

        summarizer = FunctionSummarizer(llm=llm, max_summary_words=50)
        chunks = ["chunk1", "chunk2", "chunk3"]
        result = summarizer.summarize_chunks(chunks)

        assert isinstance(result, str)
        # 3 chunk icin 3 summarize_chunk cagrisi yapilmali
        assert llm.invoke.call_count == 3

    def test_merge_fallback_on_llm_error(self) -> None:
        call_count = 0

        def side_effect(messages):
            nonlocal call_count
            call_count += 1
            # Ilk 2 cagri basarili (summarize), 3. hata atar (merge)
            if call_count <= 2:
                m = MagicMock()
                m.content = f"summary {call_count}"
                return m
            raise RuntimeError("merge LLM failed")

        llm = MagicMock()
        llm.invoke.side_effect = side_effect

        summarizer = FunctionSummarizer(llm=llm, max_summary_words=50)
        result = summarizer.summarize_chunks(["c1", "c2"])
        # Merge hatasinda concat fallback devreye girmeli
        assert isinstance(result, str)
        assert len(result) > 0


class _Capped:
    """A summariser model built with ``max_tokens``, answering each call from a queue."""

    def __init__(self, replies: list[Any], max_tokens: int | None = None) -> None:
        self.max_tokens = max_tokens
        self.replies = list(replies)
        self.calls: list[dict[str, Any]] = []

    def invoke(self, messages: Any, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        return self.replies.pop(0)


def _answer(text: str, tokens: int, finish: str = "stop") -> AIMessage:
    return AIMessage(
        content=text,
        usage_metadata={"input_tokens": 50, "output_tokens": tokens, "total_tokens": 50 + tokens},
        response_metadata={"finish_reason": finish},
    )


class TestACutSummaryIsMarkedCut:
    """A summary that ended at its output limit reads as whole unless it is said:
    it becomes an analyst's input, and the analyst takes it as the chunk's
    account. The same rule as an analyst's answer (``answer_cut_at_cap``):
    the server's ``length``, or a count that reached the cap in force, which
    is the call's held cap where it was held and the model's own otherwise."""

    def test_a_summary_at_the_built_cap_is_marked_and_recorded(self) -> None:
        ledger = MagicMock()
        llm = _Capped([_answer("It injects into expl", 100)], max_tokens=100)
        summarizer = FunctionSummarizer(llm=llm, truncation_ledger=ledger)  # type: ignore[arg-type]

        result = summarizer.summarize_chunk("code")

        assert result.startswith(SUMMARY_CUT_NOTE.format(cap=100))
        assert result.endswith("It injects into expl")
        (sentence,) = [c.args[0] for c in ledger.record_input_shortened.call_args_list]
        assert "100-token output limit" in sentence

    def test_summaries_cut_at_one_limit_are_counted_in_one_sentence(self) -> None:
        from maljan.core.truncation_ledger import TruncationLedger

        ledger = TruncationLedger()
        ledger.record_input_shortened("Another input was shortened.")
        llm = _Capped(
            [_answer("cut one", 100), _answer("whole", 10), _answer("cut two", 100)],
            max_tokens=100,
        )
        summarizer = FunctionSummarizer(llm=llm, truncation_ledger=ledger)  # type: ignore[arg-type]

        summarizer.summarize_chunk("a")
        assert ledger.input_shortened[1:] == [
            "A function summary ended at its 100-token output limit; the analyst was told "
            "its end is missing."
        ]
        summarizer.summarize_chunk("b")
        summarizer.summarize_chunk("c")

        assert ledger.input_shortened == [
            "Another input was shortened.",
            "2 function summaries ended at their 100-token output limit; the analyst was "
            "told each one's end is missing.",
        ]

    def test_summaries_cut_at_different_limits_are_counted_apart(self) -> None:
        from contextlib import contextmanager

        from maljan.core.truncation_ledger import TruncationLedger

        holds = iter([40, None, None])

        @contextmanager
        def _held(*_args: Any, **_kwargs: Any) -> Any:
            yield next(holds)

        ledger = TruncationLedger()
        llm = _Capped(
            [_answer("cut", 40), _answer("cut", 100), _answer("cut", 100)], max_tokens=100
        )
        summarizer = FunctionSummarizer(llm=llm, truncation_ledger=ledger)  # type: ignore[arg-type]
        with patch("maljan.core.spend.admitted", _held):
            for chunk in ("a", "b", "c"):
                summarizer.summarize_chunk(chunk)

        assert ledger.input_shortened == [
            "A function summary ended at its 40-token output limit; the analyst was told "
            "its end is missing.",
            "2 function summaries ended at their 100-token output limit; the analyst was "
            "told each one's end is missing.",
        ]

    def test_a_server_that_says_length_is_believed(self) -> None:
        llm = _Capped([_answer("It injects", 12, finish="length")])
        result = FunctionSummarizer(llm=llm).summarize_chunk("code")  # type: ignore[arg-type]
        assert result.startswith("NOTE: this summary ended at its")

    def test_a_summary_short_of_the_cap_is_whole(self) -> None:
        ledger = MagicMock()
        llm = _Capped([_answer("It injects into explorer.", 60)], max_tokens=100)
        summarizer = FunctionSummarizer(llm=llm, truncation_ledger=ledger)  # type: ignore[arg-type]

        assert summarizer.summarize_chunk("code") == "It injects into explorer."
        ledger.record_input_shortened.assert_not_called()

    def test_a_held_call_is_checked_against_its_held_cap(self) -> None:
        from contextlib import contextmanager

        @contextmanager
        def _held(*_args: Any, **_kwargs: Any) -> Any:
            yield 40

        llm = _Capped([_answer("It injects", 40), _answer("It reads.", 30)])
        summarizer = FunctionSummarizer(llm=llm)  # type: ignore[arg-type]
        with patch("maljan.core.spend.admitted", _held):
            cut = summarizer.summarize_chunk("code")
            whole = summarizer.summarize_chunk("code")

        assert llm.calls[0] == {"max_tokens": 40}
        assert cut.startswith(SUMMARY_CUT_NOTE.format(cap=40))
        assert whole == "It reads."

    def test_a_cut_merge_is_marked_too(self) -> None:
        replies = [_answer(f"summary {n}", 5) for n in range(1, 5)]
        replies.append(_answer("merged and cu", 100))
        llm = _Capped(replies, max_tokens=100)

        result = FunctionSummarizer(llm=llm).summarize_chunks(["a", "b", "c", "d"])  # type: ignore[arg-type]

        assert result.startswith(SUMMARY_CUT_NOTE.format(cap=100))
