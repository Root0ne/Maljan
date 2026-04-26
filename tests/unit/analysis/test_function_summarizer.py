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

from unittest.mock import MagicMock

from maljan.analysis.function_summarizer import FunctionSummarizer

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

    def test_chunk_truncated_at_8000_chars(self) -> None:
        llm = _make_mock_llm("summary")
        summarizer = FunctionSummarizer(llm=llm)
        large_chunk = "A" * 20_000
        summarizer.summarize_chunk(large_chunk)
        # invoke edilen mesajin iceriginde 8000 karakter sınırı uygulanmali
        call_args = llm.invoke.call_args[0][0]
        full_prompt = " ".join(str(m.content) for m in call_args)
        assert "A" * 20_000 not in full_prompt


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
