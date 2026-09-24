"""FunctionSummarizer — two-stage token-cost optimisation.

Problem:
    Large binary analysis reports (decompile output, 1000+ functions)
    sent directly to the expert LLM:
      - Blow past the context window (gpt-4o: 128k tokens = ~$0.60/run)
      - Degrade model performance (needle-in-a-haystack effect)

Solution — two-stage pipeline:
    Stage 1 (Summarize): A small / cheap LLM (e.g. llama3.2:3b,
                         gpt-4o-mini) condenses each chunk down to
                         MAX_SUMMARY_WORDS words.
    Stage 2 (Analyze):   The expert LLM only ever sees the summary text.

Token-cost comparison (illustrative):
    Direct send : ~20,000 tokens / analysis (@gpt-4o: ~$0.15)
    Two-stage   : ~3,000 tokens / analysis (@gpt-4o: ~$0.02)
    Savings     : ~85% reduction

Class design:
    - Self-contained: only a LangChain ``BaseChatModel`` is required.
    - Accessed via ServiceContainer.get_function_summarizer().
    - Activated with Settings.preprocessing.use_function_summarizer=True.
    - When it returns None the pipeline transparently skips this stage.

Usage:
    summarizer = container.get_function_summarizer()
    if summarizer is not None:
        condensed = summarizer.summarize_chunks(function_chunks)
    else:
        condensed = "\n".join(function_chunks)
    # ``condensed`` can now be handed to the expert LLM.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from maljan.core.logger import logger

if TYPE_CHECKING:
    from langchain_core.language_models.chat_models import BaseChatModel

# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_SUMMARIZE_SYSTEM = (
    "You are a malware analysis assistant. "
    "Your task is to summarize a decompiled code fragment or function list "
    "in plain English, focusing ONLY on security-relevant behaviors. "
    "Be concise. Never hallucinate."
)

_SUMMARIZE_HUMAN_TMPL = (
    "Summarize the following decompiled code fragment in at most {max_words} words. "
    "Focus on: API calls, suspicious operations, network activity, persistence, "
    "process manipulation, encryption, and evasion techniques. "
    "Omit boilerplate code, standard library internals, and benign operations.\n\n"
    "--- BEGIN CODE ---\n"
    "{code_chunk}\n"
    "--- END CODE ---\n\n"
    "Summary:"
)

_MERGE_SYSTEM = (
    "You are a malware analysis assistant. "
    "Merge the following chunk summaries into a single coherent analysis summary."
)

_MERGE_HUMAN_TMPL = (
    "Merge these chunk summaries into one coherent analysis summary "
    "in at most {max_words} words:\n\n"
    "{summaries}\n\n"
    "Merged summary:"
)


# ---------------------------------------------------------------------------
# FunctionSummarizer
# ---------------------------------------------------------------------------


class FunctionSummarizer:
    """Two-stage LLM-based token-cost optimisation.

    Args:
        llm:              Summarizer LLM (a small / cheap model is recommended).
        max_summary_words: Maximum word count per chunk summary.
    """

    def __init__(
        self,
        llm: BaseChatModel,
        max_summary_words: int = 150,
        token_ledger: Any | None = None,
        model_label: str = "",
    ) -> None:
        self._llm = llm
        self._max_words = max_summary_words
        # Each summary is a model call the run pays for, recorded under
        # ``summarizer`` and the model the summariser calls.
        self._token_ledger = token_ledger
        self._model_label = model_label

    def _record(self, response: Any) -> None:
        from maljan.core.token_ledger import record_response_usage

        record_response_usage(
            self._token_ledger, response, agent="summarizer", model=self._model_label
        )

    def summarize_chunk(self, code_chunk: str) -> str:
        """Summarise a single block of code or list of functions.

        Args:
            code_chunk: A decompiled-code excerpt, a function list, or a
                        slice of an analysis report.

        Returns:
            Condensed text covering only the security-relevant behaviours.
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        prompt = _SUMMARIZE_HUMAN_TMPL.format(
            max_words=self._max_words,
            code_chunk=code_chunk[:8000],  # Hard limit — token budget.
        )

        messages = [
            SystemMessage(content=_SUMMARIZE_SYSTEM),
            HumanMessage(content=prompt),
        ]

        try:
            response = self._ask(messages)
            self._record(response)
            summary: str = response.content  # type: ignore[assignment,union-attr]
            word_count = len(summary.split())
            logger.debug(
                "FunctionSummarizer: chunk summarized — %d chars -> %d words.",
                len(code_chunk),
                word_count,
            )
            return summary.strip()
        except Exception as exc:
            logger.warning(
                "FunctionSummarizer.summarize_chunk failed: %s — returning raw chunk.", exc
            )
            # Graceful degradation: on error return the raw chunk.
            return code_chunk[: self._max_words * 6]  # Approximate char limit.

    def _ask(self, messages: list[Any]) -> Any:
        """One summariser call, on the agent loop so a cancelled job cancels it in flight.

        Held to what the call's own request is given: the provider's request
        timeout, or, where the model's pace is measured and its output cap
        takes longer at that pace, that time
        (``generation_rate.sized_request_timeout``), so the wait never ends
        before the request would. A model that has only a synchronous
        ``invoke`` is called as before.
        """
        import inspect

        from maljan.agents.base_agent import run_coro_blocking
        from maljan.llm.generation_rate import sized_request_timeout
        from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

        if not inspect.iscoroutinefunction(getattr(type(self._llm), "ainvoke", None)):
            return self._llm.invoke(messages)
        cap = 0
        for attr in ("max_tokens", "num_predict", "max_output_tokens"):
            value = getattr(self._llm, attr, None)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                cap = value
                break
        chars = sum(len(str(getattr(message, "content", message))) for message in messages)
        seconds = sized_request_timeout(self._llm, cap, chars)
        return run_coro_blocking(
            self._llm.ainvoke(messages),
            float(seconds if seconds is not None else PROVIDER_REQUEST_TIMEOUT_SECONDS),
            label="function-summarizer",
        )

    def summarize_chunks(self, chunks: list[str]) -> str:
        """Summarise multiple chunks and merge the results.

        Each chunk is summarised individually; the per-chunk summaries can
        then be folded into a single merged summary (merge is optional).

        Args:
            chunks: List of code / report blocks to summarise.

        Returns:
            Merged summary of all chunks (single text).
        """
        if not chunks:
            return ""

        if len(chunks) == 1:
            return self.summarize_chunk(chunks[0])

        summaries: list[str] = []
        for i, chunk in enumerate(chunks, start=1):
            logger.info(
                "FunctionSummarizer: summarizing chunk %d/%d (%d chars).",
                i,
                len(chunks),
                len(chunk),
            )
            summary = self.summarize_chunk(chunk)
            summaries.append(f"[Chunk {i}] {summary}")

        # No need to merge if there are only a handful of summaries.
        if len(summaries) <= 3:
            merged = "\n\n".join(summaries)
        else:
            merged = self._merge_summaries(summaries)

        logger.info(
            "FunctionSummarizer: %d chunks -> merged summary (%d chars).",
            len(chunks),
            len(merged),
        )
        return merged

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _merge_summaries(self, summaries: list[str]) -> str:
        """Merge many chunk summaries into a single combined summary.

        Args:
            summaries: List of per-chunk summary strings.

        Returns:
            Combined summary text.
        """
        from langchain_core.messages import HumanMessage, SystemMessage

        combined = "\n\n".join(summaries)
        prompt = _MERGE_HUMAN_TMPL.format(
            max_words=self._max_words * 2,
            summaries=combined[:12000],  # Token budget guard.
        )

        messages = [
            SystemMessage(content=_MERGE_SYSTEM),
            HumanMessage(content=prompt),
        ]

        try:
            response = self._ask(messages)
            self._record(response)
            result: str = response.content  # type: ignore[assignment,union-attr]
            return result.strip()
        except Exception as exc:
            logger.warning(
                "FunctionSummarizer._merge_summaries failed: %s — returning concatenated.", exc
            )
            return combined
