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


# Said at the head of a text the summariser's window could not hold whole.
SHORTENED_NOTE = (
    "NOTE: only the first {shown:,} of {total:,} characters fit this model's window; "
    "the text below ends in … where it was cut."
)
SHORTENED_NOTE_ROOM = 200


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
        room_chars: Any = None,
        truncation_ledger: Any = None,
    ) -> None:
        self._llm = llm
        self._max_words = max_summary_words
        # What one summariser prompt may carry, in characters, asked per call:
        # a callable returning the window's room, or ``None`` for no bound. A
        # fixed 8,000 and 12,000 used to stand here.
        self._room_chars = room_chars
        # Where a shortened prompt is recorded, for the run's degradation reasons.
        self._truncation_ledger = truncation_ledger
        # Each summary is a model call the run pays for, recorded under
        # ``summarizer`` and the model the summariser calls.
        self._token_ledger = token_ledger
        self._model_label = model_label

    def _record(self, response: Any) -> None:
        from maljan.core.token_ledger import record_response_usage

        record_response_usage(
            self._token_ledger,
            response,
            agent="summarizer",
            model=self._model_label,
            call="function summary",
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
            code_chunk=self._fitted(code_chunk, _SUMMARIZE_SYSTEM + _SUMMARIZE_HUMAN_TMPL),
        )

        messages = [
            SystemMessage(content=_SUMMARIZE_SYSTEM),
            HumanMessage(content=prompt),
        ]

        try:
            response = self._ask(messages)
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
            # Graceful degradation: on error return the raw chunk, whole; the
            # analyst's input it becomes is sized from the analyst's window.
            return code_chunk

    def _fitted(self, text: str, framing: str) -> str:
        """``text`` whole when the window's room holds it beside ``framing``, else shortened, said.

        The room is asked of ``room_chars`` per call; with none, or no window
        learned, the text goes whole. A shortened text ends in the cut mark
        and begins with a line saying how much of it is shown.
        """
        from maljan.utils.marked_cut import marked_cut

        try:
            room = self._room_chars() if callable(self._room_chars) else None
        except Exception:  # noqa: BLE001 — a room that cannot be read bounds nothing
            room = None
        if not isinstance(room, int) or room <= 0:
            return text
        width = room - len(framing) - SHORTENED_NOTE_ROOM
        if len(text) <= width:
            return text
        shown = marked_cut(text, max(1, width))
        logger.warning(
            "FunctionSummarizer: %d of %d characters fit the window; the rest is left out.",
            len(shown),
            len(text),
        )
        record = getattr(self._truncation_ledger, "record_input_shortened", None)
        if callable(record):
            try:
                record(
                    "The function summariser's prompt was shortened: the first "
                    f"{len(shown):,} of {len(text):,} characters fit its model's window."
                )
            except Exception as exc:  # noqa: BLE001 — a record never costs a summary
                logger.debug("FunctionSummarizer: the shortening was not recorded (%s).", exc)
        return f"{SHORTENED_NOTE.format(shown=len(shown), total=len(text))}\n{shown}"

    def _ask(self, messages: list[Any]) -> Any:
        """One summariser call, on the agent loop so a cancelled job cancels it in flight.

        Held to what the call's own request is given: the provider's request
        timeout, or, where the model's pace is measured and its output cap
        takes longer at that pace, that time
        (``generation_rate.sized_request_timeout``), so the wait never ends
        before the request would. A model that has only a synchronous
        ``invoke`` is called as before.

        Admitted by the job's spend ceiling first, like every model call: sent
        with its cap held to what the spend pays for, reserved while it runs,
        and recorded on the token ledger before the reservation goes. A call
        the ceiling refuses raises :class:`SpendCeilingStop`, and the caller
        keeps the raw text.
        """
        import inspect

        from maljan.agents.base_agent import run_coro_blocking
        from maljan.core.spend import admitted
        from maljan.llm.context_window import output_bound_kwargs
        from maljan.llm.generation_rate import sized_request_timeout
        from maljan.llm.registry import PROVIDER_REQUEST_TIMEOUT_SECONDS

        cap = 0
        for attr in ("max_tokens", "num_predict", "max_output_tokens"):
            value = getattr(self._llm, attr, None)
            if isinstance(value, int) and not isinstance(value, bool) and value > 0:
                cap = value
                break
        chars = sum(len(str(getattr(message, "content", message))) for message in messages)
        seconds = sized_request_timeout(self._llm, cap, chars)
        with admitted(
            self._token_ledger,
            kind="summary",
            llm=self._llm,
            model=self._model_label,
            prompt_chars=chars,
            cap_tokens=cap,
        ) as bound:
            held = output_bound_kwargs(self._llm, bound) if bound is not None else {}
            if not inspect.iscoroutinefunction(getattr(type(self._llm), "ainvoke", None)):
                response = self._llm.invoke(messages, **held)
            else:
                response = run_coro_blocking(
                    self._llm.ainvoke(messages, **held),
                    float(seconds if seconds is not None else PROVIDER_REQUEST_TIMEOUT_SECONDS),
                    label="function-summarizer",
                )
            self._record(response)
            return response

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
            summaries=self._fitted(combined, _MERGE_SYSTEM + _MERGE_HUMAN_TMPL),
        )

        messages = [
            SystemMessage(content=_MERGE_SYSTEM),
            HumanMessage(content=prompt),
        ]

        try:
            response = self._ask(messages)
            result: str = response.content  # type: ignore[assignment,union-attr]
            return result.strip()
        except Exception as exc:
            logger.warning(
                "FunctionSummarizer._merge_summaries failed: %s — returning concatenated.", exc
            )
            return combined
