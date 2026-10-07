"""An analyst whose answer ended at its output cap is asked once for a whole shorter one.

The reference run's static analyst answered in one step: 42 claims in exactly
the 4,096 tokens its cap allows, the last one cut. Its validation turn asked
fourteen questions over that answer, the retry spent the whole cap again and
returned no claim, and the first answer was kept with every question
unanswered. The judge and the composer were asked about a cut answer; an
analyst was not.

It is now, the way they are: the question states the cap, the characters the
answer ran to and the claims it began, and the length it was cut at as the
bound to stay under; the cut answer is not sent back; it is asked only when
the question and an answer of the cap's size fit the model's window; and a
whole answer that comes back is the analyst's, however many claims it has. The
cap is the one in force and nothing raises it.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.messages import AIMessage

from maljan.agents.base_agent import BaseAnalyst, answer_cut_at_cap
from maljan.pipeline.validation import ANALYST_CUT_CODE, analyst_cut_violation
from maljan.schemas.isr_models import AgentISR

CAP = 4096


def _block(n: int) -> str:
    return (
        f"CLAIM: The file carries configuration string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\n"
        "CONFIDENCE: 0.8\n"
        "TECHNIQUE: NONE\n"
        "---\n"
    )


FIRST = "".join(_block(n) for n in range(1, 4)) + "CLAIM: The file carries configur"
WHOLE = _block(1)


def _message(text: str, tokens: int) -> AIMessage:
    return AIMessage(
        content=text,
        usage_metadata={"input_tokens": 900, "output_tokens": tokens, "total_tokens": 900 + tokens},
    )


class _Analyst(BaseAnalyst):
    """Answers each retry from a queue, recording each answer as the real call does."""

    def __init__(self, replies: list[tuple[str, int]]) -> None:
        super().__init__(llm=MagicMock(), name="static")
        self.pack_ledger_ids = ["ev_0001"]
        self._replies = list(replies)
        self.seen_turns: list[list[Any]] = []

    def analyze(self, data: str) -> str:  # pragma: no cover - unused
        return ""

    def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover - unused
        return ""

    def _invoke_llm_with_timeout(self, messages: list, timeout: float, **_: Any) -> str:
        self.seen_turns.append(list(messages))
        text, tokens = self._replies.pop(0)
        self._record_usage(_message(text, tokens))
        return text


def _check(analyst: _Analyst, first: str = FIRST, *, fits: bool = True) -> AgentISR:
    """The loop's own answer, cut at the cap, through the validation turn."""
    isr = analyst._text_to_isr(first, 0)
    with (
        patch("maljan.agents.base_agent.analyst_output_cap", return_value=CAP),
        patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        patch.object(BaseAnalyst, "_fits_the_window", return_value=fits),
    ):
        analyst._record_usage(_message(first, CAP))
        return analyst._validate_isr(isr, "evidence")


class TestTheSignal:
    def test_an_answer_that_used_the_whole_cap_was_cut(self) -> None:
        assert answer_cut_at_cap(_message(FIRST, CAP), CAP) == (CAP, FIRST)

    def test_one_that_ended_short_of_it_was_not(self) -> None:
        assert answer_cut_at_cap(_message(WHOLE, 300), CAP) is None

    def test_the_question_states_the_cap_what_was_begun_and_the_bound(self) -> None:
        message = analyst_cut_violation(CAP, FIRST).message

        assert f"output limit of {CAP} tokens" in message
        assert "began 4 CLAIM block(s)" in message
        assert f"shorter than those {len(FIRST):,} characters" in message
        assert "not shown to you again" in message


class TestTheValidationTurn:
    def test_the_cut_answer_is_asked_for_and_not_sent_back(self) -> None:
        analyst = _Analyst([(WHOLE, 300)])

        _check(analyst)

        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert ANALYST_CUT_CODE in question
        assert f"output limit of {CAP} tokens" in question
        assert not any("configuration string number 3" in str(t.content) for t in turns)

    def test_a_whole_shorter_answer_is_the_analyst_s(self) -> None:
        analyst = _Analyst([(WHOLE, 300)])

        result = _check(analyst)

        assert [c.claim for c in result.claims] == [
            "The file carries configuration string number 1."
        ]
        assert ANALYST_CUT_CODE not in [v.code for v in analyst.validation_findings]

    def test_a_retry_cut_again_keeps_the_first_and_records_the_cut(self) -> None:
        analyst = _Analyst([(_block(9) + "CLAIM: cut", CAP)])

        result = _check(analyst)

        assert len(result.claims) >= 3
        assert ANALYST_CUT_CODE in [v.code for v in analyst.validation_findings]

    def test_a_question_that_does_not_fit_the_window_is_recorded_not_asked(self) -> None:
        analyst = _Analyst([(FIRST, 300)])

        _check(analyst, fits=False)

        # The cut last claim still carries its own question, asked over the
        # answer as every other question is; the cut question is not among them.
        assert all(ANALYST_CUT_CODE not in str(t[-1].content) for t in analyst.seen_turns)
        (finding,) = [v for v in analyst.validation_findings if v.code == ANALYST_CUT_CODE]
        assert finding.asked is False
        assert "do not fit this model's window" in finding.message

    def test_an_answer_that_was_not_cut_is_asked_nothing_about_its_length(self) -> None:
        analyst = _Analyst([])
        isr = analyst._text_to_isr(WHOLE, 0)
        with (
            patch("maljan.agents.base_agent.analyst_output_cap", return_value=CAP),
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
        ):
            analyst._record_usage(_message(WHOLE, 300))
            analyst._validate_isr(isr, "evidence")

        assert analyst.seen_turns == []
        assert analyst.validation_findings == []


class TestTheWindowIsMeasuredWithTheQuestions:
    def test_the_feedback_turn_is_part_of_what_must_fit(self) -> None:
        analyst = _Analyst([(WHOLE, 300)])
        measured: list[int] = []

        def _fits(_self: Any, messages: list[Any], _cap: int) -> bool:
            measured.append(len(messages))
            return True

        isr = analyst._text_to_isr(FIRST, 0)
        with (
            patch("maljan.agents.base_agent.analyst_output_cap", return_value=CAP),
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", _fits),
        ):
            analyst._record_usage(_message(FIRST, CAP))
            analyst._validate_isr(isr, "evidence")

        (turns,) = analyst.seen_turns
        # The conversation it measured is the one the retry sends, question included.
        assert measured == [len(turns)]


class TestATechniqueCardNeverCostsAQuestion:
    def test_a_turn_that_fits_without_its_cards_is_sent_without_them(self) -> None:
        # The first claim names a technique its sentence does not describe, so
        # the turn carries that question and, with it, the technique's card.
        first = FIRST.replace("TECHNIQUE: NONE", "TECHNIQUE: T1003", 1)
        analyst = _Analyst([(WHOLE, 300)])
        measured: list[bool] = []

        def _fits(_self: Any, messages: list[Any], _cap: int) -> bool:
            carded = "card:" in str(messages[-1].content)
            measured.append(carded)
            return not carded

        isr = analyst._text_to_isr(first, 0)
        with (
            patch("maljan.agents.base_agent.analyst_output_cap", return_value=CAP),
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", _fits),
        ):
            analyst._record_usage(_message(first, CAP))
            analyst._validate_isr(isr, "evidence")

        assert measured == [True, False]
        (turns,) = analyst.seen_turns
        question = str(turns[-1].content)
        assert ANALYST_CUT_CODE in question
        assert "attck.claim_does_not_describe" in question
        assert "card:" not in question
        assert ANALYST_CUT_CODE not in [v.code for v in analyst.validation_findings]


class TestTheWindow:
    def test_a_conversation_and_the_cap_that_fit_are_asked(self) -> None:
        analyst = _Analyst([])
        budget = SimpleNamespace(
            derives=True, chars_per_token=3, window=SimpleNamespace(tokens=32768)
        )
        with patch.object(BaseAnalyst, "_context_budget", return_value=budget):
            assert analyst._fits_the_window([SimpleNamespace(content="x" * 60_000)], CAP)
            assert not analyst._fits_the_window([SimpleNamespace(content="x" * 90_000)], CAP)

    def test_with_no_window_learned_the_question_is_asked(self) -> None:
        analyst = _Analyst([])
        with patch.object(BaseAnalyst, "_context_budget", return_value=None):
            assert analyst._fits_the_window([SimpleNamespace(content="x" * 10**7)], CAP)


BUILT = 32768


def _local_settings() -> Any:
    """Settings whose derivation, with no window learned, is the documented 8,192."""
    from maljan.core.config import LLMConfig, Settings

    settings = Settings(llm=LLMConfig(provider="openai"))
    settings.llm.openai.context_size = 0
    settings.llm.openai.expert_model = "local-model"
    settings.llm.openai.judge_model = "local-model"
    settings.llm.openai.base_url = "http://127.0.0.1:8080/v1"
    return settings


def _built_analyst(replies: list[tuple[str, int]]) -> _Analyst:
    """An analyst whose model carries the cap the container built it with."""
    from maljan.llm.context_window import OutputCap, record_built_cap

    analyst = _Analyst(replies)
    record_built_cap(analyst.llm, OutputCap(BUILT, "a quarter of 131072 (probed)"))
    return analyst


class TestTheCheckReadsTheCapTheCallWasBuiltWith:
    """Not patched, and with the window cache expired: derived again it would say 8,192."""

    def _expired(self) -> Any:
        from maljan.llm.context_window import DEFAULT_REPLY_TOKENS, forget_learned_windows

        forget_learned_windows()
        settings = _local_settings()
        from maljan.llm.context_window import output_cap_for

        assert output_cap_for(settings, "expert_max_tokens", "static").tokens == (
            DEFAULT_REPLY_TOKENS
        )
        return patch("maljan.agents.base_agent.get_settings", return_value=settings)

    def test_an_answer_under_the_built_cap_is_not_cut(self) -> None:
        analyst = _built_analyst([])
        with self._expired():
            analyst._record_usage(_message(FIRST, 8_600))

        assert analyst._last_answer_cut is None

    def test_an_answer_at_the_built_cap_is_cut_and_named_with_it(self) -> None:
        analyst = _built_analyst([(WHOLE, 300)])
        isr = analyst._text_to_isr(FIRST, 0)
        with (
            self._expired(),
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
        ):
            analyst._record_usage(_message(FIRST, BUILT))
            analyst._validate_isr(isr, "evidence")

        (turns,) = analyst.seen_turns
        assert f"output limit of {BUILT} tokens" in str(turns[-1].content)

    def test_the_spend_meter_is_given_the_built_cap(self) -> None:
        analyst = _built_analyst([])
        meter = MagicMock()
        meter.admit.return_value = None
        with self._expired(), patch.object(BaseAnalyst, "_spend_meter", return_value=meter):
            analyst._spend_admits("loop turn", [])

        assert meter.admit.call_args.kwargs["cap_tokens"] == BUILT

    def test_the_judge_reads_the_cap_its_model_was_built_with(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent
        from maljan.llm.context_window import OutputCap, record_built_cap

        judge = JudgeAgent(llm=MagicMock())
        record_built_cap(judge.llm, OutputCap(BUILT, "built"))
        with self._expired():
            assert judge._output_cap().tokens == BUILT


class TestACutInAChunkIsNamed:
    def test_the_question_names_the_chunk_whose_answer_was_cut(self) -> None:
        analyst = _Analyst([])
        isr = analyst._text_to_isr(WHOLE, 0)
        with (
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=False),
        ):
            analyst._last_answer_cut = (CAP, FIRST)
            analyst._validate_isr(isr, "evidence", chunk="chunk 1 of 2", only_cut=True)

        (finding,) = [v for v in analyst.validation_findings if v.code == ANALYST_CUT_CODE]
        assert finding.message.startswith("Your answer to chunk 1 of 2 stopped")
        assert f"output limit of {CAP} tokens" in finding.message


def _claims(prefix: str, count: int) -> str:
    return "".join(
        f"CLAIM: The file carries {prefix} string number {n}.\n"
        "EVIDENCE: [ev_0001] strings\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"
        for n in range(1, count + 1)
    )


class _Chunked(_Analyst):
    """Two chunks: the first answer is cut at the cap, the second is short and whole."""

    def __init__(self, replies: list[tuple[str, int]], answers: list[tuple[str, int]]) -> None:
        super().__init__(replies)
        self._answers = list(answers)

    def analyze_isr(self, data: str) -> AgentISR:
        text, tokens = self._answers.pop(0)
        self._record_usage(_message(text, tokens))
        return self._text_to_isr(text, 0)


class TestACutChunkIsAnsweredInsideItsChunk:
    """A cut in chunk 1 replaces chunk 1's contribution alone, never the merged answer."""

    CUT = _claims("first-chunk", 3) + "CLAIM: The file carries first-chunk str"
    SECOND = _claims("second-chunk", 6)

    def _run(self, retry: tuple[str, int]) -> tuple[_Chunked, AgentISR]:
        from maljan.loaders.binary_chunker import ChunkStrategy, TextChunk

        analyst = _Chunked([retry], [(self.CUT, CAP), (self.SECOND, 900)])
        chunks = [
            TextChunk(
                index=i,
                total=2,
                strategy=ChunkStrategy.SLIDING_WINDOW,
                content=f"part {i}",
                char_count=6,
                token_estimate=2,
                domain="static",
            )
            for i in range(2)
        ]
        with (
            patch("maljan.agents.base_agent.analyst_output_cap", return_value=CAP),
            patch("maljan.agents.base_agent.validity_check_available", return_value=True),
            patch.object(BaseAnalyst, "_fits_the_window", return_value=True),
            patch("maljan.tools.knowledge.resolve_technique", return_value={"candidates": []}),
        ):
            return analyst, analyst.safe_analyze_isr_chunked(chunks)

    def test_the_second_chunk_s_claims_all_survive(self) -> None:
        analyst, merged = self._run((_claims("rewritten", 1), 300))

        texts = [c.claim for c in merged.claims]
        for n in range(1, 7):
            assert f"The file carries second-chunk string number {n}." in texts
        assert "The file carries rewritten string number 1." in texts
        assert not any("first-chunk" in t for t in texts)
        # The question went to chunk 1's own input, named by its chunk.
        (turns,) = analyst.seen_turns
        assert "Your answer to chunk 1 of 2 stopped" in str(turns[-1].content)
        assert any("part 0" in str(t.content) for t in turns)
        assert not any("part 1" in str(t.content) for t in turns)

    def test_a_chunk_still_cut_is_kept_and_recorded_unread_for_that_chunk(self) -> None:
        analyst, merged = self._run((_claims("again", 2) + "CLAIM: cut", CAP))

        texts = [c.claim for c in merged.claims]
        assert sum("second-chunk" in t for t in texts) == 6
        assert sum("first-chunk" in t for t in texts) >= 3
        (finding,) = [v for v in analyst.validation_findings if v.code == ANALYST_CUT_CODE]
        assert "chunk 1 of 2" in finding.message
        assert "is unread" in finding.message
