"""A call's timeout follows the model's measured generation rate.

A 27B model on Ollama generated about 3.8 tokens a second. The judge's call
waited 600 s against ``judge_max_tokens`` 8,192, so only about 2,280 tokens
could ever arrive in time, and a composer section waited 120 s against 900
tokens that need about 237 s at that pace. Both passed on that run only because
the answers were short. The rate is read from what the providers already
return on every call, kept per model for the job, and each timeout becomes the
larger of the configured value and ``max_tokens / rate × margin``, never above
the stated ceiling.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import AIMessage, HumanMessage

from maljan.llm.generation_rate import (
    TIMEOUT_CEILING_SECONDS,
    TIMEOUT_MARGIN,
    GenerationRates,
    attach_rate_meter,
    measured_generation,
)

SLOW = "qwen3.8:27b"


def _ollama_answer(tokens: int, seconds: float) -> AIMessage:
    # Ollama reports ``eval_duration`` in nanoseconds.
    return AIMessage(
        content="x",
        response_metadata={"eval_count": tokens, "eval_duration": int(seconds * 1e9)},
    )


class TestTheRateIsReadFromWhatTheProviderReturned:
    def test_ollama_s_eval_count_and_duration(self) -> None:
        tokens, seconds, source = measured_generation(_ollama_answer(380, 100.0), 130.0)

        assert (tokens, seconds) == (380, pytest.approx(100.0))
        assert "eval_count" in source

    def test_llama_cpp_s_timings(self) -> None:
        message = AIMessage(
            content="x", response_metadata={"timings": {"predicted_n": 76, "predicted_ms": 20000}}
        )

        tokens, seconds, source = measured_generation(message, 25.0)

        assert (tokens, seconds) == (76, pytest.approx(20.0))
        assert "timings" in source

    def test_otherwise_output_tokens_over_the_call_s_wall_clock(self) -> None:
        message = AIMessage(
            content="x",
            usage_metadata={"input_tokens": 900, "output_tokens": 50, "total_tokens": 950},
        )

        tokens, seconds, source = measured_generation(message, 25.0)

        assert (tokens, seconds) == (50, pytest.approx(25.0))
        assert "wall clock" in source

    def test_nothing_measurable_is_nothing(self) -> None:
        assert measured_generation(AIMessage(content="x"), 0.0) is None
        assert measured_generation(AIMessage(content="x"), 12.0) is None


class TestTheTimeoutFollowsTheRate:
    def test_with_no_rate_yet_the_configured_value_stands(self) -> None:
        rates = GenerationRates()

        assert rates.call_timeout("judge:verdict", SLOW, 600.0, 8192) == 600.0
        row = rates.snapshot()["timeouts"]["judge:verdict"]
        assert row["applied_s"] == 600.0 and row["tokens_per_second"] is None

    def test_the_judge_waits_for_its_whole_budget_at_the_measured_pace(self) -> None:
        rates = GenerationRates()
        rates.observe(SLOW, 380, 100.0, "ollama eval_count/eval_duration")

        applied = rates.call_timeout("judge:verdict", SLOW, 600.0, 8192)

        # 8,192 / 3.8 × 1.5 is about 3,234 s; the ceiling holds it at 1,800 s,
        # three times the configured wait.
        assert 8192 / 3.8 * TIMEOUT_MARGIN > TIMEOUT_CEILING_SECONDS
        assert applied == TIMEOUT_CEILING_SECONDS

    def test_a_composer_section_gets_the_time_its_tokens_need(self) -> None:
        rates = GenerationRates()
        rates.observe(SLOW, 380, 100.0, "ollama eval_count/eval_duration")

        assert rates.call_timeout("composer:section", SLOW, 120.0, 900) == pytest.approx(
            900 / 3.8 * TIMEOUT_MARGIN
        )

    def test_a_fast_model_keeps_the_configured_value(self) -> None:
        rates = GenerationRates()
        rates.observe("fast", 6200, 100.0, "llama.cpp timings")

        assert rates.call_timeout("judge:verdict", "fast", 600.0, 8192) == 600.0

    def test_the_ceiling_bounds_it(self) -> None:
        rates = GenerationRates()
        rates.observe(SLOW, 100, 100.0, "ollama eval_count/eval_duration")

        assert rates.call_timeout("judge:verdict", SLOW, 600.0, 8192) == TIMEOUT_CEILING_SECONDS

    def test_a_configured_value_above_the_ceiling_is_not_cut(self) -> None:
        rates = GenerationRates()
        rates.observe(SLOW, 100, 100.0, "ollama eval_count/eval_duration")

        assert rates.call_timeout("judge:verdict", SLOW, 7200.0, 8192) == 7200.0

    def test_the_ceiling_is_the_request_timeout_the_client_is_built_with(self) -> None:
        from pydantic import SecretStr

        from maljan.core.config import Settings
        from maljan.llm.openai_provider import OpenAIProvider

        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        settings.llm.openai.base_url = "http://127.0.0.1:8080/v1"
        settings.llm.openai.api_key = SecretStr("local")
        built = OpenAIProvider(settings).build_model("m", 0.1)

        assert built.request_timeout == TIMEOUT_CEILING_SECONDS  # type: ignore[attr-defined]

    def test_no_output_budget_leaves_the_configured_value(self) -> None:
        rates = GenerationRates()
        rates.observe(SLOW, 380, 100.0, "ollama eval_count/eval_duration")

        assert rates.call_timeout("judge:verdict", SLOW, 600.0, 0) == 600.0

    def test_the_rate_is_per_model(self) -> None:
        rates = GenerationRates()
        rates.observe(SLOW, 380, 100.0, "ollama eval_count/eval_duration")

        assert rates.rate("another") is None
        assert rates.rate(SLOW) == pytest.approx(3.8)

    def test_the_snapshot_states_every_number_and_its_source(self) -> None:
        rates = GenerationRates()
        rates.observe(SLOW, 380, 100.0, "ollama eval_count/eval_duration")
        rates.observe(SLOW, 400, 100.0, "ollama eval_count/eval_duration")
        rates.call_timeout("judge:verdict", SLOW, 600.0, 8192)

        snap = rates.snapshot()

        assert snap["margin"] == TIMEOUT_MARGIN
        assert snap["ceiling_s"] == TIMEOUT_CEILING_SECONDS
        model = snap["models"][SLOW]
        assert model["tokens_per_second"] == pytest.approx(3.9)
        assert model["tokens"] == 780 and model["calls"] == 2
        assert model["sources"] == ["ollama eval_count/eval_duration"]
        row = snap["timeouts"]["judge:verdict"]
        assert row["configured_s"] == 600.0
        assert row["max_tokens"] == 8192
        assert row["derived_s"] == pytest.approx(8192 / 3.9 * TIMEOUT_MARGIN, abs=0.1)


class TestEveryRealCallIsMeasured:
    def test_the_meter_reads_each_answer_without_a_call_of_its_own(self) -> None:
        model: Any = FakeMessagesListChatModel(
            responses=[_ollama_answer(38, 10.0), _ollama_answer(40, 10.0)]
        )
        rates = GenerationRates()
        attach_rate_meter(model, rates, SLOW)

        model.invoke([HumanMessage(content="a")])
        asyncio.run(model.ainvoke([HumanMessage(content="b")]))

        assert rates.snapshot()["models"][SLOW]["calls"] == 2
        assert rates.rate(SLOW) == pytest.approx(3.9)

    def test_the_container_meters_every_model_it_builds(self) -> None:
        from unittest.mock import MagicMock

        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer
        from maljan.llm.generation_rate import RateMeter

        container = ServiceContainer(Settings(_env_file=None), mock=True)  # type: ignore[call-arg]
        registry = MagicMock()
        registry.build_model.return_value = FakeMessagesListChatModel(
            responses=[_ollama_answer(38, 10.0)]
        )
        container._llm_registry = registry  # type: ignore[assignment]

        llm: Any = container.get_expert_llm()
        llm.invoke([HumanMessage(content="a")])

        assert any(isinstance(cb, RateMeter) for cb in llm.callbacks or [])
        assert container.get_generation_rates().rate("FakeMessagesListChatModel") == (
            pytest.approx(3.8)
        )


class _Named:
    model_name = SLOW


def _measured() -> GenerationRates:
    rates = GenerationRates()
    rates.observe(SLOW, 380, 100.0, "ollama eval_count/eval_duration")
    return rates


class TestTheJudgeAndTheComposerAskForIt:
    def test_the_verdict_call_is_sized_from_the_judge_s_model(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent
        from maljan.core.config import get_settings

        judge = JudgeAgent(llm=_Named())  # type: ignore[arg-type]
        judge.generation_rates = _measured()
        cap = int(get_settings().llm.judge_max_tokens)

        assert judge._verdict_timeout(600.0) == pytest.approx(
            max(600.0, min(cap / 3.8 * TIMEOUT_MARGIN, TIMEOUT_CEILING_SECONDS))
        )

    def test_a_standalone_judge_keeps_the_configured_value(self) -> None:
        from maljan.agents.judge_agent import JudgeAgent

        judge = JudgeAgent(llm=_Named())  # type: ignore[arg-type]

        assert judge._verdict_timeout(600.0) == 600.0

    def test_a_composer_section_is_sized_from_the_reporter_s_model(self) -> None:
        from maljan.reporting.composer import ReportComposer

        composer = ReportComposer(
            llm=_Named(),  # type: ignore[arg-type]
            section_max_tokens=900,
            per_section_timeout=120,
            generation_rates=_measured(),
        )

        # The answer and its one validation retry, each at the model's pace.
        assert composer._section_timeout() == pytest.approx(2 * 900 / 3.8 * TIMEOUT_MARGIN)

    def test_a_composer_with_no_rates_keeps_the_configured_wait(self) -> None:
        from maljan.reporting.composer import ReportComposer

        composer = ReportComposer(llm=_Named(), per_section_timeout=120)  # type: ignore[arg-type]

        assert composer._section_timeout() == 120.0


class TestTheRunSummaryRecordsIt:
    def _summary(self) -> Any:
        from maljan.analysis.run_summary import RunSummaryBuilder

        rates = _measured()
        rates.call_timeout("judge:verdict", SLOW, 600.0, 8192)
        rates.call_timeout("composer:section", SLOW, 120.0, 900)
        return RunSummaryBuilder(start_time=0.0).set_generation(rates.snapshot()).build()

    def test_the_rate_and_the_timeouts_are_in_the_record(self) -> None:
        generation = self._summary().to_dict()["generation"]

        assert generation["models"][SLOW]["tokens_per_second"] == pytest.approx(3.8)
        assert generation["timeouts"]["judge:verdict"]["applied_s"] == TIMEOUT_CEILING_SECONDS
        assert generation["timeouts"]["judge:verdict"]["derived_s"] == pytest.approx(
            8192 / 3.8 * TIMEOUT_MARGIN, abs=0.1
        )
        assert generation["timeouts"]["composer:section"]["configured_s"] == 120.0

    def test_the_report_states_every_number(self) -> None:
        text = _appendix_text(self._summary().to_dict())

        assert f"Generation rate of `{SLOW}`: 3.80 tokens/s" in text
        assert "Timeout of `judge:verdict`: 1800s" in text
        assert "= 3234s, at most 1800s" in text
        assert "8192 tokens at 3.80 tokens/s (prompt read included) × 1.5" in text
        assert "Timeout of `composer:section`: 355s" in text

    def test_the_run_summary_markdown_states_it_too(self) -> None:
        assert "## Generation Rate" in self._summary().to_markdown()

    def test_a_run_that_measured_nothing_records_nothing(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder

        builder = RunSummaryBuilder(start_time=0.0).set_generation(GenerationRates().snapshot())

        assert "generation" not in builder.build().to_dict()


class _Failing(FakeMessagesListChatModel):
    """A provider that refuses every call the way a dropped connection does."""

    def _generate(self, *_a: Any, **_k: Any) -> Any:
        raise ConnectionError("connection refused")

    async def _agenerate(self, *_a: Any, **_k: Any) -> Any:
        raise ConnectionError("connection refused")


class TestAFallbackListIsMeasuredModelByModel:
    def _list(self) -> Any:
        from maljan.llm.fallback import FallbackChatModel

        first = _Failing(responses=[_ollama_answer(1, 1.0)])
        second = FakeMessagesListChatModel(responses=[_ollama_answer(38, 10.0)])
        object.__setattr__(first, "model", "first-model")
        object.__setattr__(second, "model", "second-model")
        return FallbackChatModel(
            models=[first, second], labels=["first-model", "second-model"], agent="judge"
        )

    def test_the_answer_counts_against_the_model_that_gave_it(self) -> None:
        from maljan.llm.fallback import provider_failure

        assert provider_failure(ConnectionError("connection refused")) is not None
        model = self._list()
        rates = GenerationRates()
        attach_rate_meter(model, rates)

        asyncio.run(model.ainvoke([HumanMessage(content="a")]))

        assert rates.rate("second-model") == pytest.approx(3.8)
        assert rates.rate("first-model") is None
        assert set(rates.snapshot()["models"]) == {"second-model"}

    def test_a_call_is_sized_for_the_model_that_now_answers(self) -> None:
        from maljan.llm.generation_rate import model_name_of

        model = self._list()
        assert model_name_of(model) == "first-model"
        asyncio.run(model.ainvoke([HumanMessage(content="a")]))

        # The list sticks to the model that answered for the rest of the loop.
        assert model_name_of(model) == "second-model"


class TestTheSectionCapBoundsTheCall:
    @staticmethod
    def _composer(provider: str, thinking_off: bool) -> tuple[Any, Any]:
        from unittest.mock import MagicMock

        from maljan.core.config import Settings
        from maljan.core.container import ServiceContainer

        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        settings.llm.provider = provider
        getattr(settings.llm, provider).disable_thinking = thinking_off
        settings.reporting.composer_enabled = True
        settings.reporting.composer_section_max_tokens = 900
        settings.llm.judge_max_tokens = 8192
        container = ServiceContainer(settings, mock=False)
        registry = MagicMock()
        registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
        container._llm_registry = registry  # type: ignore[assignment]
        return container.get_report_composer(), registry

    @staticmethod
    def _cap_for(registry: Any, provider: str) -> int:
        _args, kwargs = registry.build_model_for_agent.call_args
        return int(kwargs["max_tokens_for"](provider))

    @pytest.mark.parametrize("provider", ["ollama", "openai"])
    def test_a_model_told_not_to_reason_is_capped_at_the_section_budget(
        self, provider: str
    ) -> None:
        composer, registry = self._composer(provider, thinking_off=True)

        assert composer is not None
        assert self._cap_for(registry, provider) == 900
        assert composer.output_cap == 900

    @pytest.mark.parametrize("provider", ["ollama", "openai"])
    def test_a_model_left_reasoning_is_given_room_for_it(self, provider: str) -> None:
        composer, registry = self._composer(provider, thinking_off=False)

        assert self._cap_for(registry, provider) == 900 + 8192
        assert composer.section_max_tokens == 900
        assert composer.output_cap == 900 + 8192

    def test_each_model_of_the_list_is_capped_by_its_own_provider_s_switch(self) -> None:
        from unittest.mock import MagicMock

        from maljan.core.config import REPORTER_AGENT_KEY, AgentLLMConfig, ModelChoice, Settings
        from maljan.core.container import ServiceContainer
        from maljan.llm.registry import _cap_for_provider

        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        settings.llm.ollama.disable_thinking = True
        settings.llm.openai.disable_thinking = False
        settings.llm.agents[REPORTER_AGENT_KEY] = AgentLLMConfig(
            provider="ollama",
            model="qwen3.8:27b",
            fallbacks=[
                ModelChoice(provider="openai", model="qwen", base_url="http://127.0.0.1:8080/v1")
            ],
        )
        settings.reporting.composer_enabled = True
        settings.reporting.composer_section_max_tokens = 900
        settings.llm.judge_max_tokens = 8192
        container = ServiceContainer(settings, mock=False)
        registry = MagicMock()
        registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
        container._llm_registry = registry  # type: ignore[assignment]

        composer = container.get_report_composer()

        assert composer is not None
        assert sorted(composer.caps_by_model.values()) == [900, 900 + 8192]
        assert composer.output_cap == 900 + 8192, "the wait is sized for the larger cap"
        kwargs: dict[str, Any] = {
            "max_tokens_for": registry.build_model_for_agent.call_args.kwargs["max_tokens_for"]
        }
        _cap_for_provider(kwargs, "ollama")
        assert kwargs == {"max_tokens": 900}

    def test_an_ollama_model_takes_the_cap_as_num_predict(self) -> None:
        from maljan.core.config import Settings
        from maljan.llm.ollama_provider import OllamaProvider

        built: Any = OllamaProvider(Settings(_env_file=None)).build_model(  # type: ignore[call-arg]
            "qwen3.8:27b", 0.1, max_tokens=900
        )

        assert built.num_predict == 900
        assert built._chat_params([])["options"]["num_predict"] == 900


class TestAComposerSectionOnItsOwnClock:
    def test_the_list_measures_its_deadline_on_the_section_s_sized_wait(self) -> None:
        from unittest.mock import patch

        from maljan.reporting.composer import ReportComposer
        from maljan.reporting.models import MalwareReport

        seen: list[tuple[float, float]] = []

        class _List(_Named):
            def enter_loop(self, seconds: float, share: float) -> None:
                seen.append((seconds, share))

        composer = ReportComposer(
            llm=_List(),  # type: ignore[arg-type]
            section_max_tokens=900,
            per_section_timeout=120,
            generation_rates=_measured(),
            turn_share=0.4,
        )

        async def _never(*_a: Any, **_k: Any) -> None:
            return None

        composer._invoke = _never  # type: ignore[method-assign]
        with (
            patch("maljan.reporting.composer.is_empty", lambda _b: False),
            patch("maljan.reporting.composer.bundle_for", lambda *_a, **_k: {}),
            patch("maljan.reporting.composer._bundle_text", lambda *_a, **_k: ""),
        ):
            asyncio.run(
                composer._author("conclusion", MalwareReport.model_construct(), {}, Any, "x")
            )

        # The job's share, on the section's own wait; the list is not restarted.
        assert seen == [(pytest.approx(2 * 900 / 3.8 * TIMEOUT_MARGIN), 0.4)]

    def test_a_section_the_cap_cut_says_so(self) -> None:
        from maljan.reporting.composer import ReportComposer, _ProseOut

        class _Cut:
            model_name = "slow-model"

            async def ainvoke(self, _messages: Any) -> Any:
                return AIMessage(
                    content='{"body": "The sample reads',
                    response_metadata={"done_reason": "length"},
                )

        composer = ReportComposer(llm=_Cut(), section_max_tokens=900)  # type: ignore[arg-type]
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "maljan.reporting.composer.structured_output_supported_for_llm", lambda _l: False
            )
            result = asyncio.run(
                composer._invoke([HumanMessage(content="x")], _ProseOut, section="conclusion")
            )

        assert result is None
        assert any("reached the output cap of 900 tokens" in d for d in composer.degradations)


def test_one_tag_on_two_servers_is_two_paces() -> None:
    from langchain_ollama import ChatOllama

    from maljan.llm.generation_rate import model_name_of
    from tests.credential_shapes import password

    local = ChatOllama(model="qwen3.8:27b", base_url="http://127.0.0.1:11434")
    userinfo = "operator:" + password()
    remote = ChatOllama(model="qwen3.8:27b", base_url=f"http://{userinfo}@gpu.example.org:11434/x")

    assert model_name_of(local) == "qwen3.8:27b @ http://127.0.0.1:11434"
    assert model_name_of(remote) == "qwen3.8:27b @ http://gpu.example.org:11434"


class TestAModelListSwitchSticksForTheReportStage:
    """A first model that stalled in one section is not waited out again in the next."""

    def test_sections_after_the_first_go_straight_to_the_fallback(self) -> None:
        from unittest.mock import patch

        from langchain_core.language_models.chat_models import BaseChatModel
        from langchain_core.outputs import ChatGeneration, ChatResult

        from maljan.llm.fallback import FallbackChatModel, restart_models
        from maljan.reporting.composer import ReportComposer, _ProseOut
        from maljan.reporting.models import MalwareReport

        class _Stalls(BaseChatModel):
            calls: list[int] = []

            def _generate(self, *_a: Any, **_k: Any) -> Any:  # pragma: no cover
                raise NotImplementedError

            async def _agenerate(self, *_a: Any, **_k: Any) -> Any:
                self.calls.append(1)
                await asyncio.sleep(1_000)

            @property
            def _llm_type(self) -> str:
                return "stalls"

        class _Answers(BaseChatModel):
            calls: list[int] = []

            def _generate(self, *_a: Any, **_k: Any) -> Any:  # pragma: no cover
                raise NotImplementedError

            async def _agenerate(self, *_a: Any, **_k: Any) -> Any:
                self.calls.append(1)
                body = '{"body": "The sample reads its own strings.", "evidence_refs": []}'
                return ChatResult(generations=[ChatGeneration(message=AIMessage(content=body))])

            @property
            def _llm_type(self) -> str:
                return "answers"

        primary, fallback = _Stalls(calls=[]), _Answers(calls=[])
        llm = FallbackChatModel(
            models=[primary, fallback], labels=["primary", "fallback"], agent="reporter"
        )
        composer = ReportComposer(llm=llm, per_section_timeout=4, turn_share=0.25)
        # The report node starts the list once, at the start of the stage.
        restart_models(llm)

        async def _four_sections() -> list[Any]:
            return [
                await composer._author(
                    "conclusion", MalwareReport.model_construct(), {}, _ProseOut, "x"
                )
                for _ in range(4)
            ]

        with (
            patch("maljan.reporting.composer.is_empty", lambda _b: False),
            patch("maljan.reporting.composer.bundle_for", lambda *_a, **_k: {}),
            patch("maljan.reporting.composer._bundle_text", lambda *_a, **_k: ""),
            patch(
                "maljan.reporting.composer.structured_output_supported_for_llm", lambda _l: False
            ),
        ):
            authored = asyncio.run(_four_sections())

        assert all(section is not None for section in authored), composer.degradations
        assert len(primary.calls) == 1, "the stalled first model was waited out once"
        assert len(fallback.calls) == 4


def _appendix_text(run_summary: dict) -> str:
    """The report's run-summary appendix for a report carrying ``run_summary``."""
    from maljan.reporting.models import MalwareReport
    from maljan.reporting.renderers.markdown import MarkdownRenderer

    report = MalwareReport.model_validate(
        {"identity": {"hashes": {"sha256": "0" * 64}}, "run_summary": run_summary}
    )
    return MarkdownRenderer()._appendix_run(report)


class TestThePromptReadIsTimedToo:
    """With the server's own generation rate, the prompt read is added at its own rate.

    The wall clock's rate included the prompt read and the margin covered it.
    The server's rate leaves it out, so a slow-reading model answering a long
    prompt to its cap timed out where the wall clock's rate had waited long
    enough.
    """

    @staticmethod
    def _rates(write: float, read: float, whole: float) -> GenerationRates:
        rates = GenerationRates()
        rates.observe("m", int(write * 100), 100.0, "llama.cpp timings.predicted_n/predicted_ms")
        rates.observe_prompt("m", int(read * 100), 100.0, "llama.cpp timings.prompt_n/prompt_ms")
        rates.observe_whole("m", int(whole * 100), 100.0)
        return rates

    def test_a_slow_prefill_is_waited_for(self) -> None:
        # 20 tokens/s written, 100 read: a full 8,192-token answer to a
        # 24,000-token prompt needs 240 + 410 s.
        rates = self._rates(write=20.0, read=100.0, whole=15.0)

        applied = rates.call_timeout("composer:section", "m", 120.0, 8192, prompt_tokens=24000)

        needed = 24000 / 100.0 + 8192 / 20.0
        assert applied == pytest.approx(needed * TIMEOUT_MARGIN)
        assert applied > 8192 / 20.0 * TIMEOUT_MARGIN
        row = rates.snapshot()["timeouts"]["composer:section"]
        assert row["prompt_tokens"] == 24000
        assert row["prompt_tokens_per_second"] == pytest.approx(100.0)
        assert row["tokens_per_second"] == pytest.approx(20.0)

    def test_without_a_reading_rate_the_rate_with_the_read_included_is_used(self) -> None:
        rates = GenerationRates()
        rates.observe("m", 5700, 100.0, "llama.cpp timings.predicted_n/predicted_ms")
        rates.observe_whole("m", 4000, 100.0)

        applied = rates.call_timeout("judge:verdict", "m", 60.0, 8192, prompt_tokens=5000)

        assert applied == pytest.approx(8192 / 40.0 * TIMEOUT_MARGIN)
        assert "prompt_tokens" not in rates.snapshot()["timeouts"]["judge:verdict"]

    def test_the_report_states_the_derivation(self) -> None:
        from maljan.analysis.run_summary import generation_lines

        rates = self._rates(write=20.0, read=100.0, whole=15.0)
        rates.call_timeout("composer:section", "m", 120.0, 8192, prompt_tokens=24000)

        text = "\n".join(generation_lines(rates.snapshot()))

        assert (
            "(24000 prompt tokens read at 100.00 tokens/s + 8192 tokens written at "
            "20.00 tokens/s) × 1.5"
        ) in text

    def test_the_meter_records_the_whole_rate_beside_the_server_s(self) -> None:
        import uuid

        from langchain_core.outputs import ChatGeneration, LLMResult

        from maljan.llm.generation_rate import RateMeter

        rates = GenerationRates()
        meter = RateMeter(rates, "m")
        message = AIMessage(
            content="x",
            response_metadata={"timings": {"predicted_n": 570, "predicted_ms": 10000}},
            usage_metadata={"input_tokens": 1, "output_tokens": 570, "total_tokens": 571},
        )
        run = uuid.uuid4()
        meter.on_chat_model_start({}, [], run_id=run)
        meter._started[run] -= 20.0
        meter.on_llm_end(LLMResult(generations=[[ChatGeneration(message=message)]]), run_id=run)

        row = rates._models["m"]
        assert row.rate() == pytest.approx(57.0)
        assert row.whole_rate() == pytest.approx(570 / 20.0, rel=0.05)
