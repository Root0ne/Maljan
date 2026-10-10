"""The reporter's derived output budget is every other role's: it leaves room for its prompt.

With no operator cap, the narrative round and the composer's sections derive
their output budget as the analysts and the judge do
(``context_window.derived_reply``): the smallest of a quarter of the window the
model serves and the model's declared maximum output. Sized at the declared
maximum alone, a model whose maximum output reaches its window was given the
whole window as its answer, and the narrative and the sections were left no
room for their prompt.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel

from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.llm.context_window import CHARS_PER_TOKEN, WindowFact, output_cap_for

# Hosted models whose vendors declare a maximum output in the vendored table.
DEEPSEEK = "deepseek-v4-pro"
DEEPSEEK_MAXIMUM = 393216
HAIKU = "claude-haiku-5-5"
HAIKU_MAXIMUM = 128000


def _container(window: int, model: str, **llm: int) -> ServiceContainer:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.provider = "openai"
    settings.llm.openai.base_url = "https://api.example.com"
    settings.llm.openai.expert_model = model
    settings.llm.openai.judge_model = model
    settings.llm.openai.disable_thinking = True
    settings.reporting.composer_enabled = True
    for name, value in llm.items():
        setattr(settings.llm, name, value)
    container = ServiceContainer(settings, mock=False)
    registry = MagicMock()
    registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
    container._llm_registry = registry  # type: ignore[assignment]
    return container


def _fact(window: int) -> WindowFact:
    return WindowFact(window, "probed", f"the served model list reported {window:,} tokens")


def _stage(window: int, model: str, **llm: int) -> tuple[Any, Any, Any]:
    """The narrative agent, the composer and the judge's cap, as one container builds them."""
    container = _container(window, model, **llm)
    with patch("maljan.llm.context_window.learn_window", return_value=_fact(window)):
        narrative = container.get_narrative_agent()
        composer = container.get_report_composer()
        judge = output_cap_for(container.config, "judge_max_tokens", "judge", role="judge")
    return narrative, composer, judge


def _compose_one(composer: Any) -> tuple[str, list[str]]:
    """The introduction's prompt and the degradations, from a live ``compose``."""
    import asyncio
    import json

    from maljan.reporting.composer import ReportComposer
    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

    sent: dict[str, str] = {}

    class _Capture:
        async def ainvoke(self, messages: Any, **_: Any) -> Any:
            prompt = str(messages[-1].content)
            section = prompt.split("The evidence for the ", 1)[-1].split(" section", 1)[0]
            sent.setdefault(section, prompt)
            return SimpleNamespace(content=json.dumps({"text": "An example."}))

    claims = [
        SimpleNamespace(claim=f"The sample writes example value {i}.", evidence_ref="ev_0001")
        for i in range(5)
    ]
    report = MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64)), verdict="Malware"
    )
    built = ReportComposer(
        llm=_Capture(),  # type: ignore[arg-type]
        per_section_timeout=5,
        output_cap=composer.output_cap,
        window_tokens=composer.window_tokens,
    )
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        asyncio.run(built.compose(report, isr_reports={"static": SimpleNamespace(claims=claims)}))
    return sent.get("introduction", ""), list(built.degradations)


class TestAMaximumOutputPastTheWindow:
    """A 200,000-token window under a 393,216-token declared maximum output."""

    def test_the_budget_is_the_judges_derivation(self) -> None:
        narrative, composer, judge = _stage(200000, DEEPSEEK)

        assert judge.tokens == 50000
        assert narrative.output_cap == judge.tokens
        assert composer.output_cap == judge.tokens

    def test_the_derivation_is_said(self) -> None:
        narrative, composer, _judge = _stage(200000, DEEPSEEK)

        for said in (narrative.budget_note, composer.budget_note):
            assert said.startswith("50000 tokens — the smallest of a quarter (50000)")
            assert f"declared maximum output of {DEEPSEEK_MAXIMUM}" in said

    def test_the_narrative_round_has_room_for_its_prompt(self) -> None:
        narrative, _composer, _judge = _stage(200000, DEEPSEEK)

        narrative._note_room(100_000)

        assert narrative.degradations == []

    def test_the_sections_have_room_for_their_prompt(self) -> None:
        _narrative, composer, _judge = _stage(200000, DEEPSEEK)

        assert composer._room_chars() == (200000 - 50000) * CHARS_PER_TOKEN

    def test_a_section_is_written_with_its_claims(self) -> None:
        from maljan.reporting.composer import NO_ROOM_FOR_THE_ANSWER

        _narrative, composer, _judge = _stage(200000, DEEPSEEK)

        prompt, degradations = _compose_one(composer)

        assert "The sample writes example value 4." in prompt
        assert NO_ROOM_FOR_THE_ANSWER not in prompt
        assert not [reason for reason in degradations if "window" in reason]

    def test_an_operators_value_still_wins(self) -> None:
        narrative, composer, _judge = _stage(200000, DEEPSEEK, judge_max_tokens=120000)

        assert narrative.output_cap == 120000
        assert composer.output_cap == 120000
        assert "llm.judge_max_tokens is set to 120000" in composer.budget_note


class TestAMillionTokenWindow:
    """Claude Haiku 5.5: a 1,000,000-token window and a 128,000-token maximum output."""

    def test_the_budget_is_the_judges_derivation(self) -> None:
        narrative, composer, judge = _stage(1000000, HAIKU)

        assert judge.tokens == HAIKU_MAXIMUM
        assert narrative.output_cap == judge.tokens
        assert composer.output_cap == judge.tokens

    def test_the_section_prompt_has_room(self) -> None:
        _narrative, composer, _judge = _stage(1000000, HAIKU)

        assert composer._room_chars() == (1000000 - HAIKU_MAXIMUM) * CHARS_PER_TOKEN
        prompt, degradations = _compose_one(composer)
        assert "The sample writes example value 4." in prompt
        assert not [reason for reason in degradations if "window" in reason]


class TestAListThatCannotBeBudgeted:
    def test_the_reporter_takes_the_judge_roles_cap_and_says_so(self) -> None:
        container = _container(200000, DEEPSEEK)
        with (
            patch(
                "maljan.core.model_assignments.assignment_chain_for",
                side_effect=ValueError("unreadable"),
            ),
            patch("maljan.llm.context_window.learn_window", return_value=_fact(200000)),
        ):
            narrative = container.get_narrative_agent()

        assert narrative.budget_note.startswith("llm.judge_max_tokens is 0, so derived: ")
        assert narrative.output_cap == int(narrative.budget_note.split(": ", 1)[1].split()[0])


class TestAFailedProbeOnDeepSeek:
    """A DeepSeek window probe that fails lands on the vendored table, for every role."""

    @staticmethod
    def _caps() -> tuple[Any, dict[str, int]]:
        from maljan.core.model_assignments import assignment_chain_for
        from maljan.llm import context_window

        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        settings.llm.provider = "openai"
        settings.llm.openai.base_url = "https://api.deepseek.com"
        settings.llm.openai.expert_model = "deepseek-v4-flash"
        settings.llm.openai.judge_model = "deepseek-v4-pro"
        settings.llm.openai.disable_thinking = True
        settings.reporting.composer_enabled = True
        container = ServiceContainer(settings, mock=False)
        registry = MagicMock()
        registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
        container._llm_registry = registry  # type: ignore[assignment]
        failed = context_window.unknown_window("the window probe timed out")
        context_window.forget_learned_windows()
        try:
            with patch("maljan.llm.context_window.probe_window", return_value=failed):
                judge = assignment_chain_for(settings, "judge", role="judge")[0]
                window = context_window.window_for_assignment(settings, judge)
                caps = {
                    "static": container._output_cap("expert_max_tokens", "static"),
                    "judge": container._output_cap("judge_max_tokens", "judge", role="judge"),
                    "mediator": int(container._expert_token_cap("mediator").tokens),
                    "narrative": container.get_narrative_agent().output_cap,
                    "composer": container.get_report_composer().output_cap,
                }
        finally:
            context_window.forget_learned_windows()
        return window, caps

    def test_the_window_is_the_table_s(self) -> None:
        from maljan.llm.context_window import TABLE

        window, _caps = self._caps()

        assert (window.tokens, window.source) == (1048576, TABLE)
        assert "the window probe timed out" in window.detail

    def test_every_role_derives_its_cap_from_it(self) -> None:
        _window, caps = self._caps()

        assert caps == dict.fromkeys(caps, 1048576 // 4)
