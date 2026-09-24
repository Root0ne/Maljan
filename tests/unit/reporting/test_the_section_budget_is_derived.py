"""A report section's output budget is the model's own room, not a constant.

A fixed 900 tokens dropped a section of a live report when the model reasoned
past it, and a quarter of the window held a million-token model to a quarter of
what it may write. The report stage follows, in order: the operator's section
budget, the reporter's ``llm.judge_max_tokens``, the model's declared maximum
output, and only then the analysts' derivation — a quarter of the window. It is
never more than the model's maximum, and the run summary and the worker log say
how it was reached.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel
from langchain_core.messages import HumanMessage

from maljan.analysis.run_summary import generation_lines
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.llm.context_window import WindowFact
from maljan.llm.generation_rate import GenerationRates
from maljan.reporting.composer import ReportComposer

# A hosted model whose vendor declares its maximum output in the vendored table.
HOSTED_MODEL = "deepseek-flash"
HOSTED_MAXIMUM = 393216
MILLION = 1048576


def _composer(
    window: int,
    *,
    model: str = "local-model",
    base_url: str = "http://127.0.0.1:8080/v1",
    detail: str = "",
    section: int = 0,
    thinking_off: bool = True,
    source: str = "probed",
    **llm: int,
) -> Any:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.provider = "openai"
    # By default a llama server we run, which answered the probe's /props: no
    # API limits its output.
    settings.llm.openai.base_url = base_url
    settings.llm.openai.expert_model = model
    settings.llm.openai.judge_model = model
    settings.llm.openai.disable_thinking = thinking_off
    settings.reporting.composer_enabled = True
    settings.reporting.composer_section_max_tokens = section
    for name, value in llm.items():
        setattr(settings.llm, name, value)
    container = ServiceContainer(settings, mock=False)
    registry = MagicMock()
    registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
    container._llm_registry = registry  # type: ignore[assignment]
    fact = WindowFact(window, source, detail or f"llama.cpp /props reported {window:,} tokens")
    with patch("maljan.llm.context_window.learn_window", return_value=fact):
        composer = container.get_report_composer()
    built = registry.build_model_for_agent.call_args.kwargs["max_tokens_for"]("openai")
    return composer, built


def _hosted(**kwargs: Any) -> Any:
    return _composer(
        MILLION,
        model=HOSTED_MODEL,
        base_url="https://api.example.com",
        detail="the served model list reported 1,048,576",
        **kwargs,
    )


class TestTheDefault:
    def test_the_setting_ships_at_zero(self) -> None:
        assert Settings(_env_file=None).reporting.composer_section_max_tokens == 0  # type: ignore[call-arg]

    def test_the_composer_carries_no_fixed_budget(self) -> None:
        default = inspect.signature(ReportComposer).parameters["section_max_tokens"].default
        assert default == 0


class TestTheOrder:
    def test_the_reporters_cap_is_the_operators_value(self) -> None:
        composer, built = _composer(32768, judge_max_tokens=8192, expert_max_tokens=8192)

        assert composer.output_cap == 8192
        assert built == 8192
        assert "llm.judge_max_tokens is set to 8192" in composer.budget_note

    def test_the_operators_value_is_not_cut_to_a_quarter_of_the_window(self) -> None:
        composer, built = _composer(16384, judge_max_tokens=8192)

        assert composer.output_cap == 8192
        assert built == 8192

    def test_the_analysts_cap_is_not_the_reporters(self) -> None:
        composer, _built = _composer(131072, judge_max_tokens=4096, expert_max_tokens=12000)

        assert composer.output_cap == 4096

    def test_a_declared_maximum_is_the_budget_with_no_operator_value(self) -> None:
        composer, built = _hosted()

        assert composer.output_cap == HOSTED_MAXIMUM
        assert built == HOSTED_MAXIMUM
        assert composer.budget_note.startswith(f"{HOSTED_MAXIMUM} tokens — the model's declared")
        assert "api-docs.deepseek.com" in composer.budget_note

    def test_nothing_declared_takes_a_quarter_of_the_window(self) -> None:
        composer, _built = _composer(131072, judge_max_tokens=0, expert_max_tokens=0)

        assert composer.output_cap == 32768

    def test_the_derivation_is_said(self) -> None:
        composer, _built = _composer(16384)

        assert composer.budget_note.startswith("4096 tokens — ")
        assert "16384-token context window (probed)" in composer.budget_note

    def test_the_run_summary_prints_it_beside_the_wait(self) -> None:
        composer, _built = _composer(16384)
        rates = GenerationRates()
        rates.observe("model", 1000, 100.0, "test")
        rates.call_timeout(
            "composer:section", "model", 120, composer.output_cap, budget=composer.budget_note
        )

        lines = generation_lines(rates.snapshot())

        assert any(
            line.startswith("Output budget of `composer:section`: 4096 tokens") for line in lines
        )
        assert any("4096 tokens at 10.00 tokens/s" in line for line in lines)


class TestNeverPastTheModelsMaximum:
    def test_an_operators_value_past_the_declared_maximum_is_held_at_it(self) -> None:
        composer, built = _hosted(judge_max_tokens=500000)

        assert composer.output_cap == HOSTED_MAXIMUM
        assert built == HOSTED_MAXIMUM
        assert "llm.judge_max_tokens is set to 500000" in composer.budget_note
        assert "held at the model's declared maximum output" in composer.budget_note

    def test_the_reasoning_room_does_not_push_past_it(self) -> None:
        composer, _built = _hosted(section=900, thinking_off=False)

        assert composer.output_cap == HOSTED_MAXIMUM
        assert "plus 393216 for its reasoning" in composer.budget_note

    def test_a_served_window_bounds_a_model_that_declares_nothing(self) -> None:
        composer, _built = _composer(16384, judge_max_tokens=40000)

        assert composer.output_cap == 16384
        assert "held at the model's 16384-token context window" in composer.budget_note

    def test_a_million_token_window_leaves_the_rest_for_the_evidence(self) -> None:
        from maljan.llm.context_window import CHARS_PER_TOKEN

        composer, _built = _hosted()

        assert composer._room_chars() == (MILLION - HOSTED_MAXIMUM) * CHARS_PER_TOKEN


class TestTheReportersModel:
    def test_the_narrative_round_is_built_with_the_report_stage_budget(self) -> None:
        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        settings.llm.provider = "openai"
        settings.llm.openai.base_url = "https://api.example.com"
        settings.llm.openai.judge_model = HOSTED_MODEL
        container = ServiceContainer(settings, mock=False)
        registry = MagicMock()
        registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
        container._llm_registry = registry  # type: ignore[assignment]
        fact = WindowFact(MILLION, "probed", "the served model list reported 1,048,576")
        with patch("maljan.llm.context_window.learn_window", return_value=fact):
            container.get_reporter_llm()

        assert registry.build_model_for_agent.call_args.kwargs["max_tokens"] == HOSTED_MAXIMUM


class TestAnOperatorsOwnBudget:
    @pytest.mark.parametrize("thinking_off", [True, False])
    def test_a_positive_value_is_used_as_it_always_was(self, thinking_off: bool) -> None:
        settings = Settings(_env_file=None)  # type: ignore[call-arg]
        settings.llm.provider = "openai"
        settings.llm.openai.disable_thinking = thinking_off
        settings.llm.judge_max_tokens = 8192
        settings.reporting.composer_enabled = True
        settings.reporting.composer_section_max_tokens = 900
        container = ServiceContainer(settings, mock=False)
        registry = MagicMock()
        registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
        container._llm_registry = registry  # type: ignore[assignment]

        fact = WindowFact(16384, "probed", "the server's /props")
        with patch("maljan.llm.context_window.learn_window", return_value=fact):
            composer = container.get_report_composer()

        expected = 900 if thinking_off else 900 + 8192
        assert composer.output_cap == expected
        assert "composer_section_max_tokens is set to 900" in composer.budget_note
        # The window is still learned: a section's tool answers are sized by it.
        assert composer.window_tokens == 16384


class TestTheToolAnswersShareTheWindow:
    """A section's tool answers get what the window leaves, not a fixed 1,200 characters."""

    def test_the_share_is_the_room_left_divided_evenly(self) -> None:
        composer, _built = _composer(16384)
        from maljan.llm.context_window import CHARS_PER_TOKEN

        room = (16384 - 4096) * CHARS_PER_TOKEN - 1000
        assert composer._item_chars(1000, 3) == room // 3

    def test_a_full_window_shows_no_answer_and_says_so(self) -> None:
        from maljan.reporting.composer import NO_ROOM_FOR_THE_ANSWER, _bundle_text

        composer, _built = _composer(16384)
        chars = composer._item_chars(10**7, 2)
        text = _bundle_text(
            "payloads", {"tool_outputs": [{"tool": "x", "output": "y" * 50}]}, None, chars
        )

        assert chars == 0
        assert NO_ROOM_FOR_THE_ANSWER in text

    def test_no_window_shows_each_answer_whole(self) -> None:
        from maljan.reporting.composer import _bundle_text

        composer = ReportComposer(llm=None, per_section_timeout=5)  # type: ignore[arg-type]
        chars = composer._item_chars(100, 1)
        text = _bundle_text(
            "payloads", {"tool_outputs": [{"tool": "x", "output": "y" * 5000}]}, None, chars
        )

        assert chars is None
        assert "y" * 5000 in text

    def test_the_derivation_is_said(self) -> None:
        composer, _built = _composer(16384)

        assert "tool answers share what the 16384-token window leaves" in composer.budget_note


class TestTheClaimsShareTheWindow:
    """Every analyst claim reaches its section, sized the way the tool answers are."""

    @staticmethod
    def _isrs(count: int) -> dict[str, Any]:
        from types import SimpleNamespace

        claims = [
            SimpleNamespace(claim=f"The sample writes example value {i}.", evidence_ref="ev_0001")
            for i in range(count)
        ]
        return {"static": SimpleNamespace(claims=claims)}

    @pytest.mark.parametrize("section", ["executive_summary", "introduction", "execution_flow"])
    def test_no_count_cuts_a_section_s_claims(self, section: str) -> None:
        from maljan.reporting.evidence_bundles import bundle_for
        from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

        report = MalwareReport(identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64)))

        bundle = bundle_for(section, report, isr_reports=self._isrs(40))

        assert len(bundle["claims"]) == 40

    def test_each_claim_is_shown_within_its_share_and_a_cut_says_so(self) -> None:
        from maljan.reporting.composer import _bundle_text
        from maljan.utils.marked_cut import CUT_MARK

        claims = [{"claim": "x" * 200, "evidence_ref": "ev_0001"} for _ in range(25)]

        text = _bundle_text("introduction", {"claims": claims}, None, 60)

        shown = [line for line in text.splitlines() if line.startswith("- x")]
        assert len(shown) == 25
        assert all(line.endswith(CUT_MARK) and len(line) <= 62 for line in shown)

    def test_a_full_window_says_there_was_no_room_for_a_claim(self) -> None:
        from maljan.reporting.composer import NO_ROOM_FOR_THE_ANSWER, _bundle_text

        bundle = {"claims": [{"claim": "x", "evidence_ref": ""}]}

        assert f"- {NO_ROOM_FOR_THE_ANSWER}" in _bundle_text("introduction", bundle, None, 0)

    def test_a_built_prompt_shows_every_claim_within_the_window(self) -> None:
        from maljan.llm.context_window import CHARS_PER_TOKEN
        from maljan.utils.marked_cut import CUT_MARK

        claim = "The sample writes example value {} under its settings key. " + "x" * 260
        isrs = {
            "static": SimpleNamespace(
                claims=[
                    SimpleNamespace(claim=claim.format(i), evidence_ref="ev_0001")
                    for i in range(40)
                ]
            )
        }
        sent = _compose(isrs, window_tokens=4000, output_cap=1000)

        prompt = sent["introduction"]
        shown = [line for line in prompt.splitlines() if line.startswith("- The sample writes")]
        assert len(shown) == 40
        assert all(line.endswith(CUT_MARK) for line in shown)
        assert len(prompt) <= (4000 - 1000) * CHARS_PER_TOKEN
        assert len(prompt) > (4000 - 1000) * CHARS_PER_TOKEN * 3 // 4


def _compose(isr_reports: dict[str, Any], report: Any = None, **composer: int) -> dict[str, str]:
    """The human turn each section was sent, by section, from a live ``compose``."""
    import asyncio
    import json

    from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity

    sent: dict[str, str] = {}

    class _Capture:
        def with_structured_output(self, schema: type, **_: Any) -> Any:  # pragma: no cover
            raise RuntimeError("structured output is unavailable")

        async def ainvoke(self, messages: Any, **_: Any) -> Any:
            prompt = str(messages[-1].content)
            section = prompt.split("The evidence for the ", 1)[-1].split(" section", 1)[0]
            sent.setdefault(section, prompt)
            return SimpleNamespace(content=json.dumps({"text": "An example."}))

    report = report or MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64)), verdict="Malware"
    )
    comp = ReportComposer(llm=_Capture(), per_section_timeout=5, **composer)  # type: ignore[arg-type]
    with patch("maljan.reporting.composer.structured_output_supported_for_llm", return_value=False):
        asyncio.run(comp.compose(report, isr_reports=isr_reports))
    sent["_degradations"] = "\n".join(comp.degradations)
    return sent


class TestTheFactsEnterWhole:
    """No count cuts a section's facts; a section whose facts alone overflow says so."""

    def test_every_network_value_reaches_the_configuration_section(self) -> None:
        from maljan.reporting.evidence_bundles import bundle_for
        from maljan.reporting.models import (
            FileHashes,
            MalwareReport,
            NetworkDomain,
            NetworkIOCs,
            SampleIdentity,
        )

        hosts = [f"relay{i}.example.net" for i in range(35)]
        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64)),
            network=NetworkIOCs(domains=[NetworkDomain(fqdn=h, source="sandbox") for h in hosts]),
        )

        for section in ("configuration", "communications"):
            facts = bundle_for(section, report)["facts"]
            assert facts["domains"] == hosts

    def test_a_long_command_line_is_shown_whole(self) -> None:
        from maljan.reporting.evidence_bundles import _process_lines
        from maljan.reporting.models import ProcessNode

        command = "example.exe " + "-o value " * 60
        node = ProcessNode(pid=4, name="example.exe", command_line=command)

        assert _process_lines(node, 0) == [f"pid 4 example.exe: {command}"]

    def test_a_packer_match_without_a_confidence_states_none(self) -> None:
        from maljan.reporting.evidence_bundles import _packer_line

        assert _packer_line({"name": "ExamplePack", "method": "signature"}) == (
            "ExamplePack (signature)"
        )

    def test_facts_that_overflow_the_window_record_a_degradation(self) -> None:
        from maljan.reporting.models import (
            FileHashes,
            MalwareReport,
            NetworkDomain,
            NetworkIOCs,
            SampleIdentity,
        )

        report = MalwareReport(
            identity=SampleIdentity(hashes=FileHashes(sha256="e" * 64)),
            verdict="Malware",
            network=NetworkIOCs(
                domains=[
                    NetworkDomain(fqdn=f"relay{i}.example.net", source="sandbox")
                    for i in range(3000)
                ]
            ),
        )

        sent = _compose({}, report, window_tokens=4000, output_cap=1000)

        assert "section's prompt without its claims and tool answers" in sent["_degradations"]
        assert "relay2999.example.net" in "".join(
            v for k, v in sent.items() if k != "_degradations"
        )


class TestAWindowTheBudgetFills:
    """The budget never leaves negative room, and a call is held to what the window leaves."""

    def test_a_failed_probe_is_an_unknown_window_not_a_fact(self) -> None:
        composer, built = _composer(
            8192,
            model=HOSTED_MODEL,
            base_url="https://api.example.com",
            detail="no endpoint reported a window",
            source="fallback",
        )

        assert composer.output_cap == HOSTED_MAXIMUM
        assert built == HOSTED_MAXIMUM
        assert composer.window_tokens == 0
        assert composer._room_chars() is None
        assert composer._call_bound([HumanMessage(content="x" * 30000)]) is None

    def test_a_gateway_declaring_its_window_as_its_output_leaves_no_debt(self) -> None:
        from maljan.llm import model_output_limits

        model_output_limits.note_from_model_list(
            {"data": [{"id": "gateway-model", "max_completion_tokens": 131072}]},
            "gateway-model",
        )
        try:
            composer, _built = _composer(
                131072,
                model="gateway-model",
                base_url="https://gateway.example.com",
                detail="the served model list reported 131,072",
            )
        finally:
            model_output_limits.forget_learned()

        assert composer.output_cap == 131072
        assert composer._room_chars() == 0
        assert composer._call_bound([HumanMessage(content="x" * 3000)]) == 131072 - 1000

    def test_a_local_judge_cap_past_the_window_is_held_per_call(self) -> None:
        composer, _built = _composer(16384, judge_max_tokens=40000)

        assert composer.output_cap == 16384
        assert composer._room_chars() == 0
        assert composer._call_bound([HumanMessage(content="x" * 3000)]) == 16384 - 1000

    def test_a_budget_that_fits_beside_its_prompt_is_not_held(self) -> None:
        composer, _built = _hosted()

        assert composer._call_bound([HumanMessage(content="x" * 3000)]) is None

    def test_the_held_value_reaches_the_call(self) -> None:
        import asyncio

        from maljan.reporting.composer import _IntroOut

        sent: list[dict[str, Any]] = []

        class _Raw:
            async def ainvoke(self, messages: Any, **kwargs: Any) -> Any:
                sent.append(kwargs)
                return SimpleNamespace(content='{"text": "An example."}')

        composer = ReportComposer(
            llm=_Raw(),  # type: ignore[arg-type]
            per_section_timeout=5,
            output_cap=16384,
            window_tokens=16384,
        )
        with patch(
            "maljan.reporting.composer.structured_output_supported_for_llm", return_value=True
        ):
            asyncio.run(
                composer._invoke([HumanMessage(content="x" * 3000)], _IntroOut, section="intro")
            )

        assert sent == [{"max_tokens": 16384 - 1000}]

    def test_an_ollama_model_is_left_to_its_own_context(self) -> None:
        from langchain_ollama import ChatOllama

        from maljan.llm.context_window import accepts_output_bound

        assert not accepts_output_bound(ChatOllama(model="m"))

    def test_a_prompt_larger_than_the_window_is_recorded(self) -> None:
        composer = ReportComposer(
            llm=None,  # type: ignore[arg-type]
            per_section_timeout=5,
            output_cap=1000,
            window_tokens=4000,
        )

        composer._call_bound([HumanMessage(content="x" * 30000)])

        assert any("larger than its model" in reason for reason in composer.degradations)
