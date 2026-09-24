"""A report section's output budget is the model's reply room, not a constant.

A fixed 900 tokens dropped a section of a live report: the model reasoned past
it and the answer was cut. The budget is now what an analyst's reply is given
on the same model — the deployment's generation cap, at most a quarter of the
context window that model serves — and the run summary says how it was
reached. An operator's own positive value is used as it always was.
"""

from __future__ import annotations

import inspect
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from langchain_core.language_models.fake_chat_models import FakeMessagesListChatModel

from maljan.analysis.run_summary import generation_lines
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer
from maljan.llm.context_window import WindowFact
from maljan.llm.generation_rate import GenerationRates
from maljan.reporting.composer import ReportComposer


def _composer(window: int, **llm: int) -> Any:
    settings = Settings(_env_file=None)  # type: ignore[call-arg]
    settings.llm.provider = "openai"
    # A llama server we run, on loopback: no API limits its output.
    settings.llm.openai.base_url = "http://127.0.0.1:8080/v1"
    settings.llm.openai.expert_model = "local-model"
    settings.llm.openai.judge_model = "local-model"
    settings.reporting.composer_enabled = True
    for name, value in llm.items():
        setattr(settings.llm, name, value)
    container = ServiceContainer(settings, mock=False)
    registry = MagicMock()
    registry.build_model_for_agent.return_value = FakeMessagesListChatModel(responses=[])
    container._llm_registry = registry  # type: ignore[assignment]
    fact = WindowFact(window, "probed", "the server's /props")
    with patch("maljan.llm.context_window.learn_window", return_value=fact):
        composer = container.get_report_composer()
    built = registry.build_model_for_agent.call_args.kwargs["max_tokens_for"]("openai")
    return composer, built


class TestTheDefault:
    def test_the_setting_ships_at_zero(self) -> None:
        assert Settings(_env_file=None).reporting.composer_section_max_tokens == 0  # type: ignore[call-arg]

    def test_the_composer_carries_no_fixed_budget(self) -> None:
        default = inspect.signature(ReportComposer).parameters["section_max_tokens"].default
        assert default == 0


class TestTheDerivation:
    def test_a_large_window_gives_the_generation_cap(self) -> None:
        composer, built = _composer(32768, judge_max_tokens=8192, expert_max_tokens=8192)

        assert composer.output_cap == 8192
        assert built == 8192

    def test_a_small_window_gives_a_quarter_of_it(self) -> None:
        composer, built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)

        assert composer.output_cap == 4096
        assert built == 4096

    def test_the_larger_generation_cap_is_the_one_that_holds(self) -> None:
        composer, _built = _composer(131072, judge_max_tokens=4096, expert_max_tokens=12000)

        assert composer.output_cap == 12000

    def test_no_generation_cap_takes_a_quarter_of_the_window_with_no_ceiling(self) -> None:
        composer, _built = _composer(131072, judge_max_tokens=0, expert_max_tokens=0)

        assert composer.output_cap == 32768

    def test_the_derivation_is_said(self) -> None:
        composer, _built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)

        assert composer.budget_note.startswith("4096 tokens — ")
        assert "16384-token context window (probed)" in composer.budget_note
        assert "of 8192" in composer.budget_note

    def test_the_run_summary_prints_it_beside_the_wait(self) -> None:
        composer, _built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)
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
        composer, _built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)
        from maljan.llm.context_window import CHARS_PER_TOKEN

        room = (16384 - 4096) * CHARS_PER_TOKEN - 1000
        assert composer._item_chars(1000, 3) == room // 3

    def test_a_full_window_shows_no_answer_and_says_so(self) -> None:
        from maljan.reporting.composer import NO_ROOM_FOR_THE_ANSWER, _bundle_text

        composer, _built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)
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
        composer, _built = _composer(16384, judge_max_tokens=8192, expert_max_tokens=8192)

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

        async def ainvoke(self, messages: Any) -> Any:
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
