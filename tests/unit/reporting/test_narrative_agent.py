"""Unit tests for ``NarrativeAgent`` and ``NarrativeOutput``.

The agent is exercised with three LLM stand-ins:

  - a structured-output mock that returns a valid ``NarrativeOutput``,
  - a structured-output mock that raises (forcing the manual-parse path),
  - a manual-parse path that returns junk (final fallback → ``None``).

We also pin the prompt builder so we catch unintentional schema drift.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from pydantic import ValidationError

from maljan.pipeline.validation import FEEDBACK_PREAMBLE
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import (
    DefensiveRecommendation,
    EvidenceIndexRow,
    KeyFinding,
    MalwareReport,
    TTPMapping,
)
from maljan.reporting.narrative_agent import (
    NarrativeAgent,
    NarrativeOutput,
    _message_text,
    build_prompt_text,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _make_report(**overrides: Any) -> MalwareReport:
    sandbox = overrides.pop(
        "sandbox_report",
        {
            "target": {"file": {"sha256": "d" * 64, "name": "test.exe"}},
            "behavior": {
                "processes": [{"name": "test.exe", "pid": 100, "ppid": 1, "cmd": "test.exe"}],
                "calls": [
                    {
                        "api": "RegSetValueExA",
                        "arguments": [
                            {
                                "FullName": "HKLM\\Software\\Run",
                                "ValueName": "x",
                                "Buffer": "C:\\x.exe",
                            }
                        ],
                    }
                ],
            },
            "network": {
                "dns": [{"request": "evil.duckdns.org"}],
                "tcp": [{"dst": "1.2.3.4", "dport": 443}],
            },
            "signatures": [{"name": "Persistence", "severity": 8, "ttp_tags": ["T1547"]}],
        },
    )
    report = MalwareReportBuilder(
        file_hash=overrides.pop("file_hash", "d" * 64),
        file_name=overrides.pop("file_name", "test.exe"),
        sample_path=overrides.pop("sample_path", None),
        sandbox_report=sandbox,
        reports=overrides.pop("reports", {}),
        isr_reports=overrides.pop("isr_reports", {}),
        stix_output=overrides.pop("stix_output", {"objects": []}),
        run_summary=overrides.pop("run_summary", {}),
        discussion_history=overrides.pop("discussion_history", []),
        final_decision=overrides.pop("final_decision", "Malware"),
        overall_confidence=overrides.pop("overall_confidence", 0.9),
        judge_assessment=overrides.pop("judge_assessment", None),
        malware_category=overrides.pop("malware_category", "ransomware"),
    ).build_deterministic()
    # The narrative fixture below describes persistence, a C2 channel and a
    # ransomware variant. A report that established none of those is a report
    # the capability guard is right to object to, so this one establishes them
    # — which is what the sandbox report above was always describing.
    report.ttp_mappings = overrides.pop(
        "ttp_mappings",
        [
            TTPMapping(technique_id="T1547.001", technique_name="Registry Run Keys"),
            TTPMapping(technique_id="T1071.001", technique_name="Web Protocols"),
            TTPMapping(technique_id="T1486", technique_name="Data Encrypted for Impact"),
        ],
    )
    return report


def _valid_narrative() -> NarrativeOutput:
    return NarrativeOutput(
        executive_summary=(
            "Sample is a Windows ransomware variant exhibiting registry-based "
            "persistence (T1547.001) and TLS C2 to 1.2.3.4. Confidence is high "
            "given corroborated dynamic + network evidence." * 1
        ),
        key_findings=[
            KeyFinding(text="It writes a Run key (T1547.001) under HKLM Software\\Run."),
            KeyFinding(text="It connects out over TLS to 1.2.3.4 on port 443."),
            KeyFinding(text="Its execution chain is short, with limited debug surface."),
        ],
        defensive_recommendations=[
            DefensiveRecommendation(
                category="firewall",
                action="Block 1.2.3.4/32 outbound at the perimeter.",
                rationale="Sample observed beaconing to this IP.",
                priority="P0",
            ),
            DefensiveRecommendation(
                category="registry_hardening",
                action="Audit HKLM Software\\Run for unexpected entries.",
                rationale="Persistence artefact path.",
                priority="P1",
            ),
            DefensiveRecommendation(
                category="edr_hunting",
                action="Hunt for process tree pivots from test.exe.",
                rationale="Sample spawned via this binary.",
                priority="P2",
            ),
        ],
    )


# ---------------------------------------------------------------------------
# NarrativeOutput schema
# ---------------------------------------------------------------------------


class TestNarrativeOutputSchema:
    def test_valid_output_round_trip(self) -> None:
        out = _valid_narrative()
        rebuilt = NarrativeOutput.model_validate(out.model_dump())
        assert rebuilt.executive_summary == out.executive_summary
        assert len(rebuilt.key_findings) == 3

    def test_no_upper_bound_cuts_what_the_evidence_supports(self) -> None:
        good = _valid_narrative()
        out = NarrativeOutput(
            executive_summary="The sample encrypts documents on local drives. " * 100,
            key_findings=good.key_findings * 5,
            defensive_recommendations=good.defensive_recommendations * 5,
        )

        assert len(out.executive_summary) > 4000
        assert len(out.key_findings) == 15
        assert len(out.defensive_recommendations) == 15

    def test_the_prompt_sets_no_upper_size(self) -> None:
        import re

        from maljan.reporting.narrative_agent import _SYSTEM_PROMPT, EXPECTED_OBJECT

        for text in (_SYSTEM_PROMPT, EXPECTED_OBJECT):
            assert not re.search(r"\d+\s*(-|to)\s*\d+", text)
            assert not re.search(r"\b(at most|no more than|up to)\b", text)

    def test_the_prompt_states_the_minimums_the_schema_holds(self) -> None:
        from maljan.reporting.narrative_agent import _SYSTEM_PROMPT, EXPECTED_OBJECT

        assert NarrativeOutput.model_fields["executive_summary"].metadata[0].min_length == 120
        assert "at least 120 characters" in _SYSTEM_PROMPT
        assert "at least 120 characters" in EXPECTED_OBJECT
        assert "at least two objects" in _SYSTEM_PROMPT
        assert "at least three entries" in _SYSTEM_PROMPT

    def test_two_good_key_findings_are_kept(self) -> None:
        """Two findings are a whole answer; the lower bound is what the schema keeps."""
        out = NarrativeOutput(
            executive_summary="A" * 200,
            key_findings=_valid_narrative().key_findings[:2],
            defensive_recommendations=_valid_narrative().defensive_recommendations,
        )
        assert len(out.key_findings) == 2

    def test_too_few_key_findings_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeOutput(
                executive_summary="A" * 200,
                key_findings=[KeyFinding(text="only one")],
                defensive_recommendations=_valid_narrative().defensive_recommendations,
            )

    def test_executive_summary_min_length(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeOutput(
                executive_summary="too short",
                key_findings=_valid_narrative().key_findings,
                defensive_recommendations=_valid_narrative().defensive_recommendations,
            )

    def test_invalid_priority_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeOutput.model_validate(
                {
                    "executive_summary": "A" * 200,
                    "key_findings": [{"text": "a"}, {"text": "b"}, {"text": "c"}],
                    "defensive_recommendations": [
                        {
                            "category": "firewall",
                            "action": "x",
                            "rationale": "y",
                            "priority": "urgent",
                        }
                    ],
                }
            )

    def test_extra_field_ignored(self) -> None:
        # Extra LLM-added field must NOT cause validation errors.
        data = _valid_narrative().model_dump()
        data["confidence_in_narrative"] = 0.7
        rebuilt = NarrativeOutput.model_validate(data)
        assert rebuilt.executive_summary == data["executive_summary"]


# ---------------------------------------------------------------------------
# Prompt builder
# ---------------------------------------------------------------------------


class TestPromptBuilder:
    def test_prompt_contains_verdict_and_severity(self) -> None:
        report = _make_report()
        text = build_prompt_text(report)
        assert "Verdict: Malware" in text
        assert "Severity:" in text

    def test_prompt_contains_attack_techniques(self) -> None:
        report = _make_report()
        text = build_prompt_text(report)
        assert "Published ATT&CK techniques" in text

    def test_an_evidence_quote_is_shown_whole(self) -> None:
        report = _make_report()
        long_quote = "x" * 500
        report.ttp_mappings = [
            TTPMapping(
                technique_id="T1547.001",
                technique_name="Registry Run Keys",
                evidence_quotes=[long_quote, "second quote"],
                confidence=0.9,
            )
        ]
        text = build_prompt_text(report)
        assert long_quote in text
        assert "second quote" in text

    def test_every_published_fact_is_shown(self) -> None:
        from maljan.reporting.models import (
            DynamicBehavior,
            NetworkDomain,
            NetworkIOCs,
            NetworkIP,
            PersistenceMechanism,
            SandboxSignature,
            TTPMapping,
        )

        report = _make_report()
        report.ttp_mappings = [
            TTPMapping(technique_id=f"T999{i}", technique_name=f"Fake-{i}") for i in range(20)
        ]
        report.dynamic = DynamicBehavior(
            sandbox_signatures=[SandboxSignature(name=f"sig-{i}", severity=1) for i in range(9)]
        )
        report.network = NetworkIOCs(
            domains=[
                NetworkDomain(fqdn=f"relay{i}.example.net", source="sandbox") for i in range(7)
            ],
            ips=[NetworkIP(address=f"192.0.2.{i}", source="sandbox") for i in range(7)],
        )
        report.persistence = [
            PersistenceMechanism(kind="registry_run", target=f"HKCU\\Example\\{i}" + "y" * 150)
            for i in range(6)
        ]

        text = build_prompt_text(report)

        assert all(f"T999{i} " in text for i in range(20))
        assert all(f"sig-{i} " in text for i in range(9))
        assert all(f"relay{i}.example.net" in text for i in range(7))
        assert all(f"192.0.2.{i} " in text for i in range(7))
        assert all(f"HKCU\\Example\\{i}" + "y" * 150 in text for i in range(6))
        assert "top " not in text.lower() and "max " not in text.lower()


# ---------------------------------------------------------------------------
# Agent paths
# ---------------------------------------------------------------------------


def _mock_llm_with_structured(result: Any, structured_side_effect: Any = None) -> Any:
    """Return a MagicMock LLM whose ``with_structured_output().ainvoke`` is preset."""
    llm = MagicMock()
    structured = MagicMock()
    structured.ainvoke = AsyncMock(side_effect=structured_side_effect or [result])
    llm.with_structured_output.return_value = structured
    return llm


@pytest.fixture
def structured_output_endpoint(monkeypatch: Any) -> None:
    """Assert the endpoint can do structured output.

    The agent now asks before taking that path (see
    ``structured_output_supported``), and this repo's own .env points at a
    local llama-server, where it cannot. Tests that exercise the structured
    path must say which world they are in rather than inherit the developer's
    configuration.
    """
    monkeypatch.setattr(
        "maljan.reporting.narrative_agent.structured_output_supported_for_llm",
        lambda _llm: True,
    )


class TestNarrativeAgentSuccess:
    @pytest.mark.asyncio
    async def test_returns_structured_output(self, structured_output_endpoint: None) -> None:
        report = _make_report()
        expected = _valid_narrative()
        llm = _mock_llm_with_structured(expected)
        agent = NarrativeAgent(llm=llm)

        out = await agent.generate(report)
        assert out is not None
        assert out.executive_summary == expected.executive_summary
        llm.with_structured_output.assert_called_once_with(NarrativeOutput, include_raw=True)


class TestNarrativeAgentManualParseFallback:
    @pytest.mark.asyncio
    async def test_manual_parse_recovers_when_structured_fails(self) -> None:
        report = _make_report()
        llm = MagicMock()
        # First call (structured) raises; second call (raw) returns AIMessage-like.
        structured = MagicMock()
        structured.ainvoke = AsyncMock(side_effect=Exception("schema bork"))
        llm.with_structured_output.return_value = structured
        valid_json = _valid_narrative().model_dump_json()
        raw_message = MagicMock()
        raw_message.content = "```json\n" + valid_json + "\n```"
        llm.ainvoke = AsyncMock(return_value=raw_message)

        agent = NarrativeAgent(llm=llm)
        out = await agent.generate(report)
        assert out is not None
        assert len(out.key_findings) >= 3


class TestTheNarrativeGetsOneTurnToFixItsShape:
    """``NarrativeOutput`` has real constraints and they are what a model gets
    wrong. Before the loop the first breach discarded the whole answer and the
    report shipped the deterministic template, with nothing recording which
    rule was broken."""

    @staticmethod
    def _llm(*raw_answers: str) -> MagicMock:
        llm = MagicMock()
        structured = MagicMock()
        structured.ainvoke = AsyncMock(side_effect=Exception("schema bork"))
        llm.with_structured_output.return_value = structured
        llm.ainvoke = AsyncMock(side_effect=[MagicMock(content=answer) for answer in raw_answers])
        return llm

    @pytest.mark.asyncio
    async def test_an_off_schema_answer_earns_one_retry_and_is_then_accepted(self) -> None:
        # One key finding where the schema needs two.
        thin = _valid_narrative().model_dump()
        thin["key_findings"] = thin["key_findings"][:1]
        llm = self._llm(json.dumps(thin), _valid_narrative().model_dump_json())

        out = await NarrativeAgent(llm=llm).generate(_make_report())

        assert out is not None
        assert len(out.key_findings) >= 3
        assert llm.ainvoke.await_count == 2

    @pytest.mark.asyncio
    async def test_the_feedback_names_the_field_and_the_rule(self) -> None:
        thin = _valid_narrative().model_dump()
        thin["key_findings"] = thin["key_findings"][:1]
        llm = self._llm(json.dumps(thin), _valid_narrative().model_dump_json())

        await NarrativeAgent(llm=llm).generate(_make_report())

        feedback = str(llm.ainvoke.await_args_list[1].args[0][-1].content)
        assert FEEDBACK_PREAMBLE in feedback
        assert "key_findings" in feedback

    @pytest.mark.asyncio
    async def test_a_good_first_answer_costs_no_retry(self) -> None:
        llm = self._llm(_valid_narrative().model_dump_json())

        assert await NarrativeAgent(llm=llm).generate(_make_report()) is not None
        assert llm.ainvoke.await_count == 1

    @pytest.mark.asyncio
    async def test_an_answer_that_stays_off_schema_ships_no_narrative(self) -> None:
        thin = _valid_narrative().model_dump()
        thin["key_findings"] = thin["key_findings"][:1]
        llm = self._llm(json.dumps(thin), json.dumps(thin))

        assert await NarrativeAgent(llm=llm).generate(_make_report()) is None
        assert llm.ainvoke.await_count == 2


class TestNarrativeAgentReturnsNoneOnTotalFailure:
    @pytest.mark.asyncio
    async def test_both_paths_fail_returns_none(self) -> None:
        report = _make_report()
        llm = MagicMock()
        structured = MagicMock()
        structured.ainvoke = AsyncMock(side_effect=Exception("schema bork"))
        llm.with_structured_output.return_value = structured
        llm.ainvoke = AsyncMock(side_effect=Exception("raw call failed"))

        agent = NarrativeAgent(llm=llm)
        out = await agent.generate(report)
        assert out is None

    @pytest.mark.asyncio
    async def test_manual_parse_invalid_json_returns_none(self) -> None:
        report = _make_report()
        llm = MagicMock()
        structured = MagicMock()
        structured.ainvoke = AsyncMock(side_effect=Exception("schema bork"))
        llm.with_structured_output.return_value = structured
        raw_message = MagicMock()
        raw_message.content = "this is not json at all"
        llm.ainvoke = AsyncMock(return_value=raw_message)

        agent = NarrativeAgent(llm=llm)
        out = await agent.generate(report)
        assert out is None


class TestMessageText:
    def test_string_message(self) -> None:
        assert _message_text("hello") == "hello"

    def test_aimessage_like(self) -> None:
        m = MagicMock()
        m.content = "body"
        assert _message_text(m) == "body"

    def test_none(self) -> None:
        assert _message_text(None) == ""

    def test_list_of_parts(self) -> None:
        m = MagicMock()
        m.content = ["hello ", {"text": "world"}]
        assert _message_text(m) == "hello world"


# ---------------------------------------------------------------------------
# Duplicate-key recovery and shape coercion (2026-08-12)
#
# The LLM narrative arm was producing schema-valid output on 0 of 15
# generations. Two causes, both observed rather than guessed: the model emitted
# ``capabilities_narrative`` three times as separate keys of one JSON object
# (JSON's last-wins rule then reduced three paragraphs to one string), and the
# prompt named only two of the six recommendation fields as required.
# ---------------------------------------------------------------------------


def test_repeated_key_becomes_a_list_instead_of_the_last_value_winning() -> None:
    """The exact shape the model emits: one key, three times, in one object."""
    from maljan.reporting.narrative_agent import _parse_keeping_duplicate_keys

    raw = (
        '{"executive_summary": "verdict",'
        ' "capabilities_narrative": "phase one",'
        ' "capabilities_narrative": "phase two",'
        ' "capabilities_narrative": "phase three"}'
    )
    parsed = _parse_keeping_duplicate_keys(raw)
    assert parsed is not None
    assert parsed["capabilities_narrative"] == ["phase one", "phase two", "phase three"]
    assert parsed["executive_summary"] == "verdict"


def test_fenced_json_still_parses() -> None:
    from maljan.reporting.narrative_agent import _parse_keeping_duplicate_keys

    parsed = _parse_keeping_duplicate_keys('```json\n{"a": 1, "a": 2}\n```')
    assert parsed == {"a": [1, 2]}


def test_unparseable_text_defers_rather_than_raising() -> None:
    from maljan.reporting.narrative_agent import _parse_keeping_duplicate_keys

    assert _parse_keeping_duplicate_keys("I could not produce JSON.") is None


def test_single_object_is_wrapped_for_a_list_field() -> None:
    from maljan.reporting.narrative_agent import _coerce_narrative_payload

    out = _coerce_narrative_payload({"key_findings": {"text": "one finding"}})
    assert out["key_findings"] == [{"text": "one finding"}]


def test_coercion_repairs_shape_but_never_invents_content() -> None:
    """A recommendation missing its required fields must still fail validation.

    Shipping an invented remediation step is worse than shipping none, so the
    coercion is allowed to reshape a value and never to supply one.
    """
    import pydantic
    import pytest

    from maljan.reporting.narrative_agent import NarrativeOutput, _coerce_narrative_payload

    payload = _coerce_narrative_payload(
        {
            "executive_summary": "x" * 200,
            "key_findings": [{"text": "a"}, {"text": "b"}, {"text": "c"}],
            # what the model actually returned: the two optional fields only
            "defensive_recommendations": [{"technique_id": "T1055", "detection": "Sysmon 8"}] * 3,
        }
    )
    with pytest.raises(pydantic.ValidationError):
        NarrativeOutput.model_validate(payload)


class TestTheKeyFindingsAreAskedForAsAnExactObject:
    """Two unrelated models answered renamed keys every time until the prompt
    showed the exact object; the key findings are asked for the same way."""

    def test_the_prompt_shows_the_object_and_its_keys_are_the_schema_s(self) -> None:
        from maljan.reporting.narrative_agent import _SYSTEM_PROMPT, EXPECTED_OBJECT

        assert EXPECTED_OBJECT in _SYSTEM_PROMPT
        shown = json.loads(EXPECTED_OBJECT)
        assert set(shown) == set(NarrativeOutput.model_fields)
        assert set(shown["key_findings"][0]) == set(KeyFinding.model_fields)
        assert set(shown["defensive_recommendations"][0]) == set(
            DefensiveRecommendation.model_fields
        )

    def test_the_example_is_a_valid_answer(self) -> None:
        from maljan.reporting.narrative_agent import _SYSTEM_PROMPT, EXAMPLE_OBJECT

        assert EXAMPLE_OBJECT in _SYSTEM_PROMPT
        NarrativeOutput.model_validate(json.loads(EXAMPLE_OBJECT))

    def test_the_prompt_asks_for_estimative_language_and_citations(self) -> None:
        from maljan.reporting.narrative_agent import _SYSTEM_PROMPT

        assert "estimative words" in _SYSTEM_PROMPT
        assert "[ev_0007]" in _SYSTEM_PROMPT
        assert "never introduce a fact nothing above states" in _SYSTEM_PROMPT


class TestAKeyFindingCitesOnlyWhatTheLedgerHolds:
    @staticmethod
    def _report_with_index() -> MalwareReport:
        report = _make_report()
        report.evidence_index = [EvidenceIndexRow(id="ev_0001"), EvidenceIndexRow(id="ev_0002")]
        return report

    @staticmethod
    def _answer(*ids: str) -> str:
        out = _valid_narrative().model_dump()
        out["key_findings"][0]["evidence_ids"] = list(ids)
        return json.dumps(out)

    @staticmethod
    def _llm(*raw_answers: str) -> MagicMock:
        llm = MagicMock()
        structured = MagicMock()
        structured.ainvoke = AsyncMock(side_effect=Exception("schema bork"))
        llm.with_structured_output.return_value = structured
        llm.ainvoke = AsyncMock(side_effect=[MagicMock(content=answer) for answer in raw_answers])
        return llm

    @pytest.mark.asyncio
    async def test_an_unknown_id_is_fed_back_once_naming_it(self) -> None:
        llm = self._llm(self._answer("ev_9999"), self._answer("ev_0002"))
        agent = NarrativeAgent(llm=llm)

        out = await agent.generate(self._report_with_index())

        assert out is not None
        assert out.key_findings[0].evidence_ids == ["ev_0002"]
        feedback = str(llm.ainvoke.await_args_list[1].args[0][-1].content)
        assert "[narrative.ungrounded_finding]" in feedback
        assert "ev_9999" in feedback
        assert agent.validation_tally.unresolved == []

    @pytest.mark.asyncio
    async def test_a_finding_that_keeps_it_is_kept_as_written_and_recorded(self) -> None:
        llm = self._llm(self._answer("ev_9999"), self._answer("ev_9999"))
        agent = NarrativeAgent(llm=llm)

        out = await agent.generate(self._report_with_index())

        assert out is not None, "the summary ships; the finding is recorded beside it"
        assert out.key_findings[0].evidence_ids == ["ev_9999"]
        (row,) = agent.validation_tally.unresolved
        assert row["code"] == "narrative.ungrounded_finding"
        assert row["agent"] == "narrative"

    @pytest.mark.asyncio
    async def test_a_finding_that_cites_nothing_is_not_a_finding(self) -> None:
        llm = self._llm(self._answer())

        assert await NarrativeAgent(llm=llm).generate(self._report_with_index()) is not None
        assert llm.ainvoke.await_count == 1


class TestTheRoundIsSizedFromItsBudget:
    """The narrative round waits as long as its output budget takes at the model's pace."""

    MODEL = "narrative-model"

    class _Named:
        model_name = "narrative-model"

        async def ainvoke(self, messages: Any, **_: Any) -> Any:  # pragma: no cover
            raise RuntimeError("not called")

    def _agent(self, rates: Any, cap: int = 393216, window: int = 0) -> NarrativeAgent:
        return NarrativeAgent(
            llm=self._Named(),  # type: ignore[arg-type]
            output_cap=cap,
            budget_note=f"{cap} tokens — the model's declared maximum output",
            generation_rates=rates,
            window_tokens=window,
        )

    def test_with_no_rate_the_configured_wait_stands(self) -> None:
        from maljan.llm.generation_rate import GenerationRates

        assert self._agent(GenerationRates()).round_timeout(600.0) == 600.0

    def test_a_measured_pace_sizes_every_attempt(self) -> None:
        from maljan.llm.generation_rate import TIMEOUT_MARGIN, GenerationRates
        from maljan.reporting.narrative_agent import NARRATIVE_ATTEMPTS

        rates = GenerationRates()
        rates.observe(self.MODEL, 4000, 100.0, "output tokens over the call's wall clock")
        agent = self._agent(rates)
        with patch(
            "maljan.reporting.narrative_agent.structured_output_supported_for_llm",
            return_value=False,
        ):
            seconds = agent.round_timeout(600.0)

        assert seconds == pytest.approx(NARRATIVE_ATTEMPTS * 393216 / 40 * TIMEOUT_MARGIN)
        row = rates.snapshot()["timeouts"]["narrative:round"]
        assert row["max_tokens"] == 393216
        assert row["budget"].startswith("393216 tokens")

    def test_the_report_node_uses_the_sized_wait(self) -> None:
        from maljan.llm.generation_rate import GenerationRates
        from maljan.pipeline.nodes import _narrative_timeout

        rates = GenerationRates()
        rates.observe(self.MODEL, 4000, 100.0, "output tokens over the call's wall clock")
        agent = self._agent(rates)

        assert _narrative_timeout(agent, _make_report(), "", "") > 1800

    def test_a_call_past_its_window_is_held_to_what_the_window_leaves(self) -> None:
        from langchain_core.messages import HumanMessage

        agent = self._agent(None, cap=16384, window=16384)

        assert agent._call_bound([HumanMessage(content="x" * 3000)]) == 16384 - 1000
        assert self._agent(None, cap=16384, window=0)._call_bound([]) is None

    def test_a_prompt_past_the_room_is_recorded_not_trimmed(self) -> None:
        agent = self._agent(None, cap=4096, window=8192)

        agent._note_room(20000)
        agent._note_room(20000)

        (reason,) = agent.degradations
        assert "prompt (20000 characters) exceeds the 12288" in reason
        assert self._agent(None, cap=4096, window=0).degradations == []
