"""Unit tests for ``NarrativeAgent`` and ``NarrativeOutput``.

The agent is exercised with three LLM stand-ins:

  - a structured-output mock that returns a valid ``NarrativeOutput``,
  - a structured-output mock that raises (forcing the manual-parse path),
  - a manual-parse path that returns junk (final fallback → ``None``).

We also pin the prompt builder so we catch unintentional schema drift.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import ValidationError

from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import DefensiveRecommendation, MalwareReport
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
    return MalwareReportBuilder(
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
        cascade_summary=overrides.pop("cascade_summary", None),
        malware_category=overrides.pop("malware_category", "ransomware"),
    ).build_deterministic()


def _valid_narrative() -> NarrativeOutput:
    return NarrativeOutput(
        executive_summary=(
            "Sample is a Windows ransomware variant exhibiting registry-based "
            "persistence (T1547.001) and TLS C2 to 1.2.3.4. Confidence is high "
            "given corroborated dynamic + network evidence." * 1
        ),
        capabilities_narrative=[
            "Persistence: writes Run key (T1547.001) under HKLM Software\\Run.",
            "Command and Control: outbound TLS to 1.2.3.4 over port 443.",
            "Defense Evasion: short execution chain with limited debug surface.",
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
        assert len(rebuilt.capabilities_narrative) == 3

    def test_too_few_paragraphs_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeOutput(
                executive_summary="A" * 200,
                capabilities_narrative=["only one"],
                defensive_recommendations=_valid_narrative().defensive_recommendations,
            )

    def test_executive_summary_min_length(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeOutput(
                executive_summary="too short",
                capabilities_narrative=_valid_narrative().capabilities_narrative,
                defensive_recommendations=_valid_narrative().defensive_recommendations,
            )

    def test_invalid_priority_rejected(self) -> None:
        with pytest.raises(ValidationError):
            NarrativeOutput.model_validate(
                {
                    "executive_summary": "A" * 200,
                    "capabilities_narrative": ["a", "b", "c"],
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
        assert "Top ATT&CK techniques" in text

    def test_prompt_truncates_evidence_quotes(self) -> None:
        from maljan.reporting.models import TTPMapping

        report = _make_report()
        long_quote = "x" * 500
        report.ttp_mappings = [
            TTPMapping(
                technique_id="T1547.001",
                technique_name="Registry Run Keys",
                evidence_quotes=[long_quote],
                confidence=0.9,
            )
        ]
        text = build_prompt_text(report)
        assert long_quote not in text  # truncated
        assert "x" * 119 in text  # head preserved

    def test_prompt_caps_lists(self) -> None:
        report = _make_report()
        # Generate fake TTPs above the 8 cap.
        from maljan.reporting.models import TTPMapping

        report.ttp_mappings = [
            TTPMapping(technique_id=f"T999{i}", technique_name=f"Fake-{i}") for i in range(20)
        ]
        text = build_prompt_text(report)
        assert "T9990" in text  # first one
        assert "T9997" in text  # 8th index 7
        assert "T9998" not in text  # over the cap


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
        llm.with_structured_output.assert_called_once_with(NarrativeOutput)


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
        assert len(out.capabilities_narrative) >= 3


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


def test_single_string_is_wrapped_for_a_list_field() -> None:
    from maljan.reporting.narrative_agent import _coerce_narrative_payload

    out = _coerce_narrative_payload({"capabilities_narrative": "one paragraph"})
    assert out["capabilities_narrative"] == ["one paragraph"]


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
            "capabilities_narrative": ["a", "b", "c"],
            # what the model actually returned: the two optional fields only
            "defensive_recommendations": [{"technique_id": "T1055", "detection": "Sysmon 8"}] * 3,
        }
    )
    with pytest.raises(pydantic.ValidationError):
        NarrativeOutput.model_validate(payload)
