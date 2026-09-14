"""The report may not be the first place a capability is mentioned.

Run 3's executive summary asserted "active command-and-control communication",
"data exfiltration" and "persistent backdoor access". The whole run had one
technique — T1027, obfuscated files — no network capture, no sandbox report and
three analysts of which two never ran. Nothing in the pipeline objected,
because the narrative round is validated for shape and the shape was fine.

A term whose grounding is absent from the run's techniques, sections and its
analysts' own words is a violation now: fed back once with what the run does
have, and after that recorded unresolved. The prose is never rewritten — a
summary quietly edited by a regular expression is one nobody wrote.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.validation import (
    UNGROUNDED_CAPABILITY_CODE,
    CapabilityGrounding,
    feedback_text,
    narrative_capability_violations,
    section_capability_violations,
    ungrounded_capabilities,
)
from maljan.reporting.models import (
    EvidenceSection,
    FileHashes,
    MalwareReport,
    SampleIdentity,
    TTPMapping,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

_RUN_3_SUMMARY = (
    "The sample maintains active command-and-control communication with its operator, "
    "performs data exfiltration of collected documents, and establishes persistent "
    "backdoor access to the host."
)


def _report(
    techniques: tuple[str, ...] = (),
    sections: tuple[str, ...] = (),
    **fields: Any,
) -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64), file_type="pe"),
        ttp_mappings=[
            TTPMapping(technique_id=tid, technique_name=f"technique {tid}") for tid in techniques
        ],
        sections=[
            EvidenceSection(key=key, title=key.replace("_", " ").title(), kind="text", text="")
            for key in sections
        ],
        **fields,
    )


class TestTheRunThatProducedIt:
    def test_the_run_3_summary_is_ungrounded_on_every_count(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)))

        violations = ungrounded_capabilities(_RUN_3_SUMMARY, grounding)

        assert {v.path for v in violations} == {
            "command_and_control",
            "exfiltration",
            "backdoor",
            "persistence",
        }
        assert {v.code for v in violations} == {UNGROUNDED_CAPABILITY_CODE}

    def test_a_run_with_the_evidence_objects_to_nothing(self) -> None:
        grounding = CapabilityGrounding.from_report(
            _report(techniques=("T1071", "T1041", "T1547"), sections=("network",))
        )

        assert ungrounded_capabilities(_RUN_3_SUMMARY, grounding) == []

    def test_a_sub_technique_grounds_its_parent(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1055.012",)))
        assert ungrounded_capabilities("It performs process injection.", grounding) == []

    def test_a_typed_network_block_grounds_the_channel(self) -> None:
        from maljan.reporting.models import NetworkIOCs

        grounding = CapabilityGrounding.from_report(
            _report(techniques=("T1027",), network=NetworkIOCs())
        )
        assert ungrounded_capabilities("It has a C2 channel.", grounding) == []

    def test_an_analyst_who_said_it_grounds_it(self) -> None:
        """A report is allowed to repeat what its own evidence says, mapped or not."""
        isrs = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="the binary embeds a hard-coded command-and-control host",
                        evidence_ref="ev_0004",
                        confidence=0.7,
                    )
                ],
            )
        }
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)), isrs)

        assert ungrounded_capabilities("It maintains C2 communication.", grounding) == []

    def test_a_section_key_grounds_its_terms(self) -> None:
        grounding = CapabilityGrounding.from_report(
            _report(techniques=("T1027",), sections=("persistence",))
        )
        assert ungrounded_capabilities("It persists across reboots.", grounding) == []


class TestWhatTheFeedbackSays:
    def test_it_names_the_term_and_what_the_run_has(self) -> None:
        grounding = CapabilityGrounding.from_report(
            _report(techniques=("T1027",), sections=("strings",))
        )

        violations = ungrounded_capabilities("It exfiltrates documents.", grounding)
        text = feedback_text(violations)

        assert "exfiltration" in text
        assert "T1027" in text, "the model is told what the run did establish"
        assert "strings" in text
        assert "Describe what was found, or drop the claim." in text


class TestTheGuardIsNarrow:
    def test_prose_with_no_capability_word_is_left_alone(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)))
        text = "The sample is a 32-bit PE with a high-entropy section and no valid signature."
        assert ungrounded_capabilities(text, grounding) == []

    def test_an_unreadable_run_judges_nothing(self) -> None:
        """A grounding that could not be read must not fail every term."""
        assert ungrounded_capabilities(_RUN_3_SUMMARY, CapabilityGrounding()) == []

    def test_empty_prose_is_not_a_claim(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)))
        assert ungrounded_capabilities("   ", grounding) == []


class TestTheTwoProducersReadTheirOwnAnswers:
    def test_the_narrative_payload_is_read_field_by_field(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)))
        payload = {
            "executive_summary": "A packed dropper with obfuscated strings.",
            "capabilities_narrative": ["It exfiltrates browser credentials."],
            "defensive_recommendations": [],
        }

        violations = narrative_capability_violations(payload, grounding)

        assert {v.path for v in violations} == {"exfiltration", "credential_theft"}

    def test_a_narrative_payload_that_is_nothing_is_no_violation(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)))
        assert narrative_capability_violations(None, grounding) == []

    def test_a_section_answer_is_read_through_its_nesting(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)))
        payload = {
            "text": "In conclusion:",
            "channels": [{"protocol": "https", "note": "used for command and control"}],
        }

        violations = section_capability_violations(payload, grounding)

        assert [v.path for v in violations] == ["command_and_control"]


class TestTheSummaryIsKeptAndTheTermsRecorded:
    """Deleting an over-claiming summary would leave the report with neither
    the claim nor a record of it, and rewriting it would put words in the
    model's mouth. It ships, with the terms on the run's record."""

    @staticmethod
    def _narrative_json(summary: str) -> str:
        import json

        return json.dumps(
            {
                "executive_summary": summary,
                "capabilities_narrative": ["one", "two", "three"],
                "defensive_recommendations": [
                    {
                        "category": "edr_hunting",
                        "action": f"Hunt for the indicator number {n}.",
                        "rationale": "Because the evidence in this run says so.",
                        "priority": "P1",
                    }
                    for n in range(3)
                ],
            }
        )

    def _agent(self, answers: list[str]) -> Any:
        from unittest.mock import MagicMock

        from maljan.reporting.narrative_agent import NarrativeAgent

        class _LLM:
            async def ainvoke(self, messages: Any) -> Any:
                return MagicMock(content=answers.pop(0))

        return NarrativeAgent(llm=_LLM())  # type: ignore[arg-type]

    def _run(self, agent: Any, report: MalwareReport) -> Any:
        import asyncio

        from maljan.llm import registry

        original = registry.structured_output_supported_for_llm
        registry.structured_output_supported_for_llm = lambda _llm: False  # type: ignore[assignment]
        try:
            import maljan.reporting.narrative_agent as module

            module.structured_output_supported_for_llm = lambda _llm: False  # type: ignore[assignment]
            return asyncio.run(agent.generate(report))
        finally:
            registry.structured_output_supported_for_llm = original  # type: ignore[assignment]

    def test_a_corrected_second_answer_costs_one_retry_and_no_leftovers(self) -> None:
        report = _report(techniques=("T1027",))
        grounded = (
            "The sample is packed and resolves its imports at runtime, with obfuscated "
            "strings throughout. No further behaviour was observed in this run at all."
        )
        agent = self._agent([self._narrative_json(_RUN_3_SUMMARY), self._narrative_json(grounded)])

        output = self._run(agent, report)

        assert output is not None
        assert output.executive_summary == grounded
        assert agent.validation_tally.retries == 1
        assert agent.validation_tally.by_code[UNGROUNDED_CAPABILITY_CODE] == 4
        assert agent.validation_tally.unresolved == []

    def test_a_second_over_claim_is_kept_and_recorded(self) -> None:
        report = _report(techniques=("T1027",))
        agent = self._agent(
            [self._narrative_json(_RUN_3_SUMMARY), self._narrative_json(_RUN_3_SUMMARY)]
        )

        output = self._run(agent, report)

        assert output is not None, "the summary is kept, not dropped"
        assert output.executive_summary == _RUN_3_SUMMARY, "and it is not rewritten"
        rows = agent.validation_tally.unresolved
        assert {row["code"] for row in rows} == {UNGROUNDED_CAPABILITY_CODE}
        assert {row["agent"] for row in rows} == {"narrative"}
        assert len(rows) == 4
