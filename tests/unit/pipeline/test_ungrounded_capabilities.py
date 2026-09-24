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

import pytest

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

    def test_an_observed_network_block_grounds_the_channel(self) -> None:
        """A block something other than the string sweep recorded a row of;
        an empty block, or one of swept rows only, grounds nothing."""
        from maljan.reporting.models import NetworkDomain, NetworkIOCs

        observed = NetworkIOCs(domains=[NetworkDomain(fqdn="gate9.example.org", source="sandbox")])
        grounding = CapabilityGrounding.from_report(
            _report(techniques=("T1027",), network=observed)
        )
        assert ungrounded_capabilities("It has a C2 channel.", grounding) == []

        empty = CapabilityGrounding.from_report(
            _report(techniques=("T1027",), network=NetworkIOCs())
        )
        assert ungrounded_capabilities("It has a C2 channel.", empty)

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


class TestAReportOfAbsence:
    """Saying a capability was *not* found is the prose this validator wants.

    Matched by bare regex, every one of these sentences was recorded as an
    over-claim: the retry then argued against a correct negative, and a term
    that survived reached the run summary as "the text claims command and
    control" for a report that said the opposite.
    """

    def _thin(self) -> CapabilityGrounding:
        return CapabilityGrounding.from_report(_report(techniques=("T1027",)))

    def test_no_persistence_and_no_exfiltration_is_not_a_claim(self) -> None:
        text = "No persistence mechanism was observed and the sample does not exfiltrate data."
        assert ungrounded_capabilities(text, self._thin()) == []

    def test_no_evidence_of_command_and_control_is_not_a_claim(self) -> None:
        text = "There is no evidence of command-and-control communication."
        assert ungrounded_capabilities(text, self._thin()) == []

    def test_one_cue_covers_both_terms_of_its_own_clause(self) -> None:
        text = "The sample contains no keylogging or credential theft functionality."
        assert ungrounded_capabilities(text, self._thin()) == []

    def test_a_claim_after_the_clause_ends_is_still_a_claim(self) -> None:
        """A cue governs its clause, not the rest of the sentence."""
        text = "No persistence was observed; the sample injects code into another process."
        assert {v.path for v in ungrounded_capabilities(text, self._thin())} == {
            "process_injection"
        }

    def test_a_contrast_word_ends_the_clause_too(self) -> None:
        text = "The sample does not exfiltrate data, but it maintains a C2 channel."
        assert {v.path for v in ungrounded_capabilities(text, self._thin())} == {
            "command_and_control"
        }

    def test_a_parenthetical_does_not_cut_the_cue_off_from_its_term(self) -> None:
        """A comma opens an aside, it does not end the statement.

        Treating it as a clause boundary threw the cue away and re-flagged the
        honest negative, which is the failure this whole rule exists to stop.
        """
        text = "The loader does not, in any sandbox run, establish command-and-control."
        assert ungrounded_capabilities(text, self._thin()) == []

    def test_no_doubt_asserts_the_claim_rather_than_denying_it(self) -> None:
        text = "There is no doubt that the sample exfiltrates collected data."
        assert {v.path for v in ungrounded_capabilities(text, self._thin())} == {"exfiltration"}

    def test_not_only_is_two_claims_and_neither_is_cleared(self) -> None:
        text = "Not only does it persist, it also steals credentials."
        assert {v.path for v in ungrounded_capabilities(text, self._thin())} == {
            "persistence",
            "credential_theft",
        }

    def test_a_free_service_is_not_an_absence(self) -> None:
        """``free`` reads as a cue and is one only in "free of"."""
        text = "The sample uses a free dynamic-DNS host for command and control."
        assert {v.path for v in ungrounded_capabilities(text, self._thin())} == {
            "command_and_control"
        }

    def test_the_same_word_claimed_elsewhere_is_still_reported(self) -> None:
        """One honest negative does not license the claim in the next sentence."""
        text = "No exfiltration was observed. The sample exfiltrates collected documents."
        assert {v.path for v in ungrounded_capabilities(text, self._thin())} == {"exfiltration"}


class TestTheKnownLimitsOfTheWindow:
    """What the two rules cost, pinned so a later change measures itself.

    Both err toward the answer that spends a feedback turn rather than the one
    that clears a real over-claim, which is the direction a validator against
    over-claiming should fail in.
    """

    def _thin(self) -> CapabilityGrounding:
        return CapabilityGrounding.from_report(_report(techniques=("T1027",)))

    def test_a_comma_splice_hides_the_second_claim(self) -> None:
        """The comma is not a clause break, so the cue still reaches across it.

        The alternative re-flagged "does not, in any sandbox run, establish
        command-and-control", which is the honest sentence the validator wants.
        """
        text = "No persistence was observed, the sample injects code into explorer.exe"

        assert ungrounded_capabilities(text, self._thin()) == []

    def test_the_last_item_of_a_long_negative_list_is_still_flagged(self) -> None:
        """The cue is further back than the window reaches."""
        text = "There is no evidence of keylogging, credential theft, or exfiltration."

        assert {v.path for v in ungrounded_capabilities(text, self._thin())} == {"exfiltration"}


class TestWhatANegationReaches:
    """A negation governs the term it precedes in its own clause, and nothing past it."""

    def _thin(self) -> CapabilityGrounding:
        return CapabilityGrounding.from_report(_report(techniques=("T1082",)))

    def _paths(self, text: str) -> set[str]:
        return {v.path for v in ungrounded_capabilities(text, self._thin())}

    def test_does_not_perform_is_a_negation(self) -> None:
        assert self._paths("The sample does not perform lateral movement.") == set()

    def test_the_term_a_purpose_names_is_negated(self) -> None:
        assert self._paths("Isolate any host running it to prevent lateral movement.") == set()

    def test_the_term_as_the_subject_of_is_absent_is_negated(self) -> None:
        assert self._paths("Lateral movement is absent from the recorded evidence.") == set()

    @pytest.mark.parametrize(
        ("text", "path"),
        [
            (
                "It deletes shadow copies to prevent recovery and encrypts every document.",
                "encryption",
            ),
            (
                "It compresses the data to avoid detection and exfiltrates it over HTTPS.",
                "exfiltration",
            ),
            (
                "It disables the firewall to block defenders, then performs lateral movement.",
                "lateral_movement",
            ),
            (
                "It uses process hollowing to avoid detection, injecting into explorer.exe.",
                "process_injection",
            ),
            (
                "No indication of a debugger check was found, as the sample itself harvests "
                "stored credentials from browsers.",
                "credential_theft",
            ),
            (
                "There are no signs of packing or anti-analysis code in this binary, which "
                "exfiltrates the collected files over FTP.",
                "exfiltration",
            ),
            ("Persistence is missing a cleanup routine and uses a scheduled task.", "persistence"),
            (
                "Behavioural confirmation of lateral movement is absent from the evidence.",
                "lateral_movement",
            ),
        ],
    )
    def test_a_claim_past_the_negation_is_still_flagged(self, text: str, path: str) -> None:
        assert path in self._paths(text)


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
    def test_the_narrative_payload_is_read_field_by_field_key_findings_included(self) -> None:
        grounding = CapabilityGrounding.from_report(_report(techniques=("T1027",)))
        payload = {
            "executive_summary": "A packed dropper with obfuscated strings.",
            "key_findings": [{"text": "It exfiltrates browser credentials.", "evidence_ids": []}],
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
                "key_findings": [{"text": "one"}, {"text": "two"}, {"text": "three"}],
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

    def _run(self, agent: Any, report: MalwareReport, isr_reports: Any = None) -> Any:
        import asyncio

        from maljan.llm import registry

        original = registry.structured_output_supported_for_llm
        registry.structured_output_supported_for_llm = lambda _llm: False  # type: ignore[assignment]
        try:
            import maljan.reporting.narrative_agent as module

            module.structured_output_supported_for_llm = lambda _llm: False  # type: ignore[assignment]
            return asyncio.run(agent.generate(report, isr_reports))
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

    def test_an_analysts_own_word_grounds_the_narrative_round(self) -> None:
        """The narrative is graded on the grounding the composer is graded on.

        The analysts' words are one of the three sources, and the composer has
        always been given them. Without them here, a capability an analyst
        stated in a claim was a violation on the narrative and a pass on the
        composer for one run — and the round spent its retry on it.
        """
        report = _report(techniques=("T1027",))
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
        summary = (
            "The sample embeds a hard-coded command-and-control host in its strings, "
            "which is the whole of what this run established about its network use."
        )
        agent = self._agent([self._narrative_json(summary)])

        output = self._run(agent, report, isrs)

        assert output is not None
        assert output.executive_summary == summary
        assert agent.validation_tally.retries == 0, "the analyst had already said it"
        assert agent.validation_tally.unresolved == []
