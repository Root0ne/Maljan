"""A technique claim that admits it has no evidence is asked for some.

From a live run on a signed PuTTY: the static analyst wrote sixteen claims of
the form "The sample may exhibit process injection (T1055) | Evidence: no
specific imports were provided; this claim is speculative | Confidence 0.10".
Eighteen technique ids on a signed binary, every one of them citing nothing,
and the judge read them as eighteen techniques and said Malware.

The analyst is asked once to name the ledger entry it read the technique from,
or to drop the technique. Nothing here removes the claim or the id: a claim
that survives the turn is recorded, and the judge is told which techniques
nothing in the run establishes.
"""

from __future__ import annotations

from typing import Any

from maljan.pipeline.validation import (
    UNGROUNDED_TECHNIQUE_CODE,
    ungrounded_technique_note,
    validate_isr,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

LEDGER = ["ev_0001", "ev_0002"]


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="static", domain="static", claims=list(claims))


def _claim(
    evidence: str, technique: str | None = "T1055", text: str = "it injects"
) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=evidence, confidence=0.4, technique_id=technique)


def _codes(violations: list[Any]) -> set[str]:
    return {v.code for v in violations}


class TestWhatIsFlagged:
    def test_a_technique_citing_no_entry_is_a_violation(self) -> None:
        isr = _isr(_claim("no specific imports were provided; this claim is speculative"))

        violations = validate_isr(isr, ledger_ids=LEDGER)

        assert UNGROUNDED_TECHNIQUE_CODE in _codes(violations)

    def test_the_message_names_the_technique_and_what_can_be_cited(self) -> None:
        isr = _isr(_claim("this claim is speculative"))

        violations = validate_isr(isr, ledger_ids=LEDGER)
        message = next(v.message for v in violations if v.code == UNGROUNDED_TECHNIQUE_CODE)

        assert "T1055" in message
        assert "ev_0001" in message
        assert "drop the technique" in message

    def test_the_claim_and_its_id_are_left_exactly_as_written(self) -> None:
        """The validator reports; it never edits an analyst's answer."""
        claim = _claim("speculative")
        isr = _isr(claim)

        validate_isr(isr, ledger_ids=LEDGER)

        assert isr.claims[0].technique_id == "T1055"
        assert isr.claims[0].claim == "it injects"


class TestWhatIsNot:
    def test_a_cited_entry_settles_it(self) -> None:
        isr = _isr(_claim("the import table in ev_0002 lists VirtualAllocEx"))

        assert UNGROUNDED_TECHNIQUE_CODE not in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_the_id_is_read_whatever_its_case(self) -> None:
        """The counter issues lowercase; a model that writes it back in capitals
        is citing the same entry, and a false flag costs a feedback turn."""
        isr = _isr(_claim("the import table [EV_0002] lists VirtualAllocEx"))

        assert UNGROUNDED_TECHNIQUE_CODE not in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_an_id_this_run_never_issued_is_not_a_citation(self) -> None:
        """The feedback names three real ids, so the shape of one proves nothing."""
        isr = _isr(_claim("the import table [ev_9999] lists VirtualAllocEx"))

        assert UNGROUNDED_TECHNIQUE_CODE in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_an_id_in_the_claim_prose_is_not_a_citation(self) -> None:
        """ "As ev_0001 does not show, this may be injection" is not a citation.

        The claim format asks for the id on the evidence line, and reading the
        prose for one is how a validator stops validating.
        """
        isr = _isr(_claim("imports read from the PE header", text="ev_0001 shows VirtualAllocEx"))

        assert UNGROUNDED_TECHNIQUE_CODE in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_a_findings_block_citing_the_same_technique_settles_it(self) -> None:
        """The analyst already answered by machine; asking again is a wasted turn.

        This is the honest claim the prescribed format produces: an artifact
        reference in prose, and the ledger id in the structured channel
        against the same technique.
        """
        from maljan.schemas.isr_models import Finding

        isr = _isr(_claim("API call: VirtualAllocEx @ 0x401234 (import table)"))
        isr.findings = [
            Finding(
                title="Allocates memory in a remote process",
                technique_ids=["T1055"],
                confidence=0.8,
                evidence_ids=["ev_0002"],
            )
        ]

        assert UNGROUNDED_TECHNIQUE_CODE not in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_a_findings_block_about_another_technique_does_not(self) -> None:
        from maljan.schemas.isr_models import Finding

        isr = _isr(_claim("API call: VirtualAllocEx @ 0x401234"))
        isr.findings = [
            Finding(title="Obfuscated strings", technique_ids=["T1027"], evidence_ids=["ev_0002"])
        ]

        assert UNGROUNDED_TECHNIQUE_CODE in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_a_findings_block_citing_an_id_from_another_run_does_not(self) -> None:
        from maljan.schemas.isr_models import Finding

        isr = _isr(_claim("API call: VirtualAllocEx @ 0x401234"))
        isr.findings = [
            Finding(title="Injection", technique_ids=["T1055"], evidence_ids=["ev_0099"])
        ]

        assert UNGROUNDED_TECHNIQUE_CODE in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_a_findings_block_that_cites_no_id_does_not_either(self) -> None:
        from maljan.schemas.isr_models import Finding

        isr = _isr(_claim("API call: VirtualAllocEx @ 0x401234"))
        isr.findings = [Finding(title="Injection", technique_ids=["T1055"], evidence_ids=[])]

        assert UNGROUNDED_TECHNIQUE_CODE in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_the_claim_format_asks_for_the_id_the_checker_wants(self) -> None:
        """The requirement and the instruction have to be the same sentence."""
        from maljan.agents.prompt_fragments import CLAIM_FORMAT_FRAGMENT

        assert "EVIDENCE:" in CLAIM_FORMAT_FRAGMENT
        assert "ev_0002" in CLAIM_FORMAT_FRAGMENT
        assert "naming the tool result you read it from" in CLAIM_FORMAT_FRAGMENT

    def test_the_view_prompt_and_the_schema_field_ask_for_the_same_id(self) -> None:
        """The two places a reader looks for the format after the analysts."""
        from maljan.agents.base_agent import _VIEW_SYSTEM
        from maljan.schemas.isr_models import ClaimEvidence

        assert "naming the tool result you read it from" in _VIEW_SYSTEM
        assert "[ev_0002]" in _VIEW_SYSTEM
        assert "ev_0002" in str(ClaimEvidence.model_fields["evidence_ref"].description)

    def test_every_analyst_prompt_uses_that_one_fragment(self) -> None:
        import inspect

        from maljan.agents import (
            configurable_analyst,
            dynamic_analyst,
            network_analyst,
            static_analyst,
        )

        for module in (static_analyst, dynamic_analyst, network_analyst, configurable_analyst):
            source = inspect.getsource(module)
            assert "CLAIM_FORMAT_FRAGMENT" in source, module.__name__
            assert "EVIDENCE: <artifact reference>" not in source, module.__name__

    def test_a_claim_with_no_technique_is_not_this_validator_s_business(self) -> None:
        """An uncited observation is what ``isr.empty_evidence`` is for."""
        isr = _isr(_claim("the binary is signed", technique=None))

        assert UNGROUNDED_TECHNIQUE_CODE not in _codes(validate_isr(isr, ledger_ids=LEDGER))

    def test_an_analyst_with_an_empty_ledger_is_exempt(self) -> None:
        """A measurement profile has no tools, so it has nothing to cite."""
        isr = _isr(_claim("this claim is speculative"))

        assert UNGROUNDED_TECHNIQUE_CODE not in _codes(validate_isr(isr, ledger_ids=[]))
        assert UNGROUNDED_TECHNIQUE_CODE not in _codes(validate_isr(isr))


class TestTheEvidenceLineKeepsItsId:
    """The format puts the id at the end of a line whose front is prose, and
    the ISR field is cut at a fixed width: the one shape the format asks for
    is the one the cut used to break."""

    def _parsers(self) -> list[Any]:
        from maljan.agents.base_agent import parse_structured_claims
        from maljan.agents.static_analyst import _parse_claim_blocks

        return [parse_structured_claims, _parse_claim_blocks]

    def _report(self, evidence: str) -> str:
        return f"CLAIM: it injects\nEVIDENCE: {evidence}\nCONFIDENCE: 0.8\nTECHNIQUE: T1055\n---"

    def test_an_id_past_the_cut_still_reaches_the_checker(self) -> None:
        evidence = "the import table lists VirtualAllocEx " * 6 + "[ev_0002]"
        assert len(evidence) > 200

        for parse in self._parsers():
            (claim,) = parse(self._report(evidence))
            assert "ev_0002" in claim.evidence_ref, parse.__name__
            assert UNGROUNDED_TECHNIQUE_CODE not in _codes(
                validate_isr(_isr(claim), ledger_ids=LEDGER)
            )

    def test_a_line_that_fits_is_stored_as_written(self) -> None:
        for parse in self._parsers():
            (claim,) = parse(self._report("import table [ev_0002]"))
            assert claim.evidence_ref == "import table [ev_0002]"

    def test_an_id_the_cut_sliced_through_is_not_left_half_written(self) -> None:
        """The field is what the report prints and what memory embeds."""
        from maljan.agents.base_agent import evidence_ref_text

        stored = evidence_ref_text("y" * 196 + "[ev_0007]")

        assert "[ev_ " not in stored
        assert stored.endswith("[ev_0007]")
        assert stored.count("ev_0007") == 1

    def test_the_ids_written_back_are_bounded(self) -> None:
        from maljan.agents.base_agent import _EVIDENCE_REF_CHARS, evidence_ref_text

        line = "x" * 200 + " ".join(f"[ev_{n:04d}]" for n in range(1, 60))

        stored = evidence_ref_text(line)

        assert len(stored) <= _EVIDENCE_REF_CHARS + 40
        assert "ev_0001" in stored

    def test_an_id_before_the_cut_is_not_written_twice(self) -> None:
        evidence = "[ev_0002] " + "the import table lists VirtualAllocEx " * 6

        for parse in self._parsers():
            (claim,) = parse(self._report(evidence))
            assert claim.evidence_ref.count("ev_0002") == 1


class TestTheAnalystIsAskedOnce:
    """The loop that asks: one feedback turn, and the survivor is recorded."""

    def _agent(self, answers: list[str], entries: list[str]) -> Any:
        from unittest.mock import MagicMock

        from maljan.agents.base_agent import BaseAnalyst
        from maljan.schemas.evidence import LedgerEntry

        class _Analyst(BaseAnalyst):
            """The abstract halves this test does not exercise."""

            def analyze(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
                raise NotImplementedError

            def revise(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
                raise NotImplementedError

        agent = _Analyst.__new__(_Analyst)
        agent.name = "static"
        agent.logger = MagicMock()
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent._findings_buffer = []
        agent._artifacts_buffer = []
        agent._evidence_entries = [
            LedgerEntry(id=entry, agent="static", tool="pe_info") for entry in entries
        ]
        agent._answers = answers
        agent._system_prompt = lambda _evidence: "you are a static analyst"  # type: ignore[method-assign]
        agent._truncate_input = lambda text, *a, **k: text  # type: ignore[method-assign]
        agent._capture_findings = lambda text: text  # type: ignore[method-assign]

        def _invoke(turns: Any, timeout: int) -> Any:
            return MagicMock(content=agent._answers.pop(0))

        agent._invoke_llm_with_timeout = _invoke  # type: ignore[method-assign]
        return agent

    @staticmethod
    def _answer(evidence: str) -> str:
        return f"CLAIM: it injects code\nEVIDENCE: {evidence}\nCONFIDENCE: 0.4\nTECHNIQUE: T1055\n"

    def _run(self, agent: Any, isr: AgentISR) -> AgentISR:
        from unittest.mock import patch

        def _parse(text: str, revision_round: int = 0) -> AgentISR:
            evidence = text.split("EVIDENCE:", 1)[1].split("\n", 1)[0].strip()
            return _isr(_claim(evidence))

        agent._text_to_isr = _parse  # type: ignore[method-assign]
        with patch("maljan.agents.base_agent.get_settings") as settings:
            settings.return_value.react_agent_timeout = 60
            settings.return_value.react_agent_timeout_overrides = {}
            return agent._validate_isr(isr, "the evidence the analyst read")

    def test_a_corrected_second_answer_costs_one_retry_and_no_leftovers(self) -> None:
        agent = self._agent([self._answer("ev_0002 lists VirtualAllocEx")], ["ev_0001", "ev_0002"])

        revised = self._run(agent, _isr(_claim("speculative")))

        assert agent.validation_retries == 1
        assert agent.validation_fed_back.get(UNGROUNDED_TECHNIQUE_CODE) == 1
        assert agent.validation_findings == []
        assert "ev_0002" in revised.claims[0].evidence_ref

    def test_a_second_answer_that_cites_nothing_is_recorded_unresolved(self) -> None:
        agent = self._agent([self._answer("still speculative")], ["ev_0001"])

        revised = self._run(agent, _isr(_claim("speculative")))

        assert agent.validation_retries == 1
        assert [row.code for row in agent.validation_findings] == [UNGROUNDED_TECHNIQUE_CODE]
        assert revised.claims[0].technique_id == "T1055", "the id the analyst wrote is kept"


class TestWhatTheJudgeIsTold:
    def test_the_note_names_the_techniques_that_survived(self) -> None:
        findings = {
            "static": [
                {
                    "code": UNGROUNDED_TECHNIQUE_CODE,
                    "message": "TECHNIQUE T1055 cites no evidence id from this run.",
                    "path": "static.claims[0]",
                },
                {
                    "code": UNGROUNDED_TECHNIQUE_CODE,
                    "message": "TECHNIQUE T1027 cites no evidence id from this run.",
                    "path": "static.claims[1]",
                },
                {"code": "isr.empty_evidence", "message": "no evidence", "path": "x"},
            ]
        }

        note = ungrounded_technique_note(findings)

        assert "T1055" in note and "T1027" in note
        assert note.startswith("technique claims citing no evidence")

    def test_a_run_with_none_says_nothing(self) -> None:
        assert ungrounded_technique_note({}) == ""
        assert ungrounded_technique_note(None) == ""
        assert ungrounded_technique_note({"static": [{"code": "isr.empty_evidence"}]}) == ""

    def test_the_judge_node_folds_it_into_the_degradation_reasons(self) -> None:
        import inspect

        from maljan.pipeline import nodes

        source = inspect.getsource(nodes)

        assert 'ungrounded_technique_note(state.get("validation_findings"))' in source
