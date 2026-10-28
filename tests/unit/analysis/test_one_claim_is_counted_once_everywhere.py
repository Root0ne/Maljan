"""A claim mapped to several techniques is one claim on every surface (T-424).

A block whose TECHNIQUE line listed several ids is read as one claim per id
(``validation.claim_block_indexes``). The report already numbers and counts it
once; the run summary's mean confidence, the ISR summary the mediator and the
judge read, and the debate facts that resolve the mediator's "claim N" now do
too.
"""

from __future__ import annotations

import json
import pathlib
from types import SimpleNamespace

from maljan.agents.judge_agent import verdict_report_parts
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.debate_facts import ledger_count_facts
from maljan.pipeline.nodes import (
    answer_with_retry_additions,
    retry_additions_report,
    retry_additions_sentence,
)
from maljan.pipeline.validation import count_claim_blocks, mark_claims_citing_only_failed_calls
from maljan.schemas.isr_models import (
    ABSENCE_TECHNIQUE_MARKER,
    UNVERIFIED_TECHNIQUE_MARKER,
    AgentISR,
    ClaimEvidence,
    retry_added_marker,
)

NAMES = ["static", "dynamic", "network"]

# The two technique notes as both surfaces print them; the console's
# (``reportProse.ts``) is pinned against the same file by its vitest.
MARKERS = json.loads(
    (
        pathlib.Path(__file__).resolve().parents[2]
        / "fixtures"
        / "golden"
        / "technique_markers.json"
    ).read_text(encoding="utf-8")
)


def _split_isr(*, read: bool = True) -> AgentISR:
    """One block listing three techniques at 0.9, read as three claims, then one claim at 0.3.

    ``read`` records each claim's block as the reader does; without it the
    block is read from the claims' words.
    """
    sentence = "Routine 0x7fa8 calls GetComputerNameExA for the host."
    split = [
        ClaimEvidence(claim=sentence, evidence_ref="[ev_0001]", confidence=0.9, technique_id=tid)
        for tid in ("T1082", "T1016", "T1033")
    ]
    plain = ClaimEvidence(
        claim="Routine 0x1c38 walks the process list.",
        evidence_ref="[ev_0002]",
        confidence=0.3,
        technique_id="T1057",
    )
    if read:
        for claim in split:
            claim.note_block(0)
        plain.note_block(1)
    return AgentISR(agent_id="static", domain="static", claims=[*split, plain])


class TestTheMeanConfidenceCountsEachClaimOnce:
    def test_a_split_claim_weighs_as_one_claim(self) -> None:
        # Copy by copy it was (0.9 * 3 + 0.3) / 4 = 0.75.
        assert abs(_split_isr().mean_confidence - 0.6) < 1e-9

    def test_a_split_claim_built_without_the_reader_weighs_as_one_claim(self) -> None:
        assert abs(_split_isr(read=False).mean_confidence - 0.6) < 1e-9

    def test_the_run_summary_row_counts_it_once(self) -> None:
        summary = RunSummaryBuilder(start_time=0.0).set_isr_stats({"static": _split_isr()})

        (stats,) = summary._agent_stats
        assert stats.claim_count == 2
        assert abs(stats.mean_confidence - 0.6) < 1e-9


class TestTheSummaryNumbersEachClaimOnce:
    def test_a_split_claim_is_one_line_with_its_techniques_together(self) -> None:
        text = _split_isr().to_text_summary()

        assert "Mean confidence: 0.60" in text
        claim_lines = [line.strip() for line in text.splitlines() if "Claim " in line]
        assert len(claim_lines) == 2
        assert claim_lines[0].startswith(
            "Claim 1: Routine 0x7fa8 calls GetComputerNameExA for the host. (T1082, T1016, T1033)"
        )
        assert claim_lines[1].startswith("Claim 2: Routine 0x1c38 walks the process list. (T1057)")

    def test_each_technique_keeps_its_own_marker(self) -> None:
        isr = _split_isr()
        isr.claims[1].technique_id_valid = False
        isr.claims[2].kept_after_absence_question = True

        text = isr.to_text_summary()

        assert (
            f"(T1082, T1016 — {UNVERIFIED_TECHNIQUE_MARKER}, T1033 — {ABSENCE_TECHNIQUE_MARKER})"
            in text
        )


class TestTheDebateFactsResolveAClaimByItsBlock:
    def test_claim_2_after_a_split_claim_is_the_second_block(self) -> None:
        # Copy by copy "claim 2" was the split block's second copy, citing
        # ev_0001; by block it is the claim citing ev_0002.
        entries = [
            {"id": "ev_0001", "tool": "imports", "structured": {"total": 7}},
            {"id": "ev_0002", "tool": "processes", "structured": {"total": 12}},
        ]

        facts = ledger_count_facts(
            ["STATIC claim 2 counts 12 processes."], {"static": _split_isr()}, entries, NAMES
        )

        assert len(facts) == 1 and "ev_0002" in facts[0] and "total = 12" in facts[0]
        assert "ev_0001" not in facts[0]

    def test_a_number_past_the_last_block_resolves_to_no_claim(self) -> None:
        entries = [{"id": "ev_0002", "tool": "processes", "structured": {"total": 12}}]

        facts = ledger_count_facts(
            ["STATIC claim 4 counts 12 processes."], {"static": _split_isr()}, entries, NAMES
        )

        assert facts == []


def _read(text: str, tid: str, block: int, ev: str = "[ev_0003]") -> ClaimEvidence:
    claim = ClaimEvidence(claim=text, evidence_ref=ev, confidence=0.8, technique_id=tid)
    claim.note_block(block)
    return claim


class TestARetryAdditionIsNamedByItsBlock:
    def test_after_a_split_claim_in_force_the_added_claim_is_the_next_block(self) -> None:
        in_force = _split_isr()
        retried = AgentISR(
            agent_id="static",
            domain="static",
            claims=[_read("Creates the mutex Global\\x.", "T1480", 0)],
        )
        combined = answer_with_retry_additions(in_force, retried, 1)

        report = retry_additions_report("", in_force, combined, 1)

        # Copy by copy the line named "Claim 5", a claim the summary above it
        # does not have.
        assert "Claim 3 above was added by the round-1 validation retry" in report
        assert "Claim 5" not in report
        assert "  Claim 3: Creates the mutex" in report
        added = count_claim_blocks(combined.claims) - count_claim_blocks(in_force.claims)
        assert added == 1
        assert "added 1 claim(s) beside the 2 claim(s) in force" in (
            retry_additions_sentence("static", 1, in_force, added)
        )

    def test_a_retry_copy_of_a_block_in_force_keeps_its_own_block_and_mark(self) -> None:
        sentence = "Reads the host name via GetComputerNameExA."
        in_force = AgentISR(
            agent_id="static", domain="static", claims=[_read(sentence, "T1082", 0)]
        )
        retried = AgentISR(
            agent_id="static",
            domain="static",
            claims=[_read(sentence, "T1082", 0), _read(sentence, "T1033", 0)],
        )
        combined = answer_with_retry_additions(in_force, retried, 1)

        # The T1082 copy states the claim in force again and is not added;
        # the T1033 copy is added, marked, as a block of its own, and stays one
        # when the answer is read back from its stored form (no recorded block).
        for isr in (combined, AgentISR.model_validate(combined.model_dump())):
            assert count_claim_blocks(isr.claims) == 2
            lines = [ln.strip() for ln in isr.to_text_summary().splitlines() if "Claim " in ln]
            assert lines[0].startswith(f"Claim 1: {sentence} (T1082) |")
            assert lines[1].startswith(f"Claim 2: {sentence} (T1033) |")
            assert retry_added_marker(1) in lines[1] and retry_added_marker(1) not in lines[0]
        assert "Claim 2 above was" in retry_additions_report("", in_force, combined, 1)


class TestTheJudgeAndTheLogCountEachClaimOnce:
    def test_the_judge_s_isr_line_counts_a_split_claim_once(self) -> None:
        parts = verdict_report_parts({}, {"static": _split_isr()})

        assert "claims=2 | mean_conf=0.60" in parts["ISR summaries"]

    def test_a_split_claim_citing_only_failed_calls_is_named_once_by_its_block(self) -> None:
        isr = _split_isr()
        ledger = [SimpleNamespace(id="ev_0001", ok=False), SimpleNamespace(id="ev_0002", ok=False)]

        flagged = mark_claims_citing_only_failed_calls({"static": isr}, ledger)

        assert flagged == ["static claim 1", "static claim 2"]
        assert all(c.cites_only_failed_calls for c in isr.claims)


def test_the_report_s_technique_notes_are_the_ones_the_console_prints() -> None:
    assert UNVERIFIED_TECHNIQUE_MARKER == MARKERS["unverified"]
    assert ABSENCE_TECHNIQUE_MARKER == MARKERS["absence_kept"]
