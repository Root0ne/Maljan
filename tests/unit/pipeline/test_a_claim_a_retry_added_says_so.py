"""A claim a tool-less retry added says so wherever it is read, and counts for what it is.

After a revision that wrote no claim, the claims its validation retry wrote
are added beside the answer in force, each marked with the round
(``ClaimEvidence.added_by_retry_in_round``). The retry is a turn with no
tools. The mark travels with the claim to the transcript event, to the judge's
summary of the answers, to the composer's claim lines and to the report's
list of claims the body leaves out. The corroboration reading, which the
ATT&CK table and the STIX export read, does not count such a claim as support
for its technique unless it cites an entry its own analyst's tool calls
filed. Every value is synthetic.
"""

from __future__ import annotations

from maljan.pipeline.events import claims_to_payload
from maljan.pipeline.validation import corroboration, retry_claim_unbacked, tool_backed_answers
from maljan.reporting.claim_coverage import claims_not_discussed
from maljan.reporting.evidence_bundles import _claims_text
from maljan.reporting.models import FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.markdown import MarkdownRenderer
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, retry_added_marker

MARKER = "added by a tool-less retry, round 2"


def _claim(text: str, ev: str, technique: str | None = None, *, retry: bool) -> ClaimEvidence:
    claim = ClaimEvidence(claim=text, evidence_ref=ev, confidence=0.7, technique_id=technique)
    if retry:
        claim.added_by_retry_in_round = 2
    return claim


ADDED = _claim("Routine 0x7b98 reads the Startup folder path.", "[ev_0004]", retry=True)
OWN = _claim("Routine 0x33ac copies the file.", "[ev_0004]", retry=False)


def test_the_marker_words() -> None:
    assert retry_added_marker(2) == MARKER


class TestTheMarkIsRead:
    def test_the_transcript_event_carries_the_round(self) -> None:
        added, own = claims_to_payload([ADDED, OWN])

        assert added["added_by_retry_in_round"] == 2
        assert "added_by_retry_in_round" not in own

    def test_the_judge_s_summary_of_the_answer_states_it(self) -> None:
        summary = AgentISR(agent_id="reverser", domain="reverser", claims=[OWN, ADDED])
        lines = summary.to_text_summary().splitlines()

        assert MARKER not in lines[2]
        assert f"({MARKER})" in lines[3]

    def test_the_composer_s_claim_lines_state_it(self) -> None:
        isrs = {"reverser": AgentISR(agent_id="reverser", domain="reverser", claims=[OWN, ADDED])}
        own, added = _claims_text(MalwareReport(identity=_IDENTITY), isrs)

        assert own["evidence_ref"] == "[ev_0004]"
        assert added["evidence_ref"] == f"[ev_0004] ({MARKER})"

    def test_the_report_labels_it_among_the_claims_the_body_leaves_out(self) -> None:
        isrs = {"reverser": AgentISR(agent_id="reverser", domain="reverser", claims=[OWN, ADDED])}
        report = MalwareReport(identity=_IDENTITY)
        report.claims_not_discussed = claims_not_discussed(report, isrs)

        rows = {row.claim_number: row for row in report.claims_not_discussed}
        assert rows[2].added_by_retry_in_round == 2
        assert rows[1].added_by_retry_in_round is None
        markdown = MarkdownRenderer().render(report)
        [line] = [line for line in markdown.splitlines() if "0x7b98" in line]
        assert f"({MARKER}; " in line
        [line] = [line for line in markdown.splitlines() if "0x33ac" in line]
        assert MARKER not in line


_IDENTITY = SampleIdentity(hashes=FileHashes(sha256="a" * 64))


def _ledger() -> list[LedgerEntry]:
    return [
        LedgerEntry(
            id="ev_0001", tool="sandbox_registry", output="Run value set", agent="pipeline"
        ),
        LedgerEntry(id="ev_0004", tool="decompile_function", output="RegSetValueExW", agent="rev"),
        LedgerEntry(id="ev_0007", tool="decompile_function", output="RegSetValueExW", agent="dyn"),
    ]


class TestCorroboration:
    def test_a_marked_claim_citing_its_own_analyst_s_call_is_backed(self) -> None:
        claim = _claim("0x1100 writes the Run value.", "[ev_0004]", "T1547.001", retry=True)

        assert retry_claim_unbacked(claim, "rev", _ledger()) is False
        assert retry_claim_unbacked(claim, "dyn", _ledger()) is True
        unmarked = _claim("0x1100 writes the Run value.", "[ev_0001]", "T1547.001", retry=False)
        assert retry_claim_unbacked(unmarked, "rev", _ledger()) is False

    def test_a_marked_claim_on_another_s_entry_is_not_a_second_sayer(self) -> None:
        own = _claim("0x2200 writes the Run value.", "[ev_0007]", "T1547.001", retry=False)
        borrowed = _claim(
            "The sandbox records the Run value.", "[ev_0001]", "T1547.001", retry=True
        )
        isrs = {
            "dyn": AgentISR(agent_id="dyn", domain="dyn", claims=[own]),
            "rev": AgentISR(agent_id="rev", domain="rev", claims=[borrowed]),
        }

        row = corroboration(isrs, _ledger())["T1547.001"]

        assert row["independent_sayers"] == 1
        assert row["sources"] == ["ev_0007"]
        # The answers in force are not changed by the reading.
        assert isrs["rev"].claims == [borrowed]
        assert tool_backed_answers(isrs, _ledger())["rev"].claims == []

    def test_a_marked_claim_on_its_own_entry_counts(self) -> None:
        own = _claim("0x2200 writes the Run value.", "[ev_0007]", "T1547.001", retry=False)
        backed = _claim("0x1100 writes the Run value.", "[ev_0004]", "T1547.001", retry=True)
        isrs = {
            "dyn": AgentISR(agent_id="dyn", domain="dyn", claims=[own]),
            "rev": AgentISR(agent_id="rev", domain="rev", claims=[backed]),
        }

        row = corroboration(isrs, _ledger())["T1547.001"]

        assert row["independent_sayers"] == 2
        assert sorted(row["sources"]) == ["ev_0004", "ev_0007"]
