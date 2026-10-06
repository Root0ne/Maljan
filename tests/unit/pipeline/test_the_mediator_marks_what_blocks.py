"""The mediator decides which listed contradiction blocks; the platform states ledger counts.

Every listed line used to block consensus, so a bookkeeping line kept a debate
open for rounds. The platform no longer decides that any line is closed or
settled. What it does:

- for a listed line whose cited entries state, in a field named for a count or
  a total, a number the line itself states, it states those values, every one
  of them, also when they disagree. They ride on calls the debate already
  makes: the revision directive of the analysts the line names, and the next
  mediation's prompt. No call is made for them;
- it reads the mark the mediator puts on each line, ``[blocking: <reason>]`` or
  ``[not blocking: <reason>]``. A line marked not blocking does not stand
  against consensus; an unmarked line blocks, as every line did before.

A technique, a network value or a hash line may be marked not blocking: the
mediator decides, and the platform overrides it in neither direction. Every
value below is synthetic.
"""

from __future__ import annotations

from maljan.pipeline.debate_facts import (
    LEDGER_FACTS_HEAD,
    facts_naming,
    ledger_count_facts,
    read_marks,
    with_ledger_facts,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

AGENTS = ["alpha_static", "beta_reverser", "gamma"]


def _isr(agent: str, claims: int, *, ref: str = "[ev_0001]") -> AgentISR:
    return AgentISR(
        agent_id=agent,
        domain="static",
        claims=[
            ClaimEvidence(claim=f"claim {i}", evidence_ref=ref, confidence=0.8)
            for i in range(1, claims + 1)
        ],
    )


def _entry(entry_id: str, **structured: object) -> dict:
    return {"id": entry_id, "tool": "decode_blobs", "structured": structured}


class TestTheLedgerCountsAreStated:
    def test_a_cited_entry_s_count_is_stated(self) -> None:
        line = "BETA_REVERSER Claim 2 says 41 texts [ev_0007]; GAMMA Claim 1 says 40."

        facts = ledger_count_facts([line], {}, [_entry("ev_0007", total=41)], AGENTS)

        assert len(facts) == 1
        assert "ev_0007" in facts[0] and "total = 41" in facts[0]
        assert line in facts[0]

    def test_entries_that_disagree_are_all_stated(self) -> None:
        line = "BETA_REVERSER Claim 2 counts 41 [ev_0007]; GAMMA Claim 1 counts 40 [ev_0008]."

        facts = ledger_count_facts(
            [line], {}, [_entry("ev_0007", total=41), _entry("ev_0008", total=40)], AGENTS
        )

        assert "total = 41" in facts[0] and "total = 40" in facts[0]
        assert "ev_0007" in facts[0] and "ev_0008" in facts[0]

    def test_an_entry_a_named_claim_cites_is_read_too(self) -> None:
        line = "BETA_REVERSER Claim 2 (41 texts) — contradicted by GAMMA Claim 1 (40 texts)."
        reverser = _isr("beta_reverser", 3, ref="decoder output [ev_0007]")

        facts = ledger_count_facts(
            [line], {"beta_reverser": reverser}, [_entry("ev_0007", total=41)], AGENTS
        )

        assert "ev_0007" in facts[0]

    def test_a_size_or_a_time_is_not_a_count(self) -> None:
        line = "GAMMA Claim 1 says 12 frames in 60 s [ev_0009]; ALPHA_STATIC Claim 1 says 900."
        entry = _entry("ev_0009", total_seconds=60, total_bytes=900, frame_count=12)

        facts = ledger_count_facts([line], {}, [entry], AGENTS)

        assert "frame_count = 12" in facts[0]
        assert "total_seconds" not in facts[0] and "total_bytes" not in facts[0]

    def test_a_count_the_line_does_not_state_is_left_out(self) -> None:
        line = "GAMMA Claim 1 says 41 [ev_0007]; ALPHA_STATIC Claim 1 says 40."
        entry = _entry("ev_0007", total=41, string_count=218)

        facts = ledger_count_facts([line], {}, [entry], AGENTS)

        assert "total = 41" in facts[0]
        assert "218" not in facts[0]

    def test_an_entry_whose_counts_the_line_does_not_state_gives_no_fact(self) -> None:
        line = "GAMMA Claim 1 says port 443 [ev_0007]; ALPHA_STATIC Claim 1 says 80."

        assert ledger_count_facts([line], {}, [_entry("ev_0007", total=3)], AGENTS) == []

    def test_a_claim_number_is_not_a_number_the_line_states(self) -> None:
        line = "GAMMA Claim 3 says so [ev_0007]; ALPHA_STATIC Claim 1 says 40."

        assert ledger_count_facts([line], {}, [_entry("ev_0007", total=3)], AGENTS) == []

    def test_a_line_that_cites_no_entry_with_a_count_states_nothing(self) -> None:
        line = "GAMMA Claim 1 says 41 [ev_0099]; ALPHA_STATIC Claim 1 says 40."

        assert ledger_count_facts([line], {}, [_entry("ev_0007", total=41)], AGENTS) == []

    def test_a_line_with_no_number_states_nothing(self) -> None:
        line = "GAMMA says the file is packed [ev_0007]; ALPHA_STATIC says it is not."

        assert ledger_count_facts([line], {}, [_entry("ev_0007", total=41)], AGENTS) == []

    def test_a_ledger_entry_model_is_read(self) -> None:
        from maljan.schemas.evidence import LedgerEntry

        line = "GAMMA Claim 1 counts 41 [ev_0007]; BETA_REVERSER Claim 1 counts 40."
        entry = LedgerEntry(id="ev_0007", tool="t", structured={"count": 41})

        assert "count = 41" in ledger_count_facts([line], {}, [entry], AGENTS)[0]


class TestTheMediatorsMarks:
    def test_a_line_marked_not_blocking_does_not_block(self) -> None:
        marks = read_marks(["GAMMA vs BETA on a tally [not blocking: a count, no reported fact]"])

        assert marks[0].blocking is False
        assert marks[0].marked is True
        assert marks[0].reason == "a count, no reported fact"

    def test_a_line_marked_blocking_blocks(self) -> None:
        marks = read_marks(["GAMMA says T1055 [blocking: the technique is published]"])

        assert marks[0].blocking is True and marks[0].marked is True

    def test_an_unmarked_line_blocks(self) -> None:
        marks = read_marks(["GAMMA says T1055; BETA says it does not."])

        assert marks[0].blocking is True and marks[0].marked is False

    def test_a_technique_line_may_be_marked_not_blocking(self) -> None:
        marks = read_marks(["GAMMA says T1055 [Not Blocking: both agree it is a lead only]"])

        assert marks[0].blocking is False

    def test_the_mark_is_read_with_emphasis_around_it(self) -> None:
        marks = read_marks(["A vs B on a count **[not blocking: bookkeeping]**"])

        assert marks[0].blocking is False and marks[0].reason == "bookkeeping"

    def test_a_reason_may_cite_a_ledger_id_in_brackets(self) -> None:
        line = (
            "BETA Claims 6/7 (the decoded-text count does not close at 45) [ev_0029] — "
            "contradicted by ledger entry [ev_0021] [not blocking: both totals are stated, "
            "see [ev_0021] and [ev_0029]]"
        )

        mark = read_marks([line])[0]

        assert mark.blocking is False and mark.unread is False
        assert mark.reason == "both totals are stated, see [ev_0021] and [ev_0029]"

    def test_a_blocking_reason_may_cite_a_ledger_id_in_brackets(self) -> None:
        mark = read_marks(["GAMMA says T1055 [blocking: ev_0021, [ev_0055]]"])[0]

        assert mark.blocking is True and mark.marked is True and mark.unread is False

    def test_a_mark_that_cannot_be_read_blocks_and_is_recorded_as_unread(self) -> None:
        mark = read_marks(["A vs B [not blocking: see [ev_0021 [nested]]]"])[0]

        assert mark.blocking is True and mark.unread is True

    def test_a_mark_followed_by_more_text_is_unread(self) -> None:
        mark = read_marks(["A vs B [not blocking: a tally] and more words"])[0]

        assert mark.blocking is True and mark.unread is True

    def test_conflicting_marks_read_as_blocking(self) -> None:
        mark = read_marks(["A vs B [blocking: r] [not blocking: r2]"])[0]

        assert mark.blocking is True and mark.unread is True

    def test_not_blocking_with_no_reason_is_read_as_unmarked(self) -> None:
        for line in ("A vs B [not blocking]", "A vs B [not blocking: ]"):
            mark = read_marks([line])[0]

            assert mark.blocking is True and mark.marked is False and mark.unread is True

    def test_a_line_that_only_mentions_blocking_is_not_unread(self) -> None:
        mark = read_marks(["A says the gate is blocking; B says it is not"])[0]

        assert mark.blocking is True and mark.unread is False


def test_a_fact_goes_to_the_analysts_its_line_names() -> None:
    facts = ledger_count_facts(
        ["BETA_REVERSER Claim 2 counts 41 [ev_0007]; GAMMA Claim 1 counts 40."],
        {},
        [_entry("ev_0007", total=41)],
        AGENTS,
    )

    assert facts_naming("beta_reverser", facts) == facts
    assert facts_naming("gamma", facts) == facts
    assert facts_naming("alpha_static", facts) == []


def test_the_facts_reach_a_revision_under_a_fixed_head() -> None:
    directive = with_ledger_facts("feedback", ["fact one"])

    assert directive.startswith("feedback")
    assert LEDGER_FACTS_HEAD in directive and "- fact one" in directive
    assert with_ledger_facts("feedback", []) == "feedback"
