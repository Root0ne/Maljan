"""A listed contradiction that nothing still holds, or that the ledger answers, opens no round.

The mediator lists what it reads as still standing, and every line of that
block used to send all analysts to revise. Two kinds of line settle nothing:

- one about a claim no analyst still holds: the analyst it names no longer
  has that claim in its answer, so there is nothing to argue about;
- one about a count the evidence ledger states: the platform states the
  entry's number, and no revision round is spent on bookkeeping.

A line that touches a technique, a network value or a hash is never settled by
the platform: those are what the report publishes, and the analysts settle
them. Every value below is synthetic.
"""

from __future__ import annotations

from maljan.pipeline.debate_settlement import settle_contradictions
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _isr(agent: str, claims: int, *, ref: str = "[ev_0001]") -> AgentISR:
    return AgentISR(
        agent_id=agent,
        domain="static",
        claims=[
            ClaimEvidence(claim=f"claim {i}", evidence_ref=ref, confidence=0.8)
            for i in range(1, claims + 1)
        ],
    )


def _count_entry(entry_id: str = "ev_0007", total: int = 41) -> dict:
    return {
        "id": entry_id,
        "tool": "decode_blobs",
        "structured": {"tool": "decode_blobs", "total": total, "results": []},
    }


AGENTS = ["alpha_static", "beta_reverser", "gamma"]


class TestAClaimNoAnalystHolds:
    def test_a_line_about_a_claim_number_past_the_answer_is_closed(self) -> None:
        line = (
            "ALPHA_STATIC Claim 30 (calls the address the best candidate) — contradicted by "
            "GAMMA ANALYST Claim 3."
        )
        result = settle_contradictions(
            [line],
            {"alpha_static": _isr("alpha_static", 12), "gamma": _isr("gamma", 5)},
            [],
            AGENTS,
        )

        assert result.standing == []
        assert result.settled == []
        assert len(result.closed) == 1
        assert "ALPHA_STATIC" in result.closed[0] or "alpha_static" in result.closed[0]
        assert "30" in result.closed[0]

    def test_a_line_about_a_claim_the_analyst_still_holds_stands(self) -> None:
        line = "ALPHA_STATIC ANALYST Claim 3 — contradicted by GAMMA ANALYST Claim 2."
        result = settle_contradictions(
            [line],
            {"alpha_static": _isr("alpha_static", 12), "gamma": _isr("gamma", 5)},
            [],
            AGENTS,
        )

        assert result.standing == [line]
        assert result.closed == []

    def test_one_held_claim_of_several_keeps_the_line(self) -> None:
        line = "BETA_REVERSER ANALYST Claims 4/40 — contradicted by GAMMA Claim 1."
        result = settle_contradictions(
            [line],
            {"beta_reverser": _isr("beta_reverser", 10), "gamma": _isr("gamma", 2)},
            [],
            AGENTS,
        )

        assert result.standing == [line]

    def test_an_analyst_with_no_answer_holds_nothing(self) -> None:
        line = "GAMMA Claim 2 — contradicted by ALPHA_STATIC Claim 1."
        result = settle_contradictions(
            [line], {"alpha_static": _isr("alpha_static", 3)}, [], AGENTS
        )

        assert result.standing == []
        assert len(result.closed) == 1

    def test_a_line_that_names_no_claim_number_stands(self) -> None:
        line = "GAMMA says the file is packed; ALPHA_STATIC says it is not."
        result = settle_contradictions([line], {"gamma": _isr("gamma", 1)}, [], AGENTS)

        assert result.standing == [line]

    def test_a_name_that_is_part_of_a_longer_name_is_not_that_analyst(self) -> None:
        agents = ["static", "alpha_static"]
        line = "ALPHA_STATIC Claim 9 — contradicted by STATIC Claim 1."
        result = settle_contradictions(
            [line],
            {"static": _isr("static", 20), "alpha_static": _isr("alpha_static", 20)},
            [],
            agents,
        )

        assert result.standing == [line]


class TestACountTheLedgerStates:
    def test_a_count_dispute_citing_the_entry_is_settled_by_its_number(self) -> None:
        line = (
            "BETA_REVERSER Claims 6/7 (the decoded-text accounting does not close at 45: "
            "the listing [ev_0007] of 41 entries is partial) — contradicted by GAMMA Claim 2 "
            "(closed at 45 = 40 + 5)."
        )
        result = settle_contradictions(
            [line],
            {"beta_reverser": _isr("beta_reverser", 9), "gamma": _isr("gamma", 4)},
            [_count_entry()],
            AGENTS,
        )

        assert result.standing == []
        assert len(result.settled) == 1
        assert "ev_0007" in result.settled[0]
        assert "41" in result.settled[0]

    def test_the_entry_may_be_cited_by_a_claim_the_line_names(self) -> None:
        line = (
            "BETA_REVERSER Claim 2 (the listing holds 41 texts, not 40) — contradicted by "
            "GAMMA Claim 1 (40 texts and 5 unreferenced)."
        )
        reverser = _isr("beta_reverser", 3, ref="decoder output [ev_0007]")
        result = settle_contradictions(
            [line], {"beta_reverser": reverser, "gamma": _isr("gamma", 2)}, [_count_entry()], AGENTS
        )

        assert result.standing == []
        assert "ev_0007" in result.settled[0]

    def test_a_line_whose_numbers_the_entry_does_not_state_stands(self) -> None:
        line = "BETA_REVERSER Claim 2 says 38 texts [ev_0007]; GAMMA Claim 1 says 39."
        result = settle_contradictions(
            [line],
            {"beta_reverser": _isr("beta_reverser", 3), "gamma": _isr("gamma", 2)},
            [_count_entry()],
            AGENTS,
        )

        assert result.standing == [line]

    def test_one_number_alone_is_no_dispute_over_a_count(self) -> None:
        line = "BETA_REVERSER Claim 2 reads the listing [ev_0007] of 41 entries as partial."
        result = settle_contradictions(
            [line], {"beta_reverser": _isr("beta_reverser", 3)}, [_count_entry()], AGENTS
        )

        assert result.standing == [line]

    def test_a_line_naming_a_technique_is_left_to_the_analysts(self) -> None:
        line = (
            "BETA_REVERSER Claim 2 (41 decoded texts [ev_0007], so T1140 holds) — "
            "contradicted by GAMMA Claim 1 (40 texts)."
        )
        result = settle_contradictions(
            [line],
            {"beta_reverser": _isr("beta_reverser", 3), "gamma": _isr("gamma", 2)},
            [_count_entry()],
            AGENTS,
        )

        assert result.standing == [line]

    def test_a_line_naming_a_network_value_is_left_to_the_analysts(self) -> None:
        line = (
            "BETA_REVERSER Claim 2 (41 entries [ev_0007] include relay-node.top) — "
            "contradicted by GAMMA Claim 1 (40 entries)."
        )
        result = settle_contradictions(
            [line],
            {"beta_reverser": _isr("beta_reverser", 3), "gamma": _isr("gamma", 2)},
            [_count_entry()],
            AGENTS,
        )

        assert result.standing == [line]

    def test_an_entry_the_ledger_does_not_hold_settles_nothing(self) -> None:
        line = "BETA_REVERSER Claim 2 counts 41 [ev_0099]; GAMMA Claim 1 counts 40."
        result = settle_contradictions(
            [line],
            {"beta_reverser": _isr("beta_reverser", 3), "gamma": _isr("gamma", 2)},
            [_count_entry()],
            AGENTS,
        )

        assert result.standing == [line]

    def test_a_ledger_entry_given_as_a_model_is_read_too(self) -> None:
        from maljan.schemas.evidence import LedgerEntry

        line = "BETA_REVERSER Claim 2 counts 41 [ev_0007]; GAMMA Claim 1 counts 40."
        entry = LedgerEntry(id="ev_0007", tool="decode_blobs", structured={"total": 41})
        result = settle_contradictions(
            [line],
            {"beta_reverser": _isr("beta_reverser", 3), "gamma": _isr("gamma", 2)},
            [entry],
            AGENTS,
        )

        assert result.standing == []


def test_every_line_is_kept_in_one_of_the_three_lists() -> None:
    lines = [
        "ALPHA_STATIC Claim 30 — contradicted by GAMMA Claim 1.",
        "BETA_REVERSER Claim 2 counts 41 [ev_0007]; GAMMA Claim 1 counts 40.",
        "GAMMA Claim 1 says T1027; ALPHA_STATIC Claim 1 says none.",
    ]
    result = settle_contradictions(
        lines,
        {
            "alpha_static": _isr("alpha_static", 2),
            "beta_reverser": _isr("beta_reverser", 3),
            "gamma": _isr("gamma", 2),
        },
        [_count_entry()],
        AGENTS,
    )

    assert result.standing == [lines[2]]
    assert len(result.closed) == 1
    assert len(result.settled) == 1
