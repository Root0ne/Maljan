"""A blocking line carried round after round is settled, and its claims reach their owner.

A blocking line held a debate to its round limit: the analyst it named
rewrote the disputed claim each round with no new entry to read, which
counted as a change, and the line's "claim 6 of the same revision" was read
for no analyst, so no claim of it was withdrawn by rule. A "claim N" no
analyst is read for is now read for the one analyst the line may mean whose
claim N in force shares a ledger id or an address with the reference's
clause, and the owner's merge says so; with none, or more than one, it stays
unplaced as before. When every blocking line is carried from a line that was
itself carried and cites nothing new, the debate ends as
``carried_without_new_evidence``, with no consensus claimed.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.core.config import Settings
from maljan.pipeline.debate_facts import (
    NO_ANALYST_NAMED,
    OwnedClaim,
    carried_without_new_evidence,
    claims_named_by_lines,
    read_claim_references,
)
from maljan.pipeline.nodes import RevisionInput, make_revision_node
from maljan.pipeline.revision_merge import claim_tokens_by_number, merge_revision
from maljan.pipeline.routing import (
    CARRIED_NO_NEW_EVIDENCE,
    NO_CONSENSUS,
    ConsensusRouter,
    debate_route,
)
from maljan.pipeline.state import AgentArgument
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["static", "reverser"]

# A line whose second claim number is written for no analyst.
LINE = (
    "[analysts: STATIC ANALYST] Claim 1 (and claim 2 of the same revision) says the 0x1030 "
    "loop polls until the child exits. ev_0056 prints the call with one argument. "
    "[blocking: restate it as unresolved]"
)


def _claim(text: str, ref: str = "", confidence: float = 0.6) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=confidence)


def _isr(name: str, *claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id=name, domain="static", claims=list(claims))


def _in_force() -> dict[str, AgentISR]:
    return {
        "static": _isr(
            "static",
            _claim("Routine 0x1030 polls the pipe until the child exits.", "[ev_0056]", 0.7),
            _claim(
                "Slot 0x10d80 writes the exit code into 0x4f8 for routine 0x1030.",
                "[ev_0057]",
                0.6,
            ),
        ),
        "reverser": _isr(
            "reverser",
            _claim("Routine 0x1030 runs one pass.", "[ev_0056]", 0.8),
            _claim("Routine 0x7b98 returns a folder path.", "[ev_0122]", 0.8),
        ),
    }


def _owners() -> dict[str, dict[int, frozenset[str]]]:
    return {name: claim_tokens_by_number(isr) for name, isr in _in_force().items()}


# ---------------------------------------------------------------------------
# A claim number written for no analyst
# ---------------------------------------------------------------------------


class TestAClaimNumberReachesItsOwner:
    def test_with_no_claims_in_force_given_it_stays_unplaced(self) -> None:
        references = read_claim_references([LINE], NAMES)

        assert references.named == {"static": {1: [(1, True)]}}
        (unplaced,) = references.unplaced
        assert (unplaced.claims, unplaced.why, unplaced.analysts) == (
            "claim 2",
            NO_ANALYST_NAMED,
            ("static",),
        )
        assert references.owned == ()

    def test_the_owner_whose_claim_shares_an_address_is_read(self) -> None:
        references = read_claim_references([LINE], NAMES, _owners())

        assert references.named == {"static": {1: [(1, True)], 2: [(1, True)]}}
        assert references.unplaced == ()
        assert references.owned == (OwnedClaim(1, True, "static", 2, 1),)
        named = claims_named_by_lines([LINE], NAMES, _owners())
        assert named.get("static").owned == (OwnedClaim(1, True, "static", 2, 1),)
        assert named.get("reverser") is None

    def test_a_claim_sharing_nothing_with_the_clause_stays_unplaced(self) -> None:
        owners = _owners()
        owners["static"][2] = frozenset({"ev_0099"})

        references = read_claim_references([LINE], NAMES, owners)

        assert [u.claims for u in references.unplaced] == ["claim 2"]
        assert references.owned == ()

    def test_two_analysts_whose_claims_both_share_one_leave_it_unplaced(self) -> None:
        line = (
            "[analysts: STATIC ANALYST, REVERSER ANALYST] The 0x1030 loop: claim 2 of one "
            "report says it polls. [blocking: x]"
        )
        owners = _owners()
        owners["reverser"][2] = frozenset({"0x1030"})

        references = read_claim_references([line], NAMES, owners)

        assert [u.analysts for u in references.unplaced] == [("static", "reverser")]
        assert references.owned == ()

    def test_a_line_that_does_not_block_reads_no_owner(self) -> None:
        line = LINE.replace("[blocking: restate it as unresolved]", "[not blocking: hedged]")

        references = read_claim_references([line], NAMES, _owners())

        assert references.named == {"static": {1: [(1, False)]}}
        assert references.owned == ()

    def test_the_owner_s_merge_withdraws_it_by_rule_and_says_so(self) -> None:
        in_force = _in_force()["static"]
        revision = _isr("static", in_force.claims[0])
        named = claims_named_by_lines([LINE], NAMES, _owners())

        merge = merge_revision(in_force, revision, "the revision", 2, named.get("static"))

        assert [number for number, _s, _r in merge.withdrawn_by_rule] == [2]
        said = merge.sentences("static", 2)
        assert (
            "Blocking line L1 of the round-2 mediation writes claim 2 with no analyst named "
            "for it; it is read as claim 2 of the static analyst, the one analyst the line may "
            "mean whose claim 2 shares 1 ledger id or address with the line."
        ) in said
        assert not any(NO_ANALYST_NAMED in s for s in said)


def _revise(line: str) -> dict[str, Any]:
    container = MagicMock()
    container.is_mock = False
    container.event_sink = lambda *_a: None
    container.analyst_keys.return_value = NAMES
    container.agent_role.side_effect = lambda n: n
    container.config.llm.parallel_analysts = False
    container.config.agents.definitions = {}
    in_force = _in_force()
    agents: dict[str, Any] = {}
    for name in NAMES:
        agent = MagicMock()
        agent.tools = []
        # The revision writes the first claim again and leaves the second.
        agent.safe_revise_isr.return_value = (
            f"{name} revised",
            _isr(name, in_force[name].claims[0]),
        )
        agent.drain_evidence_entries.return_value = []
        agent.validation_findings = []
        agent.validation_retries = 0
        agent.validation_fed_back = {}
        agent.validation_not_run = []
        agent.revision_entries_shown = ()
        agents[name] = agent
    container.get_agent.side_effect = lambda n: agents[n]
    mediation = AgentArgument(
        agent_name="Mediator",
        finding=f"Summary.\n\nCONTRADICTIONS:\n{line}\nagreement_confidence: 0.5",
        confidence_score=0.5,
        contradictions=[line],
    )
    mediation.revise = ["static"]
    state = {
        "iteration_count": 1,
        "is_consensus": False,
        "consensus_applicable": True,
        "reports": {name: f"{name} first" for name in NAMES},
        "revised_reports": {},
        "isr_reports": in_force,
        "sycophancy_detected": False,
        "discussion_history": [mediation],
        "evidence_ledger": [],
    }
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("maljan.pipeline.nodes._revision_input", lambda *a: RevisionInput(text="data"))
        mp.setattr("maljan.pipeline.nodes.pack_text", lambda *a: "[ev_0001] identity: pe")
        return asyncio.run(make_revision_node(container)(state))


class TestTheRevisionNode:
    def test_the_owned_claim_left_unanswered_is_withdrawn_by_rule(self) -> None:
        update = _revise(LINE)

        claims = [c.claim for c in update["isr_reports"]["static"].claims]
        assert claims == ["Routine 0x1030 polls the pipe until the child exits."]
        (dropped,) = [row for row in update["dropped_claims"] if row["agent"] == "static"]
        assert dropped["claim"] == (
            "Slot 0x10d80 writes the exit code into 0x4f8 for routine 0x1030."
        )
        assert "is withdrawn by rule after the round-1 revision" in dropped["sentence"]
        said = update["revision_replacements"]
        assert any("it is read as claim 2 of the static analyst" in s for s in said)
        assert not any(NO_ANALYST_NAMED in s for s in said)
        # The analyst the line does not name keeps its answer in force.
        assert len(update["isr_reports"]["reverser"].claims) == 2


# ---------------------------------------------------------------------------
# A line carried a second time with nothing new to read
# ---------------------------------------------------------------------------

FIRST = (
    "[analysts: STATIC ANALYST] [new] Claim 1 says the 0x1030 loop polls; ev_0056 shows no "
    "write. [blocking: x]"
)
SECOND = (
    "[analysts: STATIC ANALYST] [carried: L1] Claim 1 still says the 0x1030 loop polls, as "
    "0x2200 zeroes the value; ev_0056 shows no write. [blocking: x]"
)
THIRD = (
    "[analysts: STATIC ANALYST] [carried: L1] Claim 1 again says the 0x1030 loop polls "
    "through slot 0x10d80; ev_0056 shows one argument. [blocking: x]"
)


def _record(earlier: str, *, filed: dict[str, list[str]] | None = None) -> dict[str, Any]:
    return {
        "round": 2,
        "stage": "debate",
        "made": 1,
        "identical": False,
        "reworded": False,
        "revised": ["static"],
        "not_revised": {"reverser": "not asked: not named by the mediator"},
        "lines": [
            {
                "line": earlier,
                "named": ["static"],
                "revised": ["static"],
                "shown": {"static": ["ev_0056"]},
                # The analyst rewrote its claims: a change, with nothing new read.
                "changed": ["static"],
                "entries": ["ev_0056"],
                "places": ["0x1030"],
            }
        ],
        "filed": dict(filed or {}),
    }


def _mediator(lines: list[str], carried: dict[str, int] | None = None) -> AgentArgument:
    return AgentArgument(
        agent_name="Mediator",
        finding="x",
        confidence_score=0.74,
        contradictions=list(lines),
        carried=dict(carried or {}),
    )


def _state(line: str, earlier: str, record: dict[str, Any], held: int = 3) -> dict[str, Any]:
    return {
        "iteration_count": held,
        "is_consensus": False,
        "consensus_applicable": True,
        "sycophancy_detected": False,
        "confidence_history": [0.74, 0.75, 0.6][:held],
        "discussion_history": [_mediator([earlier]), _mediator([line], {line: 1})],
        "isr_reports": {},
        "revision_rounds": [record],
    }


class TestACarriedLineWithNothingNew:
    def test_a_second_carry_with_nothing_new_ends_the_debate(self) -> None:
        record = _record(SECOND)

        assert carried_without_new_evidence([THIRD], {THIRD: 1}, record)
        assert debate_route(_state(THIRD, SECOND, record), max_rounds=5) == (
            "judge",
            CARRIED_NO_NEW_EVIDENCE,
        )

    def test_a_first_carry_keeps_the_debate_going(self) -> None:
        record = _record(FIRST)

        assert not carried_without_new_evidence([SECOND], {SECOND: 1}, record)
        assert debate_route(_state(SECOND, FIRST, record), max_rounds=5) == (
            "revision",
            NO_CONSENSUS,
        )

    def test_a_line_citing_an_entry_the_earlier_line_did_not_keeps_it_going(self) -> None:
        line = THIRD.replace("ev_0056 shows", "ev_0131 lists the call; ev_0056 shows")

        assert not carried_without_new_evidence([line], {line: 1}, _record(SECOND))

    def test_a_line_citing_an_entry_the_round_filed_keeps_it_going(self) -> None:
        record = _record(SECOND, filed={"static": ["ev_0056"]})

        assert not carried_without_new_evidence([THIRD], {THIRD: 1}, record)

    def test_a_function_an_older_listing_holds_is_nothing_new(self) -> None:
        fact = f'For the line "{THIRD}": 0x10d80 is listed in ev_0057.'

        assert carried_without_new_evidence([THIRD], {THIRD: 1}, _record(SECOND), [fact])

    def test_a_listing_the_round_filed_reached_by_a_place_fact_keeps_it_going(self) -> None:
        fact = f'For the line "{THIRD}": 0x10d80 is listed in ev_0131.'
        record = _record(SECOND, filed={"static": ["ev_0131"]})

        assert not carried_without_new_evidence([THIRD], {THIRD: 1}, record, [fact])

    def test_an_analyst_the_earlier_line_did_not_name_keeps_it_going(self) -> None:
        line = THIRD.replace("[analysts: STATIC ANALYST]", "[analysts: STATIC, REVERSER]")

        assert not carried_without_new_evidence([line], {line: 1}, _record(SECOND))

    def test_a_line_not_carried_beside_it_keeps_it_going(self) -> None:
        other = "[analysts: STATIC ANALYST] [new] Claim 2 names a mutex. [blocking: x]"

        assert not carried_without_new_evidence([THIRD, other], {THIRD: 1}, _record(SECOND))

    def test_a_record_without_line_facts_reads_as_before(self) -> None:
        record = {k: v for k, v in _record(SECOND).items() if k != "lines"}

        assert not carried_without_new_evidence([THIRD], {THIRD: 1}, record)

    def test_the_shipped_settings_route_it_to_the_judge(self) -> None:
        settings = Settings(_env_file=None)
        # The shipped server map is loaded and untouched by the rule.
        assert settings.mcp.servers
        router = ConsensusRouter(settings)

        state = _state(THIRD, SECOND, _record(SECOND))

        assert router.should_continue(state) == "judge"  # type: ignore[arg-type]
