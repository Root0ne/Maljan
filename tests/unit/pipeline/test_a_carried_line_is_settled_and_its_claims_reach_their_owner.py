"""A blocking line carried with nothing new is settled; claim numbers reach the claims they mean.

A blocking line can hold a debate to its round limit. The analyst it names
rewrites the disputed claim each round with no new entry to read, and that
counts as a change. Meanwhile the line names claims by numbers the platform
cannot place. Four rules answer it:

- A "claim N" no analyst is read for is read for the one analyst the line may
  mean whose claim N in force shares, with the reference's clause, a ledger id
  or an address that no other claim of its answer writes. The claim is
  carried with the line, never withdrawn by rule, and the owner's merge says
  so. With no such analyst, or more than one, the number stays unplaced, as
  before.
- When every blocking line is carried from a line whose own carried mark
  counted, the debate ends as ``carried_without_new_evidence``, with no
  consensus claimed. This needs every analyst named there to have revised,
  none of them to cite in its revised answer an entry it filed in the round
  beside the line's points, and the line to write no new entry id.
- A merged answer in force whose numbers differ from the ones the revision
  gave its claims carries a key from one to the other, right where the
  revision's own words begin.
- A claim the analyst keeps after a validation retry left it out takes the
  place of the one retry block that wrote it again in other words, instead
  of standing beside it.

Every value is synthetic.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import WRITTEN_BESIDES_CLAIMS
from maljan.core.config import Settings
from maljan.pipeline.debate_facts import (
    NO_ANALYST_NAMED,
    OwnedClaim,
    carried_without_new_evidence,
    claims_named_by_lines,
    line_round_facts,
    read_claim_references,
    valid_carries,
)
from maljan.pipeline.nodes import RevisionInput, make_revision_node
from maljan.pipeline.revision_merge import (
    RevisionMerge,
    claim_tokens_by_number,
    merge_revision,
    numbering_key,
    rewritten_in,
    with_numbering_key,
)
from maljan.pipeline.routing import (
    CARRIED_NO_NEW_EVIDENCE,
    NO_CONSENSUS,
    POINTS_UNCHANGED,
    ConsensusRouter,
    debate_route,
)
from maljan.pipeline.state import AgentArgument
from maljan.pipeline.validation import retry_drops
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["static", "reverser"]

# A line whose second claim number is written for no analyst.
LINE = (
    "[analysts: STATIC ANALYST] Claim 1 (and claim 2 of the same revision) says slot 0x10d80 "
    "in the 0x1030 loop writes the exit code. ev_0056 prints the call with one argument. "
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


def _owners(in_force: dict[str, AgentISR] | None = None) -> dict[str, dict[int, frozenset[str]]]:
    return {name: claim_tokens_by_number(isr) for name, isr in (in_force or _in_force()).items()}


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

    def test_the_owner_whose_claim_alone_shares_an_address_is_read_and_never_blocks(
        self,
    ) -> None:
        references = read_claim_references([LINE], NAMES, _owners())

        # Claim 2 alone writes 0x10d80; 0x1030 is written by claim 1 too.
        assert references.named == {"static": {1: [(1, True)], 2: [(1, False)]}}
        assert references.unplaced == ()
        assert references.owned == (OwnedClaim(1, True, "static", 2, 1),)
        named = claims_named_by_lines([LINE], NAMES, _owners())
        assert named.get("static").owned == (OwnedClaim(1, True, "static", 2, 1),)
        assert named.get("reverser") is None

    def test_a_claim_sharing_only_a_listing_other_claims_cite_stays_unplaced(self) -> None:
        line = (
            "[analysts: STATIC ANALYST] [carried: L1] Claim 1 (and claim 2 of the same revision) "
            "says the 0x1030 loop polls until the child exits per the listing ev_0056, showing "
            "one argument. [blocking: restate]"
        )
        in_force = {
            "static": _isr(
                "static",
                _claim("Routine 0x1030 polls until the child exits.", "[ev_0056]", 0.7),
                _claim("Strings are XOR-decoded by routine 0xae78.", "[ev_0056] 0xae78", 0.7),
                _claim("Mutex created.", "[ev_0011]", 0.7),
            ),
            "reverser": _isr("reverser"),
        }
        named = claims_named_by_lines([line], NAMES, _owners(in_force))

        assert named.references.owned == ()
        assert [u.claims for u in named.references.unplaced] == ["claim 2"]
        merge = merge_revision(
            in_force["static"],
            _isr("static", in_force["static"].claims[0]),
            "rev",
            3,
            named.get("static"),
        )
        assert merge.withdrawn_by_rule == ()

    def test_a_claim_sharing_nothing_with_the_clause_stays_unplaced(self) -> None:
        owners = _owners()
        owners["static"][2] = frozenset({"ev_0099"})

        references = read_claim_references([LINE], NAMES, owners)

        assert [u.claims for u in references.unplaced] == ["claim 2"]
        assert references.owned == ()

    def test_two_analysts_whose_claims_both_share_one_leave_it_unplaced(self) -> None:
        line = (
            "[analysts: STATIC ANALYST, REVERSER ANALYST] The 0x10d80 slot: claim 2 of one "
            "report says it writes. [blocking: x]"
        )
        owners = _owners()
        owners["reverser"][2] = frozenset({"0x10d80"})

        references = read_claim_references([line], NAMES, owners)

        assert [u.analysts for u in references.unplaced] == [("static", "reverser")]
        assert references.owned == ()

    def test_a_line_with_no_names_field_may_mean_any_analyst(self) -> None:
        line = "Claim 2 of that report says slot 0x10d80 writes the code. [blocking: x]"

        references = read_claim_references([line], NAMES, _owners())

        assert references.owned == (OwnedClaim(1, True, "static", 2, 1),)
        assert references.named == {"static": {2: [(1, False)]}}

    def test_a_line_that_does_not_block_reads_no_owner(self) -> None:
        line = LINE.replace("[blocking: restate it as unresolved]", "[not blocking: hedged]")

        references = read_claim_references([line], NAMES, _owners())

        assert references.named == {"static": {1: [(1, False)]}}
        assert references.owned == ()

    def test_the_owner_s_merge_carries_it_with_the_line_and_says_so(self) -> None:
        in_force = _in_force()["static"]
        revision = _isr("static", in_force.claims[0])
        named = claims_named_by_lines([LINE], NAMES, _owners())

        merge = merge_revision(in_force, revision, "the revision", 2, named.get("static"))

        assert merge.withdrawn_by_rule == ()
        assert [n for n, _s in merge.carried] == [2]
        (carried,) = [c for c in merge.merged.claims if "0x10d80" in c.claim]
        assert carried.carried_contested_by == ["L1 (round 2)"]
        said = merge.sentences("static", 2)
        assert (
            "Blocking line L1 of the round-2 mediation writes claim 2 with no analyst named "
            "for it; it is read as claim 2 of the static analyst, the one analyst the line may "
            "mean whose claim 2 alone shares 1 ledger id or address with the line. Read so, it "
            "is carried with the line and never withdrawn by rule."
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
    def test_the_owned_claim_left_unanswered_is_carried_with_the_line(self) -> None:
        update = _revise(LINE)

        claims = update["isr_reports"]["static"].claims
        assert [c.claim for c in claims] == [
            "Routine 0x1030 polls the pipe until the child exits.",
            "Slot 0x10d80 writes the exit code into 0x4f8 for routine 0x1030.",
        ]
        assert claims[1].carried_contested_by == ["L1 (round 1)"]
        assert not any(
            "withdrawn by rule" in row["sentence"] for row in update.get("dropped_claims") or []
        )
        said = update["revision_replacements"]
        assert any("it is read as claim 2 of the static analyst" in s for s in said)
        assert not any(NO_ANALYST_NAMED in s for s in said)
        # The analyst the line does not name keeps its answer in force.
        assert len(update["isr_reports"]["reverser"].claims) == 2

    def test_the_round_records_cited_new_and_the_line_s_carried_mark(self) -> None:
        update = _revise(LINE)

        (record,) = update["revision_rounds"]
        (fact,) = record["lines"]
        assert fact["cited_new"] == []
        # The line carries no mark: it is no carry that counts.
        assert fact["carried_valid"] is False


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


def _record(
    earlier: str,
    *,
    filed: dict[str, list[str]] | None = None,
    carried_valid: bool = True,
    cited_new: list[str] | None = None,
) -> dict[str, Any]:
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
                "cited_new": list(cited_new or []),
                "carried_valid": carried_valid,
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
        record = _record(FIRST, carried_valid=False)

        assert not carried_without_new_evidence([SECOND], {SECOND: 1}, record)
        assert debate_route(_state(SECOND, FIRST, record), max_rounds=5) == (
            "revision",
            NO_CONSENSUS,
        )

    def test_an_earlier_carry_that_did_not_count_keeps_it_going(self) -> None:
        # The earlier line wrote [carried: L1], but its mark named a line about other things.
        assert not carried_without_new_evidence(
            [THIRD], {THIRD: 1}, _record(SECOND, carried_valid=False)
        )

    def test_an_analyst_citing_an_entry_it_filed_on_the_point_keeps_it_going(self) -> None:
        record = _record(SECOND, filed={"static": ["ev_0125"]}, cited_new=["static"])

        assert not carried_without_new_evidence([THIRD], {THIRD: 1}, record)

    def test_an_entry_filed_but_not_cited_on_the_point_is_nothing_new(self) -> None:
        record = _record(SECOND, filed={"static": ["ev_0125", "ev_0126"]})

        assert carried_without_new_evidence([THIRD], {THIRD: 1}, record)

    def test_a_record_without_the_new_facts_reads_as_before(self) -> None:
        record = _record(SECOND)
        for key in ("cited_new", "carried_valid"):
            del record["lines"][0][key]

        assert not carried_without_new_evidence([THIRD], {THIRD: 1}, record)

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

    def test_a_line_with_no_names_field_keeps_it_going(self) -> None:
        line = THIRD.replace("[analysts: STATIC ANALYST] ", "")

        assert not carried_without_new_evidence([line], {line: 1}, _record(SECOND))

    def test_a_line_not_carried_beside_it_keeps_it_going(self) -> None:
        other = "[analysts: STATIC ANALYST] [new] Claim 2 names a mutex. [blocking: x]"

        assert not carried_without_new_evidence([THIRD, other], {THIRD: 1}, _record(SECOND))

    def test_unchanged_points_are_read_first(self) -> None:
        # The same point in other words: the older rule ends it, by its own reason.
        same = THIRD.replace("through slot 0x10d80", "as before").replace(
            "Claim 1 again", "Claim 1 still"
        )
        earlier = SECOND.replace(", as 0x2200 zeroes the value", "")
        state = _state(same, earlier, _record(earlier))

        assert carried_without_new_evidence([same], {same: 1}, _record(earlier))
        assert debate_route(state, max_rounds=5) == ("judge", POINTS_UNCHANGED)

    def test_the_shipped_settings_route_it_to_the_judge(self) -> None:
        settings = Settings(_env_file=None)
        # The shipped server map is loaded and untouched by the rule.
        assert settings.mcp.servers
        router = ConsensusRouter(settings)

        state = _state(THIRD, SECOND, _record(SECOND))

        assert router.should_continue(state) == "judge"  # type: ignore[arg-type]


class TestTheRoundRecord:
    def test_cited_new_names_who_cited_its_filing_beside_the_line_s_points(self) -> None:
        def cited(name: str, new: Any, ids: Any, places: Any) -> bool:
            return name == "static" and "ev_0125" in new and 0x1030 in places

        facts = line_round_facts(
            [SECOND],
            [],
            ["static"],
            ["static"],
            {},
            lambda *_a: True,
            NAMES,
            {"static": ["ev_0125"], "reverser": ["ev_0126"]},
            cited=cited,
            carried_valid={SECOND: True},
        )

        assert facts[0]["cited_new"] == ["static"]
        assert facts[0]["carried_valid"] is True

    def test_without_the_new_arguments_the_record_is_as_before(self) -> None:
        (fact,) = line_round_facts([SECOND], [], ["static"], ["static"], {}, lambda *_a: 0, NAMES)

        assert "cited_new" not in fact
        assert "carried_valid" not in fact

    def test_a_carry_counts_only_where_it_shares_a_point_with_the_line_it_names(self) -> None:
        other = "[analysts: STATIC ANALYST] [carried: L1] a mutex at ev_0099. [blocking: x]"
        record = _record(FIRST)

        valid = valid_carries([SECOND, other, FIRST], {SECOND: 1, other: 1}, record)

        assert valid == {SECOND: True, other: False, FIRST: False}


# ---------------------------------------------------------------------------
# The revision's own claim numbers, keyed to the merged answer's
# ---------------------------------------------------------------------------


class TestTheNumberingKey:
    def test_the_key_maps_each_number_the_revision_gave_to_the_merged_one(self) -> None:
        merge = RevisionMerge(numbering=((1, 1), (2, 4), (6, 27)))

        assert numbering_key(merge) == (
            "(The text below names this analyst's claims by the numbers its revision gave them. "
            "In the numbering above, its claim 1 is claim 1; its claim 2 is claim 4; its claim "
            "6 is claim 27. A number not listed names no claim the platform read from the "
            "revision.)"
        )
        text = f"  Claim 1: x\n{WRITTEN_BESIDES_CLAIMS}\nOPEN ITEMS\n- to close claim 6."
        keyed = with_numbering_key(text, merge)
        assert keyed == (
            f"  Claim 1: x\n{WRITTEN_BESIDES_CLAIMS}\n{numbering_key(merge)}\n"
            "OPEN ITEMS\n- to close claim 6."
        )

    def test_numbers_that_agree_leave_the_text_byte_identical(self) -> None:
        text = f"  Claim 1: x\n{WRITTEN_BESIDES_CLAIMS}\nprose"

        assert with_numbering_key(text, RevisionMerge(numbering=((1, 1), (2, 2)))) == text
        assert with_numbering_key("no besides", RevisionMerge(numbering=((2, 5),))) == (
            "no besides"
        )

    def test_the_merge_numbers_the_revision_s_blocks_where_they_stand(self) -> None:
        in_force = _isr(
            "static",
            _claim("Mutex runnung is created at 0x3962.", "[ev_0011]"),
            _claim("Routine 0x1030 polls the pipe until the child exits.", "[ev_0056]"),
            _claim("Beacon thread 0x5750 waits 180 s.", "[ev_0060]"),
        )
        # The revision writes the polling claim again first and adds a new one.
        revision = _isr(
            "static",
            _claim("Routine 0x1030 polls the pipe until the child exits.", "[ev_0056]"),
            _claim("Routine 0x7b98 returns the AppData path 0x1a.", "[ev_0122]"),
        )

        merge = merge_revision(in_force, revision, "the revision", 1, {})

        assert merge.numbering == ((1, 2), (2, 4))

    def test_numbers_written_on_some_blocks_only_give_no_key(self) -> None:
        in_force = _isr("static", _claim("Mutex at 0x3962.", "[ev_0011]"), _claim("Other.", ""))
        first = _claim("Mutex at 0x3962 again.", "[ev_0011]")
        first.note_number("4")
        second = _claim("A new claim on 0x7b98.", "[ev_0122]")

        merge = merge_revision(in_force, _isr("static", first, second), "rev", 1, {})

        assert merge.numbering == ()


# ---------------------------------------------------------------------------
# A claim a validation retry writes again is not put back beside it
# ---------------------------------------------------------------------------

POLLING = (
    "Routine 0x1030 polls the child. It calls slot 0x10d80 on the handle, tests 0x103, sleeps "
    "through 0xc934 and ends with slot 0x10d90."
)
POLLING_AGAIN = (
    "Routine 0x1030 runs its child until it exits: slot 0x10d80 on the process handle, a test "
    "of 0x103, a sleep through 0xc934."
)


class TestARetryThatRewritesAClaim:
    def test_a_claim_written_again_is_still_asked_about_and_paired_with_its_block(self) -> None:
        first = _isr(
            "static",
            _claim(POLLING, "[ev_0056]"),
            _claim("The mutex is runnung at 0x3962 and 0xfa00.", "[ev_0011]"),
        )
        retried = _isr(
            "static",
            _claim("Beacon thread 0x5750 waits 180 s.", "[ev_0060]"),
            _claim(POLLING_AGAIN, "[ev_0056]"),
        )

        drops = retry_drops(first, retried, "")

        assert [(c.claim[:10], missing) for c, missing in drops.claims] == [
            ("Routine 0x", ("0x10d90",)),
            ("The mutex ", ("0x3962", "0xfa00")),
        ]
        assert [(c.claim[:10], block) for c, block in drops.rewritten] == [("Routine 0x", 2)]

    def test_a_claim_sharing_less_than_two_thirds_of_its_values_is_paired_with_none(
        self,
    ) -> None:
        claim = _claim("Routine 0x1030 calls 0x10d80, 0x10d88 and 0x10d90.", "[ev_0056]")
        retried = _isr("static", _claim("Routine 0x1030 calls 0x10d80.", "[ev_0056]"))

        assert rewritten_in(claim, retried) is None
        assert retry_drops(_isr("static", claim), retried, "").rewritten == ()

    def test_kept_it_takes_the_place_of_the_block_that_wrote_it_again(self) -> None:
        from maljan.agents.base_agent import BaseAnalyst

        kept = _claim(POLLING, "[ev_0056]")
        other = _claim("The mutex is runnung at 0x3962 and 0xfa00.", "[ev_0011]")
        first = _isr("static", kept, other)
        beacon = _claim("Beacon thread 0x5750 waits 180 s.", "[ev_0060]")
        retried = _isr("static", beacon, _claim(POLLING_AGAIN, "[ev_0056]"))
        drops = retry_drops(first, retried, "")
        agent = MagicMock()

        claims = BaseAnalyst._with_restored_claims(agent, first, retried, [kept, other], drops)

        # The polling claim is stated once, as kept; the other kept claim follows.
        assert [c.claim for c in claims] == [beacon.claim, POLLING, other.claim]
        agent.logger.info.assert_called_once()
        assert agent.logger.info.call_args.args[2:] == ("1", 2)
