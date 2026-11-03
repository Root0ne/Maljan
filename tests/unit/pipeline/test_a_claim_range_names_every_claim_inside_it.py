"""A mediation line names every claim of a range or a list, and states a reference it cannot place.

"claims 32-34", "17 to 19" or "claims 3, 4, and 5" name each of those claims
of the analyst the first number is written for. A claim a blocking line
reaches only so is withdrawn by rule when its reference's clause shares a
ledger id or an address with it, exactly as a single cited claim is
(``revision_merge``), and is carried and stated otherwise. Every number the
earlier reading read is named as it was. The rest of a range longer than the
cap and a claim number no analyst is read for are never guessed onto a claim:
they withdraw nothing, and one merge says so, once per reference, where the
line blocks by a mark that was read or by having none.

Every address, name and sentence here is made up for the test.
"""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.base_agent import read_claim_blocks
from maljan.pipeline.debate_facts import (
    CLAIM_RANGE_CAP,
    NO_ANALYST_NAMED,
    RANGE_NOT_READ,
    NamedClaims,
    claims_named_by_lines,
    read_claim_numbers,
    read_claim_references,
)
from maljan.pipeline.nodes import make_revision_node
from maljan.pipeline.revision_merge import _numbers_written, merge_revision
from maljan.schemas.isr_models import AgentISR

PARTICIPANTS = ["static", "all_tools_reverser_ghidra", "dynamic", "triage"]
REVERSER = "[analysts: ALL_TOOLS_REVERSER_GHIDRA ANALYST]"
STATIC = "[analysts: STATIC ANALYST]"
BLOCKS = "[blocking: the listing shows another call.]"


def _named(line: str) -> dict[str, list[int]]:
    return {
        name: sorted(claims) for name, claims in claims_named_by_lines([line], PARTICIPANTS).items()
    }


class TestEveryFormOfARangeOrAListNamesEachClaim:
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            (f"{REVERSER} REVERSER claims 32–34 say X. {BLOCKS}", [32, 33, 34]),
            (f"{REVERSER} Reverser claims 32-34 say X. {BLOCKS}", [32, 33, 34]),
            (f"{REVERSER} Claims 32—34 say X. {BLOCKS}", [32, 33, 34]),
            (f"{REVERSER} Reverser claims 32 through 34 say X. {BLOCKS}", [32, 33, 34]),
            (f"{REVERSER} REVERSER claims 17 to 19 say X. {BLOCKS}", [17, 18, 19]),
            (f"{REVERSER} ALL_TOOLS_REVERSER_GHIDRA claims 3, 4, and 5 say X. {BLOCKS}", [3, 4, 5]),
            (f"{REVERSER} Reverser claim #3 and claim 4 say X. {BLOCKS}", [3, 4]),
            (f"{REVERSER} Reverser claims 1-2, 7 and 9 to 10 say X. {BLOCKS}", [1, 2, 7, 9, 10]),
            (f"{REVERSER} Reverser claims 32 - 34 say X. {BLOCKS}", [32, 33, 34]),
            (f"{REVERSER} Reverser claim 3 or 4 says X. {BLOCKS}", [3, 4]),
        ],
    )
    def test_the_form_names_each_claim_of_the_analyst(self, line: str, expected: list[int]) -> None:
        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"all_tools_reverser_ghidra": expected}
        assert refs.unplaced == ()

    def test_each_claim_of_the_range_carries_the_line_and_its_mark(self) -> None:
        named = claims_named_by_lines(
            ["[analysts: STATIC ANALYST] Static claims 2 to 3 are loose. [not blocking: same.]"],
            PARTICIPANTS,
        )

        assert named == {"static": {2: [(1, False)], 3: [(1, False)]}}

    def test_a_range_for_an_analyst_the_field_does_not_name_is_no_question_to_it(self) -> None:
        line = (
            "[analysts: STATIC ANALYST] Static claim 5 says X, versus ALL_TOOLS_REVERSER_GHIDRA "
            f"claims 32–34. {BLOCKS}"
        )

        assert _named(line) == {"static": [5]}
        assert read_claim_references([line], PARTICIPANTS).unplaced == ()

    def test_a_claim_said_again_for_another_analyst_is_not_given_to_the_first(self) -> None:
        line = f"{STATIC} STATIC ANALYST claim 3 and claim 4 of the dynamic analyst. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"static": [3]}
        [said] = refs.unplaced
        assert (said.claims, said.why, said.analysts) == ("claim 4", NO_ANALYST_NAMED, ("static",))

    def test_a_participant_named_in_a_parenthesis_ends_the_reference(self) -> None:
        line = f"{STATIC} STATIC ANALYST claim 3 and claim 4 (TRIAGE) say X. {BLOCKS}"

        assert _named(line) == {"static": [3]}

    @pytest.mark.parametrize(
        ("written", "expected"),
        [("3-5-7", [3, 4, 5]), ("3, 2026-10-31", [3, 2026]), ("3-2 analysts", [3])],
    )
    def test_a_range_with_no_first_number_of_its_own_ends_the_reference_unsaid(
        self, written: str, expected: list[int]
    ) -> None:
        line = f"{STATIC} STATIC ANALYST claims {written} say X. {BLOCKS}"

        assert _named(line) == {"static": expected}
        assert read_claim_references([line], PARTICIPANTS).unplaced == ()


class TestTheReaderOfEveryParticipant:
    def test_each_reference_says_whether_it_stands_inside_a_mark(self) -> None:
        from maljan.pipeline.debate_facts import claim_references_of

        text = (
            "[analysts: STATIC ANALYST] STATIC ANALYST claims 2-3 are loose, versus TRIAGE "
            "claim 9. [blocking: STATIC ANALYST claims 4-6 conflict]"
        )

        refs = claim_references_of(text, PARTICIPANTS, ["static"])

        # A reference read both by name and by short form is found by each.
        assert {(r.analyst, r.numbers.numbers, r.read_before, r.in_mark) for r in refs} == {
            ("static", ("2", "3"), True, False),
            ("static", ("4",), True, True),
            ("triage", ("9",), True, False),
        }

    def test_the_references_no_analyst_is_read_for_are_one_computation(self) -> None:
        from maljan.pipeline.debate_facts import claim_references_of, unattributed_references

        text = (
            "[analysts: STATIC ANALYST, TRIAGE ANALYST] Claim 1 and claim 44 say X; the dropper "
            "claims 3 hosts, and TRIAGE ANALYST round-3 claim 24 agrees."
        )

        refs = claim_references_of(text, PARTICIPANTS, ["static", "triage"])
        found = unattributed_references(text, PARTICIPANTS, refs)

        assert [(text[at:].split()[0], n.numbers) for at, n in found] == [("Claim", ("1", "44"))]


class TestWhatTheLineSaysAroundItsReferences:
    def test_a_claim_inside_a_mark_is_read_only_as_the_earlier_reading_read_it(self) -> None:
        # The earlier reading read "claims 4" there; the rest of the range is
        # the mark's reason and names nothing more.
        line = (
            f"{STATIC} STATIC ANALYST claim 2 is loose. "
            "[blocking: STATIC ANALYST claims 4-6 conflict with it]"
        )

        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"static": [2, 4]}
        assert refs.expanded == {} and refs.unplaced == ()

    def test_a_short_form_inside_a_mark_keeps_the_earlier_readings_claims(self) -> None:
        line = (
            f"{STATIC} Static holds it. [blocking: the static analyst's claims 4 and 5 rest on it]"
        )

        named = claims_named_by_lines([line], PARTICIPANTS)

        assert named == {"static": {4: [(1, True)], 5: [(1, True)]}}

    def test_a_claim_only_the_newer_reading_reads_inside_a_mark_is_not_read(self) -> None:
        line = f"{STATIC} Static holds it. [blocking: the static analyst's claims 4, and 5 rest]"

        assert _named(line) == {"static": [4]}

    def test_an_earlier_rounds_claim_names_nothing_and_is_not_stated(self) -> None:
        line = (
            "[analysts: STATIC ANALYST] STATIC ANALYST claim 2 says X, versus TRIAGE ANALYST "
            "round-3 claim 24 and the dynamic's round-2 claims 9 to 20. "
            f"{BLOCKS}"
        )

        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"static": [2]} and refs.unplaced == ()

    def test_a_short_form_on_a_line_without_a_field_is_read_never_unplaced(self) -> None:
        line = f"Reverser claim 3 says X, versus the own claim 4. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        # Named as the earlier reading named it: not at all; not unplaced either.
        assert refs.named == {}
        assert [u.claims for u in refs.unplaced] == ["claim 4"]

    def test_a_claim_after_a_mark_that_follows_the_field_is_read(self) -> None:
        line = "[analysts: STATIC ANALYST] [not blocking: wording only.] Claim 18 says X."

        named = claims_named_by_lines([line], PARTICIPANTS)

        # The mark stands mid-line and is not read: the line blocks with no
        # claim only the newer reading reaches.
        assert named == {"static": {18: [(1, False)]}}

    @pytest.mark.parametrize(
        "line",
        [
            f"{STATIC} The analyst's own claim 4 is loose. [not blocking: the same reading.]",
            f"{STATIC} [blocking: x] The analyst's own claim 4 is loose.",
        ],
    )
    def test_a_line_that_does_not_block_or_whose_mark_is_unread_states_nothing(
        self, line: str
    ) -> None:
        refs = read_claim_references([line], PARTICIPANTS)

        assert refs.unplaced == ()

    def test_a_reference_is_stated_by_each_analyst_it_may_mean_and_kept_once(self) -> None:
        from maljan.analysis.run_summary import RunSummaryBuilder
        from maljan.pipeline.revision_merge import unplaced_sentence

        line = f"[analysts: DYNAMIC ANALYST, STATIC ANALYST] The own claim 4 says X. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)
        named = claims_named_by_lines([line], PARTICIPANTS)

        [said] = refs.unplaced
        assert said.analysts == ("dynamic", "static")
        assert refs.unplaced_for("dynamic") == refs.unplaced_for("static") == (said,)
        # A plain dict as before; each analyst it may mean still gets it.
        assert named == {}
        for name in ("dynamic", "static"):
            stated = named.get(name)
            assert isinstance(stated, NamedClaims) and stated == {}
            assert stated.unplaced == (said,)
        assert named.get("triage") is None
        sentences = [unplaced_sentence(name, 2, said) for name in ("dynamic", "static")]
        assert sentences[0] == sentences[1]
        summary = RunSummaryBuilder(start_time=0.0).set_negotiation(
            {"iteration_count": 2, "revision_replacements": sentences}, max_iterations=3
        )
        assert summary.build().to_dict()["negotiation"]["revision_replacements"] == [sentences[0]]


class TestARangeIsCapped:
    def test_a_range_of_the_cap_is_read_whole(self) -> None:
        line = f"{STATIC} STATIC ANALYST claims 1 to {CLAIM_RANGE_CAP} say X. {BLOCKS}"

        assert _named(line) == {"static": list(range(1, CLAIM_RANGE_CAP + 1))}

    def test_a_longer_range_names_its_first_claim_as_before_and_the_rest_is_unplaced(
        self,
    ) -> None:
        line = f"{STATIC} STATIC ANALYST claims 1 to {CLAIM_RANGE_CAP + 1} say X. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"static": [1]}
        [reference] = refs.unplaced
        assert reference.analysts == ("static",)
        assert (reference.claims, reference.why, reference.line) == (
            f"claims 2-{CLAIM_RANGE_CAP + 1}",
            RANGE_NOT_READ,
            1,
        )
        assert reference.marked is True

    @pytest.mark.parametrize("written", ["9-5", "3-2"])
    def test_a_falling_range_names_its_first_claim_as_before_and_states_nothing(
        self, written: str
    ) -> None:
        line = f"{STATIC} STATIC ANALYST claims {written} say X. {BLOCKS}"

        assert _named(line) == {"static": [int(written.split("-")[0])]}
        assert read_claim_references([line], PARTICIPANTS).unplaced == ()

    def test_the_numbers_before_a_range_that_is_not_read_are_still_named(self) -> None:
        line = f"{STATIC} STATIC ANALYST claims 2, 40 to 90 say X. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"static": [2, 40]}
        assert [u.claims for u in refs.unplaced] == ["claims 41-90"]

    def test_the_disputes_read_a_falling_or_a_longer_range_as_before(self) -> None:
        assert _numbers_written("I keep claims 3-2 as stated") == {3}
        assert _numbers_written("claims 1-50 stand") == {1}


class TestANumberNoAnalystIsNamedForIsUnplaced:
    def test_a_possessive_with_a_word_between_names_no_analyst(self) -> None:
        line = f"{REVERSER} The reverser's own claim 45 says X. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        assert refs.named == {}
        [said] = refs.unplaced
        assert said.analysts == ("all_tools_reverser_ghidra",)
        assert (said.claims, said.why, said.lowest) == ("claim 45", NO_ANALYST_NAMED, 45)
        assert refs.unplaced_for("all_tools_reverser_ghidra") == (said,)
        assert refs.unplaced_for("static") == ()

    def test_a_line_without_a_field_may_mean_every_participant(self) -> None:
        refs = read_claim_references([f"The own claims 4 and 6 say X. {BLOCKS}"], PARTICIPANTS)

        [said] = refs.unplaced
        assert said.analysts == tuple(PARTICIPANTS) and said.claims == "claims 4, 6"

    def test_claims_as_a_verb_with_one_number_is_no_reference(self) -> None:
        line = f"{STATIC} STATIC ANALYST claim 2 says the dropper claims 3 hosts. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"static": [2]} and refs.unplaced == ()


class TestASingleNumberIsReadAsBefore:
    @pytest.mark.parametrize(
        ("line", "expected"),
        [
            (f"{STATIC} STATIC ANALYST claim 7 is loose. {BLOCKS}", {"static": [7]}),
            (f"{STATIC} Claims 30 and 62 say a thing. {BLOCKS}", {"static": [30, 62]}),
            (f"{STATIC} Claims 4/40 say a thing. {BLOCKS}", {"static": [4, 40]}),
            (f"{STATIC} Static claim 3 - 2 analysts agree. {BLOCKS}", {"static": [3]}),
            (f"{STATIC} Static claim 3-related text. {BLOCKS}", {"static": [3]}),
            (f"{STATIC} Static claim 3 to 0x5a is the key. {BLOCKS}", {"static": [3]}),
            (f"{STATIC} STATIC ANALYST claim 0 is no claim. {BLOCKS}", {"static": []}),
            (f"{STATIC} STATIC ANALYST claim 1234567 is too long. {BLOCKS}", {"static": []}),
        ],
    )
    def test_the_line_names_what_it_named_before(
        self, line: str, expected: dict[str, list[int]]
    ) -> None:
        assert _named(line) == expected

    def test_the_reader_reads_a_list_where_it_starts(self) -> None:
        text = "claims 3 and 4, then 9"

        read = read_claim_numbers(text, text.index("3"))

        assert read is not None and read.numbers == ("3", "4") and read.unplaced == ()
        assert text[: read.end] == "claims 3 and 4"
        assert read_claim_numbers("claims none", 7) is None


def _block(sentence: str) -> str:
    return f"CLAIM: {sentence}\nEVIDENCE: [ev_0001]\nCONFIDENCE: 0.8\nTECHNIQUE: NONE\n---\n"


def _isr(text: str) -> AgentISR:
    isr = AgentISR(agent_id="static", domain="static", claims=read_claim_blocks(text).claims)
    isr.note_answer_text(text)
    return isr


MUTEX = "0x401000 creates the mutex Global\\qx7 before anything else."
BEACON = "0x402000 beacons every 600 seconds to the configured host."
CRYPTO = "0x403000 decrypts the configuration with the key 0x5a."
PERSIST = "0x404000 writes the Run key value qx7svc."
FOUR = _block(MUTEX) + _block(BEACON) + _block(CRYPTO) + _block(PERSIST)


def _merge(line: str, answer: str) -> Any:
    return merge_revision(
        _isr(FOUR),
        _isr(answer),
        answer,
        3,
        claims_named_by_lines([line], PARTICIPANTS).get("static"),
    )


class TestTheMergeReadsARangeAsItReadsASingleClaim:
    def test_a_blocked_claim_inside_a_range_is_withdrawn_by_rule_as_a_single_one_is(self) -> None:
        # Claim 3 is reached only through the range, and shares 0x403000 with the line.
        answer = _block(MUTEX)
        ranged = _merge(f"{STATIC} Claims 2-3 say X of 0x403000. {BLOCKS}", answer)
        single = _merge(f"{STATIC} Claims 2 and 3 say X of 0x403000. {BLOCKS}", answer)

        assert ranged.withdrawn_by_rule == single.withdrawn_by_rule
        assert [n for n, _s, _r in ranged.withdrawn_by_rule] == [2, 3]
        assert ranged.withdrawn_by_rule[0][2].startswith("named by blocking line L1")
        assert ranged.merged is not None
        assert [c.claim for c in ranged.merged.claims] == [MUTEX, PERSIST]
        assert ranged.sentences("static", 3) == single.sentences("static", 3)
        assert ranged.range_carried == ()

    def test_a_ledger_id_shared_with_the_line_withdraws_a_claim_inside_a_range(self) -> None:
        # Every claim of FOUR cites ev_0001.
        merge = _merge(f"{STATIC} Claims 2 to 4 rest on ev_0001 alone. {BLOCKS}", _block(MUTEX))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2, 3, 4]

    def test_a_claim_inside_a_range_sharing_nothing_with_the_line_is_carried_and_stated(
        self,
    ) -> None:
        merge = _merge(f"{STATIC} Claims 2-4 say X of 0x402000. {BLOCKS}", _block(MUTEX))

        # Claim 2 is cited by its own number, as dev read it; claim 3 and 4
        # are reached through the range and share no id or address with it.
        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2]
        assert merge.merged is not None
        assert [c.claim for c in merge.merged.claims] == [MUTEX, CRYPTO, PERSIST]
        crypto = merge.merged.claims[1]
        assert crypto.carried_contested_by == ["L1 (round 3)"]
        assert [(n, line, ref) for n, _s, line, ref in merge.range_carried] == [
            (3, 1, "claims 2-4"),
            (4, 1, "claims 2-4"),
        ]
        said = merge.sentences("static", 3)
        assert (
            "Blocking line L1 of the round-3 mediation names claims 2-4 of the static analyst; "
            "claim 3 of its answer in force (" in said[-2]
        )
        assert said[-2].endswith("shares no ledger id or address with it, so it is carried.")

    def test_a_list_going_on_is_guarded_as_a_range_is(self) -> None:
        # The earlier reading read "2, 3" and stopped at ", and 4".
        merge = _merge(f"{STATIC} Claims 2, 3, and 4 say X. {BLOCKS}", _block(MUTEX))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2, 3]
        assert [n for n, *_rest in merge.range_carried] == [4]

    def test_a_claim_the_line_also_cites_by_its_own_number_is_not_guarded(self) -> None:
        merge = _merge(
            f"{STATIC} Claims 2-4 say X, STATIC ANALYST claim 4 most. {BLOCKS}", _block(MUTEX)
        )

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2, 4]
        assert [n for n, *_rest in merge.range_carried] == [3]

    def test_a_token_in_another_analysts_clause_is_not_the_ranges(self) -> None:
        line = (
            "[analysts: STATIC ANALYST, TRIAGE ANALYST] STATIC ANALYST claims 2-3 repeat one "
            f"technique, while TRIAGE claim 9 places the decoder at 0x403000. {BLOCKS}"
        )

        merge = _merge(line, _block(MUTEX))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2]
        assert [n for n, *_rest in merge.range_carried] == [3]

    def test_a_token_in_a_marks_reason_is_not_the_ranges(self) -> None:
        line = f"{STATIC} Claims 2-3 say X. [blocking: the listing at 0x403000 shows more.]"

        merge = _merge(line, _block(MUTEX))

        assert [n for n, *_rest in merge.range_carried] == [3]

    def test_a_sentence_opening_with_a_ledger_id_is_not_the_ranges_clause(self) -> None:
        # Every claim of FOUR cites ev_0001; the range's own sentence does not.
        line = (
            f"{STATIC} STATIC claims 2-4 repeat one technique. ev_0001 shows the decoder. {BLOCKS}"
        )

        merge = _merge(line, _block(MUTEX))

        assert [n for n, _s, _r in merge.withdrawn_by_rule] == [2]
        assert [n for n, *_rest in merge.range_carried] == [3, 4]

    def test_a_range_the_disputes_argue_answers_the_line(self) -> None:
        answer = _block(MUTEX)
        revision = _isr(answer)
        revision.dissent_items = ["I keep claims 2-3: the listing the line cites is another call."]
        refs = read_claim_references([f"{STATIC} Claims 2-3 say X. {BLOCKS}"], PARTICIPANTS)

        merge = merge_revision(_isr(FOUR), revision, answer, 3, refs.named.get("static"))

        assert merge.withdrawn_by_rule == ()
        assert merge.merged is not None
        assert [c.claim for c in merge.merged.claims] == [MUTEX, BEACON, CRYPTO, PERSIST]

    def test_an_unplaced_reference_withdraws_nothing_and_is_stated(self) -> None:
        answer = _block(MUTEX)

        merge = _merge(
            f"{STATIC} The static's own claim 2 says X; STATIC ANALYST claims 1 to 40 say Y. "
            f"{BLOCKS}",
            answer,
        )

        assert merge.withdrawn_by_rule == ()
        assert merge.merged is not None
        assert [c.claim for c in merge.merged.claims] == [MUTEX, BEACON, CRYPTO, PERSIST]
        said = [s for s in merge.sentences("static", 3) if "on that reference" in s]
        assert said == [
            "Blocking line L1 of the round-3 mediation writes claims 2-40 of the static analyst, "
            f"{RANGE_NOT_READ}: no claim of it is withdrawn by rule on that reference.",
            "Blocking line L1 of the round-3 mediation writes claim 2 and the platform reads no "
            "analyst for it: no claim is withdrawn by rule on that reference.",
        ]

    def test_an_unmarked_line_is_a_line_not_a_blocking_line(self) -> None:
        merge = _merge(f"{STATIC} The static's own claim 2 says X.", _block(MUTEX))

        assert [s for s in merge.sentences("static", 3) if "on that reference" in s] == [
            "Line L1 of the round-3 mediation writes claim 2 and the platform reads no analyst "
            "for it: no claim is withdrawn by rule on that reference."
        ]

    def test_a_range_past_every_claim_in_force_is_no_question_to_the_merge(self) -> None:
        merge = _merge(f"{STATIC} STATIC ANALYST claims 30 to 60 say X. {BLOCKS}", _block(MUTEX))

        assert merge.unplaced == ()

    def test_the_node_withdraws_inside_a_range_and_states_what_it_cannot_place(self) -> None:
        from maljan.core.config import MEDIATOR_AGENT_NAME
        from maljan.pipeline.state import AgentArgument

        answer = _block(MUTEX) + _block(PERSIST)
        container = MagicMock()
        container.is_mock = False
        container.agent_registry.list_agents.return_value = ["static"]
        container.analyst_keys.return_value = ["static"]
        container.agent_role.side_effect = lambda n: n
        container.config.llm.parallel_analysts = False
        agent = MagicMock()
        agent.safe_revise_isr.return_value = (answer, _isr(answer))
        container.get_agent.return_value = agent
        container.load_chunked.return_value = [MagicMock(content="data")]
        container.load_data.return_value = "data"
        mediation = AgentArgument(
            agent_name=MEDIATOR_AGENT_NAME,
            finding="revise",
            contradictions=[
                "[analysts: STATIC ANALYST] Claims 2 to 3 say the beacon waits 600 s and the "
                "key 0x403000 uses is 0x5a, versus the listing. [blocking: the listing shows "
                "900 s.]",
                "[analysts: STATIC ANALYST] The analyst's own claim 4 names the key loosely. "
                "[blocking: the listing names another value.]",
            ],
            revise=["static"],
        )
        state = {
            "file_hash": "abc",
            "iteration_count": 2,
            "discussion_history": [mediation],
            "reports": {"static": FOUR},
            "isr_reports": {"static": _isr(FOUR)},
        }

        out = asyncio.run(make_revision_node(container)(state))

        assert [c.claim for c in out["isr_reports"]["static"].claims] == [MUTEX, PERSIST]
        ruled = {r["claim"] for r in out["dropped_claims"] if "withdrawn by rule" in r["sentence"]}
        assert ruled == {BEACON, CRYPTO}
        said = out["revision_replacements"]
        assert any(
            s.startswith(
                "Blocking line L2 of the round-2 mediation writes claim 4 and the platform"
            )
            for s in said
        )
