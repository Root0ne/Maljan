"""A mediation line names every claim of a range or a list, and states a reference it cannot place.

"claims 32-34", "17 to 19" or "claims 3, 4, and 5" name each of those claims
of the analyst the first number is written for, so a claim the mediator
blocked inside a range is withdrawn by rule exactly as a single cited claim
is (``revision_merge``). A range longer than the cap, one that ends below
where it starts, and a claim number no analyst is named for are never guessed
onto a claim: they withdraw nothing, and the merge says so in one sentence
per reference.

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
    claims_named_by_lines,
    read_claim_numbers,
    read_claim_references,
)
from maljan.pipeline.nodes import make_revision_node
from maljan.pipeline.revision_merge import merge_revision
from maljan.schemas.isr_models import AgentISR

PARTICIPANTS = ["static", "all_tools_reverser_ghidra", "dynamic"]
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


class TestARangeIsCapped:
    def test_a_range_of_the_cap_is_read_whole(self) -> None:
        line = f"{STATIC} STATIC ANALYST claims 1 to {CLAIM_RANGE_CAP} say X. {BLOCKS}"

        assert _named(line) == {"static": list(range(1, CLAIM_RANGE_CAP + 1))}

    @pytest.mark.parametrize(
        ("written", "said"),
        [(f"1 to {CLAIM_RANGE_CAP + 1}", f"claims 1-{CLAIM_RANGE_CAP + 1}"), ("9-5", "claims 9-5")],
    )
    def test_a_longer_or_a_falling_range_names_no_claim_and_is_unplaced(
        self, written: str, said: str
    ) -> None:
        line = f"{STATIC} STATIC ANALYST claims {written} say X. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        # Not even its first number: the platform never guesses which claims it means.
        assert refs.named == {}
        [reference] = refs.unplaced
        assert reference.analysts == ("static",)
        assert (reference.claims, reference.why, reference.line) == (said, RANGE_NOT_READ, 1)
        assert reference.blocking is True

    def test_the_numbers_before_a_range_that_is_not_read_are_still_named(self) -> None:
        line = f"{STATIC} STATIC ANALYST claims 2, 40 to 90 say X. {BLOCKS}"

        refs = read_claim_references([line], PARTICIPANTS)

        assert _named(line) == {"static": [2]}
        assert [u.claims for u in refs.unplaced] == ["claims 40-90"]


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
            (f"{STATIC} Static claim 3 - 5 hosts answer it. {BLOCKS}", {"static": [3]}),
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
    refs = read_claim_references([line], PARTICIPANTS)
    return merge_revision(
        _isr(FOUR), _isr(answer), answer, 3, refs.named.get("static"), refs.unplaced_for("static")
    )


class TestTheMergeReadsARangeAsItReadsASingleClaim:
    def test_a_blocked_claim_inside_a_range_is_withdrawn_by_rule_as_a_single_one_is(self) -> None:
        answer = _block(MUTEX)
        ranged = _merge(f"{STATIC} Claims 2-3 say X. {BLOCKS}", answer)
        single = _merge(f"{STATIC} Claims 2 and 3 say X. {BLOCKS}", answer)

        assert ranged.withdrawn_by_rule == single.withdrawn_by_rule
        assert [n for n, _s, _r in ranged.withdrawn_by_rule] == [2, 3]
        assert ranged.withdrawn_by_rule[0][2].startswith("named by blocking line L1")
        assert ranged.merged is not None
        assert [c.claim for c in ranged.merged.claims] == [MUTEX, PERSIST]
        assert ranged.sentences("static", 3) == single.sentences("static", 3)

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
        said = [s for s in merge.sentences("static", 3) if "names no claim" in s]
        assert said == [
            "Blocking line L1 of the round-3 mediation writes claims 1-40 and names no claim of "
            f"the static analyst by it ({RANGE_NOT_READ}): no claim of that analyst's answer in "
            "force is withdrawn by rule on that reference.",
            "Blocking line L1 of the round-3 mediation writes claim 2 and names no claim of the "
            "static analyst by it (no analyst is named for it): no claim of that analyst's "
            "answer in force is withdrawn by rule on that reference.",
        ]

    def test_a_reference_past_every_claim_in_force_is_no_question_to_the_merge(self) -> None:
        merge = _merge(f"{STATIC} The static's own claim 45 says X. {BLOCKS}", _block(MUTEX))

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
                "key is 0x5a, versus the listing. [blocking: the listing shows 900 s.]",
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
            s.startswith("Blocking line L2 of the round-2 mediation writes claim 4 and names no")
            for s in said
        )
