"""A value of the answer in force that a revision states nowhere is recorded, not asked.

A revision used to replace the answer in force wholesale, and what it no longer
said left no trace. The platform now records, per analyst, round and claim,
the values the answer in force stated that appear nowhere in the revision's
whole text. Nothing is asked: the record is a right-or-absent fact, so the
search is generous about spelling:

- hex and decimal are one number (``0xf`` is ``15``);
- a decompiler's name carries an address (``FUN_180003cf4`` is ``0x3cf4``
  under any image base);
- a defanged value is the value (``relay-node[.]top``);
- a quoted value is tracked only when it has no space inside: quoted prose is
  not a value.

Convergence is a fact of the same kind: a revision that is the answer in force
again after whitespace changed nothing. Every value below is synthetic.
"""

from __future__ import annotations

from maljan.pipeline.claim_drops import (
    answer_unchanged,
    claim_values,
    dropped_values,
    dropped_values_sentence,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence


def _isr(*claims: str) -> AgentISR:
    return AgentISR(
        agent_id="beta",
        domain="static",
        claims=[ClaimEvidence(claim=c, evidence_ref="[ev_0001]", confidence=0.8) for c in claims],
    )


MAPPING = "Command 15 picks body format 0xa10 for kind 2 (selector 0x3ff0)."


class TestTheValuesOfAClaim:
    def test_hex_decimal_technique_and_quoted_values_are_read(self) -> None:
        values = claim_values('Opens `cfg_name` at 0x00A0, id 15, sends "x-tag" (T1105)')

        assert {"0xa0", "15", "T1105", "cfg_name", "x-tag"} <= values

    def test_quoted_prose_is_not_a_value(self) -> None:
        assert "no write path exists" not in claim_values('It says "no write path exists".')

    def test_an_unbalanced_quote_yields_no_fragment(self) -> None:
        values = claim_values('A "shim, then a call')

        assert not any("shim" in v for v in values)


class TestWhatIsRecorded:
    def test_a_value_stated_nowhere_is_recorded_with_its_claim(self) -> None:
        dropped = dropped_values(_isr(MAPPING), _isr("Body format 0xa10."), "Body format 0xa10.")

        assert [d.claim for d in dropped] == [MAPPING]
        assert set(dropped[0].missing) == {"15", "2", "0x3ff0"}

    def test_a_value_anywhere_in_the_revision_s_text_is_carried(self) -> None:
        text = (
            "CLAIM: Body format 0xa10, kind 2.\nThe selector at 0x3ff0 chooses; command 15 too.\n"
        )

        assert dropped_values(_isr(MAPPING), _isr("Body format 0xa10."), text) == []

    def test_hex_and_decimal_are_one_number(self) -> None:
        text = "Command 0xf picks format 2576 for kind 2 (selector 16368)."

        assert dropped_values(_isr(MAPPING), _isr(text), text) == []

    def test_a_decompiler_name_carries_its_address(self) -> None:
        in_force = _isr("The handler at 0x3cf4 runs it.")
        text = "FUN_180003cf4 runs it."

        assert dropped_values(in_force, _isr(text), text) == []

    def test_a_defanged_value_is_the_value(self) -> None:
        in_force = _isr('Posts to "relay-node.top" at 0x40.')
        text = "Posts to relay-node[.]top at 0x40."

        assert dropped_values(in_force, _isr(text), text) == []

    def test_a_dropped_technique_is_recorded(self) -> None:
        in_force = AgentISR(
            agent_id="beta",
            domain="static",
            claims=[
                ClaimEvidence(
                    claim="Runs a script.",
                    evidence_ref="[ev_0001]",
                    confidence=0.8,
                    technique_id="T1059",
                )
            ],
        )

        dropped = dropped_values(in_force, _isr("Runs a script."), "Runs a script.")

        assert dropped[0].missing == ("T1059",)

    def test_nothing_in_force_records_nothing(self) -> None:
        assert dropped_values(None, _isr("x 0x10"), "x 0x10") == []

    def test_the_sentence_names_the_analyst_round_values_and_claim_defanged(self) -> None:
        in_force = _isr("Posts to https://relay-node.top/gate at 0x40.")
        dropped = dropped_values(in_force, _isr("Other."), "Other.")[0]

        sentence = dropped_values_sentence("beta", 2, dropped)

        assert "beta" in sentence and "round-2" in sentence and "0x40" in sentence
        assert "relay-node.top" not in sentence and "relay-node[.]top" in sentence


class TestAnAnswerThatDidNotChange:
    def test_the_same_answer_after_whitespace_is_unchanged(self) -> None:
        assert answer_unchanged("CLAIM: a\n\nEVIDENCE:  b ", "CLAIM: a EVIDENCE: b") is True

    def test_a_reworded_answer_is_changed(self) -> None:
        assert answer_unchanged("CLAIM: 0x10 injects", "CLAIM: 0x10 does not inject") is False

    def test_a_changed_confidence_is_changed(self) -> None:
        assert answer_unchanged("CONFIDENCE: 0.9", "CONFIDENCE: 0.3") is False

    def test_an_empty_answer_is_never_unchanged(self) -> None:
        assert answer_unchanged("", "") is False


class TestADecimalCountsOnlyAsAStatedValue:
    def test_a_heading_or_a_reference_number_is_not_a_value(self) -> None:
        values = claim_values(
            "CLAIM 3 — Round 2 re-read: as in Claim 14/15 and step 4, the gate aborts "
            "below 75 processes."
        )

        assert "75" in values
        assert not {"3", "2", "14", "15", "4"} & values

    def test_a_list_number_opening_the_claim_is_not_a_value(self) -> None:
        assert "1" not in claim_values("1. The loop sleeps 180 s.")
        assert "180" in claim_values("1. The loop sleeps 180 s.")

    def test_a_number_inside_a_word_is_not_a_value(self) -> None:
        assert not {"32", "64", "8"} & claim_values("Calls Win32 APIs on x64 in utf-8.")

    def test_a_reverser_shaped_revision_records_only_the_values_it_lost(self) -> None:
        in_force = _isr(
            "[Decoding — CONFIRMED] Round 2 re-read of FUN_10000ae78 (ev_0133, see Claim 4): "
            "seed `u32@[arg1]`, 7 of 105 texts use key 0x33; the loop at 0x5750 waits 180 s.",
        )
        text = (
            "CLAIM 1 — [Decoding] The decoder at 0xae78 (ev_0333): seed `u32@[arg1]`, key "
            "0x33, 105 texts; the loop at 0x5750 waits 180 s.\n"
        )

        dropped = dropped_values(in_force, _isr(text), text, revision_round=3)

        assert [d.missing for d in dropped] == [("7",)]

    def test_the_round_s_own_number_is_not_recorded(self) -> None:
        in_force = _isr("In round 3 the count read 3 entries and 0x40.")

        dropped = dropped_values(in_force, _isr("Other."), "Other.", revision_round=3)

        assert dropped[0].missing == ("0x40",)
