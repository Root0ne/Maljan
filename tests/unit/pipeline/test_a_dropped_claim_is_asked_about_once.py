"""A revision that drops a claim stating a reported value says so, or is asked once.

A revision used to replace the answer in force wholesale: a claim of the
earlier answer that the revision did not write again was gone, and nothing
recorded it. A claim's content, for this check, is the values it states: an
address or constant written in hex, an ATT&CK technique id, a quoted value.
A claim of the answer in force whose values the revision no longer carries is
dropped. The analyst withdraws it with a reason on a ``WITHDRAWN:`` line, or is
asked once to keep it or withdraw it; what it answers stands. Every value
below is synthetic.
"""

from __future__ import annotations

from maljan.pipeline.claim_drops import (
    CLAIMS_DROPPED_CODE,
    claim_values,
    claims_dropped_violation,
    dropped_claim_sentence,
    dropped_claims,
    revision_changed,
    without_withdrawals,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding


def _isr(
    *claims: str | tuple[str, str], answer: str = "", findings: list | None = None
) -> AgentISR:
    built = []
    for claim in claims:
        text, technique = (claim, None) if isinstance(claim, str) else claim
        built.append(
            ClaimEvidence(
                claim=text, evidence_ref="[ev_0001]", confidence=0.8, technique_id=technique
            )
        )
    isr = AgentISR(agent_id="beta", domain="static", claims=built, findings=findings or [])
    if answer:
        isr.note_answer_text(answer)
    return isr


MAPPING = "The loop picks body format 0xa10 for kind 2 and 0xa20 for kind 1 (selector 0x3ff0)."
PROSE = "The sample is careful about the order it does things in."


class TestTheValuesOfAClaim:
    def test_hex_values_technique_ids_and_quoted_values_are_read(self) -> None:
        values = claim_values('Opens `cfg_name` at 0x00A0 and sends "x-tag" (T1105)', "T1071.001")

        assert "0xa0" in values
        assert "T1105" in values and "T1071.001" in values
        assert "cfg_name" in values and "x-tag" in values

    def test_a_hex_value_is_one_value_however_it_is_spelled(self) -> None:
        assert claim_values("0x0F") == claim_values("0xf")

    def test_prose_states_no_value(self) -> None:
        assert claim_values(PROSE) == frozenset()


class TestWhatIsDropped:
    def test_a_claim_whose_values_the_revision_carries_is_not_dropped(self) -> None:
        revision = _isr("Reworded: kinds 2/1 use 0xa10/0xa20, chosen by 0x3ff0.")

        assert dropped_claims(_isr(MAPPING), revision) == []

    def test_a_claim_with_a_value_the_revision_lost_is_dropped(self) -> None:
        revision = _isr("The loop builds a body at 0xa10 and 0xa20.")

        dropped = dropped_claims(_isr(MAPPING), revision)

        assert [d.claim for d in dropped] == [MAPPING]
        assert "0x3ff0" in dropped[0].missing
        assert dropped[0].reason == ""

    def test_a_finding_of_the_revision_carries_a_value_too(self) -> None:
        finding = Finding(title="Body formats", detail="kinds 2/1: 0xa10/0xa20, selector 0x3ff0")
        revision = _isr("Something else at 0x10.", findings=[finding])

        assert dropped_claims(_isr(MAPPING), revision) == []

    def test_a_prose_claim_is_not_tracked(self) -> None:
        assert dropped_claims(_isr(PROSE), _isr("Other words.")) == []

    def test_a_dropped_technique_is_dropped(self) -> None:
        dropped = dropped_claims(_isr(("Runs a script.", "T1059")), _isr("Runs a script."))

        assert [d.claim for d in dropped] == ["Runs a script."]

    def test_a_withdrawal_line_with_a_reason_withdraws_it(self) -> None:
        answer = (
            "CLAIM: The loop builds a body at 0xa10.\n---\nDISPUTES:\n"
            "- WITHDRAWN: selector 0x3ff0 kinds — the selector is a counter, not a kind.\n"
        )
        revision = _isr("The loop builds a body at 0xa10.", answer=answer)

        dropped = dropped_claims(_isr(MAPPING), revision)

        assert dropped[0].reason == "the selector is a counter, not a kind."

    def test_a_withdrawal_line_without_a_reason_is_no_withdrawal(self) -> None:
        answer = "CLAIM: The loop builds a body at 0xa10.\nWITHDRAWN: 0x3ff0\n"
        revision = _isr("The loop builds a body at 0xa10.", answer=answer)

        assert dropped_claims(_isr(MAPPING), revision)[0].reason == ""

    def test_a_withdrawal_that_names_another_claim_withdraws_nothing_here(self) -> None:
        answer = "WITHDRAWN: 0x77 — wrong function.\n"
        revision = _isr("The loop builds a body at 0xa10.", answer=answer)

        assert dropped_claims(_isr(MAPPING), revision)[0].reason == ""

    def test_nothing_in_force_drops_nothing(self) -> None:
        assert dropped_claims(None, _isr("x")) == []


class TestTheQuestion:
    def test_it_quotes_each_dropped_claim_not_withdrawn_and_how_to_answer(self) -> None:
        dropped = dropped_claims(_isr(MAPPING), _isr("Builds a body at 0xa10 and 0xa20."))

        violation = claims_dropped_violation(dropped)

        assert violation is not None
        assert violation.code == CLAIMS_DROPPED_CODE
        assert MAPPING in violation.message
        assert "WITHDRAWN:" in violation.message
        assert "0x3ff0" in violation.message

    def test_a_withdrawn_claim_is_not_asked_about(self) -> None:
        answer = "WITHDRAWN: 0x3ff0 — it is a counter.\n"
        dropped = dropped_claims(_isr(MAPPING), _isr("Body at 0xa10 and 0xa20.", answer=answer))

        assert claims_dropped_violation(dropped) is None

    def test_nothing_dropped_asks_nothing(self) -> None:
        assert claims_dropped_violation([]) is None


class TestTheRecord:
    def test_a_sentence_names_the_analyst_the_round_and_the_claim(self) -> None:
        dropped = dropped_claims(_isr(MAPPING), _isr("Body at 0xa10 and 0xa20."))[0]

        sentence = dropped_claim_sentence("beta", 2, dropped)

        assert "beta" in sentence and "round-2" in sentence and MAPPING in sentence
        assert "not withdrawn" in sentence

    def test_a_withdrawn_claim_s_sentence_carries_the_reason(self) -> None:
        answer = "WITHDRAWN: 0x3ff0 — it is a counter.\n"
        dropped = dropped_claims(_isr(MAPPING), _isr("Body at 0xa10 and 0xa20.", answer=answer))[0]

        assert "it is a counter." in dropped_claim_sentence("beta", 2, dropped)


class TestWithdrawalsAreNotDisputes:
    def test_withdrawal_lines_leave_the_disputes(self) -> None:
        items = ["WITHDRAWN: 0x3ff0 — a counter.", "**Withdrawn:** 0x1 — gone", "gamma is wrong"]

        assert without_withdrawals(items) == ["gamma is wrong"]


class TestWhetherARevisionChangedAnything:
    def test_the_same_claims_reworded_with_the_same_values_change_nothing(self) -> None:
        before = _isr((MAPPING, "T1071.001"), PROSE)
        after = _isr(("Kinds 2 and 1 use 0xa10 and 0xa20; 0x3ff0 selects.", "T1071.001"), PROSE)

        assert revision_changed(before, after) is False

    def test_a_new_claim_is_a_change(self) -> None:
        assert revision_changed(_isr(MAPPING), _isr(MAPPING, "Also writes 0x99.")) is True

    def test_a_changed_technique_is_a_change(self) -> None:
        assert revision_changed(_isr((MAPPING, "T1071")), _isr((MAPPING, "T1105"))) is True

    def test_a_changed_finding_is_a_change(self) -> None:
        before = _isr(MAPPING, findings=[Finding(title="One")])
        after = _isr(MAPPING, findings=[Finding(title="Two")])

        assert revision_changed(before, after) is True

    def test_reworded_prose_is_a_change(self) -> None:
        assert revision_changed(_isr(PROSE), _isr("Other words entirely.")) is True

    def test_nothing_in_force_is_a_change_when_the_revision_says_something(self) -> None:
        assert revision_changed(None, _isr(MAPPING)) is True


def test_a_network_value_in_a_dropped_claim_s_sentence_is_defanged() -> None:
    in_force = _isr("Posts to https://relay-node.top/gate at 0x40.")
    dropped = dropped_claims(in_force, _isr("Something else."))[0]

    sentence = dropped_claim_sentence("beta", 1, dropped)

    assert "relay-node.top" not in sentence
    assert "relay-node[.]top" in sentence
    assert "https://" not in sentence
