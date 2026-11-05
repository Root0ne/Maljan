""" "Its claim N" on a blocking line is read for the line's one analyst.

A mediator writes a line such as "Claim 27 states X, while its claim 40 says
not X, and its notes lower claim 27". The earlier reading read "claim 40" and
the repeated "claim 27" for no analyst, so withdraw-by-rule could not act on
the line. Now:

- on a line whose field names one analyst, "its claim N" (or "its own claim
  N") is that analyst's claim when no other participant is named before it,
  read as the newer reading reads a reference: withdrawn by rule only where
  its clause shares a ledger id or an address with the claim;
- a bare "claim N" the line already names for that analyst is that claim
  written again, not an unplaced reference;
- a bare "claim N" that repeats nothing stays unplaced, as before, and "its"
  binds nothing after another participant's name, on a field of two
  analysts, or inside a mark's reason.

Every value is synthetic.
"""

from __future__ import annotations

from maljan.pipeline.debate_facts import (
    NO_ANALYST_NAMED,
    claims_named_by_lines,
    read_claim_references,
)
from maljan.pipeline.revision_merge import merge_revision
from maljan.schemas.isr_models import AgentISR, ClaimEvidence

NAMES = ["a", "b"]

LINE = (
    '[analysts: a] Claim 27 states the key "k1" is applied at 0.85, while its claim 40 says no '
    "key use is shown, and its notes lower claim 27 to 0.50. [blocking: x]"
)


def test_its_claim_and_a_repeated_number_are_read_for_the_analyst() -> None:
    references = read_claim_references([LINE], NAMES)

    assert {k: set(v) for k, v in references.named.items()} == {"a": {27, 40}}
    assert references.named["a"] == {27: [(1, True)], 40: [(1, True)]}
    assert references.unplaced == ()
    # Claim 40 is read only by the newer reading: withdrawn by rule only
    # where its clause shares a ledger id or an address with it.
    assert 40 in references.expanded["a"]
    assert 27 not in references.expanded.get("a", {})


def test_a_bare_number_that_repeats_nothing_stays_unplaced() -> None:
    line = LINE.replace("its claim 40", "claim 40")

    references = read_claim_references([line], NAMES)

    assert references.named == {"a": {27: [(1, True)]}}
    assert [(u.claims, u.why) for u in references.unplaced] == [("claim 40", NO_ANALYST_NAMED)]


def test_its_claim_after_another_participant_s_name_is_not_bound() -> None:
    line = LINE.replace("while its claim 40", "while B disputes it, and its claim 40")

    references = read_claim_references([line], NAMES)

    assert 40 not in references.named.get("a", {})
    assert any(u.claims == "claim 40" for u in references.unplaced)


def test_its_claim_on_a_field_of_two_analysts_is_not_bound() -> None:
    line = LINE.replace("[analysts: a]", "[analysts: a, b]")

    references = read_claim_references([line], NAMES)

    assert all(40 not in claims for claims in references.named.values())


def test_its_claim_inside_a_mark_s_reason_is_not_read() -> None:
    line = (
        "[analysts: a] Claim 27 states the key is applied at 0.85. "
        "[blocking: its claim 40 says otherwise]"
    )

    references = read_claim_references([line], NAMES)

    assert references.named == {"a": {27: [(1, True)]}}
    assert references.unplaced == ()


def _claim(text: str, ref: str) -> ClaimEvidence:
    return ClaimEvidence(claim=text, evidence_ref=ref, confidence=0.8)


def _isr(*claims: ClaimEvidence) -> AgentISR:
    return AgentISR(agent_id="a", domain="static", claims=list(claims))


IN_FORCE = _isr(
    _claim('The key "k1" is applied to the request body.', "ev_0001"),
    _claim("No key use on the traffic is shown.", "ev_0040"),
)
# The revision writes claim 1 again and leaves claim 2 unanswered.
REVISION = _isr(_claim('The key "k1" is applied to the request body.', "ev_0001"))


def _merge(line: str) -> object:
    named = claims_named_by_lines([line], NAMES)
    return merge_revision(IN_FORCE, REVISION, "the revision", 2, named.get("a"))


def test_a_claim_reached_only_by_its_claim_with_no_shared_id_is_carried() -> None:
    line = (
        "[analysts: a] Claim 1 states the key is applied, while its claim 2 says no key use "
        "is shown. [blocking: restate one reading]"
    )

    merge = _merge(line)

    assert [n for n, *_ in merge.withdrawn_by_rule] == []  # type: ignore[attr-defined]
    assert 2 in [n for n, _s in merge.carried]  # type: ignore[attr-defined]


def test_a_claim_reached_by_its_claim_whose_clause_shares_an_id_is_withdrawn() -> None:
    line = (
        "[analysts: a] Claim 1 states the key is applied, while its claim 2 says no key use "
        "is shown in ev_0040. [blocking: restate one reading]"
    )

    merge = _merge(line)

    assert [n for n, *_ in merge.withdrawn_by_rule] == [2]  # type: ignore[attr-defined]
