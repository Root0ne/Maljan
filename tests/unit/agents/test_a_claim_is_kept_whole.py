"""A claim is stored as its analyst wrote it, however long it is.

Both claim parsers stored ``claim_text[:300]`` with no mark. In a paid run 26 of
40 claims were exactly 300 characters, cut mid-word, and every one of the five
claims asked whether its sentence described its technique was asked over the
cut text — a sentence whose behaviour came after character 300 read as
describing nothing.
"""

from __future__ import annotations

from maljan.agents.base_agent import parse_structured_claims
from maljan.agents.static_analyst import _parse_claim_blocks
from maljan.pipeline.events import FINDING_VALUE_LIMIT, safe_finding_value
from maljan.pipeline.validation import claim_does_not_describe_violation
from maljan.schemas.isr_models import ClaimEvidence
from maljan.tools import knowledge
from maljan.utils.marked_cut import CUT_MARK

# A thousand-character claim, and one whose behaviour is named only after character 300.
_LEAD = "The routine at 0x401000 walks a table of entries and " * 18
_BODY = (_LEAD * 2)[:999].rstrip()
LONG_CLAIM = _BODY + "s" * (1000 - len(_BODY))
BEHAVIOUR = "dumps the stored credentials of every account"
CLAIM_WITH_BEHAVIOUR_LATE = (_LEAD[: 1000 - len(BEHAVIOUR) - 1] + " " + BEHAVIOUR)[:1000]


def _block(claim: str) -> str:
    return f"CLAIM: {claim}\nEVIDENCE: routine [ev_0004]\nCONFIDENCE: 0.8\nTECHNIQUE: T1003\n"


class TestBothParsersKeepTheClaimWhole:
    def test_the_lenient_parser(self) -> None:
        [claim] = parse_structured_claims(_block(LONG_CLAIM))

        assert claim.claim == LONG_CLAIM
        assert len(claim.claim) == 1000

    def test_the_strict_parser(self) -> None:
        [claim] = _parse_claim_blocks(_block(LONG_CLAIM))

        assert claim.claim == LONG_CLAIM


class TestTheQuestionReadsTheWholeSentence:
    def test_a_behaviour_named_after_character_300_describes_the_technique(self) -> None:
        [claim] = parse_structured_claims(_block(CLAIM_WITH_BEHAVIOUR_LATE))

        assert BEHAVIOUR in claim.claim
        assert claim_does_not_describe_violation(claim, "T1003", knowledge) is None

    def test_the_same_sentence_cut_at_300_would_have_been_asked(self) -> None:
        cut = ClaimEvidence(
            claim=CLAIM_WITH_BEHAVIOUR_LATE[:300],
            evidence_ref="[ev_0004]",
            confidence=0.8,
            technique_id="T1003",
        )

        assert claim_does_not_describe_violation(cut, "T1003", knowledge) is not None


class TestAQuotedValueSaysItWasCut:
    def test_a_long_value_in_a_finding_row_ends_in_the_mark(self) -> None:
        quoted = safe_finding_value(LONG_CLAIM)

        assert len(quoted) <= FINDING_VALUE_LIMIT
        assert quoted.endswith(CUT_MARK)
