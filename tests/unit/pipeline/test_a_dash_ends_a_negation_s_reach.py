"""A dash ends a negation's reach, as a semicolon does.

A claim that read "the wrapper parks in a loop instead of exiting visibly —
sandbox/virtualization evasion via system checks" was asked whether it said
the behaviour was absent: "instead of" set aside what followed it, and the
reader carried that across the dash to the summary the dash introduces. A
dash opens a new phrase; the negation before it governs nothing after it.
A negation that stands over its own mention before the dash still does.
A hyphenated "never-" opens an adjective and negates nothing either: "a
complete, never-exercised web C2" says the C2 is there.
"""

from __future__ import annotations

import pytest

from maljan.pipeline.validation import absence_claim_violation
from maljan.schemas.isr_models import ClaimEvidence
from maljan.tools import knowledge


def _asked(text: str, technique: str) -> bool:
    claim = ClaimEvidence(
        claim=text, evidence_ref="[ev_0003]", confidence=0.8, technique_id=technique
    )
    return absence_claim_violation(claim, technique, knowledge) is not None


@pytest.mark.parametrize(
    "text",
    [
        "When a check fails, the wrapper loops instead of exiting visibly — sandbox/"
        "virtualization evasion via system checks.",
        "When a check fails, the wrapper loops instead of exiting visibly—virtualization "
        "evasion via system checks.",
        "When a check fails, the wrapper loops instead of exiting visibly – sandbox "
        "evasion via system checks.",
    ],
)
def test_a_cue_before_a_dash_does_not_govern_the_summary_after_it(text: str) -> None:
    assert not _asked(text, "T1497.001")


@pytest.mark.parametrize(
    "text",
    [
        "The sample performs no system checks — it runs at once.",
        "No virtualization evasion was found — the loader starts immediately.",
        "The sample does not perform system checks.",
    ],
)
def test_a_cue_over_its_own_mention_still_reads_as_absence(text: str) -> None:
    assert _asked(text, "T1497.001")


def test_a_range_written_with_an_en_dash_is_no_break() -> None:
    """ "0–7" is a range, not a phrase break: the negation still reaches past it."""
    assert _asked("The sample performs no 0–7 system checks.", "T1497.001")


def test_a_never_hyphen_adjective_asserts_what_it_describes() -> None:
    assert not _asked(
        "The module carries a complete, never-exercised web C2 with two hardcoded bases.",
        "T1071.001",
    )
    assert _asked("The sample never reached its C2 in this run.", "T1071.001")
