"""A dash ends a negation's reach only where a new statement follows it.

A claim that read "the wrapper parks in a loop instead of exiting visibly —
sandbox/virtualization evasion via system checks" was asked whether it said
the behaviour was absent: "instead of" sets aside the phrase after it, and the
reader carried that across the dash to the summary the dash introduces. A
dash ends a cue's reach where a clause with its own verb follows it ("— process
injection was not observed"), which is then read on its own, and where the cue
is one that sets aside only its own phrase ("instead of", "rather than"). A
pair of dashes around an aside ("does not — in any run — inject") is read as
if the aside were not there, and the negation keeps its verb. A dash followed
by no verb ("— not a single HTTP request") is read as before.

"never-" before one of the listed past participles ("a complete,
never-exercised web C2") opens an adjective and negates nothing; any other
"never-" ("never-contacted", "never-ever") is read as the negation it was.
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


@pytest.mark.parametrize(
    ("text", "technique"),
    [
        (
            "The sample does not — in any of the three runs — inject code into another process.",
            "T1055",
        ),
        ("No injection — process injection was not observed.", "T1055"),
        ("Injection is absent — process injection is absent.", "T1055"),
        ("The sample does not write a Run key — persistence is absent.", "T1547.001"),
        ("No web C2 traffic was seen — not a single HTTP request.", "T1071.001"),
    ],
)
def test_an_absence_written_around_a_dash_is_still_asked(text: str, technique: str) -> None:
    assert _asked(text, technique)


@pytest.mark.parametrize(
    "text",
    [
        "The sample has never-contacted its web C2 server.",
        "The sample never-ever reaches its web protocol C2.",
    ],
)
def test_a_never_hyphen_that_is_no_listed_adjective_is_a_negation(text: str) -> None:
    assert _asked(text, "T1071.001")
