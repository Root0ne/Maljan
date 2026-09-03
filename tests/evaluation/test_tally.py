"""``Tally`` is the one counter every evaluation harness reports its population with.

A harness that drops a sample it cannot parse without counting it lets a paper
denominator shrink silently. ``Tally`` forces attempted/parsed/scored/dropped to be
tracked together and serialised the same way everywhere.
"""

from __future__ import annotations

import pytest

from tests.evaluation._tally import Tally


def test_tally_counts_and_serialises(capsys: pytest.CaptureFixture[str]) -> None:
    t = Tally()
    for _ in range(3):
        t.attempt()
    t.parse_ok()
    t.score_ok()
    t.parse_ok()
    t.drop("no_profile_text")
    t.drop("unparseable", detail="NE header")
    assert t.as_dict() == {
        "attempted": 3,
        "parsed": 2,
        "scored": 1,
        "dropped": {"no_profile_text": 1, "unparseable": 1},
    }
    assert "unparseable" in capsys.readouterr().err
