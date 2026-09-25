"""A layout bound on the page says what it left out and where the whole is.

The report keeps its layout: a table value cut to fit, a long list shown in
part, a figure of a few rows, a drafted detection rule of a readable size. Each
of those now says so — how many were left out and that the JSON report, the
evidence ledger or the IOC table carries every one — so nothing on the page
reads as the whole when it is not.
"""

from __future__ import annotations

from maljan.reporting.detection_signatures import LEFT_OUT_COMMENT
from maljan.reporting.figures import _figure_left_out
from maljan.reporting.renderers.markdown import (
    CUT_CELL_SENTENCE,
    LEFT_OUT_LINE,
    _left_out,
)


class TestAListShownInPart:
    def test_says_how_many_more_and_where(self) -> None:
        assert _left_out(45, 40, "mutexes") == [
            "",
            LEFT_OUT_LINE.format(rest=5, what="mutexes"),
        ]
        assert "the JSON report carries every one" in LEFT_OUT_LINE

    def test_a_list_shown_whole_says_nothing(self) -> None:
        assert _left_out(40, 40, "mutexes") == []
        assert _left_out(3, 40, "mutexes") == []


class TestACutValue:
    def test_the_methodology_says_where_it_is_whole(self) -> None:
        assert "ends in …" in CUT_CELL_SENTENCE
        assert "JSON report" in CUT_CELL_SENTENCE and "evidence ledger" in CUT_CELL_SENTENCE


class TestAFigure:
    def test_counts_what_it_did_not_draw(self) -> None:
        said = _figure_left_out(52, 40, "processes")
        assert said.startswith(" 12 more processes are not drawn")
        assert _figure_left_out(40, 40, "processes") == ""


class TestADraftedRule:
    def test_says_how_many_indicators_it_leaves_to_the_ioc_table(self) -> None:
        said = LEFT_OUT_COMMENT.format(rest=7, what="domains")
        assert said.startswith("7 more published domains are not in this draft")
        assert "IOC table" in said
