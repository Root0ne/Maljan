"""A tool's or a sample's underscores render as underscores, never as emphasis.

The Markdown escaped every character that opens a link, a tag, a code span,
a table cell or ``*`` emphasis, but not ``_``: a banner a tool printed
(``[____DOWNLOADING____]``) or a name such as ``__init__`` came out of the
HTML and the PDF bold, with its underscores gone (T-347). An underscore that
could open or close emphasis is escaped; one between two letters or digits,
which no CommonMark reader makes emphasis of, is written as it is, so a
``FUN_00401310`` or an ``ev_0001`` reads the same in the Markdown source.
"""

from __future__ import annotations

import re

from maljan.reporting.models import EvidenceSection, FileHashes, MalwareReport, SampleIdentity
from maljan.reporting.renderers.html import HtmlRenderer
from maljan.reporting.renderers.markdown import _emphasis_escaped, _escaped

BANNER = "| [____DOWNLOADING FREE RTX____] | __init__ called _once_"


def _report() -> MalwareReport:
    return MalwareReport(
        identity=SampleIdentity(hashes=FileHashes(sha256="a" * 64)),
        sections=[
            EvidenceSection(
                key="tool_detect_packer",
                title="Detect packer",
                kind="kv",
                columns=["Field", "Value"],
                rows=[["stdout", BANNER], ["entry", "FUN_00401310"]],
                evidence_ids=["ev_0001"],
            ),
            EvidenceSection(
                key="tool_list",
                title="Listing",
                kind="list",
                items=["__main__ module", "snake_case_name"],
                evidence_ids=["ev_0002"],
            ),
        ],
    )


def test_an_underscore_that_could_open_emphasis_is_escaped() -> None:
    assert _emphasis_escaped(_escaped("__init__")) == "\\_\\_init\\_\\_"
    assert _emphasis_escaped(_escaped("_once_")) == "\\_once\\_"


def test_an_underscore_inside_a_word_is_written_as_it_is() -> None:
    assert _emphasis_escaped("FUN_00401310") == "FUN_00401310"
    assert _emphasis_escaped("snake_case_name") == "snake_case_name"


def test_a_code_span_and_an_escaped_pair_are_left_as_they_are() -> None:
    assert _emphasis_escaped("a `__x__` _b_") == "a `__x__` \\_b\\_"
    assert _emphasis_escaped("``__a`__`` __c") == "``__a`__`` \\_\\_c"
    assert _emphasis_escaped("\\\\_d") == "\\\\\\_d"


def test_the_html_draws_the_underscores_and_no_emphasis() -> None:
    html = HtmlRenderer().render(_report())
    start = html.rindex("Appendix A. Evidence index")
    body = html[start : html.index("Appendix B", start)]

    assert not re.search(r"<(strong|em)>\s*(DOWNLOADING|init|once|main)", body)
    assert "[____DOWNLOADING FREE RTX____]" in body
    assert "__init__ called _once_" in body
    assert "__main__ module" in body
    assert "FUN_00401310" in body
    assert "snake_case_name" in body
