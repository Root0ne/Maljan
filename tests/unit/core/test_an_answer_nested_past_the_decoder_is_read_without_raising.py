"""An answer nested past the JSON decoder's depth is read without raising (T-509).

A tool's output is the sample's to shape: one nested past the decoder's
depth raised ``RecursionError`` out of every reader that parsed it as JSON,
where an unparsable answer is read as no document (the rule-match reader,
the reputation reader) or as text (the code-listing reader). Each now reads
it as it reads any answer that is no JSON.

Every value is synthetic.
"""

from __future__ import annotations

from maljan.core.reputation import read_answer
from maljan.core.rule_matches import rule_matches_of
from maljan.core.tool_declarations import ToolFacts
from maljan.core.undeclared_tools import code_listing
from maljan.schemas.evidence import LedgerEntry

_DEEP = "[" * 50_000 + "]" * 50_000
_DEEP_IN_AN_OBJECT = '{"code": ' + _DEEP + "}"


def test_the_rule_match_reader_reads_it_as_no_answer() -> None:
    entry = LedgerEntry(id="ev_0001", tool="inspect_file", output=_DEEP, facts={"v": 1})
    assert rule_matches_of(entry) is None


def test_the_code_listing_reader_reads_it_as_text() -> None:
    assert code_listing(_DEEP) == (_DEEP, False)
    assert code_listing(_DEEP_IN_AN_OBJECT) == (_DEEP_IN_AN_OBJECT, False)


def test_the_reputation_reader_reads_it_as_no_document() -> None:
    record = read_answer(ToolFacts(kind="reputation"), output=_DEEP)
    assert record.malicious is None and not record.stats
