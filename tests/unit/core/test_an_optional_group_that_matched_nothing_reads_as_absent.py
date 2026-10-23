"""A declared pattern's optional group that took part in no match reads as absent.

An error pattern's message group that matched nothing filed the message
"None"; a reputation pattern whose count group matched nothing raised.
"""

from __future__ import annotations

from maljan.core.tool_declarations import ErrorPattern, ReputationFacts


def test_a_message_group_that_took_part_in_no_match_files_the_whole_text() -> None:
    pattern = ErrorPattern(match=r"error(?::(?P<body>.*))?", message_group="body")
    assert pattern.message("t", "error") == "error"
    assert pattern.message("t", "error:disk full") == "disk full"


def test_a_count_group_that_took_part_in_no_match_finds_no_count() -> None:
    facts = ReputationFacts(
        text_patterns=(r"(?P<malicious>\d+)?/(?P<total>\d+) engines", r"(?P<malicious>\d+) bad")
    )
    assert facts.counts_in_text("/70 engines") is None
    assert facts.counts_in_text("3/70 engines") == (3, 70, None)
    assert facts.counts_in_text("/70 engines, 5 bad") == (5, None, None)
