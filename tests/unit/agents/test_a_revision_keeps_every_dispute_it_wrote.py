"""A revision's DISPUTES section is read at its label, line by line, by whichever reader reads it.

The section reader stopped at any line that began with words and a colon,
in any case, so a second dispute written as prose (``Network analyst: ...``)
ended the section, and it opened on the word anywhere in the text. A
revision whose claims only the lenient reader read lost its disputes
altogether, and so did a generic agent's revision.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from maljan.agents.static_analyst import _parse_disputes

LENIENT = (
    # No EVIDENCE line: the strict reader reads no claim, the lenient one does.
    "CLAIM: The sample injects into explorer.exe\nCONFIDENCE: 0.7\n---\n"
    "DISPUTES:\n- Dynamic analyst claims no injection but the strings name it.\n"
)


class TestTheSectionReader:
    def test_every_unbulleted_dispute_is_one(self) -> None:
        text = (
            "CLAIM: a\nEVIDENCE: ev_0001\nCONFIDENCE: 0.5\n---\n"
            "DISPUTES:\nDynamic analyst: says no persistence, the run key shows it.\n"
            "Network analyst: says no C2, the beacon is in the capture.\n"
        )
        assert _parse_disputes(text) == [
            "Dynamic analyst: says no persistence, the run key shows it.",
            "Network analyst: says no C2, the beacon is in the capture.",
        ]

    def test_the_word_in_a_sentence_opens_nothing(self) -> None:
        text = "CLAIM: it has no disputes: none here\nEVIDENCE: ev_0001\nCONFIDENCE: 0.5\n"
        assert _parse_disputes(text) == []

    def test_an_all_capitals_section_still_ends_it(self) -> None:
        text = "DISPUTES:\n- one\nSUMMARY: the rest\n"
        assert _parse_disputes(text) == ["one"]

    def test_a_domain_named_in_capitals_stays_inside(self) -> None:
        text = "DISPUTES:\n- one\nNETWORK: I disagree, the beacon is there.\n"
        assert _parse_disputes(text) == ["one", "NETWORK: I disagree, the beacon is there."]

    def test_an_emphasised_section_label_closes_it(self) -> None:
        text = "DISPUTES:\n- one\n**SUMMARY:** the rest\n## FINAL VERDICT: bad\n"
        assert _parse_disputes(text) == ["one"]

    def test_a_claim_written_after_the_disputes_is_no_dispute(self) -> None:
        text = (
            "DISPUTES:\n- one\nNETWORK: I disagree, the beacon is there.\n"
            "CLAIM: late claim\nEVIDENCE: ev_0002\nCONFIDENCE: 0.6\n"
        )
        assert _parse_disputes(text) == ["one", "NETWORK: I disagree, the beacon is there."]

    def test_a_bulleted_claim_heading_is_a_dispute(self) -> None:
        text = "DISPUTES:\n- CLAIM: static says no injection, wrong\n- two\n"
        assert _parse_disputes(text) == ["CLAIM: static says no injection, wrong", "two"]
        text = "DISPUTES:\n- one\n- CLAIM 2 (static): wrong\n- three\n"
        assert len(_parse_disputes(text)) == 3

    def test_a_label_saying_none_is_no_dispute(self) -> None:
        assert _parse_disputes("CLAIM: a\nDISPUTES: NONE\n") == []

    def test_the_label_line_may_carry_the_first_dispute(self) -> None:
        assert _parse_disputes("**DISPUTES:** the hash is wrong\n- and so is the size\n") == [
            "the hash is wrong",
            "and so is the size",
        ]


@pytest.mark.parametrize(
    "module, cls",
    [
        ("maljan.agents.static_analyst", "StaticAnalyst"),
        ("maljan.agents.dynamic_analyst", "DynamicAnalyst"),
        ("maljan.agents.network_analyst", "NetworkAnalyst"),
    ],
)
def test_the_lenient_reading_keeps_the_disputes(module: str, cls: str) -> None:
    import importlib

    analyst: Any = getattr(importlib.import_module(module), cls)(llm=MagicMock(), name=cls)
    analyst.revision_answer = lambda messages: LENIENT
    _text, isr = analyst.revise_isr("{}", "own", {"peer": "theirs"}, "feedback", 1)
    assert isr.claims, "the lenient reader read the claim"
    assert isr.dissent_items == ["Dynamic analyst claims no injection but the strings name it."]


def test_a_generic_agent_s_revision_keeps_its_disputes() -> None:
    from maljan.agents.composition import ResolvedAgent
    from maljan.agents.configurable_analyst import ConfigurableAnalyst, _Run

    resolved = ResolvedAgent(
        key="reverser_x",
        role="generic",
        prompt="reverse it",
        tools=[],
        static_provider_id="",
        llm=None,
    )
    analyst = ConfigurableAnalyst("reverser_x", resolved, llm=None)  # type: ignore[arg-type]
    analyst._run = lambda messages, what: _Run(text=LENIENT, degraded=False)  # type: ignore[method-assign]
    _text, isr = analyst.revise_isr("{}", "own", {"peer": "theirs"}, "feedback", 1)
    assert isr.dissent_items == ["Dynamic analyst claims no injection but the strings name it."]


def test_a_generic_agent_s_findings_block_is_no_dispute() -> None:
    from maljan.agents.composition import ResolvedAgent
    from maljan.agents.configurable_analyst import ConfigurableAnalyst, _Run

    resolved = ResolvedAgent(
        key="reverser_x",
        role="generic",
        prompt="reverse it",
        tools=[],
        static_provider_id="",
        llm=None,
    )
    analyst = ConfigurableAnalyst("reverser_x", resolved, llm=None)  # type: ignore[arg-type]
    fenced = LENIENT + '```maljan-findings\n{"findings": [], "artifacts": []}\n```\n'
    analyst._run = lambda messages, what: _Run(text=fenced, degraded=False)  # type: ignore[method-assign]
    _text, isr = analyst.revise_isr("{}", "own", {"peer": "theirs"}, "feedback", 1)
    assert isr.dissent_items == ["Dynamic analyst claims no injection but the strings name it."]
