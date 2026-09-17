"""The ISR parser keeps a technique id as the analyst wrote it.

A range guard used to drop any id outside T1001–T1700 and a placeholder set
with no violation, no feedback and no record; the catalogue this tree ships
already carries T1695.003, and the next release crosses 1700. What is wrong
with an id is attck.unknown_id's question.
"""

from __future__ import annotations

import logging

from maljan.agents.base_agent import _extract_technique_ids


def _analyst():
    """A real analyst's free-text path with nothing behind it (see
    test_tool_call_scaffolding._isr_from_text)."""
    from maljan.agents.static_analyst import StaticAnalyst

    analyst = StaticAnalyst.__new__(StaticAnalyst)
    analyst.name = "static"
    analyst.logger = logging.getLogger("test")
    return analyst


def _answer(tid: str) -> str:
    return (
        f"CLAIM: The sample does a thing\nEVIDENCE: [ev_0001] import table\n"
        f"CONFIDENCE: 0.7\nTECHNIQUE: {tid}\n"
    )


class TestEveryIdIsKeptAsWritten:
    def test_an_id_above_the_old_ceiling_survives(self) -> None:
        isr = _analyst()._text_to_isr(_answer("T1701.001"), revision_round=1)
        assert [c.technique_id for c in isr.claims] == ["T1701.001"]

    def test_a_placeholder_survives_for_the_check_to_report(self) -> None:
        for tid in ("T9999", "T0000", "T1234"):
            isr = _analyst()._text_to_isr(_answer(tid), revision_round=1)
            assert [c.technique_id for c in isr.claims] == [tid], tid

    def test_none_still_means_no_id(self) -> None:
        isr = _analyst()._text_to_isr(_answer("none"), revision_round=1)
        assert [c.technique_id for c in isr.claims] == [None]

    def test_findings_keep_every_id_too(self) -> None:
        assert _extract_technique_ids("T1055 then T1701.001, T9999 and T1055 again") == [
            "T1055",
            "T1701.001",
            "T9999",
        ]
