"""What the judge is shown in place of a combined confidence number.

The cascade block this replaces printed one weighted figure per technique, and
the judge deferred to it. What goes in the prompt now is who said what: the
sources that named each technique and each source's own number, with nothing
multiplied together.
"""

from __future__ import annotations

from maljan.pipeline.evidence_summary import MAX_TECHNIQUES, collect, summarise
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR, ClaimEvidence, Finding


def _isr(agent_id: str, *claims: ClaimEvidence, findings: list[Finding] | None = None) -> AgentISR:
    return AgentISR(
        agent_id=agent_id, domain=agent_id, claims=list(claims), findings=findings or []
    )


def _claim(technique_id: str, confidence: float = 0.8) -> ClaimEvidence:
    return ClaimEvidence(
        claim="it does the thing",
        evidence_ref="ref",
        confidence=confidence,
        technique_id=technique_id,
    )


class TestCollect:
    def test_each_source_keeps_its_own_confidence(self):
        rows = collect(
            {
                "static": _isr("static", _claim("T1055", 0.9)),
                "dynamic": _isr("dynamic", _claim("T1055", 0.4)),
            },
            [],
        )

        assert rows["T1055"] == [("static", 0.9), ("dynamic", 0.4)]

    def test_a_tool_entry_counts_as_a_source_with_no_confidence(self):
        entry = LedgerEntry(
            id="ev_0001", tool="capa", structured={"capabilities": [{"attck": "T1055"}]}
        )

        assert collect({}, [entry]) == {"T1055": [("capa", None)]}

    def test_a_source_naming_a_technique_twice_is_still_one_source(self):
        rows = collect({"static": _isr("static", _claim("T1055"), _claim("T1055", 0.5))}, [])

        assert rows["T1055"] == [("static", 0.8)]

    def test_a_structured_finding_contributes_its_technique_ids(self):
        isr = _isr(
            "static",
            findings=[Finding(title="f", technique_ids=["T1071"], confidence=0.6)],
        )

        assert collect({"static": isr}, []) == {"T1071": [("static", 0.6)]}

    def test_an_id_that_failed_validation_is_left_out(self):
        isr = _isr("static", _claim("T9999"))
        isr.claims[0].technique_id_valid = False

        assert collect({"static": isr}, []) == {}

    def test_something_that_is_not_a_technique_id_is_ignored(self):
        entry = LedgerEntry(id="ev_0001", tool="capa", structured={"technique_id": "not-an-id"})

        assert collect({}, [entry]) == {}


class TestSummarise:
    def test_the_block_names_every_source_and_its_number(self):
        block = summarise(
            {
                "static": _isr("static", _claim("T1055", 0.9)),
                "dynamic": _isr("dynamic", _claim("T1055", 0.4)),
            },
            [LedgerEntry(id="ev_0001", tool="capa", structured={"attck": "T1055"})],
        )

        assert "T1055: 3 source(s)" in block
        assert "static (0.90)" in block
        assert "dynamic (0.40)" in block
        assert "capa" in block

    def test_it_says_the_numbers_are_not_combined(self):
        block = summarise({"static": _isr("static", _claim("T1055"))}, [])

        assert "Nothing here is combined or weighted" in block

    def test_the_best_corroborated_technique_comes_first(self):
        block = summarise(
            {
                "static": _isr("static", _claim("T1055"), _claim("T1071")),
                "dynamic": _isr("dynamic", _claim("T1071")),
            },
            [],
        )

        assert block.index("T1071") < block.index("T1055")

    def test_a_long_tail_is_counted_rather_than_printed(self):
        claims = [_claim(f"T{2000 + n}") for n in range(MAX_TECHNIQUES + 5)]
        block = summarise({"static": _isr("static", *claims)}, [])

        assert block.count("source(s)") == MAX_TECHNIQUES
        assert "+5 further techniques not listed" in block

    def test_nothing_named_a_technique_produces_no_block(self):
        assert summarise({}, []) == ""
