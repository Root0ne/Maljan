"""A reference lookup confirms that an id exists; it does not say the sample performs it.

A slow model spent ten turns looking ATT&CK ids up one by one, and the report
then said "29 asserted by a deterministic source": every id ``attck_lookup``
answered, and every technique ``similar_cases`` found on other samples, had
been counted as a rule firing on this one — including six ids the lookup
itself answered ``valid: false``. Only a source that asserts a technique from
the sample counts, and an id any source marks invalid is never counted.
"""

from __future__ import annotations

import json
from typing import Any

from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.pipeline.evidence_summary import summarise
from maljan.pipeline.validation import corroboration
from maljan.schemas.evidence import build_entry, format_entry_id
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.tools import knowledge


def _entry(tool: str, payload: dict[str, Any], seq: int, *, agent: str = "static"):
    return build_entry(
        entry_id=format_entry_id(seq),
        seq=seq,
        agent=agent,
        tool=tool,
        args={},
        server="knowledge",
        output=json.dumps(payload),
        stage="analysis",
    )


CAPA = {
    "capabilities": [
        {
            "rule": "contain obfuscated stackstrings",
            "attck": ["Defense Evasion::Obfuscated Files or Information [T1027.005]"],
        },
        {"rule": "encrypt data using RC4 PRGA", "attck": ["Defense Evasion::Obfuscation [T1027]"]},
    ]
}

# ``similar_cases`` in the shape it answers: other samples' techniques.
SIMILAR = {
    "cases": [
        {"sample_id": "a" * 64, "score": 0.81, "technique_ids": ["T1027.005", "T1082", "T1083"]}
    ],
    "techniques": [
        {"technique_id": "T1082", "support": 3, "score": 0.8},
        {"technique_id": "T1027", "support": 2, "score": 0.7},
    ],
}


def _scout_ledger() -> list[Any]:
    """capa on the sample, then an analyst's lookups, as the run recorded them."""
    ledger = [_entry("capa", CAPA, 1, agent="pipeline"), _entry("similar_cases", SIMILAR, 2)]
    for seq, tid in enumerate(("T1027.005", "T1048.003", "T1106", "T1048.004", "T1044"), start=3):
        ledger.append(_entry("attck_lookup", knowledge.attck_lookup(tid), seq))
    ledger.append(
        _entry(
            "resolve_technique",
            {"candidates": [{"technique_id": "T1140", "score_gate": 0.5, "score": 0.6}]},
            9,
        )
    )
    return ledger


class TestOnlyASourceThatReadTheSampleAsserts:
    def test_the_lookups_assert_nothing_and_add_no_row(self) -> None:
        # The fixture's premise, read off the vendored catalogue itself.
        assert knowledge.attck_lookup("T1048.004")["valid"] is False
        assert knowledge.attck_lookup("T1044")["valid"] is False

        rows = corroboration({}, _scout_ledger())

        assert rows == {
            "T1027": {"asserted_by": ["capa"], "claimed_by": []},
            "T1027.005": {"asserted_by": ["capa"], "claimed_by": []},
        }

    def test_an_analyst_s_claim_keeps_its_row_whatever_it_looked_up(self) -> None:
        claim = ClaimEvidence(
            claim="exfiltrates over an alternative protocol",
            evidence_ref="[ev_0004] lookup",
            confidence=0.4,
            technique_id="T1048.003",
        )
        isrs = {"static": AgentISR(agent_id="static", domain="static", claims=[claim])}

        rows = corroboration(isrs, _scout_ledger())

        assert rows["T1048.003"] == {"asserted_by": [], "claimed_by": ["static"]}

    def test_an_id_a_source_marks_invalid_is_never_counted_as_asserted(self) -> None:
        sigma = {"matches": [{"title": "x", "tags": ["attack.t1044"], "matched_fields": []}]}
        yara = {"matches": [{"rule": "r", "meta": {"technique_id": "T1048.004"}, "tags": []}]}
        ledger = [
            _entry("sigma_match_sandbox", sigma, 1, agent="pipeline"),
            _entry("yara_scan", yara, 2, agent="pipeline"),
            _entry("attck_lookup", knowledge.attck_lookup("T1044"), 3),
            _entry("attck_validate", knowledge.attck_validate(["T1048.004"]), 4),
        ]

        rows = corroboration({}, ledger)

        assert "T1044" not in rows
        assert "T1048.004" not in rows

    def test_a_server_prefixed_asserting_tool_still_asserts(self) -> None:
        rows = corroboration({}, [_entry("analysis__capa", CAPA, 1, agent="pipeline")])

        assert rows["T1027"] == {"asserted_by": ["capa"], "claimed_by": []}


class TestEverySurfaceCountsTheSameRows:
    def test_the_per_source_count_names_no_lookup(self) -> None:
        summary = (
            RunSummaryBuilder(start_time=0.0)
            .set_corroboration(corroboration({}, _scout_ledger()))
            ._techniques_by_layer
        )

        assert summary == {"capa": 2}

    def test_the_judge_s_evidence_block_names_no_lookup(self) -> None:
        block = summarise({}, _scout_ledger())

        assert "attck_lookup" not in block
        assert "similar_cases" not in block
        assert "resolve_technique" not in block
        assert "T1048.004" not in block and "T1082" not in block
        assert "T1027.005: 1 source(s) — capa" in block

    def test_the_report_line_counts_two_asserted(self) -> None:
        from maljan.reporting.renderers.markdown import MarkdownRenderer

        rows = corroboration({}, _scout_ledger())
        text = MarkdownRenderer()._section_run_summary({"corroboration": rows})

        assert "2 asserted by a deterministic source" in text
        assert "attck_lookup" not in text
