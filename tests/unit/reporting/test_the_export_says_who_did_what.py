"""What the export records says who did what, and one rule decides a technique id.

* A network-block row the export declines is filed under the source that
  recorded it, not under the judge, which wrote none of them.
* A bundle this pipeline built when the judge's answer was not one credits the
  analysts whose claims it carries, not the judge.
* A producer the export names in place of one the bundle does not hold is
  recorded.
* A credit the judge was asked about and kept, naming an agent that did not
  name the technique, is not printed by the export; the judge's bundle keeps it.
* The judge's bundle and the export derive a technique's object id in one
  namespace, and only an ATT&CK reference names a technique.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from maljan.agents.judge_agent import JudgeAgent
from maljan.agents.judge_postprocess import postprocess_judge_bundle
from maljan.extractors.capability_matrix import build_capability_matrix, unmapped_behaviours
from maljan.pipeline.nodes import _note_export_findings
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import MalwareReport, NetworkIOCs, NetworkURL
from maljan.reporting.renderers.stix_renderer import (
    UNPUBLISHABLE_CREDIT_CODE,
    UNPUBLISHABLE_PRODUCER_CODE,
    ExtendedSTIXRenderer,
)
from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from maljan.schemas.stix_models import Bundle, attack_pattern_id


def _report(verdict: str = "Malware") -> MalwareReport:
    return MalwareReportBuilder(
        file_hash="c" * 64,
        file_name="sample.exe",
        sample_path=None,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={},
        discussion_history=[],
        final_decision=verdict,
        overall_confidence=0.9,
        judge_assessment=None,
        malware_category="loader",
        evidence_ledger=[],
    ).build_deterministic()


def _pattern(tid: str, *refs: dict) -> dict:
    return {
        "type": "attack-pattern",
        "id": f"attack-pattern--{tid}",
        "name": tid,
        "external_references": list(refs) or [{"source_name": "mitre-attack", "external_id": tid}],
    }


class TestWhoIsNamed:
    def test_a_declined_network_row_names_the_source_that_recorded_it(self) -> None:
        report = _report()
        report.network = NetworkIOCs(urls=[NetworkURL(url="http://localho", source="sandbox")])
        renderer = ExtendedSTIXRenderer()
        renderer.render(report, None)
        holder = SimpleNamespace(run_summary={})

        _note_export_findings(holder, renderer.declined)

        (row,) = holder.run_summary["validation"]["unresolved"]
        assert row["agent"] == "sandbox"

    def test_a_fallback_bundle_credits_the_analysts_and_not_the_judge(self) -> None:
        claims = {
            "static": AgentISR(
                agent_id="static",
                domain="static",
                claims=[
                    ClaimEvidence(
                        claim="injects",
                        evidence_ref="[ev_0001]",
                        confidence=0.7,
                        technique_id="T1055",
                    )
                ],
            )
        }
        fallback = JudgeAgent(llm=MagicMock())._fallback_bundle_from_text(
            "Verdict: Malware.", {}, claims
        )

        _cells, mappings = build_capability_matrix(
            stix_output=fallback.model_dump(mode="json"), isr_reports=claims
        )

        assert [m.contributing_layers for m in mappings] == [["static"]]

    def test_a_replaced_producer_is_recorded(self) -> None:
        judge = Bundle.model_validate(
            {
                "objects": [
                    {
                        "type": "malware",
                        "id": "malware--0f1e2d3c-4b5a-4968-8776-655443332211",
                        "name": "x",
                        "is_family": False,
                        "created_by_ref": "identity--0f1e2d3c-4b5a-4968-8776-000000000000",
                    }
                ]
            }
        )
        renderer = ExtendedSTIXRenderer()
        renderer.render(_report(), judge)

        assert UNPUBLISHABLE_PRODUCER_CODE in [code for code, _why in renderer.declined]


class TestAnUnconfirmedCredit:
    def _judge(self) -> Bundle:
        return Bundle.model_validate(
            postprocess_judge_bundle(
                {
                    "objects": [
                        {"type": "malware", "id": "malware--1", "name": "x", "is_family": False},
                        _pattern("T1490"),
                        {
                            "type": "relationship",
                            "id": "relationship--1",
                            "relationship_type": "uses",
                            "source_ref": "malware--1",
                            "target_ref": "attack-pattern--T1490",
                            "x_maljan_confidence": 0.9,
                            "x_maljan_contributing_agents": ["STATIC ANALYST", "capa"],
                        },
                    ]
                }
            )
        )

    def test_it_is_not_printed_by_the_export(self) -> None:
        report = _report()
        report.ttp_mappings = build_capability_matrix(
            stix_output=self._judge().model_dump(mode="json"), isr_reports=None
        )[1]
        judge = self._judge()
        renderer = ExtendedSTIXRenderer()

        exported = renderer.render(report, judge, technique_sources={"T1490": ["capa"]})

        (edge,) = [
            o
            for o in exported.objects
            if getattr(o, "relationship_type", "") == "uses"
            and getattr(o, "x_maljan_contributing_agents", None)
        ]
        assert edge.x_maljan_contributing_agents == ["capa"]
        assert UNPUBLISHABLE_CREDIT_CODE in [code for code, _why in renderer.declined]
        (kept,) = [o for o in judge.objects if getattr(o, "type", "") == "relationship"]
        assert kept.x_maljan_contributing_agents == ["STATIC ANALYST", "capa"]


class TestOneRuleForATechnique:
    def test_both_bundles_derive_one_id(self) -> None:
        out = postprocess_judge_bundle({"objects": [_pattern("T1055")]})

        assert out["objects"][0]["id"] == attack_pattern_id("T1055")

    def test_only_an_attack_reference_names_a_technique(self) -> None:
        capec_first = _pattern(
            "T1071",
            {"source_name": "capec", "external_id": "CAPEC-137"},
            {"source_name": "mitre-attack", "external_id": "T1071"},
        )
        capec_only = _pattern("X", {"source_name": "capec", "external_id": "CAPEC-137"})
        capec_only["name"] = "Parameter injection"
        bundle = {"objects": [capec_first, capec_only]}

        cells, _mappings = build_capability_matrix(stix_output=bundle, isr_reports=None)

        assert [c.technique_id for c in cells] == ["T1071"]
        assert unmapped_behaviours(bundle) == ["Parameter injection"]
