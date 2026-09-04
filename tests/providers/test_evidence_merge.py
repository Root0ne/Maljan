"""Evidence merges into StaticAnalysis without disturbing what is already there.

Two seams are covered: ``merge_static_evidence`` directly (the pure function),
and the ``MalwareReportBuilder`` seam that calls it — ``report_node`` collects
a ``StaticEvidenceBundle`` once and hands it to the builder as
``static_evidence``; ``build_deterministic`` folds it into ``report.static``
right after ``build_static_analysis`` runs. The plan sketch had the merge
happen in the judge node, but neither of its locals (an ISR-only
``_static_imp`` and a ``_evidence_sections`` dict that doesn't exist) actually
reaches ``MalwareReport`` — the builder is the only place that assembles
``report.static``, so that is where this seam lives instead.
"""

from __future__ import annotations

from maljan.providers.base import StaticEvidenceBundle
from maljan.providers.static.capa_yara import merge_static_evidence
from maljan.reporting.builder import MalwareReportBuilder
from maljan.reporting.models import StaticAnalysis


def test_counters_are_summed_and_hits_extended():
    static = StaticAnalysis(
        api_capabilities={"network": 2, "crypto": 1},
        api_technique_hits=[{"technique_id": "T1071", "evidence": ["WS2_32.dll"]}],
    )
    merged = merge_static_evidence(
        static,
        StaticEvidenceBundle(
            api_capabilities={"crypto": 3, "anti-analysis": 1},
            technique_hits=[{"technique_id": "T1027", "evidence": ["capa: RC4"]}],
            technical_evidence={"capa": "…"},
        ),
    )
    assert merged.api_capabilities == {"network": 2, "crypto": 4, "anti-analysis": 1}
    assert [h["technique_id"] for h in merged.api_technique_hits] == ["T1071", "T1027"]


def test_the_merge_does_not_mutate_its_input():
    static = StaticAnalysis(api_capabilities={"network": 1})
    merge_static_evidence(static, StaticEvidenceBundle(api_capabilities={"network": 5}))
    assert static.api_capabilities == {"network": 1}


def test_an_empty_bundle_changes_nothing():
    static = StaticAnalysis(api_capabilities={"network": 1})
    assert merge_static_evidence(static, StaticEvidenceBundle()) == static


def _builder(
    *, sample_path: str, static_evidence: StaticEvidenceBundle | None
) -> MalwareReportBuilder:
    return MalwareReportBuilder(
        file_hash="a" * 64,
        file_name="fixture.bin",
        sample_path=sample_path,
        sandbox_report={},
        reports={},
        isr_reports={},
        stix_output={"objects": []},
        run_summary={
            "negotiation": {
                "rounds_completed": 1,
                "termination_reason": "consensus",
                "final_confidence": 0.5,
            }
        },
        discussion_history=[],
        final_decision="Suspicious",
        overall_confidence=0.5,
        cascade_summary=None,
        malware_category=None,
        static_evidence=static_evidence,
    )


def test_the_builder_folds_evidence_into_the_report(tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    bundle = StaticEvidenceBundle(
        api_capabilities={"data-manipulation": 1},
        technique_hits=[{"technique_id": "T1027", "evidence": ["capa: encrypt data using RC4"]}],
        technical_evidence={
            "capa": "| rule | namespace |\n| encrypt data using RC4 | x |",
            "yara": "ransom_note",
        },
    )
    report = _builder(sample_path=str(sample), static_evidence=bundle).build_deterministic()
    assert report.static is not None
    assert report.static.api_capabilities.get("data-manipulation") == 1
    assert any(h["technique_id"] == "T1027" for h in report.static.api_technique_hits)


def test_no_bundle_leaves_the_report_untouched(tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    report = _builder(sample_path=str(sample), static_evidence=None).build_deterministic()
    assert report.static is not None
    assert report.static.api_capabilities == {}
