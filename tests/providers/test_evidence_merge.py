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
from maljan.reporting.renderers.markdown import MarkdownRenderer

# The real row shape ``api_technique_hits`` already has one producer for
# (analysis/import_capability_layer.py) and one reader of
# (renderers/markdown.py): technique_id, name, confidence, matched_apis.
# capa rows add "source" on top — the renderer reads with ``.get``, so the
# extra key is harmless and lets a future renderer branch on where a hit
# came from.
_EXISTING_HIT = {
    "technique_id": "T1071",
    "name": "Application Layer Protocol",
    "confidence": 0.55,
    "matched_apis": ["WS2_32.dll::connect"],
}
_CAPA_HIT = {
    "technique_id": "T1027",
    "name": "encrypt data using RC4",
    "confidence": 0.70,
    "matched_apis": ["data-manipulation/encryption/rc4"],
    "source": "capa",
}


def test_counters_are_summed_and_hits_extended():
    static = StaticAnalysis(
        api_capabilities={"network": 2, "crypto": 1},
        api_technique_hits=[_EXISTING_HIT],
    )
    merged = merge_static_evidence(
        static,
        StaticEvidenceBundle(
            api_capabilities={"crypto": 3, "anti-analysis": 1},
            technique_hits=[_CAPA_HIT],
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
        technique_hits=[_CAPA_HIT],
        technical_evidence={
            "capa": "| rule | namespace |\n| encrypt data using RC4 | x |",
            "yara": "ransom_note",
        },
    )
    report = _builder(sample_path=str(sample), static_evidence=bundle).build_deterministic()
    assert report.static is not None
    assert report.static.api_capabilities.get("data-manipulation") == 1
    assert any(h["technique_id"] == "T1027" for h in report.static.api_technique_hits)


def test_a_capa_hit_renders_its_name_and_confidence_in_the_markdown_table(tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    bundle = StaticEvidenceBundle(
        api_capabilities={"data-manipulation": 1},
        technique_hits=[_CAPA_HIT],
        technical_evidence={},
    )
    report = _builder(sample_path=str(sample), static_evidence=bundle).build_deterministic()
    markdown = MarkdownRenderer().render(report)
    assert "encrypt data using RC4" in markdown
    assert "0.70" in markdown


def test_no_bundle_leaves_the_report_untouched(tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(b"MZ" + b"\x00" * 128)
    report = _builder(sample_path=str(sample), static_evidence=None).build_deterministic()
    assert report.static is not None
    assert report.static.api_capabilities == {}


def test_evidence_survives_a_sample_the_pe_extractor_cannot_read(tmp_path):
    """M5 regression: a non-PE sample (or a failed pefile parse) makes
    ``build_static_analysis`` return None — precisely the case where capa's
    evidence bundle is the *only* static evidence there is, and it used to
    be dropped on the floor rather than folded into a fresh, empty
    ``StaticAnalysis``.
    """
    non_pe_sample = tmp_path / "not_a_pe.bin"
    non_pe_sample.write_bytes(b"this is not a PE file at all")
    bundle = StaticEvidenceBundle(
        api_capabilities={"data-manipulation": 1},
        technique_hits=[_CAPA_HIT],
        technical_evidence={"capa": "| rule | namespace |\n| encrypt data using RC4 | x |"},
    )
    report = _builder(sample_path=str(non_pe_sample), static_evidence=bundle).build_deterministic()
    assert report.static is not None
    assert report.static.api_capabilities.get("data-manipulation") == 1
    assert any(h["technique_id"] == "T1027" for h in report.static.api_technique_hits)
