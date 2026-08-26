"""Unit tests for the pure scoring core of ``eval_narrative_quality``.

These exercise the deterministic scoring functions (citation extraction,
faithfulness/coverage, structural compliance) and the fixed-evidence builder
WITHOUT a live LLM, so the harness's logic is CI-covered. The end-to-end LLM
arm is validated by running the harness against a llama-server (manual).
"""

from __future__ import annotations

from tests.evaluation.eval_narrative_quality import (
    _build_report_from_fixture,
    _cited_technique_ids,
    _coverage_recall,
    _grounding_precision,
    _parenthesised_id_ratio,
    _structural_pass,
    score_narrative,
)

_FIXTURE = {"sample_id": "rat_sample_1", "technique_ids": ["T1095", "T1055", "T1003"]}


class TestCitationExtraction:
    def test_extracts_ids_from_prose(self) -> None:
        cited = _cited_technique_ids(
            "Performs process injection (T1055) and credential dumping (T1003).",
            ["It beacons over a non-application-layer protocol (T1095)."],
        )
        assert cited == {"T1055", "T1003", "T1095"}

    def test_subtechnique_and_dedup(self) -> None:
        cited = _cited_technique_ids("T1055.001 then T1055.001 again", [])
        assert cited == {"T1055.001"}

    def test_empty_when_no_ids(self) -> None:
        assert _cited_technique_ids("no techniques mentioned here", []) == set()


class TestGroundingAndCoverage:
    def test_grounding_precision_perfect(self) -> None:
        assert _grounding_precision({"T1055", "T1003"}, {"T1055", "T1003", "T1095"}) == 1.0

    def test_grounding_precision_drops_with_hallucination(self) -> None:
        # T9999 is not in the evidence -> precision 0.5.
        assert _grounding_precision({"T1055", "T9999"}, {"T1055", "T1003"}) == 0.5

    def test_grounding_precision_vacuous_when_no_cites(self) -> None:
        assert _grounding_precision(set(), {"T1055"}) == 1.0

    def test_coverage_recall(self) -> None:
        assert _coverage_recall({"T1055"}, {"T1055", "T1003"}) == 0.5
        assert _coverage_recall({"T1055", "T1003"}, {"T1055", "T1003"}) == 1.0


class TestStructural:
    def test_parenthesised_ratio(self) -> None:
        assert _parenthesised_id_ratio("uses injection (T1055)", []) == 1.0
        # Bare ID not in parentheses -> ratio < 1.0.
        assert _parenthesised_id_ratio("uses injection T1055", []) < 1.0

    def test_structural_pass_happy(self) -> None:
        exec_summary = (
            "The sample is a remote access trojan that injects into a host process "
            "(T1055) and beacons to its operator over a custom protocol. It collects "
            "host information and stages credentials for exfiltration."
        )
        caps = [
            "Establishes C2 over a non-application-layer protocol (T1095).",
            "Performs process injection (T1055) for defense evasion.",
            "Dumps credentials from OS memory (T1003).",
        ]
        assert _structural_pass(exec_summary, caps, n_recommendations=4) is True

    def test_structural_fail_short_summary(self) -> None:
        assert _structural_pass("too short", ["a", "b", "c"], n_recommendations=3) is False

    def test_structural_fail_wrong_paragraph_count(self) -> None:
        long_summary = "x" * 200
        assert _structural_pass(long_summary, ["only one paragraph"], n_recommendations=4) is False

    def test_structural_fail_bare_id(self) -> None:
        long_summary = "The sample injects into processes using T1055 without parentheses. " * 3
        caps = ["para one", "para two", "para three"]
        assert _structural_pass(long_summary, caps, n_recommendations=4) is False


class TestBuildReportFromFixture:
    def test_builds_valid_report_with_ttps(self) -> None:
        report = _build_report_from_fixture(_FIXTURE)
        assert report.verdict == "Malware"
        assert {m.technique_id for m in report.ttp_mappings} == {"T1095", "T1055", "T1003"}
        assert {c.technique_id for c in report.capability_matrix} == {"T1095", "T1055", "T1003"}
        assert report.identity.platform == "windows"
        # malware_category is inferred from the sample_id slug.
        assert report.malware_category == "rat"

    def test_name_map_labels_techniques(self) -> None:
        report = _build_report_from_fixture(_FIXTURE, {"T1055": "Process Injection"})
        names = {m.technique_id: m.technique_name for m in report.ttp_mappings}
        assert names["T1055"] == "Process Injection"
        # Unknown ids fall back to a placeholder, never crash.
        assert names["T1095"].startswith("Technique T1095")


class TestScoreNarrative:
    def test_faithful_narrative_scores_high(self) -> None:
        report = _build_report_from_fixture(_FIXTURE)
        exec_summary = (
            "This remote access trojan injects into a host process (T1055), dumps "
            "credentials (T1003), and beacons over a non-application-layer protocol "
            "(T1095) to its operator for tasking and exfiltration."
        )
        caps = [
            "C2 over a non-application-layer protocol (T1095).",
            "Process injection for stealth (T1055).",
            "OS credential dumping (T1003).",
        ]
        score = score_narrative(
            report=report,
            exec_summary=exec_summary,
            capabilities=caps,
            n_recommendations=4,
        )
        assert score.grounding_precision == 1.0
        assert score.coverage_recall == 1.0
        assert score.n_hallucinated == 0
        assert score.structural_pass is True

    def test_hallucinated_narrative_penalised(self) -> None:
        report = _build_report_from_fixture(_FIXTURE)
        exec_summary = (
            "The sample injects into processes (T1055) and also performs data "
            "encryption for impact (T1486), a technique not present in the evidence "
            "bundle, alongside some other unsupported claims about its behaviour."
        )
        caps = [
            "Process injection (T1055).",
            "Ransomware-style encryption (T1486).",
            "Inhibits system recovery (T1490).",
        ]
        score = score_narrative(
            report=report,
            exec_summary=exec_summary,
            capabilities=caps,
            n_recommendations=4,
        )
        # T1486 and T1490 are invented -> precision < 1.0, hallucinations counted.
        assert score.grounding_precision < 1.0
        assert score.n_hallucinated == 2
