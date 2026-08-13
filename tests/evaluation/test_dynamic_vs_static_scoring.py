"""C4's pure helpers, tested without a pipeline, a model or a sandbox.

The first class exists because of a specific failure. C4's first smoke run drove
a full pipeline pass — twenty minutes of static analysis, dynamic analysis,
consensus and report generation — and then threw ``AttributeError: 'str' object
has no attribute 'get'`` while *scoring* it. The harness read the predicted
techniques out of ``state["judge_report"]``, which `pipeline/state.py` declares
as ``str | None``: a prose paragraph, never a mapping. Had the full study been
launched instead, all 86 arms would have completed the expensive part and failed
at the cheap one.

So the shape of a pipeline result is now pinned here, and the extraction goes
through ``eval_temporal_drift.extract_predicted_tids`` — the extractor C5 already
uses, which is what makes the two studies' numbers comparable rather than merely
adjacent.

The remaining classes cover the covariate arithmetic. §3.21 found the dynamic
channel is 63.5-81.6% cohort-ubiquitous, and C4 reports that share next to every
delta; if ``ubiquitous_domains`` were wrong, the caveat that reads the result
would be wrong with it.
"""

from __future__ import annotations

import json

import pytest

from tests.evaluation.eval_dynamic_vs_static import (
    bootstrap_ci,
    incidental_reasons,
    load_report,
    predicted_from_result,
    sample_domains,
    techniques_by_source,
    ubiquitous_domains,
)


class TestIncidentalDegradation:
    """Separating degradation the treatment causes from degradation it doesn't.

    The static-only arm reports degradation on **every** sample, because the
    treatment is precisely that it has no sandbox report. A contamination check
    that counted those would flag 100% of pairs and read as "this study cannot
    attribute its delta" when the design is working exactly as intended.
    """

    def test_the_absent_sandbox_report_is_the_treatment_not_a_confound(self) -> None:
        observed = [
            "no sandbox report (dynamic detonation unavailable) — static-only evidence",
            "analysts produced no claims: dynamic, network",
        ]
        assert incidental_reasons(observed, "static_only") == set()

    def test_a_starved_analyst_list_keeps_the_analysts_that_were_not_starved(self) -> None:
        """dynamic and network had nothing to consume. static did, so its
        silence is a real failure and must survive the filter."""
        observed = ["analysts produced no claims: dynamic, network, static"]
        assert incidental_reasons(observed, "static_only") == {
            "analysts produced no claims: static"
        }

    def test_an_unrelated_failure_survives(self) -> None:
        observed = [
            "no sandbox report (dynamic detonation unavailable)",
            "container restart failed",
        ]
        assert incidental_reasons(observed, "static_only") == {"container restart failed"}

    def test_nothing_is_excused_in_the_dynamic_arm(self) -> None:
        """Nothing was withheld from it, so every reason it reports is real —
        including one that mentions the sandbox, which would itself be a fault."""
        observed = ["no sandbox report (dynamic detonation unavailable)"]
        assert incidental_reasons(observed, "dynamic") == set(observed)

    def test_no_reasons_is_an_empty_set(self) -> None:
        assert incidental_reasons([], "static_only") == set()


class TestPredictionExtraction:
    def test_a_prose_judge_report_does_not_crash_the_scorer(self) -> None:
        """``judge_report`` is ``str | None`` in the state definition. Reading
        ``.get("ttp_mappings")`` off it is the bug this test exists to prevent."""
        result = {
            "judge_report": "The sample encrypts files and contacts a C2 host.",
            "isr_reports": {},
            "run_summary": {},
        }
        assert predicted_from_result(result) == set()

    def test_reads_isr_claims(self) -> None:
        result = {
            "judge_report": "prose",
            "isr_reports": {
                "static": {"claims": [{"technique_id": "T1055"}, {"technique_id": "T1071"}]}
            },
        }
        assert predicted_from_result(result) == {"T1055", "T1071"}

    def test_unions_cascade_corroborated_techniques(self) -> None:
        result = {
            "isr_reports": {"static": {"claims": [{"technique_id": "T1055"}]}},
            "run_summary": {"cascade": {"corroborated_techniques": ["T1486"]}},
        }
        assert predicted_from_result(result) == {"T1055", "T1486"}

    def test_ids_are_upper_cased_so_the_metric_compares_like_with_like(self) -> None:
        result = {"isr_reports": {"s": {"claims": [{"technique_id": "t1055"}]}}}
        assert predicted_from_result(result) == {"T1055"}

    def test_an_empty_result_is_an_empty_set_not_a_crash(self) -> None:
        assert predicted_from_result({}) == set()


class TestReportVerification:
    def test_a_report_about_another_sample_is_refused(self, tmp_path, monkeypatch) -> None:
        """§6: the sandbox answers a request for a deleted report with HTTP 200
        and an error body, so a file on disk is not evidence that it describes
        the sample whose name it carries."""
        import tests.evaluation.eval_dynamic_vs_static as mod

        monkeypatch.setattr(mod, "REPORTS_DIR", tmp_path)
        sha = "a" * 64
        other = "b" * 64
        (tmp_path / f"{sha}.json").write_text(json.dumps({"target": {"file": {"sha256": other}}}))
        assert load_report(sha) is None

    def test_a_matching_report_is_returned(self, tmp_path, monkeypatch) -> None:
        import tests.evaluation.eval_dynamic_vs_static as mod

        monkeypatch.setattr(mod, "REPORTS_DIR", tmp_path)
        sha = "a" * 64
        (tmp_path / f"{sha}.json").write_text(json.dumps({"target": {"file": {"sha256": sha}}}))
        assert load_report(sha) is not None

    def test_the_sha_comparison_is_case_insensitive(self, tmp_path, monkeypatch) -> None:
        import tests.evaluation.eval_dynamic_vs_static as mod

        monkeypatch.setattr(mod, "REPORTS_DIR", tmp_path)
        sha = "a" * 64
        (tmp_path / f"{sha}.json").write_text(
            json.dumps({"target": {"file": {"sha256": sha.upper()}}})
        )
        assert load_report(sha) is not None

    def test_a_missing_or_unparseable_file_is_none_rather_than_an_exception(
        self, tmp_path, monkeypatch
    ) -> None:
        import tests.evaluation.eval_dynamic_vs_static as mod

        monkeypatch.setattr(mod, "REPORTS_DIR", tmp_path)
        assert load_report("c" * 64) is None
        (tmp_path / f"{'d' * 64}.json").write_text("{not json")
        assert load_report("d" * 64) is None


class TestContaminationCovariate:
    def test_domains_are_read_from_dicts_and_from_bare_strings(self) -> None:
        report = {"network": {"domains": [{"domain": "a.example"}, "b.example"]}}
        assert sample_domains(report) == {"a.example", "b.example"}

    def test_a_report_without_network_data_has_no_domains(self) -> None:
        assert sample_domains({}) == set()

    def test_ubiquitous_is_the_intersection_not_the_union(self) -> None:
        """The whole point of the covariate: a domain every sample shows is the
        VM describing itself, not the malware. A union would report the opposite
        and make the dynamic channel look far richer than it is."""
        reports = {
            "a": {"network": {"domains": ["vm.telemetry", "evil-one.test"]}},
            "b": {"network": {"domains": ["vm.telemetry", "evil-two.test"]}},
        }
        assert ubiquitous_domains(reports) == {"vm.telemetry"}

    def test_one_sample_makes_all_of_its_domains_ubiquitous(self) -> None:
        reports = {"a": {"network": {"domains": ["only.test"]}}}
        assert ubiquitous_domains(reports) == {"only.test"}

    def test_no_reports_yields_no_ubiquitous_domains(self) -> None:
        assert ubiquitous_domains({}) == set()


class TestBootstrap:
    def test_a_constant_sample_has_a_degenerate_interval(self) -> None:
        lo, hi = bootstrap_ci([0.5] * 20)
        assert lo == pytest.approx(0.5)
        assert hi == pytest.approx(0.5)

    def test_the_interval_brackets_the_mean(self) -> None:
        vals = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]
        lo, hi = bootstrap_ci(vals)
        assert lo <= sum(vals) / len(vals) <= hi

    def test_it_is_deterministic_under_the_fixed_seed(self) -> None:
        vals = [0.1, 0.4, 0.2, 0.9, 0.3]
        assert bootstrap_ci(vals) == bootstrap_ci(vals)

    def test_a_single_observation_is_a_point_not_a_crash(self) -> None:
        assert bootstrap_ci([0.7]) == (0.7, 0.7)

    def test_no_observations_is_zero_width_at_zero(self) -> None:
        assert bootstrap_ci([]) == (0.0, 0.0)


class TestSourceAttribution:
    """Which source claimed what — the question the eighth pair raised.

    The dynamic arm predicted more techniques than the static-only arm while
    reporting that the dynamic and network analysts produced no claims. Either
    the reason string is wrong or the gain comes from somewhere else; without
    per-source attribution the study cannot say which.
    """

    def test_reads_claims_per_source(self) -> None:
        result = {
            "isr_reports": {
                "sigma_layer": {"claims": [{"technique_id": "T1055"}, {"technique_id": "T1071"}]},
                "yara_layer": {"claims": [{"technique_id": "T1486"}]},
            }
        }
        assert techniques_by_source(result) == {
            "sigma_layer": ["T1055", "T1071"],
            "yara_layer": ["T1486"],
        }

    def test_a_source_present_but_silent_is_an_empty_list_not_absent(self) -> None:
        """The distinction the whole question turns on: an analyst that ran and
        claimed nothing is not the same as one that never ran."""
        result = {"isr_reports": {"dynamic": {"claims": []}}}
        assert techniques_by_source(result) == {"dynamic": []}

    def test_duplicate_claims_collapse(self) -> None:
        result = {
            "isr_reports": {"s": {"claims": [{"technique_id": "T1055"}, {"technique_id": "t1055"}]}}
        }
        assert techniques_by_source(result) == {"s": ["T1055"]}

    def test_object_shaped_reports_are_read_too(self) -> None:
        claim = type("C", (), {"technique_id": "T1071"})()
        isr = type("I", (), {"claims": [claim]})()
        assert techniques_by_source({"isr_reports": {"net": isr}}) == {"net": ["T1071"]}

    def test_a_result_without_isrs_attributes_nothing(self) -> None:
        assert techniques_by_source({}) == {}
