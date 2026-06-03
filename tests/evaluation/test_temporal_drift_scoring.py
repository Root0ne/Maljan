"""Unit tests for the pure scoring/resolution helpers of ``eval_temporal_drift``."""

from __future__ import annotations

from collections import OrderedDict

from maljan.schemas.isr_models import AgentISR, ClaimEvidence
from tests.evaluation.eval_temporal_drift import (
    _camel_split,
    _slugify,
    aggregate_by_cohort,
    drift_delta,
    extract_predicted_tids,
    resolve_fixture_slug,
    score_sample,
)

_AVAILABLE = {"agent_tesla", "cobalt_strike", "njrat", "redline_stealer", "emotet", "lokibot"}


class TestSlugAndCamelSplit:
    def test_slugify_matches_fixture_convention(self) -> None:
        assert _slugify("Agent Tesla") == "agent_tesla"
        assert _slugify("RedLine Stealer") == "redline_stealer"

    def test_camel_split_recovers_word_boundaries(self) -> None:
        assert _camel_split("AgentTesla") == "Agent Tesla"
        assert _camel_split("njRAT") == "nj RAT"


class TestResolveFixtureSlug:
    def test_alias_map_pins_concatenated_names(self) -> None:
        assert resolve_fixture_slug("AgentTesla", _AVAILABLE) == "agent_tesla"
        assert resolve_fixture_slug("CobaltStrike", _AVAILABLE) == "cobalt_strike"
        assert resolve_fixture_slug("RedLineStealer", _AVAILABLE) == "redline_stealer"

    def test_direct_slug_when_simple(self) -> None:
        assert resolve_fixture_slug("Emotet", _AVAILABLE) == "emotet"
        assert resolve_fixture_slug("njRAT", _AVAILABLE) == "njrat"

    def test_unknown_family_returns_none(self) -> None:
        assert resolve_fixture_slug("Formbook", _AVAILABLE) is None
        assert resolve_fixture_slug("", _AVAILABLE) is None


class TestExtractPredictedTids:
    def test_from_agentisr_objects(self) -> None:
        isr = AgentISR(
            agent_id="static",
            domain="static",
            claims=[
                ClaimEvidence(claim="a", evidence_ref="r", confidence=0.8, technique_id="T1055"),
                ClaimEvidence(claim="b", evidence_ref="r", confidence=0.7, technique_id=None),
                ClaimEvidence(
                    claim="c", evidence_ref="r", confidence=0.9, technique_id="T1071.001"
                ),
            ],
        )
        result = {"isr_reports": {"static": isr}, "run_summary": {}}
        assert extract_predicted_tids(result) == {"T1055", "T1071.001"}

    def test_unions_cascade_corroborated(self) -> None:
        result = {
            "isr_reports": {},
            "run_summary": {"cascade": {"corroborated_techniques": ["T1059", "t1486"]}},
        }
        assert extract_predicted_tids(result) == {"T1059", "T1486"}

    def test_handles_empty_result(self) -> None:
        assert extract_predicted_tids({}) == set()


class TestScoreSample:
    def test_perfect_match(self) -> None:
        sc = score_sample(
            "2023", "ab" * 32, "Emotet", {"T1055", "T1071"}, {"T1055", "T1071"}, set()
        )
        assert sc.precision == 1.0 and sc.recall == 1.0 and sc.f1 == 1.0

    def test_partial_and_hallucination(self) -> None:
        # Predicted T1055 (correct), T9999 (invalid/hallucinated); GT has T1055,T1071.
        sc = score_sample(
            "2023",
            "cd" * 32,
            "Emotet",
            {"T1055", "T9999"},
            {"T1055", "T1071"},
            {"T1055", "T1071"},  # valid universe; T9999 absent -> hallucination
        )
        assert sc.precision == 0.5  # 1 of 2 predicted in GT
        assert sc.recall == 0.5  # 1 of 2 GT recovered
        assert sc.hallucination_rate == 0.5  # T9999 not in valid set


class TestAggregateAndDrift:
    def _score(self, year: str, f1: float) -> object:
        # precision/recall don't matter for the f1-CI aggregation tests.
        return score_sample(year, "00" * 32, "x", {"T1055"}, {"T1055"} if f1 else set(), set())

    def test_aggregate_groups_years_ascending(self) -> None:
        scores = [
            score_sample("2024", "a" * 64, "x", {"T1055"}, {"T1055"}, set()),
            score_sample("2021", "b" * 64, "x", {"T1055"}, {"T1055"}, set()),
        ]
        agg = aggregate_by_cohort(scores)
        assert list(agg) == ["2021", "2024"]
        assert agg["2021"]["n"] == 1

    def test_drift_delta_earliest_vs_latest(self) -> None:
        agg: OrderedDict[str, dict] = OrderedDict()
        agg["2020"] = {"f1": 0.9, "n": 5}
        agg["2025"] = {"f1": 0.6, "n": 5}
        d = drift_delta(agg)
        assert d is not None
        assert d["earliest_year"] == "2020"
        assert d["latest_year"] == "2025"
        assert abs(d["f1_delta"] - (-0.3)) < 1e-9

    def test_drift_delta_needs_two_cohorts(self) -> None:
        agg: OrderedDict[str, dict] = OrderedDict()
        agg["2020"] = {"f1": 0.9, "n": 5}
        assert drift_delta(agg) is None
