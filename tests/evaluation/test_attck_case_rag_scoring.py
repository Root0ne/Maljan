"""The ATT&CK case-RAG eval decided a shipped default — so its arithmetic is tested.

``eval_attck_case_rag.py`` is the evidence behind keeping ``use_attck_case_rag`` off.
An eval that silently mis-scores would either bury a working feature or wave through a
broken one, and neither failure announces itself: both just produce a number. The parts
that can be wrong without looking wrong are pure functions, so they are pinned here.

Two of these pin properties the *result* hinges on:

  * ``_aggregate`` must rank by support before score — that is what makes retrieval
    differ from nearest-neighbour copying, and the whole native-vs-runtime gap is a
    statement about it.
  * ``_frequency_prior`` must count each technique once per case. Counting duplicates
    would inflate the control, and the control is what the feature was measured against.

Network-free, model-free, fast — no embeddings are involved.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_EVAL_DIR = Path(__file__).resolve().parent
if str(_EVAL_DIR) not in sys.path:
    sys.path.insert(0, str(_EVAL_DIR))

np = pytest.importorskip("numpy", reason="eval helpers import numpy at module scope")

from eval_attck_case_rag import (  # noqa: E402
    _aggregate,
    _frequency_prior,
    _load_cases,
    _mean,
    _prf,
)


class TestPrecisionRecall:
    def test_a_perfect_prediction_scores_one(self) -> None:
        assert _prf(["T1055", "T1027"], {"T1055", "T1027"}) == (1.0, 1.0, 1.0)

    def test_precision_is_over_what_was_predicted(self) -> None:
        p, _, _ = _prf(["T1055", "T9999"], {"T1055"})
        assert p == pytest.approx(0.5)

    def test_recall_is_over_the_truth_set(self) -> None:
        _, r, _ = _prf(["T1055"], {"T1055", "T1027", "T1083", "T1082"})
        assert r == pytest.approx(0.25)

    def test_predicting_nothing_scores_zero_rather_than_dividing_by_zero(self) -> None:
        """An abstaining recommender must not read as perfect precision."""
        assert _prf([], {"T1055"}) == (0.0, 0.0, 0.0)

    def test_a_disjoint_prediction_has_no_f1(self) -> None:
        assert _prf(["T9999"], {"T1055"}) == (0.0, 0.0, 0.0)


class TestAggregationRanksBySupport:
    def test_a_technique_seen_in_more_neighbours_wins(self) -> None:
        """Even when the rarer one sits on the closer neighbour."""
        truths = [["T1027"], ["T1055"], ["T1055"]]
        out = _aggregate([0, 1, 2], [0.99, 0.50, 0.49], truths, max_techniques=2)
        assert out[0] == "T1055"

    def test_similarity_breaks_ties_within_equal_support(self) -> None:
        truths = [["T1027"], ["T1055"]]
        assert _aggregate([0, 1], [0.4, 0.9], truths, max_techniques=2) == ["T1055", "T1027"]

    def test_a_repeat_inside_one_case_counts_once(self) -> None:
        """Otherwise one duplicated id outranks a genuinely corroborated one."""
        truths = [["T1027", "T1027", "T1027"], ["T1055"], ["T1055"]]
        assert _aggregate([0, 1, 2], [0.9, 0.5, 0.5], truths, max_techniques=1) == ["T1055"]

    def test_the_budget_is_respected(self) -> None:
        truths = [["T1", "T2", "T3", "T4", "T5"]]
        assert len(_aggregate([0], [0.9], truths, max_techniques=3)) == 3

    def test_no_neighbours_means_no_recommendation(self) -> None:
        assert _aggregate([], [], [["T1055"]], max_techniques=8) == []


class TestFrequencyPriorControl:
    def test_the_prior_is_the_most_common_techniques(self) -> None:
        truths = [["T1055"], ["T1055"], ["T1055"], ["T1027"], ["T1027"], ["T1083"]]
        prior, _ = _frequency_prior(truths, max_techniques=2)
        assert prior == ["T1055", "T1027"]

    def test_a_case_repeating_a_technique_still_counts_once(self) -> None:
        """A single case cannot out-vote two cases by listing an id three times."""
        truths = [["T1027", "T1027", "T1027"], ["T1055"], ["T1055"]]
        prior, _ = _frequency_prior(truths, max_techniques=1)
        assert prior == ["T1055"]

    def test_the_vocabulary_covers_every_technique_seen(self) -> None:
        _, vocab = _frequency_prior([["T1055"], ["T1027", "T1083"]], max_techniques=1)
        assert vocab == ["T1027", "T1055", "T1083"]


class TestCorpusLoading:
    def test_a_case_without_labels_is_not_scored(self, tmp_path: Path) -> None:
        """An unlabelled case has no truth to be right or wrong about."""
        p = tmp_path / "corpus.json"
        p.write_text(
            '{"cases": [{"sample_id": "a", "summary_text": "x", "technique_ids": []},'
            ' {"sample_id": "b", "summary_text": "y", "technique_ids": ["T1055"]}]}'
        )
        assert [c["sample_id"] for c in _load_cases(p)] == ["b"]

    def test_a_case_without_text_is_not_scored(self, tmp_path: Path) -> None:
        """Blank text embeds to a zero vector and would score against everything."""
        p = tmp_path / "corpus.json"
        p.write_text(
            '{"cases": [{"sample_id": "a", "summary_text": "  ", "technique_ids": ["T1"]}]}'
        )
        assert _load_cases(p) == []


class TestMeanReporting:
    def test_an_empty_run_reports_zero_not_a_crash(self) -> None:
        assert _mean([]) == {"precision": 0.0, "recall": 0.0, "f1": 0.0}

    def test_metrics_are_averaged_per_sample(self) -> None:
        assert _mean([(1.0, 1.0, 1.0), (0.0, 0.0, 0.0)])["precision"] == pytest.approx(0.5)
