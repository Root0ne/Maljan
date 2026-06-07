"""Unit tests for the static-feature family classifier.

Covers the pure render/projection helpers, the fail-safe ``load_classifier``
(missing model -> None), and ``FamilyClassifier.predict`` with a stub estimator
(threshold + top-k + sort), all without any heavy ML deps or live binaries.
"""

from __future__ import annotations

import numpy as np
import pytest

from maljan.analysis.family_classifier import (
    FamilyClassifier,
    FamilyPrediction,
    build_classifier_hint,
    load_classifier,
    reset_cache,
    to_report_dicts,
)


class _StubEstimator:
    """Minimal estimator: predict_proba over fixed classes_."""

    def __init__(self, classes: list[str], proba: list[float]) -> None:
        self.classes_ = np.array(classes)
        self._proba = np.array([proba])

    def predict_proba(self, _x: np.ndarray) -> np.ndarray:
        return self._proba


class TestBuildClassifierHint:
    def test_empty_results_no_hint(self) -> None:
        assert build_classifier_hint([]) == ""

    def test_renders_family_and_confidence(self) -> None:
        hint = build_classifier_hint([FamilyPrediction("AsyncRAT", 0.82)])
        assert "AsyncRAT" in hint
        assert "0.82" in hint
        assert "PRIOR" in hint
        assert "NOT proof" in hint  # framed as a hypothesis, not an assertion


class TestToReportDicts:
    def test_row_shape(self) -> None:
        rows = to_report_dicts([FamilyPrediction("QuasarRAT", 0.7)])
        assert rows == [
            {
                "family": "QuasarRAT",
                "confidence": 0.7,
                "match_method": "static-feature-classifier",
                "source": "maljan-ember-gbdt",
            }
        ]

    def test_empty(self) -> None:
        assert to_report_dicts([]) == []


class TestLoadClassifier:
    def setup_method(self) -> None:
        reset_cache()

    def test_missing_model_returns_none(self, tmp_path) -> None:
        assert load_classifier(str(tmp_path / "nope.joblib")) is None

    def test_empty_path_returns_none(self) -> None:
        assert load_classifier("") is None

    def test_result_is_cached(self, tmp_path) -> None:
        # Two calls for an absent model both return None without raising; the
        # second hits the cache (smoke: no exception, stable result).
        p = str(tmp_path / "nope.joblib")
        assert load_classifier(p) is None
        assert load_classifier(p) is None


class TestPredict:
    def _clf(self, classes, proba) -> FamilyClassifier:
        return FamilyClassifier(_StubEstimator(classes, proba), classes, model_path="stub")

    def test_topk_threshold_and_sort(self, monkeypatch) -> None:
        # Feature extraction is stubbed so no ember/binary is needed.
        monkeypatch.setattr(
            "maljan.analysis.family_classifier._extract_features",
            lambda _p: np.zeros(8, dtype=np.float32),
        )
        clf = self._clf(["AsyncRAT", "QuasarRAT", "njRAT"], [0.7, 0.2, 0.1])
        preds = clf.predict("x.exe", top_k=2, threshold=0.15)
        # Sorted desc, threshold drops njRAT (0.1), top_k caps at 2.
        assert [p.family for p in preds] == ["AsyncRAT", "QuasarRAT"]
        assert preds[0].confidence == 0.7

    def test_threshold_can_empty(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "maljan.analysis.family_classifier._extract_features",
            lambda _p: np.zeros(8, dtype=np.float32),
        )
        clf = self._clf(["AsyncRAT", "QuasarRAT"], [0.4, 0.3])
        assert clf.predict("x.exe", top_k=3, threshold=0.6) == []

    def test_unreadable_features_failsafe_empty(self, monkeypatch) -> None:
        # _extract_features returns None (missing ember / unreadable file) -> [].
        monkeypatch.setattr("maljan.analysis.family_classifier._extract_features", lambda _p: None)
        clf = self._clf(["AsyncRAT"], [0.9])
        assert clf.predict("x.exe", top_k=1, threshold=0.1) == []

    def test_predict_never_raises_on_estimator_error(self, monkeypatch) -> None:
        monkeypatch.setattr(
            "maljan.analysis.family_classifier._extract_features",
            lambda _p: np.zeros(8, dtype=np.float32),
        )

        class _Boom:
            classes_ = np.array(["x"])

            def predict_proba(self, _x):  # noqa: ANN001
                raise RuntimeError("boom")

        clf = FamilyClassifier(_Boom(), ["x"], model_path="stub")
        assert clf.predict("x.exe", top_k=1, threshold=0.1) == []  # fail-safe


@pytest.mark.parametrize("threshold", [0.0, 0.5, 0.99])
def test_hint_roundtrip_is_pure(threshold) -> None:
    # Pure helpers are deterministic and dependency-free regardless of threshold.
    preds = [FamilyPrediction("Emotet", 0.95)]
    assert "Emotet" in build_classifier_hint(preds)
    assert to_report_dicts(preds)[0]["family"] == "Emotet"
