"""Unit tests for the dynamic semantic category classifier and dispatcher.

Two layers:
  * Pure-logic tests (no fastembed / no ATT&CK cache): the embedding is
    monkeypatched so argmax / margin / abstain / fail-safe behaviour is
    deterministic and CI-portable.
  * Availability-guarded build test: only runs when fastembed + the cached
    ATT&CK corpus are present; asserts prototypes build and inference is total.
"""

from __future__ import annotations

import pytest

from maljan.analysis import semantic_category as sc
from maljan.analysis.schema_pruner import MalwareCategory
from maljan.analysis.semantic_category import (
    CategoryPrediction,
    SemanticCategoryClassifier,
    _category_technique_ids,
    _mean_unit_vector,
    infer_category,
)
from maljan.memory import embeddings

R = MalwareCategory.RANSOMWARE
RAT = MalwareCategory.RAT
UNK = MalwareCategory.UNKNOWN


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _two_proto_clf(**kw: float) -> SemanticCategoryClassifier:
    """Classifier with two orthonormal prototypes: ransomware=x, rat=y."""
    return SemanticCategoryClassifier(
        {R: [1.0, 0.0, 0.0], RAT: [0.0, 1.0, 0.0]},
        **kw,  # type: ignore[arg-type]
    )


# ---------------------------------------------------------------------------
# _mean_unit_vector
# ---------------------------------------------------------------------------
class TestMeanUnitVector:
    def test_empty_returns_empty(self) -> None:
        assert _mean_unit_vector([]) == []

    def test_single_vector_is_normalized(self) -> None:
        out = _mean_unit_vector([[3.0, 4.0]])
        assert out == pytest.approx([0.6, 0.8])

    def test_mean_then_normalize(self) -> None:
        out = _mean_unit_vector([[1.0, 0.0], [0.0, 1.0]])
        # mean (0.5,0.5) -> normalized
        assert out == pytest.approx([0.7071, 0.7071], abs=1e-3)

    def test_opposite_vectors_zero_mean(self) -> None:
        # mean is zero vector -> norm 0 -> returned as-is (zeros)
        out = _mean_unit_vector([[1.0, 0.0], [-1.0, 0.0]])
        assert out == [0.0, 0.0]

    def test_mismatched_dims_skipped(self) -> None:
        out = _mean_unit_vector([[1.0, 0.0], [9.9]])
        assert out == pytest.approx([1.0, 0.0])


# ---------------------------------------------------------------------------
# _category_technique_ids
# ---------------------------------------------------------------------------
class TestCategoryTechniqueIds:
    def test_all_five_categories_seeded(self) -> None:
        seeds = _category_technique_ids()
        assert set(seeds) == {
            MalwareCategory.RANSOMWARE,
            MalwareCategory.RAT,
            MalwareCategory.DROPPER,
            MalwareCategory.WORM,
            MalwareCategory.INFOSTEALER,
        }

    def test_ids_are_uppercase_technique_ids(self) -> None:
        for tids in _category_technique_ids().values():
            assert tids, "every seeded category must have at least one technique"
            for t in tids:
                assert t.startswith("T") and t[1:5].isdigit()


# ---------------------------------------------------------------------------
# SemanticCategoryClassifier.infer — pure logic via monkeypatched encode
# ---------------------------------------------------------------------------
class TestInferLogic:
    def test_empty_text_is_unknown(self) -> None:
        clf = _two_proto_clf()
        pred = clf.infer("")
        assert pred.category is UNK
        assert pred.score == 0.0

    def test_no_prototypes_is_unknown(self) -> None:
        clf = SemanticCategoryClassifier({})
        assert clf.infer("anything").category is UNK

    def test_argmax_picks_nearest_prototype(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(embeddings, "encode", lambda _t: [0.9, 0.1, 0.0])
        clf = _two_proto_clf()
        pred = clf.infer("malware text")
        assert pred.category is R
        assert pred.scores[R] > pred.scores[RAT]

    def test_high_rel_margin_threshold_forces_unknown(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # near-tie between the two prototypes
        monkeypatch.setattr(embeddings, "encode", lambda _t: [0.71, 0.70, 0.0])
        clf = _two_proto_clf(min_rel_margin=0.5)
        assert clf.infer("x").category is UNK

    def test_high_min_score_threshold_forces_unknown(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # vector nearly orthogonal to both -> low absolute cosine
        monkeypatch.setattr(embeddings, "encode", lambda _t: [0.05, 0.04, 0.99])
        clf = _two_proto_clf(min_score=0.5)
        assert clf.infer("x").category is UNK

    def test_embedding_error_is_failsafe(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _boom(_t: str) -> list[float]:
            raise RuntimeError("embed exploded")

        monkeypatch.setattr(embeddings, "encode", _boom)
        clf = _two_proto_clf()
        pred = clf.infer("x")  # must not raise
        assert pred.category is UNK

    def test_empty_prototypes_dropped_at_construction(self) -> None:
        clf = SemanticCategoryClassifier({R: [1.0, 0.0], RAT: []})
        assert clf.categories == [R]


# ---------------------------------------------------------------------------
# from_labeled_examples
# ---------------------------------------------------------------------------
class TestFromLabeledExamples:
    def test_builds_prototype_per_category(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(embeddings, "encode_batch", lambda ts: [[1.0, 0.0]] * len(ts))
        clf = SemanticCategoryClassifier.from_labeled_examples(
            [(R, "encrypts files"), (R, "drops ransom note"), (RAT, "reverse shell")]
        )
        assert set(clf.categories) == {R, RAT}

    def test_blank_examples_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(embeddings, "encode_batch", lambda ts: [[1.0, 0.0]] * len(ts))
        clf = SemanticCategoryClassifier.from_labeled_examples([(R, "   "), (RAT, "shell")])
        assert clf.categories == [RAT]


# ---------------------------------------------------------------------------
# infer_category dispatcher
# ---------------------------------------------------------------------------
class TestDispatcher:
    _RANSOM_TEXT = "drops a ransom note and encrypts files with aes, deletes shadow copies"
    _NEUTRAL_TEXT = "the quick brown fox jumps over the lazy dog repeatedly"

    def test_keyword_backend_matches_direct_inference(self) -> None:
        cat = infer_category({"a": self._RANSOM_TEXT}, backend="keyword")
        assert cat is R

    def test_keyword_backend_never_calls_semantic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _should_not_run() -> object:
            raise AssertionError("semantic path must not run for keyword backend")

        monkeypatch.setattr(sc, "get_default_semantic_classifier", _should_not_run)
        monkeypatch.setattr(sc, "backend_is_semantic", _should_not_run)
        assert infer_category({"a": self._RANSOM_TEXT}, backend="keyword") is R

    def test_hybrid_keeps_keyword_when_confident(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # keyword resolves confidently -> semantic must not be consulted
        def _should_not_run() -> object:
            raise AssertionError("semantic must not run when keyword is confident")

        monkeypatch.setattr(sc, "get_default_semantic_classifier", _should_not_run)
        assert infer_category({"a": self._RANSOM_TEXT}, backend="hybrid") is R

    def test_hybrid_falls_back_to_semantic_on_abstain(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        class _FakeClf:
            def infer(self, _t: str) -> CategoryPrediction:
                return CategoryPrediction(RAT, 0.9, 0.5, {RAT: 0.9})

        monkeypatch.setattr(sc, "backend_is_semantic", lambda: True)
        monkeypatch.setattr(sc, "get_default_semantic_classifier", lambda: _FakeClf())
        # neutral text -> keyword UNKNOWN -> semantic fills in RAT
        assert infer_category({"a": self._NEUTRAL_TEXT}, backend="hybrid") is RAT

    def test_semantic_falls_back_to_keyword_when_fastembed_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(sc, "backend_is_semantic", lambda: False)
        # BoW fallback -> dispatcher must use keyword's confident answer
        assert infer_category({"a": self._RANSOM_TEXT}, backend="semantic") is R

    def test_semantic_error_falls_back_to_keyword(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(sc, "backend_is_semantic", lambda: True)

        def _boom() -> object:
            raise RuntimeError("classifier build failed")

        monkeypatch.setattr(sc, "get_default_semantic_classifier", _boom)
        assert infer_category({"a": self._RANSOM_TEXT}, backend="semantic") is R

    def test_unknown_backend_uses_keyword(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _should_not_run() -> object:
            raise AssertionError("semantic must not run for unknown backend")

        monkeypatch.setattr(sc, "get_default_semantic_classifier", _should_not_run)
        assert infer_category({"a": self._RANSOM_TEXT}, backend="bogus") is R

    def test_dispatcher_never_raises_on_empty(self) -> None:
        for backend in ("keyword", "semantic", "hybrid"):
            assert isinstance(infer_category({}, backend=backend), MalwareCategory)


# ---------------------------------------------------------------------------
# Availability-guarded real build (fastembed + ATT&CK cache)
# ---------------------------------------------------------------------------
def _real_semantics_available() -> bool:
    try:
        return sc.backend_is_semantic()
    except Exception:  # noqa: BLE001
        return False


@pytest.mark.skipif(
    not _real_semantics_available(),
    reason="fastembed unavailable (BoW fallback) — real prototype build not meaningful",
)
class TestRealBuild:
    def test_zero_shot_builds_five_prototypes(self) -> None:
        sc.reset_default_classifier()
        try:
            clf = SemanticCategoryClassifier.from_attck_techniques()
        except Exception:  # noqa: BLE001
            pytest.skip("ATT&CK cache unavailable for prototype build")
        # All five behavioural categories should get a prototype.
        assert len(clf.categories) == 5
        assert MalwareCategory.UNKNOWN not in clf.categories

    def test_inference_is_total(self) -> None:
        try:
            clf = SemanticCategoryClassifier.from_attck_techniques()
        except Exception:  # noqa: BLE001
            pytest.skip("ATT&CK cache unavailable for prototype build")
        pred = clf.infer("encrypts the victim's files and demands a ransom payment")
        assert isinstance(pred.category, MalwareCategory)
        assert 0.0 <= pred.score <= 1.0001
