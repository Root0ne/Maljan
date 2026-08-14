"""C3's bookkeeping, tested because the first run's arithmetic misread its own data.

The original harness recorded five of nine judge calls as the error string
``"reconcile never ran"`` and the summary counted them as ``failed_calls``. They
were not failures. ``give_verdict`` returns ``_fallback_bundle_from_text`` from
four separate branches, none of which calls ``postprocess_judge_bundle``, so on
those calls the reconciliation step genuinely never runs and the cascade's
technique set is never injected. Five measurements of a *second construction
path* were filed as machine trouble.

That is the failure this file guards against, in three forms — plus a fourth,
below, where the instrument that was built to measure the fallback path could
only ever report zeros from it:

* **a fallback counted as a failure.** It is an outcome with its own branch and
  its own consequence for the bundle; folding it into ``failed_calls`` hides the
  finding that produced it.
* **a fallback counted as a success.** It has no ``cascade_size``, so letting it
  into the scored set would divide judge contribution by a denominator that
  includes calls where no cascade was ever consulted.
* **an all-fallback run reported as empty.** If every call leaves the
  reconciliation path, that is the strongest version of this study's result, not
  an absence of one — and the first implementation would have printed "no
  scoreable calls" and stopped.

The branch names come from ``_fallback_reason``, which reads the text the branch
was handed rather than a stack trace, so its mapping is pinned here too.
"""

from __future__ import annotations

from tests.evaluation.eval_judge_contribution import (
    _fallback_reason,
    fallback_breakdown,
    summarise,
)


def reconciled_row(sid: str, *, own: list[str] | None = None) -> dict:
    """A row as the reconcile spy records it."""
    return {
        "key": f"judge:{sid}",
        "sample_id": sid,
        "path": "reconciled",
        "judge_patterns_emitted": 5,
        "judge_patterns_resolvable": 2,
        "judge_patterns_unresolvable_dropped": 3,
        "cascade_size": 10,
        "judge_ids_agreeing_with_cascade": 2,
        "judge_ids_outside_cascade": own or [],
        "injected_because_judge_omitted": 8,
        "final_bundle_size": 10 + len(own or []),
    }


def fallback_row(sid: str, reason: str = "verdict_timed_out") -> dict:
    return {
        "key": f"judge:{sid}",
        "sample_id": sid,
        "path": "fallback",
        "fallback_reason": reason,
        "response_chars": 0,
        "fallback_patterns_emitted": 0,
        "fallback_patterns_resolvable": 0,
        "final_bundle_size": 0,
    }


class TestFallbackReason:
    def test_timeout_is_named_from_its_literal(self) -> None:
        """The timeout branch passes ``"[TIMEOUT]"``; nothing else does."""
        assert _fallback_reason("[TIMEOUT]") == "verdict_timed_out"

    def test_prose_response_is_unparseable(self) -> None:
        assert _fallback_reason("This sample is clearly a dropper.") == "no_json_in_response"

    def test_json_array_is_not_an_object(self) -> None:
        """A bundle must be a dict; a list parses but fails the second gate."""
        assert _fallback_reason('["T1055", "T1027"]') == "json_not_an_object"

    def test_valid_object_means_postprocessing_raised(self) -> None:
        """Past both JSON gates, only the post-process ``except`` is left."""
        assert _fallback_reason('{"type": "bundle"}') == "postprocess_or_validation_raised"


class TestFallbackBreakdown:
    def test_counts_by_branch(self) -> None:
        rows = [
            fallback_row("a", "verdict_timed_out"),
            fallback_row("b", "verdict_timed_out"),
            fallback_row("c", "no_json_in_response"),
        ]
        assert fallback_breakdown(rows) == {"verdict_timed_out": 2, "no_json_in_response": 1}

    def test_ignores_rows_that_reached_the_seam(self) -> None:
        assert fallback_breakdown([reconciled_row("a")]) == {}


class TestSummariseSeparatesTheThreeOutcomes:
    def test_fallback_is_not_a_failure(self) -> None:
        """The bug this file exists for: five measurements filed as errors."""
        rows = [reconciled_row("a"), fallback_row("b"), fallback_row("c")]
        _md, blob = summarise(rows)
        assert blob["n_calls"] == 1
        assert blob["calls_fell_back"] == 2
        assert blob["failed_calls"] == 0

    def test_fallback_is_not_scored(self) -> None:
        """It has no cascade, so it cannot sit in a denominator about cascades."""
        rows = [reconciled_row("a"), fallback_row("b")]
        _md, blob = summarise(rows)
        assert blob["totals"]["cascade_size"] == 10
        assert len(blob["per_call"]) == 1
        assert len(blob["per_call_fallback"]) == 1

    def test_a_genuine_exception_is_still_a_failure(self) -> None:
        rows = [reconciled_row("a"), {"key": "judge:z", "error": "ConnectionError: refused"}]
        _md, blob = summarise(rows)
        assert blob["failed_calls"] == 1
        assert blob["calls_fell_back"] == 0

    def test_legacy_rows_without_a_path_still_count_as_reached(self) -> None:
        """The four rows from the first run predate the ``path`` key."""
        legacy = reconciled_row("old")
        del legacy["path"]
        _md, blob = summarise([legacy])
        assert blob["n_calls"] == 1

    def test_all_fallback_is_reported_not_swallowed(self) -> None:
        rows = [fallback_row("a"), fallback_row("b", "no_json_in_response")]
        md, blob = summarise(rows)
        assert blob["status"] == "no-call-reached-reconciliation"
        assert blob["calls_fell_back"] == 2
        assert blob["fallback_reasons"] == {"verdict_timed_out": 1, "no_json_in_response": 1}
        assert "never reached" in md

    def test_reachability_section_states_the_share(self) -> None:
        rows = [reconciled_row("a"), fallback_row("b"), fallback_row("c"), fallback_row("d")]
        md, _blob = summarise(rows)
        assert "3/4" in md
        assert "75% of judge calls never reached the reconciliation step" in md


class TestBundleObjectsAreReadWhicheverSideOfValidation:
    """The spy read zero attack-patterns from every fallback bundle, structurally.

    ``_reconcile_with_cascade`` runs before validation and sees dicts. The
    fallback path ends in ``Bundle.model_validate(...)``, and ``Bundle.objects``
    is a union of pydantic models — so ``_pattern_ids``, which skips anything
    that is not a dict, returned ``(0, [])`` for every fallback no matter what
    the bundle held. The production fallback builder visibly copies technique ids
    out of the ISR claims, so "zero patterns" was not a finding about the bundle;
    it was a fact about an ``isinstance`` check, and it would have been written up
    as *the analyst receives no techniques when the judge times out*.
    """

    def test_a_validated_model_still_yields_its_pattern(self) -> None:
        from pydantic import BaseModel

        from tests.evaluation.eval_judge_contribution import _pattern_ids, as_dicts

        class FakeAttackPattern(BaseModel):
            type: str = "attack-pattern"
            name: str = "T1055"
            external_references: list[dict] = [
                {"source_name": "mitre-attack", "external_id": "T1055"}
            ]

        objects = [FakeAttackPattern()]
        assert _pattern_ids(objects) == (0, [])  # the defect, pinned
        total, ids = _pattern_ids(as_dicts(objects))
        assert total == 1
        assert ids == ["T1055"]

    def test_plain_dicts_pass_through_unchanged(self) -> None:
        from tests.evaluation.eval_judge_contribution import as_dicts

        obj = {"type": "attack-pattern", "name": "T1027"}
        assert as_dicts([obj]) == [obj]

    def test_an_object_that_is_neither_is_dropped_rather_than_crashing(self) -> None:
        from tests.evaluation.eval_judge_contribution import as_dicts

        assert as_dicts(["not an object", 7, None]) == []
