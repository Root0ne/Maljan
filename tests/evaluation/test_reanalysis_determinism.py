"""The re-analysis must produce the same artifact twice, and the committed one must be it.

The rubric asks for "two runs of the full pipeline produce identical outputs".
The pipeline that matters here is the offline one: given the committed
per-sample records, every interval, p-value, q-value and design effect the paper
quotes has to fall out the same way on any machine, or the correction is no more
auditable than the estimator it replaces.

Two properties, tested separately because they fail for different reasons:

* **determinism** — the seed reaches every resample. Cheap, so it runs at a
  reduced iteration count; the iteration count is not a source of randomness.
* **currency** — the checked-in ``cluster_analysis.json`` is what the current
  code produces from the current artifacts. This is the expensive one and it is
  the one that catches a stale commit.

Neither test writes to ``tests/evaluation/``. ``build_paper.py`` fails the build
when any artifact there is newer than the derived facts, so a test that rewrote
its own output would break the paper build on every test run — the kind of
coupling this directory has been bitten by before.
"""

from __future__ import annotations

import json

import pytest

from tests.evaluation import reanalyse


def test_the_reanalysis_is_deterministic():
    """Same inputs, same seed, byte-identical result."""
    first = json.dumps(reanalyse.analyse(iters=200), indent=1, sort_keys=True)
    second = json.dumps(reanalyse.analyse(iters=200), indent=1, sort_keys=True)
    assert first == second


def test_a_different_seed_would_move_the_intervals():
    """Guards a resample that is not resampling.

    A frozen RNG produces a perfectly reproducible and perfectly wrong artifact,
    and the determinism test above would pass on it.
    """
    baseline = reanalyse.analyse(iters=200)["comparisons"]["P1"]["interval"]
    original = reanalyse.SEED
    try:
        reanalyse.SEED = original + 1
        moved = reanalyse.analyse(iters=200)["comparisons"]["P1"]["interval"]
    finally:
        reanalyse.SEED = original
    assert (baseline["lo"], baseline["hi"]) != (moved["lo"], moved["hi"])


def test_every_comparison_declares_its_multiplicity_family():
    result = reanalyse.analyse(iters=200)
    for cid, comp in result["comparisons"].items():
        assert comp["family"] in {"A_primary", "B_posthoc"}, cid
        assert "q_exact" in comp and "q_bootstrap" in comp, cid


def test_every_interval_records_the_unit_it_resampled():
    """An interval with no cluster count cannot be checked by a reader."""
    result = reanalyse.analyse(iters=200)
    for cid, comp in result["comparisons"].items():
        iv = comp.get("interval")
        if iv is None:
            continue
        assert iv["n_clusters"] >= 2, cid
        assert iv["seed"] == reanalyse.SEED, cid
        assert iv["method"].startswith("cluster_bootstrap"), cid


def test_the_fixture_corpus_floor_is_reported_and_binding():
    """At five clusters no comparison on that corpus can reach alpha=0.05.

    This is the correction's headline, and it is asserted rather than written
    down: if a sixth fixture is ever added the floor moves and the sentence in
    the paper that quotes it has to move with it.
    """
    result = reanalyse.analyse(iters=200)
    design = result["design"]
    assert design["fixture_clusters"] == 5
    assert design["signflip_floor"] == pytest.approx(0.0625)
    assert design["corpora_comparable"] is False
    on_fixtures = [c for c in result["comparisons"].values() if c["corpus"] == "fixtures-n5"]
    assert on_fixtures
    assert all(c["p_exact_signflip"] >= 0.0625 for c in on_fixtures)


def test_the_two_corpora_are_never_pooled():
    """The CAPE baseline and the fixture arms must not share an estimate."""
    result = reanalyse.analyse(iters=200)
    assert result["cape_baseline"]["corpus"] == "cape-n97"
    assert result["cape_baseline"]["f1"]["structure"]["k"] == 24
    for comp in result["comparisons"].values():
        assert comp["corpus"] == "fixtures-n5"
        assert comp["structure"]["k"] == 5


@pytest.mark.slow
def test_the_committed_artifact_matches_a_fresh_full_run():
    """Regenerate with ``make reanalyse`` when this fails.

    Runs at the real iteration count, which takes about half a minute — the
    reason it is marked slow rather than dropped is that a committed artifact
    nobody re-derives is exactly the staleness the facts pipeline exists to stop.
    """
    fresh = json.dumps(reanalyse.analyse(), indent=1, sort_keys=True) + "\n"
    assert reanalyse.OUT.exists(), "run tests/evaluation/reanalyse.py"
    assert reanalyse.OUT.read_text() == fresh
