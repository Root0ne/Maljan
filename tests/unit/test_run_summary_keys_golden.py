"""The key set of the summary a run is *stored* with is a contract, so it is pinned.

What the API stores, what the report renders and what every evaluation script
reads back out of a stored run is not ``RunSummary.to_dict()`` alone. Four more
keys are written onto that dict after the dataclass exists — ``dedupe`` by the
report builder, ``evidence`` and ``sections_without_evidence`` by the report
node, ``fp_warnings`` by the post-pipeline linter — and the worker adds
``settings_snapshot``. The golden used to cover the dataclass only, so
``dedupe`` was pinned by nothing at all: a rename of ``indicators_merged`` or
``findings_merged`` would have left every test in this repository green and
broken a consumer that is not in it.

The golden is the key set alone, not the values: what a run measures is
allowed to change from one run to the next, but what it is *called* is not.
The summary is built by ``scripts/goldens/capture_run_summary_golden.py``,
which the golden is regenerated with, so the test and the capture cannot
disagree about what a stored summary is.
"""

from __future__ import annotations

import json
from pathlib import Path

from scripts.goldens.capture_run_summary_golden import GOLDEN, key_shape, stored_summary

# The four keys the post-pass adds. Named here so a reader of a failure knows
# which half of the summary moved, and so removing one from the capture fails
# rather than quietly shrinking what is pinned.
POST_PASS_KEYS = ("dedupe", "evidence", "sections_without_evidence", "fp_warnings")


def test_the_stored_summary_key_set_matches_the_golden():
    shape = key_shape(stored_summary())
    expected = json.loads(Path(GOLDEN).read_text(encoding="utf-8"))
    assert shape == expected, (
        "the stored run summary changed shape. If the change is intended, "
        "regenerate the golden with "
        "`uv run python scripts/goldens/capture_run_summary_golden.py` in the "
        "same commit and say in the message which consumer of the stored "
        "summary was checked."
    )


def test_the_golden_covers_what_is_written_after_the_dataclass():
    """The gap this golden was widened to close, stated as an assertion."""
    expected = json.loads(Path(GOLDEN).read_text(encoding="utf-8"))
    missing = [key for key in POST_PASS_KEYS if key not in expected]
    assert not missing, f"the golden no longer pins {missing}"


def test_the_summary_is_still_json_serializable():
    json.dumps(stored_summary())
