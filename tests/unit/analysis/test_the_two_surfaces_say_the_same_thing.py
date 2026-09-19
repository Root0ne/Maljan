"""The report and the console describe one bundle's losses in one wording.

``integrity_objects_removed`` counts both integrity passes, and the second one
runs after the indicator cap and removes nothing but relationships the cap
orphaned. The report's Bounds Hit line printed that total as "STIX objects
repaired away"; the console had already learned to subtract the orphans. On the
"everything at once" shape the report said 10 and the console said 4 about the
same run.

One reading now, built the same way on both sides and pinned here against the
counts of the eight measured bundle shapes. The TypeScript half asserts the same
file (``apps/web/src/lib/__tests__/bundleLoss.test.ts``), so a change to either
wording fails on the side that was not changed.
"""

from __future__ import annotations

import json
import pathlib
from dataclasses import dataclass, field
from typing import Any

import pytest

from maljan.analysis.run_summary import TruncationMetrics, bundle_loss_sentence

FIXTURE = (
    pathlib.Path(__file__).resolve().parents[2]
    / "fixtures"
    / "golden"
    / "bundle_loss_sentences.json"
)
CASES = json.loads(FIXTURE.read_text(encoding="utf-8"))["cases"]


@dataclass
class _Counts:
    """Only the fields the sentence reads, so the fixture is the whole input."""

    integrity_objects_removed: int = 0
    indicator_cap_removed: int = 0
    integrity_refs_trimmed: int = 0
    integrity_dropped: dict[str, int] = field(default_factory=dict)


@pytest.mark.parametrize("case", CASES, ids=[c["shape"] for c in CASES])
def test_the_sentence_is_the_one_the_fixture_pins(case: dict[str, Any]) -> None:
    assert bundle_loss_sentence(_Counts(**case["counts"])) == case["sentence"]


def test_the_real_metrics_object_reads_the_same() -> None:
    """Not only the stand-in: the dataclass the run summary actually carries."""
    everything = next(c for c in CASES if c["shape"] == "everything at once")
    metrics = TruncationMetrics(
        tool_output_calls=0,
        tool_output_over_limit=0,
        tool_output_summarised=0,
        tool_output_hard_truncated=0,
        tool_output_chars_dropped=0,
        react_invocations=0,
        react_step_cap_hits=0,
        judge_invocations=0,
        judge_token_cap_hits=0,
        integrity_invocations=1,
        **everything["counts"],
    )

    assert bundle_loss_sentence(metrics) == everything["sentence"]


def test_the_report_prints_it_and_not_the_lumped_total() -> None:
    """Through the builder, so the line is the one a run really renders."""
    from maljan.analysis.run_summary import RunSummaryBuilder

    everything = next(c for c in CASES if c["shape"] == "everything at once")
    snapshot: dict[str, Any] = {
        "integrity_invocations": 1,
        "integrity_objects_removed": everything["counts"]["integrity_objects_removed"],
        "indicator_cap_removed": everything["counts"]["indicator_cap_removed"],
        "integrity_refs_trimmed": everything["counts"]["integrity_refs_trimmed"],
        "integrity_dropped": dict(everything["counts"]["integrity_dropped"]),
    }
    builder = RunSummaryBuilder(start_time=0.0)
    builder.set_sample("d" * 64, "sample.exe")
    summary = builder.set_truncation(snapshot).build()

    markdown = summary.to_markdown()

    assert everything["sentence"] in markdown
    assert "STIX objects repaired away" not in markdown
