"""One way to skip a golden case whose source is absent, and one count of those skips.

A golden suite compares today's output with a frozen answer, and some of the
sources those answers were captured from are kept only on the machine that
captured them (they are large, or not ours to publish). Where a source is
missing the case is skipped, never failed. Left at that, a run without the
sources reports hundreds of quiet skips and a drift in the frozen answers goes
unseen for as long as nobody runs the suite with them, so every such skip
carries one reason prefix and the session ends with their number.

On GitHub Actions the number is also a warning annotation and a line in the
job summary, so a run that compared nothing against a golden says so where the
run is read.
"""

from __future__ import annotations

import os
from collections.abc import Iterable
from typing import Any

import pytest

ABSENT_FIXTURE_REASON = "golden fixture absent"


def skip_absent_fixture(detail: str) -> None:
    """Skip this golden case because its source is not on this machine."""
    pytest.skip(f"{ABSENT_FIXTURE_REASON}: {detail}")


def _skip_reason(report: Any) -> str:
    longrepr = getattr(report, "longrepr", None)
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    return str(longrepr or "")


def absent_fixture_skips(skipped: Iterable[Any]) -> int:
    """How many of the ``skipped`` test reports are golden cases without their source."""
    return sum(1 for report in skipped if ABSENT_FIXTURE_REASON in _skip_reason(report))


def absent_fixture_summary(count: int) -> str:
    """The session's closing line about golden cases that compared nothing."""
    noun = "test" if count == 1 else "tests"
    return (
        f"{count} golden {noun} skipped: {ABSENT_FIXTURE_REASON} "
        "(their source reports are not on this machine, so these goldens were not compared)"
    )


def report_absent_fixture_skips(terminalreporter: Any) -> int:
    """Write the count at the end of the session; on GitHub Actions also annotate the run."""
    count = absent_fixture_skips(terminalreporter.stats.get("skipped", []))
    if not count:
        return 0
    line = absent_fixture_summary(count)
    terminalreporter.write_sep("=", line, yellow=True, bold=True)
    if os.environ.get("GITHUB_ACTIONS") == "true":
        terminalreporter.write_line(f"::warning title=Golden fixtures absent::{line}")
        summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary_path:
            try:
                with open(summary_path, "a", encoding="utf-8") as handle:
                    handle.write(f"- {line}\n")
            except OSError:
                terminalreporter.write_line("the job summary could not be written")
    return count
