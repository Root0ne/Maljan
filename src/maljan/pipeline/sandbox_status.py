"""Whether a sandbox ran, read once, in the words every reader of the report uses.

A run's sandbox report is one of three things, and they read alike. A live
sandbox's report is an observation, empty or not. The mock sandbox's recorded
fixture is an observation too, but of some earlier detonation, not of this
run. And when the mock has no fixture for the sample it answers with an empty
stand-in, marked ``synthetic``, which is no observation at all — one scored
run's pack rendered it as "sandbox processes: 0 processes" and "no network
activity recorded", and the report built on that spoke of what the sample did
"during sandbox execution" when nothing had been executed.

The pack, the degradation reasons, the run summary and the report all ask this
module rather than the report's keys, so each says the same true thing: no
sandbox ran, or the report is a recorded fixture and not a live detonation, or
nothing is added to what a sandbox observed.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# The three answers. Words rather than codes because they are written into
# the ledger entry and the run summary, where a reader meets them as they are.
NOT_RUN = "not run"
RECORDED_FIXTURE = "recorded fixture"
OBSERVED = "observed"

# The mark the mock sandbox's stand-in report carries (``MockSandboxClient``).
SYNTHETIC_KEY = "synthetic"
# The mark a report the mock sandbox read from a fixture file carries
# (``providers.cape_view``).
FIXTURE_KEY = "recorded_fixture"

# The tool name of the pack entry that states the status. Named like the
# sandbox views so the console files it with them.
STATUS_TOOL = "sandbox_status"

_NO_REPORT = (
    "No sandbox ran on this run: there is no sandbox report, so nothing here was "
    "observed by executing the sample."
)
_STAND_IN = (
    "No sandbox ran for this sample: the mock sandbox has no recorded report for it "
    "and answered with an empty stand-in, so nothing here was observed by executing "
    "the sample."
)
_FIXTURE = (
    "The sandbox report is a recorded fixture the mock sandbox returned for this "
    "sample, not a live detonation in this run."
)


@dataclass(frozen=True)
class SandboxStatus:
    """What a run's sandbox report is, and the one sentence that says so."""

    status: str
    statement: str

    def as_entry(self) -> dict[str, str]:
        """The ledger entry's answer: the status word and the sentence."""
        return {"sandbox": self.status, "statement": self.statement}


def sandbox_status(report: Any) -> SandboxStatus:
    """What ``report`` — the run's CAPE-shaped sandbox report, or ``None`` — is."""
    if not isinstance(report, dict) or not report:
        return SandboxStatus(NOT_RUN, _NO_REPORT)
    if report.get(SYNTHETIC_KEY):
        return SandboxStatus(NOT_RUN, _STAND_IN)
    if report.get(FIXTURE_KEY):
        return SandboxStatus(RECORDED_FIXTURE, _FIXTURE)
    return SandboxStatus(OBSERVED, "")


def observed_report(report: Any) -> dict[str, Any] | None:
    """``report`` when a sandbox produced it, ``None`` when none ran."""
    if sandbox_status(report).status == NOT_RUN:
        return None
    return report if isinstance(report, dict) else None
