"""Whether a sandbox ran, read once, in the words every reader of the report uses.

A run's sandbox report is one of three things, and their sections read alike.
A live sandbox's report is an observation, empty or not. The mock sandbox's
recorded fixture is an observation too, but of some earlier detonation, not of
this run. And when the mock has no fixture for the sample it answers with an
empty stand-in, marked ``synthetic``, which is no observation at all.

The pack, the in-process sandbox tools, the degradation reasons, the run
summary and the report all ask this module rather than the report's keys, so
each says the same true thing: no sandbox ran, or the report is a recorded
fixture and not a live detonation, or nothing is added to what a sandbox
observed.

A live or attached report whose sandbox names a target SHA-256 that is not
the sample's is still an observation, and reads as one everywhere; the run marks it before
the graph runs (``app.MaljanApp``), and its status carries the sentence that
says so, for the pack to hand the analysts and the judge. What it touches is
theirs to decide.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

# The marks are the document's (``schemas.sandbox_document.PLATFORM_MARKS``):
# the mock sandbox's stand-in carries ``SYNTHETIC_KEY`` (``MockSandboxClient``),
# a report it read from a fixture file ``FIXTURE_KEY``, and a live or attached
# report whose sandbox names another target than the sample ``TARGET_KEY`` (set by the run,
# ``app.MaljanApp._tell_the_target``). Named here as every reader of the status
# has always imported them.
from maljan.schemas.sandbox_document import FIXTURE_KEY, SYNTHETIC_KEY, TARGET_KEY

__all__ = ["FIXTURE_KEY", "SYNTHETIC_KEY", "TARGET_KEY"]

# The three answers. Words rather than codes because they are written into
# the ledger entry and the run summary, where a reader meets them as they are.
NOT_RUN = "not run"
RECORDED_FIXTURE = "recorded fixture"
OBSERVED = "observed"

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
    """What ``report`` — the run's sandbox report document, or ``None`` — is."""
    if not isinstance(report, dict) or not report:
        return SandboxStatus(NOT_RUN, _NO_REPORT)
    if report.get(SYNTHETIC_KEY):
        return SandboxStatus(NOT_RUN, _STAND_IN)
    if report.get(FIXTURE_KEY):
        return SandboxStatus(RECORDED_FIXTURE, _FIXTURE)
    return SandboxStatus(OBSERVED, _target_statement(report.get(TARGET_KEY)))


def target_mark(record: Mapping[str, Any]) -> dict[str, Any]:
    """The mark a report carries for ``record``, a ``sandbox_target_record``: its two hashes."""
    mark: dict[str, Any] = {
        "expected_sha256": str(record.get("expected_sha256") or ""),
        "sandbox_sha256": str(record.get("sandbox_sha256") or ""),
    }
    if record.get("sandbox_sha256_valid") is False:
        mark["sandbox_sha256_valid"] = False
    return mark


def _target_statement(mark: Any) -> str:
    """The sentences of a report's target mark; ``""`` with none.

    Both values are kept again as the record keeps a sandbox's value, whoever
    wrote the mark: a value that is not a SHA-256 is one bounded line. Each is
    written as a code span (:func:`_code`), so the sandbox's text reads as a
    value in the pack and in the report, never as their markup.
    """
    from maljan.analysis.sample_integrity import (
        kept_hash,
        sandbox_target_lines,
        sandbox_target_record,
    )

    if not isinstance(mark, Mapping):
        return ""
    expected = kept_hash(str(mark.get("expected_sha256") or ""))
    record = sandbox_target_record(expected, mark.get("sandbox_sha256"))
    if record is None and expected and mark.get("sandbox_sha256_valid") is False:
        # A target that held no printable character: kept empty, still said.
        record = {"expected_sha256": expected, "sandbox_sha256": "", "sandbox_sha256_valid": False}
    return " ".join(sandbox_target_lines(record, _code))


def _code(text: str) -> str:
    """``text`` as one code span, fenced longer than any backtick run inside it.

    Its ledger ids, run-state markers and chat-template control tokens are
    written out first, as a sample's text is wherever a line holds it.
    """
    from maljan.utils.written_forms import sample_written_out, template_tokens_written_out

    # A chat template's control token is written out as a prompt hint writes it.
    written = template_tokens_written_out(sample_written_out(text))
    longest = max((len(run) for run in re.findall(r"`+", written)), default=0)
    if not longest:
        return f"`{written}`"
    fence = "`" * (longest + 1)
    return f"{fence} {written} {fence}"


def observed_report(report: Any) -> dict[str, Any] | None:
    """``report`` when a sandbox produced it, ``None`` when none ran."""
    if sandbox_status(report).status == NOT_RUN:
        return None
    return report if isinstance(report, dict) else None
