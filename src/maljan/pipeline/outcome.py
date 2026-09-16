"""What a run amounts to when the evidence for it is thin or absent.

Two readings, and the difference between them is the whole module. A run with
some evidence and a judge that answered is an *analysis*, however degraded: the
verdict is the judge's and the degradation reasons say what it was missing. A
run with no evidence at all, or with no analyst and no judge, is not a thin
analysis — it is an absent one, and reporting it as an ordinary result is a
false negative dressed as a finding.

Both readings live here rather than in the node that happens to notice them,
because the report builder and the worker have to agree with the judge node
about what the run was.
"""

from __future__ import annotations

import re
from typing import Any

# What the run summary and the report header say about a verdict drawn from an
# empty run. It is a degradation reason and not an override: the judge made no
# claim that this replaces, because there was nothing for it to claim.
INCONCLUSIVE_REASON = "inconclusive: no analysis was performed"

# The verdict such a run carries. Never "Benign": an empty findings set means
# nothing was looked at, and the two are indistinguishable from the bundle
# alone — which is how a run whose every analyst failed came to be reported as
# benign at 0.10 confidence.
INCONCLUSIVE_VERDICT = "Suspicious"

# How ``judge_node`` records a judge that raised rather than answered.
JUDGE_FAILED_PREFIX = "[ERROR] Judge failed"

# How an analyst node records one that raised rather than answered.
ANALYST_FAILED_PREFIX = "[ERROR]"

# The exception class and, where the provider gave one, the HTTP status out of
# a recorded failure. Both are the provider's own words about what went wrong
# and neither can carry a credential.
_FAILURE_CLASS_RE = re.compile(r"\((?P<name>[A-Za-z_][A-Za-z0-9_.]*)\)")
_STATUS_RE = re.compile(r"\b(?:code|status)[: ]+(?P<status>\d{3})\b", re.IGNORECASE)

# A message that reaches a job row and a browser: one line, bounded.
_MESSAGE_LIMIT = 300


def _one_line(text: str, limit: int = _MESSAGE_LIMIT) -> str:
    """A provider's sentence, made safe to put in a log line or a job row."""
    flattened = " ".join(str(text or "").split())
    return flattened[:limit]


def nothing_was_analysed(evidence_entries: Any, isr_reports: Any) -> bool:
    """Whether the run produced no tool evidence and no analyst claim.

    The two together, because either alone has an innocent reading: an analyst
    can reach a claim from the pre-extracted profile without calling a tool,
    and a tool call can be made by an analyst that then declines to claim
    anything. Neither happening is a run in which nothing was examined.
    """
    if list(evidence_entries or []):
        return False
    values = isr_reports.values() if hasattr(isr_reports, "values") else (isr_reports or ())
    return not any(getattr(isr, "claims", None) for isr in values)


def verdict_for_run(decision: str, *, evidence_entries: Any, isr_reports: Any) -> tuple[str, str]:
    """The verdict to report, and the reason if the run forced it.

    ``("Benign", "")`` for a run that established nothing is the shape this
    exists to prevent: the bundle is empty because nothing was examined, not
    because something was examined and found clean. Every other verdict is the
    judge's and passes through untouched, reason empty.
    """
    if str(decision).strip().lower().startswith("benign") and nothing_was_analysed(
        evidence_entries, isr_reports
    ):
        return INCONCLUSIVE_VERDICT, INCONCLUSIVE_REASON
    return decision, ""


def _analyst_answered(state: Any) -> bool:
    """Whether any analyst produced a report or a claim in this run."""
    reports = (state or {}).get("revised_reports") or {}
    for source in (reports, (state or {}).get("reports") or {}):
        for text in source.values():
            if (
                isinstance(text, str)
                and text.strip()
                and not text.strip().startswith(ANALYST_FAILED_PREFIX)
            ):
                return True
    isrs = (state or {}).get("isr_reports") or {}
    values = isrs.values() if hasattr(isrs, "values") else ()
    return any(getattr(isr, "claims", None) for isr in values)


def _judge_failure(state: Any) -> str:
    """The judge's recorded failure, or ``""`` when the judge answered."""
    report = str((state or {}).get("judge_report") or "")
    return report if report.startswith(JUDGE_FAILED_PREFIX) else ""


def absent_analysis_message(state: Any) -> str:
    """Why this run has nothing to report, or ``""`` when it has something.

    A run in which no analyst answered *and* the judge never answered has not
    produced a degraded analysis; it has produced none. The message names the
    provider's own error class and status so the operator reads "402" rather
    than a verdict, and carries nothing else from the provider's body — a key
    quoted back in an error message is the one way a credential reaches a job
    row.
    """
    failure = _judge_failure(state)
    if not failure or _analyst_answered(state):
        return ""
    name = _FAILURE_CLASS_RE.search(failure)
    status = _STATUS_RE.search(failure)
    detail = name.group("name") if name else "unknown error"
    if status:
        detail = f"{detail} {status.group('status')}"
    return _one_line(
        f"no analysis was produced: every analyst failed and the judge did not answer ({detail})"
    )
