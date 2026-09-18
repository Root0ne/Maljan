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

from maljan.schemas.judgement import VERDICT_VALUES

# What the run summary and the report header say about a verdict drawn from an
# empty run. It is a degradation reason and not an override: the judge made no
# claim that this replaces, because there was nothing for it to claim.
INCONCLUSIVE_REASON = "inconclusive: no analysis was performed"

# The verdict such a run carries. Never "Benign": an empty findings set means
# nothing was looked at, and the two are indistinguishable from the bundle
# alone — which is how a run whose every analyst failed came to be reported as
# benign at 0.10 confidence.
INCONCLUSIVE_VERDICT = "Suspicious"

# The same verdict over a run that did record evidence after the judge read the
# ledger. The evidence-only static provider's passes are collected in the
# report stage, so a run whose only evidence is capa's reached the verdict with
# an empty ledger and was told nothing had been analysed — which the report it
# ships plainly contradicts. The verdict stays where the judge's own answer put
# it; only the sentence is corrected to what actually happened.
NO_CLAIMS_REASON = "inconclusive: no analyst claim was made"

# Both readings of an inconclusive run, for the readers that treat them alike.
INCONCLUSIVE_REASONS: tuple[str, ...] = (INCONCLUSIVE_REASON, NO_CLAIMS_REASON)


def corrected_reasons(reasons: Any, evidence_entries: Any) -> list[str]:
    """The run's degradation reasons, with the empty-run sentence made true.

    Called once the whole ledger is known. A reason claiming no analysis was
    performed, on a run that turns out to carry evidence entries, becomes the
    narrower claim that no analyst claimed anything -- which is what was
    actually observed and what the verdict was drawn from.
    """
    rows = [str(reason) for reason in (reasons or [])]
    if not list(evidence_entries or []):
        return rows
    return [NO_CLAIMS_REASON if reason == INCONCLUSIVE_REASON else reason for reason in rows]


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


def stated_verdict(bundle: Any) -> str:
    """The verdict the judge wrote in its assessment, or ``""``.

    One reading, so that the pipeline, the conflict check and the export all
    take the judge at its word in the same words. A value outside
    :data:`VERDICT_VALUES` is not a verdict this pipeline can act on and reads
    as unstated; ``pipeline.validation`` is where the judge is told so.
    """
    assessment = getattr(bundle, "x_maljan_assessment", None)
    if assessment is None:
        return ""
    written = str(getattr(assessment, "verdict", "") or "").strip()
    for value in VERDICT_VALUES:
        if written.lower() == value.lower():
            return value
    return ""


def stated_confidence(bundle: Any) -> float | None:
    """The judge's own confidence for the verdict it stated, or ``None``.

    ``None`` is the answer for a judge that stated no number, and the report
    prints "not assessed" for it. Nothing else may stand in: a confidence
    averaged from the analysts belongs to the analysts' own claims, and one
    derived from the presence of an object is the object deciding.
    """
    assessment = getattr(bundle, "x_maljan_assessment", None)
    declared = getattr(assessment, "confidence", None) if assessment is not None else None
    if declared is None:
        return None
    try:
        return float(declared)
    except (TypeError, ValueError):
        return None


def decide_from_bundle(bundle: Any) -> str:
    """The verdict a final STIX bundle carries.

    Three readings, in this order, and the order is the whole function.

    A bundle carrying ``x_maljan_fallback_verdict`` was built by this pipeline
    because the judge's answer was not a bundle, and it states its verdict
    rather than implying it through its objects. That statement is read first
    and nothing else is counted: the object set of such a bundle follows the
    decision, so reading it back would only be this function agreeing with
    itself — and when it did not, a judge that timed out produced "Malware".

    Then the judge's own statement, ``x_maljan_assessment.verdict``. A signed,
    clean PuTTY was published as "Malware @ 1.0" over a judge that had rated
    it Informational, categorised it ``legitimate-utility`` and written that
    the assessment confirms it is benign — because the bundle carried a
    ``malware`` object and the object set was read as the answer. The judge
    decides; the objects illustrate the decision.

    The object set is read only for a bundle that states nothing — a stored
    run, or a model that omitted the field, which ``pipeline.validation``
    records as ``verdict.unstated``:
      * a ``malware`` object marks the sample malicious.
      * an ``indicator``/``attack-pattern``/``relationship`` set with no
        ``malware`` object but suspicious confidence is "Suspicious".
      * an explicitly empty findings set (no indicators, no attack patterns,
        no malware) maps to "Benign", which :func:`verdict_for_run` then reads
        against what the run actually examined.

    Here rather than in the node that used to hold it, because the validator
    that asks whether the judge's own severity agrees with its verdict has to
    read the verdict the same way the pipeline does.
    """
    fallback = getattr(bundle, "x_maljan_fallback_verdict", None)
    if fallback is not None:
        decision = str(getattr(fallback, "decision", "") or "").strip()
        return decision or INCONCLUSIVE_VERDICT

    stated = stated_verdict(bundle)
    if stated:
        return stated

    has_malware = False
    has_suspicious_indicator = False
    for obj in getattr(bundle, "objects", None) or []:
        obj_type = getattr(obj, "type", "")
        if obj_type == "malware":
            has_malware = True
            break
        if obj_type in {"indicator", "attack-pattern", "relationship"}:
            has_suspicious_indicator = True

    if has_malware:
        return "Malware"
    if has_suspicious_indicator:
        return "Suspicious"
    return "Benign"


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


def _judge_answered(state: Any) -> bool:
    """Whether a verdict stage ran and produced something.

    The question is whether there is a verdict, not whether a failure was
    recorded. A verdict stage carrying a ``when`` that declines never enters
    ``judge_node``, so nothing writes the failure string and nothing writes a
    decision either -- and a run with no analyst behind it would then take the
    ordinary completion path and publish a report for an analysis nobody
    performed.
    """
    state = state or {}
    if _judge_failure(state):
        return False
    return bool(str(state.get("judge_report") or "").strip()) or bool(
        str(state.get("final_decision") or "").strip()
    )


def absent_analysis_message(state: Any) -> str:
    """Why this run has nothing to report, or ``""`` when it has something.

    A run in which no analyst answered *and* the judge never answered has not
    produced a degraded analysis; it has produced none. A judge that raised and
    a judge that never ran are the same fact here, and only the first has a
    provider to name: the message then carries that provider's own error class
    and status so the operator reads "402" rather than a verdict, and nothing
    else from the provider's body — a key quoted back in an error message is
    the one way a credential reaches a job row.
    """
    if _judge_answered(state) or _analyst_answered(state):
        return ""
    if str((state or {}).get("report_error") or "").strip():
        # The report stage raised and said what raised. That run fails too,
        # through the check that owns the message: naming the absence here
        # would replace a diagnosis with a summary of it.
        return ""
    failure = _judge_failure(state)
    if not failure:
        return _one_line(
            "no analysis was produced: every analyst failed and no verdict was produced"
        )
    name = _FAILURE_CLASS_RE.search(failure)
    status = _STATUS_RE.search(failure)
    detail = name.group("name") if name else "unknown error"
    if status:
        detail = f"{detail} {status.group('status')}"
    return _one_line(
        f"no analysis was produced: every analyst failed and the judge did not answer ({detail})"
    )
