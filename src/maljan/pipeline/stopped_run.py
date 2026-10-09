"""What a run stopped part-way keeps: its run summary and a partial report.

A job is stopped for three reasons other than finishing: its job timeout
(``core.job_timeout``) was reached, the operator cancelled it, or the worker
running it shut down. Whatever the run had produced by then is kept, and
nothing is made up for what it had not:

* The state is the one after the last complete graph step
  (``MaljanApp.latest_state``), or the state the report was built from when
  the report node had already returned (``MaljanApp.built_report``).
* The run summary is the judge's when the judge ran, otherwise one built here
  from the same state with the same builder; either way its token usage,
  models, spend and stage rollup are read again at the stop, so the calls made
  after the judge (the report's narrative and composer sections) are counted.
* The report is, in order of preference, the report the report node returned,
  the report it was building when the run stopped (the deterministic report,
  the narrative on it if that round ended, and every composer section already
  written into it), or the deterministic report built here from the state. A
  stage that did not run is said not to have run: a report built here says
  that no summary was written and, when no judge ran, that no verdict was
  reached.

Every function here is total: a stopped run that could not keep its partial
report must still be recorded as stopped.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any, cast

from maljan.core.logger import logger

if TYPE_CHECKING:
    from maljan.pipeline.state import AnalysisState

# What a report built here says when no judge ran: the report model's verdict
# field holds a value whatever happens, and this is what the reader is told
# about it. Also written into the run summary's degradation reasons.
NO_VERDICT_REASON = (
    "verdict not assessed: the run was stopped before its verdict stage ran, so no "
    "verdict was reached; the verdict field holds the report's placeholder and is not "
    "a finding about the sample"
)

# The run summary's and the stored report's ``final_decision`` when no judge
# ran: the word every surface already reads as "no verdict".
NO_VERDICT_DECISION = "Unknown"


def stopped_state(app: Any) -> dict[str, Any]:
    """The pipeline state a stopped run had produced, or an empty dict.

    The report node's state when it had returned (a superset of every step
    before it), otherwise the state after the last complete step.
    """
    built = getattr(app, "built_report", None)
    if isinstance(built, dict) and built:
        return dict(built)
    latest = getattr(app, "latest_state", None)
    return dict(latest) if isinstance(latest, dict) else {}


def judge_ran(state: dict[str, Any]) -> bool:
    """Whether the verdict stage wrote a decision into ``state``."""
    return bool(state.get("final_decision"))


def _degraded(summary: dict[str, Any], note: str) -> dict[str, Any]:
    out = dict(summary)
    out["degraded_mode"] = True
    reasons = out.get("degradation_reasons")
    out["degradation_reasons"] = [
        *(reasons if isinstance(reasons, list) else []),
        note,
    ]
    return out


def _built_summary(state: dict[str, Any], container: Any) -> dict[str, Any]:
    """A run summary from the state, for a run stopped before its judge built one.

    The judge node's own builder, given what the state holds; a part the state
    has nothing for is left as the builder leaves it.
    """
    from maljan.analysis.run_summary import RunSummaryBuilder, tool_asks_of
    from maljan.pipeline import nodes
    from maljan.pipeline.validation import validation_metrics

    started = float(state.get("run_started_at") or 0.0) or time.time()
    builder = RunSummaryBuilder(start_time=started)
    builder.set_sample(str(state.get("file_hash") or ""), state.get("file_name"))
    builder.set_verdict(str(state.get("final_decision") or NO_VERDICT_DECISION), 0)

    def _part(name: str, apply: Any) -> None:
        try:
            apply()
        except Exception as exc:  # noqa: BLE001 — one part is never worth the summary
            logger.debug(
                "stopped run: the run summary's %s was not recorded (%s).", name, type(exc).__name__
            )

    def _negotiation() -> None:
        max_iters, sycophancy_check = nodes.debate_options(container)
        builder.set_negotiation(
            {
                "confidence_history": state.get("confidence_history") or [],
                "iteration_count": state.get("iteration_count", 0),
                "is_consensus": state.get("is_consensus", False),
                "consensus_applicable": state.get("consensus_applicable", True),
                "sycophancy_detected": state.get("sycophancy_detected", False),
                "discussion_history": state.get("discussion_history") or [],
                "revision_rounds": state.get("revision_rounds") or [],
                "dropped_claims": state.get("dropped_claims") or [],
            },
            max_iterations=max_iters,
            sycophancy_check=sycophancy_check,
        )

    def _validation() -> None:
        unresolved = [
            (name, violation)
            for name, entries in (state.get("validation_findings") or {}).items()
            for violation in nodes._violations_from_rows(entries)
        ]
        builder.set_validation(
            validation_metrics(
                int(state.get("validation_retries") or 0),
                unresolved,
                dict(state.get("validation_fed_back") or {}),
                not_run=sorted(str(x) for x in state.get("validation_not_run") or []),
                unparsed_answers=list(state.get("validation_unparsed_answers") or []),
            )
        )

    def _profile() -> None:
        keys = list(container.analyst_keys())
        builder.set_profile(
            container.config.agents.profile,
            keys,
            [k for k in keys if k not in nodes.BUILTIN_AGENTS],
            analyst_mode=nodes._analyst_mode_record(container),
        )

    _part("negotiation", _negotiation)
    _part("analysts", lambda: builder.set_isr_stats(dict(state.get("isr_reports") or {})))
    _part("validation", _validation)
    _part(
        "degradation",
        lambda: builder.set_degraded_mode(
            bool(state.get("degraded_mode")), list(state.get("degradation_reasons") or [])
        ),
    )
    _part("profile", _profile)
    _part(
        "stages",
        lambda: builder.set_stages(nodes.stage_rollup(container, cast("AnalysisState", state))),
    )
    _part("server rests", lambda: builder.set_server_rests(container.server_rests()))
    _part("truncation", lambda: builder.set_truncation(nodes._truncation_snapshot(container)))
    _part("triage", lambda: builder.set_triage(state.get("triage_facts") or {}))
    _part("sandbox", lambda: builder.set_sandbox(state.get("sandbox_report")))
    _part(
        "nudge",
        lambda: builder.set_nudge(
            state.get("nudge_retry_modes") or {},
            no_tool_call=tool_asks_of(state.get("budget_records") or {}),
        ),
    )
    _part("budget", lambda: builder.set_budget(state.get("budget_records") or {}))
    _part("tool latency", lambda: builder.set_tool_latency(state.get("evidence_ledger") or []))
    return builder.build().to_dict()


def stopped_run_summary(state: dict[str, Any], container: Any, *, note: str) -> dict[str, Any]:
    """The run summary of a stopped run, as of the stop, with ``note`` among its reasons.

    The judge's summary when the judge built one, otherwise one built from the
    state. What the run spent, which models answered, the spend against the
    ceiling, the measured generation rates, the stage rollup and the elapsed
    time are read again here: everything after the judge's snapshot happened
    too. Never raises; a summary that cannot be built at all is the note alone.
    """
    from maljan.analysis.run_summary import spend_blocks
    from maljan.pipeline import nodes

    try:
        existing = state.get("run_summary")
        summary = (
            dict(existing)
            if isinstance(existing, dict) and existing
            else _built_summary(state, container)
        )
    except Exception as exc:  # noqa: BLE001 — a stopped run is recorded whatever happens
        logger.warning("stopped run: the run summary could not be built (%s).", type(exc).__name__)
        summary = {}

    def _part(name: str, apply: Any) -> None:
        try:
            apply()
        except Exception as exc:  # noqa: BLE001 — one part is never worth the summary
            logger.debug(
                "stopped run: the run summary's %s was not read again (%s).",
                name,
                type(exc).__name__,
            )

    def _spent() -> None:
        summary.update(spend_blocks(container.get_token_ledger().snapshot()))
        ceiling = nodes._spend_snapshot(container)
        if ceiling:
            summary["spend"] = ceiling

    def _generation() -> None:
        generation = nodes._generation_snapshot(container)
        if generation and (generation.get("models") or generation.get("timeouts")):
            summary["generation"] = generation

    def _elapsed() -> None:
        started = float(state.get("run_started_at") or 0.0)
        if started:
            summary["elapsed_seconds"] = round(max(0.0, time.time() - started), 3)

    _part("spend", _spent)
    _part("generation", _generation)
    _part(
        "stages",
        lambda: summary.update(
            {"stages": nodes.stage_rollup(container, cast("AnalysisState", state))}
        ),
    )
    _part("elapsed time", _elapsed)
    return _degraded(summary, note)


def _report_dump(report: Any) -> dict[str, Any] | None:
    if isinstance(report, dict):
        return dict(report)
    dump = getattr(report, "model_dump", None)
    if callable(dump):
        try:
            out = dump(mode="json")
        except Exception as exc:  # noqa: BLE001 — an unreadable report is no report
            logger.warning(
                "stopped run: the report in progress could not be read (%s).", type(exc).__name__
            )
            return None
        return out if isinstance(out, dict) else None
    return None


def _deterministic_report(state: dict[str, Any], container: Any) -> dict[str, Any] | None:
    """The deterministic report from the state, for a run stopped before its report node.

    The report node's own builder and inputs, with nothing run that the run
    did not run: no tool is called, no model is asked. No summary is written
    and the report says why; with no judge, it says no verdict was reached.
    """
    from maljan.pipeline import nodes
    from maljan.pipeline.outcome import corrected_reasons
    from maljan.reporting.builder import MalwareReportBuilder
    from maljan.schemas.evidence import LedgerEntry

    assessment = None
    judge_bundle = state.get("stix_output") or {}
    if isinstance(judge_bundle, dict) and judge_bundle.get("x_maljan_assessment"):
        try:
            from maljan.schemas.judgement import JudgeAssessment

            assessment = JudgeAssessment.model_validate(judge_bundle["x_maljan_assessment"])
        except Exception as exc:  # noqa: BLE001 — an unreadable assessment is "not assessed"
            logger.debug(
                "stopped run: the judge's assessment could not be read (%s).", type(exc).__name__
            )
    fallback = state.get("verdict_fallback") or None
    ledger: list[Any] = []
    for row in state.get("evidence_ledger") or []:
        try:
            ledger.append(LedgerEntry.model_validate(row))
        except Exception:  # noqa: BLE001 — one bad row is not a lost report
            continue
    ledger.sort(key=lambda entry: entry.seq)
    reasons = corrected_reasons(state.get("degradation_reasons"), ledger)
    if not judge_ran(state):
        reasons = [*reasons, NO_VERDICT_REASON]
    builder = MalwareReportBuilder(
        file_hash=state.get("file_hash"),
        file_name=state.get("file_name"),
        sample_path=state.get("sample_path"),
        sandbox_report=state.get("sandbox_report"),
        reports=state.get("reports"),
        isr_reports=dict(state.get("isr_reports") or {}),
        stix_output=state.get("stix_output"),
        run_summary=state.get("run_summary") or {},
        discussion_history=[
            arg.model_dump() if hasattr(arg, "model_dump") else dict(arg)
            for arg in (state.get("discussion_history") or [])
        ],
        final_decision=str(state.get("final_decision") or ""),
        overall_confidence=nodes._overall_confidence(
            assessment, judged=nodes.the_judge_stated_the_verdict(fallback)
        )
        if judge_ran(state)
        else None,
        judge_assessment=assessment,
        malware_category=getattr(assessment, "malware_category", None),
        degraded_mode=True,
        degradation_reasons=reasons,
        sample_platform=state.get("platform"),
        sample_file_type=state.get("file_type"),
        evidence_ledger=ledger,
    )
    report = builder.build_deterministic()
    report = MalwareReportBuilder.apply_fallback_narrative(
        report, "the run was stopped before its report stage wrote one"
    )
    return _report_dump(report)


def partial_report(state: dict[str, Any], container: Any, *, note: str) -> dict[str, Any] | None:
    """The stopped run's report, marked partial with ``note``, or ``None``.

    The report the report node returned, else the one it was building, else
    the deterministic report from the state. ``None`` only when none of the
    three could be had; the run summary is kept either way.
    """
    report: dict[str, Any] | None = None
    if isinstance(state.get("malware_report"), dict) and state["malware_report"]:
        report = dict(state["malware_report"])
    if report is None:
        report = _report_dump(getattr(container, "report_in_progress", None))
    if report is None:
        try:
            report = _deterministic_report(state, container)
        except Exception as exc:  # noqa: BLE001 — the summary is kept whatever happens
            logger.warning(
                "stopped run: no partial report could be built from the state (%s).",
                type(exc).__name__,
            )
            return None
    if report is None:
        return None
    report["degraded_mode"] = True
    reasons = report.get("degradation_reasons")
    report["degradation_reasons"] = [*(reasons if isinstance(reasons, list) else []), note]
    return report
