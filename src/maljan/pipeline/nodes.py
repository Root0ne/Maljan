"""Generic node factories for the LangGraph pipeline.

Each factory returns a node function bound to a specific agent name and the
shared ServiceContainer. The factories work with any agent in the registry —
no per-agent branching exists.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import threading
import time
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast

from maljan.agents.delegation import REFUSAL_PREFIX
from maljan.agents.evidence_recorder import EvidenceRecorder
from maljan.agents.judge_agent import (
    VERDICT_FALLBACK_CODE,
    VERDICT_FALLBACK_REASON,
    VERDICT_TIMEOUT_CODE,
    VERDICT_TIMEOUT_REASON,
)
from maljan.agents.run_evidence_corpus import (
    NO_CORPUS,
    CorpusState,
    both_searched,
    parts_of,
    state_of,
)
from maljan.analysis.corroboration import corroboration_row
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import BUILTIN_AGENTS, JUDGE_AGENT_KEY, PROMPT_ROLES, ReportingConfig
from maljan.core.container import ServiceContainer
from maljan.core.exceptions import AnalystError, LLMError
from maljan.core.logger import logger
from maljan.memory.long_term_memory import build_stored_case
from maljan.pipeline.conditions import (
    ConditionError,
    StageContext,
    StageResult,
    TriageFacts,
    evaluate,
)
from maljan.pipeline.events import (
    claims_to_payload,
    describe_exception,
    emit,
    emit_agent_message,
    emit_stage_ended_at_cap,
    summarize_claims,
)
from maljan.pipeline.evidence_summary import collect as collect_technique_sources
from maljan.pipeline.evidence_summary import summarise, technique_evidence
from maljan.pipeline.mediation_models import consensus_applies
from maljan.pipeline.outcome import (
    VERDICT_READ_FALLBACK,
    corrected_reasons,
    decide_from_bundle,
    normalise_verdict,
    unrecognised_verdict_reason,
    verdict_for_run,
    verdict_reading,
)
from maljan.pipeline.run_state import render_run_state
from maljan.pipeline.sandbox_status import NOT_RUN as SANDBOX_NOT_RUN
from maljan.pipeline.sandbox_status import sandbox_status
from maljan.pipeline.state import AgentArgument, AnalysisState, _merge_stage_results
from maljan.pipeline.sycophancy_detector import build_revision_directive, detect_sycophancy
from maljan.pipeline.triage_pack import (
    NOT_RUN_PREFIX,
    PIPELINE,
    CapaSettings,
    FlossSettings,
    PackInputs,
    failure_reason,
    pack_block,
    pack_entries,
    reason_sentence,
    rules_already_recorded,
    run_is_degraded,
    run_pack,
)
from maljan.pipeline.validation import (
    VALIDITY_CODE,
    ValidationTally,
    Violation,
    corroboration,
    corroboration_sources,
    not_run_sentence,
    partial_grounding_reason,
    technique_check_note,
    ungrounded_technique_note,
    validation_metrics,
    validity_check_available,
)
from maljan.reporting.ledger_report import section_is_grounded
from maljan.schemas.evidence import LedgerEntry, apply_budget
from maljan.schemas.isr_models import AgentISR
from maljan.schemas.stix_models import Bundle
from maljan.schemas.tool_evidence import trim_output

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Wall-clock ceiling for the single narrative LLM round in the report node.
# Generous — the deterministic report is already built by then and the prose is
# the last thing standing between a finished analysis and the operator — but
# finite, which it was not. See the call site for the 30-minute silence this
# bounds.
_NARRATIVE_TIMEOUT_SECONDS = 600


def _restart_reporter(llm: Any, seconds: Any, container: Any) -> None:
    """Start the reporter's model list for one round, against that round's clock. Never raises."""
    try:
        from maljan.llm.fallback import restart_models

        share = getattr(getattr(container.config, "llm", None), "fallback_turn_share", None)
        restart_models(
            llm,
            loop_seconds=float(seconds) if isinstance(seconds, int | float) else None,
            share=float(share) if isinstance(share, int | float) else None,
        )
    except Exception as exc:  # noqa: BLE001 — a restart never costs the report
        logger.debug("report_node: the reporter's model list was not restarted (%s).", exc)


# What the run summary calls a judge annotation whose technique did not
# survive validation. Its own code: the technique's own rejection is recorded
# under its own, and this row says what that rejection cost the export.
UNLINKED_TECHNIQUE_CODE = "stix.unlinked_technique"


def _empty_isr(agent_name: str, revision_round: int = 0) -> AgentISR:
    """Build an empty placeholder ISR (e.g. for mock or error paths)."""
    return AgentISR(
        agent_id=agent_name,
        domain=agent_name,
        claims=[],
        dissent_items=[],
        revision_round=revision_round,
    )


def _note_unlinked_techniques(report: Any, unlinked: Sequence[tuple[str, int]]) -> None:
    """Record the judge annotations that went with a rejected technique.

    One row per technique, under a code of its own — the technique's own
    rejection is recorded under ``attck.unknown_id`` or
    ``stix.unknown_technique``, and this says what that rejection cost the
    export — so a reader of ``run_summary.validation`` finds the annotation's
    fate beside the reason the technique was dropped.
    """
    _note_export_findings(
        report,
        [
            (
                UNLINKED_TECHNIQUE_CODE,
                f"{count} judge relationship(s) about {technique} were not published: "
                "the technique is not in the report's validated list.",
            )
            for technique, count in unlinked
        ],
    )


def _note_export_findings(report: Any, rows: Sequence[tuple[str, str]]) -> None:
    """Record what the STIX export left out, where the run's findings are.

    The export declines to carry an object that contradicts the verdict the
    run publishes — a malware object under a Benign one — or that no consumer
    could act on, such as a URL whose host is a string sweep's cut-off. The
    object is never edited and the judge's own bundle keeps it; these rows are
    how a reader of ``run_summary.validation`` learns it is not in the export.
    """
    if not rows:
        return
    summary = dict(getattr(report, "run_summary", None) or {})
    validation = dict(summary.get("validation") or {})
    unresolved = [dict(row) for row in validation.get("unresolved") or []]
    by_code = dict(validation.get("by_code") or {})
    for row in rows:
        code, message = row
        # Who wrote the object down: the judge for its own objects, the source
        # of a network-block row for one of those.
        agent = str(getattr(row, "by", "") or JUDGE_AGENT_KEY)
        unresolved.append({"agent": agent, "code": code, "message": message})
        by_code[code] = by_code.get(code, 0) + 1
    validation["unresolved"] = unresolved
    validation["by_code"] = dict(sorted(by_code.items()))
    validation.setdefault("retries", int(validation.get("retries") or 0))
    validation.setdefault("not_run", list(validation.get("not_run") or []))
    summary["validation"] = validation
    report.run_summary = summary


def promoted_asks(agent: Any, own: AgentISR | None = None) -> dict[str, AgentISR]:
    """The answered asks a stage takes when the caller's own report is empty.

    A lead's report is the only channel its stage has, so a lead that produced
    nothing — its loop hit the wall-clock cap, or it failed outright — used to
    take every answer it had already received down with it: one audited chunk
    spent 1,830 s, collected six answered asks and 52 ledger entries, and
    merged zero claims. The specialists' own ISRs are model output of this
    team, they carry the agent that produced them, and here they stand in for
    the report the lead never wrote. Empty when the lead did answer: nothing is
    promoted beside a report that exists.

    Every answered ask, in the order the lead asked it. A lead asks the same
    specialist about the imports, then the strings, then the packer, and those
    are three answers, not one: keyed by agent alone the second and third were
    dropped, which is the loss this exists to stop. The key carries the agent
    and the ask's number (``deep_static#2``), so nothing collapses and nothing
    collides with a stage agent's own key either.
    """
    if own is not None and getattr(own, "claims", None):
        return {}
    answers = getattr(agent, "answered_asks", None)
    if not callable(answers):
        return {}
    out: dict[str, AgentISR] = {}
    asked: dict[str, int] = {}
    for isr in answers() or []:
        key = str(getattr(isr, "agent_id", "") or "").strip()
        if not key or not getattr(isr, "claims", None):
            continue
        asked[key] = asked.get(key, 0) + 1
        out[f"{key}#{asked[key]}"] = isr
    if out:
        logger.warning(
            "The lead produced no claims; promoting %d answered ask(s) into the stage: %s.",
            len(out),
            ", ".join(out),
        )
    return out


# The file-loader placeholder for a missing per-sample fixture
# ("No static data available for sample <sha>."). Local copy of the
# placeholder pattern from static_analyst to avoid a nodes->agents import edge.
_STATIC_PLACEHOLDER_RE = re.compile(r"^\s*no\s+\w+\s+data\s+available\b", re.IGNORECASE)


def _is_placeholder_only(chunks: list, role: str = "") -> bool:
    """True when the loader produced nothing but its "no data" sentence.

    The graceful no-data path below was unreachable, and had been since it was
    written. ``file_loader`` does not return an empty result when a sample has
    no data for a layer — it returns the *string* ``"No dynamic data available
    for sample <sha>."``, which is truthy, chunks into exactly one chunk, and
    sails past ``if not chunks``. So the pipeline paid for a full MCP
    connection attempt and an LLM call to analyse that one sentence, and the
    network analyst dutifully reported it back as its sole "evidence-backed
    claim" — into the transcript, the report and the UI.

    Two placements are deliberate and both are load-bearing:

    * **After** the static augmentation block, never before. Static's real head
      chunk is *synthesized* because the loader returned this placeholder, so
      matching earlier would disable the static analyst on every live run.
    * **Never for static at all**, even after augmentation. When the sample
      cannot be mirrored for the Ghidra container ``static_sample_path`` stays
      ``None``, augmentation returns the placeholder untouched, and the static
      analyst is *supposed* to fall back to a metadata-only prompt — an
      intended degraded path, not an absence of data. Skipping it here would
      silently delete the primary analyst on exactly the runs that most need
      whatever it can still say.
    * **Never for generic either**, live-fix L1 (2026-09-06). A ``generic``
      agent's input is now built the same way (see ``make_analyst_node``'s
      generic branch): the static sample context — file path plus
      sample-profile text — always exists because the sample itself always
      does, even on the runs where the sandbox carries no report at all. That
      context can still be the bare placeholder when the sample could not be
      mirrored for a provider, which is the same degraded-but-intentional
      path static falls back to, not an absence of data.
    """
    if role in SAMPLE_FED_ROLES or len(chunks) != 1:
        return False
    content = getattr(chunks[0], "content", "") or ""
    return bool(_STATIC_PLACEHOLDER_RE.match(content.strip()))


# The reason a sandbox-fed analyst is skipped when nothing was detonated.
SYNTHETIC_SANDBOX_REASON = "no sandbox fixture for this sample"

# The roles whose input is the sample itself rather than the sandbox report:
# the static analyst, and the two roles that are a prompt over the sample and
# whatever tools the definition gives them. These get the sample path pinned
# and spliced into their first chunk; the others read a report.
SAMPLE_FED_ROLES: tuple[str, ...] = ("static", *PROMPT_ROLES)


def _sandbox_report_is_synthetic(state: AnalysisState) -> bool:
    """True when the sandbox report stands in for a run that never happened.

    The mock provider answers with a structurally valid, entirely empty report
    when it has no fixture for the sample. Read as data that is exactly a
    detonation that did nothing, and the dynamic and network analysts each
    wrote half a dozen claims at confidence 1.00 about it. A real run with no
    behaviour is not synthetic and is analysed as before.
    """
    report = state.get("sandbox_report")
    return isinstance(report, dict) and bool(report.get("synthetic"))


def sandbox_degradation_reason(report: Any) -> str | None:
    """The degradation reason a run whose sandbox never ran carries, or ``None``.

    No report at all keeps the reason it always had. The mock sandbox's empty
    stand-in is the same absence, said with its cause; a report with contents,
    a recorded fixture included, carries none.
    """
    if not isinstance(report, dict) or not report:
        return "no sandbox report (dynamic detonation unavailable) — static-only evidence"
    if sandbox_status(report).status == SANDBOX_NOT_RUN:
        return (
            "no sandbox ran (the mock sandbox has no recorded report for this sample) "
            "— static-only evidence"
        )
    return None


def _sandbox_fed(role: str) -> bool:
    """Whether this role's input is the sandbox report rather than the sample."""
    return role not in SAMPLE_FED_ROLES


def _tools_that_were_shortened(ledger: Any) -> set[str]:
    """The tools whose answers reached the evidence corpus with rows missing.

    Read off the stored document rather than off a counter: the shortener puts
    its own map into the answer under a reserved key, and that is the one thing
    that says *this* answer is partial. A ledger entry with no parsed document
    cannot have been shortened — shortening is what keeps an answer parseable.
    """
    from maljan.agents.output_shortening import our_key_in

    found: set[str] = set()
    for entry in ledger or ():
        structured = getattr(entry, "structured", None)
        if not isinstance(structured, dict):
            continue
        try:
            if our_key_in(structured):
                found.add(str(getattr(entry, "tool", "") or "").strip())
        except Exception:  # noqa: BLE001 — a feedback sentence is never worth a run
            continue
    found.discard("")
    return found


def _what_the_run_saw(container: Any, ledger: Any) -> tuple[list[str], CorpusState]:
    """The tool answers a grounding check may search, and how whole they are.

    The run's own in-memory corpus first: it holds every answer as the model
    received it, which is the only record that can answer "did a tool in this
    run produce this value". It is consulted whenever it exists and has
    anything to say — either it kept something, or it says it kept less than
    the run produced. Asking it only when it held something threw away the
    verdict of a corpus that kept *nothing*, which is precisely what an
    operator gets by setting the ceiling to zero, and the check then fell back
    to the stored ledger and was told the evidence was whole.

    The stored entries are the fallback — a report rebuilt later, a run resumed
    in another process — and a fallback is never whole on its own: any of those
    entries may have been blanked by the byte budget after the model read it,
    and there is no record of what a corpus that is gone would have held. So
    what the check is told is the **conjunction** of the sources it searched:
    the fallback's own count of blanked entries, and the state of the corpus it
    fell back from, which for a corpus that does not exist is partial by
    construction.
    """
    corpus = None
    try:
        corpus = container.get_evidence_corpus()
    except Exception:  # noqa: BLE001 — a container without one is the fallback
        corpus = None
    corpus_state = state_of(corpus) if corpus is not None else NO_CORPUS
    if corpus is not None and (len(corpus) or corpus_state.partial):
        return list(parts_of(corpus)), corpus_state

    entries = list(ledger or [])
    blanked = [e for e in entries if getattr(e, "truncated", False) and not e.output]
    stored = CorpusState(
        complete=not blanked,
        missing_answers=len(blanked),
        missing_tools=tuple(sorted({str(getattr(e, "tool", "") or "") for e in blanked} - {""})),
    )
    return [e.output for e in entries if e.output], both_searched(corpus_state, stored)


def _report_entry_texts(container: Any, ledger: Any) -> Any:
    """Each ledger entry's text for the report rounds, or ``None`` when none can be read.

    The run's corpus first, which holds every answer as the model received it,
    and the stored output where the corpus kept nothing. Never raises: without
    it the rounds judge no citation against an entry, which is what they did
    before.
    """
    try:
        from maljan.pipeline.validation import EntryTexts

        try:
            corpus = container.get_evidence_corpus()
        except Exception:  # noqa: BLE001 — the stored outputs are the fallback
            corpus = None
        return EntryTexts.from_ledger(list(ledger or []), corpus)
    except Exception as exc:  # noqa: BLE001
        logger.debug("report_node: entry texts not read (%s).", exc)
        return None


def _violations_from_rows(rows: Any) -> list[Violation]:
    """Rebuild the violations an analyst node put on the state channel."""
    out: list[Violation] = []
    for row in rows or []:
        if isinstance(row, dict) and row.get("code"):
            out.append(
                Violation(
                    code=str(row.get("code")),
                    message=str(row.get("message") or ""),
                    path=str(row.get("path") or ""),
                    # A row that crossed the state channel keeps whether
                    # anything may act on it; rebuilt without the flag, an
                    # advisory absence would come back as a reason to drop.
                    advisory=bool(row.get("advisory")),
                )
            )
    return out


def _judge_budget(container: Any) -> dict[str, Any]:
    """The judges' budget rows, drained wherever their ledger is drained.

    Every path that drains one drains the other: a meter that is read on one
    of them and not the other reports a loop that made calls and spent
    nothing.
    """
    try:
        rows = container.drain_all_judge_budget_records()
    except Exception as exc:  # noqa: BLE001 — the meter never breaks a run
        logger.debug("budget records not read for the judges: %s", exc)
        return {}
    return {"budget_records": {"judge": rows}} if rows else {}


def _budget_update(agent: Any, agent_name: str) -> dict[str, Any]:
    """The budget meter's rows for this agent since it was last drained.

    Filed under the agent that ran the loop, not the one that was drained.
    A lead hands over what its specialists spent, and a summary that counted
    those against the lead would say the lead ended at a cap a specialist hit
    and would have no row at all for the specialist. The row names its own
    agent; only a row that does not falls back to the drained key.
    """
    drain = getattr(agent, "drain_budget_records", None)
    if not callable(drain):
        return {}
    try:
        rows = list(drain() or [])
    except Exception as exc:  # noqa: BLE001 — telemetry never breaks a run
        logger.debug("budget records not read for %s: %s", agent_name, exc)
        return {}
    if not rows:
        return {}
    by_agent: dict[str, list[dict[str, Any]]] = {}
    for row in rows:
        whose = str(row.get("agent") or agent_name)
        by_agent.setdefault(whose, []).append(row)
    return {"budget_records": by_agent}


def _nudge_mode(agent: Any) -> str | None:
    """How this agent's last nudge had to be sent, read and cleared in one place."""
    drain = getattr(agent, "drain_nudge_retry_mode", None)
    if drain is None:
        return None
    try:
        mode = drain()
    except Exception as exc:  # noqa: BLE001 — a metric is never worth a lost run
        logger.debug("nudge mode read skipped: %s", exc)
        return None
    return str(mode) if mode else None


def _validation_update(agent: Any, agent_name: str) -> dict[str, Any]:
    """What this analyst was told and did not fix, on the state's channels."""
    drain = getattr(agent, "drain_validation_findings", None)
    if drain is None:
        return {}
    try:
        drained = drain()
    except Exception as exc:  # noqa: BLE001 — a metric is never worth a lost run
        logger.debug("validation findings read skipped for %s: %s", agent_name, exc)
        return {}
    # Unpacked outside the guard above, and the two ways it can be wrong are
    # not the same. An agent that drained the wrong number of values is on an
    # older contract — a mistake in this repository that used to cost that
    # analyst its findings, retries and feedback counts in silence — and is
    # said out loud. Anything that is not a drain result at all is a stub or a
    # double, which is not news.
    if not isinstance(drained, tuple | list):
        logger.debug("validation findings for %s are not a drain result.", agent_name)
        return {}
    if len(drained) != 3:
        logger.error(
            "validation findings for %s drained %d value(s), not three; they are dropped.",
            agent_name,
            len(drained),
        )
        return {}
    rows, retries, fed_back = drained
    update: dict[str, Any] = {}
    if rows:
        update["validation_findings"] = {agent_name: rows}
    if retries:
        update["validation_retries"] = retries
    if fed_back:
        update["validation_fed_back"] = dict(fed_back)
    drain_not_run = getattr(agent, "drain_validation_not_run", None)
    if drain_not_run is not None:
        try:
            not_run = [str(code) for code in (drain_not_run() or [])]
        except Exception as exc:  # noqa: BLE001 — a metric is never worth a lost run
            logger.debug("validation not-run read skipped for %s: %s", agent_name, exc)
            not_run = []
        if not_run:
            update["validation_not_run"] = not_run
    return update


def mean_claim_confidence(isrs: Any) -> float | None:
    """The mean confidence of the analysts that produced claims, or ``None``.

    An analyst that was skipped, or that read its data and found nothing to
    say, is excluded rather than counted as a zero. Averaging it in was how a
    run with one analyst at 0.50 and two skipped ones reported 0.167 — a
    number about how many analysts ran, presented as how sure the run was.
    """
    values = [
        float(getattr(isr, "mean_confidence", 0.0) or 0.0)
        for isr in (isrs.values() if isinstance(isrs, dict) else (isrs or []))
        if list(getattr(isr, "claims", None) or [])
    ]
    return sum(values) / len(values) if values else None


def _overall_confidence(assessment: Any, *, judged: bool = True) -> float | None:
    """The judge's confidence in the verdict the judge itself stated, or ``None``.

    One answer, because the verdict has one author. The judge decides the
    verdict and says how sure it is, and that number is the run's. There is no
    second answer to fall to: the analysts' mean is their confidence in their
    own claims and not in a verdict they did not reach, so attaching it to one
    puts a number on a decision nobody rated. ``None`` says the confidence was
    not assessed, which is the fact.

    A number is published only *with* a verdict the judge stated and this
    pipeline could read. On the two other paths the verdict is not the judge's
    — the object set's fail-safe reading, or the inconclusive verdict a word
    nobody can read falls to — and putting the judge's number beside either is
    how a signed utility came to be published as "Malware @ 1.00": that number
    was real and it was about something else.

    ``judged`` is false when the judge never answered and the verdict is the
    pipeline's own fallback, which nobody put a number on either.
    """
    if not judged or normalise_verdict(getattr(assessment, "verdict", None)) is None:
        return None
    declared = getattr(assessment, "confidence", None)
    if declared is None:
        return None
    try:
        return float(declared)
    except (TypeError, ValueError):
        logger.warning("report_node: the judge's confidence %r is not a number.", declared)
        return None


def isr_status(isr: Any) -> str:
    """The lifecycle status one analyst's answer reports for itself.

    The ISR's own ``status`` wins when it set one — an analyst that ended
    without a report knows something ``claims == []`` cannot say — and the
    claim list decides otherwise.
    """
    declared = str(getattr(isr, "status", "") or "").strip()
    if declared:
        return declared
    return "complete" if list(getattr(isr, "claims", None) or []) else "no_data"


def _assessment(bundle: Any) -> Any | None:
    """The judge's own severity / category / family, when it produced one."""
    return getattr(bundle, "x_maljan_assessment", None)


def _assessed_category(bundle: Any) -> str | None:
    assessment = _assessment(bundle)
    value = str(getattr(assessment, "malware_category", "") or "").strip()
    return value or None


def _assessed_family(bundle: Any) -> str | None:
    assessment = _assessment(bundle)
    family = getattr(assessment, "family", None)
    value = str(getattr(family, "name", "") or "").strip()
    return value or None


def _absolute_host_sample_path(state: AnalysisState) -> str:
    """``state['sample_path']`` made absolute, or "" when there is none.

    Absolute is the whole point (BUG 11): a relative path is only meaningful
    against a working directory, and the tool that reads it — an MCP sidecar,
    a container — does not share the worker's. ``resolve`` is used for its
    normalisation, not to check the file: it works on a path that does not
    exist, which is what a mock or fixture run has.

    Two things it cannot do better than the value it is given. A *relative*
    ``sample_path`` is resolved against **this process's** working directory,
    which is right when the worker wrote the value (it always does) and a guess
    when something else did — there is no other cwd available to guess with.
    And ``resolve`` follows symlinks, so a corpus entry that is a link is handed
    over as its target; that is the path the reader will actually open, but it
    is not the name the operator used.
    """
    raw = state.get("sample_path")
    if not isinstance(raw, str) or not raw:
        return ""
    from pathlib import Path

    try:
        return str(Path(raw).resolve())
    except OSError:  # pragma: no cover — an unresolvable path is still better than none
        return raw


def _pin_sample_path(agent: Any, state: AnalysisState) -> None:
    """Pin the path this agent's tools must be given, on the agent itself.

    The same three-step lookup ``_augment_static_chunks_with_path`` does — the
    agent's own provider mirror, the global mirror, then the absolute host
    path (BUG 11) — because the two have to agree: the chunk tells the model
    which path to use and this tells the tool layer, and a disagreement is a
    tool call against a file that is not there.

    BUG 11, second round (live 2026-09-07, S5c): this used to run for the
    ``static`` role only. A *generic* agent (``static_qu1cksc0pe``, provider
    ``none``) therefore had the path in its chunk JSON and nothing anywhere
    else, so when the model called ``analyze_file`` with the bare filename
    there was no pinned value to correct it against and Qu1cksc0pe resolved
    the name against its own working directory.

    Assigned unconditionally: agents are cached across samples, so a path that
    cannot be recomputed must become ``None`` rather than stay yesterday's.
    """
    agent._analysis_file_path = (
        (state.get("static_sample_paths") or {}).get(agent._resolved.static_provider_id)
        or state.get("static_sample_path")
        or _absolute_host_sample_path(state)
        or None
    )
    # The same three choices, kept on the agent for the agents it may ask: a
    # callee's tools open the mirror its own provider was given, which the
    # caller's pinned path cannot say. See ``agents.delegation``.
    agent.sample_path_choices = {
        "by_provider": dict(state.get("static_sample_paths") or {}),
        "static": state.get("static_sample_path") or None,
        "host": _absolute_host_sample_path(state) or None,
    }
    # And the per-server overrides, for a tool server that was handed the
    # bytes instead of sharing this filesystem. Assigned unconditionally for
    # the same reason the path above is: an agent is cached across samples.
    agent._path_by_server = dict(getattr(agent._resolved, "path_by_server", {}) or {})


def _augment_static_chunks_with_path(
    chunks: list,
    state: AnalysisState,
    *,
    provider_id: str | None = None,
) -> list:
    """Inject the container-visible sample path into the static analyst's chunks.

    The static analyst's data surface is a JSON-stringified ``target`` block
    from the sandbox report (or a raw chunk when no sandbox ran). The chunk
    used to carry only ``{sha256, md5, name, size}`` — there was no way for the LLM
    to know which path to hand ``load_program``, so it either guessed
    (always wrong, since the file lived in the host tempdir invisible to
    the Ghidra container) or skipped the call entirely. We now splice
    ``analysis_file_path`` into the JSON when the worker recorded a
    container-visible mirror via ``state['static_sample_path']``.

    Ghidra-path fix (2026-07-12, job 60df48cb): when the head chunk is the
    file-loader placeholder ("No static data available for sample <sha>"),
    synthesize a real JSON chunk instead of passing the placeholder through.
    Without it the LLM never sees ``analysis_file_path``, hallucinates a
    path for ``load_program`` and reports "file was not found on the server
    filesystem" even though the mirror succeeded. The synthesized chunk
    carries the paths plus a deterministic PE summary (``static``) so fresh
    samples get a real data surface. Non-placeholder non-JSON chunks (legacy
    raw decompile output) still pass through unchanged.

    The chunk objects are immutable dataclasses; rebuild with the same
    chunker so downstream code (token budget, chunk_text) keeps working.
    """

    # ``provider_id`` is the agent's own static provider: with two static
    # analysts on two providers each is shown the mirror its own tools point
    # at, not the global provider's. The global key stays the fallback, which
    # is what a single-provider run has always had.
    paths = state.get("static_sample_paths") or {}
    static_path = paths.get(provider_id) if provider_id else None
    if not static_path:
        static_path = state.get("static_sample_path")
    if not static_path:
        # BUG 11 (live 2026-09-07, S5): a provider that mirrors nothing — the
        # `none` provider, capa/YARA, anything that reads in place — left this
        # empty, and the helper returned the chunks untouched. The only
        # path-shaped thing the agent then saw was the sample's own *name*,
        # which Qu1cksc0pe resolved against its own working directory. A tool
        # cannot be handed a bare filename: with no mirror, the absolute host
        # path is the one that is true for every reader on this machine.
        static_path = _absolute_host_sample_path(state)
    if not static_path or not chunks:
        return chunks

    head = chunks[0]
    parsed: dict[str, Any] | None = None
    try:
        loaded = json.loads(head.content)
        if isinstance(loaded, dict):
            parsed = loaded
    except (json.JSONDecodeError, ValueError):
        parsed = None

    if parsed is None:
        if not _STATIC_PLACEHOLDER_RE.match(head.content.strip()):
            # Legacy raw (non-JSON, non-placeholder) chunk — pass through.
            return chunks
        parsed = {
            "note": (
                "Live analysis run: no pre-extracted static fixture exists "
                "for this sample. Nothing about the binary is pasted here on "
                "purpose — call your tools for the section table, the imports "
                "and the strings, and cite the ids their results carry."
            ),
            "sha256": state.get("file_hash") or "",
        }

    parsed["analysis_file_path"] = static_path
    # What the routing layer already decided, so the analyst does not have to
    # spend a call rediscovering it before it can choose a tool.
    for key in ("file_type", "platform"):
        value = state.get(key)
        if isinstance(value, str) and value and value != "unknown":
            parsed[key] = value
    # Also carry the HOST-readable path (when present) so the static-feature
    # family classifier can read the raw bytes — ember reads the file on the
    # host, unlike Ghidra which reads the container-visible ``analysis_file_path``.
    host_path = state.get("sample_path")
    if isinstance(host_path, str) and host_path:
        parsed["host_sample_path"] = host_path
    # The toolchain: knowing a sample is AutoIt or PyInstaller rather than
    # "a PE" changes which tools are worth spending steps on, and it costs one
    # line of prompt. It is the one fact here no tool answers directly.
    #
    # Detected here from a bounded prefix rather than threaded through state:
    # toolchain markers live in the runtime stub near the front of the file, and
    # a new state channel for one string is more machinery than the fact
    # deserves.
    if isinstance(host_path, str) and host_path:
        try:
            from pathlib import Path as _P

            from maljan.extractors.sample_identity import _detect_language_or_compiler

            with _P(host_path).open("rb") as _fh:
                _lang = _detect_language_or_compiler(_fh.read(4 * 1024 * 1024))
            if _lang:
                parsed["language_or_compiler"] = _lang
        except Exception as _e:  # noqa: BLE001 — a prompt hint is never worth a failure
            logger.debug("static chunk: language fingerprint skipped (%s)", _e)
    new_content = json.dumps(parsed, indent=2, default=str)

    import dataclasses as _dc

    try:
        rebuilt = _dc.replace(
            head,
            content=new_content,
            char_count=len(new_content),
            token_estimate=len(new_content) // 4,
        )
    except TypeError:
        # Not a dataclass (e.g. a future chunk type) — give up gracefully
        # rather than crashing the analyst node over a presentation detail.
        return chunks
    return [rebuilt, *chunks[1:]]


# ---------------------------------------------------------------------------
# Triage node
# ---------------------------------------------------------------------------


# How long the pack waits for the one reputation call. A lookup by hash is a
# single round trip; a server that has not answered in this long is one the
# run goes on without, and the entry says so.
REPUTATION_TIMEOUT_S = 60.0


def _withheld_servers(container: ServiceContainer) -> set[str] | None:
    """The servers the active team withholds, or ``None`` when that cannot be read.

    ``None`` rather than an empty set on a failure to read: a lookup that
    sends the sample hash to a service the team meant to keep it from is the
    disclosure the setting exists to prevent, so not knowing is treated as
    withheld.
    """
    try:
        return {str(name) for name in container.active_profile().exclude_servers}
    except Exception as exc:  # noqa: BLE001 — unreadable exclusions withhold everything
        logger.warning("triage pack: the team's exclude_servers could not be read (%s).", exc)
        return None


def _reputation_lookup(container: ServiceContainer, sha256: str) -> Any:
    """The pack's reputation step, bound to this job's servers and settings.

    Returns a callable the pack invokes with its recorder. The callable makes
    at most one call: ``get_file_report`` on VirusTotal's own server when it
    is enabled, else ``check_hash`` on the threat-intel sidecar when it is, and
    otherwise writes the entry that says why there was none — no server
    enabled, the setting off, the team withholding the server, no hash to ask
    about. The call goes through the tool server registry exactly as an
    agent's does and is recorded under that server, so a run's ledger says
    which service was asked, not only that something was. A server the active
    team lists in ``exclude_servers`` is never asked, for the same reason its
    agents never see it.
    """
    from maljan.core import virustotal
    from maljan.core.config import ALL_SERVERS, ToolRef

    def _skip(recorder: Any, why: str) -> Any:
        # The prefix is what tells the pack's rendering a call that was never
        # made from one that was made and failed (``triage_pack._was_not_made``).
        message = f"{NOT_RUN_PREFIX} {why}"
        return recorder.record(
            tool="reputation",
            args={"sha256": sha256},
            server=PIPELINE,
            output=message,
            ok=False,
            error=message,
            started_at=time.time(),
        )

    def lookup(recorder: Any) -> Any:
        if str(container.config.triage.reputation) == "off":
            return _skip(recorder, "core.triage.reputation is off; no lookup was made")
        if not sha256:
            return _skip(recorder, "the run has no sha256 to look up; no lookup was made")
        servers = container.config.mcp.servers
        candidates: list[tuple[str, str, dict[str, Any]]] = [
            (virustotal.SERVER_KEY, "get_file_report", {"hash": sha256}),
            ("threatintel", "check_hash", {"file_hash": sha256}),
        ]
        enabled = [c for c in candidates if getattr(servers.get(c[0]), "enabled", False)]
        if not enabled:
            return _skip(
                recorder,
                f"no reputation server is enabled ({virustotal.SERVER_KEY}, threatintel); "
                "no lookup was made",
            )
        withheld = _withheld_servers(container)
        usable = (
            []
            if withheld is None or ALL_SERVERS in withheld
            else [c for c in enabled if c[0] not in withheld]
        )
        if not usable:
            names = ", ".join(c[0] for c in enabled)
            return _skip(
                recorder,
                f"{names} withheld by the team's exclude_servers; no lookup was made"
                if withheld is not None
                else f"{names} withheld because the team's exclusions could not be read",
            )
        server, tool_name, args = usable[0]
        from maljan.agents.base_agent import run_coro_blocking

        started, wall_clock = time.monotonic(), time.time()
        registry = container.get_server_registry()
        tools, reasons = registry.tools_for_ref(
            ToolRef(kind="mcp", server=server, name=tool_name),
            container.job_key(),
            truncation_ledger=container.get_truncation_ledger(),
        )
        if not tools:
            why = "; ".join(reasons) or f"{server} offered no tool named {tool_name}"
            return recorder.record(
                tool=tool_name,
                args=args,
                server=server,
                output=why,
                ok=False,
                error=why,
                started_at=wall_clock,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        try:
            output = str(
                run_coro_blocking(
                    tools[0].ainvoke(args), REPUTATION_TIMEOUT_S, label=f"triage:{tool_name}"
                )
            )
        except Exception as exc:  # noqa: BLE001 — a failed lookup is an entry
            message = f"{type(exc).__name__}: {exc}"
            return recorder.record(
                tool=tool_name,
                args=args,
                server=server,
                output=message,
                ok=False,
                error=message,
                started_at=wall_clock,
                duration_ms=int((time.monotonic() - started) * 1000),
            )
        # Handed in as a success and left to ``build_entry`` to read: it
        # already knows the structured shape, the flat one and the MCP
        # client's own marker, and one place deciding what a failure looks
        # like is what keeps the pack and an agent's loop agreeing.
        return recorder.record(
            tool=tool_name,
            args=args,
            server=server,
            output=output,
            started_at=wall_clock,
            duration_ms=int((time.monotonic() - started) * 1000),
        )

    return lookup


# Held while a degradation reason is added, so a parallel stage fan-out cannot
# write the same sentence twice.
_REASON_LOCK = threading.Lock()


# How much of a failure's message the header prints. A tool server on another
# host can answer with a stack trace, and the header is a list of things to
# fix rather than a log.
MAX_FAILURE_CHARS = 400


def tool_failures(ledger: Sequence[Any], limit: int = 20) -> list[dict[str, Any]]:
    """Each distinct tool failure in the ledger, once, with its remedy.

    Keyed by tool and message so a call that failed the same way five times
    is one row with a count of five; the report header and the console read
    this rather than walking the ledger. A step the pack's budget stopped is
    not a failure and is left out, as the run-state block leaves it out.
    """
    rows: dict[tuple[str, str], dict[str, Any]] = {}
    for entry in ledger:
        if getattr(entry, "ok", True) or getattr(entry, "repeated_of", None):
            continue
        # A refused ask is a guard working: a cycle, a depth, a clock the
        # caller had already spent. It is a failed entry so the model reads
        # it, and it is not a tool an operator can go and fix. A callee that
        # raised or ran out of time is a different thing and stays in the
        # list, which is why this reads the refusal rather than the server.
        if str(getattr(entry, "error", "") or "").startswith(REFUSAL_PREFIX):
            continue
        message = str(getattr(entry, "error", "") or getattr(entry, "output", "") or "").strip()
        if message.startswith(NOT_RUN_PREFIX):
            continue
        # Trimmed the way the ledger trims a result: an external server that
        # answers a failure with a stack trace would otherwise print it whole
        # in the report header.
        message = trim_output(message, MAX_FAILURE_CHARS)
        key = (str(getattr(entry, "tool", "")), message)
        row = rows.get(key)
        if row is None:
            rows[key] = row = {
                "tool": key[0],
                "server": getattr(entry, "server", None),
                "error": message,
                "remediation": getattr(entry, "remediation", None),
                "entry_id": str(getattr(entry, "id", "")),
                "count": 0,
            }
        row["count"] += 1
    kept = list(rows.values())[:limit]
    if len(rows) > limit:
        # Said rather than silently dropped: a header that shows twenty of
        # thirty-one failures and does not say so reads as thirty-one fixed.
        kept.append(
            {
                "tool": "",
                "server": None,
                "error": f"and {len(rows) - limit} more distinct failure(s), not listed",
                "remediation": None,
                "entry_id": "",
                "count": len(rows) - limit,
            }
        )
    return kept


def evidence_summary(ledger: Sequence[Any]) -> dict[str, Any]:
    """What the report is standing on, counted, for ``run_summary.evidence``.

    One place rather than an inline literal, so the golden that pins the
    stored summary pins the shape this writes rather than a copy of it.
    """
    by_tool: dict[str, int] = {}
    for entry in ledger:
        by_tool[entry.tool] = by_tool.get(entry.tool, 0) + 1
    return {
        "entries": len(ledger),
        "ok": sum(1 for e in ledger if e.ok),
        "failed": sum(1 for e in ledger if not e.ok),
        "trimmed": sum(1 for e in ledger if e.truncated),
        "by_tool": dict(sorted(by_tool.items())),
        "failures": tool_failures(ledger),
    }


def with_verdict_fallback(validation: Any, failure: str) -> dict[str, Any]:
    """``run_summary.validation`` with the note that no judge answered.

    A note rather than a resolved finding, and it goes where the other things
    a run was told and did not fix already go: under ``verdict.fallback``,
    the code the judge agent already records when its answer was not the
    verdict it was asked for. A judge that raised is the same fact one step
    earlier, so a reader of the summary sees one list and not a special case.
    The failure's class travels; its message does not.
    """
    block = dict(validation or {})
    by_code = dict(block.get("by_code") or {})
    by_code[VERDICT_FALLBACK_CODE] = by_code.get(VERDICT_FALLBACK_CODE, 0) + 1
    rows = [dict(row) for row in block.get("unresolved") or []]
    rows.append(
        {
            "agent": JUDGE_AGENT_KEY,
            "code": VERDICT_FALLBACK_CODE,
            "message": f"the judge did not answer ({failure}); the verdict is the pipeline's",
        }
    )
    block["by_code"] = dict(sorted(by_code.items()))
    block["unresolved"] = rows
    block.setdefault("retries", int(block.get("retries") or 0))
    block.setdefault("not_run", list(block.get("not_run") or []))
    return block


def _function_matches_step(container: ServiceContainer, state: AnalysisState) -> Any:
    """The pack's exact-match attribution step, or ``None`` when it cannot run.

    Three things have to be there: a Qdrant memory backend, a static provider
    that can hash functions, and a mirror path for it to read. Without any
    one of them there is no entry, because there is nothing that could have
    been asked; with all three the step is the judge's function-hash read,
    made before the analysts instead of after them.
    """
    cfg = container.config
    static_path = state.get("static_sample_path")
    if str(getattr(cfg.memory, "backend", "")) != "qdrant" or not static_path:
        return None
    try:
        provider = container.get_static_provider()
    except Exception as exc:  # noqa: BLE001 — no provider, no step
        logger.debug("triage pack: no static provider for function hashes (%s)", exc)
        return None
    if not provider.capabilities.provides_function_hashes:
        return None
    sha256 = str(state.get("file_hash") or "")

    def step() -> tuple[dict[str, Any], dict[str, Any]]:
        from maljan.providers.base import StaticJobContext
        from maljan.tools import knowledge

        job = StaticJobContext(mirror_sample_path=str(static_path), sha256=sha256)
        hashes = [h for _name, h in provider.function_hashes(job)]
        args = {
            "func_hashes": hashes,
            "qdrant_url": cfg.memory.qdrant_url,
            "collection": cfg.memory.qdrant_function_hash_collection,
            "exclude_sample_id": sha256,
        }
        api_key = (
            cfg.memory.qdrant_api_key.get_secret_value() if cfg.memory.qdrant_api_key else None
        )
        return args, knowledge.function_matches(
            hashes,
            cfg.memory.qdrant_url,
            collection=cfg.memory.qdrant_function_hash_collection,
            api_key=api_key,
            exclude_sample_id=sha256,
        )

    return step


def _analysis_server_environ(container: ServiceContainer) -> dict[str, str]:
    """This process's environment with the analysis server's own ``env`` map over it.

    What the pack's FLOSS step reads ``MALJAN_FLOSS_PATH`` and the staging base
    from, so an operator who named the build or the base in the server's
    settings gets the same build and the same directory from the pack as from
    the tool. Never raises: a server entry that cannot be read leaves this
    process's environment.
    """
    environ = dict(os.environ)
    try:
        server = container.config.mcp.servers.get("analysis")
        extra = dict(getattr(server, "env", None) or {})
    except Exception as exc:  # noqa: BLE001 — an unreadable entry adds nothing
        logger.debug("triage pack: the analysis server's env could not be read (%s).", exc)
        return environ
    environ.update({str(k): str(v) for k, v in extra.items()})
    return environ


def _knowledge_module() -> Any:
    """``maljan.tools.knowledge`` when it imports, else ``None``."""
    try:
        from maljan.tools import knowledge
    except Exception:  # noqa: BLE001 — a knowledge module that will not import is absent
        return None
    return knowledge


def make_triage_node(
    container: ServiceContainer,
    *,
    stage: Any,
    announces: bool = True,
    finishes: tuple[str, ...] = (),
) -> Any:
    """Factory: the node a triage stage runs as.

    It runs the pack (``pipeline.triage_pack``) over the sample on a worker
    thread, writes every entry to the evidence ledger and the four facts a
    later stage's condition may read to ``triage_facts``. It declines, with
    the reason recorded, when the stage's condition is false, when
    ``core.triage.enabled`` is off, when the stage withholds the built-in
    tools, and when there is no sample on disk to read; and it never fails
    the job — a pack that raised is a stage that ran and says it failed.
    """

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        started = time.monotonic()
        announce_finished(container, state, tuple(k for k in finishes if k != stage.key))

        runs, reason = stage_runs(stage, state)
        path = _absolute_host_sample_path(state)
        if runs and not bool(container.config.triage.enabled):
            runs, reason = False, "core.triage.enabled is off"
        if runs and not getattr(stage, "builtin_tools", True):
            runs, reason = False, "the stage withholds the built-in tools"
        if runs and not (path and Path(path).is_file()):
            runs, reason = False, "no sample on disk to read"
        if not runs:
            logger.info("stage %s skipped: %s", stage.key, reason)
            if announces:
                announce_skipped(container, stage, reason)
            return stage_record(stage, ran=False, reason=reason)

        if announces:
            announce_started(container, stage)

        recorder = EvidenceRecorder(
            PIPELINE,
            counter=container.get_evidence_counter(),
            stage=stage.key,
            # The pack's steps are tool calls like any other, and the console
            # draws them in the same conversation, so they are fed out as the
            # pack writes them rather than only after the run.
            sink=container.event_sink,
            # The pack's answers are what the run saw too, and a judge
            # grounding an indicator in one must find it.
            corpus=container.get_evidence_corpus(),
        )
        cfg = container.config
        capa_cfg = cfg.static.capa
        inputs = PackInputs(
            sample_path=path,
            sha256=str(state.get("file_hash") or ""),
            file_type=str(state.get("file_type") or ""),
            strings_head=int(cfg.triage.strings_head),
            capa=CapaSettings(
                rules_dir=str(capa_cfg.rules_dir),
                signatures_dir=str(capa_cfg.signatures_dir),
                timeout_s=int(capa_cfg.timeout_seconds),
                backend=str(capa_cfg.backend),
            ),
            sandbox_report=state.get("sandbox_report"),
            evidence_budget_bytes=int(getattr(cfg.reporting, "evidence_budget_bytes", 0) or 0),
            budget_s=float(cfg.triage.budget_seconds),
            floss=FlossSettings(
                environ=_analysis_server_environ(container), job_id=container.job_key()
            ),
        )

        def _elapsed_ms() -> int:
            return int((time.monotonic() - started) * 1000)

        try:
            result = await asyncio.to_thread(
                run_pack,
                recorder,
                inputs,
                reputation=_reputation_lookup(container, inputs.sha256),
                function_matches=_function_matches_step(container, state),
            )
        except Exception as exc:  # noqa: BLE001 — the pack never fails the job
            logger.warning(
                "triage pack failed (%s: %s); the run goes on without it.", type(exc).__name__, exc
            )
            # What was written before the crash is evidence and is kept, under
            # the same budget a finished pack gets; the crash is the one
            # failure this path counts.
            entries = list(recorder.entries)
            apply_budget(entries, inputs.evidence_budget_bytes)
            update: dict[str, Any] = {
                "triage_facts": {
                    **TriageFacts().to_dict(),
                    "entries": len(entries),
                    "failed": 1,
                    "duration_ms": _elapsed_ms(),
                    "degradation_reasons": [failure_reason("pack")],
                },
                **stage_record(
                    stage,
                    ran=True,
                    reason=f"triage pack failed: {type(exc).__name__}: {exc}",
                    failure=True,
                    duration_ms=_elapsed_ms(),
                ),
            }
            if entries:
                update["evidence_ledger"] = [e.model_dump(mode="json") for e in entries]
            if stage.key in finishes:
                announce_finished(container, state, (stage.key,), extra=update.get("stage_results"))
            return update

        logger.info(
            "triage pack: %d entries, %d failed, %d ms.",
            len(result.entries),
            len(result.failed),
            result.duration_ms,
        )
        stopped = list(getattr(result, "stopped_by_budget", None) or [])
        if stopped:
            emit_stage_ended_at_cap(
                container.event_sink,
                stage=stage.key,
                agent=PIPELINE,
                cap="budget_seconds",
                detail=f"{len(stopped)} step(s) not run: {', '.join(stopped)}",
            )
        update = {
            "triage_facts": result.to_state(),
            **stage_record(stage, ran=True, duration_ms=_elapsed_ms()),
        }
        if result.entries:
            update["evidence_ledger"] = [e.model_dump(mode="json") for e in result.entries]
        if stage.key in finishes:
            announce_finished(container, state, (stage.key,), extra=update.get("stage_results"))
        return update

    node_fn.__name__ = f"{stage.key}_triage_node"
    node_fn.__doc__ = f"The triage pack, run as stage '{stage.key}'."
    return node_fn


# ---------------------------------------------------------------------------
# Analyst node
# ---------------------------------------------------------------------------


def _sample_identity(state: AnalysisState) -> dict[str, Any]:
    """What the run knows about the sample before anyone analysed it.

    The hash the job was queued under, the name it arrived with and the format
    detection are the router's; the md5, sha1 and size come from the sandbox
    report's own file block when there is one, and the size otherwise from the
    file on disk. None of them is a conclusion about the sample, which is why they are
    put in front of the judge without a caveat. The name is the one the
    submitter gave and is labelled so.

    Never raises. An identity block that cannot be built is one the prompt goes
    without, and a judge with no hash is what this exists to stop, not one this
    should fail a run for.
    """
    identity: dict[str, Any] = {
        "sha256": str(state.get("file_hash") or ""),
        "file_name": str(state.get("file_name") or ""),
        "file_type": str(state.get("file_type") or ""),
        "platform": str(state.get("platform") or ""),
    }
    report = state.get("sandbox_report")
    target = (report or {}).get("target") if isinstance(report, dict) else None
    sandbox_file = target.get("file") if isinstance(target, dict) else None
    if isinstance(sandbox_file, dict):
        identity["md5"] = str(sandbox_file.get("md5") or "")
        identity["sha1"] = str(sandbox_file.get("sha1") or "")
        identity["size_bytes"] = sandbox_file.get("size") or ""
    if not identity.get("size_bytes"):
        from pathlib import Path

        path = state.get("sample_path")
        with suppress(OSError, TypeError, ValueError):
            identity["size_bytes"] = Path(str(path)).stat().st_size if path else ""
    return {key: value for key, value in identity.items() if str(value or "").strip()}


def _ledger_servers(state: AnalysisState) -> set[str]:
    """Every server the run has recorded a tool call against, by key.

    Read off the raw rows rather than through ``LedgerEntry``: the question is
    which servers were asked, one malformed row must not cost the answer, and
    a row written by an in-process tool carries no server at all.
    """
    servers: set[str] = set()
    for row in state.get("evidence_ledger") or []:
        name = row.get("server") if isinstance(row, dict) else getattr(row, "server", None)
        if name:
            servers.add(str(name))
    return servers


# ---------------------------------------------------------------------------
# Stage plumbing
# ---------------------------------------------------------------------------


def pack_text(state: AnalysisState, container: ServiceContainer) -> str:
    """The triage pack as every agent is shown it, or ``""`` on a run without one.

    Cut at ``reporting.upstream_findings_max_chars``, the same bound the
    upstream findings block has: both are what a stage is told before it
    starts, and one budget for the two keeps a long pack from spending a
    late stage's context.
    """
    limit = int(ReportingConfig.model_fields["upstream_findings_max_chars"].default)
    with suppress(AttributeError, TypeError, ValueError):
        limit = int(container.config.reporting.upstream_findings_max_chars)
    return pack_block(pack_entries(state.get("evidence_ledger") or []), limit)


def ledger_ids(state: AnalysisState) -> list[str]:
    """Every id the run's evidence ledger issued, in ledger order: what a report may cite."""
    ids: list[str] = []
    for row in state.get("evidence_ledger") or []:
        value = row.get("id") if isinstance(row, dict) else getattr(row, "id", None)
        if value and str(value) not in ids:
            ids.append(str(value))
    return ids


def pack_ledger_ids(state: AnalysisState) -> list[str]:
    """The ids of the pack's entries: what every agent may cite besides its own."""
    return [entry.id for entry in pack_entries(state.get("evidence_ledger") or [])]


def brief_agent(agent: Any, state: AnalysisState, container: ServiceContainer) -> None:
    """Hand an agent the run's two standing blocks and the ids it may cite.

    Assigned unconditionally, like the pinned sample path: agents are cached
    across samples, and a block from the previous sample is worse than none.
    """
    agent.facts_block = pack_text(state, container)
    agent.pack_ledger_ids = pack_ledger_ids(state)
    agent.run_state_block = render_run_state(state)
    # The routed format, so the platform check compares the agent's
    # techniques against the sample it is looking at.
    agent.sample_format = (
        str(state.get("file_type") or "unknown"),
        str(state.get("platform") or "unknown"),
    )


def stage_context(state: AnalysisState) -> StageContext:
    """The sample and the run so far, as a stage condition sees them.

    Built from the state rather than from the job, so a condition reads the
    same facts the nodes do and a replayed state evaluates identically.
    """
    report = state.get("sandbox_report") or {}
    network = report.get("network") if isinstance(report, dict) else None
    name = state.get("file_name") or ""
    extension = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    target = report.get("target") if isinstance(report, dict) else None
    size = 0
    mime = ""
    if isinstance(target, dict):
        with suppress(TypeError, ValueError):
            size = int(target.get("size") or 0)
        mime = str(target.get("type") or target.get("mime") or "")
    results = {
        key: StageResult.from_dict(value)
        for key, value in (state.get("stage_results") or {}).items()
        if isinstance(value, dict)
    }
    return StageContext(
        file_type=str(state.get("file_type") or ""),
        platform=str(state.get("platform") or ""),
        mime=mime,
        size=size,
        extension=extension,
        sandbox_available=bool(report),
        has_pcap=bool(isinstance(network, dict) and network),
        has_sandbox_report=bool(report),
        stages=results,
        triage=TriageFacts.from_dict(state.get("triage_facts") or {}),
    )


def stage_runs(stage: Any, state: AnalysisState) -> tuple[bool, str]:
    """Whether ``stage`` runs for this state, and the reason when it does not.

    A condition that cannot be evaluated skips the stage rather than failing
    the run: the graph is already built, the sample is already detonated, and
    an operator typo in one stage's condition must not cost the other six.
    """
    when = getattr(stage, "when", "") or ""
    if not when.strip():
        return True, ""
    try:
        if evaluate(when, stage_context(state)):
            return True, ""
    except ConditionError as exc:
        logger.warning("stage %s: condition error: %s", getattr(stage, "key", "?"), exc)
        return False, f"condition error: {exc}"
    return False, f"condition not met: {when}"


def stage_record(
    stage: Any,
    *,
    ran: bool,
    reason: str = "",
    failure: bool = False,
    agents: tuple[str, ...] = (),
    agent_reasons: Mapping[str, str] | None = None,
    claim_count: int = 0,
    technique_ids: tuple[str, ...] = (),
    finding_count: int = 0,
    duration_ms: int = 0,
) -> dict[str, Any]:
    """One stage's contribution to ``state["stage_results"]``.

    ``reason`` answers "why did this stage not run", and one other thing: why a
    stage that did run went wrong, which ``failure`` says. A stage of three
    analysts, one of which had no data, *ran*: writing that analyst's skip
    reason as the stage's put "no sandbox fixture for this sample" beside
    ``ran: true`` in the run summary, which reads as the stage having been
    skipped and is contradicted by the same row's duration. Such a reason is
    recorded per agent instead, under ``agent_reasons``.

    A mediation that timed out is the other case and is not that one: the stage
    ran, the reason belongs to the stage rather than to any of its members, and
    the first version of this rule blanked it — the debate's only reason, and
    the run summary stopped carrying it at all.
    """
    if ran and reason and not failure:
        if agents:
            agent_reasons = {**(agent_reasons or {}), **{agent: reason for agent in agents}}
        else:
            logger.debug(
                "stage %s ran and gave the reason %r with no agent to attribute it to; "
                "it is dropped. Pass agents, agent_reasons, or failure=True.",
                getattr(stage, "key", ""),
                reason,
            )
        reason = ""
    entry = StageResult(
        ran=ran,
        reason=reason,
        claim_count=claim_count,
        technique_ids=technique_ids,
        finding_count=finding_count,
        agents=agents,
    ).to_dict()
    if agent_reasons:
        entry["agent_reasons"] = dict(agent_reasons)
    # A stage that ran and went wrong, said as a flag rather than inferred
    # from a reason beside ``ran: true``: the console draws it as failed.
    entry["failure"] = bool(ran and failure)
    entry["kind"] = str(getattr(stage, "kind", "analysis"))
    # The reducer adds durations up across a stage's nodes, which is right for
    # a chain and wrong for a fan-out; it needs the mode to tell them apart.
    entry["mode"] = str(getattr(stage, "mode", "sequential"))
    entry["duration_ms"] = int(duration_ms)
    return {"stage_results": {str(getattr(stage, "key", "")): entry}}


def upstream_findings(stage: Any, state: AnalysisState, container: ServiceContainer) -> str:
    """What the stages this one depends on found, as a prompt block.

    ``findings`` is the claim spine — title, technique, confidence, evidence id
    — which is what a downstream analyst needs to build on rather than repeat.
    ``full`` adds each upstream agent's prose, for a correlation or reversing
    stage that has to read the argument and not only its conclusion.
    ``none`` is what the default profile uses, because its analysts have never
    seen each other's work before the debate and changing that would change
    every number the paper reports.
    """
    mode = str(getattr(stage, "inject_upstream", "findings"))
    if mode == "none":
        return ""
    upstream = set(getattr(stage, "depends_on", []) or ())
    if not upstream:
        return ""
    profile = container.active_profile()
    wanted: list[str] = []
    for candidate in profile.stages:
        if candidate.key in upstream:
            wanted.extend(candidate.agents)
    if not wanted:
        return ""

    isr_reports = state.get("isr_reports") or {}
    reports = state.get("reports") or {}
    lines: list[str] = ["## Upstream findings", ""]
    for agent in wanted:
        isr = isr_reports.get(agent)
        claims = list(getattr(isr, "claims", []) or []) if isr is not None else []
        if not claims and mode != "full":
            continue
        lines.append(f"### {agent}")
        for claim in claims:
            technique = getattr(claim, "technique_id", None) or "—"
            reference = getattr(claim, "evidence_ref", "") or "—"
            confidence = float(getattr(claim, "confidence", 0.0) or 0.0)
            text = " ".join(str(getattr(claim, "claim", "") or "").split())
            lines.append(f"- {text} [{technique}, confidence {confidence:.2f}, {reference}]")
        if not claims:
            lines.append("- no claims")
        if mode == "full":
            prose = str(reports.get(agent) or "").strip()
            if prose:
                lines.extend(["", prose])
        lines.append("")

    if len(lines) <= 2:
        return ""
    block = "\n".join(lines).rstrip()
    limit = int(ReportingConfig.model_fields["upstream_findings_max_chars"].default)
    with suppress(AttributeError, TypeError, ValueError):
        limit = int(container.config.reporting.upstream_findings_max_chars)
    if limit and len(block) > limit:
        block = block[:limit].rstrip() + "\n\n[upstream findings truncated]"
    return block


def _with_upstream(chunks: list, block: str) -> list:
    """Put the upstream block into the first chunk, without breaking its shape.

    Two constraints meet here. The block has to go into an existing chunk
    rather than become one of its own, because a single chunk and a list of
    chunks take different paths through the analyst below and a stage's
    upstream context must not be what decides which one a sample gets. And the
    head chunk of a static or generic agent is a JSON document with a contract
    on it — ``analysis_file_path`` is read back out of it by
    ``StaticAnalyst._extract_load_hint``, ``_extract_analysis_path`` and
    ``ConfigurableAnalyst._analysis_path_in``, all of which bail the moment the
    text does not start with ``{``.

    So a JSON head gains a field and keeps being JSON; anything else takes the
    prose in front of it. Prepending prose onto the JSON, which is what this
    did first, silently cost every injecting static stage its
    ``LOAD THIS BINARY FIRST`` line and sent it back to inventing a path.
    """
    if not block or not chunks:
        return chunks
    head = chunks[0]
    stripped = head.content.strip()
    content: str | None = None
    if stripped.startswith("{"):
        try:
            parsed = json.loads(stripped)
        except (json.JSONDecodeError, ValueError):
            parsed = None
        if isinstance(parsed, dict):
            parsed["upstream_findings"] = block
            content = json.dumps(parsed, indent=2, default=str)
    if content is None:
        content = f"{block}\n\n{head.content}"
    return [replace(head, content=content, char_count=len(content)), *chunks[1:]]


def _corroboration_with_publication(report: Any, state: AnalysisState) -> dict[str, Any] | None:
    """The corroboration rows, each saying whether this run published the id.

    ``None`` when there is nothing to amend — no summary, or no technique named
    — so an untouched column stays untouched.
    """
    from maljan.analysis.corroboration import mark_unpublished

    stored = (state.get("run_summary") or {}).get("corroboration") or {}
    rows = (report.run_summary or {}).get("corroboration") or stored
    if not rows:
        return None
    published = {
        str(mapping.technique_id or "").strip().upper()
        for mapping in (getattr(report, "ttp_mappings", None) or [])
    }
    reasons = {
        str(cell.technique_id or "").strip().upper(): cell.not_published
        for cell in (getattr(report, "capability_matrix", None) or [])
        if cell.not_published
    }
    return mark_unpublished(rows, published, reasons)


def _amended_validation(validation: Any, tally: ValidationTally) -> dict[str, Any] | None:
    """A ``validation`` block plus what the report round cost.

    ``validation`` is the block as the report already carries it, which on a
    run whose judge raised is the judge's block *plus* the ``verdict.fallback``
    note. Amending that rather than rebuilding from the state is what keeps the
    note: a report-round correction used to reconstruct the block from the
    summary the judge wrote, which on such a run is the summary it never wrote.

    ``None`` when there is no block at all — mock mode, where the judge never
    built a summary and nothing has been told to anybody.
    """
    block = dict(validation or {})
    if not block:
        return None
    by_code = dict(block.get("by_code") or {})
    for code, count in tally.by_code.items():
        by_code[code] = int(by_code.get(code, 0)) + int(count)
    block["by_code"] = dict(sorted(by_code.items()))
    block["retries"] = int(block.get("retries") or 0) + tally.retries
    # A capability claim the run does not establish survives into the report,
    # because deleting the sentence would leave neither the claim nor a record
    # of it. The row is how a reader learns the summary outran the evidence.
    # Written only when there is one: a run that over-claimed nothing should
    # not carry an empty key implying the question was asked and answered.
    merged_unresolved = [*(block.get("unresolved") or []), *tally.unresolved]
    if merged_unresolved:
        block["unresolved"] = merged_unresolved
    # A block from before the row existed reads as a run whose checks all ran.
    block.setdefault("not_run", [])
    return block


def stage_rollup(
    container: ServiceContainer, state: AnalysisState, extra: dict[str, Any] | None = None
) -> list[dict[str, Any]]:
    """Every stage of the active profile, in declaration order, as summary rows.

    A stage the state has nothing for did not report — which for the verdict
    and report stages simply means the rollup is being taken from inside them —
    and is rendered as not run with the reason saying so, rather than left out.
    An absent row and a skipped row are different findings.
    """
    recorded = dict(state.get("stage_results") or {})
    recorded.update(extra or {})
    rows: list[dict[str, Any]] = []
    for stage in container.active_profile().stages:
        entry = recorded.get(stage.key) or {}
        rows.append(
            {
                "key": stage.key,
                "kind": stage.kind,
                "ran": bool(entry.get("ran", False)),
                "failure": bool(entry.get("failure", False)),
                "reason": str(entry.get("reason") or ("" if entry else "stage did not report")),
                "agents": list(entry.get("agents") or stage.agents),
                "duration_ms": int(entry.get("duration_ms") or 0),
                # Why an individual member of a stage that ran did not work.
                # Absent when every member worked, which is the common row.
                **(
                    {"agent_reasons": dict(entry["agent_reasons"])}
                    if entry.get("agent_reasons")
                    else {}
                ),
            }
        )
    return rows


def stage_key_of(stage: Any, default: str) -> str:
    """The key of the stage a node belongs to, or ``default`` when it has none.

    Every transcript line says which step of the team said it, so the console
    can file a message under the stage that produced it rather than under the
    run as a whole. A node built without a stage — the graph a test assembles
    by hand — falls back to the name its kind has always had.
    """
    return str(getattr(stage, "key", "") or default)


# The room itself, rather than a participant. A watcher nobody composed into
# the team — the mediator, the sycophancy detector — speaks as the pipeline and
# names itself in the line it says, so the console draws a notice instead of
# adding a participant to a roster the operator never wrote.
ROOM_SPEAKER = "pipeline"


def label_of(container: ServiceContainer, key: str) -> str:
    """The label an operator gave this agent, or its key. Never raises."""
    try:
        from maljan.agents.composition import display_name

        return display_name(container.config, key)
    except Exception:  # noqa: BLE001 — a name is never worth a node
        return str(key)


def announce_started(container: ServiceContainer, stage: Any) -> None:
    """``stage_started``, from the one node of the stage that announces it."""
    emit(
        container.event_sink,
        "stage_started",
        {"stage": stage.key, "kind": stage.kind, "agents": list(stage.agents)},
    )


def announce_skipped(container: ServiceContainer, stage: Any, reason: str) -> None:
    emit(
        container.event_sink,
        "stage_skipped",
        {"stage": stage.key, "kind": stage.kind, "reason": reason},
    )


def announce_finished(
    container: ServiceContainer,
    state: AnalysisState,
    keys: tuple[str, ...],
    *,
    extra: dict[str, Any] | None = None,
) -> None:
    """``stage_finished`` for every stage in ``keys`` that ran, once each.

    Read from ``stage_results`` rather than from a node's return value, because
    the node closing a stage is often the first node of the *next* one and all
    it has is the merged state. A stage that declined to run is not announced
    again: ``stage_skipped`` was its terminator.

    The announcement is claimed from the container rather than simply emitted.
    A terminal parallel stage with no barrier and a terminal debate have no
    single node that runs after them, so every one of their own nodes is a
    finisher and would otherwise announce the stage once per node; the report
    node's closing rollup would announce every stage a second time. Claiming
    leaves the first announcement standing and drops the rest, which is what
    makes the rollup a repair for a run that crashed mid-way rather than a
    duplicate of a run that did not.
    """
    # ``extra`` is the closing node's own contribution, which LangGraph has
    # not merged into the state yet. Merged here with the channel's own
    # reducer, so a chain's last analyst announces the whole stage rather than
    # only itself.
    recorded = _merge_stage_results(dict(state.get("stage_results") or {}), dict(extra or {}))
    for key in keys:
        record = recorded.get(key)
        if not isinstance(record, dict) or not record.get("ran"):
            continue
        if not container.claim_stage_finished(key):
            continue
        emit(
            container.event_sink,
            "stage_finished",
            {
                "stage": key,
                "kind": record.get("kind", ""),
                "ran": True,
                "reason": record.get("reason", ""),
                "agents": list(record.get("agents") or []),
                "duration_ms": int(record.get("duration_ms") or 0),
            },
        )


def make_join_node(stage: Any, container: ServiceContainer, finishes: tuple[str, ...] = ()) -> Any:
    """The barrier at the end of a parallel analysis stage.

    Does nothing but exist. LangGraph waits for every predecessor of a node, so
    one node behind the stage's agents is a fan-in; the stage's own result is
    already in the state, written by each agent through the merging reducer.
    """

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        announce_finished(container, state, finishes)
        return {}

    node_fn.__name__ = f"{stage.key}_join_node"
    node_fn.__doc__ = f"Fan-in barrier for the parallel stage '{stage.key}'."
    return node_fn


# The format-specific parsers, and the routed formats each is for. A parser the
# sample's format never calls on is not something this run lost: a missing
# Mach-O library on a PE sample said nothing about the PE and still reached
# the report's first page as a degradation. A tool not named here, or a sample
# whose format is unknown, keeps its reason.
_FORMAT_TOOLS: dict[str, frozenset[str]] = {
    "pe_info": frozenset({"pe"}),
    "elf_info": frozenset({"elf"}),
    "macho_info": frozenset({"mach-o", "macho"}),
    "apk_info": frozenset({"apk", "dex"}),
    "document_info": frozenset({"ole2", "ooxml", "pdf", "doc", "docx", "xls", "xlsx", "rtf"}),
}


_UNAVAILABLE_TOOL_RE = re.compile(r"^server\.[^.]+\.(?P<tool>[^.(]+)_unavailable\(")


def reason_applies_to_format(reason: str, file_type: str) -> bool:
    """Whether a server's degradation reason costs a sample of this format anything.

    The registry records a withheld tool when it attaches the server, before
    any sample is known; this is where the reason meets the sample. Only a
    format-specific parser the routed format never needs is left out.
    """
    match = _UNAVAILABLE_TOOL_RE.match(str(reason or ""))
    return match is None or _needed_for(match.group("tool"), file_type)


def _needed_for(tool: str, file_type: str) -> bool:
    """Whether a missing ``tool`` costs this sample anything, by its routed format."""
    formats = _FORMAT_TOOLS.get(tool)
    routed = str(file_type or "").strip().lower()
    if formats is None or not routed or routed == "unknown":
        return True
    return routed in formats


def note_unavailable_tools(
    container: ServiceContainer, agent: Any, file_type: str = ""
) -> list[str]:
    """Record, once, each bound tool the server's manifest says cannot answer here.

    Read at stage start from the capability manifests the registry kept when
    it attached the servers, so an operator sees ``document_info`` is missing
    its library before the analyst spends a step discovering it. The reason
    is ``server.<key>.<tool>_unavailable(<why>)`` with the remedy after it; it
    goes on the registry's list, which the judge reads into the run summary,
    and is written there once however many agents bind the tool. A
    format-specific parser the routed ``file_type`` never needs is not recorded.
    """
    from maljan.agents.tool_pinning import server_of

    registry = getattr(container, "_server_registry_cache", None)
    if registry is None:
        return []
    by_server: dict[str, list[str]] = {}
    for tool in list(getattr(agent, "tools", None) or []):
        key = server_of(tool)
        if key:
            bound = str(getattr(tool, "name", ""))
            by_server.setdefault(key, []).append(_manifest_name(key, bound))
    noted: list[str] = []
    for key, names in by_server.items():
        try:
            manifest = registry.get(key).capabilities
        except Exception:  # noqa: BLE001 — a server that is gone has no manifest
            continue
        if manifest is None:
            continue
        for missing in manifest.unavailable(names):
            if not _needed_for(missing.tool, file_type):
                continue
            reason = missing.degradation_reason
            noted.append(reason)
            if _record_once(registry.degradation_reasons, reason):
                logger.info("stage start: %s", reason)
    return noted


def _record_once(reasons: list[str], reason: str) -> bool:
    """Append ``reason`` unless it is already there, and say whether it was new.

    Under this module's lock, because a parallel fan-out has two stage nodes
    starting at once and check-then-append can write the same sentence twice.
    The registry appends its own attach reasons to the same list without it,
    so this closes the race between two stage starts rather than every race
    on the list.
    """
    with _REASON_LOCK:
        if reason in reasons:
            return False
        reasons.append(reason)
        return True


def _manifest_name(server: str, bound: str) -> str:
    """A bound tool's name as its server's manifest spells it.

    Two servers offering one tool name is legal, and the registry renames the
    second to ``<server>__<tool>`` so a model can call both. The manifest is
    keyed by the name the server itself uses, so the prefix has to come off
    before the lookup — without this the renamed tool's cell is never found
    and its stage-start record is lost with nothing saying so.
    """
    prefix = f"{server}__"
    return bound[len(prefix) :] if bound.startswith(prefix) else bound


def make_stage_agent_node(
    stage: Any,
    agent_name: str,
    container: ServiceContainer,
    *,
    announces: bool = True,
    finishes: tuple[str, ...] = (),
) -> Any:
    """Factory: the node one agent of one analysis stage runs as.

    The stage decides three things the agent itself does not: whether it runs
    at all (``when``), what it is told about the stages before it
    (``inject_upstream``) and whether it keeps the built-in tool servers
    (``builtin_tools``). Everything else is the analyst node this has always
    been.
    """

    def node_fn(state: AnalysisState) -> dict[str, Any]:
        started = time.monotonic()
        # Whatever finished upstream of this node, announced before this stage
        # begins: for a fan-out with no barrier, the first node of the next
        # stage is the only place the merged result is visible.
        announce_finished(container, state, tuple(k for k in finishes if k != stage.key))

        runs, skip_reason = stage_runs(stage, state)
        if not runs:
            logger.info("stage %s skipped for %s: %s", stage.key, agent_name, skip_reason)
            if announces:
                announce_skipped(container, stage, skip_reason)
            return stage_record(stage, ran=False, reason=skip_reason)

        if announces:
            announce_started(container, stage)
        # Analysts run sequentially on the single-slot local model, so a
        # per-agent "working now" event is the only way the UI can say which
        # one is actually working — the worker's up-front announcement marks
        # them all busy at once and is a poor proxy, and the stage event above
        # is one per stage rather than one per agent.
        emit(container.event_sink, "agent_progress", {"agent": agent_name, "phase": "analyzing"})

        def _elapsed_ms() -> int:
            return int((time.monotonic() - started) * 1000)

        def _closing(update: dict[str, Any]) -> dict[str, Any]:
            """Announce this stage's end, when this node is the one that does."""
            if stage.key in finishes:
                announce_finished(container, state, (stage.key,), extra=update.get("stage_results"))
            return update

        if container.is_mock:
            return _closing(
                {
                    "reports": {agent_name: f"MOCK: {agent_name} analysis complete."},
                    "isr_reports": {agent_name: _empty_isr(agent_name)},
                    **stage_record(
                        stage,
                        ran=True,
                        agents=(agent_name,),
                        duration_ms=_elapsed_ms(),
                    ),
                }
            )

        bound_agent: Any = None

        def _evidence_update() -> dict[str, Any]:
            """This agent's calls, drained, in the shape the state expects.

            Called on the failure paths as well as the success one: an analyst
            that made twenty calls and then died made twenty calls, and a run
            that reaches consensus in round one never revises, so nothing else
            would ever drain it.
            """
            if bound_agent is None:
                return {}
            try:
                entries = bound_agent.drain_evidence_entries()
            except Exception as exc:  # noqa: BLE001
                logger.debug("evidence ledger read skipped for %s: %s", agent_name, exc)
                return {}
            update: dict[str, Any] = {}
            if entries:
                update["evidence_ledger"] = [e.model_dump(mode="json") for e in entries]
                update["tool_evidence"] = {
                    agent_name: [e.to_captured().model_dump() for e in entries]
                }
            update.update(_validation_update(bound_agent, agent_name))
            mode = _nudge_mode(bound_agent)
            if mode:
                update["nudge_retry_modes"] = {agent_name: mode}
            update.update(_budget_update(bound_agent, agent_name))
            return update

        # Bound before the try so the failure paths below can ask it what it
        # already had: a container that cannot build the agent at all leaves it
        # None, and nothing is promoted from an agent that never existed.
        agent: Any = None
        try:
            agent = container.get_agent(agent_name)
            bound_agent = agent
            role = container.agent_role(agent_name)
            note_unavailable_tools(container, agent, str(state.get("file_type") or ""))

            agent.pipeline_stage = stage.key
            # What the pipeline established before this analyst, and the run
            # as it stands: the pack at the head of its first turn, the run
            # state in its system turn on every turn.
            brief_agent(agent, state, container)
            sandbox_report = state.get("sandbox_report")

            # The two roles whose tools open the sample by path need the path
            # pinned on the agent before anything else: the augmentation below
            # reads a file and can raise, and agents are cached across samples,
            # so a stale path from the previous sample must be cleared even on
            # the failure path. The chunk carries the path for the model to
            # read; the pin carries it for the tool layer, which is what
            # actually corrects a model that sends the bare filename.
            if role in SAMPLE_FED_ROLES:
                _pin_sample_path(agent, state)

            chunks = container.load_data_for_agent(
                agent_name,
                file_hash=state["file_hash"],
                sandbox_report=sandbox_report,
                sample_path=_absolute_host_sample_path(state) or None,
            )

            if role in SAMPLE_FED_ROLES:
                # The mirror is looked up by this agent's own static provider
                # id so two static analysts on two providers each get their own
                # mirror path, with the absolute host path as the fallback a
                # provider that mirrors nothing leaves.
                chunks = _augment_static_chunks_with_path(
                    chunks,
                    state,
                    provider_id=agent._resolved.static_provider_id,
                )

            # The no-data guard runs on what the *loaders* produced. Injecting
            # first would hide a placeholder behind the upstream block, and an
            # analyst with nothing to read would spend a whole ReAct loop
            # analysing "No network data available for sample <sha>" and report
            # it back as its one evidence-backed claim.
            # A synthetic report is an absence, not an observation, and the
            # loaders cannot tell: they are handed a well-formed report with
            # empty sections and produce chunks describing exactly that.
            synthetic = _sandbox_fed(role) and _sandbox_report_is_synthetic(state)
            if not chunks or synthetic or _is_placeholder_only(chunks, role):
                # A Linux ELF audit found that an ELF sample with no PCAP / sandbox network
                # trace caused the network analyst to fail-hard with an
                # AnalystError ([ERROR] prefix), which then routed into
                # ``failed_analysts`` and forced ``degraded_mode=true``.
                # For analysts whose absence of input data is normal (a
                # PE without dynamic, or a Linux ELF without PCAP), this
                # is graceful degradation, not failure — emit a [WARN]
                # report with an empty ISR so the rest of the pipeline
                # treats the analyst as "absent" rather than "broken".
                logger.info(
                    "Agent '%s': no data chunks available — emitting empty ISR "
                    "as graceful degradation (no-data path).",
                    agent_name,
                )
                no_data_text = (
                    f"[WARN] {agent_name}: {SYNTHETIC_SANDBOX_REASON} — analyst skipped."
                    if synthetic
                    else (
                        f"[WARN] {agent_name}: no {agent_name} data available "
                        "for this sample — analyst skipped."
                    )
                )
                emit_agent_message(
                    container.event_sink,
                    speaker=agent_name,
                    role="analyst",
                    text=no_data_text,
                    status="no_data",
                    stage=stage_key_of(stage, "analysis"),
                    display_name=label_of(container, agent_name),
                )
                return _closing(
                    {
                        "reports": {agent_name: no_data_text},
                        "isr_reports": {agent_name: _empty_isr(agent_name)},
                        **stage_record(
                            stage,
                            ran=True,
                            agents=(agent_name,),
                            # The reason belongs to this agent, not to a stage
                            # that ran. The analyst's own findings row carries
                            # it too, as its ``status_reason``.
                            agent_reasons={
                                agent_name: (
                                    SYNTHETIC_SANDBOX_REASON
                                    if synthetic
                                    else "no data for this agent"
                                )
                            },
                            duration_ms=_elapsed_ms(),
                        ),
                    }
                )

            chunks = _with_upstream(chunks, upstream_findings(stage, state, container))

            if len(chunks) == 1:
                # View-decomposition pilot (findings-log §3.6): when enabled,
                # split the single text bundle into N focused, equal-budget
                # sub-prompts and merge. Default 0 keeps the monolithic path.
                _views = int(getattr(container.config.llm, "view_decomposition_views", 0) or 0)
                if _views >= 2:
                    _budget = int(getattr(container.config.llm, "expert_max_tokens", 0) or 0)
                    # Item 3 (LAMD): "tier" reinterprets the N knob as sequential
                    # vertical reasoning tiers; "facet" (default) keeps the §3.6
                    # horizontal concurrent views. Both share the equal budget.
                    _mode = str(
                        getattr(container.config.llm, "view_decomposition_mode", "facet") or "facet"
                    )
                    if _mode == "tier":
                        isr = agent.safe_analyze_isr_tiered(
                            chunks[0].content,
                            _views,
                            total_max_tokens=_budget or None,
                        )
                    else:
                        isr = agent.safe_analyze_isr_views(
                            chunks[0].content,
                            _views,
                            total_max_tokens=_budget or None,
                        )
                else:
                    isr = agent.safe_analyze_isr(chunks[0].content)
                fallback_text = chunks[0].content
            else:
                # TraceRAG function-level retrieval (findings-log §4 Item 2):
                # for large static binaries, feed only the behavior-relevant
                # function chunks instead of every chunk. Default top_k=0 keeps
                # the full linear path (zero behaviour change).
                if role == "static":
                    _rag_k = int(
                        getattr(container.config.preprocessing, "static_function_rag_top_k", 0) or 0
                    )
                    _rag_min = int(
                        getattr(container.config.preprocessing, "static_function_rag_min_chunks", 6)
                        or 6
                    )
                    if _rag_k > 0 and len(chunks) > _rag_min:
                        from maljan.memory.function_index import select_relevant_chunks

                        chunks = select_relevant_chunks(chunks, _rag_k)
                logger.info(
                    "Agent '%s': processing %d chunks for sample '%s'.",
                    agent_name,
                    len(chunks),
                    state["file_hash"],
                )
                isr = agent.safe_analyze_isr_chunked(chunks)
                # Multi-chunk: never re-run analyze() on a single chunk as a
                # fallback — that would silently drop the rest of the sample.
                fallback_text = ""

            if isr.claims:
                report = isr.to_text_summary()
            elif getattr(agent, "ended_out_of_room", False) is True:
                # A second loop over the same material meets the same full
                # window. The analyst has no prose; why is on its budget record.
                report = ""
            elif fallback_text:
                report = agent.safe_analyze(fallback_text)
            else:
                report = (
                    f"[WARN] {agent_name}: ISR produced no claims (multi-chunk fallback empty)."
                )

            # Carry the captured tool-loop outputs
            # (decompiled functions, crypto constants, emulation/dataflow) into
            # state so report_node can ground the deep technical spine. Best-
            # effort — a capture read must never break the analyst node.
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=summarize_claims(isr.claims, speaker=agent_name),
                round_index=0,
                status=isr_status(isr),
                claims=claims_to_payload(isr.claims),
                dissent=list(isr.dissent_items or []),
                # The analyst's own prose, so the transcript can offer it behind
                # a disclosure. Previously this text reached the database as
                # ``agent_reports`` and the UI could only show it as a JSON dump.
                report=report,
                stage=stage_key_of(stage, "analysis"),
                display_name=label_of(container, agent_name),
            )

            technique_ids = tuple(
                dict.fromkeys(str(c.technique_id) for c in isr.claims if c.technique_id is not None)
            )
            # A lead that answered with no claims still has whatever its
            # specialists answered, and their ISRs are the only place those
            # answers survive.
            _promoted = promoted_asks(agent, isr)
            node_out: dict[str, Any] = {
                "reports": {
                    agent_name: report,
                    **{key: answer.to_text_summary() for key, answer in _promoted.items()},
                },
                "isr_reports": {agent_name: isr, **_promoted},
                **stage_record(
                    stage,
                    ran=True,
                    agents=(agent_name,),
                    claim_count=len(isr.claims),
                    technique_ids=technique_ids,
                    duration_ms=_elapsed_ms(),
                ),
            }
            # Where this agent's tool servers were handed the sample, when any
            # of them were. The reducer merges across agents, so a server two
            # analysts share is recorded once.
            staged = dict(getattr(agent, "_path_by_server", {}) or {})
            if staged:
                node_out["remote_sample_paths"] = staged
            node_out.update(_evidence_update())
            return _closing(node_out)
        except (AnalystError, LLMError) as e:
            # Structured error event so Loki/Promtail
            # can aggregate ``event_type=analyst_error`` instead of regex-
            # scanning free-text. ``sample_hash`` is short-fingerprinted so
            # the log line stays human-skim-friendly.
            logger.error(
                "%s analysis failed: %s",
                agent_name,
                e,
                extra={
                    "event_type": "analyst_error",
                    "agent": agent_name,
                    "sample_hash": (state.get("file_hash") or "")[:16],
                    "error_type": type(e).__name__,
                },
            )
            failed_text = f"[ERROR] {agent_name} analysis failed: {describe_exception(e)}"
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=failed_text,
                status="failed",
                stage=stage_key_of(stage, "analysis"),
                display_name=label_of(container, agent_name),
            )
            _promoted = promoted_asks(agent)
            return _closing(
                {
                    "reports": {
                        agent_name: failed_text,
                        **{key: answer.to_text_summary() for key, answer in _promoted.items()},
                    },
                    "isr_reports": {agent_name: _empty_isr(agent_name), **_promoted},
                    **_evidence_update(),
                    **stage_record(
                        stage,
                        ran=True,
                        reason=f"{agent_name} failed",
                        agents=(agent_name,),
                        duration_ms=_elapsed_ms(),
                    ),
                }
            )
        except (ValueError, RuntimeError) as e:
            logger.exception(
                "%s analysis crashed with %s.",
                agent_name,
                type(e).__name__,
                extra={
                    "event_type": "analyst_error",
                    "agent": agent_name,
                    "sample_hash": (state.get("file_hash") or "")[:16],
                    "error_type": type(e).__name__,
                    "fatal": True,
                },
            )
            crashed_text = f"[ERROR] {agent_name} crashed: {describe_exception(e)}"
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=crashed_text,
                status="failed",
                stage=stage_key_of(stage, "analysis"),
                display_name=label_of(container, agent_name),
            )
            return _closing(
                {
                    "reports": {agent_name: crashed_text},
                    "isr_reports": {agent_name: _empty_isr(agent_name)},
                    **_evidence_update(),
                    **stage_record(
                        stage,
                        ran=True,
                        reason=f"{agent_name} crashed",
                        agents=(agent_name,),
                        duration_ms=_elapsed_ms(),
                    ),
                }
            )

    node_fn.__name__ = f"{agent_name}_analyst_node"
    node_fn.__doc__ = f"Analysis node for '{agent_name}' in stage '{stage.key}'."
    return node_fn


# ---------------------------------------------------------------------------
# Revision context builder
# ---------------------------------------------------------------------------


def _revision_input_is_absent(
    state: AnalysisState,
    container: ServiceContainer,
    agent_name: str,
) -> bool:
    """True when ``agent_name`` has no data to revise against.

    Deliberately the *same* signal the analyst node uses before the initial
    pass, so an analyst cannot be skipped on round 0 and then resurrected on
    round 1. ``_is_placeholder_only`` carries the static carve-out with it:
    static falls back to a metadata-only prompt rather than being skipped.

    "The same signal" has to mean the same *source*, and that is BUG 12. Round 0
    reads ``load_sandbox_data_for_agent(agent, sandbox_report)`` whenever a
    sandbox report exists, and only falls back to ``load_chunked`` when one does
    not. This asked ``load_chunked`` unconditionally — which for dynamic and
    network on a live sample is the file loader's own "No <layer> data
    available" placeholder — so an analyst that had just analysed a full
    detonation report was judged data-less and its round-0 claims were
    discarded. A sandbox report that yields chunks *is* the data; the
    placeholder check belongs to the loader path alone.

    Fails **open**. A loader that raises tells us nothing about whether data
    exists, and silently deleting an analyst on a transient Qdrant blip is a
    far worse failure than one wasted revise call.
    """
    if _sandbox_fed(container.agent_role(agent_name)) and _sandbox_report_is_synthetic(state):
        return True
    sandbox_report = state.get("sandbox_report")
    if isinstance(sandbox_report, dict) and sandbox_report:
        try:
            sandbox_chunks = container.load_data_for_agent(
                agent_name,
                file_hash=str(state.get("file_hash") or ""),
                sandbox_report=sandbox_report,
            )
        except Exception as exc:  # noqa: BLE001 — fails open, same as the loader below
            logger.debug(
                "_revision_input_is_absent: sandbox slice failed for '%s' (%s); revising anyway.",
                agent_name,
                exc,
            )
            return False
        if sandbox_chunks:
            return False
    try:
        chunks = container.load_chunked(state.get("file_hash", ""), agent_name)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "_revision_input_is_absent: load_chunked failed for '%s' (%s); revising anyway.",
            agent_name,
            exc,
        )
        return False
    return not chunks or _is_placeholder_only(chunks, container.agent_role(agent_name))


def _build_revision_context(
    state: AnalysisState,
    container: ServiceContainer,
    agent_name: str,
) -> str:
    """Select the appropriate original_data context for a revision round.

    For single-chunk samples the raw chunk text is used. For multi-chunk
    samples the agent's consolidated analysis summary is used instead of
    re-loading data, because load_data() silently truncates large samples
    and would make revision grounding inconsistent with initial analysis.
    """
    file_hash = state.get("file_hash", "")

    try:
        chunks = container.load_chunked(file_hash, agent_name)
    except Exception as exc:
        logger.warning(
            "_build_revision_context: load_chunked failed for '%s/%s' (%s). "
            "Falling back to load_data().",
            file_hash,
            agent_name,
            exc,
        )
        return container.load_data(file_hash, agent_name)

    if len(chunks) == 1:
        return str(chunks[0].content)

    revised = state.get("revised_reports") or {}
    reports = state.get("reports") or {}
    summary_text = revised.get(agent_name) or reports.get(agent_name, "")

    if not summary_text:
        logger.warning(
            "_build_revision_context: no summary for '%s' in state. Falling back to load_data().",
            agent_name,
        )
        return container.load_data(file_hash, agent_name)

    total_chunks = getattr(chunks[0], "total", len(chunks))
    strategy_obj = getattr(chunks[0], "strategy", None)
    strategy = getattr(strategy_obj, "name", "unknown")
    header = (
        f"[CHUNKED ANALYSIS CONTEXT | domain={agent_name} | "
        f"chunks={total_chunks} | strategy={strategy}]\n"
        "This is your consolidated analysis summary produced from all "
        f"{total_chunks} chunks of the sample. Use it as grounding context "
        "for your revision; do not contradict findings without evidence.\n"
        "--- Consolidated Analysis Summary ---"
    )
    return f"{header}\n\n{summary_text}"


# ---------------------------------------------------------------------------
# Negotiation node
# ---------------------------------------------------------------------------


def _debate_threshold(stage: Any) -> float | None:
    """A debate stage's consensus threshold, or ``None`` for the global one."""
    options = getattr(stage, "debate", None)
    return None if options is None else float(options.consensus_threshold)


def _debate_record(stage: Any, started: float, *, reason: str = "") -> dict[str, Any]:
    """One round's contribution to the debate stage's result.

    The reducer adds the durations up, so a debate of four rounds records the
    time all four of them took rather than the time the last one did.

    The only reason this stage ever gives is a mediation that failed or timed
    out, and that is the stage's own — it belongs to the round, not to a member
    of it — so it is passed as a failure and survives ``stage_record``'s rule
    about a stage that ran.
    """
    if stage is None:
        return {}
    return stage_record(
        stage,
        ran=True,
        reason=reason,
        failure=bool(reason),
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def _agents_that_ran(container: ServiceContainer, state: AnalysisState) -> list[str]:
    """Every analysis-stage agent of the active profile whose stage ran.

    ``container.analyst_keys()`` is the whole roster, skipped stages included,
    which is the right answer for the worker's up-front announcement and the
    wrong one for anything that reads a run's output: an agent of a stage the
    condition turned off produced nothing, and handing the judge an empty
    report for it makes a skipped stage look like a failed analyst.
    """
    results = state.get("stage_results") or {}
    try:
        stages = container.active_profile().stages
    except Exception:  # noqa: BLE001 — a double without a profile keeps the roster
        return container.analyst_keys()
    names: list[str] = []
    for stage in stages:
        if stage.kind != "analysis":
            continue
        record = results.get(stage.key)
        if isinstance(record, dict) and not record.get("ran", True):
            continue
        names.extend(stage.agents)
    return names


def _debate_participants(
    container: ServiceContainer, stage: Any, state: AnalysisState
) -> list[str]:
    """Whose reports this debate argues over.

    Every agent of the analysis stages upstream of it, and only the ones that
    actually ran: a stage skipped by its condition contributed no report, and
    treating its absent analysts as silent dissenters would keep the loop
    running for rounds over nothing. A debate with no stage attached — the
    shape every test that builds a node by hand uses — argues over the whole
    profile, which is what it always did.
    """
    if stage is None:
        return container.analyst_keys()
    profile = container.active_profile()
    results = state.get("stage_results") or {}
    upstream = {s.key for s in profile.stages if s.key in set(stage.depends_on)}
    pending = list(upstream)
    while pending:
        current = pending.pop()
        found = profile.stage(current)
        if found is None:
            continue
        for dependency in found.depends_on:
            if dependency not in upstream:
                upstream.add(dependency)
                pending.append(dependency)
    names: list[str] = []
    for candidate in profile.stages:
        if candidate.kind != "analysis" or candidate.key not in upstream:
            continue
        record = results.get(candidate.key)
        if isinstance(record, dict) and not record.get("ran", True):
            continue
        names.extend(candidate.agents)
    # No fallback to the whole roster. A debate whose only upstream analysis
    # stage was skipped has nothing to argue over, and arguing over agents that
    # never ran would put empty reports in front of the mediator and spend the
    # round limit disagreeing about nothing.
    return names


# What a debate round writes when no agreement was measured: consensus does
# not apply, ``is_consensus`` is neither true nor false, and the confidence
# series gets nothing — never a 1.0 for agreement among nobody, never a 0.0.
_NO_CONSENSUS_MEASURED: dict[str, Any] = {
    "is_consensus": None,
    "consensus_applicable": False,
    "confidence_history": [],
}


def make_negotiation_node(
    container: ServiceContainer,
    *,
    stage: Any = None,
    announces: bool = True,
    finishes: tuple[str, ...] = (),
) -> Any:
    """Factory: creates the mediator negotiation node of one debate stage."""

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        started = time.monotonic()
        first_round = not (state.get("discussion_history") or [])
        if first_round:
            announce_finished(container, state, finishes)
        if stage is not None:
            runs, skip_reason = stage_runs(stage, state)
            if not runs:
                # A debate that does not run leaves the analysts' own ISRs
                # standing and hands them straight on. No agreement was
                # measured, so none is recorded; ``consensus_applicable`` is
                # the router's way out rather than looping a stage the
                # operator asked to skip.
                if announces:
                    announce_skipped(container, stage, skip_reason)
                return {
                    **_NO_CONSENSUS_MEASURED,
                    **stage_record(stage, ran=False, reason=skip_reason),
                }
            if not _debate_participants(container, stage, state):
                # Nothing upstream of it ran, so there is nothing to argue
                # over. Announced as a skip before the start, because a debate
                # that announces itself and then declines reads as one that
                # failed. ``consensus_applicable`` sends the router straight on.
                reason = "no analysis stage upstream of it ran"
                logger.info("stage %s skipped: %s", stage.key, reason)
                if announces:
                    announce_skipped(container, stage, reason)
                return {
                    **_NO_CONSENSUS_MEASURED,
                    **stage_record(stage, ran=False, reason=reason),
                }
            if announces and first_round:
                announce_started(container, stage)
        iteration = state.get("iteration_count", 0)
        agent_names = _debate_participants(container, stage, state)

        revised = state.get("revised_reports") or {}
        original = state.get("reports") or {}
        active_reports = {name: revised.get(name) or original.get(name, "") for name in agent_names}

        current_isrs = list((state.get("isr_reports") or {}).values())
        # Agreement among fewer than two analysts that produced claims measures
        # nothing: the round is still held, and no agreement value is recorded.
        applies = consensus_applies(agent_names, state.get("isr_reports") or {})

        if container.is_mock and not applies:
            return {
                "iteration_count": iteration + 1,
                **_NO_CONSENSUS_MEASURED,
                "sycophancy_detected": False,
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding="MOCK: fewer than two analysts produced claims.",
                        confidence_score=None,
                    )
                ],
                **_debate_record(stage, started),
            }
        if container.is_mock:
            is_consensus = iteration >= 1
            mean_conf = 0.95 if is_consensus else 0.4
            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
                "consensus_applicable": True,
                "sycophancy_detected": False,
                "confidence_history": [mean_conf],
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=(
                            "MOCK: All experts agree. Confidence: 0.95"
                            if is_consensus
                            else "MOCK: Contradictions found. Confidence: 0.4"
                        ),
                        confidence_score=mean_conf,
                    )
                ],
                **_debate_record(stage, started),
            }

        # Sycophancy detector skips the first round internally.
        syco = detect_sycophancy(current_isrs, iteration=iteration) if current_isrs else False

        def _judge_evidence() -> list[dict[str, Any]]:
            """The judges' tool calls, drained from every cached role.

            Drained here rather than named by role because the two roles are
            two objects — the mediator runs on ``expert`` and the verdict on
            ``judge`` — and only mediation reaches a tool loop. A node that
            drained one by name drained the empty one.
            """
            try:
                return [
                    entry.model_dump(mode="json") for entry in container.drain_all_judge_evidence()
                ]
            except Exception as exc:  # noqa: BLE001
                logger.debug("evidence ledger read skipped for the judges: %s", exc)
                return []

        # Two descriptions of one failure, and the difference is who reads
        # them. The log gets the message — that is the operator's line, on the
        # operator's host. The event gets the type and nothing else: it is
        # fanned out to every browser and kept in a table. Imported before the
        # ``try``, so the handler still has both names when the failure is the
        # first line inside it.
        from maljan.agents.base_agent import describe_exception_for_log, run_on_agent_loop

        try:
            judge = container.get_judge_agent(role="expert")
            # Mediation is this debate stage's work, so the tool calls it makes
            # are recorded against it rather than against "analysis".
            judge.pipeline_stage = stage.key if stage is not None else "analysis"
            # Mediation runs on the shared agent loop, not this one. The openai
            # SDK's httpx pool is process-wide and bound to whichever loop first
            # awaited it — always the agent loop, because the analysts ran
            # first — so awaiting the mediator here killed every call instantly
            # with a bogus ``APIConnectionError("Connection error.")``. See
            # ``run_on_agent_loop`` for the full account; before this, no run in
            # the database had ever completed a negotiation round.
            #
            # ``mediate`` budgets itself internally (``react_agent_timeout`` for
            # the reasoning call, then the bounded structured-output retries),
            # so the outer cap covers both phases plus the house +30s of decode
            # headroom rather than truncating a mediation that is still working.
            from maljan.core.config import get_settings

            mediation_timeout = float(get_settings().react_agent_timeout) * 2 + 30
            argument, is_consensus = await run_on_agent_loop(
                judge.mediate(
                    reports=active_reports,
                    history=state.get("discussion_history") or [],
                    isr_reports=state.get("isr_reports") or {},
                    # Which servers the run has actually called. The mediator
                    # opens its tool loop to ask who this sample is only when
                    # nothing has asked a reputation server yet, and that is a
                    # question about the ledger rather than about the
                    # analysts' prose.
                    ledger_servers=_ledger_servers(state),
                    # The sample's own facts. The mediator tells the judge to
                    # look a hash up, and until now no message in the
                    # conversation carried one.
                    sample=_sample_identity(state),
                    # The stage's own bar for calling it agreement. ``None``
                    # leaves the mediator on the global setting, which is what
                    # the stage's options were seeded from.
                    consensus_threshold=_debate_threshold(stage),
                    # The same facts the analysts were given, so the mediator
                    # weighs their reports against the record rather than
                    # against each other alone.
                    facts_block=pack_text(state, container),
                    run_state=render_run_state(state),
                ),
                hard_timeout=mediation_timeout,
                label="mediation",
            )

            # Only the analysts that produced claims. A skipped analyst
            # averaged in as a zero dragged the whole negotiation's confidence
            # down for having had nothing to read, and that number is what the
            # report carried.
            _claimed = mean_claim_confidence(current_isrs)
            mean_conf = _claimed if _claimed is not None else argument.confidence_score
            # The mediator counted the same claims and said consensus does not
            # apply; nothing is appended to the confidence series.
            measured = is_consensus is not None and applies

            emit_agent_message(
                container.event_sink,
                speaker=ROOM_SPEAKER,
                role="negotiator",
                text=f"Mediator: {argument.finding}",
                round_index=iteration + 1,
                status="complete",
                confidence=argument.confidence_score,
                stage=stage_key_of(stage, "debate"),
                # The mediator is the debate itself speaking, not a member of
                # the team, so it is a notice that names itself.
                kind="system",
            )
            if syco:
                emit_agent_message(
                    container.event_sink,
                    speaker=ROOM_SPEAKER,
                    role="system",
                    text=(
                        "Sycophancy detector: agents converged without new evidence — "
                        "flagged as sycophantic agreement. The next revision round "
                        "carries a directive to re-argue from evidence rather than "
                        "defer to peers."
                    ),
                    round_index=iteration + 1,
                    status="complete",
                    stage=stage_key_of(stage, "debate"),
                    # A notice to the room, not a line somebody said: the
                    # console draws it centred rather than as a bubble.
                    kind="system",
                )

            return {
                "iteration_count": iteration + 1,
                **(
                    {
                        "is_consensus": is_consensus,
                        "consensus_applicable": True,
                        "confidence_history": [mean_conf],
                    }
                    if measured
                    else _NO_CONSENSUS_MEASURED
                ),
                "sycophancy_detected": syco,
                "discussion_history": [argument],
                # Mediation is the only place a judge agent calls a tool, so
                # this is where those calls have to leave the agent.
                "evidence_ledger": _judge_evidence(),
                **_judge_budget(container),
                **_debate_record(stage, started),
            }
        except Exception as e:  # noqa: BLE001 — per-run fault-isolation boundary
            # The mediation step calls the LLM; on a constrained / local host that
            # call can fail in many ways (AnalystError, LLMError, a bare asyncio
            # TimeoutError re-raised by judge_agent.execute_tool_loop, or a transient
            # openai APIConnectionError under concurrent analyst load). A single
            # failed mediation round must NOT crash the whole graph — degrade
            # gracefully to "no consensus" and carry the current ISRs forward (they
            # are already populated by the analyst nodes), so the run still returns a
            # scoreable result instead of aborting an entire batch on one blip.
            label = "timed out" if isinstance(e, TimeoutError) else "failed"
            status = "timeout" if isinstance(e, TimeoutError) else "failed"
            logger.error("Negotiation %s: %s", label, describe_exception_for_log(e))
            emit_agent_message(
                container.event_sink,
                speaker=ROOM_SPEAKER,
                role="negotiator",
                # The class of the failure, never its message: an exception's
                # text can carry a path, a host or a credential, and this line
                # is published to every reader of the run. One helper decides
                # what that class is called, here and at every other published
                # failure, so a group names what is inside it and a refusal
                # keeps its remedy.
                text=f"Mediator: [ERROR] Mediation {label} ({describe_exception(e)}).",
                round_index=iteration + 1,
                status=status,
                stage=stage_key_of(stage, "debate"),
                kind="system",
            )
            return {
                "iteration_count": iteration + 1,
                # A failed round among analysts that produced claims is "no
                # consensus"; among fewer than two there was none to fail at.
                **(
                    {
                        "is_consensus": False,
                        "consensus_applicable": True,
                        "confidence_history": [0.0],
                    }
                    if applies
                    else _NO_CONSENSUS_MEASURED
                ),
                "sycophancy_detected": syco,
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=f"[ERROR] Mediation {label}: {describe_exception(e)}",
                        confidence_score=0.0 if applies else None,
                        # The structured signal. The "[ERROR] Mediation " prefix
                        # above stays for old stored state, but nothing new
                        # should have to parse prose to learn this.
                        status=status,
                    )
                ],
                # A mediation that timed out still made the calls it made.
                "evidence_ledger": _judge_evidence(),
                **_judge_budget(container),
                **_debate_record(stage, started, reason=f"mediation {label}"),
            }

    node_fn.__name__ = "negotiation_node"
    return node_fn


# ---------------------------------------------------------------------------
# Revision node
# ---------------------------------------------------------------------------


def make_revision_node(container: ServiceContainer, *, stage: Any = None) -> Any:
    """Factory: creates the revision node where all agents revise concurrently."""

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        agent_names = _debate_participants(container, stage, state)
        iteration = state.get("iteration_count", 0)

        history = state.get("discussion_history") or []
        mediator_feedback = ""
        for arg in reversed(history):
            if arg.agent_name == "Mediator":
                mediator_feedback = arg.finding
                break

        syco_detected = state.get("sycophancy_detected", False)
        revision_directive = build_revision_directive(syco_detected, mediator_feedback)

        original_reports = state.get("reports") or {}

        if container.is_mock:
            mock_isrs: dict[str, AgentISR] = {
                name: _empty_isr(name, revision_round=iteration) for name in agent_names
            }
            return {
                "revised_reports": {
                    name: f"MOCK REVISED: {name} analysis updated." for name in agent_names
                },
                "isr_reports": mock_isrs,
            }

        async def _revise_one(name: str) -> tuple[str, AgentISR]:
            # Same guard the analyst node applies before the initial pass. It
            # was missing here, so every negotiation round re-ran the analysts
            # that had just been skipped for having nothing to analyse. The
            # cost was never the wasted minutes: ``peer_reports`` below hands
            # the agent what its peers said, so an analyst with no evidence of
            # its own has nothing to write but static's findings — returned
            # tagged ``domain="dynamic"``. ``is_corroborated`` is
            # ``len(contributing_layers) >= 2``, so that echo promotes a
            # single-layer static finding to CORROBORATED and enters at
            # LAYER_WEIGHTS["dynamic"]=0.45, above static's own 0.35.
            # Measured 2026-07-29 with CAPE unreachable: the sycophancy
            # detector flagged static vs dynamic at sim=1.000.
            if _revision_input_is_absent(state, container, name):
                # Declining to revise is the point; deleting is not (BUG 12).
                # An analyst that made claims on round 0 keeps them — whatever
                # the guard now says about round 1, those claims were made
                # against data that existed at the time, and replacing them
                # with an empty ISR both loses evidence and makes the report
                # say "analysts produced no claims" about an analyst that
                # produced several. Only an analyst that had nothing to begin
                # with gets a fresh empty ISR.
                _round0 = (state.get("isr_reports") or {}).get(name)
                if _round0 is not None and getattr(_round0, "claims", None):
                    logger.info(
                        "Agent '%s': no data to revise — keeping its report and its "
                        "%d round-0 claim(s) (round %d).",
                        name,
                        len(_round0.claims),
                        iteration,
                    )
                    return original_reports.get(name, ""), _round0
                logger.info(
                    "Agent '%s': no data to revise — keeping its report and "
                    "contributing no claims (round %d).",
                    name,
                    iteration,
                )
                return original_reports.get(name, ""), _empty_isr(name, revision_round=iteration)
            data = _build_revision_context(state, container, name)
            agent = container.get_agent(name)
            brief_agent(agent, state, container)
            own_report = original_reports.get(name, "")
            peer_reports = {k: v for k, v in original_reports.items() if k != name}
            return await asyncio.to_thread(
                agent.safe_revise_isr,
                data,
                own_report,
                peer_reports,
                revision_directive,
                iteration,
            )

        # Slot-topology parity with the initial fan-out (builder.py). On a
        # single-slot local llama-server the analysts' revise calls must NOT
        # run concurrently or they clobber each other's per-slot recurrent
        # DeltaNet state → full re-prefill every step (the 2026-07-13 root
        # cause; see LLMConfig.parallel_analysts). The initial pass is
        # serialised by the graph edges, but this revision node fans out
        # itself, so it must honour the same flag. When sequential, await each
        # revise in turn (exclusive slot use); when parallel, keep the
        # concurrent gather for hosted multi-slot APIs. Both branches tolerate
        # a per-analyst failure (mirrors gather(return_exceptions=True)) so one
        # bad revise never aborts the round.
        parallel = True
        try:
            parallel = bool(container.config.llm.parallel_analysts)
        except AttributeError:
            parallel = True

        results: list[Any] = []
        if parallel:
            tasks = [_revise_one(name) for name in agent_names]
            results = list(await asyncio.gather(*tasks, return_exceptions=True))
        else:
            for name in agent_names:
                try:
                    results.append(await _revise_one(name))
                except Exception as exc:  # noqa: BLE001 — parity with gather()
                    results.append(exc)

        revised: dict[str, str] = {}
        revised_isrs: dict[str, AgentISR] = {}
        # A revision round that used tools issued ids from the job counter, so
        # leaving its entries behind puts holes in the persisted ledger and
        # makes anything the revised answer cites unresolvable. Built-in
        # analysts revise without tools; a composed agent does not.
        revision_ledger: list[dict[str, Any]] = []
        revision_nudge_modes: dict[str, str] = {}
        revision_budget: dict[str, list[dict[str, Any]]] = {}

        # strict=True: agent_names and results MUST be equal length; mismatch
        # is a programming error and must surface, not be silently truncated.
        for name, result in zip(agent_names, results, strict=True):
            if isinstance(result, BaseException):
                logger.error("%s revision failed: %s", name, result)
                revised[name] = original_reports.get(name, "")
                revised_isrs[name] = _empty_isr(name, revision_round=iteration)
                emit_agent_message(
                    container.event_sink,
                    speaker=name,
                    role="reviser",
                    # The class of the failure and nothing else, as the judge
                    # and the mediator already say it. The log above keeps the
                    # exception's own words for an operator; this line goes to
                    # every reader of the run, and an exception's text can
                    # carry a path, a host or a credential. One helper decides
                    # what that class is called, so a group names what is
                    # inside it and a refusal keeps its remedy.
                    text=f"[ERROR] {name} revision failed: {describe_exception(result)}",
                    round_index=iteration,
                    status="failed",
                    stage=stage_key_of(stage, "debate"),
                    display_name=label_of(container, name),
                )
            else:
                revised_text, isr = result
                revised[name] = revised_text
                revised_isrs[name] = isr
                try:
                    revision_ledger.extend(
                        entry.model_dump(mode="json")
                        for entry in container.get_agent(name).drain_evidence_entries()
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.debug("evidence ledger read skipped for %s: %s", name, exc)
                # A nudge repaired in this round belongs to this round, not to
                # the next analysis node that happens to drain the agent.
                revision_mode = _nudge_mode(container.get_agent(name))
                if revision_mode:
                    revision_nudge_modes[name] = revision_mode
                # This round's loop spent budget too, and the analysis node
                # that drained this agent has already run: rows left here
                # would never reach the state at all.
                for agent_key, rows in (
                    _budget_update(container.get_agent(name), name).get("budget_records") or {}
                ).items():
                    revision_budget.setdefault(agent_key, []).extend(rows)
                emit_agent_message(
                    container.event_sink,
                    speaker=name,
                    role="reviser",
                    text=summarize_claims(isr.claims, speaker=name),
                    round_index=iteration,
                    status=isr_status(isr),
                    claims=claims_to_payload(isr.claims),
                    dissent=list(isr.dissent_items or []),
                    # The rewritten report. This text was previously dropped
                    # entirely: ``revised_reports`` never reached the database,
                    # so what an agent said *after* the negotiation existed only
                    # inside the run.
                    report=revised_text,
                    stage=stage_key_of(stage, "debate"),
                    display_name=label_of(container, name),
                )

        out: dict[str, Any] = {"revised_reports": revised, "isr_reports": revised_isrs}
        if revision_ledger:
            out["evidence_ledger"] = revision_ledger
        if revision_nudge_modes:
            out["nudge_retry_modes"] = revision_nudge_modes
        if revision_budget:
            out["budget_records"] = revision_budget
        return out

    node_fn.__name__ = "revision_node"
    return node_fn


# ---------------------------------------------------------------------------
# Judge node
# ---------------------------------------------------------------------------


def _verdict_record(stage: Any, started: float, *, ran: bool, reason: str = "") -> dict[str, Any]:
    """The verdict or report stage's own line in ``stage_results``."""
    if stage is None:
        return {}
    return stage_record(
        stage,
        ran=ran,
        reason=reason,
        agents=tuple(stage.agents),
        duration_ms=int((time.monotonic() - started) * 1000),
    )


def _truncation_snapshot(container: ServiceContainer) -> dict[str, Any]:
    """The bound-hit ledger, with the window its tool-output caps came from.

    Written on the ledger rather than handed to the builder separately, so the
    caps a run applied and the window they were derived from travel as one
    record and a summary read back from storage carries both or neither.
    """
    ledger = container.get_truncation_ledger()
    try:
        ledger.note_context_window(container.context_budget_snapshot())
    except Exception as exc:  # noqa: BLE001 — telemetry never breaks a verdict
        logger.debug("the context window was not recorded on the run summary: %s", exc)
    return ledger.snapshot()


def _generation_snapshot(container: Any) -> dict[str, Any] | None:
    """The measured generation rates and the timeouts sized from them, or ``None``."""
    try:
        snapshot = container.get_generation_rates().snapshot()
    except Exception as exc:  # noqa: BLE001 — telemetry never breaks a verdict
        logger.debug("the generation rate was not recorded on the run summary: %s", exc)
        return None
    return snapshot if isinstance(snapshot, dict) else None


def make_judge_node(
    container: ServiceContainer,
    *,
    stage: Any = None,
    announces: bool = True,
    finishes: tuple[str, ...] = (),
) -> Any:
    """Factory: creates the final judge verdict node of the verdict stage."""

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        started = time.monotonic()
        verdict_stage = stage
        announce_finished(
            container, state, tuple(k for k in finishes if stage is None or k != stage.key)
        )
        if announces and verdict_stage is not None:
            announce_started(container, verdict_stage)

        def _closing(update: dict[str, Any]) -> dict[str, Any]:
            if verdict_stage is not None and verdict_stage.key in finishes:
                announce_finished(
                    container, state, (verdict_stage.key,), extra=update.get("stage_results")
                )
            return update

        if container.is_mock:
            return _closing(
                {
                    "final_decision": "Malware",
                    "judge_report": "MOCK: Evaluated all indicators.",
                    "stix_output": {},
                    "run_summary": None,
                    **(
                        stage_record(verdict_stage, ran=True, agents=tuple(verdict_stage.agents))
                        if verdict_stage is not None
                        else {}
                    ),
                }
            )

        def _judge_evidence() -> list[dict[str, Any]]:
            """Whatever the judges still hold, drained once, whichever way this ends.

            Mediation is where a judge agent calls a tool and the negotiation
            node drains it there; this is the backstop for a run that reached
            the verdict without one, and for a verdict path that grows tools
            later. A drain leaves nothing behind, so draining twice is safe.
            """
            try:
                return [
                    entry.model_dump(mode="json") for entry in container.drain_all_judge_evidence()
                ]
            except Exception as exc:  # noqa: BLE001
                logger.debug("evidence ledger read skipped for the judges: %s", exc)
                return []

        try:
            judge = container.get_judge_agent(role="judge")
            judge.pipeline_stage = verdict_stage.key if verdict_stage is not None else "analysis"

            revised = state.get("revised_reports") or {}
            original = state.get("reports") or {}
            _ran = _agents_that_ran(container, state)
            reports = {name: revised.get(name) or original.get(name, "") for name in _ran}

            isr_reports: dict[str, AgentISR] = dict(state.get("isr_reports") or {})

            # The run's tool calls, read back so the evidence summary can count
            # a capa or YARA hit as a source alongside the analysts. Bad rows
            # are skipped rather than failing the verdict.
            _ledger: list[LedgerEntry] = []
            for _row in state.get("evidence_ledger") or []:
                try:
                    _ledger.append(LedgerEntry.model_validate(_row))
                except Exception as exc:  # noqa: BLE001 — one bad row is not a lost verdict
                    logger.debug("judge_node: unreadable ledger row skipped (%s).", exc)

            # Who named which technique, and how sure each of them was. This is
            # what the judge weighs; nothing here combines the numbers.
            _corroboration = corroboration(isr_reports, _ledger)
            # What the analysts claimed is the technique count; rule matches
            # carrying tags nobody claimed are counted apart, or richly-firing
            # rules on benign software read as thirty techniques.
            _technique_count = sum(
                1 for row in _corroboration.values() if corroboration_row(row)["claimed_by"]
            )
            _rule_only = sum(
                1
                for row in _corroboration.values()
                if corroboration_row(row)["asserted_by"]
                and not corroboration_row(row)["claimed_by"]
            )
            _corroborated = sum(
                1 for row in _corroboration.values() if len(corroboration_sources(row)) > 1
            )
            evidence_summary = summarise(isr_reports, _ledger)
            # What the technique check questioned and the analysts kept, put
            # in front of the judge beside the evidence summary: the domain,
            # the platforms, the index's candidates, in the analysts' own rows.
            _check_note = technique_check_note(state.get("validation_findings"))
            if _check_note:
                evidence_summary = (
                    f"{evidence_summary}\n\n{_check_note}" if evidence_summary else _check_note
                )

            # When this run began. The state carries the caller's own clock;
            # a graph assembled without it falls back to here, which is the
            # reading the summary used to publish for every run and which made
            # a 473 s job print 66 s.
            start_time = float(state.get("run_started_at") or 0.0) or time.time()

            memory_store: MemoryStore | None = None
            try:
                memory_store = container.get_memory_store()
            except Exception as e:
                logger.warning("Memory store unavailable: %s. Skipping LTM context.", e)

            # The corpus an indicator's pattern value has to appear in. It is
            # no longer a filter: the judge is told which values are not in it
            # and gets a turn to withdraw them.
            #
            # What goes into it is what the run SAW. The stored ledger is not
            # that: ``apply_budget`` blanks an entry's output once an agent
            # passes its byte budget, *after* the model has read the answer, so
            # a corpus built from stored entries told the judge that a C2 a
            # tool really returned appears nowhere. The container keeps the
            # answers as the model received them, in memory, for the length of
            # the job; the stored entries are the fallback for a run whose
            # corpus is gone, and a fallback that had to read a blanked entry
            # says so.
            evidence_corpus: set[str] = set()
            corpus_state = NO_CORPUS
            try:
                from maljan.agents.judge_postprocess import build_evidence_corpus

                # Best-effort — interesting strings come from a partial
                # MalwareReport build later in the pipeline, so we pull
                # from the raw sandbox report and what the run's tools said.
                sandbox_report = state.get("sandbox_report") or {}
                seen, corpus_state = _what_the_run_saw(container, _ledger)
                # The run's own answers travel beside the token corpus rather
                # than inside it: added as set elements they were copied once
                # more, and joined into one string to be searched a third time.
                evidence_corpus = build_evidence_corpus(
                    interesting_strings=None,
                    sandbox_report=sandbox_report if isinstance(sandbox_report, dict) else None,
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Evidence corpus build skipped: %s", exc)

            # A shortened answer is the one the model read — the shortener
            # hands one string to the model and to the ledger — so nothing
            # about the grounding rule changes. What changes is what an
            # absence is allowed to sound like: the tools whose answers went
            # in with rows missing are named, so the judge can ask one of them
            # again with a narrower argument.
            shortened_tools = sorted(_tools_that_were_shortened(_ledger))

            # How whole the evidence the grounding checks searched was, on the
            # run's own record. A phrase inside one feedback message was the
            # only place it appeared, so a run whose grounding went advisory
            # looked exactly like one whose grounding was whole.
            try:
                from maljan.agents.run_evidence_corpus import held_by

                container.get_truncation_ledger().record_evidence_corpus(
                    missing_answers=corpus_state.missing_answers,
                    missing_tools=corpus_state.missing_tools,
                    reason="" if corpus_state.complete else corpus_state.why,
                    # Read while the container still has a corpus: after it
                    # closes there is none to ask, and what it held would be
                    # recorded as nothing.
                    held=held_by(container.get_evidence_corpus()),
                )
            except Exception as exc:  # noqa: BLE001 — telemetry never breaks a verdict
                logger.debug("Evidence corpus state not recorded: %s", exc)

            # Failure signals, computed before the verdict rather than after
            # it: the judge is told why the run is thin so it can weigh its own
            # confidence, which is the whole point of not capping the number
            # afterwards.
            _failed_analysts = [
                name
                for name, text in (state.get("reports") or {}).items()
                if isinstance(text, str) and text.strip().startswith("[ERROR]")
            ]
            # F2b (2026-07-05): an LLM analyst whose ReAct loop AND forced
            # synthesis both fail (e.g. a request timeout on a large binary)
            # yields an empty ISR, but if a later revision round emits
            # anything the analyst is reported as ``complete`` and never
            # lands in ``_failed_analysts`` above. Surface analysts that
            # produced *zero* claims as their own degradation signal so a
            # verdict assembled without a functioning primary analyst is not
            # presented at full confidence. (A benign sample still yields at
            # least one observational claim, so a truly empty ISR is a
            # failure signal, not a clean result.)
            _analyst_keys = _ran
            _empty_analysts = [
                name
                for name in _analyst_keys
                if name in isr_reports and not getattr(isr_reports.get(name), "claims", None)
            ]
            # BUG 12: two different findings, reported as one sentence. An
            # analyst that had nothing to read says the run was thin; one that
            # read everything and claimed nothing says the analyst failed.
            #
            # The distinction is carried as *data* — a per-agent flag on
            # ``run_summary.agent_stats`` — and emphatically not as a second
            # degradation-reason string. ``eval_dynamic_vs_static``'s
            # ``incidental_reasons`` partitions on the literal "analysts
            # produced no claims:" to strip the starved analysts out of the
            # static-only arm's treatment, and that tree is read-only: a rival
            # string would make every static-only arm record an unexplained
            # incidental degradation and move the E.1 numbers with nothing
            # saying so. The reason below is therefore byte-for-byte what it
            # always was, for every claimless analyst.
            #
            # In a thread: the guard reads the file loader from disk and
            # ``json.dumps`` a whole sandbox slice per analyst, which is
            # exactly the kind of work the preceding commit moved off this
            # loop.
            _no_data_analysts = set(
                await asyncio.to_thread(
                    lambda: [
                        name
                        for name in _empty_analysts
                        if _revision_input_is_absent(state, container, name)
                    ]
                )
            )
            # D10: surface anti-emulation / anti-VM / sandbox-detection
            # signatures so the existing DEGRADED RUN banner can explain
            # the empty dynamic tab (sandbox traced nothing because the
            # sample noticed it was being observed). Pattern matched
            # case-insensitively against the signature name + description
            # so a sandbox's verbose copy ("Listens for changes in the
            # sensor environment (might be used to detect emulation)") is
            # caught the same as CAPE's short ("anti-vm").
            _ANTI_EMU_RE = re.compile(
                r"emulation|anti[\s_-]?vm|anti[\s_-]?debug|sandbox\s*detect|"
                r"qemu|virtualbox|vmware|hyper[\s_-]?v",
                re.IGNORECASE,
            )
            _anti_emu_hits: list[str] = []
            for sig in (state.get("sandbox_report") or {}).get("signatures") or []:
                if not isinstance(sig, dict):
                    continue
                _haystack = f"{sig.get('name', '')} {sig.get('description', '')}"
                if _ANTI_EMU_RE.search(_haystack):
                    _hit_name = str(sig.get("name") or "").strip()
                    if _hit_name and _hit_name not in _anti_emu_hits:
                        _anti_emu_hits.append(_hit_name)
            # What the triage pack could not establish comes first: those
            # reasons were recorded before any analyst ran, and the judge is
            # the one node that assembles the run's list. They stay tokens
            # here, for the run summary; the prompt below gets them as
            # sentences.
            _triage_facts = dict(state.get("triage_facts") or {})
            _degradation_reasons: list[str] = [
                str(reason) for reason in (_triage_facts.get("degradation_reasons") or [])
            ]
            # The previous guard required
            # ``_technique_count > 0`` and so silently *missed* the most
            # degraded outcome of all — a run with zero corroboration AND
            # zero techniques (every LLM analyst failed and no YARA/Sigma
            # layer fired). That left ``degraded_mode = False`` and shipped
            # an uncapped confidence for an evidence-free verdict. The LTM
            # quality gate below (``_corroborated == 0 and _technique_count
            # <= 1``) already treated that case as low-quality, so the two
            # gates disagreed. Trigger on zero corroboration regardless of
            # technique count and word the reason for the empty case.
            if _corroborated == 0:
                _degradation_reasons.append(
                    f"zero cross-layer corroboration ({_technique_count} claimed "
                    f"technique{'s' if _technique_count != 1 else ''})"
                    if _technique_count > 0
                    else "no techniques claimed (no corroborating evidence)"
                )
                if _rule_only:
                    _degradation_reasons.append(
                        f"{_rule_only} rule match{'es' if _rule_only != 1 else ''} carry "
                        "technique tags no analyst claimed"
                    )
            # A missing sandbox report is itself a
            # degradation, and it was the one cause NOT represented here. With
            # CAPE unreachable ``_submit_to_sandbox`` swallows the error and
            # returns None, so the run silently becomes static-only; the
            # anti-emulation reason below cannot fire either because it needs a
            # sandbox report to inspect. If static analysis alone corroborated a
            # technique, ``degraded_mode`` stayed False and an uncapped
            # confidence shipped for a verdict formed without any dynamic
            # evidence. Verified live: the only operator signal was a single
            # "Sandbox submission failed" line in the worker log.
            _no_sandbox = sandbox_degradation_reason(state.get("sandbox_report"))
            if _no_sandbox:
                _degradation_reasons.append(_no_sandbox)
            # A container we accept but cannot open. A .docm reaches here
            # legitimately — macro documents are among the commonest Windows
            # carriers, so rejecting them would be wrong — but the only analysis
            # it receives is a raw-byte string sweep, and without this the report
            # renders a confident verdict over an unread payload.
            try:
                from maljan.extractors.sample_identity import unparsed_container_reason

                _container_reason = unparsed_container_reason(
                    state.get("sample_path"), state.get("evidence_ledger")
                )
                if _container_reason:
                    _degradation_reasons.append(_container_reason)
            except Exception as _e:  # noqa: BLE001
                logger.debug("container-format check skipped (%s)", _e)
            # A tool server an operator added is never the evidence a verdict
            # rests on, so it degrades rather than failing — but the reader of
            # the report is entitled to know the judge ran without its
            # threat-intel lookups.
            _degradation_reasons.extend(
                reason
                for reason in container.server_degradation_reasons()
                if reason_applies_to_format(reason, str(state.get("file_type") or ""))
            )
            if _failed_analysts:
                _degradation_reasons.append(f"analyst failures: {', '.join(_failed_analysts)}")
            if _empty_analysts:
                _degradation_reasons.append(
                    f"analysts produced no claims: {', '.join(_empty_analysts)}"
                )
            # Technique claims the analyst kept after being asked to cite the
            # entry it read them from. A live run put sixteen of these in front
            # of the judge, which read them as sixteen techniques.
            _ungrounded_note = ungrounded_technique_note(state.get("validation_findings"))
            if _ungrounded_note:
                _degradation_reasons.append(_ungrounded_note)
            # A run whose grounding could not search its own whole record says
            # so as a run fact. Every absence it stated is a note, and an
            # operator reading the verdict should know that before reading the
            # indicators.
            # Only when there was something to ground against: a run whose
            # ledger is empty grounded nothing, and saying its corpus was
            # partial would be a reason about a check that never ran.
            if _ledger or corpus_state.missing_answers:
                _corpus_note = partial_grounding_reason(corpus_state)
                if _corpus_note:
                    _degradation_reasons.append(_corpus_note)
            # A check that could not run is a fact about the run, not a
            # finding about the sample: it is said here and listed under
            # ``validation.not_run``.
            _not_run = {str(code) for code in (state.get("validation_not_run") or [])}
            # The judge's own bundle check asks the same catalogue; when it
            # cannot be read the judge's attack-patterns went unchecked too.
            if not validity_check_available(_knowledge_module()):
                _not_run.add(VALIDITY_CODE)
            for _code in sorted(_not_run):
                _degradation_reasons.append(not_run_sentence(_code))
            if _anti_emu_hits:
                _short = _anti_emu_hits[0]
                _suffix = f" (+{len(_anti_emu_hits) - 1} more)" if len(_anti_emu_hits) > 1 else ""
                _degradation_reasons.append(
                    f"sandbox detected anti-emulation behaviour: {_short}{_suffix}"
                )
            # A pack tool that did not answer is an absence the judge is told
            # about; only the identity tools, or the pack itself, failing makes
            # the run degraded on their own. Everything that is not the pack's
            # keeps the weight it always had.
            _degraded_mode = run_is_degraded(_degradation_reasons)
            if _degraded_mode:
                logger.warning("Degraded run detected (%s).", "; ".join(_degradation_reasons))

            # The degradation, said to the judge in the prompt. What used to
            # happen instead was a fixed ceiling applied to the finished number
            # in the report node, which told the reader the confidence was
            # capped and told the judge nothing at all. The pack's tokens are
            # rendered as sentences here and stay tokens in the run summary.
            degradation_note = ""
            if _degradation_reasons:
                _sentences = "; ".join(reason_sentence(r) for r in _degradation_reasons)
                degradation_note = (
                    (
                        f"RUN QUALITY — this analysis is degraded because {_sentences}. "
                        "Weigh your confidence accordingly: a verdict drawn from thin "
                        "evidence should say so in its numbers, not only in its prose."
                    )
                    if _degraded_mode
                    else (
                        f"RUN QUALITY — {_sentences}. The rest of the pack ran; read a "
                        "missing tool as an absence of that evidence, not as a finding."
                    )
                )

            verdict = await judge.give_verdict(
                reports=reports,
                history=state.get("discussion_history") or [],
                isr_reports=isr_reports,
                evidence_summary=evidence_summary,
                degradation_note=degradation_note,
                memory_store=memory_store,
                evidence_corpus=evidence_corpus or None,
                # Which of those answers reached the corpus with rows missing.
                # The judge is not told a different rule, it is told which call
                # to narrow before it withdraws a value.
                shortened_tools=shortened_tools,
                # What the run's tools answered, as the answers they are, and
                # whether that is this run's whole record. When it is not, an
                # absence is a note and nothing is dropped for it.
                searched=seen,
                corpus_state=corpus_state,
                current_sample_id=state.get("file_hash"),
                sample=_sample_identity(state),
                # What the run recorded, so a verdict that says the sample is
                # clean can be asked which entry says so.
                ledger_ids=[entry.id for entry in _ledger],
                facts_block=pack_text(state, container),
                run_state=render_run_state(state),
                # Who named which technique — the evidence summary as data —
                # so a relationship crediting an agent with a technique it never
                # named can be asked about.
                technique_sources={
                    tid: [source for source, _confidence in rows]
                    for tid, rows in collect_technique_sources(isr_reports, _ledger).items()
                },
            )
            # A verdict the judge never expressed as a bundle is the thinnest
            # answer this pipeline can produce — no severity, no reasoning the
            # model stands behind — and before this it reached the reader as an
            # ordinary verdict with a slightly emptier STIX object.
            _verdict_codes = {v.code for v in verdict.violations}
            if VERDICT_FALLBACK_CODE in _verdict_codes:
                _degradation_reasons.append(VERDICT_FALLBACK_REASON)
                _degraded_mode = True
            if VERDICT_TIMEOUT_CODE in _verdict_codes:
                _degradation_reasons.append(VERDICT_TIMEOUT_REASON)
                _degraded_mode = True

            bundle = verdict.bundle
            stix_output: dict[str, Any] = bundle.model_dump() if isinstance(bundle, Bundle) else {}
            decision = decide_from_bundle(bundle) if isinstance(bundle, Bundle) else "Suspicious"
            # A verdict the judge wrote in a word this pipeline cannot read is
            # published as the inconclusive one, and the judge's own word goes
            # with it: the header prints the degradation reasons directly under
            # the verdict, so the two are read together.
            _unreadable = unrecognised_verdict_reason(bundle) if isinstance(bundle, Bundle) else ""
            if _unreadable:
                _degradation_reasons.append(_unreadable)
                _degraded_mode = True
            # An empty bundle over an empty run is not a clean sample. The
            # judge emitted no malware object because there was nothing to
            # emit one from -- no tool call was recorded and no analyst
            # claimed anything -- and reporting that as Benign is a false
            # negative with a confidence number attached.
            decision, _inconclusive = verdict_for_run(
                decision, evidence_entries=_ledger, isr_reports=isr_reports
            )
            if _inconclusive:
                _degradation_reasons.append(_inconclusive)
                _degraded_mode = True

            # A verdict the judge expressed as text, or never expressed at
            # all, is not a verdict a model put a confidence on. The bundle
            # itself says when it is one this pipeline built, and that mark is
            # what is asked: keying off the violation codes missed the bundle
            # built from JSON that was not a bundle, and the report then
            # printed a confidence averaged from the analysts' own claims
            # beside a verdict no judge expressed. It travels on the same
            # channel a judge that raised uses, so the report node has one
            # question to ask; ``recorded`` says the violation is already among
            # the leftovers below, so the summary is not told twice.
            _verdict_fallback: dict[str, Any] | None = None
            _stated = bundle.x_maljan_fallback_verdict if isinstance(bundle, Bundle) else None
            _recorded = bool(_verdict_codes & {VERDICT_FALLBACK_CODE, VERDICT_TIMEOUT_CODE})
            if _stated is not None or _recorded:
                _verdict_fallback = {
                    "decision": decision,
                    "failure": (
                        VERDICT_TIMEOUT_CODE
                        if VERDICT_TIMEOUT_CODE in _verdict_codes
                        else VERDICT_FALLBACK_CODE
                    ),
                    # Whether the judge's own row is already among the
                    # leftovers, asked of them rather than assumed: a bundle
                    # that carries the mark and no code would otherwise leave
                    # the summary with nothing at all to say about it.
                    "recorded": _recorded,
                }

            # What the analysts and the judge were told and did not fix. Both
            # are recorded rather than resolved, and both are what
            # ``run_summary.validation`` is made of.
            _unresolved: list[tuple[str, Violation]] = [
                (name, violation)
                for name, entries in (state.get("validation_findings") or {}).items()
                for violation in _violations_from_rows(entries)
            ]
            _retries = int(state.get("validation_retries") or 0) + verdict.retries
            _unresolved.extend(("judge", violation) for violation in verdict.violations)
            # And what every producer was *shown*. A code the retry fixed is
            # invisible in the leftovers, which is how ``by_code`` came to read
            # ``{}`` beside a run that had spent a retry on ``verdict.not_json``.
            _fed_back: dict[str, int] = dict(state.get("validation_fed_back") or {})
            for _code, _count in (verdict.fed_back or {}).items():
                _fed_back[_code] = _fed_back.get(_code, 0) + int(_count)

            run_summary_dict = None
            try:
                max_iters = container.config.negotiation.max_iterations
                negotiation_state = {
                    "confidence_history": state.get("confidence_history") or [],
                    "iteration_count": state.get("iteration_count", 0),
                    "is_consensus": state.get("is_consensus", False),
                    "consensus_applicable": state.get("consensus_applicable", True),
                    "sycophancy_detected": state.get("sycophancy_detected", False),
                    "discussion_history": state.get("discussion_history") or [],
                }
                summary = (
                    RunSummaryBuilder(start_time=start_time)
                    .set_sample(state.get("file_hash", ""), state.get("file_name"))
                    .set_verdict(decision, len(bundle.objects) if isinstance(bundle, Bundle) else 0)
                    .set_negotiation(negotiation_state, max_iterations=max_iters)
                    .set_isr_stats(isr_reports, no_data=_no_data_analysts)
                    .set_validation(
                        validation_metrics(
                            _retries, _unresolved, _fed_back, not_run=sorted(_not_run)
                        )
                    )
                    .set_corroboration(_corroboration)
                    .set_degraded_mode(_degraded_mode, _degradation_reasons)
                    .set_failed_analysts(_failed_analysts)
                    .set_profile(
                        container.config.agents.profile,
                        _analyst_keys,
                        [k for k in _analyst_keys if k not in BUILTIN_AGENTS],
                    )
                    .set_stages(
                        stage_rollup(
                            container,
                            state,
                            _verdict_record(verdict_stage, started, ran=True).get("stage_results"),
                        )
                    )
                    .set_token_usage(container.get_token_ledger().snapshot())
                    .set_server_rests(container.server_rests())
                    .set_generation(_generation_snapshot(container))
                    .set_truncation(_truncation_snapshot(container))
                    .set_triage(_triage_facts)
                    .set_sandbox(state.get("sandbox_report"))
                    .set_nudge(state.get("nudge_retry_modes") or {})
                    .set_budget(state.get("budget_records") or {})
                    .set_tool_latency(state.get("evidence_ledger") or [])
                    .build()
                )
                run_summary_dict = summary.to_dict()
                # How the verdict above was arrived at, as one word a consumer
                # can branch on. The degradation reasons already say it in a
                # sentence, and a sentence is not something an API client or a
                # console can read: `Suspicious` with no confidence is the
                # judge's own conclusion on one run and "the judge's answer
                # could not be read" on the next, and only this tells them
                # apart.
                run_summary_dict["verdict_reading"] = (
                    verdict_reading(bundle) if isinstance(bundle, Bundle) else VERDICT_READ_FALLBACK
                )
                logger.info(
                    "RunSummary built: verdict=%s, rounds=%d, techniques=%d, "
                    "validation retries=%d, unresolved=%d",
                    decision,
                    summary.negotiation.rounds_completed,
                    _technique_count,
                    _retries,
                    len(_unresolved),
                )
            except Exception as exc:
                logger.warning("RunSummary build failed (%s). Skipping.", exc)

            if memory_store is not None and isr_reports:
                # Quality gate: skip the upsert
                # when the run is clearly degraded (no corroboration, no
                # techniques, failed analysts, etc.). A polluted entry
                # poisons future analyses via the few-shot prior block.
                _ltm_skip_reason: str | None = None
                if _corroborated == 0 and _technique_count <= 1:
                    _ltm_skip_reason = (
                        f"thin evidence: corroborated={_corroborated}, "
                        f"techniques={_technique_count}"
                    )
                elif _failed_analysts:
                    _ltm_skip_reason = f"analyst failures: {', '.join(_failed_analysts)}"
                elif state.get("iteration_count", 0) == 0 and not state.get("is_consensus", False):
                    _ltm_skip_reason = "no negotiation rounds completed"

                if _ltm_skip_reason is not None:
                    logger.info(
                        "LTM: skipping store for '%s' (reason: %s).",
                        state.get("file_hash", "unknown")[:16],
                        _ltm_skip_reason,
                    )
                else:
                    try:
                        # The judge's own category, or nothing. A keyword
                        # classifier used to fill this in over the judge's head
                        # and the stored case then taught the next run its guess.
                        category = _assessed_category(bundle) or "unknown"
                        case = build_stored_case(
                            sample_id=state.get("file_hash", "unknown"),
                            isr_reports=isr_reports,
                            stix_bundle_json=(
                                bundle.model_dump_json() if isinstance(bundle, Bundle) else ""
                            ),
                            malware_category=category,
                            corroborated_count=_corroborated,
                            total_techniques=_technique_count,
                            has_analyst_errors=bool(_failed_analysts),
                        )
                        memory_store.store(case)
                        logger.info(
                            "LTM: stored case '%s' (category=%s, techniques=%d).",
                            case.sample_id,
                            case.malware_category,
                            len(case.technique_ids),
                        )
                    except Exception as e:
                        logger.warning(
                            "LTM store failed (%s). Analysis result is unaffected.",
                            e,
                        )

            # Function-hash attribution (deterministic, exact opcode-hash).
            # Read side: which known families this sample shares code with
            # (threaded into the report). Write side: upsert this sample's
            # function hashes under its inferred family so the corpus grows.
            # Fully gated + fail-safe; never affects the verdict.
            _func_hash_report: list[dict[str, Any]] = []
            _family_rag_report: list[dict[str, Any]] = []
            try:
                from maljan.core.config import get_settings

                _cfg = get_settings()
                _provider = container.get_static_provider()
                _static_path = state.get("static_sample_path")
                if (
                    _cfg.preprocessing.use_function_hash_attribution
                    and _provider.capabilities.provides_function_hashes
                    and _cfg.memory.backend == "qdrant"
                    and _static_path
                ):
                    from maljan.analysis.function_hash_attribution import (
                        aggregate_matches,
                        to_report_dicts,
                    )
                    from maljan.memory.function_hash_store import FunctionHashStore
                    from maljan.providers.base import StaticJobContext

                    _sample_id = state.get("file_hash", "") or ""
                    _funcs = _provider.function_hashes(
                        StaticJobContext(mirror_sample_path=str(_static_path))
                    )
                    if _funcs:
                        _fh_store = FunctionHashStore(
                            url=_cfg.memory.qdrant_url,
                            collection=_cfg.memory.qdrant_function_hash_collection,
                            api_key=(
                                _cfg.memory.qdrant_api_key.get_secret_value()
                                if _cfg.memory.qdrant_api_key
                                else None
                            ),
                        )
                        # Read side: surface prior family overlap in the report.
                        _func_hash_report = to_report_dicts(
                            aggregate_matches(
                                _fh_store.match(
                                    [h for _n, h in _funcs],
                                    exclude_sample_id=_sample_id or None,
                                ),
                                max_families=_cfg.preprocessing.function_hash_max_matches,
                            )
                        )
                        # Write side: only persist under a grounded family so an
                        # UNKNOWN verdict cannot pollute the attribution corpus.
                        _family = _assessed_family(bundle)
                        if _family:
                            _fh_store.upsert_sample(_sample_id, _family, _funcs)
            except Exception as _e:
                logger.warning("Function-hash attribution skipped (%s). Verdict unaffected.", _e)

            # Family-feature RAG (read side): record the families retrieved by
            # static-feature similarity as report evidence. Reads the HOST binary
            # (pe_extractor), so it uses ``sample_path`` (not the container path).
            # LLM-centric: these are candidates the analyst weighed, not a verdict.
            # Fail-safe and gated OFF by default (no catalog -> no rows).
            try:
                from maljan.core.config import get_settings as _get_settings

                _cfg2 = _get_settings()
                _host = state.get("sample_path")
                if _cfg2.preprocessing.use_family_feature_rag and _host:
                    from maljan.analysis.family_feature_rag import (
                        build_sample_profile_text,
                        retrieve_candidates,
                    )
                    from maljan.analysis.family_feature_rag import (
                        to_report_dicts as _rag_to_report_dicts,
                    )
                    from maljan.core.paths import resolve_data
                    from maljan.extractors.pe_extractor import build_static_analysis
                    from maljan.memory.family_fingerprint_index import load_family_index

                    _static = build_static_analysis(sample_path=str(_host))
                    # resolve_data, not the raw config string: the default is the
                    # relative "data/family_fingerprints_v1.json", which otherwise
                    # resolves against the process CWD rather than the repo root.
                    _index = load_family_index(
                        str(resolve_data(_cfg2.preprocessing.family_fingerprint_catalog_path))
                    )
                    if _static is not None and _index is not None:
                        _cands = retrieve_candidates(
                            build_sample_profile_text(_static),
                            _index,
                            top_k=_cfg2.preprocessing.family_rag_top_k,
                            min_score=_cfg2.preprocessing.family_rag_min_score,
                        )
                        _family_rag_report = _rag_to_report_dicts(_cands)
            except Exception as _e:
                logger.warning("Family-feature RAG skipped (%s). Verdict unaffected.", _e)

            emit_agent_message(
                container.event_sink,
                speaker=JUDGE_AGENT_KEY,
                display_name=label_of(container, JUDGE_AGENT_KEY),
                role="judge",
                text=(
                    f"Verdict: {decision}."
                    + (
                        " Run flagged as degraded — "
                        + "; ".join(_degradation_reasons)
                        + ". The judge was told this and set its confidence knowing it."
                        if _degraded_mode
                        else f" {_corroborated} technique(s) named by more than one source."
                    )
                ),
                round_index=state.get("iteration_count", 0),
                status="complete",
                stage=stage_key_of(verdict_stage, "verdict"),
                # The line that closes the conversation, which the console
                # draws as a full-width card rather than as another bubble.
                kind="verdict",
            )

            return _closing(
                {
                    **_verdict_record(verdict_stage, started, ran=True),
                    "final_decision": decision,
                    "judge_report": "Analyzed negotiation history and expert reports.",
                    "stix_output": stix_output,
                    # The map from each label the judge wrote to the id it was
                    # published under, kept with the judge's own bundle.
                    "stix_labels": dict(verdict.labels),
                    "stix_written": verdict.written,
                    # Set when the judge's answer was not the verdict it was
                    # asked for — text, or nothing at all. Written rather than
                    # left alone: the verdict stage runs once today, and a
                    # channel that is only ever set would suppress a real
                    # confidence the first time it is not.
                    "verdict_fallback": _verdict_fallback,
                    "run_summary": run_summary_dict,
                    # The judge's own tool calls — threat intel on a disputed
                    # indicator, a knowledge lookup — on the same append-only
                    # channel the analysts use, so a verdict that leans on one can
                    # cite it and the citation resolves.
                    "evidence_ledger": _judge_evidence(),
                    **_judge_budget(container),
                    "isr_reports": isr_reports,
                    # Surface the degraded-mode signal to the report
                    # node and downstream consumers (API/dashboard).
                    "degraded_mode": _degraded_mode,
                    "degradation_reasons": _degradation_reasons,
                    # Exact opcode-hash family overlap, surfaced into the report's
                    # FamilyAttribution.function_hash_matches by the report node.
                    "function_hash_matches": _func_hash_report,
                    # Family-feature RAG candidates (retrieved by static-feature
                    # similarity), surfaced into FamilyAttribution.family_rag_candidates
                    # by the report node. Empty unless the RAG is enabled with a catalog.
                    "family_rag_candidates": _family_rag_report,
                }
            )
        except Exception as e:  # noqa: BLE001 — per-run fault-isolation boundary
            # give_verdict() drives the LLM; on a constrained / local host it can
            # fail with a bare asyncio TimeoutError or a transient openai
            # APIConnectionError as well as AnalystError / LLMError. A failed final
            # verdict must degrade to a conservative "Suspicious" result, not abort
            # the run (and, in a batch eval, drop the whole sample).
            logger.error("Judge verdict %s: %s", type(e).__name__, e or "")
            emit_agent_message(
                container.event_sink,
                speaker=JUDGE_AGENT_KEY,
                display_name=label_of(container, JUDGE_AGENT_KEY),
                role="judge",
                # The class of the failure and nothing else. The log above
                # carries the exception's own words for an operator; this line
                # goes to every reader of the run, and an exception's text can
                # carry a path, a host or a credential.
                text=(
                    f"[ERROR] Judge failed ({describe_exception(e)}). "
                    "Falling back to a conservative Suspicious verdict; the run is "
                    "marked degraded and the report says why."
                ),
                round_index=state.get("iteration_count", 0),
                status="failed",
                stage=stage_key_of(verdict_stage, "verdict"),
            )
            # The verdict below is written by this pipeline, not decided by a
            # model, and it says so: ``verdict_fallback`` tells the report node
            # that no judge answered, which is what stops a confidence being
            # derived from the analysts' own claims and attached to a verdict
            # none of them reached. The run is also flagged degraded, which is
            # what draws the DEGRADED banner.
            return _closing(
                {
                    **_verdict_record(
                        verdict_stage,
                        started,
                        ran=True,
                        reason=f"judge failed ({type(e).__name__})",
                    ),
                    "final_decision": "Suspicious",
                    "judge_report": f"[ERROR] Judge failed ({describe_exception(e)}).",
                    "stix_output": {},
                    "verdict_fallback": {
                        "decision": "Suspicious",
                        # The class of the failure and nothing else; the same
                        # rule the published line above follows.
                        "failure": describe_exception(e),
                    },
                    "degraded_mode": True,
                    "degradation_reasons": [f"judge failed ({type(e).__name__})"],
                    "evidence_ledger": _judge_evidence(),
                    **_judge_budget(container),
                }
            )

    node_fn.__name__ = "judge_node"
    return node_fn


# ---------------------------------------------------------------------------
# Report node — assembles the comprehensive MalwareReport
# ---------------------------------------------------------------------------


def make_report_node(
    container: ServiceContainer,
    *,
    stage: Any = None,
    announces: bool = True,
    finishes: tuple[str, ...] = (),
) -> Any:
    """Factory: builds the final ``MalwareReport`` and renders markdown + STIX.

    Runs after the judge node. The narrative LLM round and the auto-generated
    detection signatures are added in later phases; for now we ship a
    deterministic fallback narrative so the report never leaves a consumer
    with empty prose.
    """

    async def node_fn(state: AnalysisState) -> dict[str, Any]:
        try:
            cfg = container.config.reporting
        except AttributeError:
            cfg = None

        # Feature flag: when reporting is disabled we leave the new state
        # fields untouched so downstream consumers see ``None`` and fall back
        # to ``judge_report`` / ``stix_output``.
        if cfg is not None and not cfg.enabled:
            return {}

        started = time.monotonic()
        announce_finished(
            container, state, tuple(k for k in finishes if stage is None or k != stage.key)
        )
        if stage is not None:
            runs, skip_reason = stage_runs(stage, state)
            if not runs:
                if announces:
                    announce_skipped(container, stage, skip_reason)
                return _verdict_record(stage, started, ran=False, reason=skip_reason)
            if announces:
                announce_started(container, stage)

        from maljan.reporting.builder import MalwareReportBuilder
        from maljan.reporting.renderers import ExtendedSTIXRenderer, MarkdownRenderer
        from maljan.schemas.stix_models import Bundle

        isr_reports = dict(state.get("isr_reports") or {})

        report_sample_platform = state.get("platform") or "unknown"

        run_summary_state = state.get("run_summary") or {}

        # Severity, category and family come off the judge's bundle. Nothing
        # here computes them: a report that cannot say what the judge decided
        # says "not assessed" rather than substituting an arithmetic.
        _bundle_assessment = None
        try:
            _judge_bundle = state.get("stix_output") or {}
            if isinstance(_judge_bundle, dict) and _judge_bundle.get("x_maljan_assessment"):
                from maljan.schemas.judgement import JudgeAssessment

                _bundle_assessment = JudgeAssessment.model_validate(
                    _judge_bundle["x_maljan_assessment"]
                )
        except Exception as exc:  # noqa: BLE001 — an unreadable assessment is "not assessed"
            logger.warning("report_node: the judge's assessment could not be read (%s).", exc)
        malware_category = getattr(_bundle_assessment, "malware_category", None)

        # And so does the confidence, from the same block and from nowhere
        # else. It used to be the negotiation's mean over *every* analyst, with
        # a skipped one counted as a zero: one analyst at 0.50 beside two that
        # never ran produced 0.167 on the front page of a "Malware" verdict.
        # Narrowing that to the analysts who did claim something left a number
        # that still belonged to their claims rather than to the verdict. The
        # judge's own number is the verdict's, and a verdict the judge put no
        # number on is published with none; see ``_overall_confidence``.
        _fallback = state.get("verdict_fallback") or None
        overall_confidence = _overall_confidence(_bundle_assessment, judged=not _fallback)

        # A degraded run is not capped here. It is said to the judge in the
        # verdict prompt and printed in the report header, and the confidence
        # is whatever the run actually reached — a number silently pulled down
        # to 0.60 told the reader the same thing for every kind of thinness.

        discussion_history = [
            arg.model_dump() if hasattr(arg, "model_dump") else dict(arg)
            for arg in (state.get("discussion_history") or [])
        ]

        # Evidence-only static providers (capa_yara) have no ISR and no tool
        # loop, so nothing writes their passes to the evidence ledger as they
        # run. The bundle is collected once here, turned into ledger entries
        # below, and its rendered tables still reach the Composer through
        # ``report.technical_evidence``. Best-effort — a provider failure here
        # must never fail the report.
        _static_bundle = None
        try:
            _static_provider = container.get_static_provider()
            _sample_for_evidence = state.get("sample_path")
            # When the triage pack ran capa or YARA, their entries are already
            # in the ledger under the pipeline; running the provider again
            # would pay capa's budget twice and record the pair twice.
            if rules_already_recorded(state.get("evidence_ledger") or []):
                logger.info(
                    "report_node: the triage pack recorded capa/YARA; the static provider is "
                    "not run again."
                )
            elif _static_provider.capabilities.provides_evidence and _sample_for_evidence:
                # capa is a subprocess with a 900s budget and YARA is a corpus
                # scan; both are synchronous, and this is the report phase the
                # worker's heartbeat went quiet in.
                _static_bundle = await asyncio.to_thread(
                    _static_provider.collect_evidence, str(_sample_for_evidence)
                )
        except Exception as exc:  # noqa: BLE001 - evidence must never fail a report
            logger.warning(
                "report_node: static evidence collection failed (%s: %s); continuing without it.",
                type(exc).__name__,
                exc,
            )
            _static_bundle = None

        # The run's evidence, in the order the ids were issued, plus the
        # entries the evidence-only static provider could not write itself.
        _ledger: list[LedgerEntry] = []
        for _row in state.get("evidence_ledger") or []:
            try:
                _ledger.append(LedgerEntry.model_validate(_row))
            except Exception as exc:  # noqa: BLE001 — one bad row is not a lost report
                logger.debug("report_node: unreadable ledger row skipped (%s).", exc)
        # The entries the evidence-only static provider could not write itself.
        # They go back onto the state channel below, not only into this local
        # list: the report cites their ids, and a citation the evidence
        # endpoint cannot resolve is worse than no citation.
        _capa_entries: list[LedgerEntry] = []
        if _static_bundle is not None:
            try:
                from maljan.providers.static.capa_yara import ledger_entries

                _capa_entries = ledger_entries(
                    _static_bundle,
                    container.get_evidence_counter(),
                    stage.key if stage is not None else "analysis",
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("report_node: capa/YARA evidence not recorded (%s).", exc)
        _ledger.extend(_capa_entries)
        _ledger.sort(key=lambda entry: entry.seq)

        try:
            builder = MalwareReportBuilder(
                file_hash=state.get("file_hash"),
                file_name=state.get("file_name"),
                sample_path=state.get("sample_path"),
                sandbox_report=state.get("sandbox_report"),
                reports=state.get("reports"),
                isr_reports=isr_reports,
                stix_output=state.get("stix_output"),
                run_summary=run_summary_state,
                discussion_history=discussion_history,
                final_decision=state.get("final_decision") or "Suspicious",
                overall_confidence=overall_confidence,
                judge_assessment=_bundle_assessment,
                malware_category=malware_category,
                # Degraded-run signalling: surfaced as a banner so a numerically
                # high verdict/severity on a low-data run is not read as authoritative.
                degraded_mode=bool(state.get("degraded_mode")),
                # Corrected against the whole ledger: the evidence-only static
                # provider's entries are collected above, after the verdict
                # stage read the ledger, so a run that carries them must not
                # ship a report saying no analysis was performed.
                degradation_reasons=corrected_reasons(state.get("degradation_reasons"), _ledger),
                # The routing minimum, which stands in for the identity block
                # when no agent called an identification tool.
                sample_platform=state.get("platform"),
                sample_file_type=state.get("file_type"),
                evidence_ledger=_ledger,
            )
            # Deterministic and self-contained — every input is already in the
            # builder — so a thread changes when it runs, never what it
            # produces. It walks every section of every report, which on a
            # full run is the other half of the report node's loop time.
            report = await asyncio.to_thread(builder.build_deterministic)
            # Thread the judge node's exact opcode-hash family overlap into the
            # report (deterministic code-reuse links). Best-effort post-build,
            # mirroring how ``similar_samples`` is populated in enrichment.
            _fh_matches = cast("list[dict[str, Any]]", state.get("function_hash_matches") or [])
            if _fh_matches and getattr(report, "attribution", None) is not None:
                report.attribution.function_hash_matches = _fh_matches
            # Same post-build threading for the family-feature RAG candidates.
            _rag_cands = cast("list[dict[str, Any]]", state.get("family_rag_candidates") or [])
            if _rag_cands and getattr(report, "attribution", None) is not None:
                report.attribution.family_rag_candidates = _rag_cands
            # Attach the captured tool-loop evidence so
            # the Composer can ground the deep technical spine. Already size-
            # capped upstream (schemas.tool_evidence); stored verbatim here.
            _tool_ev = cast(
                "dict[str, list[dict[str, Any]]]", dict(state.get("tool_evidence") or {})
            )
            # capa/YARA text has no ReAct tool call behind it, so it is wrapped
            # in the same ``CapturedToolOutput`` row shape (schemas.tool_evidence)
            # the analyst node emits, under its own agent id, and appended
            # rather than replacing anything already captured for that id.
            if _static_bundle is not None and _static_bundle.technical_evidence:
                for _agent, _text in _static_bundle.technical_evidence.items():
                    _rows = list(_tool_ev.get(_agent) or [])
                    _rows.append(
                        {
                            "agent_id": _agent,
                            "tool_name": _agent,
                            "args": {},
                            "symbol": None,
                            "output": _text,
                            "seq": 0,
                        }
                    )
                    _tool_ev[_agent] = _rows
            if _tool_ev:
                report.technical_evidence = _tool_ev
        except Exception as exc:  # noqa: BLE001
            logger.error("report_node: deterministic build failed (%s).", exc, exc_info=True)
            return {"report_error": f"{type(exc).__name__}: {exc}"}

        # What the report is standing on, counted. ``sections_without_evidence``
        # is the number that matters: a section that can name neither a ledger
        # entry nor the finding it came from is ungrounded, and a run where
        # that number is not zero has a defect worth seeing rather than a
        # report worth reading.
        _summary = dict(report.run_summary or {})
        _summary["evidence"] = evidence_summary(_ledger)
        if _fallback and not _fallback.get("recorded"):
            # The run summary says the same thing the report header says: this
            # verdict has no model behind it. A judge that answered with
            # something other than a bundle has already recorded its own
            # unresolved finding, so that one is not written a second time.
            _summary["validation"] = with_verdict_fallback(
                _summary.get("validation"), str(_fallback.get("failure", "") or "unknown")
            )
        _summary["sections_without_evidence"] = sum(
            1 for section in report.sections if not section_is_grounded(section)
        )
        report.run_summary = _summary
        if _summary["sections_without_evidence"]:
            logger.warning(
                "report_node: %d report section(s) carry no evidence id and no source.",
                _summary["sections_without_evidence"],
            )

        # Narrative LLM round. NarrativeAgent is None in mock mode;
        # also returns None when the structured-output and manual-parse
        # fallbacks both fail. In every "no narrative" branch we apply the
        # deterministic template so the report never ships with empty prose.
        # What the report's own two LLM rounds were told was wrong with their
        # answers. They run after the judge built the run summary, so the
        # summary's ``validation`` block is amended here rather than there.
        _report_tally = ValidationTally()
        # Each ledger entry's text as the run holds it, read once for both
        # report rounds: a value their prose quotes is looked for in the entry
        # it cites, and the composer is shown which entries hold what the
        # analysts' claims quote.
        _entry_texts = _report_entry_texts(container, _ledger)

        narrative_dict: dict[str, Any] | None = None
        # Why no summary was written, when none is: said where the summary
        # would have been, because the platform no longer writes one itself.
        no_summary_because = "no report model ran in this run"
        try:
            narrative_agent = container.get_narrative_agent()
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: NarrativeAgent unavailable (%s); using fallback.", exc)
            narrative_agent = None
            no_summary_because = f"the report model was unavailable ({type(exc).__name__})"

        # The narrative round is the reporter's first loop: its model list
        # starts at its first model again, with turn deadlines measured against
        # the narrative's own 600 s clock.
        _restart_reporter(
            getattr(narrative_agent, "llm", None), _NARRATIVE_TIMEOUT_SECONDS, container
        )

        if narrative_agent is not None:
            try:
                # Bounded, like every ReportComposer section below it. This
                # await had no deadline of its own, so the only limit was the
                # provider's ``request_timeout`` (1800s) times the three
                # attempts in ``retry_on_connection_error``. Measured live
                # 2026-08-07: the report node went silent at 17:25:54 and did
                # not speak again until 17:55:54, on attempt 1 of 3 — a job
                # that looked alive purely because of the worker heartbeat.
                narrative_output = await asyncio.wait_for(
                    narrative_agent.generate(
                        report,
                        state.get("isr_reports"),
                        facts_block=pack_text(state, container),
                        run_state=render_run_state(state),
                        citable_ids=ledger_ids(state),
                        evidence=_entry_texts,
                    ),
                    timeout=_NARRATIVE_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                logger.error(
                    "report_node: NarrativeAgent exceeded %ds; using fallback narrative.",
                    _NARRATIVE_TIMEOUT_SECONDS,
                )
                narrative_output = None
                no_summary_because = (
                    f"the report model did not answer within {_NARRATIVE_TIMEOUT_SECONDS}s"
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: NarrativeAgent.generate raised (%s); using fallback.",
                    exc,
                )
                narrative_output = None
                no_summary_because = f"the narrative round failed ({type(exc).__name__})"
            else:
                no_summary_because = (
                    "the report model's answer did not fit its schema after its retry"
                )
            if narrative_output is not None:
                narrative_dict = narrative_output.model_dump(mode="json")
            _report_tally.merge(getattr(narrative_agent, "validation_tally", ValidationTally()))

        if narrative_dict is not None:
            report = MalwareReportBuilder.apply_narrative(report, narrative_dict)
            logger.info(
                "report_node: narrative LLM round succeeded (summary_chars=%d, "
                "key_findings=%d, recs=%d).",
                len(report.executive_summary),
                len(report.key_findings),
                len(report.defensive_recommendations),
            )
        else:
            report = MalwareReportBuilder.apply_fallback_narrative(report, no_summary_because)

        # Section-wise Composer authors the professional
        # spine (background, execution flow, technical-analysis subsections by
        # capability, configuration, commands, C2 channels),
        # each grounded in its isolated evidence bundle. Best-effort — a Composer
        # failure never blocks the report. None in mock / when composer disabled.
        try:
            composer = container.get_report_composer()
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: ReportComposer unavailable (%s); skipping spine.", exc)
            composer = None
        if composer is not None:
            # The composer sections are its second: the list starts over, and
            # each turn is measured against one section's clock. A slow
            # narrative that moved the list does not decide the sections.
            _restart_reporter(
                getattr(composer, "llm", None),
                getattr(container.config.reporting, "composer_per_section_timeout", None),
                container,
            )
            try:
                await composer.compose(
                    report,
                    state.get("isr_reports"),
                    facts_block=pack_text(state, container),
                    run_state=render_run_state(state),
                    citable_ids=ledger_ids(state),
                    evidence=_entry_texts,
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: ReportComposer.compose raised (%s); spine skipped.", exc
                )
            _report_tally.merge(getattr(composer, "validation_tally", ValidationTally()))
            # What the spine lost, said where the report says what it is
            # missing. A section dropped after its retries used to leave the
            # report with no conclusion and no sentence about it anywhere.
            for _reason in getattr(composer, "degradations", None) or []:
                if _reason not in report.degradation_reasons:
                    report.degradation_reasons.append(str(_reason))

        # Deterministic figures (inline SVG + Ghidra
        # code listings) generated from the report's own data — real charts, no
        # fabricated screenshots. Best-effort; empty when data is absent.
        try:
            from maljan.reporting.figures import build_figures

            report.figures = build_figures(report)
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: figure generation failed (%s).", exc)

        # Detection signatures — template-based YARA/Sigma/Suricata
        # generation. Runs after narrative so the LLM-written family name can
        # influence rule metadata. Disabled via config when desired.
        if cfg is None or cfg.auto_generate_detection_rules:
            try:
                report = MalwareReportBuilder.attach_detection_signatures(report)
                logger.info(
                    "report_node: detection rules generated (count=%d, errors=%d).",
                    len(report.detection_signatures),
                    sum(1 for r in report.detection_signatures if r.compile_error),
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("report_node: detection rule generation failed (%s).", exc)

        extended_dump: dict[str, Any] | None = None
        if cfg is None or cfg.include_extended_stix:
            try:
                base = (
                    Bundle.model_validate(state["stix_output"])
                    if state.get("stix_output")
                    else None
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: judge bundle could not be re-validated (%s). "
                    "Falling back to fresh extended bundle.",
                    exc,
                )
                base = None
            try:
                _renderer = ExtendedSTIXRenderer()
                extended_bundle = _renderer.render(
                    report,
                    base,
                    ledger=container.get_truncation_ledger(),
                    # What the run saw, for the cited entries the byte budget
                    # blanked: the second-source test reads the same record
                    # the judge's grounding check does.
                    corpus=container.get_evidence_corpus(),
                    # Who named which technique, the record the judge's credit
                    # question was asked against: a credit it kept that names
                    # no source is left off the export's copy.
                    technique_sources={
                        tid: [source for source, _confidence in rows]
                        for tid, rows in collect_technique_sources(isr_reports, _ledger).items()
                    },
                    # The ledger entries the record ties to each technique:
                    # the ids a finding naming it cites, and the entries of the
                    # tools that asserted it. Written on the export's edges.
                    technique_evidence=technique_evidence(isr_reports, _ledger),
                    # The run's ledger, in its order: the export writes no id
                    # it does not hold.
                    ledger_ids=[entry.id for entry in _ledger],
                )
                extended_dump = extended_bundle.model_dump(mode="json")
                # What the judge said about a technique the checks rejected
                # went with that technique. Recorded where the run's other
                # unresolved findings are, not counted as a bundle defect: the
                # annotation was sound, the technique it was about was not.
                _note_unlinked_techniques(report, _renderer.unlinked)
                # And what the export declined to carry at all. Recorded the
                # same way and for the same reason: the object is the judge's,
                # the bundle is what a consumer acts on, and a reader is owed
                # the sentence saying which one this run kept.
                _note_export_findings(report, _renderer.declined)
            except Exception as exc:  # noqa: BLE001
                logger.warning("report_node: extended STIX render failed (%s).", exc)
                extended_dump = None

        if extended_dump is not None:
            # D20 fix: rewrite the malware SDO description when the judge
            # emitted a fallback placeholder (timeout / non-JSON output).
            # The fallback writes a stale verdict that cross-layer
            # aggregation may upgrade — STIX consumers should see the
            # FINAL verdict in the user-visible description, not the
            # intermediate ``judge fallback`` text.
            _confidence = (
                "not assessed"
                if report.overall_confidence is None
                else f"{report.overall_confidence:.2f}"
            )
            _final_desc = (
                f"Verdict: {report.verdict} "
                f"(confidence={_confidence}; "
                f"severity={report.severity.rating if report.severity else 'not assessed'})"
            )
            for obj in extended_dump.get("objects", []) or []:
                if obj.get("type") != "malware":
                    continue
                _desc = str(obj.get("description", "")).lower()
                if "judge fallback" in _desc or "verdict pending" in _desc:
                    obj["description"] = _final_desc
                    break

            report.stix_bundle_extended = extended_dump

        # Post-pipeline FP linter. Run after every other
        # mutation has happened (narrative + detection sigs + STIX dump)
        # so the linter sees the exact payload a downstream consumer
        # will see. Findings are merged into ``run_summary`` so the API
        # serialiser ships them without further work.
        try:
            from maljan.qa.fp_linter import lint_report as _lint_report

            fp_warnings = [w.to_dict() for w in _lint_report(report, report_sample_platform)]
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: FP linter raised (%s); continuing.", exc)
            fp_warnings = []

        if fp_warnings:
            logger.warning(
                "FP linter: %d warning(s) — %s",
                len(fp_warnings),
                ", ".join(w["rule"] for w in fp_warnings),
            )
            run_summary_dict = report.run_summary or {}
            run_summary_dict["fp_warnings"] = fp_warnings
            report.run_summary = run_summary_dict

        # Surface ``fp_warnings`` into the
        # pipeline state's ``run_summary`` so the worker writes them to the
        # ``reports.run_summary`` JSONB column. Without this the warnings
        # only landed on ``MalwareReport.run_summary`` (saved to the
        # ``malware_report`` column / ``/full`` endpoint); the UI SUMMARY
        # tab reads from the ``/reports/{id}`` DTO which surfaces the
        # narrower ``run_summary`` column, so the QA WARNINGS banner
        # stayed empty even when the linter had real findings to show.
        #
        # Only override state["run_summary"] when there are warnings to
        # add — leaving it untouched preserves the mock-mode contract
        # (state.run_summary remains None when the judge node skipped
        # RunSummaryBuilder, exercised by test_run_summary_is_none_in_mock_mode).
        _state_summary: dict[str, Any] = {}
        # The block the report carries is the base, because it already holds
        # the ``verdict.fallback`` note when the judge never answered. What is
        # stored is then compared against what the judge stored: an amendment
        # that changes nothing is not written, which is what keeps the
        # mock-mode contract and an untouched column untouched.
        _stored_validation = (state.get("run_summary") or {}).get("validation")
        _validation_block = _amended_validation(
            (report.run_summary or {}).get("validation"), _report_tally
        )
        if _validation_block is not None and _validation_block != _stored_validation:
            _state_summary["validation"] = _validation_block
            # A name of its own: ``_summary`` above is still read below this
            # point, and rebinding it here was correct only for as long as
            # nothing moved.
            _amended_report_summary = dict(report.run_summary or {})
            _amended_report_summary["validation"] = _validation_block
            report.run_summary = _amended_report_summary
        if fp_warnings:
            _state_summary["fp_warnings"] = fp_warnings
        if _ledger:
            _state_summary["evidence"] = _summary["evidence"]
            _state_summary["sections_without_evidence"] = _summary["sections_without_evidence"]
        # Which of the techniques the run named it actually published, said
        # here because this is the first node that holds both lists. The
        # corroboration metric counts every id any producer named, including
        # the ones that reach it through a finding rather than a claim, and a
        # run whose report printed three enterprise-only ids on an Android
        # sample said nothing about their not being published anywhere.
        _published_summary = _corroboration_with_publication(report, state)
        if _published_summary is not None:
            _state_summary["corroboration"] = _published_summary
            _with_publication = dict(report.run_summary or {})
            if _with_publication:
                _with_publication["corroboration"] = _published_summary
                report.run_summary = _with_publication
        # The stage rollup is finished here rather than in the judge: the
        # judge cannot know how long the report took or whether it ran, and a
        # run summary whose own report stage is missing is the one row a reader
        # would notice. Only added when the judge already wrote a summary — an
        # untouched value keeps the mock-mode contract, where the column is
        # legitimately null.
        own = _verdict_record(stage, started, ran=True).get("stage_results")
        if stage is not None and state.get("run_summary"):
            _state_summary["stages"] = stage_rollup(container, state, own)
            _rolled_up = dict(report.run_summary or {})
            if _rolled_up:
                _rolled_up["stages"] = _state_summary["stages"]
                report.run_summary = _rolled_up
        # The run's elapsed time, closed here for the same reason the rollup
        # is: the judge's clock stops before the report is composed, and the
        # figure a reader compares against the job's own duration is the whole
        # run. Measured from the instant the caller started counting.
        _run_started_at = float(state.get("run_started_at") or 0.0)
        if _run_started_at and state.get("run_summary"):
            _elapsed = round(max(0.0, time.time() - _run_started_at), 3)
            _state_summary["elapsed_seconds"] = _elapsed
            _closed_summary = dict(report.run_summary or {})
            if _closed_summary:
                _closed_summary["elapsed_seconds"] = _elapsed
                report.run_summary = _closed_summary
        # What the run spent, closed here for the same reason: the narrative
        # round and the composer sections are model calls the judge's snapshot
        # was taken before, so the ledger is read again after the last model
        # call of the run.
        if state.get("run_summary"):
            from maljan.analysis.run_summary import spend_blocks

            _ledger_of = getattr(container, "get_token_ledger", None)
            _spent = spend_blocks(_ledger_of().snapshot()) if callable(_ledger_of) else {}
            if _spent:
                _state_summary.update(_spent)
                _with_spend = dict(report.run_summary or {})
                if _with_spend:
                    _with_spend.update(_spent)
                    report.run_summary = _with_spend
        # The generation rates again, now that the composer has sized its
        # sections from them: the judge's snapshot predates those timeouts.
        _generation = _generation_snapshot(container)
        if (
            state.get("run_summary")
            and _generation
            and (_generation.get("models") or _generation.get("timeouts"))
            and _generation != (state.get("run_summary") or {}).get("generation")
        ):
            _state_summary["generation"] = _generation
            _rated_summary = dict(report.run_summary or {})
            if _rated_summary:
                _rated_summary["generation"] = _generation
                report.run_summary = _rated_summary
        # The markdown is rendered once every field it reads is final: the
        # validation block, the corroboration's published marks, the stage
        # rollup and the elapsed time are all written above this line, and so
        # is the report's own snapshot below it. Rendered before them — and
        # snapshotted before them — a served report printed "24 claimed, 24
        # published" over four published techniques, carried no section
        # naming the twenty it did not publish, and gave the judge stage's
        # clock as the run's.
        markdown = MarkdownRenderer().render(report)

        logger.info(
            "report_node: built MalwareReport (verdict=%s, severity=%s, "
            "markdown_chars=%d, extended_objects=%d, fp_warnings=%d).",
            report.verdict,
            report.severity.rating if report.severity else "not assessed",
            len(markdown),
            len(extended_dump.get("objects", [])) if extended_dump else 0,
            len(fp_warnings),
        )

        result: dict[str, Any] = {
            "malware_report": report.model_dump(mode="json"),
            "malware_report_markdown": markdown,
            "stix_bundle_extended": extended_dump,
        }
        if _capa_entries:
            # ``evidence_ledger`` is append-only, so this adds the provider's
            # entries to the run's rather than replacing it.
            result["evidence_ledger"] = [e.model_dump(mode="json") for e in _capa_entries]
        # ``run_summary`` on the state is what the API's own column carries, so
        # anything a reader is meant to see outside the full report has to be
        # added here too. Only written when there is something to add — an
        # untouched value keeps the mock-mode contract, where the judge node
        # skipped the RunSummaryBuilder and the column is legitimately null.
        if _state_summary:
            result["run_summary"] = {**(state.get("run_summary") or {}), **_state_summary}
        if own:
            result["stage_results"] = own
        # Every stage announces its own end from the node that closes it, so
        # there is nothing to replay here; this one is the report's own.
        if stage is not None and stage.key in finishes:
            announce_finished(container, state, (stage.key,), extra=own)
        return result

    node_fn.__name__ = "report_node"
    return node_fn
