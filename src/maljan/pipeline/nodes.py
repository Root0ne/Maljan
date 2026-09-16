"""Generic node factories for the LangGraph pipeline.

Each factory returns a node function bound to a specific agent name and the
shared ServiceContainer. The factories work with any agent in the registry —
no per-agent branching exists.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import replace
from typing import TYPE_CHECKING, Any, cast

from maljan.agents.judge_agent import (
    VERDICT_FALLBACK_CODE,
    VERDICT_FALLBACK_REASON,
    VERDICT_TIMEOUT_CODE,
    VERDICT_TIMEOUT_REASON,
)
from maljan.analysis.run_summary import RunSummaryBuilder
from maljan.core.config import BUILTIN_AGENTS
from maljan.core.container import ServiceContainer
from maljan.core.exceptions import AnalystError, LLMError
from maljan.core.logger import logger
from maljan.memory.long_term_memory import build_stored_case
from maljan.pipeline.conditions import (
    ConditionError,
    StageContext,
    StageResult,
    evaluate,
)
from maljan.pipeline.events import (
    claims_to_payload,
    emit,
    emit_agent_message,
    summarize_claims,
)
from maljan.pipeline.evidence_summary import summarise
from maljan.pipeline.outcome import corrected_reasons, decide_from_bundle, verdict_for_run
from maljan.pipeline.state import AgentArgument, AnalysisState, _merge_stage_results
from maljan.pipeline.sycophancy_detector import build_revision_directive, detect_sycophancy
from maljan.pipeline.validation import (
    ValidationTally,
    Violation,
    corroboration,
    validation_metrics,
)
from maljan.reporting.ledger_report import section_is_grounded
from maljan.schemas.evidence import LedgerEntry
from maljan.schemas.isr_models import AgentISR
from maljan.schemas.stix_models import Bundle

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


def _empty_isr(agent_name: str, revision_round: int = 0) -> AgentISR:
    """Build an empty placeholder ISR (e.g. for mock or error paths)."""
    return AgentISR(
        agent_id=agent_name,
        domain=agent_name,
        claims=[],
        dissent_items=[],
        revision_round=revision_round,
    )


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
    if role in ("static", "generic") or len(chunks) != 1:
        return False
    content = getattr(chunks[0], "content", "") or ""
    return bool(_STATIC_PLACEHOLDER_RE.match(content.strip()))


# The reason a sandbox-fed analyst is skipped when nothing was detonated.
SYNTHETIC_SANDBOX_REASON = "no sandbox fixture for this sample"


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


def _sandbox_fed(role: str) -> bool:
    """Whether this role's input is the sandbox report rather than the sample."""
    return role not in ("static", "generic")


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
                )
            )
    return out


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


def _overall_confidence(assessment: Any, isrs: Any) -> float:
    """The judge's confidence when it gave one, else the analysts' own mean.

    Three answers in order, and the order is the point: the judge decides the
    verdict, so the judge's number is the verdict's number; failing that, the
    analysts that actually produced claims; failing that, zero, which says the
    run reached no confidence rather than naming one.
    """
    declared = getattr(assessment, "confidence", None)
    if declared is not None:
        try:
            return float(declared)
        except (TypeError, ValueError):
            logger.warning("report_node: the judge's confidence %r is not a number.", declared)
    mean = mean_claim_confidence(isrs)
    return float(mean) if mean is not None else 0.0


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
# Analyst node
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Stage plumbing
# ---------------------------------------------------------------------------


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
    limit = 6000
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


def _amended_validation(run_summary: Any, tally: ValidationTally) -> dict[str, Any] | None:
    """The run summary's ``validation`` block plus what the report round cost.

    ``None`` when there is nothing to amend — no summary (mock mode, where the
    judge never built one) or no corrections in the report stage.
    """
    if not tally.retries and not tally.by_code and not tally.unresolved:
        return None
    block = dict((run_summary or {}).get("validation") or {}) if run_summary else {}
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
            return update

        try:
            agent = container.get_agent(agent_name)
            bound_agent = agent
            role = container.agent_role(agent_name)

            agent.pipeline_stage = stage.key
            sandbox_report = state.get("sandbox_report")

            # The two roles whose tools open the sample by path need the path
            # pinned on the agent before anything else: the augmentation below
            # reads a file and can raise, and agents are cached across samples,
            # so a stale path from the previous sample must be cleared even on
            # the failure path. The chunk carries the path for the model to
            # read; the pin carries it for the tool layer, which is what
            # actually corrects a model that sends the bare filename.
            if role in ("static", "generic"):
                _pin_sample_path(agent, state)

            chunks = container.load_data_for_agent(
                agent_name,
                file_hash=state["file_hash"],
                sandbox_report=sandbox_report,
                sample_path=_absolute_host_sample_path(state) or None,
            )

            if role in ("static", "generic"):
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
            )

            technique_ids = tuple(
                dict.fromkeys(str(c.technique_id) for c in isr.claims if c.technique_id is not None)
            )
            node_out: dict[str, Any] = {
                "reports": {agent_name: report},
                "isr_reports": {agent_name: isr},
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
            failed_text = f"[ERROR] {agent_name} analysis failed: {e}"
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=failed_text,
                status="failed",
            )
            return _closing(
                {
                    "reports": {agent_name: failed_text},
                    "isr_reports": {agent_name: _empty_isr(agent_name)},
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
            crashed_text = f"[ERROR] {agent_name} crashed: {e}"
            emit_agent_message(
                container.event_sink,
                speaker=agent_name,
                role="analyst",
                text=crashed_text,
                status="failed",
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
                # standing and hands them straight on: ``is_consensus`` is set
                # so the router's own branch takes the way out rather than
                # looping a stage the operator asked to skip.
                if announces:
                    announce_skipped(container, stage, skip_reason)
                return {
                    "is_consensus": True,
                    **stage_record(stage, ran=False, reason=skip_reason),
                }
            if not _debate_participants(container, stage, state):
                # Nothing upstream of it ran, so there is nothing to argue
                # over. Announced as a skip before the start, because a debate
                # that announces itself and then declines reads as one that
                # failed. ``is_consensus`` sends the router straight on.
                reason = "no analysis stage upstream of it ran"
                logger.info("stage %s skipped: %s", stage.key, reason)
                if announces:
                    announce_skipped(container, stage, reason)
                return {
                    "is_consensus": True,
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

        if container.is_mock:
            is_consensus = iteration >= 1
            mean_conf = 0.95 if is_consensus else 0.4
            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
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
            from maljan.agents.base_agent import describe_exception, run_on_agent_loop
            from maljan.core.config import get_settings

            mediation_timeout = float(get_settings().react_agent_timeout) * 2 + 30
            argument, is_consensus = await run_on_agent_loop(
                judge.mediate(
                    reports=active_reports,
                    history=state.get("discussion_history") or [],
                    isr_reports=state.get("isr_reports") or {},
                    # The stage's own bar for calling it agreement. ``None``
                    # leaves the mediator on the global setting, which is what
                    # the stage's options were seeded from.
                    consensus_threshold=_debate_threshold(stage),
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

            emit_agent_message(
                container.event_sink,
                speaker="Mediator",
                role="negotiator",
                text=argument.finding,
                round_index=iteration + 1,
                status="complete",
                confidence=argument.confidence_score,
            )
            if syco:
                emit_agent_message(
                    container.event_sink,
                    speaker="Sycophancy detector",
                    role="system",
                    text=(
                        "Agents converged without new evidence — flagged as sycophantic "
                        "agreement. The next revision round carries a directive to "
                        "re-argue from evidence rather than defer to peers."
                    ),
                    round_index=iteration + 1,
                    status="complete",
                )

            return {
                "iteration_count": iteration + 1,
                "is_consensus": is_consensus,
                "sycophancy_detected": syco,
                "confidence_history": [mean_conf],
                "discussion_history": [argument],
                # Mediation is the only place a judge agent calls a tool, so
                # this is where those calls have to leave the agent.
                "evidence_ledger": _judge_evidence(),
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
            logger.error("Negotiation %s: %s", label, describe_exception(e))
            emit_agent_message(
                container.event_sink,
                speaker="Mediator",
                role="negotiator",
                text=f"[ERROR] Mediation {label}: {describe_exception(e)}",
                round_index=iteration + 1,
                status=status,
            )
            return {
                "iteration_count": iteration + 1,
                "is_consensus": False,
                "sycophancy_detected": syco,
                "confidence_history": [0.0],
                "discussion_history": [
                    AgentArgument(
                        agent_name="Mediator",
                        finding=f"[ERROR] Mediation {label}: {describe_exception(e)}",
                        confidence_score=0.0,
                        # The structured signal. The "[ERROR] Mediation " prefix
                        # above stays for old stored state, but nothing new
                        # should have to parse prose to learn this.
                        status=status,
                    )
                ],
                # A mediation that timed out still made the calls it made.
                "evidence_ledger": _judge_evidence(),
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
                    text=f"[ERROR] {name} revision failed: {result}",
                    round_index=iteration,
                    status="failed",
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
                )

        out: dict[str, Any] = {"revised_reports": revised, "isr_reports": revised_isrs}
        if revision_ledger:
            out["evidence_ledger"] = revision_ledger
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
            _technique_count = len(_corroboration)
            _corroborated = sum(1 for sources in _corroboration.values() if len(sources) > 1)
            evidence_summary = summarise(isr_reports, _ledger)

            start_time = time.time()

            memory_store: MemoryStore | None = None
            try:
                memory_store = container.get_memory_store()
            except Exception as e:
                logger.warning("Memory store unavailable: %s. Skipping LTM context.", e)

            # The corpus an indicator's pattern value has to appear in. It is
            # no longer a filter: the judge is told which values are not in it
            # and gets a turn to withdraw them.
            evidence_corpus: set[str] = set()
            try:
                from maljan.agents.judge_postprocess import build_evidence_corpus

                # Best-effort — interesting strings come from a partial
                # MalwareReport build later in the pipeline, so we pull
                # from the raw sandbox report and the ledger's own outputs.
                sandbox_report = state.get("sandbox_report") or {}
                evidence_corpus = build_evidence_corpus(
                    interesting_strings=None,
                    sandbox_report=sandbox_report if isinstance(sandbox_report, dict) else None,
                    extra=[entry.output for entry in _ledger if entry.output],
                )
            except Exception as exc:  # noqa: BLE001
                logger.debug("Evidence corpus build skipped: %s", exc)

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
            _degradation_reasons: list[str] = []
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
                    f"zero cross-layer corroboration ({_technique_count} single-layer techniques)"
                    if _technique_count > 0
                    else "no techniques mapped (no corroborating evidence)"
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
            if not state.get("sandbox_report"):
                _degradation_reasons.append(
                    "no sandbox report (dynamic detonation unavailable) — static-only evidence"
                )
            # A container we accept but cannot open. A .docm reaches here
            # legitimately — macro documents are among the commonest Windows
            # carriers, so rejecting them would be wrong — but the only analysis
            # it receives is a raw-byte string sweep, and without this the report
            # renders a confident verdict over an unread payload.
            try:
                from maljan.extractors.sample_identity import unparsed_container_reason

                _container_reason = unparsed_container_reason(state.get("sample_path"))
                if _container_reason:
                    _degradation_reasons.append(_container_reason)
            except Exception as _e:  # noqa: BLE001
                logger.debug("container-format check skipped (%s)", _e)
            # A tool server an operator added is never the evidence a verdict
            # rests on, so it degrades rather than failing — but the reader of
            # the report is entitled to know the judge ran without its
            # threat-intel lookups.
            _degradation_reasons.extend(container.server_degradation_reasons())
            if _failed_analysts:
                _degradation_reasons.append(f"analyst failures: {', '.join(_failed_analysts)}")
            if _empty_analysts:
                _degradation_reasons.append(
                    f"analysts produced no claims: {', '.join(_empty_analysts)}"
                )
            if _anti_emu_hits:
                _short = _anti_emu_hits[0]
                _suffix = f" (+{len(_anti_emu_hits) - 1} more)" if len(_anti_emu_hits) > 1 else ""
                _degradation_reasons.append(
                    f"sandbox detected anti-emulation behaviour: {_short}{_suffix}"
                )
            _degraded_mode = bool(_degradation_reasons)
            if _degraded_mode:
                logger.warning("Degraded run detected (%s).", "; ".join(_degradation_reasons))

            # The degradation, said to the judge in the prompt. What used to
            # happen instead was a fixed ceiling applied to the finished number
            # in the report node, which told the reader the confidence was
            # capped and told the judge nothing at all.
            degradation_note = ""
            if _degradation_reasons:
                degradation_note = (
                    "RUN QUALITY — this analysis is degraded because "
                    + "; ".join(_degradation_reasons)
                    + ". Weigh your confidence accordingly: a verdict drawn from thin "
                    "evidence should say so in its numbers, not only in its prose."
                )

            verdict = await judge.give_verdict(
                reports=reports,
                history=state.get("discussion_history") or [],
                isr_reports=isr_reports,
                evidence_summary=evidence_summary,
                degradation_note=degradation_note,
                memory_store=memory_store,
                evidence_corpus=evidence_corpus or None,
                current_sample_id=state.get("file_hash"),
            )
            # A verdict the judge never expressed as a bundle is the thinnest
            # answer this pipeline can produce — no severity, no reasoning the
            # model stands behind — and before this it reached the reader as an
            # ordinary verdict with a slightly emptier STIX object.
            if any(v.code == VERDICT_FALLBACK_CODE for v in verdict.violations):
                _degradation_reasons.append(VERDICT_FALLBACK_REASON)
                _degraded_mode = True
            if any(v.code == VERDICT_TIMEOUT_CODE for v in verdict.violations):
                _degradation_reasons.append(VERDICT_TIMEOUT_REASON)
                _degraded_mode = True

            bundle = verdict.bundle
            stix_output: dict[str, Any] = bundle.model_dump() if isinstance(bundle, Bundle) else {}
            decision = decide_from_bundle(bundle) if isinstance(bundle, Bundle) else "Suspicious"
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
                    "sycophancy_detected": state.get("sycophancy_detected", False),
                    "discussion_history": state.get("discussion_history") or [],
                }
                summary = (
                    RunSummaryBuilder(start_time=start_time)
                    .set_sample(state.get("file_hash", ""), state.get("file_name"))
                    .set_verdict(decision, len(bundle.objects) if isinstance(bundle, Bundle) else 0)
                    .set_negotiation(negotiation_state, max_iterations=max_iters)
                    .set_isr_stats(isr_reports, no_data=_no_data_analysts)
                    .set_validation(validation_metrics(_retries, _unresolved, _fed_back))
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
                    .set_truncation(container.get_truncation_ledger().snapshot())
                    .build()
                )
                run_summary_dict = summary.to_dict()
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
            _attck_case_report: list[dict[str, Any]] = []
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

            # ATT&CK case-prior RAG (§4 U2, read side): record the ATT&CK techniques
            # recurring in behaviourally-similar prior cases (mined from our own LTM)
            # as report evidence. Same host static profile as the family RAG, different
            # KB. LLM-centric: these are candidates the analyst weighed, not a verdict.
            # Fail-safe and gated OFF by default (no corpus -> no rows).
            try:
                from maljan.core.config import get_settings as _get_settings3

                _cfg3 = _get_settings3()
                _host3 = state.get("sample_path")
                if _cfg3.preprocessing.use_attck_case_rag and _host3:
                    from maljan.analysis.attck_case_rag import (
                        retrieve_techniques,
                    )
                    from maljan.analysis.attck_case_rag import (
                        to_report_dicts as _attck_to_report_dicts,
                    )
                    from maljan.analysis.family_feature_rag import build_sample_profile_text
                    from maljan.core.paths import resolve_data
                    from maljan.extractors.pe_extractor import build_static_analysis
                    from maljan.memory.attck_case_index import load_attck_case_index

                    _static3 = build_static_analysis(sample_path=str(_host3))
                    # See the family-RAG block above: relative paths must be
                    # resolved against the repo root, not the CWD.
                    _index3 = load_attck_case_index(
                        str(resolve_data(_cfg3.preprocessing.attck_case_corpus_path))
                    )
                    if _static3 is not None and _index3 is not None:
                        _techs = retrieve_techniques(
                            build_sample_profile_text(_static3),
                            _index3,
                            top_k=_cfg3.preprocessing.attck_case_rag_top_k,
                            min_score=_cfg3.preprocessing.attck_case_rag_min_score,
                            max_techniques=_cfg3.preprocessing.attck_case_rag_max_techniques,
                        )
                        _attck_case_report = _attck_to_report_dicts(_techs)
            except Exception as _e:
                logger.warning("ATT&CK-case RAG skipped (%s). Verdict unaffected.", _e)

            emit_agent_message(
                container.event_sink,
                speaker="Judge",
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
            )

            return _closing(
                {
                    **_verdict_record(verdict_stage, started, ran=True),
                    "final_decision": decision,
                    "judge_report": "Analyzed negotiation history and expert reports.",
                    "stix_output": stix_output,
                    "run_summary": run_summary_dict,
                    # The judge's own tool calls — threat intel on a disputed
                    # indicator, a knowledge lookup — on the same append-only
                    # channel the analysts use, so a verdict that leans on one can
                    # cite it and the citation resolves.
                    "evidence_ledger": _judge_evidence(),
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
                    # ATT&CK case-prior RAG candidates (recurring TTPs from similar prior
                    # cases), surfaced into FamilyAttribution.attck_case_candidates by the
                    # report node. Empty unless the RAG is enabled with a case corpus.
                    "attck_case_candidates": _attck_case_report,
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
                speaker="Judge",
                role="judge",
                text=(
                    f"[ERROR] Judge failed ({type(e).__name__}): {e or ''}. "
                    "Falling back to a conservative Suspicious verdict; the run is "
                    "marked degraded and the report says why."
                ),
                round_index=state.get("iteration_count", 0),
                status="failed",
            )
            # A judge-body failure must ALSO flag the run as degraded so the
            # report node caps ``overall_confidence`` and the UI shows the
            # DEGRADED banner. Without these keys the report
            # node saw ``degraded_mode`` unset and could ship an uncapped
            # confidence for a verdict the judge never actually produced.
            return _closing(
                {
                    **_verdict_record(
                        verdict_stage,
                        started,
                        ran=True,
                        reason=f"judge failed ({type(e).__name__})",
                    ),
                    "final_decision": "Suspicious",
                    "judge_report": f"[ERROR] Judge failed ({type(e).__name__}): {e or ''}",
                    "stix_output": {},
                    "degraded_mode": True,
                    "degradation_reasons": [f"judge failed ({type(e).__name__})"],
                    "evidence_ledger": _judge_evidence(),
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

        # And so does the confidence. It used to be the negotiation's mean over
        # *every* analyst, with a skipped one counted as a zero: one analyst at
        # 0.50 beside two that never ran produced 0.167 on the front page of a
        # "Malware" verdict. An analyst that had nothing to read is not a vote
        # of no confidence, and the mean of the analysts that did produce
        # claims is the fallback — the judge's own number is the answer when
        # the judge gave one.
        overall_confidence = _overall_confidence(_bundle_assessment, isr_reports)

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
            if _static_provider.capabilities.provides_evidence and _sample_for_evidence:
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
            # Same post-build threading for the ATT&CK case-prior RAG candidates.
            _attck_cands = cast("list[dict[str, Any]]", state.get("attck_case_candidates") or [])
            if _attck_cands and getattr(report, "attribution", None) is not None:
                report.attribution.attck_case_candidates = _attck_cands
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
        _by_tool: dict[str, int] = {}
        for _entry in _ledger:
            _by_tool[_entry.tool] = _by_tool.get(_entry.tool, 0) + 1
        _summary = dict(report.run_summary or {})
        _summary["evidence"] = {
            "entries": len(_ledger),
            "ok": sum(1 for e in _ledger if e.ok),
            "failed": sum(1 for e in _ledger if not e.ok),
            "trimmed": sum(1 for e in _ledger if e.truncated),
            "by_tool": dict(sorted(_by_tool.items())),
        }
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

        narrative_dict: dict[str, Any] | None = None
        try:
            narrative_agent = container.get_narrative_agent()
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: NarrativeAgent unavailable (%s); using fallback.", exc)
            narrative_agent = None

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
                    narrative_agent.generate(report, state.get("isr_reports")),
                    timeout=_NARRATIVE_TIMEOUT_SECONDS,
                )
            except TimeoutError:
                logger.error(
                    "report_node: NarrativeAgent exceeded %ds; using fallback narrative.",
                    _NARRATIVE_TIMEOUT_SECONDS,
                )
                narrative_output = None
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: NarrativeAgent.generate raised (%s); using fallback.",
                    exc,
                )
                narrative_output = None
            if narrative_output is not None:
                narrative_dict = narrative_output.model_dump(mode="json")
            _report_tally.merge(getattr(narrative_agent, "validation_tally", ValidationTally()))

        if narrative_dict is not None:
            report = MalwareReportBuilder.apply_narrative(report, narrative_dict)
            logger.info(
                "report_node: narrative LLM round succeeded (summary_chars=%d, "
                "paragraphs=%d, recs=%d).",
                len(report.executive_summary),
                len(report.capabilities_narrative),
                len(report.defensive_recommendations),
            )
        else:
            report = MalwareReportBuilder.apply_fallback_narrative(report)

        # Section-wise Composer authors the professional
        # spine (intro, technical-analysis subsections, C2 channels, conclusion),
        # each grounded in its isolated evidence bundle. Best-effort — a Composer
        # failure never blocks the report. None in mock / when composer disabled.
        try:
            composer = container.get_report_composer()
        except Exception as exc:  # noqa: BLE001
            logger.warning("report_node: ReportComposer unavailable (%s); skipping spine.", exc)
            composer = None
        if composer is not None:
            try:
                await composer.compose(report, state.get("isr_reports"))
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "report_node: ReportComposer.compose raised (%s); spine skipped.", exc
                )
            _report_tally.merge(getattr(composer, "validation_tally", ValidationTally()))

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

        markdown = MarkdownRenderer().render(report)

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
                extended_bundle = ExtendedSTIXRenderer().render(
                    report, base, ledger=container.get_truncation_ledger()
                )
                extended_dump = extended_bundle.model_dump(mode="json")
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
            _final_desc = (
                f"Verdict: {report.verdict} "
                f"(confidence={report.overall_confidence:.2f}; "
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

        logger.info(
            "report_node: built MalwareReport (verdict=%s, severity=%s, "
            "markdown_chars=%d, extended_objects=%d, fp_warnings=%d).",
            report.verdict,
            report.severity.rating if report.severity else "not assessed",
            len(markdown),
            len(extended_dump.get("objects", [])) if extended_dump else 0,
            len(fp_warnings),
        )

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
        _state_summary: dict[str, Any] = {}
        _validation_block = _amended_validation(state.get("run_summary"), _report_tally)
        if _validation_block is not None:
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
        # The stage rollup is finished here rather than in the judge: the
        # judge cannot know how long the report took or whether it ran, and a
        # run summary whose own report stage is missing is the one row a reader
        # would notice. Only added when the judge already wrote a summary — an
        # untouched value keeps the mock-mode contract, where the column is
        # legitimately null.
        own = _verdict_record(stage, started, ran=True).get("stage_results")
        if stage is not None and state.get("run_summary"):
            _state_summary["stages"] = stage_rollup(container, state, own)
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
