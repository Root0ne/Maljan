"""Analysis run observability: structured RunSummary report.

After a complete analysis run, the pipeline has produced:
  - ISR reports (per-agent structured claims)
  - Negotiation history (mediator arguments + confidence evolution)
  - What the validation loop found and could not get fixed
  - Which sources corroborated each technique id
  - Final STIX 2.1 bundle

RunSummary aggregates all of these into a single inspectable object that
can be rendered as a Markdown report, serialized to JSON, or logged.

This gives security analysts full explainability: they can see exactly
WHY the pipeline reached its verdict, which agents agreed, which TTPs
were cross-corroborated, and which claims were flagged as hallucinations.

Design:
  - RunSummary is built post-verdict in the judge node via RunSummaryBuilder.
  - It is stored in AnalysisState["run_summary"] as a plain dict
    (JSON-serializable; avoids TypedDict + dataclass compatibility issues).
  - MaljanApp.run() returns it alongside the STIX output.
  - The CLI renders it as a Markdown block or writes it to a .md file.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from maljan.analysis.corroboration import (
    corroboration_row,
    corroboration_sources,
    published_count,
    technique_label,
)

# ---------------------------------------------------------------------------
# Sub-components
# ---------------------------------------------------------------------------


# The termination reason of a debate that measured no agreement: fewer than
# two analysts produced claims, or the stage did not run.
NOT_APPLICABLE = "not_applicable"

# What every surface says for it. The record does not say which of the two
# causes held, so the words name neither.
NOT_APPLICABLE_PHRASE = "not applicable; no agreement was measured"
NOT_APPLICABLE_SENTENCE = f"Consensus: {NOT_APPLICABLE_PHRASE}."


@dataclass
class NegotiationMetrics:
    """Statistics from the negotiation loop.

    Attributes:
        rounds_completed:    Number of negotiation rounds actually executed.
        max_rounds:          Hard limit configured at startup.
        termination_reason:  Why the loop stopped (consensus / hard_limit /
                             convergence / sycophancy / not_applicable).
        sycophancy_events:   Number of rounds where sycophancy was detected.
        confidence_history:  Per-round mediator confidence scores.
        final_confidence:    Last recorded confidence value; ``None`` when
                             consensus did not apply, because fewer than two
                             analysts produced claims or the debate did not
                             run. No agreement was measured, so none is stated.
    """

    rounds_completed: int
    max_rounds: int
    termination_reason: str
    sycophancy_events: int
    confidence_history: list[float]
    final_confidence: float | None

    @property
    def consensus_applicable(self) -> bool:
        return self.termination_reason != NOT_APPLICABLE

    @property
    def converged_early(self) -> bool:
        return self.termination_reason != "hard_limit"


@dataclass
class ISRAgentStats:
    """Per-agent ISR statistics extracted from the final AgentISR objects."""

    agent_id: str
    domain: str
    revision_round: int
    claim_count: int
    mean_confidence: float
    technique_ids: list[str]
    has_dissent: bool
    # True when this analyst had nothing to analyse, as opposed to having
    # analysed its data and claimed nothing. The two are different findings —
    # one says the run was thin, the other says the analyst failed — and they
    # were reported identically until BUG 12.
    #
    # A flag rather than a second degradation-reason string, deliberately:
    # readers partition on the literal "analysts produced no claims:" to strip
    # the starved analysts out of a static-only run. A new reason string would
    # have made every such run record an unexplained incidental degradation.
    no_data: bool = False
    # What the analyst says about its own answer, when the claim count cannot
    # say it: ``no_claims`` for one that read its data and whose model ended
    # without a structured report. Without it this row showed such an analyst
    # as ``no_data: false`` with zero claims — the one view an operator and the
    # judge's degradation note read, and the one that could not tell "nothing
    # to read" from "never answered". Empty for an analyst that just answered.
    status: str = ""


@dataclass
class ValidationMetrics:
    """What the validation loop found, and what it could not get fixed.

    ``unresolved`` is the part that matters. A violation a producer was shown
    and did not fix is the honest residue of this pipeline: it is not silently
    corrected any more, so it has to be somewhere a reader can see it.
    """

    retries: int = 0
    by_code: dict[str, int] = field(default_factory=dict)
    unresolved: list[dict[str, str]] = field(default_factory=list)
    # The checks that could not run at all, by code. A check that ran and
    # found nothing and a check that never ran are different facts.
    not_run: list[str] = field(default_factory=list)


@dataclass
class TokenUsageMetrics:
    """What the run's model calls spent, in the providers' own figures.

    ``unreported_calls`` counts the calls whose provider reported no usage.
    Their tokens are not in the sums and are not estimated: a sum is what the
    providers reported, and the calls that reported nothing are said to have
    reported nothing. ``cost`` is present only where a provider reported one,
    over ``cost_calls`` calls; there is no price table. ``per_agent`` holds
    the same figures for each agent, and the models that answered it.
    """

    input_tokens: int
    output_tokens: int
    total_tokens: int
    llm_calls: int
    unreported_calls: int = 0
    cost: float | None = None
    cost_calls: int = 0
    per_agent: dict[str, dict[str, Any]] = field(default_factory=dict)


def tokens_sentence(tokens: dict[str, Any] | None) -> str | None:
    """One sentence saying what the run's model calls spent, or ``None`` with no calls.

    The report and the console print the same words. Tokens a provider did
    not report are said to be not reported, never estimated; a cost appears
    only where a provider reported one, with how many calls it covers.
    """
    if not isinstance(tokens, dict):
        return None
    calls = int(tokens.get("llm_calls") or 0)
    if calls <= 0:
        return None
    noun = "call" if calls == 1 else "calls"
    # A summary stored before this release folded a character estimate into
    # its sums for every call whose provider reported nothing, and said so
    # only in ``estimated_calls``. Those sums are not counts, so none is shown.
    if int(tokens.get("estimated_calls") or 0) > 0:
        return (
            f"Tokens: this run was recorded with estimates mixed into its {calls} model "
            f"{noun}, so no count is shown."
        )
    unreported = int(tokens.get("unreported_calls") or 0)
    reported = calls - unreported
    if reported <= 0:
        return f"Tokens: not reported by the provider for any of {calls} model {noun}."
    text = (
        f"Tokens: {int(tokens.get('input_tokens') or 0):,} in and "
        f"{int(tokens.get('output_tokens') or 0):,} out over {calls} model {noun}"
    )
    if unreported:
        text += f"; not reported for {unreported} of them"
    cost = tokens.get("cost")
    cost_calls = int(tokens.get("cost_calls") or 0)
    if isinstance(cost, int | float) and cost_calls:
        # The only usage block that carries ``cost`` is an OpenAI-compatible
        # router's, which reports it in US dollars.
        text += (
            f"; a cost of {float(cost):.4f} USD as the provider reported it for "
            f"{cost_calls} {'call' if cost_calls == 1 else 'calls'}"
        )
    return text + "."


def spend_blocks(snapshot: dict[str, Any] | None) -> dict[str, Any]:
    """``tokens`` and ``models`` as the run summary stores them, from a ledger snapshot.

    For a node that closes the summary after the judge built it: the report
    stage's own model calls — the narrative round and every composer section —
    happen after the judge's snapshot, and a run total without them is short.
    Empty when the snapshot holds no call.
    """
    if not isinstance(snapshot, dict) or not snapshot.get("llm_calls"):
        return {}
    summary = RunSummaryBuilder(start_time=time.time()).set_token_usage(snapshot).build()
    stored = summary.to_dict()
    return {"tokens": stored["tokens"], "models": stored["models"]}


def server_rest_sentence(row: dict[str, Any]) -> str:
    """One rested tool server, in the words the report and the console print."""
    failures = int(row.get("failures") or 0)
    noun = "call" if failures == 1 else "calls"
    reason = str(row.get("reason") or "").strip()
    return (
        f"Tool server {row.get('server', '')!s} was rested for "
        f"{float(row.get('cooldown_s') or 0):.0f} s after {failures} {noun} in a row it did not "
        "answer" + (f" (the last: {reason})" if reason else "") + "."
    )


@dataclass
class TruncationMetrics:
    """Per-run tally of every bound this run hit (pitfall P6).

    *Chasing Shadows* asks papers to "report truncation frequency and performance
    impacts". Truncation is designed into this pipeline — capped tool output, a
    capped ReAct loop, a capped judge, all inside a context window that is itself
    half the model's native 262,144 (findings-log §2.0) — and until 2026-08-09
    none of it was counted.

    The integrity and cap fields are not truncation: they record what left the
    **exported** STIX bundle, because the claim that repairing beats rejecting
    needs a number, and because everything a bundle loses should leave under a
    name — the pass's own repairs, the references it trims out of a report or a
    note, and the total indicator cap's own removals. Those three reconcile
    with the bundle a reader holds. The ``judge_integrity_*`` fields are the
    same pass on the judge's own bundle, once per verdict attempt including a
    discarded retry, and are deliberately not part of that total.
    """

    tool_output_calls: int
    tool_output_over_limit: int
    tool_output_summarised: int
    tool_output_hard_truncated: int
    tool_output_chars_dropped: int
    react_invocations: int
    react_step_cap_hits: int
    judge_invocations: int
    judge_token_cap_hits: int
    integrity_invocations: int
    integrity_objects_removed: int
    integrity_dropped: dict[str, int] = field(default_factory=dict)
    # A JSON answer shortened by dropping list elements rather than characters.
    # Defaulted because a summary read back from storage predates the outcome.
    tool_output_shortened: int = 0
    tool_output_shortening_timeouts: int = 0
    # Answers the conversation had no room left for at all: the model was
    # handed one sentence saying so and the answer stayed on the ledger.
    tool_output_no_room: int = 0
    # JSON answers over the cap only because of their whitespace, handed over
    # whole without it. Nothing was left out of them.
    tool_output_compacted: int = 0
    # References the pass took out of a report's or a note's ``object_refs``.
    # No object left the bundle for these, which is why they are their own
    # number rather than a reason under ``integrity_dropped``.
    integrity_refs_trimmed: int = 0
    # Indicators the total indicator cap removed, and how often the cap ran.
    # Defaulted for the same reason the two above are: a summary read back from
    # storage predates them.
    indicator_cap_invocations: int = 0
    indicator_cap_removed: int = 0
    # The judge path's own integrity passes. Apart from the figures above, and
    # never summed into them: that pass runs once per verdict *attempt*,
    # discarded retries included, over a bundle the export may not carry, so a
    # total holding both reconciles with nothing a reader has.
    judge_integrity_invocations: int = 0
    judge_integrity_objects_removed: int = 0
    judge_integrity_dropped: dict[str, int] = field(default_factory=dict)
    # What the run's grounding corpus could not hold. Not truncation of a
    # model's input: it is how much of the run's own record the grounding
    # checks could not search, which is why an absence this run stated may be
    # a note rather than a finding.
    evidence_corpus_missing_answers: int = 0
    evidence_corpus_missing_tools: list[str] = field(default_factory=list)
    evidence_corpus_partial_reason: str = ""
    # And what it did hold, against its ceiling. ``None`` rather than zero: a
    # summary stored before these existed, or a run whose corpus was gone when
    # the record was written, knows nothing about what was held, and zero would
    # be a claim that nothing was.
    evidence_corpus_answers: int | None = None
    evidence_corpus_bytes_held: int | None = None
    evidence_corpus_bytes_ceiling: int | None = None
    # The cap that was actually in force on a tool answer, smallest and
    # largest. Derived from what the window had left at the moment of each
    # call, so the two differ inside one run and a reader asking why one answer
    # was cut and another was not is asking about these.
    tool_output_limit_smallest: int = 0
    tool_output_limit_largest: int = 0
    # The window those caps were worked out from: how many tokens, where that
    # was learned (declared, probed, table, fallback) in words, the
    # characters-per-token figure and the room kept back for the model's reply.
    # Empty on a run whose cap was an operator's own number, because no window
    # was consulted then.
    context_window: dict[str, Any] = field(default_factory=dict)

    @property
    def any_bound_hit(self) -> bool:
        """The per-run P6 headline: did anything get cut at all?"""
        return bool(
            self.tool_output_over_limit
            or self.tool_output_no_room
            or self.react_step_cap_hits
            or self.judge_token_cap_hits
        )


def _recorded_calls(latency: Any) -> int:
    """How many calls the per-agent latency table counts, across every agent."""
    total = 0
    for row in (latency or {}).values():
        if isinstance(row, dict):
            try:
                total += max(0, int(row.get("calls") or 0))
            except (TypeError, ValueError):
                continue
    return total


def _optional_count(value: Any) -> int | None:
    """A recorded count, or ``None`` when nothing was recorded.

    ``None`` and ``0`` are two different answers here: one says this run made
    no record, the other says the record is zero.
    """
    if value is None:
        return None
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return None


# Past this share of the ceiling the figures are printed unasked: a corpus
# holding more than half of what it may hold is one whose ceiling is a number
# the operator should know before the run that reaches it.
CORPUS_LOUD_SHARE = 0.5


def corpus_held_sentence(truncation: Any) -> str:
    """What the run's grounding corpus held, as one sentence, or ``""``.

    Printed only where it tells a reader something: a corpus that went partial
    (the loss is stated beside it) or one past half its ceiling. Otherwise the
    figures stay on the record and nothing is said, because a run with room to
    spare has nothing to act on.
    """
    answers = getattr(truncation, "evidence_corpus_answers", None)
    held = getattr(truncation, "evidence_corpus_bytes_held", None)
    ceiling = getattr(truncation, "evidence_corpus_bytes_ceiling", None)
    if answers is None or held is None or ceiling is None:
        return ""
    partial = bool(str(getattr(truncation, "evidence_corpus_partial_reason", "") or "").strip())
    if not partial and not (ceiling > 0 and held > ceiling * CORPUS_LOUD_SHARE):
        return ""
    return (
        f"The grounding corpus held {count_label(int(answers), 'answer')}, "
        f"{int(held)} of {int(ceiling)} bytes."
    )


# The one source word from which nothing may be derived, spelled here rather
# than imported so the reporting layer keeps no provider import it does not
# otherwise need. Pinned against the provider module by a test.
UNKNOWN_WINDOW_SOURCE = "fallback"

# How a window that was *refused* is told from one that was never reported.
# Both are unknown windows; only the first has something an operator can go
# and fix at the endpoint. Pinned against the sentence the probe writes.
REFUSAL_MARK = "refused"


def cap_in_force_sentence(truncation: Any) -> str:
    """The cap one tool answer was measured against, and where it came from.

    The cap is no longer a constant a reader can look up: derived, it is worked
    out per call from what the served window had left, so the run has to say
    what was in force while it ran. A run whose cap was an operator's own
    number consulted no window, and says that instead.
    """
    smallest = int(getattr(truncation, "tool_output_limit_smallest", 0) or 0)
    largest = int(getattr(truncation, "tool_output_limit_largest", 0) or 0)
    if largest <= 0:
        return ""
    window = getattr(truncation, "context_window", None) or {}
    window = window if isinstance(window, dict) else {}
    tokens = int(window.get("tokens", 0) or 0)
    if not window:
        return f"One tool answer was capped at {largest:,} characters, the number this run was set."
    if str(window.get("source", "")) == UNKNOWN_WINDOW_SOURCE:
        # Nothing was measured, so nothing is derived and nothing derived is
        # printed: no characters-per-token figure and no reply reserve, because
        # neither decided anything. What an operator can act on is the remedy —
        # and, where the window is unknown because a figure was *refused*
        # rather than because nothing answered, the reason. That is the one
        # case with a concrete and unusual problem behind it, and a generic
        # sentence would send its operator looking for the wrong thing.
        why = str(window.get("detail", "") or "")
        said = (
            f"The served context window is unknown, so one tool answer was capped at the "
            f"documented {largest:,} characters rather than derived"
        )
        if REFUSAL_MARK in why:
            said = f"{said} ({why})"
        return f"{said}. To derive it, {window.get('remedy', '')}.".replace(" .", ".")
    span = (
        f"{largest:,} characters"
        if smallest == largest
        else f"between {smallest:,} and {largest:,} characters"
    )
    return (
        f"One tool answer was capped at {span}, derived from a context window of "
        f"{tokens:,} tokens ({window.get('source', '')} — {window.get('detail', '')}) at "
        f"{int(window.get('chars_per_token', 0) or 0)} characters per token, with "
        f"{int(window.get('reply_tokens', 0) or 0):,} tokens held back for the model's reply."
    )


def count_label(count: int, singular: str, plural: str = "") -> str:
    """ "1 object", "2 objects" — a count and its noun, agreeing.

    The console has the same helper, and the two sentences below are pinned
    against one shared fixture so the wordings cannot drift apart.
    """
    return f"{count} {singular if count == 1 else (plural or singular + 's')}"


def bundle_loss_sentence(truncation: Any) -> str:
    """What the exported STIX bundle lost, as one sentence, or ``""``.

    Built from the reasons, never from the total. ``integrity_objects_removed``
    counts both integrity passes, and the second one runs after the indicator
    cap and removes nothing but relationships the cap orphaned — so a line that
    printed the total called six orphaned relationships "repaired away", and
    the console, which had already learned to subtract them, disagreed with the
    report about the same run. One reading, two surfaces.
    """
    dropped = getattr(truncation, "integrity_dropped", None) or {}

    def _count(value: Any) -> int:
        try:
            return max(0, int(value or 0))
        except (TypeError, ValueError):
            return 0

    orphaned = _count(dropped.get("cap_orphan"))
    repaired = max(0, _count(getattr(truncation, "integrity_objects_removed", 0)) - orphaned)
    capped = _count(getattr(truncation, "indicator_cap_removed", 0))
    refs = _count(getattr(truncation, "integrity_refs_trimmed", 0))

    parts: list[str] = []
    if repaired:
        parts.append(f"{count_label(repaired, 'object')} repaired away as malformed or duplicated")
    if capped:
        parts.append(
            f"{count_label(capped, 'indicator')} over the export's total cap, lowest priority first"
        )
    if orphaned:
        parts.append(f"{count_label(orphaned, 'relationship')} left pointing at a capped indicator")
    if refs:
        parts.append(f"{count_label(refs, 'reference')} trimmed from a report or a note")
    if not parts:
        return ""
    return f"The exported STIX bundle is shorter than what the run produced: {'; '.join(parts)}."


def stage_duration_lines(stages: Any) -> list[str]:
    """How long each stage that ran took, as the lines beside the elapsed time.

    Read from the stage rollup, which is the same list the console's stage
    headers are drawn from, so the two cannot disagree about where a run spent
    its time. A stage that did not run contributes nothing: an absent row and a
    zero are different facts, and the rollup's own ``reason`` says which.
    """
    rows = [
        (str(row.get("key") or ""), float(row.get("duration_ms") or 0.0))
        for row in (stages or [])
        if isinstance(row, dict) and row.get("ran") and float(row.get("duration_ms") or 0.0) > 0
    ]
    if not rows:
        return []
    spent = ", ".join(f"{key} {ms / 1000.0:.1f}s" for key, ms in rows if key)
    return [f"**Per stage**: {spent}  "] if spent else []


def generation_lines(generation: Any) -> list[str]:
    """Each model's measured generation rate and each call timeout it produced.

    One line per model and one per sized call, so a reader can check the
    arithmetic: the budget, the rate, the margin, the ceiling, and what the
    call was finally given. Nothing measured contributes nothing.
    """
    if not isinstance(generation, dict):
        return []
    lines: list[str] = []
    for model, row in sorted((generation.get("models") or {}).items()):
        if not isinstance(row, dict) or row.get("tokens_per_second") is None:
            continue
        sources = "; ".join(str(x) for x in row.get("sources") or []) or "unknown"
        lines.append(
            f"Generation rate of `{model}`: {float(row['tokens_per_second']):.2f} tokens/s "
            f"({int(row.get('tokens') or 0)} tokens over {float(row.get('seconds') or 0.0):.1f}s "
            f"in {int(row.get('calls') or 0)} call(s); from {sources})"
        )
    margin = generation.get("margin")
    ceiling = generation.get("ceiling_s")
    for call, row in sorted((generation.get("timeouts") or {}).items()):
        if not isinstance(row, dict):
            continue
        configured = float(row.get("configured_s") or 0.0)
        applied = float(row.get("applied_s") or 0.0)
        if row.get("derived_s") is None:
            lines.append(
                f"Timeout of `{call}`: {applied:.0f}s, the configured value "
                "(no rate measured for its model yet, or no output budget)"
            )
            continue
        lines.append(
            f"Timeout of `{call}`: {applied:.0f}s — the larger of {configured:.0f}s configured "
            f"and {int(row.get('max_tokens') or 0)} tokens at "
            f"{float(row.get('tokens_per_second') or 0.0):.2f} tokens/s × {margin} "
            f"= {float(row['derived_s']):.0f}s, at most {float(ceiling or 0.0):.0f}s"
        )
    return lines


def tool_latency_lines(latency: Any) -> list[str]:
    """What each agent's tool calls cost, and which single call cost the most.

    Beside the per-stage line, because the two answer one question between
    them: a stage that took four minutes is a slow model or a slow tool, and
    only this says which. An agent whose calls were never timed contributes
    nothing rather than a row of zeros.
    """
    rows = []
    for agent, row in sorted((latency or {}).items()):
        if not isinstance(row, dict):
            continue
        slowest = row.get("slowest")
        if not isinstance(slowest, dict):
            continue
        total = float(row.get("total_ms") or 0) / 1000.0
        rows.append(
            f"{agent} {int(row.get('calls') or 0)} calls in {total:.1f}s, "
            f"slowest `{slowest.get('tool')}` {float(slowest.get('ms') or 0) / 1000.0:.1f}s"
        )
    return [f"**Tool calls**: {'; '.join(rows)}  "] if rows else []


def _attribution_layers() -> list[str]:
    """The layer order the per-layer breakdown renders, profile first.

    Was the literal ``("static", "dynamic", "network", "yara", "sigma")``,
    which named three analysts that a custom profile may not run and missed
    every analyst it does. The two rule layers stay appended: they are
    deterministic passes, not analysts, and they run whatever the profile says.
    """
    from maljan.agents.composition import current_analyst_keys

    try:
        analysts = current_analyst_keys()
    except Exception:  # noqa: BLE001 — a report renders even without settings
        analysts = ["static", "dynamic", "network"]
    return [*analysts, "yara", "sigma"]


# ---------------------------------------------------------------------------
# RunSummary
# ---------------------------------------------------------------------------


@dataclass
class RunSummary:
    """Full observability report for a single Maljan analysis run.

    Attributes:
        file_hash:          Sample identifier.
        file_name:          Human-readable filename (if provided).
        final_decision:     Pipeline verdict (Malware / Benign / Suspicious).
        stix_object_count:  Number of objects in the STIX Bundle.
        negotiation:        Negotiation loop metrics.
        agent_stats:        Per-agent ISR statistics.
        validation:         What the validation loop found (None if it never ran).
        corroboration:      Per technique id, the sources that named it.
        elapsed_seconds:    Wall-clock time from start to verdict.
        timestamp:          Unix timestamp of verdict generation.

        degraded_mode:      Set True when the verdict came from a partial /
                            failed pipeline (zero corroboration, analyst
                            errors).
        degradation_reasons: Human-readable bullets explaining why this run
                            is flagged as degraded.
        failed_analysts:    Names of analysts whose ``reports[name]`` started
                            with ``[ERROR]``.
        techniques_by_layer: How many techniques each source named, so the
                            report can show "1 capa + 9 static + 1 network"
                            instead of the opaque "11 techniques".
        profile:            which profile ran, the analysts it named, and
                            which of them are not built in.
    """

    file_hash: str
    file_name: str | None
    final_decision: str
    stix_object_count: int
    negotiation: NegotiationMetrics
    agent_stats: list[ISRAgentStats]
    validation: ValidationMetrics | None
    elapsed_seconds: float
    # Per technique id, ``{asserted_by: [deterministic sources], claimed_by:
    # [agents]}``. Two flat lists and no score.
    corroboration: dict[str, dict[str, list[str]]] = field(default_factory=dict)
    tokens: TokenUsageMetrics | None = None
    truncation: TruncationMetrics | None = None
    timestamp: float = field(default_factory=time.time)
    degraded_mode: bool = False
    degradation_reasons: list[str] = field(default_factory=list)
    failed_analysts: list[str] = field(default_factory=list)
    techniques_by_layer: dict[str, int] = field(default_factory=dict)
    profile: dict[str, Any] | None = None
    # What each stage of the profile did: ``{key, kind, ran, reason, agents,
    # duration_ms}`` in the order the profile declares them. A stage that
    # declined to run is here too, with the reason it gave — an absent row and
    # a skipped row mean different things and a reader has to be able to tell
    # them apart.
    stages: list[dict[str, Any]] = field(default_factory=list)
    # What the triage pack did: ``{entries, failed, duration_ms}``. ``None``
    # on a run whose team has no triage stage or whose pack declined to run,
    # which a reader has to be able to tell from a pack that wrote nothing.
    triage: dict[str, Any] | None = None
    # How the final-answer nudge had to be sent, per analyst, when the plain
    # way failed: ``{"retry_mode": {"static": "invalid_tool_calls_dropped"}}``.
    # ``None`` when no analyst needed a different way.
    nudge: dict[str, Any] | None = None
    # The budget meter, per agent: ``{loops, steps_used, max_steps,
    # elapsed_s, timeout_s, delegated_steps, caps}`` summed over the agent's
    # loops, ``caps`` being the caps that ended one of them (``steps``,
    # ``time``, ``repeats``, ``budget_seconds``). ``None`` on a run that
    # recorded no loop.
    budget: dict[str, Any] | None = None
    # What each agent's tool calls cost, from the ledger's own per-call clock:
    # ``{calls, total_ms, slowest: {tool, ms, id}}`` per agent. A run that
    # overran used to leave a reader deriving latency from raw timestamps, and
    # a slow tool could not be told from a slow model. ``None`` on a run whose
    # ledger holds no timed call.
    tool_latency: dict[str, Any] | None = None
    # Which model answered each agent's turns: ``{agent: {turns: {model:
    # count}, fallbacks: [{model, reason}]}}``. A fallback row is a turn
    # another model answered because the one before it failed as a provider,
    # with that failure in words. ``None`` on a run that recorded no turn.
    models: dict[str, Any] | None = None
    # The tool servers this run rested after a run of calls they did not answer:
    # ``[{server, failures, cooldown_s, reason}]`` in the order they opened.
    # ``None`` when no server was rested.
    server_rests: list[dict[str, Any]] | None = None
    # What the run's sandbox report is, when it is not a live sandbox's:
    # ``{status, statement}`` from ``pipeline.sandbox_status`` — no sandbox
    # ran, or the report is a recorded fixture. ``None`` when a sandbox
    # observed the run, which needs no sentence.
    sandbox: dict[str, str] | None = None
    # Each model's measured generation rate and each per-call timeout it
    # produced (``llm.generation_rate.GenerationRates.snapshot``). ``None`` on
    # a run that measured no answer and sized no call.
    generation: dict[str, Any] | None = None
    # ``dedupe`` is deliberately not a field here. What the report folded is
    # counted while the report's sections are built, which happens after this
    # object exists, so the report builder writes ``dedupe`` onto the summary
    # *dict* it was handed (``reporting.builder``). A field nothing could ever
    # set would read as a summary that folded nothing on every run.

    # ------------------------------------------------------------------
    # Rendering
    # ------------------------------------------------------------------

    def __post_init__(self) -> None:
        # A summary read back from storage may carry the flat rows written
        # before the two lists; every reader below assumes the current shape.
        self.corroboration = {
            tid: corroboration_row(row) for tid, row in (self.corroboration or {}).items()
        }

    def to_markdown(self) -> str:
        """Render the full run summary as a human-readable Markdown report."""
        sample_label = f"{self.file_hash}"
        if self.file_name:
            sample_label = f"{self.file_name} ({self.file_hash})"

        lines: list[str] = [
            "# Maljan Analysis Report",
            "",
            f"**Sample**: `{sample_label}`  ",
            f"**Verdict**: {self.final_decision}  ",
            f"**STIX objects**: {self.stix_object_count}  ",
            f"**Elapsed**: {self.elapsed_seconds:.1f}s  ",
            *([f"**Sandbox**: {self.sandbox['statement']}  "] if self.sandbox else []),
            *stage_duration_lines(self.stages),
            *tool_latency_lines(self.tool_latency),
            "",
        ]

        # Banner the degraded run prominently so a reader can't miss it when
        # scrolling. It names the reasons and nothing else: the confidence
        # above is the one the judge set knowing them, not a ceiling something
        # downstream applied to it.
        if self.degraded_mode:
            lines += [
                "> [!WARNING]",
                "> **DEGRADED RUN.** The verdict above was produced with reduced signal.",
                "",
            ]
            if self.degradation_reasons:
                lines += ["**Degradation reasons:**", ""]
                for reason in self.degradation_reasons:
                    lines.append(f"- {reason}")
                lines.append("")

        # Negotiation
        n = self.negotiation
        lines += [
            "## Negotiation",
            "",
            "| Metric | Value |",
            "|---|---|",
            f"| Rounds completed | {n.rounds_completed} / {n.max_rounds} |",
            f"| Termination reason | `{n.termination_reason}` |",
            f"| Sycophancy events | {n.sycophancy_events} |",
        ]
        if n.consensus_applicable and n.final_confidence is not None:
            lines += [
                f"| Final confidence | {n.final_confidence:.3f} |",
                f"| Converged early | {'yes' if n.converged_early else 'no'} |",
            ]
        lines.append("")
        if not n.consensus_applicable:
            lines += [NOT_APPLICABLE_SENTENCE, ""]

        if n.confidence_history:
            history_str = " → ".join(f"{c:.2f}" for c in n.confidence_history)
            lines.append(f"**Confidence history**: {history_str}")
            lines.append("")

        # Agent ISR statistics
        lines += ["## Agent ISR Statistics", ""]
        if self.agent_stats:
            lines.append("| Agent | Domain | Claims | Mean Conf | TTPs | Round | Dissent |")
            lines.append("|---|---|---|---|---|---|---|")
            for s in self.agent_stats:
                ttps = ", ".join(s.technique_ids) if s.technique_ids else "—"
                dissent = "yes" if s.has_dissent else "no"
                # An analyst with zero claims reads as a failure unless the
                # table says it had nothing to read (BUG 12).
                agent = f"{s.agent_id} (no data)" if s.no_data else s.agent_id
                lines.append(
                    f"| {agent} | {s.domain} | {s.claim_count} | "
                    f"{s.mean_confidence:.2f} | {ttps} | {s.revision_round} | {dissent} |"
                )
            lines.append("")
        else:
            lines += ["*No ISR reports collected.*", ""]

        # Corroboration
        if self.corroboration:
            published = published_count(self.corroboration)
            lines += [
                "## Corroboration",
                "",
                "Which sources named each technique: the deterministic sources that carry",
                "their own ATT&CK ids, and the agents. Two lists, not a combined confidence:",
                "nothing here multiplies one layer's number by another's. A row that names",
                "a technique this run did not publish says so, with the reason.",
                "",
                f"**{len(self.corroboration)} claimed, {published} published.**",
                "",
                "| Technique | Asserted by | Claimed by | Catalogue |",
                "|---|---|---|---|",
            ]
            for tid, sources in sorted(
                self.corroboration.items(),
                key=lambda item: (-len(corroboration_sources(item[1])), item[0]),
            ):
                asserted = ", ".join(sources.get("asserted_by") or []) or "—"
                claimed = ", ".join(sources.get("claimed_by") or []) or "—"
                associated = ", ".join(sources.get("associated_by") or []) or "—"
                lines.append(
                    f"| {technique_label(tid, sources)} | {asserted} | {claimed} | {associated} |"
                )
            lines.append("")
            if self.techniques_by_layer:
                lines.append("**Per-source attribution:**")
                lines.append("")
                layers_in_order = _attribution_layers()
                for layer in layers_in_order:
                    lines.append(f"- `{layer}`: {self.techniques_by_layer.get(layer, 0)}")
                for layer, count in sorted(self.techniques_by_layer.items()):
                    if layer not in set(layers_in_order):
                        lines.append(f"- `{layer}`: {count}")
                lines.append("")
        else:
            lines += ["## Corroboration", "", "*No technique was named by any source.*", ""]

        # Always render the
        # failed-analyst section so operators see "0 failures" rather than
        # ambiguity.
        lines += ["## Analyst Errors", ""]
        if self.failed_analysts:
            for name in self.failed_analysts:
                lines.append(f"- `{name}` — reported `[ERROR]` status")
        else:
            lines.append("*No analyst failures recorded.*")
        lines.append("")

        # Validation loop
        if self.validation:
            v = self.validation
            lines += [
                "## Validation",
                "",
                "| Metric | Value |",
                "|---|---|",
                f"| Feedback retries | {v.retries} |",
                f"| Unresolved findings | {len(v.unresolved)} |",
                "",
            ]
            if v.by_code:
                lines += ["| Code | Count |", "|---|---|"]
                lines += [f"| {code} | {count} |" for code, count in sorted(v.by_code.items())]
                lines.append("")
            if v.unresolved:
                lines.append("**Still wrong after the retry:**")
                lines.append("")
                for row in v.unresolved:
                    lines.append(
                        f"- `{row.get('agent', '?')}` / `{row.get('code', '?')}`: "
                        f"{row.get('message', '')}"
                    )
                lines.append("")
        else:
            lines += ["## Validation", "", "*Validation did not run.*", ""]

        # What the model calls spent, in the providers' own figures.
        if self.tokens:
            tok = self.tokens
            lines += ["## Token Usage", "", self._tokens_dict()["sentence"], ""]
            if tok.per_agent:
                lines += [
                    "| Agent | Calls | Input | Output | Not reported | Models |",
                    "|---|---|---|---|---|---|",
                ]
                for agent, spent in sorted(tok.per_agent.items()):
                    turns: dict[str, Any] = dict(spent.get("models") or {})
                    answered = ", ".join(f"{name} ×{count}" for name, count in turns.items())
                    # Nothing reported is said, not printed as a zero count.
                    silent = int(spent.get("unreported_calls", 0) or 0) >= int(
                        spent.get("llm_calls", 0) or 0
                    )
                    inp = "not reported" if silent else spent.get("input_tokens", 0)
                    out = "not reported" if silent else spent.get("output_tokens", 0)
                    lines.append(
                        f"| {agent} | {spent.get('llm_calls', 0)} | {inp} | {out} | "
                        f"{spent.get('unreported_calls', 0)} | {answered or '—'} |"
                    )
                lines.append("")

        fallbacks = [
            (agent, row)
            for agent, block in sorted((self.models or {}).items())
            for row in (block.get("fallbacks") or [])
        ]
        if fallbacks:
            lines += ["## Model Fallbacks", ""]
            for agent, row in fallbacks:
                lines.append(f"- `{agent}`: {row.get('reason', '')}")
            lines.append("")

        if self.server_rests:
            lines += ["## Tool Servers Rested", ""]
            for row in self.server_rests:
                lines.append(f"- {server_rest_sentence(row)}")
            lines.append("")

        generation = generation_lines(self.generation)
        if generation:
            lines += ["## Generation Rate", "", *(f"- {line}" for line in generation), ""]

        if self.truncation:
            trunc = self.truncation
            lines += [
                "## Bounds Hit",
                "",
                "| Bound | Hits / calls |",
                "|---|---|",
                f"| Tool output over limit | {trunc.tool_output_over_limit}"
                f" / {trunc.tool_output_calls} |",
                f"| — summarised | {trunc.tool_output_summarised} |",
                f"| — hard truncated | {trunc.tool_output_hard_truncated} |",
                f"| — shortened as a document | {trunc.tool_output_shortened} |",
                f"| — shortening gave up on its clock | {trunc.tool_output_shortening_timeouts} |",
                f"| — no room left for the answer | {trunc.tool_output_no_room} |",
                f"| — handed over whole without its whitespace | {trunc.tool_output_compacted} |",
                f"| Characters dropped | {trunc.tool_output_chars_dropped} |",
                f"| ReAct step cap | {trunc.react_step_cap_hits} / {trunc.react_invocations} |",
                f"| Judge token cap | {trunc.judge_token_cap_hits} / {trunc.judge_invocations} |",
                f"| STIX indicators over the cap | {trunc.indicator_cap_removed} |",
                f"| STIX references trimmed | {trunc.integrity_refs_trimmed} |",
                f"| Judge bundles repaired | {trunc.judge_integrity_objects_removed}"
                f" over {trunc.judge_integrity_invocations} attempt(s) |",
                "",
            ]
            cap = cap_in_force_sentence(trunc)
            if cap:
                lines += [cap, ""]
            # Said only where the two counts could be read against each other
            # and disagree, or where something was actually cut. On a run that
            # hit no bound and counted the same calls twice it is a paragraph
            # explaining a difference the reader cannot see.
            if trunc.any_bound_hit or _recorded_calls(self.tool_latency) != trunc.tool_output_calls:
                lines += [
                    "Tool output calls are the answers a tool server returned through the "
                    "guardrail. The per-call latency table counts every recorded call, so it "
                    "also holds the ones answered in process, which no guardrail sees.",
                    "",
                ]
            if trunc.evidence_corpus_partial_reason:
                lines += [
                    "Grounding searched less than this run produced "
                    f"({trunc.evidence_corpus_partial_reason}): "
                    f"{trunc.evidence_corpus_missing_answers} answer(s) not kept"
                    + (
                        f", from {', '.join(trunc.evidence_corpus_missing_tools)}"
                        if trunc.evidence_corpus_missing_tools
                        else ""
                    )
                    + ". An absence measured against it is a note and drops nothing.",
                    "",
                ]
            corpus_held = corpus_held_sentence(trunc)
            if corpus_held:
                lines += [corpus_held, ""]
            # The reasons, never the total: a line printing
            # ``integrity_objects_removed`` called the cap's orphaned
            # relationships repairs, and said 10 where the console said 4.
            loss = bundle_loss_sentence(trunc)
            if loss:
                lines += [loss, ""]
            if any(trunc.integrity_dropped.values()):
                reasons = ", ".join(
                    f"{k}={v}" for k, v in sorted(trunc.integrity_dropped.items()) if v
                )
                lines += [f"STIX integrity removals: {reasons}", ""]

        return "\n".join(lines)

    def _tokens_dict(self) -> dict[str, Any]:
        """``tokens`` as it is stored, the sentence the report prints included."""
        tok = self.tokens
        if tok is None:
            return {}
        out: dict[str, Any] = {
            "input_tokens": tok.input_tokens,
            "output_tokens": tok.output_tokens,
            "total_tokens": tok.total_tokens,
            "llm_calls": tok.llm_calls,
            "unreported_calls": tok.unreported_calls,
            "per_agent": {agent: dict(row) for agent, row in sorted(tok.per_agent.items())},
        }
        if tok.cost is not None and tok.cost_calls:
            out["cost"] = round(tok.cost, 6)
            out["cost_calls"] = tok.cost_calls
        out["sentence"] = tokens_sentence(out) or ""
        return out

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a JSON-compatible dict."""
        n = self.negotiation
        result: dict[str, Any] = {
            "file_hash": self.file_hash,
            "file_name": self.file_name,
            "final_decision": self.final_decision,
            "stix_object_count": self.stix_object_count,
            "elapsed_seconds": round(self.elapsed_seconds, 3),
            "timestamp": self.timestamp,
            "negotiation": {
                "rounds_completed": n.rounds_completed,
                "max_rounds": n.max_rounds,
                "termination_reason": n.termination_reason,
                "sycophancy_events": n.sycophancy_events,
                "confidence_history": n.confidence_history,
                # Absent, not zero, when no agreement was measured.
                **(
                    {
                        "final_confidence": round(n.final_confidence, 4),
                        "converged_early": n.converged_early,
                    }
                    if n.consensus_applicable and n.final_confidence is not None
                    else {}
                ),
            },
            "agent_stats": [
                {
                    "agent_id": s.agent_id,
                    "domain": s.domain,
                    "revision_round": s.revision_round,
                    "claim_count": s.claim_count,
                    "mean_confidence": round(s.mean_confidence, 4),
                    "technique_ids": s.technique_ids,
                    "has_dissent": s.has_dissent,
                    "no_data": s.no_data,
                    "status": s.status,
                }
                for s in self.agent_stats
            ],
            "validation": None,
            "corroboration": {
                k: corroboration_row(v) for k, v in sorted(self.corroboration.items())
            },
            "tokens": None,
            "degraded_mode": self.degraded_mode,
            "degradation_reasons": list(self.degradation_reasons),
            "failed_analysts": list(self.failed_analysts),
            "techniques_by_layer": dict(self.techniques_by_layer),
            "profile": dict(self.profile) if self.profile else None,
            "stages": [dict(row) for row in self.stages],
            "triage": dict(self.triage) if self.triage else None,
            "nudge": dict(self.nudge) if self.nudge else None,
            "budget": dict(self.budget) if self.budget else None,
            "tool_latency": dict(self.tool_latency) if self.tool_latency else None,
            "sandbox": dict(self.sandbox) if self.sandbox else None,
        }

        if self.validation:
            result["validation"] = {
                "retries": self.validation.retries,
                "by_code": dict(sorted(self.validation.by_code.items())),
                "unresolved": [dict(row) for row in self.validation.unresolved],
                "not_run": list(self.validation.not_run),
            }

        if self.tokens:
            result["tokens"] = self._tokens_dict()
        result["models"] = dict(self.models) if self.models else None
        result["server_rests"] = [dict(row) for row in self.server_rests or []] or None

        if self.generation:
            result["generation"] = dict(self.generation)

        if self.truncation:
            t = self.truncation
            result["truncation"] = {
                "tool_output_calls": t.tool_output_calls,
                "tool_output_over_limit": t.tool_output_over_limit,
                "tool_output_summarised": t.tool_output_summarised,
                "tool_output_hard_truncated": t.tool_output_hard_truncated,
                "tool_output_shortened": t.tool_output_shortened,
                "tool_output_shortening_timeouts": t.tool_output_shortening_timeouts,
                "tool_output_no_room": t.tool_output_no_room,
                "tool_output_compacted": t.tool_output_compacted,
                "tool_output_chars_dropped": t.tool_output_chars_dropped,
                "react_invocations": t.react_invocations,
                "react_step_cap_hits": t.react_step_cap_hits,
                "judge_invocations": t.judge_invocations,
                "judge_token_cap_hits": t.judge_token_cap_hits,
                "integrity_invocations": t.integrity_invocations,
                "integrity_objects_removed": t.integrity_objects_removed,
                "integrity_refs_trimmed": t.integrity_refs_trimmed,
                "integrity_dropped": dict(t.integrity_dropped),
                "indicator_cap_invocations": t.indicator_cap_invocations,
                "indicator_cap_removed": t.indicator_cap_removed,
                "judge_integrity_invocations": t.judge_integrity_invocations,
                "judge_integrity_objects_removed": t.judge_integrity_objects_removed,
                "judge_integrity_dropped": dict(t.judge_integrity_dropped),
                "evidence_corpus_missing_answers": t.evidence_corpus_missing_answers,
                "evidence_corpus_missing_tools": list(t.evidence_corpus_missing_tools),
                "evidence_corpus_partial_reason": t.evidence_corpus_partial_reason,
                "tool_output_limit_smallest": t.tool_output_limit_smallest,
                "tool_output_limit_largest": t.tool_output_limit_largest,
                "context_window": dict(t.context_window),
                "any_bound_hit": t.any_bound_hit,
            }
            # Absent rather than zero when this run recorded nothing about
            # what its corpus held: a stored summary written before the
            # figures existed must not read as a corpus that held nothing.
            for key, value in (
                ("evidence_corpus_answers", t.evidence_corpus_answers),
                ("evidence_corpus_bytes_held", t.evidence_corpus_bytes_held),
                ("evidence_corpus_bytes_ceiling", t.evidence_corpus_bytes_ceiling),
            ):
                if value is not None:
                    result["truncation"][key] = value

        return result


# ---------------------------------------------------------------------------
# Builder
# ---------------------------------------------------------------------------


class RunSummaryBuilder:
    """Constructs a RunSummary from pipeline state and phase-specific results.

    Designed to be called once at the end of the judge node, after all
    pipeline phases have completed.

    Usage:
        builder = RunSummaryBuilder(start_time=t0)
        builder.set_sample(file_hash, file_name)
        builder.set_verdict(final_decision, stix_object_count)
        builder.set_negotiation(state)
        builder.set_isr_stats(isr_reports)
        builder.set_validation(validation_metrics)
        builder.set_corroboration(corroboration)
        summary = builder.build()
    """

    def __init__(self, start_time: float) -> None:
        self._start_time = start_time
        self._file_hash: str = ""
        self._file_name: str | None = None
        self._final_decision: str = "Unknown"
        self._stix_object_count: int = 0
        self._negotiation: NegotiationMetrics | None = None
        self._agent_stats: list[ISRAgentStats] = []
        self._validation: ValidationMetrics | None = None
        self._corroboration: dict[str, dict[str, list[str]]] = {}
        self._degraded_mode: bool = False
        self._degradation_reasons: list[str] = []
        self._failed_analysts: list[str] = []
        self._techniques_by_layer: dict[str, int] = {}
        self._tokens: TokenUsageMetrics | None = None
        self._generation: dict[str, Any] | None = None
        self._truncation: TruncationMetrics | None = None
        self._profile: dict[str, Any] | None = None
        self._stages: list[dict[str, Any]] = []
        self._triage: dict[str, Any] | None = None
        self._sandbox: dict[str, str] | None = None
        self._nudge: dict[str, Any] | None = None
        self._budget: dict[str, Any] | None = None
        self._tool_latency: dict[str, Any] | None = None
        self._models: dict[str, Any] | None = None
        self._server_rests: list[dict[str, Any]] | None = None

    def set_budget(self, records: dict[str, list[dict[str, Any]]] | None) -> RunSummaryBuilder:
        """What each agent spent, summed over its loops, and the caps that ended them.

        ``records`` is the state channel the nodes write: per agent, one row
        per loop as ``BaseAnalyst`` recorded it. Summed here rather than kept
        as rows because the summary is read per agent; the caps are kept as
        the distinct list, in the order they were hit.
        """
        out: dict[str, Any] = {}
        for agent, rows in (records or {}).items():
            loops = [row for row in (rows or []) if isinstance(row, dict)]
            if not loops:
                continue
            caps: list[str] = []
            for row in loops:
                cap = row.get("cap")
                if cap and str(cap) not in caps:
                    caps.append(str(cap))
            out[str(agent)] = {
                "loops": len(loops),
                "steps_used": sum(int(row.get("steps_used") or 0) for row in loops),
                "max_steps": max(int(row.get("max_steps") or 0) for row in loops),
                "elapsed_s": round(sum(float(row.get("elapsed_s") or 0.0) for row in loops), 1),
                "timeout_s": max(float(row.get("timeout_s") or 0.0) for row in loops),
                "delegated_steps": sum(int(row.get("delegated_steps") or 0) for row in loops),
                "caps": caps,
            }
        self._budget = out or None
        return self

    def set_tool_latency(self, entries: Any) -> RunSummaryBuilder:
        """What each agent's tool calls cost, per agent, from the ledger.

        Every ledger entry carries the clock of its own round trip, so the
        question "was the model slow or was the tool slow" is answerable
        without deriving anything from raw timestamps. Three numbers per
        agent — how many calls, how long they took together, and the single
        slowest with the tool that answered it — because the slowest call is
        what an operator looks for first when a run overran and a list of
        every call is the ledger, which is already there.

        A call with no measured duration contributes to the count and to
        nothing else: a zero is not a measurement.
        """
        rows: dict[str, dict[str, Any]] = {}
        for entry in entries or []:
            row = entry if isinstance(entry, dict) else getattr(entry, "__dict__", None)
            if not isinstance(row, dict):
                continue
            agent = str(row.get("agent") or "").strip()
            tool = str(row.get("tool") or "").strip()
            if not agent or not tool:
                continue
            try:
                ms = int(row.get("duration_ms") or 0)
            except (TypeError, ValueError):
                ms = 0
            seen = rows.setdefault(agent, {"calls": 0, "total_ms": 0, "slowest": None})
            seen["calls"] += 1
            if ms <= 0:
                continue
            seen["total_ms"] += ms
            slowest = seen["slowest"]
            if slowest is None or ms > int(slowest["ms"]):
                seen["slowest"] = {"tool": tool, "ms": ms, "id": str(row.get("id") or "")}
        self._tool_latency = rows or None
        return self

    def set_nudge(self, retry_modes: dict[str, str] | None) -> RunSummaryBuilder:
        """Which analysts needed the nudge sent another way, and which way."""
        modes = {str(k): str(v) for k, v in (retry_modes or {}).items() if v}
        self._nudge = {"retry_mode": modes} if modes else None
        return self

    def set_triage(self, facts: dict[str, Any] | None) -> RunSummaryBuilder:
        """The pack's three counts, out of the state channel the triage node wrote.

        Only the counts: the four facts are for the stage conditions and the
        prompts, and the ledger holds the entries themselves.
        """
        if facts and "entries" in facts:
            self._triage = {
                "entries": int(facts.get("entries") or 0),
                "failed": int(facts.get("failed") or 0),
                "duration_ms": int(facts.get("duration_ms") or 0),
            }
        return self

    def set_sandbox(self, report: Any) -> RunSummaryBuilder:
        """What the run's sandbox report is, when no live sandbox observed the run."""
        from maljan.pipeline.sandbox_status import OBSERVED, sandbox_status

        found = sandbox_status(report)
        self._sandbox = (
            None
            if found.status == OBSERVED
            else {"status": found.status, "statement": found.statement}
        )
        return self

    def set_degraded_mode(
        self, degraded: bool, reasons: list[str] | None = None
    ) -> RunSummaryBuilder:
        """Mark the run as degraded with optional human-readable reasons."""
        self._degraded_mode = bool(degraded)
        self._degradation_reasons = list(reasons or [])
        return self

    def set_token_usage(self, snapshot: dict[str, Any] | None) -> RunSummaryBuilder:
        """What the run spent and which models answered, from a ``TokenLedger.snapshot()``.

        A None / empty snapshot leaves ``tokens`` and ``models`` unset (mock
        runs and zero-call runs render no Token Usage section). The per-agent
        model counts and the fallbacks come out of the same snapshot, because
        the call that is counted is the call whose model is named.
        """
        if not snapshot or not snapshot.get("llm_calls"):
            return self
        raw_agents = snapshot.get("agents")
        agents: dict[str, Any] = raw_agents if isinstance(raw_agents, dict) else {}
        cost = snapshot.get("cost")
        self._tokens = TokenUsageMetrics(
            input_tokens=int(snapshot.get("input_tokens", 0)),
            output_tokens=int(snapshot.get("output_tokens", 0)),
            total_tokens=int(snapshot.get("total_tokens", 0)),
            llm_calls=int(snapshot.get("llm_calls", 0)),
            unreported_calls=int(snapshot.get("unreported_calls", 0)),
            cost=float(cost) if isinstance(cost, int | float) else None,
            cost_calls=int(snapshot.get("cost_calls", 0) or 0),
            per_agent={str(name): dict(row) for name, row in agents.items()},
        )
        models: dict[str, Any] = {}
        for name, row in agents.items():
            turns = dict(row.get("models") or {})
            if turns:
                models[str(name)] = {"turns": turns, "fallbacks": []}
        for row in snapshot.get("fallbacks") or []:
            agent = str(row.get("agent") or "")
            block = models.setdefault(agent, {"turns": {}, "fallbacks": []})
            block["fallbacks"].append(
                {"model": str(row.get("model") or ""), "reason": str(row.get("reason") or "")}
            )
        self._models = models or None
        return self

    def set_server_rests(self, rows: list[dict[str, Any]] | None) -> RunSummaryBuilder:
        """The tool servers this run rested, in the order their breakers opened."""
        self._server_rests = [dict(row) for row in rows or [] if isinstance(row, dict)] or None
        return self

    def set_generation(self, snapshot: dict[str, Any] | None) -> RunSummaryBuilder:
        """Record the measured generation rates and the timeouts they produced.

        A snapshot with no measured model and no sized call leaves it unset.
        """
        if isinstance(snapshot, dict) and (snapshot.get("models") or snapshot.get("timeouts")):
            self._generation = dict(snapshot)
        return self

    def set_truncation(self, snapshot: dict[str, Any] | None) -> RunSummaryBuilder:
        """Record bound-hits from a ``TruncationLedger.snapshot()`` (pitfall P6).

        Unlike ``set_token_usage``, a snapshot with **zero** hits is still
        recorded when anything was measured at all: "nothing was truncated on
        this run" is the answer P6 asks for just as much as a nonzero count is,
        and dropping it would leave the aggregate unable to tell *no truncation*
        from *not instrumented*.
        """
        if not snapshot:
            return self
        measured = (
            int(snapshot.get("tool_output_calls", 0))
            or int(snapshot.get("react_invocations", 0))
            or int(snapshot.get("judge_invocations", 0))
            or int(snapshot.get("integrity_invocations", 0))
        )
        if not measured:
            return self
        dropped = snapshot.get("integrity_dropped")
        judge_dropped = snapshot.get("judge_integrity_dropped")
        self._truncation = TruncationMetrics(
            tool_output_calls=int(snapshot.get("tool_output_calls", 0)),
            tool_output_over_limit=int(snapshot.get("tool_output_over_limit", 0)),
            tool_output_summarised=int(snapshot.get("tool_output_summarised", 0)),
            tool_output_hard_truncated=int(snapshot.get("tool_output_hard_truncated", 0)),
            tool_output_shortened=int(snapshot.get("tool_output_shortened", 0)),
            tool_output_shortening_timeouts=int(snapshot.get("tool_output_shortening_timeouts", 0)),
            tool_output_no_room=int(snapshot.get("tool_output_no_room", 0)),
            tool_output_compacted=int(snapshot.get("tool_output_compacted", 0)),
            tool_output_chars_dropped=int(snapshot.get("tool_output_chars_dropped", 0)),
            react_invocations=int(snapshot.get("react_invocations", 0)),
            react_step_cap_hits=int(snapshot.get("react_step_cap_hits", 0)),
            judge_invocations=int(snapshot.get("judge_invocations", 0)),
            judge_token_cap_hits=int(snapshot.get("judge_token_cap_hits", 0)),
            integrity_invocations=int(snapshot.get("integrity_invocations", 0)),
            integrity_objects_removed=int(snapshot.get("integrity_objects_removed", 0)),
            integrity_refs_trimmed=int(snapshot.get("integrity_refs_trimmed", 0)),
            integrity_dropped=dict(dropped) if isinstance(dropped, dict) else {},
            indicator_cap_invocations=int(snapshot.get("indicator_cap_invocations", 0)),
            indicator_cap_removed=int(snapshot.get("indicator_cap_removed", 0)),
            judge_integrity_invocations=int(snapshot.get("judge_integrity_invocations", 0)),
            judge_integrity_objects_removed=int(snapshot.get("judge_integrity_objects_removed", 0)),
            judge_integrity_dropped=(
                dict(judge_dropped) if isinstance(judge_dropped, dict) else {}
            ),
            evidence_corpus_missing_answers=int(snapshot.get("evidence_corpus_missing_answers", 0)),
            evidence_corpus_missing_tools=[
                str(tool) for tool in (snapshot.get("evidence_corpus_missing_tools") or [])
            ],
            evidence_corpus_partial_reason=str(
                snapshot.get("evidence_corpus_partial_reason", "") or ""
            ),
            evidence_corpus_answers=_optional_count(snapshot.get("evidence_corpus_answers")),
            evidence_corpus_bytes_held=_optional_count(snapshot.get("evidence_corpus_bytes_held")),
            evidence_corpus_bytes_ceiling=_optional_count(
                snapshot.get("evidence_corpus_bytes_ceiling")
            ),
            tool_output_limit_smallest=int(snapshot.get("tool_output_limit_smallest", 0)),
            tool_output_limit_largest=int(snapshot.get("tool_output_limit_largest", 0)),
            context_window=(
                dict(window) if isinstance(window := snapshot.get("context_window"), dict) else {}
            ),
        )
        return self

    def set_failed_analysts(self, names: list[str]) -> RunSummaryBuilder:
        """Record analysts whose reports failed with an [ERROR] prefix."""
        self._failed_analysts = list(names)
        return self

    def set_stages(self, stages: list[dict[str, Any]]) -> RunSummaryBuilder:
        """Record what each stage of the profile did."""
        self._stages = [dict(row) for row in stages]
        return self

    def set_profile(self, name: str, analysts: list[str], custom: list[str]) -> RunSummaryBuilder:
        """Record which ensemble ran (spec §5).

        ``custom`` is the subset of ``analysts`` that is not one of the four
        built-in definitions — what the report and the pipeline panel badge, so
        a reader can tell a measured run from an operator's own arrangement.
        """
        self._profile = {
            "name": name,
            "analysts": list(analysts),
            "custom": list(custom),
        }
        return self

    def set_sample(self, file_hash: str, file_name: str | None) -> RunSummaryBuilder:
        self._file_hash = file_hash
        self._file_name = file_name
        return self

    def set_verdict(self, final_decision: str, stix_object_count: int) -> RunSummaryBuilder:
        self._final_decision = final_decision
        self._stix_object_count = stix_object_count
        return self

    def set_negotiation(
        self,
        state: dict[str, Any],
        max_iterations: int | None = None,
    ) -> RunSummaryBuilder:
        """Extract negotiation metrics from the final pipeline state.

        Args:
            state: Final AnalysisState (subset OK).
            max_iterations: Configured hard limit. If None, falls back to
                ``iteration_count`` so the report stays self-consistent.
        """
        confidence_history: list[float] = state.get("confidence_history") or []
        iteration_count: int = state.get("iteration_count", 0)
        is_consensus = bool(state.get("is_consensus", False))
        sycophancy_detected: bool = state.get("sycophancy_detected", False)
        discussion_history = state.get("discussion_history") or []

        sycophancy_events = sum(
            1
            for arg in discussion_history
            if getattr(arg, "agent_name", "") == "Mediator"
            and "sycophancy" in getattr(arg, "finding", "").lower()
        )
        if sycophancy_detected and sycophancy_events == 0:
            sycophancy_events = 1

        applicable = state.get("consensus_applicable", True) is not False
        if not applicable:
            termination_reason = NOT_APPLICABLE
        elif is_consensus:
            termination_reason = "consensus"
        elif len(confidence_history) >= 3:
            recent = confidence_history[-3:]
            std = _rolling_std(recent)
            termination_reason = "convergence" if std < 0.02 else "hard_limit"
        else:
            termination_reason = "hard_limit"

        if max_iterations is None:
            # Backward-compat: legacy callers passed state with "_max_iterations".
            max_iterations = state.get("_max_iterations", iteration_count)

        self._negotiation = NegotiationMetrics(
            rounds_completed=iteration_count,
            max_rounds=max_iterations,
            termination_reason=termination_reason,
            sycophancy_events=sycophancy_events,
            confidence_history=confidence_history,
            final_confidence=(
                None if not applicable else confidence_history[-1] if confidence_history else 0.0
            ),
        )
        return self

    def set_isr_stats(
        self, isr_reports: dict[str, Any], no_data: set[str] | None = None
    ) -> RunSummaryBuilder:
        """Extract per-agent ISR statistics.

        ``no_data`` names the analysts that had nothing to analyse, so a reader
        can tell them from the ones that analysed their data and claimed
        nothing. Optional, and empty by default: every caller that does not know
        the difference reports what it always did.

        The third case is the analyst's own: an ISR that carries a ``status``
        had data, read it, and its model ended without a report. That is
        neither of the other two and the row now says so.
        """
        starved = no_data or set()
        stats: list[ISRAgentStats] = []
        for isr in isr_reports.values():
            technique_ids = [c.technique_id for c in isr.claims if c.technique_id is not None]
            stats.append(
                ISRAgentStats(
                    agent_id=isr.agent_id,
                    domain=isr.domain,
                    revision_round=isr.revision_round,
                    claim_count=len(isr.claims),
                    mean_confidence=isr.mean_confidence,
                    technique_ids=list(dict.fromkeys(technique_ids)),  # deduplicate, preserve order
                    has_dissent=bool(isr.dissent_items),
                    no_data=isr.agent_id in starved,
                    status=str(getattr(isr, "status", "") or ""),
                )
            )
        self._agent_stats = stats
        return self

    def set_validation(self, metrics: dict[str, Any] | None) -> RunSummaryBuilder:
        """Record the validation loop's tally (``pipeline.validation``)."""
        if not metrics:
            return self
        self._validation = ValidationMetrics(
            retries=int(metrics.get("retries") or 0),
            by_code=dict(metrics.get("by_code") or {}),
            unresolved=[dict(row) for row in metrics.get("unresolved") or []],
            not_run=[str(code) for code in metrics.get("not_run") or []],
        )
        return self

    def set_corroboration(self, corroboration: dict[str, Any] | None) -> RunSummaryBuilder:
        """Record who asserted and who claimed each technique, and count per source.

        A flat list of sources — the shape stored before the two lists — is
        read as claimed by all of them, so an older summary still builds.
        """
        self._corroboration = {
            tid: corroboration_row(row) for tid, row in (corroboration or {}).items()
        }
        counts: dict[str, int] = {}
        for row in self._corroboration.values():
            for source in corroboration_sources(row):
                counts[str(source)] = counts.get(str(source), 0) + 1
        self._techniques_by_layer = counts
        return self

    def build(self) -> RunSummary:
        """Construct the final RunSummary. Raises ValueError if incomplete."""
        if self._negotiation is None:
            self._negotiation = NegotiationMetrics(
                rounds_completed=0,
                max_rounds=0,
                termination_reason="unknown",
                sycophancy_events=0,
                confidence_history=[],
                final_confidence=0.0,
            )

        return RunSummary(
            file_hash=self._file_hash,
            file_name=self._file_name,
            final_decision=self._final_decision,
            stix_object_count=self._stix_object_count,
            negotiation=self._negotiation,
            agent_stats=self._agent_stats,
            validation=self._validation,
            elapsed_seconds=time.time() - self._start_time,
            corroboration=self._corroboration,
            tokens=self._tokens,
            models=self._models,
            server_rests=self._server_rests,
            truncation=self._truncation,
            degraded_mode=self._degraded_mode,
            degradation_reasons=self._degradation_reasons,
            failed_analysts=self._failed_analysts,
            techniques_by_layer=self._techniques_by_layer,
            profile=self._profile,
            stages=self._stages,
            triage=self._triage,
            nudge=self._nudge,
            budget=self._budget,
            tool_latency=self._tool_latency,
            sandbox=self._sandbox,
            generation=self._generation,
        )


# ---------------------------------------------------------------------------
# Pure-Python helper (avoids importing from routing to prevent circular deps)
# ---------------------------------------------------------------------------


def _rolling_std(values: list[float]) -> float:
    """Population standard deviation of the provided values."""
    if len(values) < 2:
        return float("inf")
    mean = sum(values) / len(values)
    variance = sum((v - mean) ** 2 for v in values) / len(values)
    return float(variance**0.5)
