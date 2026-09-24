"""Per-run tally of every place this pipeline hit a bound.

*Chasing Shadows* (`arXiv:2512.09549`, NDSS'26) names **context truncation** as
pitfall P6 and asks for one specific thing: *"report truncation frequency and
performance impacts."* Maljan's self-audit scored that row `EXPOSED` — not
because truncation is hidden, but because it is everywhere and **nobody has ever
counted it**. Tool output is capped at ``max_tool_output_chars``; the ReAct loop
is capped at ``react_agent_max_steps``; the judge is capped at
``judge_max_tokens``; and all of it runs inside ``-c 131072`` on a model whose
native context is 262,144, so the window itself is a deliberate halving
(findings-log §2.0).

``TruncationLedger`` is the counter that was missing. It follows
:class:`~maljan.core.token_ledger.TokenLedger` exactly — one thread-safe
instance per run on the ``ServiceContainer``, written to at each bound, and
snapshotted into the ``RunSummary`` by the judge node.

It also carries the **STIX integrity pass** counters, which are not truncation
but are the same kind of question: the pass drops malformed indicators, dedups
attack-patterns and prunes dangling relationships, and the claim that repairing
is better than rejecting needs a number for *how often the pass fires* and
*what it removes*.

Recording never raises. Telemetry that can break an analysis is worse than no
telemetry, which is the same rule ``TokenLedger`` follows.
"""

from __future__ import annotations

import threading

# Reasons the STIX integrity pass removes an object. Fixed set, because a
# free-form reason string turns the aggregate into something nobody can total.
INTEGRITY_REASONS = (
    "empty_pattern",
    "duplicate_attack_pattern",
    "duplicate_indicator",
    "dangling_relationship",
    "duplicate_relationship",
    # The pass runs a second time after the indicator cap, and everything it
    # takes out there is something the cap orphaned — a relationship whose
    # endpoint is no longer in the bundle. Its own reason, because it is the
    # cap's loss rather than a defect of anybody's bundle, and because that
    # second pass used to run without a ledger at all, so what it removed was
    # counted nowhere.
    "cap_orphan",
)

# What the indicator cap itself removed, and what step 5 of the integrity pass
# takes out of a report's or a note's ``object_refs`` without removing an
# object. Neither is a repair and neither belongs in ``INTEGRITY_REASONS`` —
# the reasons there total to what the pass removed, and folding two other
# kinds of loss in would break that total. They are counted here so that
# everything that leaves a bundle leaves under a name.
INDICATOR_CAP_REASON = "indicator_cap"
REFS_TRIMMED_REASON = "refs_trimmed"

# Whose removals a run of the integrity pass is. The pass runs on two bundles
# and the two do not add up to one number: the export's passes act on the
# bundle that is published, while the judge path's run once per verdict
# *attempt* — including an attempt whose bundle was discarded and retried, and
# on objects the export may never carry. Summed together, the total could not
# be reconciled with anything a reader holds. The export's figures are the ones
# the run summary reconciles; the judge path's are kept under their own name.
EXPORT_PASS = "export"
JUDGE_PASS = "judge"


def truncation_rate(over_limit: int, calls: int) -> float:
    """Fraction of calls that exceeded the bound. 0.0 when nothing was called.

    Separate from the ledger so the arithmetic behind a reported number is
    unit-tested independently of the accumulation, which is the repo's
    ``test_*_scoring.py`` convention.
    """
    if calls <= 0:
        return 0.0
    return max(0, over_limit) / calls


def chars_dropped(chars_in: int, chars_kept: int) -> int:
    """Characters removed by the guardrail. Never negative.

    A summariser may legitimately *expand* a short input; clamping at zero keeps
    a rewrite from reading as negative loss.
    """
    return max(0, chars_in - chars_kept)


def record_guardrail_outcome(
    ledger: object | None,
    *,
    chars_in: int,
    chars_kept: int,
    over_limit: bool,
    summarised: bool = False,
    hard_truncated: bool = False,
    shortened: bool = False,
    shortening_timed_out: bool = False,
    no_room: bool = False,
    compacted: bool = False,
    limit: int = 0,
) -> None:
    """Record one tool-output guardrail decision on ``ledger``.

    A free function rather than a method on each caller because the guardrail
    exists twice — ``MCPLangChainToolkit`` (stdio) and ``GhidraHTTPClient``
    (HTTP, the production path) each carry their own copy. One implementation
    of the swallow-everything contract is better than two that drift.

    ``limit`` is the cap that was in force for this one call. It is recorded
    because the cap is no longer a constant an operator can read off the
    settings page: derived, it is worked out per call from what the window has
    left, so a reader asking why an answer was cut needs the number that cut it.

    No-op when ``ledger`` is None; never raises.
    """
    if ledger is None:
        return
    try:
        ledger.record_tool_output(  # type: ignore[attr-defined]
            chars_in=chars_in,
            chars_kept=chars_kept,
            over_limit=over_limit,
            summarised=summarised,
            hard_truncated=hard_truncated,
            shortened=shortened,
            shortening_timed_out=shortening_timed_out,
            no_room=no_room,
            compacted=compacted,
            limit=limit,
        )
    except Exception:  # noqa: BLE001 — telemetry must never break a tool call
        return


def hit_length_cap(response: object) -> bool:
    """True when a provider stopped generating because it ran out of tokens.

    OpenAI-compatible servers — llama-server included — report this as
    ``finish_reason == "length"`` (some emit ``stop_reason``/``max_tokens``).
    That is the direct signal for ``judge_max_tokens`` binding, and §1.7.1
    showed a bounded judge is not a hypothetical: without the schema-pruning
    hint the model overran a 600 s ceiling and produced an empty bundle 6/17
    times instead of 1/17.

    Returns False on anything unrecognised, so a provider that omits the field
    is counted as *not* capped rather than silently inflating the rate.
    """
    meta = getattr(response, "response_metadata", None)
    if not isinstance(meta, dict):
        return False
    # Ollama says ``done_reason: "length"`` for the same event.
    for key in ("finish_reason", "stop_reason", "done_reason"):
        value = meta.get(key)
        if isinstance(value, str) and value.lower() in {"length", "max_tokens"}:
            return True
    return False


def completion_tokens_of(response: object) -> int | None:
    """Generated-token count from whichever place the provider put it."""
    meta = getattr(response, "response_metadata", None)
    usage = getattr(response, "usage_metadata", None)
    for blob, key in (
        (usage, "output_tokens"),
        (meta, "token_usage"),
    ):
        if isinstance(blob, dict):
            value = blob.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, dict) and isinstance(value.get("completion_tokens"), int):
                return int(value["completion_tokens"])
    return None


def record_judge_response(ledger: object | None, response: object, cap: int | None = None) -> None:
    """Count one judge call and whether it hit the token ceiling. Never raises.

    ``cap`` exists because ``finish_reason`` is not a reliable truncation signal
    on the server this project runs. Probed directly on 2026-08-15: asked for 64
    tokens with ``n_predict`` set, ik_llama.cpp returned **exactly 64** and still
    reported ``finish_reason: "stop"``. Nothing in the response says it was cut —
    no ``stopped_limit``, no ``length`` — so a counter keyed on the finish reason
    alone reads zero however often the cap binds.

    That mattered twice over. Before the cap was re-sent under the key the
    server actually reads it never reached the server at all (§3.35), so the
    counter was measuring an event that could not occur; after the fix it can
    occur and the counter still could not see it.
    Comparing the generated-token count against the cap that was requested is the
    signal the server actually leaves behind.
    """
    if ledger is None:
        return
    try:
        hit = hit_length_cap(response)
        if not hit and isinstance(cap, int) and cap > 0:
            produced = completion_tokens_of(response)
            hit = produced is not None and produced >= cap
        ledger.record_judge_call(hit_token_cap=hit)  # type: ignore[attr-defined]
    except Exception:  # noqa: BLE001 — telemetry must never break a verdict
        return


class TruncationLedger:
    """Thread-safe tally of bound-hits across one analysis run."""

    def __init__(self) -> None:
        self._lock = threading.Lock()

        # Tool output guardrail (agents/mcp_client._apply_output_guardrail).
        self.tool_output_calls = 0
        self.tool_output_over_limit = 0
        self.tool_output_summarised = 0
        self.tool_output_hard_truncated = 0
        # A JSON answer shortened by dropping list elements rather than
        # characters: still a document, still parsed into the ledger's
        # ``structured``, and saying how many rows it handed over.
        self.tool_output_shortened = 0
        # A shortening that ran past its wall and gave way to the character
        # cut. Counted apart because it is a cost signal, not a shape one: a
        # run with any of these was spending an analyst's budget on
        # serialisation.
        self.tool_output_shortening_timeouts = 0
        # An answer the conversation had no room left for at all. The model was
        # handed one sentence saying so and the answer stayed on the ledger.
        # Counted because it is the loudest thing the cap can do to a run, and
        # a reader seeing thin late evidence needs to know it happened.
        self.tool_output_no_room = 0
        # A JSON answer over the cap only because of its whitespace, handed
        # over whole and written without it. Not a shortening — every value is
        # the tool's — and counted apart so a reader can see how many answers
        # the cap would have cut for their layout alone.
        self.tool_output_compacted = 0
        self.tool_output_chars_in = 0
        self.tool_output_chars_kept = 0
        # The caps that were actually in force, smallest and largest. With the
        # cap derived from what the window has left they differ within one run,
        # and a reader asking why one answer was cut and another was not is
        # asking about these two numbers rather than about a setting.
        self.tool_output_limit_smallest = 0
        self.tool_output_limit_largest = 0
        # Where the window those caps came from was learned, as the context
        # budget reported it. Empty on a run whose caps were an operator's own
        # number, because then no window was consulted.
        self.context_window: dict[str, object] = {}

        # ReAct loop step ceiling (agents/base_agent, LangGraph recursion_limit).
        self.react_invocations = 0
        self.react_step_cap_hits = 0

        # Judge output ceiling (LLMConfig.judge_max_tokens).
        self.judge_invocations = 0
        self.judge_token_cap_hits = 0

        # Evidence ledger byte budget (schemas.evidence.apply_budget).
        self.evidence_entries = 0
        self.evidence_trimmed = 0

        # STIX integrity pass (agents/judge_postprocess.enforce_bundle_integrity).
        self.integrity_invocations = 0
        self.integrity_objects_in = 0
        self.integrity_objects_out = 0
        self.integrity_dropped: dict[str, int] = dict.fromkeys(INTEGRITY_REASONS, 0)
        # References a report or a note lost in step 5 of the pass. The object
        # count does not move, so this is not an ``integrity_dropped`` reason;
        # it is nonetheless a removal a reader comparing the bundle with the
        # judge's own would otherwise find unaccounted.
        self.integrity_refs_trimmed = 0

        # The judge path's own passes, counted apart for the reason above.
        self.judge_integrity_invocations = 0
        self.judge_integrity_objects_in = 0
        self.judge_integrity_objects_out = 0
        self.judge_integrity_dropped: dict[str, int] = dict.fromkeys(INTEGRITY_REASONS, 0)

        # The total indicator cap (reporting/renderers/stix_renderer).
        self.indicator_cap_invocations = 0
        self.indicator_cap_removed = 0

        # What the run's grounding corpus could not hold, as the judge node
        # found it. Not a bound on a model's input — it is how much of this
        # run's own record a grounding check could not search, which is what
        # makes an absence a note rather than a finding.
        self.evidence_corpus_missing_answers = 0
        self.evidence_corpus_missing_tools: tuple[str, ...] = ()
        self.evidence_corpus_partial_reason = ""
        # And what it did hold, against the ceiling it held it under. ``None``
        # until the node that reads the corpus records it: a run whose corpus
        # was gone by then knows nothing about what it held, which is not the
        # same statement as holding nothing.
        self.evidence_corpus_answers: int | None = None
        self.evidence_corpus_bytes_held: int | None = None
        self.evidence_corpus_bytes_ceiling: int | None = None

    # -- tool output --------------------------------------------------------

    def record_tool_output(
        self,
        *,
        chars_in: int,
        chars_kept: int,
        over_limit: bool,
        summarised: bool = False,
        hard_truncated: bool = False,
        shortened: bool = False,
        shortening_timed_out: bool = False,
        no_room: bool = False,
        compacted: bool = False,
        limit: int = 0,
    ) -> None:
        """Record one guardrail decision.

        ``over_limit`` false means the output passed through untouched; the call
        is still counted, because a frequency needs its denominator. ``limit``
        is the cap this one call was measured against, kept as the smallest and
        the largest the run saw.
        """
        with self._lock:
            self.tool_output_calls += 1
            self.tool_output_chars_in += max(0, int(chars_in))
            self.tool_output_chars_kept += max(0, int(chars_kept))
            if int(limit) > 0:
                smallest = self.tool_output_limit_smallest
                self.tool_output_limit_smallest = (
                    int(limit) if smallest == 0 else min(smallest, int(limit))
                )
                self.tool_output_limit_largest = max(self.tool_output_limit_largest, int(limit))
            if over_limit:
                self.tool_output_over_limit += 1
            if summarised:
                self.tool_output_summarised += 1
            if hard_truncated:
                self.tool_output_hard_truncated += 1
            if shortened:
                self.tool_output_shortened += 1
            if shortening_timed_out:
                self.tool_output_shortening_timeouts += 1
            if no_room:
                self.tool_output_no_room += 1
            if compacted:
                self.tool_output_compacted += 1

    def note_context_window(self, snapshot: dict[str, object] | None) -> None:
        """Record the window the derived caps were worked out from.

        Written once per run, from the job's context budget. A run whose caps
        came from an operator's own number records nothing here, and the
        absence is the answer: no window was consulted.
        """
        with self._lock:
            self.context_window = dict(snapshot or {})

    # -- loop / generation ceilings ----------------------------------------

    def record_react_loop(self, *, hit_step_cap: bool) -> None:
        with self._lock:
            self.react_invocations += 1
            if hit_step_cap:
                self.react_step_cap_hits += 1

    def record_judge_call(self, *, hit_token_cap: bool) -> None:
        with self._lock:
            self.judge_invocations += 1
            if hit_token_cap:
                self.judge_token_cap_hits += 1

    # -- evidence ledger ----------------------------------------------------

    def record_evidence_budget(self, *, entries: int, trimmed: int) -> None:
        """Record one agent's ledger against its byte budget.

        Both numbers, not just the loss: "12 entries trimmed" says nothing
        without the total it was trimmed from.
        """
        with self._lock:
            self.evidence_entries += max(0, int(entries))
            self.evidence_trimmed += max(0, int(trimmed))

    # -- STIX integrity pass ------------------------------------------------

    def record_integrity_pass(
        self,
        *,
        objects_in: int,
        objects_out: int,
        dropped: dict[str, int] | None = None,
        refs_trimmed: int = 0,
        whose: str = EXPORT_PASS,
    ) -> None:
        """Record one ``enforce_bundle_integrity`` invocation.

        Unknown reason keys are ignored rather than accumulated, so a typo at a
        call site cannot silently invent a category in the C7 report.

        ``refs_trimmed`` is counted apart from ``dropped``: the references step
        5 takes out of a report or a note remove no object, so adding them to a
        reason would stop the reasons totalling to what the pass removed.

        ``whose`` says which bundle this pass ran on. Only :data:`EXPORT_PASS`
        counts toward the figures the run summary reconciles with the published
        bundle; :data:`JUDGE_PASS` runs once per verdict attempt, discarded
        retries included, and is kept under its own name.
        """
        with self._lock:
            if whose == JUDGE_PASS:
                self.judge_integrity_invocations += 1
                self.judge_integrity_objects_in += max(0, int(objects_in))
                self.judge_integrity_objects_out += max(0, int(objects_out))
                for reason, count in (dropped or {}).items():
                    if reason in self.judge_integrity_dropped:
                        self.judge_integrity_dropped[reason] += max(0, int(count))
                return
            self.integrity_invocations += 1
            self.integrity_objects_in += max(0, int(objects_in))
            self.integrity_objects_out += max(0, int(objects_out))
            self.integrity_refs_trimmed += max(0, int(refs_trimmed))
            for reason, count in (dropped or {}).items():
                if reason in self.integrity_dropped:
                    self.integrity_dropped[reason] += max(0, int(count))

    # -- the grounding corpus -----------------------------------------------

    def record_evidence_corpus(
        self,
        *,
        missing_answers: int,
        missing_tools: tuple[str, ...],
        reason: str,
        held: object | None = None,
    ) -> None:
        """Record how whole the evidence a grounding check searched was.

        Recorded once, from the node that builds the corpus the judge is
        grounded against. Nothing here is a count of calls: a run whose corpus
        held everything records zeroes, which is the answer an operator needs
        as much as a number is.

        ``held`` is the corpus's own account of what it is holding, read while
        the container still has one. Left out — a run resumed without its
        corpus — the three figures stay absent rather than reading as zero.
        """
        with self._lock:
            self.evidence_corpus_missing_answers = max(0, int(missing_answers))
            self.evidence_corpus_missing_tools = tuple(missing_tools)
            self.evidence_corpus_partial_reason = str(reason or "")
            if held is None:
                return
            self.evidence_corpus_answers = max(0, int(getattr(held, "answers", 0)))
            self.evidence_corpus_bytes_held = max(0, int(getattr(held, "bytes_held", 0)))
            self.evidence_corpus_bytes_ceiling = max(0, int(getattr(held, "ceiling", 0)))

    # -- indicator cap ------------------------------------------------------

    def record_indicator_cap(self, *, removed: int) -> None:
        """Record one run of the total indicator cap.

        Recorded even when the cap did not bind, so the count of removals has
        the denominator every other bound on this ledger has.
        """
        with self._lock:
            self.indicator_cap_invocations += 1
            self.indicator_cap_removed += max(0, int(removed))

    # -- reporting ----------------------------------------------------------

    def snapshot(self) -> dict[str, object]:
        """A plain-dict copy for handing to the RunSummary builder."""
        with self._lock:
            return {
                "tool_output_calls": self.tool_output_calls,
                "tool_output_over_limit": self.tool_output_over_limit,
                "tool_output_summarised": self.tool_output_summarised,
                "tool_output_hard_truncated": self.tool_output_hard_truncated,
                "tool_output_shortened": self.tool_output_shortened,
                "tool_output_shortening_timeouts": self.tool_output_shortening_timeouts,
                "tool_output_no_room": self.tool_output_no_room,
                "tool_output_compacted": self.tool_output_compacted,
                "tool_output_chars_in": self.tool_output_chars_in,
                "tool_output_chars_kept": self.tool_output_chars_kept,
                "tool_output_chars_dropped": chars_dropped(
                    self.tool_output_chars_in, self.tool_output_chars_kept
                ),
                "tool_output_truncation_rate": truncation_rate(
                    self.tool_output_over_limit, self.tool_output_calls
                ),
                "tool_output_limit_smallest": self.tool_output_limit_smallest,
                "tool_output_limit_largest": self.tool_output_limit_largest,
                "context_window": dict(self.context_window),
                "react_invocations": self.react_invocations,
                "react_step_cap_hits": self.react_step_cap_hits,
                "react_step_cap_rate": truncation_rate(
                    self.react_step_cap_hits, self.react_invocations
                ),
                "judge_invocations": self.judge_invocations,
                "judge_token_cap_hits": self.judge_token_cap_hits,
                "judge_token_cap_rate": truncation_rate(
                    self.judge_token_cap_hits, self.judge_invocations
                ),
                "evidence_entries": self.evidence_entries,
                "evidence_trimmed": self.evidence_trimmed,
                "evidence_trim_rate": truncation_rate(self.evidence_trimmed, self.evidence_entries),
                "integrity_invocations": self.integrity_invocations,
                "integrity_objects_in": self.integrity_objects_in,
                "integrity_objects_out": self.integrity_objects_out,
                "integrity_objects_removed": max(
                    0, self.integrity_objects_in - self.integrity_objects_out
                ),
                "integrity_refs_trimmed": self.integrity_refs_trimmed,
                "integrity_dropped": dict(self.integrity_dropped),
                "indicator_cap_invocations": self.indicator_cap_invocations,
                "indicator_cap_removed": self.indicator_cap_removed,
                "judge_integrity_invocations": self.judge_integrity_invocations,
                "judge_integrity_objects_removed": max(
                    0, self.judge_integrity_objects_in - self.judge_integrity_objects_out
                ),
                "judge_integrity_dropped": dict(self.judge_integrity_dropped),
                "evidence_corpus_missing_answers": self.evidence_corpus_missing_answers,
                "evidence_corpus_missing_tools": list(self.evidence_corpus_missing_tools),
                "evidence_corpus_partial_reason": self.evidence_corpus_partial_reason,
                "evidence_corpus_answers": self.evidence_corpus_answers,
                "evidence_corpus_bytes_held": self.evidence_corpus_bytes_held,
                "evidence_corpus_bytes_ceiling": self.evidence_corpus_bytes_ceiling,
            }

    @property
    def any_bound_hit(self) -> bool:
        """True when this run hit at least one bound — the P6 headline per run."""
        with self._lock:
            return bool(
                self.tool_output_over_limit
                or self.tool_output_no_room
                or self.react_step_cap_hits
                or self.judge_token_cap_hits
                or self.evidence_trimmed
            )
