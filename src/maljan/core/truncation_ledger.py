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
attack-patterns and prunes dangling relationships, and C7 claims that repairing
is better than rejecting. That claim needs a number for *how often the pass
fires* and *what it removes* — see queue item B4.

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
)


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
) -> None:
    """Record one tool-output guardrail decision on ``ledger``.

    A free function rather than a method on each caller because the guardrail
    exists twice — ``MCPLangChainToolkit`` (stdio) and ``GhidraHTTPClient``
    (HTTP, the production path) each carry their own copy. One implementation
    of the swallow-everything contract is better than two that drift.

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
    for key in ("finish_reason", "stop_reason"):
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

    That mattered twice over. Before OUTPUT-CAP-01 the cap never reached the
    server at all (§3.35), so the counter was measuring an event that could not
    occur; after the fix it can occur and the counter still could not see it.
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
        self.tool_output_chars_in = 0
        self.tool_output_chars_kept = 0

        # ReAct loop step ceiling (agents/base_agent, LangGraph recursion_limit).
        self.react_invocations = 0
        self.react_step_cap_hits = 0

        # Judge output ceiling (LLMConfig.judge_max_tokens).
        self.judge_invocations = 0
        self.judge_token_cap_hits = 0

        # STIX integrity pass (agents/judge_postprocess.enforce_bundle_integrity).
        self.integrity_invocations = 0
        self.integrity_objects_in = 0
        self.integrity_objects_out = 0
        self.integrity_dropped: dict[str, int] = dict.fromkeys(INTEGRITY_REASONS, 0)

    # -- tool output --------------------------------------------------------

    def record_tool_output(
        self,
        *,
        chars_in: int,
        chars_kept: int,
        over_limit: bool,
        summarised: bool = False,
        hard_truncated: bool = False,
    ) -> None:
        """Record one guardrail decision.

        ``over_limit`` false means the output passed through untouched; the call
        is still counted, because a frequency needs its denominator.
        """
        with self._lock:
            self.tool_output_calls += 1
            self.tool_output_chars_in += max(0, int(chars_in))
            self.tool_output_chars_kept += max(0, int(chars_kept))
            if over_limit:
                self.tool_output_over_limit += 1
            if summarised:
                self.tool_output_summarised += 1
            if hard_truncated:
                self.tool_output_hard_truncated += 1

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

    # -- STIX integrity pass ------------------------------------------------

    def record_integrity_pass(
        self,
        *,
        objects_in: int,
        objects_out: int,
        dropped: dict[str, int] | None = None,
    ) -> None:
        """Record one ``enforce_bundle_integrity`` invocation.

        Unknown reason keys are ignored rather than accumulated, so a typo at a
        call site cannot silently invent a category in the C7 report.
        """
        with self._lock:
            self.integrity_invocations += 1
            self.integrity_objects_in += max(0, int(objects_in))
            self.integrity_objects_out += max(0, int(objects_out))
            for reason, count in (dropped or {}).items():
                if reason in self.integrity_dropped:
                    self.integrity_dropped[reason] += max(0, int(count))

    # -- reporting ----------------------------------------------------------

    def snapshot(self) -> dict[str, object]:
        """A plain-dict copy for handing to the RunSummary builder."""
        with self._lock:
            return {
                "tool_output_calls": self.tool_output_calls,
                "tool_output_over_limit": self.tool_output_over_limit,
                "tool_output_summarised": self.tool_output_summarised,
                "tool_output_hard_truncated": self.tool_output_hard_truncated,
                "tool_output_chars_in": self.tool_output_chars_in,
                "tool_output_chars_kept": self.tool_output_chars_kept,
                "tool_output_chars_dropped": chars_dropped(
                    self.tool_output_chars_in, self.tool_output_chars_kept
                ),
                "tool_output_truncation_rate": truncation_rate(
                    self.tool_output_over_limit, self.tool_output_calls
                ),
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
                "integrity_invocations": self.integrity_invocations,
                "integrity_objects_in": self.integrity_objects_in,
                "integrity_objects_out": self.integrity_objects_out,
                "integrity_objects_removed": max(
                    0, self.integrity_objects_in - self.integrity_objects_out
                ),
                "integrity_dropped": dict(self.integrity_dropped),
            }

    @property
    def any_bound_hit(self) -> bool:
        """True when this run hit at least one bound — the P6 headline per run."""
        with self._lock:
            return bool(
                self.tool_output_over_limit or self.react_step_cap_hits or self.judge_token_cap_hits
            )
