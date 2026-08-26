"""Pipeline event sink — the transcript feed behind the live UI.

The pipeline used to be opaque while it ran. The worker announced which agents
were *about* to run and then nothing until the verdict arrived, 30+ minutes
later: the UI could show a spinner and no reason to trust what came out of it.
This module is how a node says what it just found, while it is still running.

Deliberately minimal, and deliberately not async:

* **A plain callable, not a Redis handle.** ``maljan`` is framework-agnostic —
  it must not learn about Redis, ARQ or FastAPI to describe its own progress.
  The worker supplies a sink; the CLI supplies none and every ``emit`` becomes
  a no-op.
* **Synchronous, and safe to call from any thread.** The analyst node is sync
  and LangGraph runs it in a worker thread, while the negotiation, revision and
  judge nodes are coroutines on the loop. One sync signature serves both; the
  sink implementation is responsible for getting the payload back to its own
  loop (see ``analysis_worker._make_event_sink``).
* **Never raises, never blocks.** Telemetry must not be able to fail an
  analysis. ``emit`` swallows everything the sink throws — a broken progress
  feed is an annoyance, a broken pipeline is a lost 30-minute run.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger

# (event_type, payload) -> None. Must be safe to call from any thread.
EventSink = Callable[[str, dict[str, Any]], None]

# The single event type the transcript UI consumes. One type with a ``role``
# discriminator rather than one type per speaker: the frontend renders them
# through a single code path, and a new participant needs no client change.
AGENT_MESSAGE = "agent_message"

# Ceiling on the full prose report carried alongside a message. These events are
# fanned out to every connected browser and mirrored into a bounded Redis Stream
# (maxlen 1000), so an unbounded field would let one verbose analyst evict the
# rest of the run from the replay window. Generous enough for a real report;
# truncation is flagged in the payload rather than done silently.
REPORT_CHAR_LIMIT = 8_000


def emit(sink: EventSink | None, event_type: str, data: dict[str, Any]) -> None:
    """Send one event to ``sink``, swallowing every failure.

    A no-op when ``sink`` is ``None`` — that is the normal CLI/test path.
    """
    if sink is None:
        return
    try:
        sink(event_type, data)
    except Exception as exc:  # noqa: BLE001 — telemetry must never fail a run
        logger.debug("event sink raised (%s: %s); continuing.", type(exc).__name__, exc)


def emit_agent_message(
    sink: EventSink | None,
    *,
    speaker: str,
    role: str,
    text: str,
    round_index: int = 0,
    status: str = "complete",
    confidence: float | None = None,
    claims: list[dict[str, Any]] | None = None,
    dissent: list[str] | None = None,
    report: str | None = None,
) -> None:
    """Emit one transcript line.

    Args:
        speaker: Who is talking — an agent registry name ("static") or a stage
            ("negotiation", "judge").
        role: ``analyst`` | ``reviser`` | ``negotiator`` | ``judge`` | ``system``.
            Drives grouping and styling in the UI.
        text: Human-readable summary. This is what a reader skims.
        round_index: Negotiation round; 0 for the initial pass.
        status: ``complete`` | ``no_data`` | ``failed`` | ``timeout``. Mirrors
            ``AgentFinding.status`` so a live message and the persisted row that
            replaces it after the run read identically.
        confidence: 0-1 self-reported confidence, when the speaker has one.
        claims: Evidence-backed claims, already dumped to plain dicts.
        dissent: Peer claims this speaker still disputes.
        report: The speaker's full prose report for this round, if it wrote one.
            Deliberately *not* folded into ``text`` — see ``summarize_claims``
            below for why that was undone once already. The UI keeps the
            headline as the message body and puts this behind a disclosure, so
            the conversation stays skimmable and the evidence stays one click
            away. Truncated to ``REPORT_CHAR_LIMIT``; when that happens the
            payload also carries ``report_truncated: True`` rather than leaving
            the reader to guess whether the report really ended there.
    """
    payload: dict[str, Any] = {
        "speaker": speaker,
        "role": role,
        "round": round_index,
        "status": status,
        "text": text,
    }
    if confidence is not None:
        payload["confidence"] = round(float(confidence), 4)
    if claims:
        payload["claims"] = claims
    if dissent:
        payload["dissent"] = dissent
    if report:
        body = str(report)
        if len(body) > REPORT_CHAR_LIMIT:
            body = body[:REPORT_CHAR_LIMIT]
            payload["report_truncated"] = True
        payload["report"] = body
    emit(sink, AGENT_MESSAGE, payload)


def summarize_claims(claims: Any, *, speaker: str) -> str:
    """One skimmable line standing in for an analyst's full ISR text.

    The raw ``to_text_summary()`` is several hundred words that already restate
    every claim inline, so sending it as the transcript body produced a wall of
    text with the same claims repeated underneath in structured form. Worse, the
    persisted view summarises ("N evidence-backed claims") — so the same run
    read differently live and on replay, which is exactly what one shared
    transcript model is supposed to prevent. The structured ``claims`` payload
    carries the detail; this is the headline.
    """
    items = list(claims or [])
    if not items:
        return f"{speaker}: no claims produced."
    # Claim text comes straight from the model and often carries newlines and
    # markdown emphasis. This is a one-line headline, so collapse it — the
    # expandable claim list below shows the value verbatim.
    lead = " ".join(str(getattr(items[0], "claim", "") or "").split())
    if len(lead) > 240:
        lead = lead[:239] + "…"
    plural = "" if len(items) == 1 else "s"
    headline = f"{len(items)} evidence-backed claim{plural} from the {speaker} layer."
    return f"{headline} Leading: {lead}" if lead else headline


def claims_to_payload(claims: Any, limit: int = 12) -> list[dict[str, Any]]:
    """Reduce ``ClaimEvidence`` objects to the fields the transcript shows.

    Capped because these events are fanned out to every connected browser and
    mirrored into a bounded Redis Stream; a pathological analyst emitting
    hundreds of claims should not push the rest of the run out of the replay
    window. The full set is always available from the persisted report.
    """
    out: list[dict[str, Any]] = []
    for claim in list(claims or [])[:limit]:
        try:
            out.append(
                {
                    "claim": str(getattr(claim, "claim", "") or "")[:400],
                    "evidence_ref": str(getattr(claim, "evidence_ref", "") or "")[:300],
                    "confidence": round(float(getattr(claim, "confidence", 0.0) or 0.0), 4),
                    "technique_id": getattr(claim, "technique_id", None),
                }
            )
        except Exception:  # noqa: BLE001 — one malformed claim must not drop the rest
            continue
    return out
