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

import re
from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger

# (event_type, payload) -> None. Must be safe to call from any thread.
EventSink = Callable[[str, dict[str, Any]], None]

# The single event type the transcript UI consumes. One type with a ``role``
# discriminator rather than one type per speaker: the frontend renders them
# through a single code path, and a new participant needs no client change.
AGENT_MESSAGE = "agent_message"

# The rest of the live conversation, one type per thing that happens rather
# than one more ``role`` on the message: a tool call is not a line somebody
# said, and a console that draws it as one has to strip the prose back out
# again. Every one of them carries the stage it happened in, so the console
# can file it under the step of the team that produced it, and every one of
# them is assigned its ``seq`` by the publisher rather than here — nothing in
# this package knows the job, and a second counter would order one run two
# ways.
TOOL_CALL_STARTED = "tool_call_started"
TOOL_CALL_FINISHED = "tool_call_finished"
VALIDATION_FEEDBACK = "validation_feedback"
JUDGE_QUESTION = "judge_question"
AGENT_MESSAGE_DELTA = "agent_message_delta"
ROSTER = "roster"

# What an ``agent_message`` is. ``says`` is the default and is what every
# message emitted before this field existed was; the rest name the ones a
# console draws differently. ``tool_call`` and ``tool_result`` are here for a
# producer that wants a line in the conversation rather than the two typed
# events above, and ``verdict`` is the judge's closing message.
MESSAGE_KINDS: tuple[str, ...] = (
    "says",
    "tool_call",
    "tool_result",
    "validation_feedback",
    "judge_question",
    "verdict",
    "system",
    "delegation_ask",
    "delegation_answer",
)
DEFAULT_MESSAGE_KIND = "says"

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


# The budget meter. ``budget_tick`` is one agent's spend as of one model turn
# — every ``BUDGET_TICK_EVERY`` steps and once more when its loop ends — and
# ``stage_ended_at_cap`` says which cap, when a cap is what ended the work:
# ``steps`` (the loop's own recursion limit), ``time``
# (the wall-clock hard cap), ``repeats`` (the repeat guard) or
# ``budget_seconds`` (the triage pack's budget). Both are telemetry; neither
# changes what a model said.
BUDGET_TICK = "budget_tick"
STAGE_ENDED_AT_CAP = "stage_ended_at_cap"
BUDGET_TICK_EVERY = 5
CAPS: tuple[str, ...] = ("steps", "time", "repeats", "budget_seconds")


def emit_budget_tick(
    sink: EventSink | None,
    *,
    agent: str,
    stage: str,
    steps_used: int,
    max_steps: int,
    elapsed_s: float,
    timeout_s: float,
    prompt_chars: int,
    ledger_entries: int,
    final: bool = False,
) -> None:
    """One agent's spend as of now: steps against its cap, seconds against its limit."""
    emit(
        sink,
        BUDGET_TICK,
        {
            "agent": str(agent),
            "stage": str(stage),
            "steps_used": max(0, int(steps_used)),
            "max_steps": max(0, int(max_steps)),
            "elapsed_s": round(max(0.0, float(elapsed_s)), 1),
            "timeout_s": round(max(0.0, float(timeout_s)), 1),
            "prompt_chars": max(0, int(prompt_chars)),
            "ledger_entries": max(0, int(ledger_entries)),
            "final": bool(final),
        },
    )


def emit_stage_ended_at_cap(
    sink: EventSink | None, *, stage: str, agent: str, cap: str, detail: str = ""
) -> None:
    """A cap, not an answer, ended this agent's work in this stage."""
    payload: dict[str, Any] = {"stage": str(stage), "agent": str(agent), "cap": str(cap)}
    if detail:
        payload["detail"] = str(detail)
    emit(sink, STAGE_ENDED_AT_CAP, payload)


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
    stage: str | None = None,
    addressed_to: str | None = None,
    kind: str = DEFAULT_MESSAGE_KIND,
    display_name: str | None = None,
) -> None:
    """Emit one transcript line.

    Args:
        speaker: Who is talking — an agent registry name ("static") or a stage
            ("negotiation", "judge").
        role: ``analyst`` | ``reviser`` | ``negotiator`` | ``judge`` | ``system``.
            Drives grouping and styling in the UI.
        text: Human-readable summary. This is what a reader skims.
        round_index: Negotiation round; 0 for the initial pass.
        status: ``complete`` | ``no_data`` | ``no_claims`` | ``failed`` |
            ``timeout``. Mirrors
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
        stage: The team stage the speaker is working in, when the producer
            knows it. An ask and its answer carry it so the transcript can
            place a delegated exchange inside the stage that made it.
        addressed_to: The agent this line is said *to*, when it is said to one
            agent rather than to the room: the caller's ask names the callee,
            the callee's answer names the caller. Absent on every other line.
        kind: What this line *is*, from ``MESSAGE_KINDS``. ``says`` is the
            default and is what every message emitted before the field existed
            was, so a stored run without it reads the same as one with it. An
            unknown value is recorded as ``says`` rather than passed on: the
            console switches on this, and a kind it cannot draw is a message
            that disappears.
        display_name: The speaker's configured label, so a reader who cannot
            open the admin settings still sees the name the operator gave the
            agent rather than its registry key. Absent when the producer has
            no label to give, and never a substitute for ``speaker`` — the key
            stays the identity everything else joins on.
    """
    # ``confidence`` is spread into the literal rather than written in
    # afterwards. Nothing about the value changes either way; what changes is
    # that this stays visibly a construction of a fresh envelope, which is the
    # only shape ``tests/unit/test_no_silent_overrides.py`` allows for a
    # decision-bearing key.
    payload: dict[str, Any] = {
        "speaker": speaker,
        "role": role,
        "round": round_index,
        "status": status,
        "text": text,
        "kind": kind if kind in MESSAGE_KINDS else DEFAULT_MESSAGE_KIND,
        **({"confidence": round(float(confidence), 4)} if confidence is not None else {}),
    }
    if display_name:
        payload["display_name"] = str(display_name)
    if stage:
        payload["stage"] = str(stage)
    if addressed_to:
        payload["addressed_to"] = str(addressed_to)
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


# ── The rest of the conversation ─────────────────────────────────────────

# What a tool call's arguments are allowed to look like on the wire. These
# events are fanned out to every connected browser, mirrored into a Redis
# stream and written to a table that outlives the run, so the arguments go out
# as a short summary and never verbatim: the full arguments are in the
# evidence ledger, behind the same ownership check as the report.
_SECRET_ARGUMENT_WORDS = (
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "bearer",
    "cookie",
    "credential",
    "passphrase",
    "passwd",
    "password",
    "private_key",
    "pwd",
    "secret",
    "session",
    "token",
)

# A name is the weaker half of the check. A key travels just as happily under
# ``query``, ``value`` or ``header``, and a sandbox command line carries host
# paths in the middle of a sentence, so every string value is scrubbed on its
# way out whatever it is called:
#
# * anything shaped like a credential is replaced outright — a ``Bearer``
#   prefix, one of the vendor key prefixes, or an unbroken run of hex or
#   base64 long enough to be a key rather than a hash fragment somebody is
#   discussing — except an exact md5, sha1 or sha256 digest, which is the
#   subject of the analysis rather than a secret;
# * a URL keeps its scheme and host and loses its userinfo, path and query,
#   because the userinfo *is* a credential and the query is where one is
#   usually smuggled;
# * every remaining whitespace-separated token that *looks like a filesystem
#   path* is cut to its last segment, so a command line with three host paths
#   loses all three rather than only the last.
#
# Each token is peeled of the punctuation around it before any of that and
# wrapped in it again afterwards. A tool result is JSON, so the thing a rule
# has to recognise arrives as ``"sk-liveKey",`` rather than as ``sk-liveKey``
# — every rule here is anchored to the whole token, so without the peel a key
# echoed by an API response travelled verbatim while the same key passed as a
# bare argument was replaced.
_CREDENTIAL_PREFIXES = ("sk-", "sk_", "nvapi-", "ghp_", "gho_", "xoxb-")
# An authorization scheme and the word after it, which the token-by-token pass
# cannot see as one thing: "Bearer" is a word and the secret is the next one,
# however short it is.
_SCHEME_AND_SECRET = re.compile(r"(?i)\b(bearer|basic|token)\s+\S+")
# 24 is above a CRC, a short hash prefix and a ledger id, and below every API
# key shape this has met.
_CREDENTIAL_RUN = re.compile(r"(?:[A-Fa-f0-9]{24,}|[A-Za-z0-9_\-]{24,}={0,2})\Z")
# The three digests a malware analysis is *about*, which the rule above would
# otherwise take for keys: md5, sha1 and sha256. A sample hash is not a secret
# — it is on the job, on the report and in ``pipeline_started`` already — and a
# tool bubble reading ``hash=***`` cannot say which of three artifacts a
# reputation lookup was for, which is most of what the bubble is for.
#
# Exact lengths, not a range: 32, 40 and 64 hex characters are what a digest
# is, and widening it to "any hex" would hand back the shape the rule exists
# to catch.
_DIGEST = re.compile(r"\A[A-Fa-f0-9]{32}\Z|\A[A-Fa-f0-9]{40}\Z|\A[A-Fa-f0-9]{64}\Z")
_URL = re.compile(r"\A(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*)://(?P<rest>\S*)\Z")
# What a filesystem path starts with, and nothing else does. A slash alone is
# not the signal: a MIME type (``application/x-msdownload``), a sub-technique
# id (``T1055/012``), a date (``2026/09/17``) and a ratio all carry one, and
# cutting them to their last segment turned readable tool output into
# nonsense. A relative path with no marker (``data/samples/a.exe``) is left
# alone under this rule — it names no host directory, which is the thing that
# must not travel.
_PATH_START = re.compile(r"\A(?:/|\./|\.\./|~/|[A-Za-z]:[\\/]|\\\\)")
# The punctuation a token arrives wrapped in, peeled before the rules run and
# restored after. Kept narrow: these are quoting and separator characters, not
# characters a path, a URL or a key is made of.
_PEEL_LEADING = "\"'`([{<"
_PEEL_TRAILING = "\"'`)]}>,;:"
# One argument's value, and the whole summary. Short on purpose: this is the
# line under a chat bubble that says which call is running, not a record of it.
# 64 rather than a rounder number so a sha256 — the one long value this is
# meant to let through whole — fits exactly instead of arriving one character
# short of identifying anything.
ARGUMENT_VALUE_CHARS = 64
ARGUMENT_SUMMARY_CHARS = 240
ARGUMENTS_SUMMARISED = 6
# One tool result's headline, for the same reason.
RESULT_SUMMARY_CHARS = 240

_REDACTED = "***"


def _is_secret_argument(name: str) -> bool:
    """Whether this argument's *name* says its value is a credential.

    Matched on whole words rather than on any substring. A plain containment
    check redacted ``author`` for holding ``auth`` and ``session_id`` is a
    genuine hit while ``obsession`` is not, so the name is split on the
    separators argument names actually use and each word is compared whole. A
    listed word that is itself compound (``api_key``, ``private_key``) is also
    tried against the joined name, because ``apiKey`` and ``api-key`` are the
    same argument written three ways.
    """
    lowered = str(name).lower()
    words = set(re.split(r"[^a-z0-9]+", lowered)) - {""}
    joined = re.sub(r"[^a-z0-9]+", "", lowered)
    for secret in _SECRET_ARGUMENT_WORDS:
        if secret in words:
            return True
        if "_" in secret and secret.replace("_", "") in joined:
            return True
    return False


def _looks_like_a_credential(token: str) -> bool:
    """Whether this run of characters is a key rather than a word or a digest."""
    if _DIGEST.match(token):
        return False
    lowered = token.lower()
    if any(lowered.startswith(prefix) for prefix in _CREDENTIAL_PREFIXES):
        return True
    return bool(_CREDENTIAL_RUN.match(token))


def _scrub_url(token: str) -> str | None:
    """A URL cut back to scheme and host, or ``None`` when this is not one.

    The userinfo is a credential outright, and the query is where one travels
    when it is not in the userinfo, so neither survives. The host stays
    because which service was called is the fact a reader of the conversation
    is after.
    """
    found = _URL.match(token)
    if not found:
        return None
    rest = found.group("rest")
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    return f"{found.group('scheme')}://{host}/…" if host else token


def _peel(token: str) -> tuple[str, str, str]:
    """``token`` split into the punctuation around it and the value inside."""
    core = token.lstrip(_PEEL_LEADING)
    lead = token[: len(token) - len(core)]
    stripped = core.rstrip(_PEEL_TRAILING)
    return lead, stripped, core[len(stripped) :]


def _scrub_core(core: str) -> str:
    """One token's value, without the punctuation it arrived wrapped in."""
    if _looks_like_a_credential(core):
        return _REDACTED
    as_url = _scrub_url(core)
    if as_url is not None:
        return as_url
    if _PATH_START.match(core):
        # A host path is reduced to its last segment. The sample lives under a
        # per-job directory whose name is an internal identifier and whose
        # prefix is wherever this deployment happens to be installed, and
        # neither belongs in a payload that a browser and a long-lived table
        # both keep; the file name is the part a reader is actually reading.
        return core.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1] or core
    return core


def _scrub_token(token: str) -> str:
    """One whitespace-separated word of a value, made safe to publish."""
    if not token:
        return token
    lead, core, tail = _peel(token)
    if not core:
        return token
    return f"{lead}{_scrub_core(core)}{tail}"


def scrub(text: Any) -> str:
    """Any text on its way into an event payload.

    One whole-string pass first, for the one shape a token-by-token pass
    cannot see — an authorization scheme and the word after it — then token by
    token for the rest.
    """
    joined = _SCHEME_AND_SECRET.sub(lambda m: f"{m.group(1)} {_REDACTED}", str(text or ""))
    return " ".join(_scrub_token(token) for token in joined.split())


def _summarize_value(value: Any) -> str:
    """One argument, short enough to read and stripped of what must not travel."""
    if isinstance(value, bool) or value is None:
        return str(value).lower() if isinstance(value, bool) else "null"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, dict | list | tuple):
        return f"<{len(value)} items>" if not isinstance(value, dict) else f"<{len(value)} keys>"
    text = scrub(value)
    if len(text) > ARGUMENT_VALUE_CHARS:
        text = text[: ARGUMENT_VALUE_CHARS - 1] + "…"
    return text


def summarize_args(args: Any) -> str:
    """A tool call's arguments as one short, redacted line.

    Never the arguments themselves. An argument named like a credential is
    replaced outright; every value, whatever it is named, is scrubbed of
    credential shapes, URL userinfo and host paths; every value is capped and
    only the first few arguments are named at all. A caller that wants the
    arguments as sent reads the ledger entry this call writes, which is behind
    the same ownership check as the report.

    A long unbroken run of hex or base64 is replaced, except one that is
    exactly an md5, sha1 or sha256 digest: those are what the analysis is
    about and are on the job, the report and ``pipeline_started`` already.
    """
    if not isinstance(args, dict) or not args:
        return ""
    parts: list[str] = []
    for name in list(args)[:ARGUMENTS_SUMMARISED]:
        shown = _REDACTED if _is_secret_argument(name) else _summarize_value(args[name])
        parts.append(f"{name}={shown}")
    if len(args) > ARGUMENTS_SUMMARISED:
        parts.append(f"+{len(args) - ARGUMENTS_SUMMARISED} more")
    line = ", ".join(parts)
    return line[: ARGUMENT_SUMMARY_CHARS - 1] + "…" if len(line) > ARGUMENT_SUMMARY_CHARS else line


def summarize_result(output: Any, *, ok: bool = True, remediation: str = "") -> str:
    """A tool result's headline, scrubbed and capped.

    A result is not safer than an argument. An API answer echoes the key it
    was called with, an error names the host path it could not read, and a
    string lifted out of the sample is whatever the sample's author put there,
    so the whole of it goes through the same scrub.

    A failure says so and says what would fix it, and nothing else: the raw
    exception text is the part that names paths and hosts, and it is already
    kept verbatim on the ledger entry, behind the report's ownership check.
    """
    if not ok:
        fix = scrub(remediation)
        headline = "the call failed"
        text = f"{headline}; {fix}" if fix else headline
    else:
        text = scrub(output)
    if len(text) > RESULT_SUMMARY_CHARS:
        text = text[: RESULT_SUMMARY_CHARS - 1] + "…"
    return text


def emit_tool_call_started(
    sink: EventSink | None,
    *,
    stage: str,
    agent: str,
    tool: str,
    server: str | None = None,
    args_summary: str = "",
) -> None:
    """One tool call, as it starts.

    Paired with ``tool_call_finished`` on every path the recorder takes,
    including the one where the repeat guard answers instead of the tool: a
    console that draws a spinner on the start and clears it on the finish must
    never be left holding one.
    """
    emit(
        sink,
        TOOL_CALL_STARTED,
        {
            "stage": str(stage),
            "agent": str(agent),
            "tool": str(tool),
            "server": str(server) if server else None,
            "args_summary": str(args_summary),
        },
    )


def emit_tool_call_finished(
    sink: EventSink | None,
    *,
    stage: str,
    agent: str,
    tool: str,
    server: str | None = None,
    evidence_id: str = "",
    ok: bool = True,
    duration_ms: int = 0,
    summary: str = "",
) -> None:
    """One tool call, as it answers, with the ledger id its result is under."""
    emit(
        sink,
        TOOL_CALL_FINISHED,
        {
            "stage": str(stage),
            "agent": str(agent),
            "tool": str(tool),
            "server": str(server) if server else None,
            "evidence_id": str(evidence_id),
            "ok": bool(ok),
            "duration_ms": max(0, int(duration_ms)),
            "summary": str(summary),
        },
    )


def emit_validation_feedback(
    sink: EventSink | None,
    *,
    stage: str,
    agent: str,
    code: str,
    message: str,
    retry_index: int,
) -> None:
    """One correction a producer is shown before it answers again.

    Emitted where the correction turn is written rather than where the run
    summary counts it: a violation the retry fixes leaves no other trace, and
    the conversation is the one place a reader can see that the answer they
    are reading is the second one.
    """
    emit(
        sink,
        VALIDATION_FEEDBACK,
        {
            "stage": str(stage),
            "agent": str(agent),
            "code": str(code),
            "message": str(message),
            "retry_index": max(0, int(retry_index)),
        },
    )


def emit_judge_question(
    sink: EventSink | None,
    *,
    stage: str,
    text: str,
    addressed_to: str | None = None,
) -> None:
    """A question the judge asked mid-loop, rather than its closing verdict."""
    emit(
        sink,
        JUDGE_QUESTION,
        {
            "stage": str(stage),
            "text": str(text),
            "addressed_to": str(addressed_to) if addressed_to else None,
        },
    )


def emit_agent_message_delta(
    sink: EventSink | None,
    *,
    stage: str,
    agent: str,
    text_delta: str,
) -> None:
    """Part of what an agent is saying, before it has finished saying it.

    A delta is what the loop has newly produced at the moment it is emitted,
    not a token: the analyst loop reads its graph as a stream of states and
    the smallest thing it observes is one model turn's text. The console
    appends deltas under the speaker and replaces them with the
    ``agent_message`` that closes the turn.
    """
    if not text_delta:
        return
    emit(
        sink,
        AGENT_MESSAGE_DELTA,
        {"stage": str(stage), "agent": str(agent), "text_delta": str(text_delta)},
    )


def roster_payload(profile: Any, definitions: Any) -> dict[str, Any]:
    """Everyone who can speak in this run, and the stages they speak in.

    Read off the team the job runs rather than off the messages as they
    arrive, so the console can draw the participants before the first one
    says anything, and so a reader who cannot open the admin settings still
    sees the label the operator gave an agent. An agent a stage names but no
    definition describes is still listed: it is going to speak, and a roster
    that omits it sends the console back to the registry key it was trying to
    replace.

    Accepts the pydantic models or the plain documents they dump to, because
    the worker holds the models and the API holds the stored documents, and
    one shape of roster is the point.
    """

    def field(obj: Any, name: str, fallback: Any = "") -> Any:
        if isinstance(obj, dict):
            return obj.get(name, fallback)
        return getattr(obj, name, fallback)

    stages_out: list[dict[str, Any]] = []
    agents_out: dict[str, dict[str, Any]] = {}
    definition_map = definitions if isinstance(definitions, dict) else {}
    for stage in list(field(profile, "stages", []) or []):
        key = str(field(stage, "key", ""))
        if not key:
            continue
        members = [str(a) for a in (field(stage, "agents", []) or [])]
        stages_out.append(
            {
                "key": key,
                "label": str(field(stage, "label", "") or key),
                "kind": str(field(stage, "kind", "analysis") or "analysis"),
                "agents": members,
            }
        )
        for member in members:
            definition = definition_map.get(member)
            entry = agents_out.setdefault(
                member,
                {
                    "key": member,
                    "label": str(field(definition, "label", "") or member),
                    "role": str(field(definition, "role", "") or ""),
                    "stages": [],
                },
            )
            if key not in entry["stages"]:
                entry["stages"].append(key)
    return {"agents": list(agents_out.values()), "stages": stages_out}


def emit_roster(sink: EventSink | None, payload: dict[str, Any]) -> None:
    """The roster, once, at the start of the run."""
    emit(sink, ROSTER, dict(payload))
