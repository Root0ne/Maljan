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

import base64
import binascii
import re
from collections.abc import Callable
from typing import Any

from maljan.core.logger import logger
from maljan.utils.marked_cut import marked_cut

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

# What became of one violation. ``retried`` is the correction turn as it
# happens; the other two are what the run knows once the producer has answered
# again — and a violation the retry itself introduced is announced once, as
# ``survived``, because nobody was ever shown it.
VALIDATION_RETRIED = "retried"
VALIDATION_RESOLVED = "resolved"
VALIDATION_SURVIVED = "survived"
VALIDATION_STATES: tuple[str, ...] = (
    VALIDATION_RETRIED,
    VALIDATION_RESOLVED,
    VALIDATION_SURVIVED,
)

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
# (the wall-clock hard cap), ``repeats`` (the repeat guard), ``no_room`` (the
# conversation had no room left for a tool answer) or ``budget_seconds`` (the
# triage pack's budget). Both are telemetry; neither changes what a model said.
BUDGET_TICK = "budget_tick"
STAGE_ENDED_AT_CAP = "stage_ended_at_cap"
# A tool server this job stopped calling for a while, after a run of calls it
# did not answer (``maljan.providers.server_guard``).
TOOL_SERVER_RESTED = "tool_server_rested"
# An agent's model list moved on to its next model because the one before it
# failed as a provider (``maljan.llm.fallback``). Once per switch.
MODEL_FALLBACK = "model_fallback"
BUDGET_TICK_EVERY = 5
CAPS: tuple[str, ...] = ("steps", "time", "repeats", "no_room", "budget_seconds")


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
    tool_definition_chars: int = 0,
) -> None:
    """One agent's spend as of now: steps against its cap, seconds against its limit.

    ``tool_definition_chars`` is what the loop's tool definitions weigh; they
    go with every request and the context budget counts them beside the
    prompt, so the two figures together are what a turn sends.
    """
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
            "tool_definition_chars": max(0, int(tool_definition_chars)),
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


def emit_model_fallback(
    sink: EventSink | None, *, stage: str, agent: str, model: str, reason: str
) -> None:
    """An agent's model list moved on: which model now answers, and why, once per switch."""
    emit(
        sink,
        MODEL_FALLBACK,
        {"stage": str(stage), "agent": str(agent), "model": str(model), "reason": str(reason)},
    )


def announce_model_fallback(
    sink: EventSink | None, message: Any, *, agent: str, stage: str
) -> None:
    """Publish ``model_fallback`` when ``message`` is the answer its model list moved on for.

    Published whatever ``core.events.stream_deltas`` says: the switch is a
    fact about the run a reader of the conversation has to see, not part of
    the text being streamed. Once per switch, because a list that moved stays
    moved for the loop and only the answer that moved it carries the reason.
    Never raises.
    """
    try:
        from maljan.llm.fallback import turn_model

        model, reason = turn_model(message)
        if reason:
            emit_model_fallback(sink, stage=stage, agent=agent, model=model, reason=scrub(reason))
    except Exception as exc:  # noqa: BLE001 — an announcement never costs a turn
        logger.debug("model fallback not announced (%s).", exc)


def emit_tool_server_rested(sink: EventSink | None, record: dict[str, Any]) -> None:
    """A tool server is resting: which one, after how many failures, for how long and why."""
    emit(
        sink,
        TOOL_SERVER_RESTED,
        {
            "server": str(record.get("server") or ""),
            "failures": max(0, int(record.get("failures") or 0)),
            "cooldown_s": round(max(0.0, float(record.get("cooldown_s") or 0.0)), 1),
            "reason": str(record.get("reason") or ""),
        },
    )


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
                    "claim": marked_cut(str(getattr(claim, "claim", "") or ""), 400),
                    "evidence_ref": marked_cut(str(getattr(claim, "evidence_ref", "") or ""), 300),
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
# Where a run of interest may begin: the start of the text, or right after a
# character that separates values. Whitespace is not enough — a compact JSON
# body from a tool server is one whitespace-separated word, and everything
# worth finding inside it sits behind a quote, a colon, a comma or a brace.
#
# The backtick and the angle brackets are here for the same reason the value
# run excludes them: a path or a URL in markdown prose, or in the angle
# brackets a placeholder is written in, sits against one of them, and a
# lookbehind that did not admit them let an absolute host path through whole
# while the credential pass beside it was splitting the same punctuation off
# cleanly. Admitting a character here only lets a match *begin*; every marker
# requirement below still has to be met.
#
# A backslash is here because a tool result is JSON inside JSON: the value a
# rule has to find arrives as ``\"sk-…\"``, and the escape sits against it on
# both sides. Everything outside ASCII is here because a model writes prose
# with the punctuation its own language uses — an em dash, a curly quote —
# and a key or a path written after one of those is a key or a path.
_AFTER = r"(?:\A|(?<=[\s\"'`<>=:,{\[(\\]|[^\x00-\x7f]))"
# Where such a run ends: the next separator that cannot be part of a path, a
# URL or a key.
#
# The colon is deliberately *not* one of them, which is the one place this
# class and the value run's differ. ``_UNTIL`` matches the rest of a URL after
# its ``://``, and that rest carries a colon whenever there is userinfo
# (``u:p@h``) or a port (``h:8080``): ending the run at the first colon would
# hand ``_shorten_url`` the host ``u`` and leave ``:p@h/x`` — the password
# included — standing in the text. A colon can also be the drive letter's own
# separator. Everywhere a colon genuinely ends a value, ``_AFTER`` already
# starts the next run after it.
_UNTIL_CHARS = r"[^\s\"'`<>;,)\]}]"
_UNTIL = _UNTIL_CHARS + r"*"
# A URL's authority, which ends only where the authority ends: at the ``/`` of
# the path, the ``?`` of the query, the ``#`` of a fragment, or a character no
# URL can carry at all. A semicolon is legal in userinfo and a password
# containing one used to end the run in front of the ``@`` — which handed
# ``_shorten_url`` the *user* as the host and left the real host, the fragment
# and the password standing in the text.
_AUTHORITY = r"[^\s\"'`<>,)\]}/?#]*"
# A path run ends later than any other run. A directory name may carry a
# semicolon or a comma, and stopping at one cut the *prefix* off and left the
# rest of the path — the intermediate directories — standing where the whole
# point was to remove them. Whitespace and the quoting characters still end
# it: a path with a space in it cannot be told from a path followed by prose.
_PATH_UNTIL = r"[^\s\"'`<>)\]}]*"
# An authorization scheme and the secret after it, which no per-value rule can
# see as one thing: "Bearer" is a word and the secret is the next one, however
# short it is. Bounded by the same separators as every other run rather than
# by ``\S+``, which used to swallow the closing quote of a JSON string — and
# by the same *constant*, so the two cannot drift apart again.
_SCHEME_AND_SECRET = re.compile(r"(?i)\b(bearer|basic|token)\s+" + _UNTIL_CHARS + r"+")
# 24 is above a CRC, a short hash prefix and a ledger id, and below every API
# key shape this has met. The second alternative is the *standard* base64
# alphabet, not the URL-safe one alone: an AWS secret key, a PKCS blob and
# anything a server base64-encodes carry ``+`` and ``/``, and a rule that
# stopped at ``[A-Za-z0-9_-]`` read the run as ending at the first of them and
# then failed its own whole-run anchor.
_CREDENTIAL_RUN = re.compile(r"(?:[A-Fa-f0-9]{24,}|[A-Za-z0-9+/_\-]{24,}={0,2})\Z")
# A JSON Web Token, which no length rule can see: it is three base64url runs
# with dots between them, and this project's own access token is one. The
# segments are held to a floor so that a dotted module name or a hostname is
# not a candidate, and the head still has to *be* a header — see
# ``_is_a_token``.
_JWT_RUN = re.compile(r"\A[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}={0,2}\Z")
# What the base64 alternative must not take for a key. A MIME type is long
# enough for it (``application/octet-stream`` is exactly 24 characters) and is
# the subject of half the tool answers in a run; a path is cut to its file
# name by the pass below, which is what a reader needs, and reading it as a
# key would replace the file name too. A path here is one with a marker *and*
# a second separator: ``/wJalrXUtnFEMIK7MDENG`` is a key that begins with a
# slash, not a directory.
_MIME_TYPE = re.compile(r"\A[a-z]+/[a-z0-9][a-z0-9.+_\-]*\Z")
# The identifier this system issues for a job, a report, a sample and a
# message. Exempt for the reason a digest is: it is on the job, on the report
# and on the event that announced it, and an event reading ``report_id=***``
# is a console that cannot open the report it is announcing. Exact shape, not
# "any long run of hex and dashes", and an argument *named* like a credential
# is still replaced by name — which is what covers a session id written this
# way.
_IDENTIFIER = re.compile(
    r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z"
)
_PATH_SHAPED = re.compile(r"\A(?:/|\./|\.\./|~/|[A-Za-z]:/)[^/]*/")
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
# A URL, wherever it starts. Found before the path pass, so the slashes in
# ``https://host/x`` are never read as a path.
_URL_RUN = re.compile(
    _AFTER + r"(?P<scheme>[a-zA-Z][a-zA-Z0-9+.\-]*)://(?P<rest>" + _AUTHORITY + _UNTIL + r")"
)
# One value, for the credential test. Delimited rather than whitespace-split,
# because a key a tool server echoes arrives as ``{"api_key":"sk-…"}`` with no
# spaces in it at all.
#
# The class has to hold every character that could sit against a key, because
# both credential rules are anchored to the whole run: a backtick left inside
# it makes ``startswith("sk-")`` false, and a trailing ``;`` makes the
# 24-plus shape fail to match. A key in markdown prose, one in the angle
# brackets tool documentation writes placeholders in, and one ended by the
# ``;`` of a ``Set-Cookie`` all have to split cleanly off their punctuation.
# Splitting on more characters can only expose a credential run and never hide
# one — a run either rule can fire on is made of ``[A-Za-z0-9_-]`` and nothing
# else — and the pieces a split leaves behind (``api_key``, ``C``, ``https``)
# are far too short to match anything.
# The backslash and the non-ASCII range split for the same reasons ``_AFTER``
# admits them: an escaped quote is what a key inside nested JSON sits against,
# and a dash or a quotation mark a model typed is the end of the value in
# front of it. A colon is already outside the class, so a JWT's dots are the
# one separator left inside it — which is what lets the whole token be seen as
# one run.
_VALUE_RUN = re.compile(r"[^\s\"'`<>;:{}\[\](),=\\\x80-\U0010ffff]+")
# A filesystem path, wherever it starts. A slash alone is not the signal: a
# MIME type (``application/x-msdownload``), a sub-technique id
# (``T1055/012``), a date (``2026/09/17``) and a ratio all carry one, and
# cutting them to their last segment turned readable tool output into
# nonsense. What marks a path is how it *begins* — but "begins" is not
# "begins its whitespace-separated word": a host path travels just as happily
# after ``--out=``, after a colon, or inside a compact JSON body, and anchoring
# the marker at position 0 let all three through.
#
# ``/`` must not be followed by another ``/``: that is the ``//`` of a URL
# whose scheme the pass above has already reduced to a host. A drive letter is
# held to the same rule for the same reason — one letter and ``:/`` is also
# how a one-character URL scheme begins, and ``a://h/x`` reduced to nothing at
# all until the slash after the colon had to be a lone one. A relative path
# with no marker (``data/samples/a.exe``) is still left alone — it names no
# host directory, which is the thing that must not travel.
#
# A UNC marker has to be a UNC *shape*, not two backslashes: a host-like
# segment, a separator, and something after it. A leading ``\\`` alone is what
# a single backslash looks like inside a JSON string, so taking it as the
# marker cut ``"\\d+"`` — a regex argument — down to ``d+``. Two or more
# backslashes are accepted at each separator because the whole path arrives
# doubled when the tool serialised it as JSON.
# The host segment admits ``:`` and ``@`` because a UNC path carries
# credentials in front of its host exactly as a URL does, and one that did
# not match the marker was left in the text whole — password included.
_UNC = r"\\{2,}[A-Za-z0-9._:@-]+\\+."
_PATH_RUN = re.compile(
    _AFTER
    + r"(?P<run>(?:/(?!/)|\./|\.\./|~/|[A-Za-z]:(?:\\|/(?!/))|"
    + _UNC
    + r")"
    + _PATH_UNTIL
    + r")"
)
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


def _name_words(name: str) -> set[str]:
    """The words an argument name is made of, however it was spelled.

    Splitting on separators alone is not enough, and the gap is the shape most
    tool servers actually use: ``auth_token`` splits into two words and
    ``authToken`` — the JavaScript spelling, and the norm for an MCP server
    written in it — splits into none, so a credential named that way was read
    as one long word matching nothing. The case change is a word boundary, and
    so is the letter-to-digit change, so ``token2`` is a token.

    Whole words, still: that is what keeps ``author`` and ``obsession`` out of
    it, which is the thing the substring check got wrong in the other
    direction.
    """
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", str(name))
    spaced = re.sub(r"(?<=[A-Za-z])(?=[0-9])|(?<=[0-9])(?=[A-Za-z])", "_", spaced)
    return set(re.split(r"[^a-z0-9]+", spaced.lower())) - {""}


def _is_secret_argument(name: str) -> bool:
    """Whether this argument's *name* says its value is a credential.

    Matched on the whole words the name is made of. A plain containment check
    redacted ``author`` for holding ``auth``; whole words keep ``author``,
    ``authored``, ``obsession`` and ``tokenizer`` out of it while ``authToken``
    and ``sessionId`` are in.

    A simple plural counts as its singular — ``secrets``, ``tokens``,
    ``passwords``, ``credentials`` are the same argument named for a list of
    them. A listed word that is itself compound (``api_key``,
    ``private_key``) is also tried against the joined name, because ``apiKey``
    and ``api-key`` are the same argument written three ways.
    """
    raw = str(name)
    words = _name_words(raw)
    singulars = {word[:-1] for word in words if len(word) > 3 and word.endswith("s")}
    joined = re.sub(r"[^a-z0-9]+", "", raw.lower())
    # A name written in capitals throughout carries no case change to split
    # on, so ``AUTHTOKEN`` and ``SESSIONID`` are one word each and match
    # nothing. For those, and only those, the joined name is searched for the
    # listed word instead — the substring check this rule otherwise replaced.
    # It costs an all-capitals ``AUTHOR``, which is the price of not letting
    # an all-capitals ``AUTHTOKEN`` through.
    shouting = not any(char.islower() for char in raw)
    for secret in _SECRET_ARGUMENT_WORDS:
        if secret in words or secret in singulars:
            return True
        if "_" in secret and secret.replace("_", "") in joined:
            return True
        if shouting and secret.replace("_", "") in joined:
            return True
    return False


def _is_a_token(run: str) -> bool:
    """Whether this dotted run is a JWT rather than three words with dots in them.

    The shape alone is not enough — a long enough hostname has it — so the
    first segment has to be a JOSE header: either the ``eyJ`` every
    base64url-encoded ``{"`` begins with, or something that really decodes to
    the start of a JSON object.
    """
    if not _JWT_RUN.match(run):
        return False
    head = run.split(".", 1)[0]
    if head.startswith("eyJ"):
        return True
    try:
        decoded = base64.urlsafe_b64decode(head + "=" * (-len(head) % 4))
    except (ValueError, binascii.Error):
        return False
    return decoded.lstrip().startswith(b"{")


def _looks_like_a_credential(token: str) -> bool:
    """Whether this run of characters is a key rather than a word or a digest.

    In this order, and the order is the argument. A digest and an identifier
    are what the analysis is *about*. A vendor prefix is a key however short
    it is and whatever else its shape reads as, so it is asked before the
    shapes that are exempt. What is left is exempt when it is a MIME type or a
    path, and a credential when it is long enough to be one or is a token.

    Nothing is exempt for being lowercase. Four real key formats — Mailgun's
    ``key-…``, Google's ``gocspx-…``, GitHub's ``ghs_…`` and a base64url blob
    that happens to have no capitals in it — are nothing but lowercase
    letters, digits and a separator, so a shape test written around the keys
    *this* system issues let every one of them through. The names an event
    carries are exempted where their names are known, by key, in the
    publisher (``analysis_worker.scrubbed``); they are not guessed at here.

    What that costs, stated rather than discovered: an agent key of 24 to 32
    characters — the pattern allows up to 32 — has the shape of a key, so it
    reads as ``***`` inside a *sentence*. The identity fields the line is
    filed under are exempt by name and travel whole, so attribution is
    unaffected and only the name inside the prose goes. The roster is not
    consulted here on purpose: this is one pure function shared by every job
    on the worker, and a redaction rule whose answer depended on which run was
    publishing would not be a redaction rule. ``docs/configuration.md`` tells
    an operator to keep keys short; no shipped key is close to the floor.
    """
    if _DIGEST.match(token) or _IDENTIFIER.match(token):
        return False
    lowered = token.lower()
    if any(lowered.startswith(prefix) for prefix in _CREDENTIAL_PREFIXES):
        return True
    if _MIME_TYPE.match(token) or _PATH_SHAPED.match(token):
        return False
    return bool(_CREDENTIAL_RUN.match(token)) or _is_a_token(token)


def _shorten_url(found: re.Match[str]) -> str:
    """One URL, cut back to its scheme and host.

    The userinfo is a credential outright, and the query is where one travels
    when it is not in the userinfo, so neither survives. The host stays
    because which service was called is the fact a reader is after. A URL with
    no authority at all — ``file:///home/op/samples/x.exe`` — keeps its scheme
    and loses the rest, which is a host path by another spelling.
    """
    rest = found.group("rest")
    host = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    return f"{found.group('scheme')}://{host}/…"


def _shorten_path(found: re.Match[str]) -> str:
    """One path, cut to its last segment.

    The sample lives under a per-job directory whose name is an internal
    identifier and whose prefix is wherever this deployment happens to be
    installed, and neither belongs in a payload that a browser and a
    long-lived table both keep; the file name is the part a reader is reading.

    Two things the marker alone does not decide. A UNC path can carry
    credentials in front of its host, exactly like a URL, and they are the
    whole reason that path must not travel — so they go whatever else happens.
    And a single rootless word is not a path at all: ``</token>`` in a tool
    result matched the marker and was rewritten to ``<token>``, silently
    corrupting the XML the model then read back. A run is cut when it has more
    than one segment or a segment with a dot in it, which every real path has
    and a closing tag does not.
    """
    run = found.group("run")
    flat = run.replace("\\", "/").rstrip("/")
    credentialed = "@" in flat
    if credentialed:
        flat = flat.rsplit("@", 1)[1]
    segments = [segment for segment in flat.split("/") if segment]
    if not segments:
        return run
    if not credentialed and len(segments) < 2 and not any("." in s for s in segments):
        return run
    return segments[-1]


def _hide_credentials(found: re.Match[str]) -> str:
    value = found.group(0)
    return _REDACTED if _looks_like_a_credential(value) else value


def scrub(text: Any) -> str:
    """Any text on its way into an event payload.

    Four passes over the whole text, in this order, because each one's output
    is the next one's input:

    1. an authorization scheme and the secret after it, which no per-value
       rule can see as one thing;
    2. URLs, reduced to scheme and host — first, so the ``//`` of a URL is
       never read as a path;
    3. values that are shaped like a credential;
    4. paths, reduced to their last segment.

    Whole-text rather than word by word, and that is the point. A tool server
    that answers with compact JSON hands this one whitespace-separated word
    with the key, the URL and the host path all inside it, and a rule anchored
    to the start of a word found none of them.
    """
    return _scrub_line(" ".join(str(text or "").split()))


def _scrub_line(line: str) -> str:
    """The four passes, over text that is already one line."""
    line = _SCHEME_AND_SECRET.sub(lambda m: f"{m.group(1)} {_REDACTED}", line)
    line = _URL_RUN.sub(_shorten_url, line)
    line = _VALUE_RUN.sub(_hide_credentials, line)
    return _PATH_RUN.sub(_shorten_path, line)


# How much of a model-written value reaches a finding row. Such a row is
# stored with the report and printed verbatim by the console, so what goes in
# it is held to the same rule an event payload is and then bounded: a value a
# model wrote is as long as the model cared to make it, and a 4 KB "verdict"
# drawn as one line of a run record is a page nobody can read.
FINDING_VALUE_LIMIT = 200


def safe_finding_value(value: Any) -> str:
    """One model-written value, made safe to store in a finding row and to print.

    The same four passes :func:`scrub` makes — an authorization scheme and its
    secret, a URL cut back to scheme and host so its userinfo goes with the
    rest, credential-shaped runs redacted, paths cut to their last segment —
    and then a bound. A validation message, a degradation reason and an export
    decline all end up in ``run_summary``, in the stored report and on the
    analysis page, and none of them is an event, so none of them was covered by
    the scrubbing the publisher does.
    """
    from maljan.utils.marked_cut import marked_cut

    # Bounded where it is shown, and marked: a claim quoted back to its analyst
    # cut mid-word read as the analyst's own ending.
    return marked_cut(scrub(value), FINDING_VALUE_LIMIT)


def scrub_keeping_layout(text: Any) -> str:
    """The same four passes, with the text's own lines and indentation kept.

    For a field a reader reads as prose rather than skims as a summary — an
    analyst's report, a correction, a failure's detail. ``scrub`` collapses
    whitespace because a one-line summary has no use for any of it; doing that
    to a written report turns it into a wall of text and flattens the lists
    and code blocks in it. Every rule is applied to each line on its own,
    which is exactly what ``scrub`` does to the single line it makes.
    """
    return "\n".join(_scrub_line(line) for line in str(text or "").splitlines())


def describe_exception(exc: BaseException) -> str:
    """What a failure may be called on the wire: its type, and its remedy.

    Never its message. A published failure reaches every connected browser,
    the Redis stream and the ``job_events`` table for the whole retention
    window, and the message is the part that names the things a reader of that
    feed has no business seeing: an ``OSError`` names the host path of the
    sample, an ``httpx`` transport error names the request URL, and a base URL
    configured with userinfo carries the credential into the text. The
    verbatim text is on the ledger and in the log, behind the report's
    ownership check, which is where it belongs.

    A failure that carries a ``remediation`` — the shape
    ``maljan.tools.errors`` uses, and what a refusal is made of — says it,
    because a remedy is authored text about what the reader should do rather
    than a report of what went wrong. It is scrubbed like anything else.

    The class alone is not always enough to tell two failures apart:
    ``concurrent.futures.CancelledError`` and ``asyncio.CancelledError`` print
    the same word and only one of them is an ``Exception``, so a class outside
    the builtins is qualified with its module. A group names what is inside
    it, because an MCP connection error inside a task group is otherwise a
    bare ``ExceptionGroup``.

    This is not ``maljan.agents.base_agent.describe_exception``, which keeps
    the message on purpose: that one writes the operator's log, where the
    detail is the whole value and the reader is the operator.
    """
    inner = getattr(exc, "exceptions", None)
    if isinstance(inner, list | tuple) and inner:
        parts = [describe_exception(sub) for sub in inner[:3]]
        return f"{_qualified(exc)}({'; '.join(part for part in parts if part)})"
    remedy = scrub(getattr(exc, "remediation", "") or "")
    return f"{_qualified(exc)}: {remedy}" if remedy else _qualified(exc)


def _qualified(exc: BaseException) -> str:
    """The exception's class, with its module when the name alone is ambiguous."""
    module = type(exc).__module__
    if module and module not in ("builtins", "__main__"):
        return f"{module}.{type(exc).__name__}"
    return type(exc).__name__


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
    state: str = VALIDATION_RETRIED,
    path: str = "",
) -> None:
    """One violation, and what became of it.

    Emitted where the correction turn is written rather than where the run
    summary counts it: a violation the retry fixes leaves no other trace, and
    the conversation is the one place a reader can see that the answer they
    are reading is the second one.

    ``state`` is ``retried`` when the producer is being shown the violation,
    then ``resolved`` or ``survived`` once the run knows which. Only the
    correction turn used to be published, so a reader saw the violations that
    triggered a retry and never the ones that survived it or the ones the retry
    introduced — two events in the feed of a run whose summary recorded ten
    unresolved findings.

    **Folding.** ``(agent, code, path)`` is the key: the same violation, shown
    and then resolved or survived, arrives under it twice, and a reader that
    draws one line per violation folds on it. ``path`` is the producer's own
    locator — ``static.claims[2]`` for an analyst, ``objects[3]`` for the
    judge's bundle — and it is what separates two violations of one code on
    different claims; it is ``""`` for a violation about the answer as a whole,
    where ``(agent, code)`` is already the whole key.
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
            "state": str(state),
            "path": str(path),
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
    model: str = "",
    tokens: dict[str, Any] | None = None,
) -> None:
    """Part of what an agent is saying, before it has finished saying it.

    A delta is what the loop has newly produced at the moment it is emitted,
    not a token: the analyst loop reads its graph as a stream of states and
    the smallest thing it observes is one model turn's text. The console
    appends deltas under the speaker and replaces them with the
    ``agent_message`` that closes the turn.

    It is also the one event per model turn, so it says which model gave the
    turn (``model``) and what the turn spent as the provider reported it
    (``tokens``; absent where the provider reported nothing). A turn that said
    nothing — one that only asked for tools — is still published when it
    carries tokens, so a reader sees what every turn spent. The turn a
    fallback model gave is announced by ``model_fallback``, which is
    published whether or not deltas are.
    """
    if not text_delta and not tokens:
        return
    payload: dict[str, Any] = {
        "stage": str(stage),
        "agent": str(agent),
        "text_delta": str(text_delta),
    }
    if model:
        payload["model"] = str(model)
    if tokens:
        payload["tokens"] = dict(tokens)
    emit(sink, AGENT_MESSAGE_DELTA, payload)


def _field(obj: Any, name: str, fallback: Any = "") -> Any:
    """One attribute of a model or one key of the document it dumps to."""
    if isinstance(obj, dict):
        return obj.get(name, fallback)
    return getattr(obj, name, fallback)


def _asks_of(definition: Any) -> list[str]:
    """Every agent this definition can task, from its ``ask_<key>`` tools."""
    asked: list[str] = []
    for ref in list(_field(definition, "tools", []) or []):
        if str(_field(ref, "kind", "")) != "agent":
            continue
        callee = str(_field(ref, "agent", "") or "")
        if callee and callee not in asked:
            asked.append(callee)
    return asked


def roster_payload(profile: Any, definitions: Any, depth: int = 2) -> dict[str, Any]:
    """Everyone who can speak in this run, and the stages they speak in.

    Read off the team the job runs rather than off the messages as they
    arrive, so the console can draw the participants before the first one
    says anything, and so a reader who cannot open the admin settings still
    sees the label the operator gave an agent. An agent a stage names but no
    definition describes is still listed: it is going to speak, and a roster
    that omits it sends the console back to the registry key it was trying to
    replace.

    The stages are not the whole team. A lead-shaped profile names one agent
    and reaches its specialists through ``ToolRef(kind="agent")`` — a live
    ``team_lead`` run rostered three participants and then produced messages
    from five more — so the walk follows those references from each stage
    agent, ``depth`` hops deep, which is the same bound
    ``core.agents.delegation_depth`` puts on the asks themselves. A specialist
    is listed with ``stages: []`` and a ``via`` naming the agents that can
    task it; a stage agent carries no ``via``, because nothing had to ask it
    to be there. ``stages`` itself is unchanged: a specialist belongs to no
    step of the team, which is the fact that made it invisible.

    A definition that is disabled is not reachable — an ask of it is refused
    by name — so it is not listed. A cycle is walked once: the traversal keeps
    what it has already reached, and delegation refuses an ask back up its own
    chain anyway.

    Accepts the pydantic models or the plain documents they dump to, because
    the worker holds the models and the API holds the stored documents, and
    one shape of roster is the point.
    """
    field = _field

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

    # The specialists, breadth first from the agents the stages named, so a
    # callee reached from two callers is listed once with both of them.
    named_by_a_stage = set(agents_out)
    frontier = list(agents_out)
    for _hop in range(max(0, int(depth))):
        next_frontier: list[str] = []
        for caller in frontier:
            for callee in _asks_of(definition_map.get(caller)):
                definition = definition_map.get(callee)
                if definition is None or field(definition, "enabled", True) is False:
                    continue
                first_time = callee not in agents_out
                entry = agents_out.setdefault(
                    callee,
                    {
                        "key": callee,
                        "label": str(field(definition, "label", "") or callee),
                        "role": str(field(definition, "role", "") or ""),
                        "stages": [],
                    },
                )
                if callee not in named_by_a_stage:
                    via = entry.setdefault("via", [])
                    if caller not in via:
                        via.append(caller)
                if first_time:
                    next_frontier.append(callee)
        frontier = next_frontier
        if not frontier:
            break
    return {"agents": list(agents_out.values()), "stages": stages_out}


def emit_roster(sink: EventSink | None, payload: dict[str, Any]) -> None:
    """The roster, once, at the start of the run."""
    emit(sink, ROSTER, dict(payload))
