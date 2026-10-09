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
import json
import re
from collections.abc import Callable, Iterable, Mapping
from typing import Any

from maljan.core.logger import logger
from maljan.utils.marked_cut import CUT_MARK, marked_cut

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
# conversation had no room left for a tool answer), ``spend`` (the operator's
# spend ceiling for the job) or ``budget_seconds`` (the
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
CAPS: tuple[str, ...] = ("steps", "time", "repeats", "no_room", "spend", "budget_seconds")


def emit_budget_tick(
    sink: EventSink | None,
    *,
    agent: str,
    stage: str,
    steps_used: int,
    max_steps: int | None,
    elapsed_s: float,
    timeout_s: float | None,
    prompt_chars: int,
    ledger_entries: int,
    final: bool = False,
    tool_definition_chars: int = 0,
) -> None:
    """One agent's spend as of now: steps against its cap, seconds against its limit.

    ``max_steps`` and ``timeout_s`` are ``None`` for a loop with no limit in
    that dimension, and are sent as ``null``.

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
            "max_steps": None if max_steps is None else max(0, int(max_steps)),
            "elapsed_s": round(max(0.0, float(elapsed_s)), 1),
            "timeout_s": None if timeout_s is None else round(max(0.0, float(timeout_s)), 1),
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


def summarize_claims(claims: Any, *, speaker: str, source: str = "") -> str:
    """One skimmable line standing in for an analyst's full ISR text.

    The raw ``to_text_summary()`` is several hundred words that already restate
    every claim inline, so sending it as the transcript body produced a wall of
    text with the same claims repeated underneath in structured form. Worse, the
    persisted view summarises ("N evidence-backed claims") — so the same run
    read differently live and on replay, which is exactly what one shared
    transcript model is supposed to prevent. The structured ``claims`` payload
    carries the detail; this is the headline.

    ``source`` is the whole phrase the claims come "from", where the speaker's
    name does not read inside "the … layer" (``nodes.claims_source``: an
    agent named by its place in a stage); the name's layer otherwise.
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
    headline = (
        f"{len(items)} evidence-backed claim{plural} from {source or f'the {speaker} layer'}."
    )
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
            # The heading's note, where the debate is read; only when there is one.
            note = getattr(claim, "heading_note", None)
            if note:
                out[-1]["heading_note"] = marked_cut(str(note), 300)
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
# Vendor key formats whose prefix is also the start of ordinary words
# (``key-exchange``) or whose body can be letter groups the word rule below
# reads as words. A run that begins with one of these and carries a body of at
# least ``PREFIXED_KEY_BODY_FLOOR`` characters after it is a key, asked before
# the word rule: GitLab, Slack, GitHub, Hugging Face, Mailgun, Stripe, npm and
# Google OAuth client secrets. Every real body of these formats is longer than
# the floor. Mailgun's ``key-`` is asked apart (``_MAILGUN_PREFIX``): it begins
# ordinary phrases (``key-derivation-function-parameters``), so its body must
# also not be words.
_PREFIXED_KEY_FORMATS = (
    "glpat-",
    "xoxp-",
    "xoxb-",
    "xoxa-",
    "xoxs-",
    "xoxr-",
    "xapp-",
    "ghs_",
    "ghp_",
    "gho_",
    "ghu_",
    "ghr_",
    "github_pat_",
    "hf_",
    "rk_live_",
    "sk_live_",
    "pk_live_",
    "rk_test_",
    "sk_test_",
    "pk_test_",
    "npm_",
    "gocspx-",
    *_CREDENTIAL_PREFIXES,
)
PREFIXED_KEY_BODY_FLOOR = 20
_MAILGUN_PREFIX = "key-"
# The secret values this process holds in its own settings — model API keys,
# sandbox and Ghidra tokens, the VirusTotal key, the database, Redis and object
# store passwords — masked by exact value wherever the scrub runs, whatever
# their shape: a passphrase an operator configured reads as words to every
# shape rule here, and this is what catches it. Held per scope — ``process``
# for what a worker or an app holds from its start, ``job`` for a job's own
# settings — and a scope registered again replaces what it held, so a secret no
# longer configured stops being masked. Filled by ``remember_secret_values``.
_SECRET_SCOPES: dict[str, frozenset[str]] = {}
# The union of every scope as one pattern, longest value first so a secret that
# contains another is masked whole, and each value only where no letter, digit
# or underscore touches it: ``minioadmin`` configured leaves ``minioadministrator``
# as written. ``None`` when nothing is registered.
_CONFIGURED_PATTERN: re.Pattern[str] | None = None
# Configured values shorter than the floor, per scope: kept out of finding
# rows only, each as a whole word (``_mask_short_secrets``).
_SHORT_SECRETS: dict[str, frozenset[str]] = {}
# The scopes whose configured values could not be read
# (``secret_registration_failed``); while any is listed, a finding row is held
# to the whole event scrub.
_FAILED_SCOPES: set[str] = set()
# A configured value shorter than this is not masked by value: a four-letter
# password masked everywhere would take every word it spells out of every
# sentence. Such a value is still masked by name and by shape.
CONFIGURED_SECRET_FLOOR = 8
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
# The environment variables the platform's own sentences name, which the rule
# above takes for keys by their length. Named one by one rather than by shape:
# an upper-case run with underscores in it is also what a key can look like,
# and the remedy "check GHIDRA_CONTAINER_SAMPLES_PATH" read "check ***" on the
# console, for the one failure whose remedy is that variable.
_OWN_VARIABLE_NAMES = frozenset({"GHIDRA_CONTAINER_SAMPLES_PATH"})
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
# slash, not a directory. The type is one of the registered top-level types
# (or an ``x-`` one), and the subtype is exempt only when it is no key itself:
# ``left/<key>`` has the shape of a MIME type and is a key after a word.
_MIME_TYPE = re.compile(
    r"\A(?:application|audio|chemical|font|image|inode|message|model|multipart|text|video"
    r"|x-[a-z0-9.+\-]+)/[a-z0-9][a-z0-9.+_\-]*\Z"
)
# Words with separators between them, which the base64 alternative above reads
# as a key by its length alone: a claim's ``anti-debugging/environment``, a
# STIX property name and an analyst's roster key are all 24 characters and
# more of that alphabet. Two or more pieces split on ``_``, ``-`` or ``/``,
# each written the way a word is — all lower case, all capitals, or one
# capital in front — and each shorter than the length floor, so that a piece
# which would be a key on its own keeps the whole run a key. A key's body of
# random letters mixes its case or runs past the floor; a vendor prefix is
# asked before this and wins.
_WORD_PIECE = re.compile(r"\A(?:[a-z]{1,23}|[A-Z]{1,23}|[A-Z][a-z]{1,22})\Z")
# A capitalised compound of two or three words, as a family or a product name
# is written (``NorthWind``): a first word of three letters or more, then one
# or two more, each a capital and small letters. A key's random case does not
# keep that pattern, and one alternating letter by letter (``AbCdEf…``) has
# more words than three. Read only by :func:`_is_a_family_name`, and never
# for a run that follows a credential label.
_COMPOUND_PIECE = re.compile(r"\A(?=[A-Za-z]{1,23}\Z)[A-Z][a-z]{2,}(?:[A-Z][a-z]+){1,2}\Z")
# A credential label right before a run: an argument word a credential is
# named by (``_SECRET_ARGUMENT_WORDS``, "Access Token" among them by its last
# word), an authorization scheme, then an optional ``:`` or ``=`` and quote.
_LABEL_BEFORE_RE = re.compile(
    r"(?i)(?:api[_-]?key|auth\w*|bearer|basic|cookie|credentials?|passphrase|passwd|password"
    r"|private[_-]?key|pwd|secrets?|session\w*|tokens?)[\s\"']*[:=]?[\s\"']*\Z"
)
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
# one run. ``!`` splits too: ``kernel32.dll!<key>`` is a module name and a key,
# and read as one run neither rule saw the key.
_VALUE_RUN = re.compile(r"[^\s\"'`<>;:{}\[\](),=!\\\x80-\U0010ffff]+")
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
#
# Each of these caps, and ``FINDING_VALUE_LIMIT`` below, can be exceeded by one
# whole value: a digest or an identifier the cut would split is kept whole with
# its extension (``_cut_whole``), so ``<sha256>.exe`` runs past the cap by a
# few characters rather than arriving as half a digest a second scrub masks.
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


def _looks_like_a_credential(token: str, *, whole: bool = False) -> bool:
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

    Words joined by separators are exempt by their shape (``_is_words``):
    every piece letters alone, written the way a word is, and shorter than the
    floor. That is what keeps a claim's ``anti-debugging/environment`` and an
    agent key such as ``windows_pe_static_reverse_engineer`` in a sentence.
    What is left costs, stated rather than discovered: an agent key of 24 to
    32 characters with a digit in one of its pieces has the shape of a key, so
    it reads as ``***`` inside a *sentence*. The identity fields the line is
    filed under are exempt by name and travel whole, so attribution is
    unaffected and only the name inside the prose goes. The roster is not
    consulted here on purpose: this is one pure function shared by every job
    on the worker, and a redaction rule whose answer depended on which run was
    publishing would not be a redaction rule.
    """
    if _DIGEST.match(token) or _IDENTIFIER.match(token) or token in _OWN_VARIABLE_NAMES:
        return False
    lowered = token.lower()
    if any(lowered.startswith(prefix) for prefix in _CREDENTIAL_PREFIXES):
        return True
    if any(
        lowered.startswith(prefix) and len(token) - len(prefix) >= PREFIXED_KEY_BODY_FLOOR
        for prefix in _PREFIXED_KEY_FORMATS
    ):
        return True
    if (
        lowered.startswith(_MAILGUN_PREFIX)
        and len(token) - len(_MAILGUN_PREFIX) >= PREFIXED_KEY_BODY_FLOOR
        and not _is_words(token)
    ):
        return True
    if _MIME_TYPE.match(token) and not _looks_like_a_credential(token.split("/", 1)[1]):
        return False
    if _PATH_SHAPED.match(token) or _is_words(token):
        return False
    if _is_api_name(token):
        return False
    if _CREDENTIAL_RUN.match(token) or _is_a_token(token):
        return True
    if whole:
        return False
    # A key joined to other text by a slash, a bar, a plus or an ampersand is
    # still a key: ``<jwt>/name`` failed every rule anchored to the whole run.
    # ``whole`` asks only the rules that read the run as one.
    if _glued_token(token) is not None:
        return True
    pieces = [piece for piece in _JOINS.split(token) if piece]
    return len(pieces) > 1 and any(_looks_like_a_credential(piece) for piece in pieces)


# The Windows function names and hash-algorithm ids the scrub leaves as
# written. The length rule reads ``ZwSetInformationJobObject`` as a key, and a
# pair of algorithm ids joined by a slash as one; the live console and the
# stored transcript printed ``***`` where the report printed the names. Three
# sources, all exact: the vendored export-name catalogue and the vendored
# hash-algorithm catalogue (``api_hashes``' data files, each read once), and
# the names this job's hash resolution on the analysis server read
# (``remember_resolved_names``), which the next job forgets. A vendor prefix is
# asked before any of them, and a configured value is masked by value before any
# rule is read, so none exempts a credential.
_EXPORT_NAMES_FILE = "data/windows_export_names_v1.json"
_ALGORITHMS_FILE = "data/api_hash_algorithms_v1.json"
_RESOLVED_NAMES: set[str] = set()
# The catalogues' names, read on first use.
_CATALOGUE: frozenset[str] | None = None
_ALGORITHM_IDS: frozenset[str] | None = None
# What joins several names into one run: a slash, a bar, a plus, an ampersand.
_JOINS = re.compile(r"[/|+&]")
# A resolved name is taken only in the shape a Windows function name has: an
# identifier with both cases in it. An all-lowercase run is what several key
# formats are, and no catalogue name past the length floor is written that way
# except words joined by underscores, which the word rule already keeps.
_API_NAME_SHAPE = re.compile(r"\A[A-Za-z_?@$][A-Za-z0-9_?@$]*\Z")


def _read_data(path: str) -> Any:
    import json

    from maljan.core.paths import resolve_data

    return json.loads(resolve_data(path).read_text(encoding="utf-8"))


def _catalogue_names() -> frozenset[str]:
    """Every exported name the vendored catalogue holds; empty when it cannot be read."""
    global _CATALOGUE
    if _CATALOGUE is None:
        try:
            document = _read_data(_EXPORT_NAMES_FILE)
            _CATALOGUE = frozenset(
                str(name)
                for exported in (document.get("dlls") or {}).values()
                for name in exported or []
            )
        except Exception as exc:  # noqa: BLE001 — the shape rules still run
            logger.warning(
                "The export-name catalogue was not read for the scrub (%s).", type(exc).__name__
            )
            _CATALOGUE = frozenset()
    return _CATALOGUE


def _algorithm_ids() -> frozenset[str]:
    """Every hash-algorithm id the vendored catalogue holds; empty when it cannot be read."""
    global _ALGORITHM_IDS
    if _ALGORITHM_IDS is None:
        try:
            document = _read_data(_ALGORITHMS_FILE)
            _ALGORITHM_IDS = frozenset(
                str(entry["id"])
                for entry in document.get("algorithms") or []
                if isinstance(entry, dict) and entry.get("id")
            )
        except Exception as exc:  # noqa: BLE001 — the shape rules still run
            logger.warning(
                "The hash-algorithm catalogue was not read for the scrub (%s).", type(exc).__name__
            )
            _ALGORITHM_IDS = frozenset()
    return _ALGORITHM_IDS


def _is_a_catalogue_name(name: str) -> bool:
    return name in _RESOLVED_NAMES or name in _catalogue_names() or name in _algorithm_ids()


def _module_names() -> frozenset[str]:
    """The vendored catalogue's module names, folded to lower case; empty when unread."""
    global _MODULES
    if _MODULES is None:
        try:
            document = _read_data(_EXPORT_NAMES_FILE)
            names = (document.get("modules") or {}).get("names") or []
            _MODULES = frozenset(
                str(name).lower() for name in [*names, *(document.get("dlls") or {})]
            )
        except Exception as exc:  # noqa: BLE001 — the shape rules still run
            logger.warning(
                "The module-name catalogue was not read for the scrub (%s).", type(exc).__name__
            )
            _MODULES = frozenset()
    return _MODULES


# What a tool or a decompiler writes that the length rule read as a key, each by
# its exact form: an address or a decimal number (a list of them joined by
# ``/`` is one run), a name Ghidra gives a stack or a local variable
# (``in_stack_ffffffffffffffc8``), and a stretch of a base64 alphabet itself
# (the table a decoder is built from). None is a key's form: a key is not a
# number, a decompiler's variable or the alphabet it is written in.
_MODULES: frozenset[str] | None = None
_NUMBER_PIECE = re.compile(r"\A(?:0[xX][0-9A-Fa-f]{1,16}|[0-9]{1,10})\Z")
_DECOMPILER_NAME = re.compile(r"\A(?:in_stack|local|param|[a-z]{1,3}Stack)_[0-9a-f]{1,16}\Z")
# A stretch of an alphabet is that table only at a key's own length floor: a
# short piece of a key is a stretch of its alphabet too.
_ALPHABET_SLICE_FLOOR = 24
_BASE64_ALPHABETS = (
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
)


def _is_a_written_name(token: str) -> bool:
    """Whether ``token`` is a module name, a decompiler's variable name or a stretch
    of a base64 alphabet: what the scrub keeps by its exact form beside the catalogue."""
    return bool(
        token.lower() in _module_names()
        or _DECOMPILER_NAME.match(token)
        or (len(token) >= _ALPHABET_SLICE_FLOOR and any(token in a for a in _BASE64_ALPHABETS))
    )


def _completes_a_name(piece: str, named: str) -> str:
    """The catalogue name ``piece`` completes after a head of ``named``, or ``""``.

    How a list abbreviates a name it repeats: ``FindFirstFileA/W`` for the A
    and W forms, ``NtQueryInformationProcess/Thread`` for the process and the
    thread form. The completion must itself be a catalogue name.
    """
    if not named or not piece[:1].isupper():
        return ""
    for end in range(len(named) - 1, 0, -1):
        whole = named[:end] + piece
        if _is_a_catalogue_name(whole):
            return whole
    return ""


def _is_api_name(token: str) -> bool:
    """Whether ``token`` is a Windows function name or a hash-algorithm id, alone or
    several joined by ``/``, ``|``, ``+`` or ``&``.

    A module in front of a name (``kernel32.dll!Name``) is split off by the
    value run itself, so the name is asked alone. In a list, a piece may also
    be a module name the catalogue lists (in any case), an address or a number,
    a decompiler's variable name, or an abbreviation that completes the name
    before it to a catalogue name (``FindFirstFileA/W``).
    """
    # The catalogue first, alone and over every piece, as before the exact
    # forms existed: those are asked only of what the catalogue does not hold.
    if _is_a_catalogue_name(token):
        return True
    pieces = [piece for piece in _JOINS.split(token) if piece]
    if len(pieces) < 2:
        # Alone, a run shorter than the length floor is no key to begin with.
        return len(token) >= _ALPHABET_SLICE_FLOOR and _is_a_written_name(token)
    if all(_is_a_catalogue_name(piece) for piece in pieces):
        return True
    named = ""
    for piece in pieces:
        if _is_a_catalogue_name(piece):
            named = piece
            continue
        if _is_a_written_name(piece) or _NUMBER_PIECE.match(piece):
            continue
        completed = _completes_a_name(piece, named)
        if not completed:
            return False
        named = completed
    return True


def remember_resolved_names(answer: Any) -> None:
    """Add the function names a ``resolve_api_hashes`` answer read to the names kept as written.

    ``answer`` is the tool's answer as a dict or as its JSON text; every
    reading under ``hits`` and ``lone_hits`` is taken whose name has the shape
    a Windows function name has (``_API_NAME_SHAPE`` and both cases). Held for
    the job, in this process, until ``forget_resolved_names``. Never raises.
    """
    try:
        if isinstance(answer, str):
            import json

            answer = json.loads(answer)
        if not isinstance(answer, dict):
            return
        for key in ("hits", "lone_hits"):
            for hit in answer.get(key) or []:
                for reading in (hit.get("readings") or []) if isinstance(hit, dict) else []:
                    name = str(reading.get("name") or "") if isinstance(reading, dict) else ""
                    if (
                        _API_NAME_SHAPE.match(name)
                        and any(c.islower() for c in name)
                        and any(c.isupper() for c in name)
                    ):
                        _RESOLVED_NAMES.add(name)
    except Exception as exc:  # noqa: BLE001 — the shape rules still run
        logger.debug("A hash resolution's names were not handed to the scrub (%s).", exc)


def forget_resolved_names() -> None:
    """Clear the names a job's hash resolution read: the next job starts with none."""
    _RESOLVED_NAMES.clear()


def resolved_names_held() -> int:
    """How many resolved names the scrub keeps as written for this job."""
    return len(_RESOLVED_NAMES)


def _is_words(run: str) -> bool:
    """Whether this run is words joined by ``_``, ``-`` or ``/`` rather than a key.

    What this costs: no shape tells a passphrase or a letters-only grouped
    code from a hyphenated phrase, so a secret of that shape passes this rule.
    A vendor prefix is asked before it (``_PREFIXED_KEY_FORMATS``), and the
    secrets the platform holds are masked by value before any shape is read
    (``remember_secret_values``); ``apps/docs/content/docs/configuration.mdx`` states the rest.
    """
    pieces = re.split(r"[_\-/]", run)
    return len(pieces) >= 2 and all(_WORD_PIECE.match(piece) for piece in pieces)


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


def _is_a_family_name(run: str) -> bool:
    """Whether ``run`` is a family name of words joined by ``/``, one a capitalised compound.

    ``Rivulet/NorthWind/Calder``: two or more pieces, each a word
    (``_WORD_PIECE``) or a capitalised compound (``_COMPOUND_PIECE``), at
    least one a compound and none with a digit. The caller asks it only where
    no credential label stands before the run.
    """
    pieces = run.split("/")
    return (
        len(pieces) >= 2
        and all(_WORD_PIECE.match(piece) or _COMPOUND_PIECE.match(piece) for piece in pieces)
        and any(_COMPOUND_PIECE.match(piece) for piece in pieces)
    )


def _hide_credentials(found: re.Match[str], hex_fields: Mapping[str, int] | None = None) -> str:
    """One value run, with every key in it masked together with the base64 around it.

    In this order:

    - A run that reads as a key as one run is masked whole.
    - A run that is a name the scrub keeps (a digest, an identifier, one of the
      platform's own variable names, a MIME type, a path, words, a catalogue
      name) is kept, whatever follows it: ``ZwSetInformationJobObject=1`` is an
      assignment to a name.
    - A run followed by base64 padding (``_PADDING``: one or two ``=`` that end
      a value) ends in a base64 value: its last stretch of base64 characters,
      when it is 24 characters or more and no name the scrub keeps, is masked,
      whatever it begins with. A standard base64 key cut by its own ``/`` and
      ``+`` into fragments shorter than the length rule, or beginning with a
      slash as a path does, is caught here by its padding. An ``=`` that starts
      a value is an assignment and not padding.
    - Otherwise, when a piece of the run between ``/``, ``|``, ``+`` and ``&``
      reads as a key, or a token sits inside it, the key is masked with the
      whole stretch of base64 characters (``A-Za-z0-9+/_-``) around it. Any
      character outside those alphabets (a dot, ``%``, ``|``, ``&``) bounds
      the stretch: ``host.example/<key>/x.php`` reads ``host.***.php``.
    """
    value = found.group(0)
    if _names_only(value):
        return value
    if _is_a_family_name(value) and not _LABEL_BEFORE_RE.search(
        found.string[max(0, found.start() - 40) : found.start()]
    ):
        return value
    if hex_fields and value in hex_fields:
        return value
    if _looks_like_a_credential(value, whole=True):
        return _REDACTED
    head = ""
    tail = _TRAILING_STRETCH.search(value)
    padding = _PADDING.match(found.string, found.end())
    if (
        tail is not None
        and padding is not None
        and len(tail.group(0)) >= 24
        and not _names_only(tail.group(0))
        and (
            padding.group("end") is not None
            or (len(tail.group(0)) + len(padding.group("signs"))) % 4 == 0
        )
    ):
        head, value = value[: tail.start()], ""
    if not value:
        return f"{_hide_in_run(head)}{_REDACTED}" if head else _REDACTED
    return _hide_in_run(value)


# Bytes a tool states as hex under its own ``hex`` field (a memory read, a
# byte range): data the tool read, which the length rule took for a key. Kept
# only where the text parses as JSON (``json.loads``, nothing read by a pattern)
# and the run is the string value of a real ``"hex"`` key, in an object with no
# credential or key-material word in any of its keys or string values and none
# in the key of any object or list around it (``{"token": {"hex": "…"}}``,
# ``{"hex": "…", "kind": "api_key"}``). A JSON document carried as a string
# value of another is read the same way, as part of it. Every place the run
# stands in the text must be such a field: a run that also stands anywhere else
# (a second copy in prose, a key repeated with another value) is masked.
_HEX_DATA = re.compile(r"\A(?:[0-9A-Fa-f]{2})+\Z")
# The words a credential or key material is named by. ``iv`` and ``pwd`` only as
# a whole word: as letters inside another word they name nothing. The scrub's
# own mark counts too: a value an earlier pass masked was read as a credential.
_CREDENTIAL_WORD_RE = re.compile(
    r"(?i)api|auth|bearer|cookie|credential|hmac|key|mnemonic|nonce|passphrase|passwd"
    r"|password|priv|salt|secret|seed|session|signing|token"
    r"|(?<![a-z])(?:iv|pwd)(?![a-z])|\*\*\*"
)
# The key a hex field is read under, as it stands in JSON text, plain or escaped
# once: a text without it is not parsed at all.
_HEX_KEYS_IN_TEXT = ('"hex"', '\\"hex\\"')


def _hex_fields(text: str) -> dict[str, int]:
    """The hex runs of ``text`` that are a tool's ``"hex"`` field and nothing else.

    ``{run: count}``; empty unless ``text`` is one JSON document. Read once per
    scrub call, by that call alone: no state outlives it. The work is linear in
    the text: one parse, one walk that visits each value once (by a stack, so
    no nesting reaches Python's recursion), and one pass over its hex runs.
    """
    if not any(key in text for key in _HEX_KEYS_IN_TEXT):
        return {}
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return {}
    found = _collect_hex_fields(document, budget=len(text))
    if not found:
        return {}
    standing: dict[str, int] = {}
    for run in _HEX_RUN.finditer(text):
        if run.group(0) in found:
            standing[run.group(0)] = standing.get(run.group(0), 0) + 1
    return {run: count for run, count in found.items() if standing.get(run) == count}


# Every hex run of a text, whole: what a field's run is counted against.
_HEX_RUN = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]+(?![0-9A-Fa-f])")
# How deep the reading follows nested objects and JSON documents carried as
# strings; past it a branch counts as naming a credential, which only masks.
_HEX_FIELD_DEPTH = 64


def _collect_hex_fields(document: Any, *, budget: int) -> dict[str, int]:
    """The clean ``"hex"`` fields under ``document``, counted by value.

    A ``"hex"`` field counts when neither its object's own keys and string
    values, nor anything below that object, nor the keys and string values of
    any object around it name a credential. Walked with an explicit stack in
    post order, so an object's own field is decided after its children report
    whether anything below names one. A JSON document carried as a string
    value is parsed and walked as that value's child; no more characters are
    parsed again in all than ``budget`` (the text's own length), and a string
    past it is read as a string.
    """
    found: dict[str, int] = {}
    # Each frame: [node, named around it, depth, children left, below, own].
    stack: list[list[Any]] = [[document, False, 0, None, False, False]]
    reparsed = 0
    while stack:
        frame = stack[-1]
        node, named, depth, children, below, own = frame
        if children is None:
            if depth > _HEX_FIELD_DEPTH:
                stack.pop()
                _pass_up(stack, True)
                continue
            if isinstance(node, str):
                stripped = node.strip()
                inner: Any = None
                parsed = False
                if stripped[:1] in ("{", "[") and reparsed + len(stripped) <= budget:
                    reparsed += len(stripped)
                    try:
                        inner = json.loads(stripped)
                        parsed = True
                    except (ValueError, RecursionError):
                        parsed = False
                if not parsed:
                    stack.pop()
                    _pass_up(stack, bool(_CREDENTIAL_WORD_RE.search(node)))
                    continue
                frame[3] = iter([inner])
            elif isinstance(node, list):
                frame[3] = iter(node)
            elif isinstance(node, dict):
                own = any(_CREDENTIAL_WORD_RE.search(str(key)) for key in node) or any(
                    isinstance(item, str) and _CREDENTIAL_WORD_RE.search(item)
                    for key, item in node.items()
                    if key != "hex"
                )
                frame[4] = frame[5] = own
                frame[3] = iter(
                    item
                    for key, item in node.items()
                    if not (key == "hex" and isinstance(item, str) and _HEX_DATA.match(item))
                )
            else:
                stack.pop()
                _pass_up(stack, False)
                continue
            children = frame[3]
        child = next(children, _NO_CHILD)
        if child is not _NO_CHILD:
            stack.append([child, named or frame[5], depth + 1, None, False, False])
            continue
        stack.pop()
        if isinstance(node, dict):
            value = node.get("hex")
            if not (named or frame[4]) and isinstance(value, str) and _HEX_DATA.match(value):
                found[value] = found.get(value, 0) + 1
        _pass_up(stack, frame[4])
    return found


# What ``next`` answers for a frame with no child left.
_NO_CHILD = object()


def _pass_up(stack: list[list[Any]], below: bool) -> None:
    """Hand a finished frame's "something below names a credential" to its parent."""
    if stack and below:
        stack[-1][4] = True


def _names_only(stretch: str) -> bool:
    """Whether a run is a name the scrub keeps, or names joined by ``/``, with no
    vendor prefix in it: ``path/ZwSetInformationJobObject`` is a word and a
    catalogue name, and a random key is not written that way.

    Split on ``/`` alone: ``+`` joins no words, and a key cut by its own ``+``
    into letter-only pieces is a key. Catalogue names joined by ``+`` are kept
    as one run by the catalogue rule (``_is_api_name``).

    Asked before the padding rule, so a kept name stays readable in front of
    ``=``. A path's shape is not asked here: a key that begins with a slash has
    it, and padding after a run is what a path does not end with; the path rule
    is asked in ``_hide_in_run``, for a run with no padding after it.
    """
    pieces = [piece for piece in stretch.split("/") if piece]
    if _kept_name(stretch):
        return True
    return (
        len(pieces) > 1
        and all(_WORD_PIECE.match(piece) or _kept_name(piece) for piece in pieces)
        and not any(_looks_like_a_credential(piece, whole=True) for piece in pieces)
    )


def _kept_name(token: str) -> bool:
    """``_readable`` without the path rule, and never a run with a vendor prefix."""
    return _readable(token, path=False) and not _looks_like_a_credential(token, whole=True)


def _hide_in_run(value: str) -> str:
    """The rest of ``_hide_credentials`` for a run with no padding after it."""
    if not value or _readable(value) or not _looks_like_a_credential(value):
        return value
    # A token glued to a word in front of it (``name_<jwt>``): its head is
    # found where it starts, wherever that is in the run.
    for start, end in reversed(_glued_tokens(value)):
        value = value[:start] + _REDACTED + value[end:]
    # A token inside the run: its dots end every stretch, so it is found as
    # itself first and masked with the stretches on either side of it.
    value = _JWT_INSIDE.sub(
        lambda token: _REDACTED if _is_a_token(token.group(0)) else token.group(0), value
    )
    return _BASE64_STRETCH.sub(
        lambda stretch: _REDACTED if _stretch_holds_a_key(stretch.group(0)) else stretch.group(0),
        value,
    )


# A stretch of base64 or base64url characters, and one next to the mark a token
# was masked with.
_BASE64_STRETCH = re.compile(r"[A-Za-z0-9+/_\-]*\*\*\*[A-Za-z0-9+/_\-]*|[A-Za-z0-9+/_\-]+")
# The stretch of base64 characters a run ends with.
_TRAILING_STRETCH = re.compile(r"[A-Za-z0-9+/_\-]+\Z")
# Base64 padding after a run: one or two ``=`` that end the value. What may
# follow them is the end of the text or a character no value starts with:
# whitespace; a closing quote, bracket or brace, or ``</`` of a closing tag;
# the separators ``,`` ``;`` ``:`` ``.``; and the scrub's joiners ``/`` ``|``
# ``+`` ``&`` ``!``, which join a key to a path, a module name or a list. A
# quote is closing when an end or one of those separators follows it, and a
# backslash before a quote is the JSON escape of one. Any other follower (a
# letter, a digit, ``-``, ``_``, an opening quote) starts a value, so that
# ``=`` is an assignment; ``_hide_credentials`` still takes it for padding
# when the stretch and its signs together are a multiple of 4 characters,
# which is what a base64 value's length is.
_PADDING = re.compile(
    r"(?P<signs>={1,2})(?!=)"
    r"(?P<end>\Z|(?=[\s)\]}>,;:.\/|+&!])|(?=</)|(?=\\?[\"'`](?:\Z|[\s)\]}>,;:.\/|&!])))?"
)
# A token's shape anywhere in a run: three base64url segments with dots between.
_JWT_INSIDE = re.compile(r"[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
# A token glued to other text inside a longer run: three dot-separated
# base64url segments whose first is the run's trailing stretch from some point
# on. A JOSE header is a JSON object, and base64url of ``{`` begins with ``e``
# and one of ``w``-``z``, a digit, ``-`` or ``_``; the first four characters
# decode to three bytes, and the first being ``{`` is what ``_is_a_token``'s
# decode would find, so each start is decided from those four alone.
_URLSAFE_STRETCH_END = re.compile(r"[A-Za-z0-9_\-]+\Z")
_URLSAFE_SEGMENT = re.compile(r"[A-Za-z0-9_\-]{8,}\Z")
_URLSAFE_SEGMENT_HEAD = re.compile(r"[A-Za-z0-9_\-]{8,}(?:={1,2})?")


def _glued_tokens(run: str) -> list[tuple[int, int]]:
    """Where tokens stand inside ``run`` behind other text, in order. Linear in ``run``."""
    if run.count(".") < 2:
        return []
    parts = run.split(".")
    starts = [0]
    for part in parts[:-1]:
        starts.append(starts[-1] + len(part) + 1)
    spans: list[tuple[int, int]] = []
    index = 0
    while index + 2 < len(parts):
        head = _URLSAFE_STRETCH_END.search(parts[index])
        tail = _URLSAFE_SEGMENT_HEAD.match(parts[index + 2])
        if head is None or tail is None or not _URLSAFE_SEGMENT.match(parts[index + 1]):
            index += 1
            continue
        stretch = head.group(0)
        at = next(
            (
                offset
                for offset in range(len(stretch) - 7)
                if stretch[offset] == "e" and _opens_an_object(stretch[offset : offset + 4])
            ),
            None,
        )
        if at is None:
            index += 1
            continue
        spans.append((starts[index] + head.start() + at, starts[index + 2] + tail.end()))
        index += 3
    return spans


def _opens_an_object(four: str) -> bool:
    """Whether four base64url characters decode to bytes that begin with ``{``."""
    try:
        return base64.urlsafe_b64decode(four).startswith(b"{")
    except (ValueError, binascii.Error):
        return False


def _glued_token(run: str) -> tuple[int, int] | None:
    """Where the first token stands inside ``run`` behind other text, or ``None``."""
    spans = _glued_tokens(run)
    return spans[0] if spans else None


def _readable(token: str, *, path: bool = True) -> bool:
    """Whether the whole run is a name the scrub keeps: a digest, an identifier, one of
    the platform's own variable names, a MIME type, a path (unless ``path`` is false),
    words, or a catalogue name."""
    if _DIGEST.match(token) or _IDENTIFIER.match(token) or token in _OWN_VARIABLE_NAMES:
        return True
    if _MIME_TYPE.match(token) and not _looks_like_a_credential(token.split("/", 1)[1]):
        return True
    return bool((path and _PATH_SHAPED.match(token)) or _is_words(token) or _is_api_name(token))


def _stretch_holds_a_key(stretch: str) -> bool:
    """Whether a stretch of base64 characters holds a key: a masked token, or a piece
    of it between ``/`` and ``+`` that reads as a key."""
    if _REDACTED in stretch:
        return True
    return any(_looks_like_a_credential(piece) for piece in re.split(r"[/+]", stretch) if piece)


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
    line = " ".join(str(text or "").split())
    return _scrub_line(line, _hex_fields(line))


def remember_secret_values(values: Iterable[str], *, scope: str = "job") -> None:
    """Set the values the scrub masks by exact value under ``scope``, in this process.

    A scope registered again replaces what it held: the worker registers each
    job's settings under ``job``, so a secret the operator removed is not masked
    in the next job, and its own startup secrets under ``process``, which stay.
    A value shorter than ``CONFIGURED_SECRET_FLOOR``, or blank, is not kept.
    Only the count is logged, never a value.
    """
    texts = [text for text in (str(value or "") for value in values) if text.strip()]
    kept = frozenset(text for text in texts if len(text) >= CONFIGURED_SECRET_FLOOR)
    _SECRET_SCOPES[scope] = kept
    # A shorter value is kept out of finding rows only (``safe_finding_value``):
    # masked everywhere, a short password would take a word out of every event.
    _SHORT_SECRETS[scope] = frozenset(text for text in texts if len(text) < CONFIGURED_SECRET_FLOOR)
    _FAILED_SCOPES.discard(scope)
    _rebuild_configured_pattern()
    logger.debug("The scrub masks %d configured value(s) under %s.", len(kept), scope)


def secret_registration_failed(scope: str) -> None:
    """Record that a scope's configured values could not be read.

    Until that scope is registered again, a finding row is held to the whole
    event scrub (``safe_finding_value``): with no value to mask by, the shape
    rules are what keeps an operator credential out of report text.
    """
    _FAILED_SCOPES.add(scope)


def forget_secret_values() -> None:
    """Clear every scope: nothing is masked by value afterwards."""
    _SECRET_SCOPES.clear()
    _SHORT_SECRETS.clear()
    _FAILED_SCOPES.clear()
    _rebuild_configured_pattern()


def _rows_kept_as_written() -> bool:
    """Whether finding rows may keep their words: values registered, and no scope failed."""
    return bool(_SECRET_SCOPES) and not _FAILED_SCOPES


def _rebuild_configured_pattern() -> None:
    global _CONFIGURED_PATTERN
    values = sorted(set().union(*_SECRET_SCOPES.values()), key=len, reverse=True)
    _CONFIGURED_PATTERN = (
        re.compile(
            _SECRET_BOUNDARY_BEFORE
            + "(?:"
            + "|".join(re.escape(value) for value in values)
            + r")(?![A-Za-z0-9_])"
        )
        if values
        else None
    )


# In front of a configured value: no letter, digit or underscore — or the end of
# an escape sequence. A tool answer carried as JSON text puts ``\n``, ``\t`` or
# ``\u00a0`` against a value at the start of a line, and the escape's letter or
# last hex digit is not part of the value. After the value an escape begins with
# a backslash, which already counts as a boundary.
_SECRET_BOUNDARY_BEFORE = r"(?:(?<![A-Za-z0-9_])|(?<=\\[A-Za-z])|(?<=\\u[0-9A-Fa-f]{4}))"


def _mask_configured_values(line: str) -> str:
    """``line`` with every configured value replaced by the redaction mark."""
    if _CONFIGURED_PATTERN is None:
        return line
    return _CONFIGURED_PATTERN.sub(_REDACTED, line)


# How many times the passes are repeated at most before the text is taken as
# settled. Each pass only removes or masks, so the text settles in two or three.
_SCRUB_PASSES = 4


def _scrub_line(line: str, hex_fields: Mapping[str, int] | None = None) -> str:
    """The passes over text that is already one line, repeated until they change nothing.

    Once is not always enough: a path cut to its last segment can leave a
    key-shaped segment the value pass had not seen as a run of its own, and a
    second scrub then masked it. Repeating until nothing changes makes the
    scrub idempotent, which is what lets the publisher scrub a payload a
    producer already scrubbed without changing a character of it.
    """
    for _ in range(_SCRUB_PASSES):
        scrubbed = _scrub_once(line, hex_fields)
        if scrubbed == line:
            break
        line = scrubbed
    return line


# The ATT&CK names a label word stands in, read once from the vendored table:
# for each, the text in front of the word and the word after it
# (``Access Token Manipulation`` → ``("access ", "token", "Manipulation")``).
_ATTCK_FILE = "data/attck_techniques.json"
_LABELLED_NAMES: frozenset[tuple[str, str, str]] | None = None


def _labelled_attck_names() -> frozenset[tuple[str, str, str]]:
    """``(text before, label word, word after)`` for each vendored ATT&CK name with a label word."""
    global _LABELLED_NAMES
    if _LABELLED_NAMES is None:
        found: set[tuple[str, str, str]] = set()
        try:
            import json

            from maljan.core.paths import resolve_data

            table = json.loads(resolve_data(_ATTCK_FILE).read_text(encoding="utf-8"))
            for key, row in table.items():
                if key.startswith("_") or not isinstance(row, dict):
                    continue
                name = str(row.get("name") or "")
                for match in re.finditer(r"(?i)\b(bearer|basic|token)\s+(\S+)", name):
                    in_front = name[: match.start()].lower()
                    found.add((in_front, match.group(1).lower(), match.group(2)))
        except Exception as exc:  # noqa: BLE001 — every label then masks what follows it
            logger.warning("The ATT&CK names were not read for the scrub (%s).", exc)
        _LABELLED_NAMES = frozenset(found)
    return _LABELLED_NAMES


def _scheme_and_secret(found: re.Match[str]) -> str:
    """An authorization scheme with what follows it masked, unless the two are an ATT&CK name.

    Kept only on an exact match with a name in the vendored ATT&CK table, the
    words in front of the label included: ``Access Token Manipulation``.
    Anything else after ``Bearer``, ``Basic`` or ``token`` is masked.
    """
    scheme = found.group(1)
    after = found.group(0)[len(scheme) :].strip().rstrip(".,;:!?")
    before = found.string[max(0, found.start() - 80) : found.start()].lower()
    for in_front, label, word in _labelled_attck_names():
        if label == scheme.lower() and after == word and before.endswith(in_front):
            return found.group(0)
    return f"{scheme} {_REDACTED}"


def _scrub_once(line: str, hex_fields: Mapping[str, int] | None = None) -> str:
    """The configured secrets by value, then the four passes, once.

    ``hex_fields`` are the runs of the whole text that are a tool's own hex
    field (:func:`_hex_fields`), read before any pass changed the text.
    """
    line = _mask_configured_values(line)
    line = _SCHEME_AND_SECRET.sub(_scheme_and_secret, line)
    line = _URL_RUN.sub(_shorten_url, line)
    if hex_fields:
        line = _VALUE_RUN.sub(lambda found: _hide_credentials(found, hex_fields), line)
    else:
        line = _VALUE_RUN.sub(_hide_credentials, line)
    return _PATH_RUN.sub(_shorten_path, line)


# How much of a model-written value reaches a finding row. Such a row is
# stored with the report and printed verbatim by the console, so it is
# bounded: a value a model wrote is as long as the model cared to make it, and
# a 4 KB "verdict" drawn as one line of a run record is a page nobody can read.
FINDING_VALUE_LIMIT = 200


def safe_finding_value(value: Any) -> str:
    """One model-written value, made fit to store in a finding row and to print.

    A finding row is report text, printed in the report's notes, stored with
    it and served by the API. With the operator's configured values
    registered, the row keeps the words of the evidence and the catalogue it
    quotes; what is kept out is every operator credential: each configured
    value, by value (a short one as a whole word), a URL's userinfo, and a
    query value whose key names a credential. The event scrub's shape rules do
    not run, and the publisher still scrubs the event that carries the row.

    With no values registered, or a scope that could not be read
    (``secret_registration_failed``), the row is held to the whole event
    scrub, as before: the shape rules are then what keeps a credential out.

    Bounded either way, and never cut inside a value the scrub would mask.
    """
    one_line = " ".join(str(value or "").split())
    if not _rows_kept_as_written():
        return _cut_whole(scrub(one_line), FINDING_VALUE_LIMIT)
    kept = _mask_short_secrets(_mask_configured_values(one_line))
    kept = _URL_RUN.sub(_without_credentials, kept)
    return _bound_whole(kept, FINDING_VALUE_LIMIT)


def _mask_short_secrets(text: str) -> str:
    """``text`` with every configured value shorter than the floor masked as a whole word.

    A value of fewer than four characters is not masked as a word anywhere,
    which would take ordinary words out of the row; it is masked as the whole
    word after an authorization scheme (``Bearer``, ``Basic``, ``token``),
    where it stands as the credential, and where it is a URL's password, the
    userinfo removal takes it.
    """
    short = {value for values in _SHORT_SECRETS.values() for value in values}
    values = sorted((value for value in short if len(value) >= 4), key=len, reverse=True)
    tiny = sorted((value for value in short if len(value) < 4), key=len, reverse=True)
    if values:
        pattern = (
            _SECRET_BOUNDARY_BEFORE
            + "(?:"
            + "|".join(re.escape(value) for value in values)
            + r")(?![A-Za-z0-9_])"
        )
        text = re.sub(pattern, _REDACTED, text)
    if tiny:
        after_a_scheme = (
            r"(?<![A-Za-z0-9_])(?i:bearer|basic|token)(\s+)(?:"
            + "|".join(re.escape(value) for value in tiny)
            + r")(?![A-Za-z0-9_])"
        )
        text = re.sub(
            after_a_scheme,
            lambda found: (
                found.group(0)[: found.start(1) - found.start(0)] + found.group(1) + _REDACTED
            ),
            text,
        )
    return text


# One query parameter of a URL, its key and its value.
_QUERY_PARAMETER = re.compile(r"(?P<lead>[?&;#])(?P<key>[^=&;#?]+)=(?P<value>[^&;#]*)")


def _without_credentials(found: re.Match[str]) -> str:
    """One URL with its userinfo masked and each credential-named query value masked."""
    from maljan.core.settings_catalog import names_a_credential_value

    rest = found.group("rest")
    cut = min((rest.find(mark) for mark in "/?#" if mark in rest), default=len(rest))
    authority, tail = rest[:cut], rest[cut:]
    if "@" in authority:
        authority = f"{_REDACTED}@" + authority.rsplit("@", 1)[1]

    def _query(parameter: re.Match[str]) -> str:
        key = parameter.group("key")
        if not names_a_credential_value(key) and key.lower() not in _CREDENTIAL_QUERY_KEYS:
            return parameter.group(0)
        return f"{parameter.group('lead')}{key}={_REDACTED}"

    return f"{found.group('scheme')}://{authority}{_QUERY_PARAMETER.sub(_query, tail)}"


# The query keys a service URL carries a credential under, named by their last
# word or as written here.
_CREDENTIAL_QUERY_KEYS = frozenset({"api_key", "apikey", "access_token", "token", "key"})


def _bound_whole(text: str, limit: int) -> str:
    """``text`` bounded near ``limit`` and marked, never cut inside a value the scrub masks.

    A digest or an identifier the cut would split is kept whole. Any other
    run the cut falls in is cut in front of when the scrub would mask it, so
    the event that carries the row never holds the head of a key.
    """
    if len(text) <= limit:
        return text
    cut = limit - 1
    for found in _WHOLE_RUN.finditer(text):
        if found.start() < cut < found.end():
            cut = found.end()
            break
    if cut >= len(text):
        return text
    for found in _VALUE_RUN.finditer(text):
        if found.start() < cut < found.end():
            if scrub(found.group(0)) != found.group(0) or _looks_like_a_credential(
                text[found.start() : cut]
            ):
                cut = found.start()
            break
    return text[:cut] + CUT_MARK


# Where the run record keeps an analyst answer no claim could be read from.
UNPARSED_ANSWERS_RECORD = "run_summary.validation.unparsed_answers"


def unparsed_answer_kept_sentence(answer: str) -> str:
    """What an event says of an answer no claim could be read from: never the answer."""
    return (
        f"The answer ({len(str(answer or '')):,} characters) could not be read as claims; "
        f"it is kept whole in the run record ({UNPARSED_ANSWERS_RECORD})."
    )


def safe_answer_text(value: Any) -> str:
    """A whole model answer, made fit to keep in the run record.

    The masking a finding row gets (:func:`safe_finding_value`) — every
    configured value, a URL's userinfo and a credential-named query value; the
    whole event scrub where no values are registered — with the answer's own
    lines kept and no bound: the answer is as long as it is, and kept to be
    read for why it could not be parsed.
    """
    text = str(value or "")
    if not _rows_kept_as_written():
        return scrub_keeping_layout(text)
    kept = _mask_short_secrets(_mask_configured_values(text))
    return _URL_RUN.sub(_without_credentials, kept)


def scrub_keeping_layout(text: Any) -> str:
    """The same four passes, with the text's own lines and indentation kept.

    For a field a reader reads as prose rather than skims as a summary — an
    analyst's report, a correction, a failure's detail. ``scrub`` collapses
    whitespace because a one-line summary has no use for any of it; doing that
    to a written report turns it into a wall of text and flattens the lists
    and code blocks in it. Every rule is applied to each line on its own,
    which is exactly what ``scrub`` does to the single line it makes.
    """
    whole = str(text or "")
    fields = _hex_fields(whole)
    return "\n".join(_scrub_line(line, fields) for line in whole.splitlines())


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
    return _cut_whole(scrub(value), ARGUMENT_VALUE_CHARS)


# A digest or an identifier inside a longer text, which a cut must not split:
# the publisher scrubs every payload again, and the part of a digest left in
# front of the cut is a hex run of no digest's length, which that second pass
# reads as a key.
_WHOLE_RUN = re.compile(
    r"(?<![A-Za-z0-9])(?:[A-Fa-f0-9]{64}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{32}"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r"(?:\.[A-Za-z0-9]{1,16}(?![A-Za-z0-9.]))?(?![A-Za-z0-9])"
)


def _cut_whole(text: str, limit: int) -> str:
    """``text`` bounded near ``limit`` and marked, never cut inside a value the scrub kept.

    ``text`` is already scrubbed. A digest or an identifier the cut would
    split is kept whole, with the file extension after it: ``<sha256>.exe`` is
    the name a reader needs, and it runs past the cap by a few characters. Any
    other run the cut would leave in a shape the scrub reads as a key is cut in
    front of instead. And whatever the cut leaves, a URL cut short or a scheme
    word with the cut mark after it, the result is scrubbed once more: while
    that changes it, the cut moves back to the start of the word it falls in,
    so scrubbing the result again changes nothing.
    """
    if len(text) <= limit:
        return text
    cut = limit - 1
    for found in _WHOLE_RUN.finditer(text):
        if found.start() < cut < found.end():
            cut = found.end()
            break
    if cut >= len(text):
        return text
    for found in _VALUE_RUN.finditer(text):
        if found.start() < cut < found.end():
            if _looks_like_a_credential(text[found.start() : cut]):
                cut = found.start()
            break
    made = text[:cut] + CUT_MARK
    while cut > 0 and scrub(made) != made:
        cut = text.rfind(" ", 0, cut)
        cut = max(cut, 0)
        made = text[:cut].rstrip() + CUT_MARK
    return made


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
    # The joined line is scrubbed as a whole too: two values side by side can
    # make a run neither was alone.
    return _cut_whole(scrub(", ".join(parts)), ARGUMENT_SUMMARY_CHARS)


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
    return _cut_whole(text, RESULT_SUMMARY_CHARS)


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
    repeated_of: str = "",
) -> None:
    """One tool call, as it answers, with the ledger id its result is under.

    ``repeated_of`` is the earlier entry a call the repeat guard answered
    without running repeats; the key is sent only for such a call.
    """
    payload: dict[str, Any] = {
        "stage": str(stage),
        "agent": str(agent),
        "tool": str(tool),
        "server": str(server) if server else None,
        "evidence_id": str(evidence_id),
        "ok": bool(ok),
        "duration_ms": max(0, int(duration_ms)),
        "summary": str(summary),
    }
    if repeated_of:
        payload["repeated_of"] = str(repeated_of)
    emit(sink, TOOL_CALL_FINISHED, payload)


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
    answer_kept: str = "",
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

    ``answer_kept`` is one short sentence, for a violation that says none of
    the producer's answer could be read: that it could not, how long it was,
    and where the run record keeps it (``unparsed_answer_kept_sentence``). The
    answer itself never rides on an event: events reach every connected
    browser, the Redis stream and ``job_events``, and each field on them is
    bounded. Left out when empty.
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
            **({"answer_kept": str(answer_kept)} if answer_kept else {}),
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
