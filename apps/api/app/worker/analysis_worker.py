"""ARQ worker — executes MaljanApp pipeline in a background process.

This worker is started separately from the API server:

    arq app.worker.analysis_worker.WorkerSettings

It picks up jobs from Redis and runs the full multi-agent analysis
pipeline, streaming progress events via Redis PubSub.
"""

import asyncio
import gc
import json
import os
import platform
import signal
import sys
import threading
import time
import traceback
import uuid
from collections.abc import Callable, Iterable
from contextlib import suppress
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis
from arq import cron
from maljan.agents.base_agent import CANCEL_DELIVERY_GRACE
from maljan.core.cancellation import Cancellation, JobCancelled
from maljan.core.config import Settings as _CoreSettings
from maljan.core.settings_catalog import core_catalog
from maljan.core.settings_overrides import build_settings, public_snapshot
from maljan.pipeline.outcome import absent_analysis_message
from pydantic import ValidationError
from sqlalchemy import Select, delete, func, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import get_settings, settings
from app.logging_config import get_logger, setup_logging
from app.runtime_config import runtime_config
from app.worker.queues import ANALYSIS_QUEUE, build_redis_settings

logger = get_logger("worker")

_SECRET_PATHS = [e.path for e in core_catalog() if e.secret]


def is_publishable(message: str) -> bool:
    """Whether this sentence can go out as it stands.

    The test is the event publisher's own scrubber: if it would change the
    text, the text holds something that must not travel — a host path, a URL,
    a digest, a credential shape — and what this module undertook to publish is
    sentences it wrote itself, not data it was handed.
    """
    if not message:
        return True
    # Deferred like every other ``maljan`` import here: the API process must
    # not pay for the core package at import time.
    from maljan.pipeline.events import scrub

    return scrub(message) == message


class StatedFailure(Exception):
    """A failure whose message this module wrote for an operator to read.

    Every word of it is composed here, from constants and from ids this system
    issued — never by a driver, a filesystem or a model — so it carries no host
    path, no connection string and nothing a sample author chose. That is what
    makes it safe to publish, and ``failure_reason`` keeps the message of this
    class where it puts only the exception's class name for everything else.

    Raise it wherever this module knows better than the caller's stack trace
    what the operator should do next; a bare ``ValueError`` in the same place
    reaches the console as ``ValueError (error id …)`` and the sentence stays
    in the log.

    The promise is checked where it is made, and checking it never costs a run.
    A message the event publisher's own scrubber would change is not an
    authored sentence — it carries a path, a URL, a digest or something shaped
    like a credential — so the instance is marked ``publishable = False`` and
    ``failure_reason`` falls back to the class name and the error id for it,
    with the sentence going to the log under that id. Raising here instead
    would replace the failure being reported with a failure about reporting it,
    inside whatever ``except`` built it.

    ``StatedFailure(str(exc))`` — the one way this class could leak a driver's
    words — is therefore harmless at runtime and caught in CI:
    ``test_absent_analysis.py`` walks every site in this module that raises one
    and asserts its authored sentence is publishable, so a bad sentence fails a
    build rather than a job.
    """

    def __init__(self, message: str = "") -> None:
        text = str(message)
        super().__init__(text)
        self.publishable = is_publishable(text)


class AbsentAnalysisError(StatedFailure):
    """The pipeline ran and produced no analysis at all.

    Its own class rather than a flag, so the one failure path already in this
    module marks the job failed, records the message and persists no report —
    a job that says "completed" over a run nobody performed is worse than one
    that says it failed, because only the first is read as a result.

    The message comes from ``pipeline.outcome``, which composes it from a
    provider's error class and status and never from its body.
    """


# What ``AgentFinding.status`` may hold. The column feeds a TypeScript union
# and a status badge, so a value an ISR invented would reach both and render
# as whatever the UI's fallback happens to be.
_AGENT_FINDING_STATUSES = frozenset({"complete", "no_data", "no_claims", "failed", "timeout"})


def attached_report_stmt(report_id: uuid.UUID, sample_id: uuid.UUID) -> Select[Any]:
    """The one attached sandbox report a job may read: its own sample's.

    This used to select by report id alone and
    compare ``row.sample_id`` afterwards. Asking the ownership question in SQL
    keeps the two from ever drifting apart, and a report belonging to another
    sample is not read out of the database on the way to being refused.
    """
    from app.models.sandbox_report import SandboxReportRow

    return select(SandboxReportRow).where(
        SandboxReportRow.id == report_id,
        SandboxReportRow.sample_id == sample_id,
    )


def build_job_settings(
    overrides: dict[str, Any], job_config: dict[str, Any] | None
) -> _CoreSettings:
    """UI overrides layered over the model defaults, then the job's own config on top.

    The job's values are folded into the override dict rather than assigned
    afterwards, so the model's Literal choices and bounds apply to them too
    (``Settings`` does not validate on assignment). Which provider ids are
    legal here stays in step with the registry and ``Settings`` themselves via
    ``test_job_provider_overrides.py::test_the_ids_agree_exactly_in_all_three_places``.
    """
    merged = dict(overrides)
    if job_config:
        if job_config.get("max_iterations") is not None:
            merged["negotiation.max_iterations"] = job_config["max_iterations"]
        if job_config.get("llm_provider") is not None:
            merged["llm.provider"] = job_config["llm_provider"]
        if job_config.get("static_provider") is not None:
            merged["static.provider"] = job_config["static_provider"]
        if job_config.get("sandbox_provider") is not None:
            merged["sandbox.provider"] = job_config["sandbox_provider"]
        if job_config.get("sandbox_report_id") is not None:
            # An attached report is the strongest statement of intent there is:
            # it names the evidence, so it also names the provider that reads it.
            merged["sandbox.provider"] = "upload"
        if job_config.get("profile") is not None:
            merged["agents.profile"] = job_config["profile"]
    return build_settings(merged)


def ghidra_samples_path_line(api_settings: Any) -> str:
    """The line the worker states at start: the Ghidra samples path and where it came from.

    The path is the one the Ghidra container sees the samples directory at,
    and the worker hands Ghidra every sample under it. A host path here makes
    every load answer "File not found" from inside the container, so the
    value and its source are said once, where an operator reads the start.
    """
    path = str(api_settings.ghidra_container_samples_path)
    if "ghidra_container_samples_path" in api_settings.model_fields_set:
        source = "from GHIDRA_CONTAINER_SAMPLES_PATH"
    else:
        source = "the default; GHIDRA_CONTAINER_SAMPLES_PATH is not set"
    return (
        f"Ghidra samples path: {path} ({source}). Ghidra is handed each sample under "
        "this path, which is the samples directory as the Ghidra container sees it, "
        "not a path on this host."
    )


def mirror_target_for(provider: Any, *, sha256: str, extension: str) -> tuple[Path, str] | None:
    """Where this sample has to be copied for the static provider to read it.

    Returns (host path, container-visible path), or None when the provider does
    not need a copy at all — a capa/YARA or radare2 run that reads the bytes in
    place, and every future provider that does the same. The host directory and
    its 0o700/0o600 handling stay in ``sample_files``; only the decision moved.
    """
    from app.worker import sample_files

    if not provider.capabilities.needs_sample_mirror:
        return None
    spec = provider.mirror_spec()
    if spec is None:
        return None
    # The spec's own subdirectory, not a fixed one. This was ``work_dir()``
    # unconditionally, which put r2's copy in the hidden ``.work`` that radare2
    # refuses to open — BUG 10, every live r2 tool call answering "Failed to
    # open file." The container-visible path below already read the spec.
    host = sample_files.work_dir(spec.work_subdir) / f"{sha256}{extension}"
    if not spec.container_prefix:
        # An empty prefix means the analyst-facing tool is co-located with the
        # worker (e.g. a stdio r2mcp) and opens the sample by its host path
        # directly — there is no separate container mount to translate into.
        return host, str(host)
    prefix = settings.ghidra_container_samples_path.rstrip("/")
    container = f"{prefix}/{spec.work_subdir}/{sha256}{extension}"
    return host, container


def global_mirror_path(paths: dict[str, str], static_settings: Any) -> str | None:
    """``state["static_sample_path"]``: the globally configured provider's mirror.

    That key is *the* static sample path and every
    single-provider reader still means the global provider by it, so it is
    ``None`` when that provider needed no copy — even if a clone on another
    provider mirrored. Taking whichever provider happened to mirror first
    handed the clone's path to readers that mean the global one.
    """
    return paths.get(str(static_settings.provider))


def profile_static_providers(container: Any) -> list[str]:
    """The distinct static provider ids this job needs, the global one first.

    Order matters for the mirror log and for ``global_mirror_path``, which
    reads the global provider's entry back out of the per-provider map to fill
    ``state["static_sample_path"]`` — the frozen key every single-provider
    reader still uses. The globally configured provider is
    always in the list even when no analyst names it, because that provider is
    the one that key means.

    Every agent that opens a static provider counts, not only the ``static``
    role: a generic reverser given ``static_provider="ghidra"`` and a
    ``provider`` tool reference opens Ghidra too, and without a mirror for
    Ghidra its ``load_program`` is handed a path the container cannot see.
    The agents a lead can ask count as well, since they run under the same
    job and open their own providers.
    """
    from maljan.agents.composition import (
        reachable_agents,
        reads_static_provider,
        static_provider_id_for,
    )

    settings = container.config
    ids = [str(settings.static.provider)]
    for key in reachable_agents(settings, container.analyst_keys()):
        if not reads_static_provider(settings.agents.definitions.get(key)):
            continue
        provider_id = static_provider_id_for(settings, key)
        if provider_id not in ids:
            ids.append(provider_id)
    return ids


def mirror_static_samples(
    container: Any,
    *,
    temp_path: str,
    sha256: str,
    extension: str,
    copy_fn: Callable[[Path, Path], None],
    job_id: str = "",
) -> tuple[list[Path], dict[str, str]]:
    """Copy the sample once per distinct host path this job's providers need.

    Two static providers (e.g. Ghidra and a co-located r2mcp) can answer the
    same ``mirror_target_for(...)`` host path for the same sample — see
    ``test_each_provider_gets_its_own_container_visible_path``. Looping over
    ``profile_static_providers`` and copying on every hit copied that file
    twice and left a duplicate entry in the returned mirror list, so a caller
    that removes each entry on cleanup tried to remove the same path twice.
    This copies and records each host path once, while still mapping every
    provider id that reaches it to its own container-visible path.

    Exceptions from ``copy_fn`` are caught and logged, matching the previous
    inline behaviour: whatever mirrored before the failure is kept.
    """
    host_mirrors: list[Path] = []
    static_sample_paths: dict[str, str] = {}
    copied_host_paths: set[Path] = set()
    mirror_target_path: Path | str = Path(temp_path)
    try:
        for provider_id in profile_static_providers(container):
            target = mirror_target_for(
                container.get_static_provider(provider_id),
                sha256=sha256,
                extension=extension,
            )
            if target is None:
                logger.info(
                    "Static provider '%s' needs no sample mirror; skipping the copy.",
                    provider_id,
                    extra={"job_id": job_id, "component": "sample-mirror"},
                )
                continue
            host_mirror, container_path = target
            mirror_target_path = host_mirror
            # This job's mirror directory is a directory the sidecars may
            # read a path in. Named here as well as at startup because the
            # job's settings decide which subdirectory a provider mirrors into,
            # and startup only knows the ones its own settings named.
            #
            # It has to be named *before* a sidecar starts, not merely before
            # the path is used: ``child_env`` copies the environment into the
            # child at spawn, so a root added afterwards never reaches a server
            # that is already running. That holds here because the mirror runs
            # in ``run_analysis`` and every sidecar is opened later, inside
            # ``MaljanApp.arun``.
            from maljan.tools.roots import add_sample_root

            add_sample_root(host_mirror.parent)
            if host_mirror not in copied_host_paths:
                copy_fn(Path(temp_path), host_mirror)
                host_mirrors.append(host_mirror)
                copied_host_paths.add(host_mirror)
            static_sample_paths[provider_id] = container_path
            logger.info(
                "Mirrored sample to %s for static provider '%s' (%s).",
                host_mirror,
                provider_id,
                container_path,
                extra={"job_id": job_id, "component": "sample-mirror"},
            )
    except Exception as mirror_exc:
        # M2: this used to hard-code "for Ghidra" and log settings.samples_dir
        # (the samples root, not the mirror target that actually failed) — a
        # leftover from before the mirror step was generalised to any static
        # provider.
        logger.warning(
            "Failed to mirror sample to %s for the static provider: %s. "
            "Static analyst will fall back to metadata-only prompt.",
            mirror_target_path,
            mirror_exc,
            extra={"job_id": job_id, "component": "sample-mirror"},
        )
    return host_mirrors, static_sample_paths


def settings_snapshot(
    core_settings: _CoreSettings, overridden_keys: Iterable[str] | None = None
) -> dict[str, Any]:
    """Non-secret view of the effective per-job Settings for ``run_summary``.

    ``overridden_keys`` names the dotted core paths (without the ``core.``
    namespace prefix) that came from a stored UI override rather than the
    environment/default, so a report reader can tell what was in effect
    without re-deriving it from the (masked) values alone.
    """
    snap: dict[str, Any] = public_snapshot(core_settings, _SECRET_PATHS)
    snap["overridden_keys"] = sorted(overridden_keys or [])
    return snap


# ── Redis event channel helper ───────────────────────────────────


class _JobEventBuffer:
    """One job's events on their way to ``job_events``, in batches.

    A row per event, committed as the event is published, would put a
    transaction between every tool call and the next on a database the same
    process is running the analysis against. A batch costs one transaction per
    batch and still leaves a cancelled run holding all but its last handful of
    lines, which is the case the table exists for.

    The batch is written on the first event after fifty have queued or after
    two seconds have passed — on an event, not on a timer. Nothing here wakes
    up on its own: a run that emits five lines and then spends half an hour
    inside one analyst turn keeps those five in memory until the next event or
    until the run ends, and the ``finally`` that ends it covers cancellation
    and failure alike. What that leaves uncovered is a ``SIGKILL`` or the
    memory recycler taking the process mid-silence, which costs the handful of
    lines still queued; a timer task per job would close it and would have to
    be cancelled on every path out of a run, which is a failure mode of its
    own for the last few lines of a run nobody is watching.

    Never raises and never blocks the publish it was called from. A feed that
    could fail a run would be worse than no feed: the rows are a record of the
    analysis, not part of it. A batch that will not insert is dropped with a
    warning rather than retried, because the events it holds are already on
    the socket and in the Redis stream, and a retry queue that grows during a
    database outage is a second failure on top of the first.
    """

    BATCH = 50
    SECONDS = 2.0

    def __init__(self, job_id: str, db_session: async_sessionmaker) -> None:
        self.job_id = job_id
        self.db_session = db_session
        self._pending: list[dict[str, Any]] = []
        self._last_flush = time.monotonic()
        self._lock = asyncio.Lock()

    async def add(self, seq: int, event_type: str, data: dict[str, Any], ts: str) -> None:
        """Queue one event, writing the batch when it is full or old enough."""
        async with self._lock:
            self._pending.append(
                {
                    "seq": int(seq),
                    "type": str(event_type)[:64],
                    "payload": data,
                    "ts": _parse_event_ts(ts),
                }
            )
            due = (
                len(self._pending) >= self.BATCH
                or (time.monotonic() - self._last_flush) >= self.SECONDS
            )
        if due:
            await self.flush()

    async def flush(self) -> None:
        """Write what is queued. Never raises."""
        async with self._lock:
            rows, self._pending = self._pending, []
            self._last_flush = time.monotonic()
        if not rows:
            return
        try:
            from app.models.job_event import JobEvent

            async with self.db_session() as db:
                db.add_all([JobEvent(job_id=uuid.UUID(self.job_id), **row) for row in rows])
                await db.commit()
        except Exception as exc:  # noqa: BLE001 — the feed never costs a run
            logger.warning(
                "Could not persist %d event(s) for job %s (%s).",
                len(rows),
                self.job_id,
                exc,
                extra={"job_id": self.job_id, "component": "pubsub"},
            )


# The jobs this process is persisting a feed for. ``_publish_event`` is called
# from a dozen places with nothing but a Redis handle and a job id, so the
# session factory is registered once by the task that has one rather than
# threaded through every call site.
_EVENT_BUFFERS: dict[str, _JobEventBuffer] = {}


def _start_event_feed(job_id: str, db_session: async_sessionmaker) -> None:
    """Persist this job's feed from here on, in batches."""
    _EVENT_BUFFERS[job_id] = _JobEventBuffer(job_id, db_session)


async def _stop_event_feed(job_id: str) -> None:
    """Write whatever is still queued and forget this job. Never raises.

    Called from the task's one ``finally``, which every path out of a run goes
    through — success, failure, and the early return a cancellation takes — so
    the last handful of lines of a run that stopped part-way is written rather
    than lost with the process.
    """
    buffer = _EVENT_BUFFERS.pop(job_id, None)
    _LAST_SEQ.pop(job_id, None)
    if buffer is not None:
        await buffer.flush()


# The per-job sequence counter, and the last number this process handed out
# for each job. Redis ``INCR`` is the source of truth — it is atomic, so two
# publishers cannot be given the same number — and the local map is both a
# mirror of it and the fallback for a Redis that is refusing writes: a feed
# with no counter at all is a feed a client cannot resume, which is worse than
# one whose numbering restarts after an outage.
_LAST_SEQ: dict[str, int] = {}


def _seq_key(job_id: str) -> str:
    return f"analysis:{job_id}:seq"


async def seed_seq_from_the_table(
    redis_conn: aioredis.Redis, db_session: async_sessionmaker, job_id: str
) -> int | None:
    """Continue this job's numbering from what is stored. Never raises.

    The counter is a Redis key with a 24-hour life, because the stream it
    numbers has one too. The table does not: an event published for a job whose
    counter has expired — an operator pressing Enrich on last week's report —
    would take the number 1, collide with the row that job's first event
    already has (``uq_job_events_job_seq``), and be dropped by a feed that
    never fails a run. The same "published but not stored" the enrichment event
    was fixed for.

    So before such an event is published, the counter is set to the highest
    number the table holds for that job, and only when Redis holds none: ``NX``
    rather than a plain ``SET``, so a live run's counter is never overwritten
    by a straggler. Returns the number it seeded with, or ``None`` when there
    was nothing to do.

    Callers do not have to remember this: ``_next_seq`` runs it for every job
    whose feed is being persisted, before it hands out that job's first number
    in this process. This is the body it runs.

    One window this does not close: a counter that expires between the
    ``EXISTS`` here and the ``INCR`` that follows numbers from 1 again. The key
    lives 24 hours and every ``INCR`` refreshes it, so the window is the few
    microseconds between two Redis calls on a job whose counter was about to
    expire anyway; the row that collides is dropped by a feed that never fails
    a run, as it was before any of this.
    """
    key = _seq_key(job_id)
    try:
        if await redis_conn.exists(key):
            return None
        from app.models.job_event import JobEvent

        async with db_session() as db:
            highest = (
                await db.execute(
                    select(func.max(JobEvent.seq)).where(JobEvent.job_id == uuid.UUID(job_id))
                )
            ).scalar()
            await db.commit()
        if not highest:
            return None
        await redis_conn.set(key, int(highest), nx=True, ex=86_400)
    except Exception as exc:  # noqa: BLE001 — numbering never costs an event
        logger.debug(
            "Could not continue the event numbering for job %s (%s).",
            job_id,
            type(exc).__name__,
            extra={"job_id": job_id},
        )
        return None
    return int(highest)


async def _seed_seq_once(redis_conn: aioredis.Redis, job_id: str) -> None:
    """Continue a stored job's numbering before its first number here.

    Seeding belongs to whoever hands out the numbers, not to whoever happens
    to publish late: a task that re-opens an old job's feed and forgets the
    seed loses its event to the unique constraint, and there is no way to see
    that from the call site. So the publisher does it, once per job per
    process — the first number is the only one that can collide, every later
    one comes from a counter this process advanced.

    Only for a job whose feed is being persisted. Without a buffer there is no
    row to collide with, and the query would buy nothing.
    """
    if job_id in _LAST_SEQ:
        return
    buffer = _EVENT_BUFFERS.get(job_id)
    if buffer is None:
        return
    await seed_seq_from_the_table(redis_conn, buffer.db_session, job_id)


async def _next_seq(redis_conn: aioredis.Redis, job_id: str) -> int:
    """The next sequence number for this job's feed. Never raises."""
    await _seed_seq_once(redis_conn, job_id)
    try:
        seq = int(await redis_conn.incr(_seq_key(job_id)))
    except Exception as exc:  # noqa: BLE001 — a counter never costs a run
        logger.debug(
            "Event sequence INCR failed (%s); numbering locally.",
            exc,
            extra={"job_id": job_id, "component": "pubsub"},
        )
        seq = _LAST_SEQ.get(job_id, 0) + 1
    else:
        # Only the ``INCR`` decides the number. A failing TTL refresh used to
        # land in the same ``except`` and throw away a number Redis had
        # already advanced past, so the fallback handed out a value the next
        # successful ``INCR`` would hand out again — a duplicate ``seq`` under
        # two publishers, and an integrity error on the batch that carried it.
        #
        # The same 24 h the stream gets: the counter is only meaningful while
        # there is a stream to read alongside it, and the table keeps its own
        # copy of every number for the replay after that.
        try:
            await redis_conn.expire(_seq_key(job_id), 86_400)
        except Exception as exc:  # noqa: BLE001 — a TTL never costs a number
            logger.debug(
                "Event sequence TTL refresh failed (%s); the number stands.",
                exc,
                extra={"job_id": job_id, "component": "pubsub"},
            )
    # Written without an await in between, so two coroutines interleaving here
    # cannot both read the same previous value.
    _LAST_SEQ[job_id] = max(seq, _LAST_SEQ.get(job_id, 0))
    return seq


# The fields of an event that *name* something rather than say something: an
# identifier this system issued, a key one of its own patterns produced, a
# label an operator typed, or a word the console switches on. None of them is
# text a model or a sample author wrote, and each of them is read rather than
# skimmed — a speaker replaced by ``***`` is a conversation the console cannot
# group under anybody, and a ``report_id`` replaced by ``***`` is a completion
# nobody can open.
#
# Named here, in the one place that knows which field a string sits in, rather
# than guessed at from the shape of the value. A shape test around "the keys
# this system issues are lowercase" let four real credential formats through —
# ``key-…``, ``gocspx-…``, ``ghs_…`` and any base64url blob without capitals —
# and a credential does not become safe by sitting in a field with a friendly
# name, which is why ``text``, ``report``, ``summary``, ``message``,
# ``detail``, ``reason``, ``claim``, ``evidence_ref`` and the sample's own
# filename are deliberately absent from this list.
IDENTITY_FIELDS = frozenset(
    {
        # What this system issued.
        "report_id",
        "job_id",
        "sample_id",
        "error_id",
        "evidence_id",
        "technique_id",
        # Who and where: agent, stage, server and tool keys, in the singular
        # and in the lists an event carries them in.
        "speaker",
        "agent",
        "agents",
        "addressed_to",
        "stage",
        "stages",
        "via",
        "server",
        "tool",
        "key",
        "profile",
        # What an operator called them.
        "label",
        "display_name",
        # The words the console switches on.
        "role",
        "kind",
        "status",
        "phase",
        "cap",
        "code",
        "verdict",
    }
)


def scrubbed(value: Any, *, field: str = "") -> Any:
    """``value`` with every string inside it scrubbed, however deeply it sits.

    Keys are left as they are: a key is a field name the console switches on,
    not text somebody wrote. Numbers, booleans and ``None`` keep their type,
    so a payload that goes through this is still the payload the reader
    expects — only its prose has been through ``maljan.pipeline.events.scrub``.

    A value sitting directly under one of ``IDENTITY_FIELDS`` is left alone,
    and so is each string of a list under one — ``agents: ["static", …]`` is
    the same kind of thing as ``agent: "static"``. The exemption stops there:
    a dict below an identity field is walked like any other, so its own fields
    are judged by their own names.
    """
    from maljan.pipeline.events import scrub_keeping_layout

    if isinstance(value, str):
        return value if field in IDENTITY_FIELDS else scrub_keeping_layout(value)
    if isinstance(value, dict):
        return {key: scrubbed(item, field=str(key)) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [scrubbed(item, field=field) for item in value]
    return value


async def _publish_event(
    redis_conn: aioredis.Redis,
    job_id: str,
    event_type: str,
    data: dict[str, Any] | None = None,
    stamp: dict[str, Any] | None = None,
) -> None:
    """Publish a pipeline progress event to Redis PubSub + Stream + the table.

    PubSub channel ``analysis:{job_id}`` is used by the live WebSocket
    fan-out. A parallel Redis Stream ``analysis:{job_id}:events`` keeps
    the last 1000 events so a client opening the Live tab mid-run can
    back-fill its event log via ``GET /api/v1/jobs/{job_id}/events``.

    Message format on both channels:
    ``{"type": ..., "data": ..., "ts": ...}``.

    Every event is stamped with a per-job ``seq`` *here* and nowhere else.
    Nothing in ``maljan`` knows which job it is running under, so nothing in
    ``maljan`` can number a run; and a second counter anywhere would order one
    conversation two ways. The number is what a client resumes from, on the
    socket and on the events endpoint alike.

    The same event is queued for ``job_events`` when this job registered a
    session factory (see ``_start_event_feed``), which is what keeps the
    conversation of a failed or cancelled run readable after the stream's
    24 h TTL.

    ``stamp`` is the transcript recorder's own copy of this message, given the
    same number. The recorder takes its copy synchronously on the pipeline's
    thread, before the publish is even scheduled — that is what keeps the
    record safe from a Redis outage — so the number cannot be in it when it is
    taken. Writing it here rather than numbering the transcript separately at
    the end of the run is what makes one ``seq`` mean one thing: a live
    message and the row that replaces it after the run carry the same
    identity, and a console merging the two collapses them instead of drawing
    both.
    """
    import json

    seq = await _next_seq(redis_conn, job_id)
    if stamp is not None:
        stamp["seq"] = seq
    # Scrubbed here, once, for all three sinks. Seven producers build these
    # payloads and a new one cannot be relied on to remember; the publisher is
    # where the wire begins, so it is where the guarantee belongs. Producers
    # may still scrub — doing it twice changes nothing. The recorder's copy is
    # scrubbed where it is taken (``_make_event_sink``), not here: it is taken
    # before this coroutine is even scheduled, and on the paths the recorder
    # exists for this coroutine never runs.
    stamped = {**scrubbed(data or {}), "seq": seq}
    ts = datetime.now(UTC).isoformat()
    payload = {
        "type": event_type,
        "data": stamped,
        "ts": ts,
    }
    message = json.dumps(payload)
    buffer = _EVENT_BUFFERS.get(job_id)
    if buffer is not None:
        await buffer.add(seq, event_type, stamped, ts)
    await redis_conn.publish(f"analysis:{job_id}", message)
    # Persist into the bounded Stream so the live page can replay missed
    # events when it mounts after the worker already started publishing.
    try:
        await redis_conn.xadd(
            f"analysis:{job_id}:events",
            {"payload": message},
            maxlen=1000,
            approximate=True,
        )
        # 24h TTL — every read keeps the key fresh; idle keys vanish.
        await redis_conn.expire(f"analysis:{job_id}:events", 86_400)
    except Exception as exc:  # noqa: BLE001
        logger.debug(
            "Event stream xadd failed (%s); pubsub-only.",
            exc,
            extra={"job_id": job_id, "component": "pubsub"},
        )
    logger.debug(
        f"Published event: type={event_type} job={job_id[:8]}...",
        extra={"job_id": job_id, "component": "pubsub"},
    )


def _parse_event_ts(value: Any) -> datetime | None:
    """Best-effort ISO-8601 → ``datetime`` for a recorded event timestamp.

    The recorder stamps ``datetime.now(UTC).isoformat()``, so this normally
    round-trips exactly. It returns ``None`` rather than raising on anything
    unexpected: the transcript's ordering comes from ``seq``, and a message with
    no readable clock is still worth keeping.
    """
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _returned_at(entry: dict[str, Any]) -> datetime | None:
    """The moment this tool call came back, or ``None`` when it is not known.

    ``started_at`` is a Unix timestamp the recorder stamped when the call went
    out, and ``duration_ms`` is what it measured; their sum is the only moment
    in the entry a reader can sort a ledger by. Absent, zero or nonsensical
    values give ``None``, because a 1970 timestamp on a tool call is not a fact
    about anything and the column's own default at least says "written then".
    """
    started = entry.get("started_at")
    try:
        seconds = float(started)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    try:
        duration = max(0.0, float(entry.get("duration_ms", 0) or 0) / 1000.0)
        return datetime.fromtimestamp(seconds + duration, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _evidence_row(entry: dict[str, Any], *, job_id: uuid.UUID) -> Any:
    """One ledger entry as the row that keeps it.

    Every field ``maljan.schemas.evidence.LedgerEntry`` carries has a column
    here, which is what lets a reader of the stored ledger say why an output
    is empty instead of guessing. An absent value stays absent rather than
    becoming a default, for the same reason.
    """
    from app.models.evidence import EvidenceEntry

    return EvidenceEntry(
        # When the call returned, which is what a reader of a ledger wants and
        # what the column could not say: the rows are written in one batch at
        # the end of the run, so every one of them carried the flush time — one
        # measured run's thirty entries had one distinct ``created_at`` between
        # them. The entry knows: ``started_at`` is the call's own clock and
        # ``duration_ms`` is how long it took. A row whose entry was never
        # stamped leaves the column to its server default rather than inventing
        # a moment.
        created_at=_returned_at(entry),
        job_id=job_id,
        entry_id=str(entry.get("id", ""))[:32],
        stage=str(entry.get("stage", "analysis"))[:32],
        agent=str(entry.get("agent", ""))[:100],
        server=(str(entry["server"])[:100] if entry.get("server") else None),
        tool=str(entry.get("tool", ""))[:200],
        ok=bool(entry.get("ok", True)),
        error=(str(entry["error"]) if entry.get("error") else None),
        remediation=(str(entry["remediation"]) if entry.get("remediation") else None),
        duration_ms=int(entry.get("duration_ms", 0) or 0),
        seq=int(entry.get("seq", 0) or 0),
        args=entry.get("args") or {},
        args_repaired=bool(entry.get("args_repaired", False)),
        args_raw=(str(entry["args_raw"]) if entry.get("args_raw") else None),
        model=(str(entry["model"])[:300] if entry.get("model") else None),
        output=str(entry.get("output", "") or ""),
        structured=entry.get("structured"),
        # Why the output is empty, what the call was answered from, what it
        # was aimed at, and when it ran. ``LedgerEntry.started_at`` defaults to
        # 0.0 rather than to None, so an entry the recorder never stamped and
        # one that started at the epoch are one value; it is stored as NULL,
        # because 0.0 there means "not recorded" and a 1970 timestamp on a tool
        # call is not a fact about anything.
        truncated=bool(entry.get("truncated", False)),
        repeated_of=(str(entry["repeated_of"])[:32] if entry.get("repeated_of") else None),
        symbol=(str(entry["symbol"])[:200] if entry.get("symbol") else None),
        started_at=(float(entry["started_at"]) if entry.get("started_at") else None),
    )


def _transcript_row(message: dict[str, Any], *, report_id: uuid.UUID, seq: int) -> Any:
    """One broadcast line as the row that keeps it.

    Field for field from the payload ``maljan.pipeline.events.emit_agent_message``
    built, which is the property ``AgentMessage`` is documented on: a replay
    that has to re-derive a field the publisher already sent is a replay that
    can get it wrong. A field the payload did not carry is stored as NULL, so
    a reader can tell "not recorded" from a recorded value.
    """
    from app.models.report import AgentMessage

    return AgentMessage(
        report_id=report_id,
        # The number the publisher gave this message when it went out, so the
        # stored row and the live event a console still holds are one message
        # rather than two.
        seq=seq,
        speaker=str(message.get("speaker", "unknown"))[:100],
        role=str(message.get("role", "system"))[:20],
        round=int(message.get("round", 0) or 0),
        status=str(message.get("status", "complete"))[:20],
        text=str(message.get("text", "") or ""),
        report=message.get("report"),
        report_truncated=bool(message.get("report_truncated", False)),
        confidence=message.get("confidence"),
        claims=message.get("claims") or [],
        dissent=message.get("dissent") or [],
        addressed_to=(str(message["addressed_to"])[:100] if message.get("addressed_to") else None),
        kind=(str(message["kind"])[:32] if message.get("kind") else None),
        stage=(str(message["stage"])[:64] if message.get("stage") else None),
        display_name=(str(message["display_name"])[:200] if message.get("display_name") else None),
        ts=_parse_event_ts(message.get("ts")),
    )


def _make_event_sink(
    redis_conn: aioredis.Redis,
    job_id: str,
    loop: asyncio.AbstractEventLoop,
    recorder: list[dict[str, Any]] | None = None,
) -> Callable[[str, dict[str, Any]], None]:
    """Bridge the pipeline's synchronous event sink onto this event loop.

    ``maljan.pipeline.events.EventSink`` is a plain sync callable because the
    analyst node is synchronous and LangGraph runs it in a worker thread, while
    the negotiation / revision / judge nodes are coroutines on the loop. One
    signature has to serve both, so the bridge is here rather than in the core.

    ``call_soon_threadsafe`` is correct from either side — it is the documented
    way in from another thread, and a no-op-ish fast path when already on the
    loop. Scheduling rather than awaiting also means a slow Redis never adds
    latency to the analysis itself: the pipeline hands the event off and moves
    on. Publishing is best-effort by design (see ``_publish_event``), so a
    dropped progress line never costs a run.

    When ``recorder`` is supplied, every ``agent_message`` is also appended to it
    **synchronously**, before the publish is scheduled. That list becomes the
    persisted transcript (``agent_messages``), and doing it here rather than
    reconstructing the conversation from pipeline state afterwards is what makes
    the replayed transcript the same recording the live viewer saw rather than a
    second, subtly different account of it. Appending on the calling thread also
    means a Redis outage cannot cost us the record: publishing is best-effort,
    persistence is not.

    The copy is scrubbed as it is taken, for that same reason: the publish that
    scrubs what goes on the wire is fire-and-forget, and on the two paths the
    recorder is here for — a loop that has already closed, and a run whose last
    messages are still queued when the transcript is written — it never runs.
    A record that is more revealing than the feed it is a record of would be
    one conversation told two ways.
    """

    # Deferred like every other ``maljan`` import in this module — the core
    # package is heavy and the API process must not pay for it at import time.
    from maljan.pipeline.events import AGENT_MESSAGE

    def sink(event_type: str, data: dict[str, Any]) -> None:
        recorded: dict[str, Any] | None = None
        if recorder is not None and event_type == AGENT_MESSAGE:
            try:
                recorded = {**scrubbed(data), "ts": datetime.now(UTC).isoformat()}
                recorder.append(recorded)
            except Exception as exc:  # noqa: BLE001 — recording must not fail a run
                recorded = None
                logger.debug("transcript recorder rejected an event (%s); continuing.", exc)
        try:
            loop.call_soon_threadsafe(
                lambda: asyncio.ensure_future(  # noqa: RUF006 — fire-and-forget by design
                    _publish_event(redis_conn, job_id, event_type, data, stamp=recorded)
                )
            )
        except RuntimeError:
            # Loop already closed (job cancelled / shutting down). Nothing to
            # report to, and the pipeline must not care.
            pass

    return sink


# How long the heartbeat waits between reads of this job's cancel flag. It is
# also how long the log goes quiet between "still running" lines, so it is a
# name rather than a literal: a test that has to see one poll happen does not
# have to wait a quarter of a minute for it.
CANCEL_POLL_SECONDS = 15.0

# How long a pipeline that has been told to stop is waited for before the job
# goes on without it, and how long the process waits at exit for threads still
# blocked in a call nothing can cancel — a synchronous model call in flight on a
# thread — before it leaves them. The grace a cancellation is given to be
# delivered anywhere else (``base_agent.CANCEL_DELIVERY_GRACE``). SIGTERM ends
# the worker within these two, the job's teardown (``WORKER_TEARDOWN_TIMEOUT``)
# and the closing of its two connections, each held to the same grace:
# 10 s + 60 s + 2 × 10 s + 10 s as shipped.
PIPELINE_STOP_GRACE = CANCEL_DELIVERY_GRACE
EXIT_GRACE = CANCEL_DELIVERY_GRACE


async def await_the_pipeline(task: asyncio.Task[Any], cancellation: Cancellation) -> Any:
    """The pipeline task's result, and a stop that reaches all of it when this job is cancelled.

    The job's own task being cancelled — the worker shutting down on SIGTERM,
    or arq's job timeout — used to reach the pipeline only as a cancellation of
    the task it awaited, and a pipeline that turned the cancellation into an
    ordinary error ran on: the worker ignored SIGTERM for three minutes, and
    arq's shutdown waited on it. Now the job's cancellation is set first, which
    stops every model call the job has in flight and every one it would make
    next, the pipeline task is cancelled, and it is waited for at most
    ``PIPELINE_STOP_GRACE`` before the cancellation carries on.
    """
    try:
        await asyncio.wait({task})
    except asyncio.CancelledError:
        cancellation.cancel("the worker is shutting down")
        task.cancel()
        await asyncio.wait({task}, timeout=PIPELINE_STOP_GRACE)
        raise
    return task.result()


# Whether this process has asked to be left by blocked threads at exit.
_EXIT_GUARD_ARMED = False


def blocked_threads() -> list[str]:
    """The non-daemon threads still alive besides the main thread and the caller."""
    here = threading.current_thread()
    return sorted(
        thread.name
        for thread in threading.enumerate()
        if thread.is_alive()
        and not thread.daemon
        and thread is not threading.main_thread()
        and thread is not here
    )


def _leave_blocked_threads_after(grace: float) -> None:
    """From the interpreter's own exit: end the process after ``grace`` if a thread still holds it.

    Runs when the interpreter begins shutting down, before it joins the
    threads that are still alive — the one point at which the process is
    certainly leaving. It starts a daemon thread and returns, so the joins go
    ahead; a process whose threads all end within the grace exits on its own
    and the daemon dies with it. What can hold it is a thread blocked in a call
    that cannot be cancelled — a synchronous model request in flight — which
    ends only at its provider's request timeout. Such threads are left, the
    names logged, and the process ends with status 1 so a supervisor sees
    that it did not end cleanly. Nothing is left when nothing is blocked.
    """

    def _leave() -> None:
        time.sleep(grace)
        held = blocked_threads()
        if not held:
            return
        logger.warning(
            "Worker exit held %.0fs by %d thread(s) blocked in calls that cannot be "
            "cancelled (%s); leaving them.",
            grace,
            len(held),
            ", ".join(held),
            extra={"component": "worker.lifecycle"},
        )
        os._exit(1)

    threading.Thread(target=_leave, name="worker-exit-guard", daemon=True).start()


def arm_the_exit_guard(grace: float | None = None) -> None:
    """Have the process's own exit leave threads still blocked after ``grace``. Once per process.

    Registered on the hook the interpreter runs as it starts to shut down,
    before it joins non-daemon threads (the one ``concurrent.futures`` uses to
    join its executors, which is what a blocked model call holds). Arming does
    nothing to the running process: a caller of ``shutdown`` that goes on
    running — a test — is untouched, and at its own exit the guard acts only
    if a thread is still blocked.
    """
    global _EXIT_GUARD_ARMED
    if _EXIT_GUARD_ARMED:
        return
    wait = EXIT_GRACE if grace is None else float(grace)
    register = getattr(threading, "_register_atexit", None)
    if register is None:
        logger.warning(
            "Worker exit guard not armed: this interpreter has no threading._register_atexit, "
            "so a thread blocked in a call that cannot be cancelled can hold the exit open.",
            extra={"component": "worker.lifecycle"},
        )
        return
    try:
        register(lambda: _leave_blocked_threads_after(wait))
    except RuntimeError as exc:
        logger.warning(
            "Worker exit guard not armed (%s): the interpreter is already shutting down.",
            exc,
            extra={"component": "worker.lifecycle"},
        )
        return
    _EXIT_GUARD_ARMED = True


# ── Job ownership ───────────────────────────────────────────────


# The key a worker holds while it is running a job, and how long it lives.
#
# Ownership has to be a statement by the process that is doing the work, about
# the job it is doing. arq's own keys cannot say that: the in-progress claim is
# written once and lives for the job timeout, so it outlives the process that
# made it by hours, and the health key is queue-wide and lives thirty-one
# seconds past its last write, so a worker that was killed a moment ago still
# looks alive — which is exactly the case the sweep exists for.
#
# A heartbeat under the job's own id says both things at once: it exists only
# while a worker is alive *and* still on that job, and it names which worker,
# so a second worker's job is never mistaken for an abandoned one. The value is
# for the log; the sweep reads only whether the key is there.
JOB_OWNER_KEY_PREFIX = "maljan:job-owner:"
JOB_OWNER_TTL_SECONDS = 90
JOB_OWNER_REFRESH_SECONDS = 30
# How long the release in the job's ``finally`` may wait on Redis. The worker
# takes no new job until that block returns, so an unbounded delete against a
# Redis that has stopped answering would hold the whole queue for a finished
# job. The key expires by itself either way.
JOB_OWNER_RELEASE_TIMEOUT = 5.0

# This process, as the heartbeat names it.
WORKER_ID = f"{platform.node()}:{os.getpid()}"


def canonical_job_id(job_id: str) -> str:
    """One spelling of a job id, whatever spelling arrived.

    A claim comes in as arq passed it and the sweep spells the same job from
    its database row, and ``uuid.UUID`` accepts the uppercase, brace-wrapped
    and unhyphenated forms of one id. Two spellings would mean a key written
    under one and looked for under the other — a live job with no heartbeat as
    far as the sweep can tell. Anything that does not parse is left as it is:
    this is a spelling, never a gate.
    """
    try:
        return str(uuid.UUID(job_id))
    except (ValueError, AttributeError, TypeError):
        return job_id


def job_owner_key(job_id: str) -> str:
    """Where this job's owner writes that it is still running it."""
    return f"{JOB_OWNER_KEY_PREFIX}{canonical_job_id(job_id)}"


# The jobs this process is running right now, under the one spelling. The sweep
# skips them whatever Redis says: a heartbeat that could not be written is a
# Redis problem, and a worker that failed its own live job over one would be a
# worse one.
_OWNED_JOBS: set[str] = set()


async def claim_job(redis_conn: Any, job_id: str) -> bool:
    """Say this worker is running this job, for the next TTL. Never raises."""
    canonical = canonical_job_id(job_id)
    _OWNED_JOBS.add(canonical)
    try:
        await redis_conn.set(job_owner_key(canonical), WORKER_ID, ex=JOB_OWNER_TTL_SECONDS)
    except Exception as exc:  # noqa: BLE001 — a heartbeat never costs a run
        logger.warning(
            "Could not write the owner heartbeat for job %s (%s); the sweep skips "
            "the jobs this process is running, so the run is unaffected.",
            canonical,
            type(exc).__name__,
            extra={"job_id": canonical, "component": "worker.lifecycle"},
        )
        return False
    return True


async def release_job(redis_conn: Any, job_id: str) -> None:
    """Stop claiming this job, on every way out of it. Never raises.

    Bounded, because this runs in the task's ``finally`` and the worker takes
    no new job until that returns: a Redis that has stopped answering would
    otherwise hold a finished job open, and the queue behind it. The key
    expires on its own within the TTL, so the worst a skipped delete costs is
    that long before the sweep would consider the job unowned — and the sweep
    skips the jobs this process is running anyway.
    """
    canonical = canonical_job_id(job_id)
    _OWNED_JOBS.discard(canonical)
    try:
        await asyncio.wait_for(
            redis_conn.delete(job_owner_key(canonical)), timeout=JOB_OWNER_RELEASE_TIMEOUT
        )
    except (Exception, TimeoutError) as exc:  # noqa: BLE001 — the key expires on its own
        logger.debug(
            "Could not drop the owner heartbeat for job %s (%s); it expires in %ds.",
            canonical,
            type(exc).__name__,
            JOB_OWNER_TTL_SECONDS,
            extra={"job_id": canonical},
        )


def remove_job_staging(job_id: str) -> list[Path]:
    """Take away what this job's sidecars staged and carved. Never raises.

    Staging is one directory per job, named by the same rule on both sides
    (``maljan.tools.staging``), so this removes exactly what this process
    pointed its sidecars at and nothing a concurrent job owns. Removal never
    follows a symlink: the tree holds live malware, and a link planted in it is
    the one way a cleanup becomes a delete somewhere else.

    A directory that cannot be removed is said once and left to the sidecar's
    own TTL sweep, which prunes a job directory whole by the newest mtime
    inside it. The cached upload paths go with it, because a path into a
    directory that is gone is not a cache, it is an error every tool call after
    it would answer with.
    """
    from maljan.agents import sample_staging
    from maljan.tools import staging

    wanted = staging.job_directories(job_id)
    sample_staging.forget_job(job_id)
    try:
        removed = staging.remove_job_staging(job_id)
    except Exception as exc:  # noqa: BLE001 — a cleanup never fails a finished job
        logger.warning(
            "Could not remove the staging directory of job %s (%s); the sidecar's TTL "
            "sweep prunes it.",
            job_id,
            type(exc).__name__,
            extra={"job_id": job_id, "component": "worker.lifecycle"},
        )
        return []
    left = [path for path in wanted if path not in removed]
    if left:
        logger.warning(
            "The staging directory of job %s was not fully removed (%s); the sidecar's "
            "TTL sweep prunes it.",
            job_id,
            ", ".join(str(path) for path in left),
            extra={"job_id": job_id, "component": "worker.lifecycle"},
        )
    for path in removed:
        logger.debug("Removed the staging directory %s", path, extra={"job_id": job_id})
    return removed


async def hold_job_owner(redis_conn: Any, job_id: str) -> None:
    """Refresh this job's claim until the task running this is cancelled.

    Two refreshes inside one TTL, so a missed write — a Redis blip, a loop that
    was busy — does not expire the claim on its own.

    The job's staging directory is touched beside the claim, and for the same
    reason said differently: a sidecar sweeping the shared base has no way to
    ask whether a job is alive, so a long run that stages nothing new says so
    on disk (``staging.touch_job_staging``) rather than losing its directory to
    another worker's TTL.
    """
    from maljan.tools import staging

    while True:
        await asyncio.sleep(JOB_OWNER_REFRESH_SECONDS)
        await claim_job(redis_conn, job_id)
        staging.touch_job_staging(job_id)


async def live_owners(redis_conn: Any, job_ids: list[str]) -> set[str] | None:
    """Which of these jobs a worker is currently saying it owns.

    ``None`` when Redis cannot answer, which is not the same as "nobody owns
    them" and is treated differently by the caller.
    """
    if not job_ids:
        return set()
    global _QUEUE_UNREADABLE_SAID
    try:
        held = await redis_conn.mget([job_owner_key(job_id) for job_id in job_ids])
    except Exception as exc:  # noqa: BLE001 — an unreadable queue is not a verdict
        _log_unreadable_queue(type(exc).__name__)
        return None
    # Readable again, so the next outage is worth saying out loud as well.
    _QUEUE_UNREADABLE_SAID = False
    return {job_id for job_id, value in zip(job_ids, held, strict=False) if value is not None}


# Whether the "Redis cannot be read" line has been logged since the last time
# it could be. The sweep runs every few minutes for the life of the worker, and
# an outage that logged on every pass would bury everything else.
_QUEUE_UNREADABLE_SAID = False


def _log_unreadable_queue(reason: str) -> None:
    global _QUEUE_UNREADABLE_SAID
    if _QUEUE_UNREADABLE_SAID:
        logger.debug("Orphan sweep: the queue is still unreadable (%s).", reason)
        return
    _QUEUE_UNREADABLE_SAID = True
    logger.warning(
        "Orphan sweep: the queue could not be read (%s); no job row is touched "
        "until it can be, because ownership cannot be established without it.",
        reason,
        extra={"component": "worker.lifecycle"},
    )


# ── Job outcome ─────────────────────────────────────────────────


def failure_reason(exc: BaseException, error_id: str) -> str:
    """What a failed job says about itself, on the API and in the console.

    The class of the exception and the id that reaches the log entry holding
    everything else. ``job.error_message`` is a field of ``JobResponse``, so
    the message of an exception put there is published: a file the worker
    could not open names a host path, and a driver names the connection string
    it was configured with. The same rule the event feed already follows —
    a failed node travels as the class of its exception, never its message.

    ``StatedFailure`` is the exception this module raises with a sentence it
    wrote itself — the absent analysis, an attached report that belongs to
    another sample, a sandbox provider that cannot take one — so that sentence
    is what the job says, and it is the reason the class exists. One that was
    built from something else after all is marked unpublishable when it is
    made: its sentence goes to the log under this error id and the job says the
    class name, which is what every other exception says.
    """
    if isinstance(exc, StatedFailure):
        if getattr(exc, "publishable", False):
            return f"{exc} (error id {error_id})"
        logger.error(
            "A stated failure carried something unpublishable; the job says its "
            "class instead. error_id=%s message=%s",
            error_id,
            exc,
            extra={"error_id": error_id},
        )
    return f"{type(exc).__name__} (error id {error_id})"


def cancel_flag_key(job_id: str) -> str:
    """Where a cancel request for this job is written.

    ``AnalysisService.cancel_job`` sets it and the heartbeat polls it. It is
    also how a ``CancelledError`` is told apart: an operator's cancel leaves
    this key behind, a worker shutting down or arq's own job timeout does not.
    """
    return f"analysis:{canonical_job_id(job_id)}:cancel"


async def cancel_was_requested(redis_conn: Any, job_id: str) -> bool:
    """Whether somebody asked for this job to stop. Never raises.

    Read when the task is already being cancelled, so a Redis that cannot
    answer means "not a cancel request": the run is going down either way, and
    the sweep repairs a row nobody claimed rather than this guessing at one.
    """
    try:
        return bool(
            await asyncio.wait_for(
                redis_conn.get(cancel_flag_key(job_id)), timeout=JOB_OWNER_RELEASE_TIMEOUT
            )
        )
    except (Exception, TimeoutError) as exc:  # noqa: BLE001 — a cancelled run is going down
        logger.debug(
            "Could not read the cancel flag for job %s (%s); treating this as a shutdown.",
            job_id,
            type(exc).__name__,
            extra={"job_id": job_id},
        )
        return False


async def mark_job_cancelled(db_session: async_sessionmaker, job_uuid: uuid.UUID) -> bool:
    """Record the operator's cancellation on a session of its own. Never raises.

    The same rule the failure marker follows, for the same reason: the session
    the run was writing through is the one a lost connection leaves unusable,
    and a cancelled job whose row still says ``running`` is the phantom this
    work exists to remove. Only a job that was still running is touched — a run
    that finished while the cancel was in flight keeps its result.
    """
    from app.models.job import AnalysisJob

    try:
        async with db_session() as db:
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_uuid, AnalysisJob.status.in_(("pending", "running")))
                .values(status="cancelled", completed_at=datetime.now(UTC))
            )
            await db.commit()
        return True
    except Exception as exc:  # noqa: BLE001 — the run is already stopping
        logger.error(
            "Could not mark job %s cancelled (%s); the orphan sweep repairs the row.",
            job_uuid,
            type(exc).__name__,
            extra={"job_id": str(job_uuid)},
        )
        return False


async def mark_job_failed(
    db_session: async_sessionmaker,
    job_uuid: uuid.UUID,
    *,
    reason: str,
    error_id: str,
) -> bool:
    """Record a failure on a session of its own. Never raises.

    Opens a new session rather than reusing whichever one the job was writing
    through, because the session that was writing is the one most likely to be
    unusable: once a backend has been terminated under it, every statement on
    it raises ``PendingRollbackError`` and the failure cannot be recorded at
    all. A new session takes a new connection from the pool, so the row is
    written even when the job's own connection is gone.

    A ``cancelled`` row is left alone: the operator's decision outranks
    whatever the run raised on its way down.
    """
    from app.models.job import AnalysisJob

    try:
        async with db_session() as db:
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_uuid, AnalysisJob.status != "cancelled")
                .values(
                    status="failed",
                    error_message=reason[:2000],
                    completed_at=datetime.now(UTC),
                )
            )
            await db.commit()
        return True
    except Exception as exc:  # noqa: BLE001 — the run has already failed
        logger.error(
            "Could not mark job %s failed (%s); error_id=%s. The startup sweep "
            "repairs the row when this worker next boots.",
            job_uuid,
            type(exc).__name__,
            error_id,
            extra={"job_id": str(job_uuid), "error_id": error_id},
        )
        return False


# How long a worker waits for a job row it was handed but cannot read yet, as
# the pauses between reads. The API commits the row before it enqueues, so the
# first read finds it; these cover a row whose commit is still reaching the
# database when the worker dequeues it. About fifteen seconds in all, after
# which the job is given up with a record of how long was waited.
JOB_ROW_READ_PAUSES: tuple[float, ...] = (0.5, 1.0, 2.0, 4.0, 8.0)

# What a job the worker could not read says about itself, if its row arrives
# after the worker gave up on it: it can never start, because the one queued
# run for it has ended.
_JOB_ROW_NEVER_READ = (
    "The worker was handed this job before its row could be read, waited {waited:.1f} s "
    "over {reads} reads, and gave up; the queued run for it has ended, so it was "
    "marked failed rather than left pending. Re-submit the sample."
)


async def wait_for_job_row(
    db_session: async_sessionmaker,
    job_uuid: uuid.UUID,
    *,
    pauses: Iterable[float] | None = None,
    sleep: Callable[[float], Any] = asyncio.sleep,
) -> tuple[bool, int, float]:
    """Read again after each pause until the job's row exists or the pauses run out.

    Called after a first read found nothing. Returns whether the row was found,
    how many reads this made and how many seconds were spent pausing. Each read
    is its own short session, so every read sees whatever has been committed by
    then.
    """
    from app.models.job import AnalysisJob

    reads = 0
    waited = 0.0
    for pause in JOB_ROW_READ_PAUSES if pauses is None else pauses:
        if pause:
            await sleep(pause)
            waited += pause
        reads += 1
        async with db_session() as db:
            found = (
                await db.execute(select(AnalysisJob.id).where(AnalysisJob.id == job_uuid))
            ).scalar_one_or_none()
            await db.commit()
        if found is not None:
            return True, reads, waited
    return False, reads, waited


async def fail_unread_job(
    db_session: async_sessionmaker, job_uuid: uuid.UUID, reads: int, waited: float
) -> bool:
    """Mark a job the worker gave up on as failed, if its row has since arrived.

    Only a ``pending`` row is touched: a row a cancel reached first keeps its
    own ending. Returns whether a row was marked. Never raises.
    """
    from app.models.job import AnalysisJob

    try:
        async with db_session() as db:
            result = await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_uuid, AnalysisJob.status == "pending")
                .values(
                    status="failed",
                    completed_at=func.now(),
                    error_message=_JOB_ROW_NEVER_READ.format(waited=waited, reads=reads),
                )
                .returning(AnalysisJob.id)
            )
            marked = result.first() is not None
            await db.commit()
    except Exception as exc:  # noqa: BLE001 — the give-up is already logged
        logger.warning(
            "Could not mark unread job %s failed (%s).",
            job_uuid,
            type(exc).__name__,
            extra={"job_id": str(job_uuid)},
        )
        return False
    return marked


# ── Main analysis task ──────────────────────────────────────────


async def run_analysis(ctx: dict, job_id: str) -> dict[str, Any]:
    """Execute the full Maljan analysis pipeline for the given job.

    This function:
    1. Loads the job from the database.
    2. Transitions status to 'running'.
    3. Instantiates MaljanApp and runs the pipeline.
    4. Saves the result as an AnalysisReport.
    5. Publishes progress events via Redis PubSub.

    Args:
        ctx: ARQ worker context (contains redis connection).
        job_id: UUID string of the AnalysisJob to process.

    Returns:
        Summary dict with verdict and timing info.
    """
    logger.info(f"Analysis task started: job={job_id}", extra={"job_id": job_id})

    redis_conn: aioredis.Redis = ctx["redis"]
    db_session: async_sessionmaker = ctx["db_session"]

    job_uuid: uuid.UUID | None = None  # set once the id parses; read by the failure path
    app: Any = None  # released in the finally below, whichever way we leave
    # Declared here (rather than at the download site further down) so the
    # outer ``finally`` can always remove them, including on every early
    # return above the download (invalid job id, job not found, already
    # cancelled) — those paths never reach the download but still run
    # this function's one ``finally``, which references both names.
    temp_path: str | None = None
    # One entry per provider actually mirrored (a profile with two
    # static analysts on two providers mirrors twice); the ``finally``
    # below removes every one of them, symmetric with today's single-path
    # cleanup.
    host_mirrors: list[Path] = []
    # L2 (live-run finding): set below when an attached sandbox report's
    # own claimed hash disagreed with the sample at upload time, so the
    # degradation makes it into both run_summary and the report banner
    # even though nothing in the pipeline itself reads the stored flag.
    _report_hash_mismatch_reason: str | None = None
    # The task that keeps this job's owner heartbeat alive, cancelled by the
    # ``finally`` below so it cannot outlive the run it speaks for.
    owner_task: asyncio.Task | None = None
    # Registered here rather than above the session: this is the statement
    # before the ``try`` whose ``finally`` unregisters it, so there is no
    # window in which a raise leaves a buffer in the module-global map for
    # the life of the process. Still before the run's first event — the
    # status change below — because a feed that starts late starts at the
    # wrong ``seq``.
    _start_event_feed(job_id, db_session)
    try:
        # ── 1. Load job ──────────────────────────────────────
        from app.models.job import AnalysisJob
        from app.models.sample import Sample

        try:
            job_uuid = uuid.UUID(job_id)
        except ValueError as exc:
            logger.error(f"Invalid job_id UUID: {job_id}", extra={"job_id": job_id})
            await _publish_event(redis_conn, job_id, "error", {"message": "Invalid job ID"})
            return {"status": "error", "message": f"Invalid job ID: {exc}"}

        # Before the row is touched, so there is no moment in which a job says
        # ``running`` and no worker says it is running it. Refreshed by a task
        # of its own for as long as the run lasts, and dropped by the
        # ``finally`` below on success, failure and cancellation alike. Under
        # the id as it parsed, which is the spelling the sweep reads back out
        # of the database.
        await claim_job(redis_conn, str(job_uuid))
        owner_task = asyncio.create_task(hold_job_owner(redis_conn, str(job_uuid)))

        # Everything this run needs out of the database before the models
        # start, in one short session that is closed again before the
        # pipeline is built: the job row, its sample, the stored settings
        # and any attached sandbox report, plus the move to ``running``.
        #
        # The session used to stay open for the whole analysis. That left a
        # backend ``idle in transaction`` for as long as the run took —
        # thirteen minutes and more — holding an ``AccessShareLock`` on
        # ``analysis_jobs``, ``analysis_reports`` and ``runtime_settings``
        # and pinning a snapshot. A migration's ``ALTER TABLE
        # analysis_reports`` queued behind it and every read of that table
        # queued behind the ALTER, so a running analysis could stall the
        # API's own job reads. It also made the run fragile: one lost
        # connection invalidated the transaction the whole job wrote
        # through.
        async with db_session() as db:
            result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_uuid))
            job = result.scalar_one_or_none()

            if not job:
                # A row not there yet is waited for, a bounded while, before
                # the job is given up: the queue can hand a job over before
                # the commit that made its row is visible to this session.
                # This session's read is ended first, so it is not left idle
                # in a transaction for the length of the wait.
                await db.commit()
                found, reads, waited = await wait_for_job_row(db_session, job_uuid)
                if found:
                    result = await db.execute(select(AnalysisJob).where(AnalysisJob.id == job_uuid))
                    job = result.scalar_one_or_none()
                if not job:
                    marked = await fail_unread_job(db_session, job_uuid, reads, waited)
                    logger.error(
                        "Job not found in database after %d reads over %.1f s: %s%s",
                        reads + 1,
                        waited,
                        job_id,
                        "; its row arrived after the last read and was marked failed"
                        if marked
                        else "",
                        extra={"job_id": job_id},
                    )
                    await _publish_event(redis_conn, job_id, "error", {"message": "Job not found"})
                    return {"status": "error", "message": "Job not found"}

            if job.status == "cancelled":
                logger.info(f"Job already cancelled: {job_id}", extra={"job_id": job_id})
                await _publish_event(redis_conn, job_id, "cancelled", {})
                return {"status": "cancelled"}

            if job.status in ("failed", "completed"):
                # Already ended: an enqueue that raised after the queue took the
                # job commits the row failed and tells the caller so, and
                # running it anyway would run a job the caller was told was
                # refused.
                logger.info(
                    "Job %s already ended (%s); not run.",
                    job_id,
                    job.status,
                    extra={"job_id": job_id},
                )
                return {"status": "skipped", "message": f"job already {job.status}"}

            # Read out as plain values rather than carried as ORM objects:
            # the session ends here and an attribute that had to be
            # refreshed afterwards would open a transaction of its own,
            # somewhere in the middle of the run, on whichever session
            # happened to be at hand.
            job_config: dict[str, Any] = dict(job.config or {})

            # Load associated sample
            sample_result = await db.execute(select(Sample).where(Sample.id == job.sample_id))
            sample = sample_result.scalar_one()
            sample_uuid = sample.id
            sample_sha256 = str(sample.sha256)
            sample_filename = str(sample.original_filename or "")
            sample_storage_path = str(sample.storage_path or "")

            logger.info(
                "Processing sample: sha256=%s... filename=%s",
                sample_sha256[:16],
                sample_filename,
                extra={"job_id": job_id, "sample_id": str(sample_uuid)},
            )

            # ── 2. Transition to running ─────────────────────────
            # Use Postgres ``NOW()`` for the persisted ``started_at`` so
            # it shares a clock source with ``TimestampMixin.created_at``
            # (which is also ``server_default=func.now()``). Mixing host
            # time ``datetime.now(UTC)`` here produced ``started_at <
            # created_at`` on Windows hosts where Docker Desktop's VM
            # clock drifts after sleep/hibernate.
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_uuid)
                .values(status="running", started_at=func.now())
            )
            await db.commit()

            # Build this job's Settings from any stored UI overrides plus
            # model defaults (UI > default; see settings_overrides.
            # build_settings -- the environment is not a layer here), then
            # the job's own config on top. A DB error loading overrides must
            # not fail the job -- fall back to default-only settings and say
            # so, without ever logging a secret value.
            from app.services.settings_service import load_core_overrides

            try:
                overrides = await load_core_overrides(db)
            except Exception as exc:  # noqa: BLE001 — overrides are best-effort
                logger.warning(
                    "Failed to load runtime setting overrides (%s); "
                    "running job %s on default settings only.",
                    type(exc).__name__,
                    job_id,
                    extra={"job_id": job_id},
                )
                overrides = {}

            # A job that names an attached report is read here too, for the
            # same reason: the row is wanted before the pipeline starts and
            # the ownership question belongs to the read. The bytes are
            # fetched later, once the container's sandbox provider is
            # known. The ownership is part of the query
            # (``attached_report_stmt``), so a report attached to somebody
            # else's sample is never read at all -- guessing a UUID returns
            # nothing rather than a row this then refuses.
            attached_report: Any = None
            _attached_report_id = job_config.get("sandbox_report_id")
            if _attached_report_id:
                attached_report = (
                    await db.execute(
                        attached_report_stmt(uuid.UUID(str(_attached_report_id)), sample_uuid)
                    )
                ).scalar_one_or_none()
                if attached_report is None:
                    raise StatedFailure(
                        "The attached sandbox report does not belong to this sample."
                    )
                _attached_storage_path = str(attached_report.storage_path)
                _attached_row_id = attached_report.id
                _attached_hash_matches = attached_report.sample_sha256_match

            # The reads above opened a transaction of their own after the
            # commit. Ending it here is what makes the session's whole life
            # the length of this block rather than the length of the run.
            await db.commit()

        await _publish_event(redis_conn, job_id, "status_change", {"status": "running"})
        logger.info(f"Job status -> running: {job_id}", extra={"job_id": job_id})

        # ── 3. Run the pipeline ──────────────────────────────
        start_time = time.time()

        from maljan.app import MaljanApp

        logger.info(
            "Starting pipeline execution...",
            extra={"job_id": job_id, "component": "pipeline"},
        )

        from maljan.core.config import install_settings

        try:
            core_settings = build_job_settings(overrides, job_config)
        except (ValidationError, ValueError) as exc:
            # Stored overrides that validated when saved can stop validating
            # after a deploy narrows a field, and two orphan rows can nest
            # into a conflict. One job must not take the queue down: run on
            # default settings, name the fields.
            bad = (
                sorted({".".join(str(x) for x in e["loc"]) for e in exc.errors()})
                if isinstance(exc, ValidationError)
                else [type(exc).__name__]
            )
            logger.warning(
                "Runtime settings rejected by the model (%s); "
                "retrying job %s without the stored overrides.",
                ", ".join(bad),
                job_id,
                extra={"job_id": job_id},
            )
            overrides = {}
            try:
                core_settings = build_job_settings({}, job_config)
            except (ValidationError, ValueError):
                # The rejected value was the job's own config, not a
                # stored override (the API validates it at submit time,
                # but a row written another way still reaches here).
                logger.warning(
                    "Job %s config rejected by the model; running on default settings only.",
                    job_id,
                    extra={"job_id": job_id},
                )
                core_settings = build_job_settings({}, None)
        # Agents, pipeline nodes and extractors read the process singleton
        # (``get_settings()``), not the config handed to MaljanApp. With
        # ``max_jobs = 1`` installing this job's Settings there is what
        # makes a UI override reach every consumer, not only the container.
        # The object stays installed after the job: ``enrich_threat_intel``
        # runs in this process too but reads only API settings and
        # ``runtime_config`` today; if it ever needs core config it must
        # install its own.
        install_settings(core_settings)
        if overrides:
            logger.info(
                "Applying %d runtime setting override(s) from the UI.",
                len(overrides),
                extra={"job_id": job_id},
            )

        # Mock-mode resolution.
        # Two independent toggles must agree before the pipeline runs
        # in mock mode:
        #   1. ``api.mock_mode_allowed`` — operator-level gate
        #      (defaults False; must be flipped via the settings store).
        #   2. Either the per-job ``config.mock_mode`` flag OR the
        #      ``MALJAN_MOCK_MODE`` env var.
        # A leaked env var alone is no longer sufficient — production
        # workers stay on the real LLM/sandbox path even if a stale
        # shell exports ``MALJAN_MOCK_MODE=true``.
        _env_mock = os.environ.get("MALJAN_MOCK_MODE", "false").lower() == "true"
        _job_mock = bool(job_config.get("mock_mode"))
        _mock_requested = _env_mock or _job_mock
        _mock_mode_allowed = await runtime_config.get("mock_mode_allowed")
        _mock_active = bool(_mock_mode_allowed and _mock_requested)
        # Each flag is logged as a word this module chose, not as the value it
        # read. Two of the three come out of the settings store, and a value
        # interpolated straight from there is a settings value in a log line —
        # which is what it looks like to a reader and to a scanner alike,
        # whatever this particular key happens to hold. The reader learns the
        # same thing either way: which of the three switches was on.
        _said_env = "yes" if _env_mock else "no"
        _said_job = "yes" if _job_mock else "no"
        _said_allowed = "yes" if _mock_mode_allowed else "no"
        if _mock_requested and not _mock_active:
            logger.warning(
                "Pipeline mock requested (env=%s, job=%s) but blocked: "
                "api.mock_mode_allowed is off. Running real pipeline.",
                _said_env,
                _said_job,
            )
        logger.info(
            "Pipeline mode: %s (env=%s job=%s allowed=%s).",
            "MOCK" if _mock_active else "REAL",
            _said_env,
            _said_job,
            _said_allowed,
        )
        # The sink is what turns a 30-minute silent run into a readable
        # transcript: each node reports its own findings as it produces
        # them, straight onto the same PubSub channel the Live tab is
        # already attached to. ``transcript`` collects those same messages
        # so they can be written to ``agent_messages`` when the run
        # finishes — the live feed and the permanent record are one list,
        # not two derivations that can drift.
        transcript: list[dict[str, Any]] = []
        from maljan.core import memprobe

        memprobe.reset()
        memprobe.probe("job:start", job_id=job_id)
        app = MaljanApp(
            config=core_settings,
            mock=_mock_active,
            job_id=job_id,
            event_sink=_make_event_sink(
                redis_conn,
                job_id,
                asyncio.get_running_loop(),
                recorder=transcript,
            ),
        )

        # A job that names an attached report hands its bytes to the
        # sandbox provider before anything else runs: build_job_settings
        # already forced sandbox.provider="upload" above, so the provider
        # this container builds is the one that reads what the operator
        # brought instead of detonating anything. The row itself was read
        # and checked in the session above; what is left here needs the
        # container rather than the database.
        if attached_report is not None:
            from app.api.v1.sandbox_reports import get_object

            # L2: the upload endpoint's mismatch warning promises "The
            # analysis will still run and will say so in its findings" —
            # nothing threaded the stored flag into the run until now.
            if _attached_hash_matches is False:
                _report_hash_mismatch_reason = (
                    "uploaded sandbox report's target hash differs from the sample"
                )
                logger.warning(
                    "Attached sandbox report %s claims a target hash that does not "
                    "match sample %s; recording it as a run degradation.",
                    _attached_row_id,
                    sample_sha256[:12],
                    extra={"job_id": job_id},
                )
            sandbox_provider = app.container.get_sandbox_provider()
            # A mock-mode job still resolves sandbox.provider="upload" through
            # build_job_settings, but ServiceContainer.get_sandbox_provider()'s
            # own mock override runs after that and wins, so the object here
            # can be a MockSandboxProvider with no set_pending_blob at all.
            # Checked by capability, not by provider id, the same way every
            # other branch in this layer is: an attribute error escaping to
            # job.error_message would show the user a raw internal exception
            # instead of saying what actually happened. ``StatedFailure``
            # rather than ``ValueError`` for the same reason: this sentence is
            # the answer, and only that class reaches the console whole.
            if not sandbox_provider.capabilities.accepts_uploaded_report:
                raise StatedFailure(
                    "A sandbox report is attached to this job, but the configured "
                    f"sandbox provider ({sandbox_provider.id!r}) cannot accept an "
                    "uploaded report."
                )
            sandbox_provider.set_pending_blob(
                await asyncio.to_thread(get_object, _attached_storage_path),
                filename=f"{_attached_row_id}.json",
            )

        # Announce which analysts are about to run so the frontend can show
        # them. The active profile, not the class registry: a job that runs
        # four analysts must not announce three.
        registered_agents = app.container.analyst_keys()
        await _publish_event(
            redis_conn,
            job_id,
            "pipeline_started",
            {
                "agents": registered_agents,
                "sample_filename": sample_filename,
                "sha256": sample_sha256[:16] + "...",
            },
        )
        # Everyone who can speak in this run and the stages they speak in,
        # once, before anybody does. ``pipeline_started`` names the
        # analysis-stage agents by key; this names every participant of
        # every stage, with the label the operator gave it, so a reader
        # who cannot open the admin settings still sees a name.
        await _publish_event(redis_conn, job_id, "roster", _roster_for(app.container))
        # Roster only — "waiting", not "analyzing". Analysts are serialised
        # on the single-slot local model, so marking them all busy up front
        # was simply false; each analyst node now announces its own start
        # (see maljan.pipeline.nodes), which is the real signal.
        for agent_name in registered_agents:
            await _publish_event(
                redis_conn,
                job_id,
                "agent_progress",
                {"agent": agent_name, "phase": "waiting"},
            )

        # Download sample from MinIO for sandbox submission
        # (temp_path / host_mirrors are declared above, before the early
        # returns, so the outer finally can always find them)
        static_sample_path: str | None = None
        static_sample_paths: dict[str, str] = {}
        try:
            from minio import Minio
            from pydantic import SecretStr as _SecretStr

            secret = settings.minio_secret_key
            secret_value = (
                secret.get_secret_value() if isinstance(secret, _SecretStr) else str(secret)
            )
            minio_client = Minio(
                settings.minio_endpoint,
                access_key=settings.minio_access_key,
                secret_key=secret_value,
                secure=settings.minio_secure,
            )
            # Re-derive the storage path from the sha256 instead of trusting
            # the value in the DB row (defence in depth against tampering).
            derived_path = f"samples/{sample_sha256[:2]}/{sample_sha256}"
            if sample_storage_path != derived_path:
                logger.warning(
                    "Sample storage_path drift detected: db=%s expected=%s",
                    sample_storage_path,
                    derived_path,
                )
            # Preserve the original filename extension so the sandbox
            # backend can pick the right VM profile from the suffix
            # (``.elf`` → Linux, ``.exe`` → Windows, etc.). Otherwise
            # the bare sha256 would be treated as an unknown blob.
            _orig_ext = Path(sample_filename).suffix
            # Use the Defender-excluded upload tmp dir instead of the
            # system temp dir. See ``APISettings.upload_temp_dir``.
            # ``.resolve()`` is critical here — an ELF smoke test
            # produced a relative ``data\uploads\.tmp\<sha>.elf`` path
            # which then broke the sandbox client's submit path with
            # ``[Errno 22] Invalid argument`` when its httpx coroutine
            # opened the path from a different CWD. The fix is to
            # resolve once at use-site so every downstream consumer
            # (sandbox submit, Ghidra container path map, sandbox
            # uploader) receives an absolute path.
            from app.worker import sample_files

            _worker_tmp = sample_files.temp_dir()
            temp_path = str(_worker_tmp / f"{sample_sha256}{_orig_ext}")
            # In a thread: the client is synchronous, and this loop is also
            # carrying the job's heartbeat, its cancellation poller and every
            # event the pipeline publishes. A slow store would stop all three
            # for the length of the download.
            await asyncio.to_thread(
                minio_client.fget_object,
                settings.minio_bucket,
                derived_path,
                temp_path,
            )
            # 0o600 on the file; the parent dir is already 0o700 (owner-
            # only) via ``sample_files.temp_dir()``, so this file is
            # unreachable to anyone but the worker's own user either way.
            os.chmod(temp_path, 0o600)
            logger.info(
                "Downloaded sample from MinIO: %s -> %s",
                sample_storage_path,
                temp_path,
                extra={"job_id": job_id, "component": "minio"},
            )

            # Every sample used to be mirrored into
            # ``<samples_dir>/.work/<sha256><ext>`` for the Ghidra
            # container unconditionally. Provider capabilities turned
            # that into a capability read: a
            # capa/YARA or radare2 provider reads the bytes in place and
            # needs no copy at all, so ``mirror_target_for`` asks the
            # configured static provider first and returns None when it
            # has nothing to mirror. When it does, the container-visible
            # path still mirrors the bind mount in
            # docker/docker-compose.yml (``../data/samples:/data/samples``).
            #
            # The mirror is a private
            # 0o600 copy under a 0o700 ``.work`` subdirectory of
            # ``samples_dir`` — never the operator's own corpus directory
            # itself — and is removed by the ``finally`` below when the
            # job ends, whichever way it ends.
            # The mirror runs once per distinct static provider host path;
            # ``mirror_static_samples`` is the tested unit for that loop,
            # including the dedup that keeps two providers sharing one
            # host path (e.g. Ghidra and a co-located r2mcp) from copying
            # the sample twice — see test_worker_profile_mirror.py.
            new_mirrors, new_sample_paths = mirror_static_samples(
                app.container,
                temp_path=temp_path,
                sha256=sample_sha256,
                extension=_orig_ext,
                copy_fn=sample_files.private_copy,
                job_id=job_id,
            )
            host_mirrors.extend(new_mirrors)
            static_sample_paths.update(new_sample_paths)
            static_sample_path = global_mirror_path(
                static_sample_paths, app.container.config.static
            )
        except Exception as exc:
            logger.warning(
                "Failed to download sample from MinIO: %s. Sandbox submission skipped.",
                exc,
                extra={"job_id": job_id, "component": "minio"},
            )
            temp_path = None

        # Execute the asynchronous pipeline natively to
        # avoid "Event loop is closed" errors caused by threading mismatches.
        # Heartbeat task keeps the job alive in the DB and logs progress.
        heartbeat_stop_event = asyncio.Event()
        pipeline_task: asyncio.Task | None = None
        cancelled_by_user = False

        async def _heartbeat() -> None:
            # The heartbeat is also the cancellation
            # poller. `cancel_job` sets `analysis:{job_id}:cancel`; the
            # pipeline is a single long `await`, so cancelling that task is
            # the only way to stop the run. Previously the worker checked the
            # job status exactly once (before starting), so a cancel issued
            # mid-run was ignored and the finished pipeline overwrote the
            # `cancelled` row with `completed`/`failed`.
            nonlocal cancelled_by_user
            while not heartbeat_stop_event.is_set():
                try:
                    await asyncio.wait_for(heartbeat_stop_event.wait(), timeout=CANCEL_POLL_SECONDS)
                except TimeoutError:
                    try:
                        if await cancel_was_requested(redis_conn, job_id):
                            cancelled_by_user = True
                            logger.info(
                                "Cancellation requested for job=%s — stopping pipeline.",
                                job_id,
                                extra={"job_id": job_id, "component": "heartbeat"},
                            )
                            # The job's own flag first: it stops the model
                            # calls in flight and refuses the next ones, which
                            # a task cancellation alone does not reach.
                            app.container.cancellation.cancel("the operator cancelled the job")
                            if pipeline_task is not None:
                                pipeline_task.cancel()
                            return
                    except Exception as exc:  # noqa: BLE001 — polling must never kill the run
                        logger.debug("Cancel-flag poll failed: %s", exc)
                    logger.info(
                        "Pipeline heartbeat: job=%s still running...",
                        job_id,
                        extra={"job_id": job_id, "component": "heartbeat"},
                    )

        heartbeat_task = asyncio.create_task(_heartbeat())

        # The pipeline (analysts -> mediator -> judge -> report nodes)
        # runs inside ``app.arun()`` as a single LangGraph step, so the
        # worker only sees phase boundaries at the start and end. We
        # emit a phase marker here so live consumers can distinguish
        # "running but no agent events yet" from "agents actively
        # working". Mid-pipeline phases would require LangGraph
        # callback wiring.
        await _publish_event(redis_conn, job_id, "phase_change", {"phase": "analyzing"})
        try:
            # Run the pipeline as a task so the heartbeat poller can cancel
            # it when the user cancels the job.
            pipeline_task = asyncio.create_task(
                app.arun(
                    file_hash=sample_sha256,
                    file_name=sample_filename,
                    sample_path=temp_path,
                    static_sample_path=static_sample_path,
                    static_sample_paths=static_sample_paths,
                    # The same instant this job's own duration is measured
                    # from, so the report's elapsed time and the job row
                    # cannot disagree.
                    started_at=start_time,
                )
            )
            pipeline_result = await await_the_pipeline(pipeline_task, app.container.cancellation)
        except (asyncio.CancelledError, JobCancelled):
            # Two things cancel this task and they end differently. An
            # operator's cancel leaves its flag in Redis — the heartbeat may
            # have read it already, or the cancel may have arrived between two
            # of its polls — and that run owes the operator a row saying
            # ``cancelled``. A worker shutting down and arq's own job timeout
            # leave no flag: the process is going away, writing a row on the
            # way out is a race with its own teardown, and the periodic sweep
            # repairs the row within ten minutes because the heartbeat dies
            # with the process.
            if not cancelled_by_user:
                cancelled_by_user = await cancel_was_requested(redis_conn, job_id)
            if not cancelled_by_user:
                # arq finishes a job it cancelled only on ``CancelledError``; a
                # ``JobCancelled`` reaching it would leave the job unfinished in
                # its bookkeeping, since it is no ``Exception`` either.
                if not isinstance(sys.exc_info()[1], asyncio.CancelledError):
                    raise asyncio.CancelledError from sys.exc_info()[1]
                raise
            # Worded from where the pipeline was: a check's own record when
            # one stopped it, otherwise the nodes that were running when the
            # task was cancelled under them.
            _stopped = app.container.cancellation.where_stopped()
            _into = max(0.0, time.time() - start_time)
            logger.info(
                "Pipeline cancelled by user request: job=%s (stopped %s, %.0f s into the run)",
                job_id,
                _stopped,
                _into,
                extra={"job_id": job_id},
            )
            await _publish_event(
                redis_conn,
                job_id,
                "cancelled",
                {"stopped": _stopped, "seconds_into_run": round(_into, 1)},
            )
            # On a session of its own, like every other outcome this task
            # records: the one it was working through may be the one the
            # cancellation came with.
            if job_uuid is not None:
                await mark_job_cancelled(db_session, job_uuid)
            # How this job ends depends on who cancelled what. The operator's
            # cancel reaches the pipeline task, not this one: nothing outside
            # is waiting for a ``CancelledError`` here, and raising one puts
            # arq on its retry branch — the job goes back in the queue, is
            # popped again and ends with "max retries exceeded", which reads
            # like a failure for something somebody asked for. A finished job
            # is what this is, so it returns like one.
            #
            # A worker shutting down cancels *this* task and waits for it, and
            # ``cancelling()`` is how a task knows that has happened. Then the
            # cancellation must carry on, or the shutdown waits for a task that
            # decided not to end. The ``finally`` below runs on both paths, so
            # the feed is flushed and the claim released either way.
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise
            return {"status": "cancelled", "job_id": job_id}
        finally:
            heartbeat_stop_event.set()
            try:
                heartbeat_task.cancel()
                await heartbeat_task
            except asyncio.CancelledError:
                pass

        # Announce that all analysts have finished (pipeline -> negotiation phase)
        for agent_name in registered_agents:
            await _publish_event(
                redis_conn,
                job_id,
                "agent_progress",
                {"agent": agent_name, "phase": "done"},
            )
        await _publish_event(redis_conn, job_id, "phase_change", {"phase": "negotiation"})

        elapsed = time.time() - start_time
        logger.info(
            f"Pipeline completed in {elapsed:.1f}s: job={job_id}",
            extra={"job_id": job_id, "duration_ms": round(elapsed * 1000)},
        )

        # A run in which no analyst answered and the judge never answered
        # is not a degraded analysis, it is an absent one. Saving a report
        # for it would publish a verdict and a confidence drawn from
        # nothing, which is what a provider that refused every request
        # produced: "completed", Suspicious, 0.0, no evidence and no error
        # for the operator to act on. Raised rather than handled here so
        # the one failure path below marks the job, records the message and
        # persists nothing.
        absent = absent_analysis_message(pipeline_result)
        if absent:
            raise AbsentAnalysisError(absent)

        # Persistence phase begins — the worker is about to insert
        # the report and findings into Postgres. Live consumers use
        # this to switch the UI into a "saving results" state.
        await _publish_event(redis_conn, job_id, "phase_change", {"phase": "reporting"})

        # ── 4. Build the report ──────────────────────────────
        from app.models.report import AgentFinding, AnalysisReport

        # Prefer the rich extended bundle produced by ``report_node``
        # (54+ objects with Identity/Indicator/ObservedData/Note/Report
        # SDOs) over the minimal judge bundle. The legacy field is the
        # fallback for callers that pre-date the MalwareReport refactor.
        stix_bundle_for_persist = pipeline_result.get(
            "stix_bundle_extended"
        ) or pipeline_result.get("stix_output")
        # Ensure STIX 2.1 ``spec_version`` is present on every bundle —
        # the OASIS spec requires it on top-level bundle objects, and
        # downstream tooling (OpenCTI / MISP / TAXII clients) silently
        # rejects bundles that omit the field. Defensive: covers the
        # case where the producer dropped it during serialization.
        if isinstance(stix_bundle_for_persist, dict):
            stix_bundle_for_persist.setdefault("spec_version", "2.1")

        # A masked, non-secret record of the Settings this job actually
        # ran with, plus which core keys came from a stored UI override
        # rather than the environment/default -- lets a report reader
        # tell what was in effect without re-deriving it.
        _run_summary = pipeline_result.get("run_summary")
        _run_summary = dict(_run_summary) if isinstance(_run_summary, dict) else {}
        _run_summary["settings_snapshot"] = settings_snapshot(core_settings, overrides.keys())
        if _report_hash_mismatch_reason:
            # Threaded in here rather than through the pipeline state:
            # the mismatch is known before the graph runs (it is on the
            # stored row, checked at upload time), and both the run
            # summary and the report banner read a plain list of
            # strings, so appending to each is the whole fix.
            _existing_reasons = _run_summary.get("degradation_reasons")
            _run_summary["degradation_reasons"] = [
                *(_existing_reasons if isinstance(_existing_reasons, list) else []),
                _report_hash_mismatch_reason,
            ]
            _malware_report = pipeline_result.get("malware_report")
            if isinstance(_malware_report, dict):
                _report_reasons = _malware_report.get("degradation_reasons")
                _malware_report["degradation_reasons"] = [
                    *(_report_reasons if isinstance(_report_reasons, list) else []),
                    _report_hash_mismatch_reason,
                ]

        # A pipeline that produced no report is a failed run, not a
        # completed one with nothing in it (L15, security hardening):
        # ``report_node`` returns ``{"report_error": "<type>: <msg>"}``
        # instead of a ``malware_report`` when the deterministic build
        # raised. Surface that message through the same failure path
        # every other pipeline exception takes, below.
        #
        # A missing ``malware_report`` is not on its own evidence of a
        # failure, though: with ``reporting.enabled = False`` the graph
        # routes judge -> END and never runs the report node at all
        # (``pipeline/builder.py``, ``pipeline/state.py``), so
        # ``malware_report`` stays ``None`` by design on every run. Only
        # fail the job when the report node actually raised
        # (``report_error`` present) or reporting was expected to run
        # for this job and did not produce one.
        _report_error = pipeline_result.get("report_error")
        if _report_error or (
            core_settings.reporting.enabled and not pipeline_result.get("malware_report")
        ):
            logger.error(
                "Pipeline produced no report: job=%s report_error=%s",
                job_id,
                _report_error,
                extra={"job_id": job_id},
            )
            raise RuntimeError(_report_error or "pipeline produced no report")

        # ── 4a. Save the report and everything that cites it ─
        # The run's own writes, in one short transaction of their own,
        # opened only now that the models have stopped. The report, the
        # per-agent findings, the evidence ledger, the transcript and the
        # completion go together because the report's sections cite the
        # ledger's ids and a reader who is told the job completed then goes
        # looking for them: a report whose citations resolve to nothing, or
        # a "completed" row with no report under it, is worse than one more
        # run of the analysis.
        async with db_session() as db:
            report = AnalysisReport(
                job_id=job_uuid,
                verdict=pipeline_result.get("final_decision", "Unknown"),
                overall_confidence=_extract_confidence(pipeline_result),
                malware_category=_extract_category(pipeline_result),
                stix_bundle=stix_bundle_for_persist,
                judge_stix_bundle=judge_bundle_record(pipeline_result),
                mitre_techniques=_extract_mitre(pipeline_result),
                # The agents' *final* prose. This used to persist only
                # ``reports`` — the first-pass text — so the report an analyst
                # rewrote after the negotiation was thrown away, and the stored
                # prose silently contradicted the stored claims (which do come
                # from the revised ISR). ``revised_reports`` is keyed by the
                # same agent names, so the merge is per-agent and an agent that
                # never revised keeps its original.
                agent_reports={
                    **(pipeline_result.get("reports") or {}),
                    **(pipeline_result.get("revised_reports") or {}),
                },
                negotiation_log={
                    "discussion_history": [
                        {
                            "round": i + 1,
                            "agent": (
                                arg.agent_name
                                if hasattr(arg, "agent_name")
                                else arg.get("agent_name", "")
                            ),
                            "position": "",  # derived by confidence on frontend
                            # ``None`` on a round where consensus did not
                            # apply: no agreement was measured, so none is
                            # stored, neither 100 nor 0.
                            "confidence": _argument_confidence(arg),
                            "argument": (
                                arg.finding if hasattr(arg, "finding") else arg.get("finding", "")
                            ),
                            # The platform's sentence about the round, apart
                            # from the mediator's own words.
                            "note": (
                                getattr(arg, "note", "")
                                if hasattr(arg, "finding")
                                else arg.get("note", "")
                            ),
                            # ``complete`` | ``failed`` | ``timeout``. Without
                            # it a mediation that never ran is indistinguishable
                            # from one where the agents calmly disagreed: both
                            # store ``is_consensus=False`` at 0.0 confidence.
                            # Every run in this database is the former, and the
                            # UI drew all of them as the latter.
                            "status": (
                                getattr(arg, "status", "complete")
                                if hasattr(arg, "status")
                                else arg.get("status", "complete")
                            ),
                        }
                        for i, arg in enumerate(pipeline_result.get("discussion_history") or [])
                    ],
                    "confidence_history": pipeline_result.get("confidence_history", []),
                    "iteration_count": pipeline_result.get("iteration_count", 0),
                    # ``None`` beside ``consensus_applicable: false`` when
                    # fewer than two analysts produced claims.
                    "is_consensus": pipeline_result.get("is_consensus", False),
                    "consensus_applicable": pipeline_result.get("consensus_applicable", True)
                    is not False,
                    # True when at least one round failed outright, so consumers
                    # can say "the negotiation did not run" rather than "the
                    # agents did not agree".
                    "mediation_failed": any(
                        getattr(a, "status", "complete") in ("failed", "timeout")
                        for a in (pipeline_result.get("discussion_history") or [])
                        if getattr(a, "agent_name", "") == "Mediator"
                    ),
                    # Whether the last round's agreement was flagged as
                    # sycophantic — agents converging without new evidence. It
                    # reached the database only buried inside ``run_summary``
                    # before, so nothing rendering the negotiation could tell
                    # a genuine consensus from a manufactured one.
                    "sycophancy_detected": bool(pipeline_result.get("sycophancy_detected", False)),
                },
                run_summary=_run_summary,
                malware_report=pipeline_result.get("malware_report"),
            )
            # A re-run supersedes its predecessor. ``analysis_reports.job_id``
            # is unique and this path only ever inserted, so an arq retry --
            # which arq schedules on its own -- reached the end of a full
            # analysis and threw the result away on a UniqueViolationError.
            await _supersede_previous_report(db, job_uuid)
            db.add(report)
            await db.flush()

            logger.info(
                "Report saved: id=%s verdict=%s confidence=%s",
                report.id,
                report.verdict,
                report.overall_confidence,
                extra={"job_id": job_id, "component": "report"},
            )

            # Save per-agent findings
            isr_reports = pipeline_result.get("isr_reports", {})
            pipeline_reports = pipeline_result.get("reports") or {}
            for agent_name, isr in isr_reports.items():
                if hasattr(isr, "model_dump"):
                    isr_data = isr.model_dump()
                elif isinstance(isr, dict):
                    isr_data = isr
                else:
                    continue

                # Derive agent confidence from claims (ISR has no overall_confidence field)
                claims = isr_data.get("claims", [])
                agent_confidence = 0.0
                if claims:
                    agent_confidence = sum(c.get("confidence", 0) for c in claims) / len(claims)

                # D15+D16: derive lifecycle status from the analyst's text
                # report + claim shape so the UI can render "FAILED" /
                # "NO DATA" badges instead of synthesising a misleading
                # verdict from an empty payload.
                _text_report = pipeline_reports.get(agent_name, "")
                _stripped = _text_report.strip() if isinstance(_text_report, str) else ""
                status: str
                status_reason: str | None
                if _stripped.startswith("[ERROR]"):
                    _reason = _stripped[len("[ERROR]") :].strip()[:500] or None
                    _low = (_reason or "").lower()
                    if "timeout" in _low or "timed out" in _low:
                        status = "timeout"
                    else:
                        status = "failed"
                    status_reason = _reason
                elif isr_data.get("status") in _AGENT_FINDING_STATUSES:
                    # The analyst said something about its own answer that the
                    # claim list cannot: it ended without a structured report,
                    # so this is not "no data" but "no report". Only a value
                    # from the known vocabulary is persisted — the column feeds
                    # a TypeScript union and a badge, and an unknown string
                    # would reach both.
                    status = str(isr_data["status"])
                    status_reason = str(isr_data.get("status_reason") or "") or None
                elif not claims:
                    if isr_data.get("status"):
                        logger.warning(
                            "Agent %s reported the unknown status %r; recording no_data.",
                            agent_name,
                            isr_data["status"],
                        )
                    status = "no_data"
                    status_reason = "Agent produced no claims"
                else:
                    status = "complete"
                    status_reason = None

                finding = AgentFinding(
                    report_id=report.id,
                    agent_name=agent_name,
                    domain=isr_data.get("domain", agent_name),
                    claims=claims,
                    dissent_items=isr_data.get("dissent_items", []),
                    revision_rounds=isr_data.get("revision_round", 0),
                    final_confidence=agent_confidence,
                    status=status,
                    status_reason=status_reason,
                )
                db.add(finding)

            logger.info(
                f"Saved {len(isr_reports)} agent findings for report={report.id}",
                extra={"job_id": job_id},
            )

            # ── 4a. Save the evidence ledger ─────────────────────
            # Every tool call the run made, in the order the ids were issued.
            # The report's sections cite these ids, so the two are written in
            # one transaction: a report whose citations resolve to nothing is
            # worse than one that was never saved.
            _ledger = pipeline_result.get("evidence_ledger") or []
            for _entry in _ledger:
                if not isinstance(_entry, dict):
                    continue
                db.add(_evidence_row(_entry, job_id=job_uuid))

            logger.info(
                f"Saved {len(_ledger)} evidence entries for job={job_id}",
                extra={"job_id": job_id},
            )

            # ── 4b. Save the transcript ──────────────────────────
            # The conversation itself, written down exactly as it was
            # broadcast. ``agent_findings`` above records where each agent
            # *ended up*; this records what was said and in what order, which
            # is the only place the per-round positions, the sycophancy
            # intervention and the revised prose survive past the 24 h Redis
            # stream. See ``AgentMessage`` for the full rationale.
            # Whether the publisher numbered this run at all. A run it never
            # reached — one whose loop was already closing, or whose recorder
            # raised — falls back to the position in the recording, which is
            # the order the lines were said in and all this column ever meant.
            # A run it numbered *partly* may not: the position and the
            # publisher's count share the low integers, so a line that missed
            # its stamp would borrow a number another line already owns and
            # the console would draw the two as one. Those get ``0``, which is
            # outside the publisher's range — it counts from 1 — and which
            # every reader already treats as "no number".
            _numbered = any(int(m.get("seq") or 0) > 0 for m in transcript)
            for index, message in enumerate(transcript):
                _stamped = int(message.get("seq") or 0)
                db.add(
                    _transcript_row(
                        message,
                        report_id=report.id,
                        seq=_stamped or (0 if _numbered else index),
                    )
                )

            logger.info(
                f"Saved {len(transcript)} transcript messages for report={report.id}",
                extra={"job_id": job_id},
            )

            # ── 5. Mark job complete ─────────────────────────────
            # Use Python ``datetime.now(UTC)`` instead of Postgres ``NOW()``.
            # ``func.now()`` resolves to ``transaction_timestamp()`` which is
            # the START of the current transaction — that equals
            # ``started_at`` and produces a 0-second ``completed_at`` even
            # for a 20-minute pipeline. ``duration_seconds`` is computed in
            # Python anyway so a single clock source is correct.
            now = datetime.now(UTC)
            # The status travels in the statement rather than on a loaded
            # row: this session has never seen the job row, and the one that
            # read it was closed before the pipeline started.
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_uuid)
                .values(
                    status="completed",
                    completed_at=now,
                    # Round to one decimal so sub-second jobs (~0.7s) don't
                    # collapse to zero; the column is ``Numeric(10,2)`` so
                    # fractional values survive the round-trip.
                    duration_seconds=round(float(elapsed), 1),
                )
            )
            await db.commit()
            # Read off the report while its session is still open, so nothing
            # below can send this function back to the database for a value.
            report_uuid = report.id
            report_verdict = report.verdict
            report_confidence = report.overall_confidence
            report_has_malware_report = bool(report.malware_report)

        await _publish_event(
            redis_conn,
            job_id,
            "completed",
            {
                "status": "completed",
                "verdict": report_verdict,
                "confidence": report_confidence,
                "duration_seconds": int(elapsed),
                "report_id": str(report_uuid),
            },
        )

        logger.info(
            f"Job completed: job={job_id} verdict={report_verdict} duration={int(elapsed)}s",
            extra={"job_id": job_id, "component": "lifecycle"},
        )

        # ── 6. Auto-enqueue threat-intel enrichment ───────────────
        # The enrichment job is post-hoc; pipeline latency is unaffected.
        # ARQ enforces the unique ``_job_id`` so duplicate triggers
        # (e.g. operator also calling /enrich manually) are coalesced.
        if await runtime_config.get("enrichment_enabled") and report_has_malware_report:
            try:
                arq_pool = ctx.get("arq_pool")
                if arq_pool is None:
                    from arq.connections import ArqRedis

                    arq_pool = ArqRedis(connection_pool=redis_conn.connection_pool)
                from app.worker.enrich_worker import enqueue_enrichment

                await enqueue_enrichment(arq_pool, report_uuid)
                logger.info(
                    "enrich: queued report=%s",
                    report_uuid,
                    extra={"job_id": job_id, "component": "enrich"},
                )
            except Exception as exc:  # noqa: BLE001
                logger.warning("enrich: enqueue failed (%s).", exc)

        return {
            "status": "completed",
            "verdict": report_verdict,
            "confidence": report_confidence,
            "duration_seconds": int(elapsed),
        }

    except Exception as exc:
        # ── Error handling ────────────────────────────────────
        # The error id is minted first: it is what the job row, the event and
        # the log entry below are joined on, and it is the only handle a
        # reader of any of the three is given.
        error_id = uuid.uuid4().hex
        tb = traceback.format_exc()

        logger.error(
            "Analysis failed: job=%s error=%s: %s error_id=%s",
            job_id,
            type(exc).__name__,
            exc,
            error_id,
            exc_info=True,
            extra={"job_id": job_id, "component": "pipeline", "error_id": error_id},
        )
        logger.error(
            "Pipeline failure error_id=%s job=%s traceback=%s",
            error_id,
            job_id,
            tb,
            extra={"job_id": job_id, "error_id": error_id},
        )

        reason = failure_reason(exc, error_id)
        if job_uuid is not None:
            # A session of its own, always. The session this job read through
            # was closed before the pipeline started, and the one that was
            # writing when a failure happened is exactly the session that may
            # be unusable — a backend killed under it leaves every statement
            # on it raising ``PendingRollbackError``, which is how a run that
            # failed came to publish its ``error`` event and still leave the
            # row saying ``running``, with no error and no ``completed_at``,
            # for as long as the worker stayed up.
            await mark_job_failed(db_session, job_uuid, reason=reason, error_id=error_id)
        else:
            logger.warning(
                "Cannot update job status: the job id did not parse (job_id=%s).",
                job_id,
                extra={"job_id": job_id},
            )

        # Do not leak tracebacks to clients — only emit an opaque error id
        # that maps back to the structured log entries above.
        await _publish_event(
            redis_conn,
            job_id,
            "error",
            {
                "status": "failed",
                "error_id": error_id,
                "message": "Analysis failed. See server logs for details.",
            },
        )

        return {"status": "failed", "error": reason}

    finally:
        # Everything this block does is wrapped again, because the one
        # statement that must not be skipped is the last: three of the
        # statements below are awaits, a re-cancellation while one of them is
        # unwinding is a ``BaseException`` no handler here catches, and what
        # would then be left on disk is a directory of live malware. The
        # ordering is deliberate and stays — the staging directory is taken
        # away once the teardown has returned and no child is left to write it
        # back — so the guarantee is made with a ``finally`` of its own rather
        # than by moving the call earlier.
        try:
            # Whatever is still queued of this job's conversation, written
            # before the task returns. First in the block: the teardown below
            # can take a while and a reader who opens a cancelled run wants
            # its last lines, not the ones from two seconds earlier.
            await _stop_event_feed(job_id)

            # The claim goes with the run, on every way out of it. Cancelled and
            # awaited rather than left to the garbage collector: a refresher that
            # outlived its job would keep saying a finished job is running, which
            # is the one thing the sweep believes.
            if owner_task is not None:
                owner_task.cancel()
                with suppress(asyncio.CancelledError):
                    await owner_task
            await release_job(redis_conn, job_id)

            # The worker's own private copies of the sample never outlive the
            # job that downloaded them, on success, failure or cancellation
            # alike (H3, security hardening). ``remove_quietly`` is a no-op
            # on ``None`` (nothing was ever downloaded) and never raises.
            from app.worker import sample_files

            sample_files.remove_quietly(temp_path, job_id=job_id)
            for _host_mirror in host_mirrors:
                sample_files.remove_quietly(_host_mirror, job_id=job_id)

            # Release the agents' MCP toolkits, their stdio subprocesses and the
            # per-job caches. A ``finally`` rather than ``async with`` because
            # the body above spans ~500 lines and returns early on the
            # user-cancelled path — this covers success, failure and
            # cancellation without re-indenting any of it.
            #
            # ``aclose`` is total by construction (see MaljanApp.aclose), so a
            # failed teardown cannot turn a completed analysis into a failed
            # one. Whether it actually reclaims the memory is a separate
            # question, which is why the readings are logged either side of it
            # and why the worker also carries a hard recycle backstop.
            if app is not None:
                from maljan.core import memprobe

                memprobe.probe("job:before_teardown", job_id=job_id)
                try:
                    # The outermost fence. Each toolkit close is bounded, and
                    # the container bounds them again — this bounds the lot,
                    # because a job is not finished until this returns and
                    # ``max_jobs = 1`` means the next one cannot start.
                    #
                    # Earned the hard way: a run that had already written its
                    # report sat here for 42 minutes with arq still reporting
                    # ``j_ongoing=1``, and only ended on SIGTERM. An ``mcp``
                    # stdio exit stack waits on its child process, and a child
                    # that does not exit waits forever.
                    await asyncio.wait_for(app.aclose(), timeout=_TEARDOWN_BUDGET)
                except TimeoutError:
                    logger.error(
                        "Teardown exceeded %.0fs and was abandoned; the job is "
                        "complete and its result is stored, but MCP subprocesses "
                        "may have leaked. The RSS ceiling will recycle the worker.",
                        _TEARDOWN_BUDGET,
                        extra={"job_id": job_id},
                    )
                except Exception as exc:  # noqa: BLE001 — teardown never fails a job
                    logger.warning("Teardown failed (non-fatal): %s", exc)
                gc.collect()
                reclaimed = memprobe.malloc_trim()
                memprobe.probe("job:end", job_id=job_id, trim_reclaimed_mb=reclaimed)

        finally:
            # What the sidecars staged and carved for this job, its sandbox
            # captures included: one directory per job, so one removal rather
            # than a search. It goes with the owner heartbeat and the sample
            # copies above — on success, failure, an operator's cancel and
            # every early return — and the sample root that named the capture
            # directory goes with it, so no later job inherits it.
            remove_job_staging(job_id)


# ── Helpers ──────────────────────────────────────────────────────


def _roster_for(container: Any) -> dict[str, Any]:
    """The run's roster, or an empty one when the team cannot be read.

    Never raises: a roster is how the console draws names, and a run that
    stopped because it could not build one would trade the whole analysis for
    a label.
    """
    try:
        from maljan.pipeline.events import roster_payload

        agents = container.config.agents
        return roster_payload(
            container.active_profile(),
            agents.definitions,
            # The same bound the asks themselves run under, so the roster
            # names exactly the agents that can be reached and no more.
            depth=int(agents.delegation_depth),
        )
    except Exception as exc:  # noqa: BLE001 — a roster never costs a run
        logger.warning("Could not build the roster for this run (%s).", exc)
        return {"agents": [], "stages": []}


def _argument_confidence(arg: Any) -> float | None:
    """One negotiation argument's confidence as a percentage, or ``None``.

    ``None`` is a mediator round where consensus did not apply; a missing
    field on an older stored argument reads as zero, as it always did.
    """
    value = (
        getattr(arg, "confidence_score", None)
        if hasattr(arg, "confidence_score")
        else arg.get("confidence_score", 0)
    )
    return None if value is None else float(value) * 100


def _extract_confidence(result: dict) -> float | None:
    """Extract overall confidence from the pipeline result.

    The ``MalwareReport`` is the authoritative source and is checked first; the
    other two are fallbacks for legacy or partial results that carry no report.
    The order is load-bearing rather than arbitrary: the report, the run summary
    and the confidence history are three places one number is written, and a
    reader who saw the DEGRADED RUN banner next to a confidence the report did
    not carry was reading whichever of them this function happened to reach.

    A report that carries the key explicitly set to ``None`` has said that no
    confidence was assessed — the judge put no number on its verdict, or never
    answered at all — and that answer is final. Falling through to the
    confidence history there would take the analysts' certainty in their own
    claims and print it beside a decision none of them made.
    """
    malware_report = result.get("malware_report")
    if isinstance(malware_report, dict) and "overall_confidence" in malware_report:
        conf = malware_report["overall_confidence"]
        return None if conf is None else float(conf)

    # From run_summary if available
    run_summary = result.get("run_summary")
    if run_summary and isinstance(run_summary, dict):
        conf = run_summary.get("overall_confidence")
        if conf is not None:
            return float(conf)

    # From confidence_history (last value)
    history = result.get("confidence_history", [])
    if history:
        return float(history[-1])

    return 0.0


def _extract_category(result: dict) -> str | None:
    """Extract malware category from the pipeline result."""
    run_summary = result.get("run_summary")
    if run_summary and isinstance(run_summary, dict):
        category = run_summary.get("malware_category")
        return str(category) if category is not None else None
    return None


def judge_bundle_record(result: dict) -> dict | None:
    """The judge's own bundle and its label map, as the report stores them.

    The export's decline and not-carried rows say an object or a property "is
    kept in the judge's own bundle"; this is that bundle, kept beside the
    export rather than only when there is no export. It is the judge's JSON as
    the judge wrote it (``as_written``), so a property the platform's models do
    not declare is still in it. A run recorded without that answer keeps the
    parsed bundle instead, and says so. ``None`` when the judge produced none.
    """
    bundle = result.get("stix_output")
    if not isinstance(bundle, dict) or not bundle:
        return None
    labels = result.get("stix_labels")
    kept_labels = dict(labels) if isinstance(labels, dict) else {}
    written = result.get("stix_written")
    if isinstance(written, dict) and written:
        return {
            "bundle": json.loads(json.dumps(written, default=str)),
            "labels": kept_labels,
            "as_written": True,
        }
    # The pipeline keeps the bundle as a Python dump, timestamps as datetimes;
    # the column stores JSON, in STIX's own timestamp form.
    from maljan.schemas.stix_models import Bundle

    try:
        as_json = Bundle.model_validate(bundle).model_dump(mode="json")
    except Exception:  # noqa: BLE001 — a record kept in a weaker form, never a failed save
        as_json = json.loads(json.dumps(bundle, default=str))
    return {
        "bundle": {"spec_version": "2.1", **as_json},
        "labels": kept_labels,
        "as_written": False,
    }


def _extract_mitre(result: dict) -> list | None:
    """Extract MITRE ATT&CK techniques for the legacy ``mitre_techniques`` column.

    Preference order:
      1. ``malware_report.ttp_mappings`` — the published technique list, which
         every other technique surface of the report is built from.
      2. ``stix_bundle_extended`` / ``stix_output`` — fall back to walking the
         STIX bundle for ``attack-pattern`` SDOs when the report builder did
         not run (mock mode without a configured pipeline, legacy rows).

    An entry with no technique id is not written on either path. One audited
    run served three of them from the fallback — ``/mitre`` listed three
    techniques with an empty ``technique_id`` while ``ttp_mappings`` was empty
    — because the judge's attack-patterns carried names and no ATT&CK
    reference. A behaviour with no technique id is reported as a behaviour, in
    the report's own ``unmapped_behaviours``, and never as a technique.
    """
    mr = result.get("malware_report") or {}
    mappings = mr.get("ttp_mappings") or []
    if mappings:
        return [
            {
                "technique_id": m.get("technique_id", ""),
                "name": m.get("technique_name") or m.get("name", ""),
                "description": " | ".join(m.get("evidence_quotes") or [])[:512],
            }
            for m in mappings
            if m.get("technique_id")
        ] or None

    stix = result.get("stix_bundle_extended") or result.get("stix_output")
    if not stix or not isinstance(stix, dict):
        return None

    techniques = []
    for obj in stix.get("objects", []):
        if not isinstance(obj, dict) or obj.get("type") != "attack-pattern":
            continue
        # ``[{}]`` as a default only covers a *missing* key. An attack-pattern
        # carrying ``"external_references": []`` — which the model emits
        # routinely — got past that default and then died on ``[0]``, taking a
        # completed analysis down with it: two consecutive live runs failed
        # with ``IndexError: list index out of range`` *after* every analyst,
        # the negotiation and the judge had finished. Losing a technique ID is
        # a missing field; losing the run is not.
        refs = obj.get("external_references")
        first = refs[0] if isinstance(refs, list) and refs and isinstance(refs[0], dict) else {}
        technique_id = str(first.get("external_id") or "").strip()
        if not technique_id:
            continue
        techniques.append(
            {
                "technique_id": technique_id,
                "name": obj.get("name", ""),
                "description": obj.get("description", ""),
            }
        )
    return techniques if techniques else None


# ── ARQ Worker Configuration ────────────────────────────────────


# What a swept row says about itself: the fact the sweep established, and what
# the operator can do about it.
_SWEPT_NO_OWNER = (
    "No worker is holding this job: its owner heartbeat has expired, so the "
    "process that was running it is gone. Marked failed by the orphan sweep — "
    "re-submit the sample if needed."
)

# When the sweep runs. Not at the instant of startup: a worker that crashed
# leaves its last heartbeat behind for up to one TTL, and a sweep that ran
# inside that window would read the dead worker's own claim as ownership and
# leave the row it exists to repair. Waiting one TTL costs a minute and a half
# on a restart and makes the first pass conclusive.
#
# Then every ten minutes for the life of the process, because a worker that
# gives up on a job while staying up — the case that left job 892659bc reading
# ``running`` for an hour — is not repaired by anything that only runs at boot.
SWEEP_FIRST_DELAY_SECONDS = JOB_OWNER_TTL_SECONDS
SWEEP_INTERVAL_SECONDS = 600


async def _sweep_orphan_jobs(db_session: async_sessionmaker, redis_conn: Any = None) -> None:
    """Mark ``running`` rows that no worker is holding as ``failed``.

    When a worker process dies mid-flight (OOM kill, the RSS recycler, an
    operator stopping it, a deploy rollover) the ``run_analysis`` task has no
    chance to flip the row from ``running`` → ``failed``. The database then
    carries a phantom ``running`` row for ever: the dashboard reports an
    analysis as in flight, nothing retries it (``max_tries = 1``), and the
    false-positive statistics count a run that never ended.

    Ownership is the heartbeat the owner itself writes (``claim_job``), not
    anything arq keeps. arq's in-progress key is written once and lives for the
    job timeout, so it outlives the process that wrote it by hours; its health
    key is queue-wide and lives thirty-one seconds past its last write, so a
    worker killed a moment ago still looks alive — and a restart lands inside
    that window, which is exactly when this runs. A per-job heartbeat with a
    ninety-second life, refreshed every thirty, says what neither of those can:
    *this* worker is still on *this* job.

    So a ``running`` row is orphaned when its heartbeat key is absent. Two
    exceptions, both in the direction of leaving a job alone: a row younger
    than one TTL is left for the next pass, because a worker may have claimed
    it a moment ago, and a job this process is running is never swept whatever
    Redis says. When Redis cannot be read at all, nothing is touched and the
    reason is logged once: ownership cannot be established without it, and
    guessing costs somebody else's run.
    """
    from datetime import UTC as _UTC
    from datetime import datetime as _datetime
    from datetime import timedelta as _timedelta

    from app.models.job import AnalysisJob

    if redis_conn is None:
        _log_unreadable_queue("no Redis connection")
        return

    young_cutoff = _datetime.now(_UTC) - _timedelta(seconds=JOB_OWNER_TTL_SECONDS)

    async with db_session() as db:
        candidates = (
            await db.execute(
                select(AnalysisJob.id, AnalysisJob.started_at, AnalysisJob.created_at).where(
                    AnalysisJob.status == "running"
                )
            )
        ).all()
        await db.commit()

    def _since(row: Any) -> Any:
        # ``started_at`` is written with the status change; ``created_at`` is
        # the fallback for a row that somehow carries none, so a job cannot
        # stay ``running`` for ever by having no clock.
        return row[1] or row[2]

    aged = [str(row[0]) for row in candidates if _since(row) is None or _since(row) < young_cutoff]
    if not aged:
        logger.debug("Orphan sweep: nothing old enough to judge.")
        return

    owners = await live_owners(redis_conn, aged)
    if owners is None:
        return
    orphans = [job_id for job_id in aged if job_id not in owners and job_id not in _OWNED_JOBS]
    if not orphans:
        logger.debug("Orphan sweep: every running job has an owner.")
        return

    async with db_session() as db:
        result = await db.execute(
            update(AnalysisJob)
            .where(
                AnalysisJob.id.in_([uuid.UUID(job_id) for job_id in orphans]),
                # Re-checked in the statement: a worker may have finished one
                # of these between the read above and this write.
                AnalysisJob.status == "running",
            )
            .values(status="failed", completed_at=func.now(), error_message=_SWEPT_NO_OWNER)
            .returning(AnalysisJob.id)
        )
        affected = [str(row[0]) for row in result.all()]
        await db.commit()

    if affected:
        logger.warning(
            "Orphan sweep: marked %d unowned 'running' job(s) as 'failed': %s",
            len(affected),
            ", ".join(affected[:8]) + (" ..." if len(affected) > 8 else ""),
            extra={"component": "worker.lifecycle", "job_count": len(affected)},
        )


async def sweep_orphans_forever(
    ctx: dict,
    *,
    first_delay: float | None = None,
    interval: float | None = None,
) -> None:
    """Run the orphan sweep on its own clock, for the life of the worker.

    A task rather than a cron job: this worker runs one job at a time, so a
    scheduled task would queue behind whatever analysis is in flight and only
    run when there is nothing to repair.

    Never raises out of a pass: a sweep that took the worker down with it would
    trade every future job for one stale row.

    The two delays are arguments with the constants as their defaults, so a
    test can watch the loop turn without waiting a minute and a half for the
    first pass.
    """
    wait_first = SWEEP_FIRST_DELAY_SECONDS if first_delay is None else first_delay
    wait_between = SWEEP_INTERVAL_SECONDS if interval is None else interval
    await asyncio.sleep(wait_first)
    while True:
        try:
            await _sweep_orphan_jobs(ctx["db_session"], ctx.get("redis"))
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 — a sweep never costs the worker
            logger.warning(
                "Orphan sweep failed (%s); trying again in %ss.",
                type(exc).__name__,
                wait_between,
                extra={"component": "worker.lifecycle"},
            )
        await asyncio.sleep(wait_between)


async def warn_if_enrichment_is_unmanned(ctx: dict, delay: float | None = None) -> None:
    """Say so, once, when enrichments are queued for a worker nobody started.

    The setting says where an enrichment goes; only the queue can say whether
    anything is reading it. arq refreshes a per-queue health key every
    ``health_check_interval`` with a TTL one second longer, so its absence one
    interval after this process booted means no enrichment worker is up —
    every enrichment then sits in its queue, kept but not run, and nothing
    would otherwise say why reputation data stopped appearing.

    Waits that interval first, because at boot the other process may be coming
    up beside this one. Never raises, and says it once: a worker that shouts
    every ten minutes teaches its reader to skip the line.
    """
    from app.worker.enrich_worker import ENRICHMENT_QUEUE, enrichment_worker_is_alive

    wait = EnrichmentWorkerSettings.health_check_interval + 1 if delay is None else delay
    await asyncio.sleep(wait)
    try:
        if not await runtime_config.get("enrichment_dedicated_worker"):
            return
        alive = await enrichment_worker_is_alive(ctx.get("redis"))
    except Exception as exc:  # noqa: BLE001 — a warning never costs the worker
        logger.debug("Could not check the enrichment worker (%s).", type(exc).__name__)
        return
    if alive is False:
        logger.warning(
            "Enrichment is queued for its own worker (api.enrichment_dedicated_worker "
            "is on) and nothing is reading %s. Enrichments are kept in the queue and "
            "will run when a worker starts: run "
            "'arq app.worker.enrich_worker.EnrichmentWorkerSettings', or turn the "
            "setting off to have this worker run them between analyses.",
            ENRICHMENT_QUEUE,
            extra={"component": "worker.lifecycle"},
        )


async def startup(ctx: dict) -> None:
    """Called when the ARQ worker starts up."""
    # Initialize logging for the worker process first: the CRITICAL bootstrap
    # failure log below must go through the configured JSON stdout handler,
    # not the ``logging.lastResort`` stderr handler a bare logger falls back
    # to before ``setup_logging()`` attaches one.
    setup_logging()

    from app.bootstrap import BootstrapProblem, require_bootstrap

    try:
        require_bootstrap(get_settings())
    except BootstrapProblem as exc:
        logger.critical(str(exc))
        raise

    logger.info(ghidra_samples_path_line(settings), extra={"component": "worker.lifecycle"})

    # Clear stale private sample copies left behind by a worker that was
    # killed mid-job (no finally ran) before this one starts taking jobs.
    try:
        from app.worker import sample_files

        # No DB session exists yet at this point in startup (the session
        # factory below is created after this block runs), so there is no
        # store to read a UI override from -- build_settings({}) is model
        # defaults only, same as bare get_settings() used to fall back to,
        # minus the environment read.
        core = build_settings({})
        sample_files.sweep(mirror_dir=core.static.r2.mirror_dir)
        # The directories this worker hands a sidecar a path into. A tool
        # server reads a path argument only inside the roots it was given, and
        # these are the ones the worker itself writes a sample to; without
        # them a sidecar would refuse the sample it was started for.
        sample_files.export_sample_roots(core.static.r2.mirror_dir)
    except OSError as exc:
        logger.warning(
            "Startup sample sweep failed (non-fatal): %s",
            exc,
            extra={"component": "worker.lifecycle"},
        )

    # Create database session factory
    engine = create_async_engine(
        settings.database_url,
        pool_size=5,
        max_overflow=10,
    )
    ctx["db_session"] = async_sessionmaker(engine, expire_on_commit=False)

    # Store a Redis connection for PubSub
    ctx["redis"] = aioredis.from_url(settings.redis_url)
    # Which queue this process reads. The enrichment task asks, because on this
    # queue it shares the worker's one slot with the analyses and gets out of
    # their way; on its own it never does.
    ctx["queue"] = ANALYSIS_QUEUE

    # Repair the phantom 'running' rows a killed worker leaves behind, and
    # keep repairing them: the first pass waits one owner TTL so a crashed
    # worker's last heartbeat has expired before anything is judged, and the
    # passes after it run every ten minutes, which is what reaches a job a
    # still-running worker gave up on.
    ctx["sweep_task"] = asyncio.create_task(sweep_orphans_forever(ctx))
    # And one look at the other queue, once the process that reads it has had
    # a health interval to come up beside this one.
    ctx["enrichment_watch_task"] = asyncio.create_task(warn_if_enrichment_is_unmanned(ctx))

    logger.info(
        "Worker started: connected to DB and Redis",
        extra={"component": "worker.lifecycle"},
    )


async def shutdown(ctx: dict) -> None:
    """Called when the ARQ worker shuts down."""
    # Before the connections they use are closed under them.
    for name in ("sweep_task", "enrichment_watch_task"):
        task: asyncio.Task | None = ctx.get(name)
        if task is not None:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task

    # Each close is bounded: a connection that does not close would otherwise
    # hold the shutdown open before the process ever reaches its exit.
    redis_conn: aioredis.Redis | None = ctx.get("redis")
    if redis_conn:
        with suppress(TimeoutError):
            await asyncio.wait_for(redis_conn.aclose(), timeout=EXIT_GRACE)

    db_session = ctx.get("db_session")
    if db_session:
        # Dispose the engine
        engine = db_session.kw.get("bind")
        if engine:
            with suppress(TimeoutError):
                await asyncio.wait_for(engine.dispose(), timeout=EXIT_GRACE)

    logger.info(
        "Worker shutdown complete",
        extra={"component": "worker.lifecycle"},
    )
    arm_the_exit_guard()


# The enrichment task lives in a sibling module. Importing it at module
# scope is fine — ``enrich_worker`` only re-enters this module lazily from
# inside its function, so there is no real circular dependency.
from app.worker.enrich_worker import (  # noqa: E402
    EnrichmentWorkerSettings,
    enrich_threat_intel,
    purge_old_job_events,
)

# Resident-memory ceiling for the worker process, in MiB. Above this, the
# worker finishes reporting the job it just completed and then exits so Docker
# restarts it clean.
#
# The measured problem: one analysis takes the process from ~3.4 GB to ~8.5 GB
# and it never comes back, on a 30 GB host that also runs a ~15 GB llama-server.
# Two analyses in a row exhausted RAM and all 8 GB of swap, at which point LLM
# inference crawls and analysts start hitting their own wall-clock caps — a
# memory problem wearing a timeout costume. The machine hard-locked once.
#
# This is a backstop, not the fix, and it is deliberately dumber than the fix:
# whatever the leak turns out to be, and however well the teardown in
# ``run_analysis``'s ``finally`` works, a worker that has grown this large has
# already stopped being safe to keep around.
_RSS_RESTART_MB = float(os.environ.get("WORKER_RSS_RESTART_MB", "6000"))

# Absolute ceiling on end-of-job teardown. Reclaiming a subprocess and a socket
# is never worth holding a finished job — and therefore the whole queue — open.
_TEARDOWN_BUDGET = float(os.environ.get("WORKER_TEARDOWN_TIMEOUT", "60"))


async def _recycle_if_bloated(ctx: dict, *args: Any, **kwargs: Any) -> None:
    """arq ``after_job_end`` hook: exit when the process has grown too large.

    Runs *after* ``finish_job`` has recorded the result, so nothing is lost by
    leaving. ``call_later`` rather than an immediate kill so the hook returns
    and arq can finish its own bookkeeping first; a timer handle is not one of
    the tasks arq's signal handler cancels, so the exit cannot be swallowed.

    SIGTERM, not ``os._exit``: arq's handler runs ``on_shutdown``, which closes
    the database engine and the Redis pool. ``restart: unless-stopped`` in
    compose brings the worker back, and the existing startup orphan sweep
    repairs any job row left mid-flight.
    """
    from maljan.core import memprobe

    rss = memprobe.rss_mb()
    if rss < _RSS_RESTART_MB:
        logger.info("Worker RSS %.0f MB (limit %.0f MB).", rss, _RSS_RESTART_MB)
        return

    logger.critical(
        "Worker RSS %.0f MB exceeds the %.0f MB ceiling — restarting after this job. "
        "Queued jobs are unaffected; the supervisor will bring the worker back.",
        rss,
        _RSS_RESTART_MB,
    )
    try:
        asyncio.get_running_loop().call_later(1.0, os.kill, os.getpid(), signal.SIGTERM)
    except RuntimeError:  # pragma: no cover — no loop means we are already going down
        os.kill(os.getpid(), signal.SIGTERM)


class WorkerSettings:
    """ARQ worker settings — configure connection and task functions."""

    functions = [run_analysis, enrich_threat_intel]
    # The one scheduled task this worker runs: the nightly sweep that bounds
    # ``job_events`` to ``core.events.retention_days``. Off-hour and off-minute
    # so it does not land on top of whatever else a deployment runs at 03:00.
    cron_jobs = [cron(purge_old_job_events, hour=3, minute=17)]
    on_startup = startup
    on_shutdown = shutdown
    after_job_end = _recycle_if_bloated

    redis_settings = build_redis_settings(settings.redis_url)
    # The analyses' queue, named rather than defaulted: the enrichment reads
    # one of its own (``enrich_worker.EnrichmentWorkerSettings``) so a 452 s
    # reputation lookup can never be what this worker's single slot is busy
    # with. A deployment that runs one process only turns
    # ``api.enrichment_dedicated_worker`` off, and enrichment is queued here
    # again.
    queue_name = ANALYSIS_QUEUE

    # Worker tuning
    # Phase A fix: max_jobs=1 prevents zombie threads from starving other jobs.
    # job_timeout=28800 (8h) — 2026-07-13 deep-analysis restore. The outer ARQ
    # ceiling must sit ABOVE the sum of the inner per-loop safety nets, or it
    # fires while a run is still legitimately progressing ("a timeout is a bug").
    # Static now runs a full-depth ReAct loop PER CHUNK (~8-10 chunks, up to
    # 1530s each) plus dynamic/CAPE, network, up to 5 revision rounds, judge and
    # the report Composer; a realistic-slow cold-cache run is ~2-4h. 8h is a
    # never-fires safety net: a single-slot LLM can't run two jobs at once so a
    # high ceiling costs nothing, and every LLM/CAPE path is bounded by its own
    # inner timeout, so this only trips on a true hang outside those paths. Was
    # 3600 (60 min), sized for the pre-restore shallow static pass.
    #
    # ``max_jobs`` is arq's CONCURRENCY limit — how many jobs run at once — not
    # a "recycle the worker after N jobs" counter. arq has no such counter;
    # ``after_job_end`` above is what bounds process lifetime here.
    max_jobs = 1
    job_timeout = 28800
    max_tries = 1  # Don't retry failed analyses automatically
    health_check_interval = 30


async def _supersede_previous_report(db: Any, job_id: Any) -> None:
    """Drop any existing report row for ``job_id`` so a re-run can persist.

    One report per job remains the right constraint — a job has one current
    result, not a history — so a second run replaces rather than accumulates.
    ``agent_findings`` and ``agent_messages`` are ``ondelete="CASCADE"``, which
    is what we want here: their contents describe the superseded analysis and
    would otherwise stay attached to a report that no longer exists. The
    evidence ledger hangs off the job instead of the report, so no cascade
    reaches it and it is deleted here by hand — otherwise a re-run's ledger
    would be the two runs' calls interleaved under one job.

    The delete is flushed before the caller adds the new row; leaving both in
    one flush puts two rows with the same ``job_id`` in the same statement
    batch and collides exactly as before.

    Never raises. The analysis is already finished by the time this runs, and a
    failed pre-check must not be the thing that loses its result — the insert
    below will surface any real problem on its own.
    """
    try:
        from app.models.evidence import EvidenceEntry
        from app.models.report import AnalysisReport

        await db.execute(delete(EvidenceEntry).where(EvidenceEntry.job_id == job_id))

        existing = (
            await db.execute(select(AnalysisReport).where(AnalysisReport.job_id == job_id))
        ).scalar_one_or_none()
        if existing is None:
            return
        logger.warning(
            "Report for job %s already exists (id=%s); superseding it with this run.",
            job_id,
            getattr(existing, "id", "<unknown>"),
            extra={"job_id": str(job_id), "component": "report"},
        )
        await db.delete(existing)
        await db.flush()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not check for a previous report on job %s (%s).", job_id, exc)
