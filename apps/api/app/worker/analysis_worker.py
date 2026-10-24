"""ARQ worker — executes MaljanApp pipeline in a background process.

This worker is started separately from the API server:

    arq app.worker.analysis_worker.WorkerSettings

It picks up jobs from Redis and runs the full multi-agent analysis
pipeline, streaming progress events via Redis PubSub.
"""

import asyncio
import functools
import gc
import json
import os
import platform
import signal
import threading
import time
import traceback
import uuid
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import redis.asyncio as aioredis
from arq import cron
from maljan.agents.base_agent import CANCEL_DELIVERY_GRACE
from maljan.core.cancellation import Cancellation, JobCancelled
from maljan.core.config import MEDIATOR_AGENT_NAME
from maljan.core.config import Settings as _CoreSettings
from maljan.core.report_formats import declarations_in_effect, recorded_signature_scale
from maljan.core.settings_catalog import core_catalog
from maljan.core.settings_overrides import (
    StoredValueRefused,
    build_settings,
    public_snapshot,
    settings_from_store,
    trim_declarations,
)
from maljan.pipeline.events import MODEL_USAGE as MODEL_USAGE_EVENT
from maljan.pipeline.outcome import absent_analysis_message
from maljan.providers.errors import AttachedReportRefused, ProviderError
from pydantic import ValidationError
from sqlalchemy import Select, delete, func, select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from app.config import get_settings, settings
from app.logging_config import get_logger, setup_logging
from app.runtime_config import runtime_config
from app.services.job_events import STREAM_TTL_SECONDS, stream_key
from app.worker.queues import ANALYSIS_QUEUE, build_redis_settings
from app.worker.sample_integrity import (
    SampleIntegrity,
    copies_of,
    ended_record,
    sandbox_target_of,
    with_record,
)

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
    afterwards, so the model's choices and bounds apply to them too
    (``Settings`` does not validate on assignment). The provider names a job
    gives are checked against their registries, as the submit route checks
    them (``_KnownJobConfig``), so a job naming a provider nothing registered
    fails here rather than when its first model is built.
    """
    merged = dict(overrides)
    if job_config:
        from maljan.core.plugins import ALLOW_LIST_PATH

        from app.schemas.job import PLUGINS_ALLOWED_CONTEXT, _KnownJobConfig

        # Judged by the allow-list these settings carry, as the save was.
        _KnownJobConfig.model_validate(
            {
                key: job_config[key]
                for key in ("llm_provider", "static_provider", "sandbox_provider")
                if job_config.get(key) is not None
            },
            context={PLUGINS_ALLOWED_CONTEXT: overrides.get(ALLOW_LIST_PATH) or []},
        )
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
    # A stored value the model refuses fails the job, naming the key and the
    # remedy; a run never takes a default in its place.
    settings = settings_from_store(merged, stored_keys=overrides)
    # The selected provider's role models come from its own block; a job never
    # runs with an empty model name borrowed from nowhere.
    from maljan.llm.provider_base import role_block_problem

    problem = role_block_problem(settings)
    if problem:
        raise JobSettingsRefused({"llm.provider": problem})
    return settings


def job_questions(job_config: Mapping[str, Any] | None) -> list[str]:
    """The questions a job was submitted with (``config.questions``), blanks left out.

    Read by the report's question round; a job with none asks nothing.
    """
    from maljan.reporting.question_round import asked_questions

    return asked_questions((job_config or {}).get("questions"))


class JobSettingsRefused(ValueError):
    """Settings a job would run with, refused here: each by its setting, with why.

    Every reason is a sentence the platform composes from setting names and
    the ids its provider registry issued (``provider_base.role_block_problem``),
    never a value an operator typed or another component's words, so a job's
    message states it whole. A plain ``ValueError`` from anywhere else is
    stated by its class alone (``run_analysis``).
    """

    def __init__(self, refused: Mapping[str, str]) -> None:
        self.refused = dict(refused)
        super().__init__("; ".join(f"{key}: {why}" for key, why in self.refused.items()))


def take_the_job_plugin_set(overrides: Mapping[str, Any]) -> None:
    """Load the provider plugins the job's own stored settings allow, and withdraw the rest.

    Run as a job starts, before its settings are built, so a plugin's own
    settings block is read with its model; nothing after this changes the
    registries until the next job starts. A store read while the job runs (a
    runtime setting, an enrichment) loads and withdraws nothing, so a list
    saved meanwhile applies to the next job, as every other setting does.
    """
    from maljan.core.plugins import ALLOW_LIST_PATH, load_allowed

    load_allowed(overrides.get(ALLOW_LIST_PATH))


def retired_environment_lines(environ: Mapping[str, str]) -> list[str]:
    """One line per retired variable still set: it is read no more, and which key holds it.

    ``settings_annotations.RETIRED_ENVIRONMENT`` names each one; the value
    itself is not repeated, only where it lives now.
    """
    from maljan.core.settings_annotations import RETIRED_ENVIRONMENT

    return [
        f"{variable} is set and no longer read; the setting {key} holds the value now "
        "(the migration that retired it copied the variable there once, only if the setting "
        "accepts its value, it differs from the shipped one and the store held none)."
        for variable, key in RETIRED_ENVIRONMENT.items()
        if str(environ.get(variable, "")).strip()
    ]


def mirror_lines(core: Any) -> list[str]:
    """The lines the worker states at start: where each static provider's sample copy goes.

    One per static provider the settings select (the global one and any
    agent's own) that mirrors: the directory its copy is written to on this host, and
    the path its server is handed, which is that copy under the server's
    declared ``sample_mount`` (or the host path itself when it declares
    none). A mount that does not match the server's own makes every load
    answer "file not found", so each pair is said once, where an operator
    reads the start.
    """
    from maljan.core.tool_declarations import selected_static_providers
    from maljan.providers.base import path_in_server
    from maljan.providers.registry import static_provider_class, static_provider_ids

    lines: list[str] = []
    selected = selected_static_providers(core)
    for provider_id in static_provider_ids():
        if provider_id not in selected:
            continue
        try:
            provider = static_provider_class(provider_id).from_settings(core)
            if not provider.capabilities.needs_sample_mirror:
                continue
            spec = provider.mirror_spec()
        except Exception:  # noqa: BLE001 - a line not stated never stops the start
            continue
        if spec is None:
            continue
        host = Path(settings.samples_dir) / Path(spec.work_subdir).name / "<sha256>"
        lines.append(
            f"Static provider '{provider_id}' mirrors a sample to {host} "
            f"and is handed it as {path_in_server(spec, host)}."
        )
    return lines


async def load_the_allowed_plugins(session_factory: Any) -> None:
    """Load the provider plugins the stored allow-list names, saying each load or failure.

    At start, off the event loop, so a plugin that fails is named in this
    worker's log before any job; each job then loads by the list its own
    settings carry (``take_the_job_plugin_set``). A store that cannot be read
    leaves that to the first job, and the start goes on.
    """
    from maljan.core.plugins import ALLOW_LIST_PATH, load_allowed

    from app.services.settings_service import load_core_overrides

    try:
        async with session_factory() as db:
            overrides = await load_core_overrides(db)
        await asyncio.to_thread(load_allowed, overrides.get(ALLOW_LIST_PATH))
    except Exception as exc:  # noqa: BLE001 - the start never stops on a plugin
        logger.warning(
            "The allowed provider plugins were not loaded at start (%s); the first job loads them.",
            type(exc).__name__,
            extra={"component": "worker.lifecycle"},
        )


async def state_the_mirrors(session_factory: Any) -> None:
    """State each static provider's copy under the stored settings; sweep and export its dir.

    The sweep at start runs before there is a session, on the shipped
    settings; this reads the store, so the lines name the mounts an operator
    saved, a stale copy in a mirror directory the store names is swept, and
    that directory is a sample root from the start. A store that cannot be
    read leaves the shipped settings', and the start goes on.
    """
    from maljan.providers.registry import mirror_work_dirs

    from app.services.settings_service import effective_core_settings
    from app.worker import sample_files

    try:
        async with session_factory() as db:
            core = await effective_core_settings(db)
    except Exception as exc:  # noqa: BLE001 - the start never stops on a statement
        logger.warning(
            "The stored settings were not read for the mirror statement (%s); "
            "it names the shipped settings' mounts.",
            type(exc).__name__,
            extra={"component": "worker.lifecycle"},
        )
        core = build_settings({})
    for line in mirror_lines(core):
        logger.info(line, extra={"component": "worker.lifecycle"})
    try:
        subdirs = mirror_work_dirs(core)
        sample_files.sweep(subdirs=subdirs)
        sample_files.export_sample_roots(subdirs)
    except OSError as exc:
        logger.warning(
            "The stored mirror directories were not swept and exported as sample roots (%s).",
            type(exc).__name__,
            extra={"component": "worker.lifecycle"},
        )


def mirror_target_for(
    provider: Any, *, sha256: str, extension: str, job_id: str = ""
) -> tuple[Path, str] | None:
    """Where this sample has to be copied for the static provider to read it.

    Returns (host path, container-visible path), or None when the provider does
    not need a copy at all — a capa/YARA or radare2 run that reads the bytes in
    place, and every future provider that does the same. The host directory and
    its 0o700/0o600 handling stay in ``sample_files``; only the decision moved.
    """
    from maljan.providers.base import path_in_server

    from app.worker import sample_files

    if not provider.capabilities.needs_sample_mirror:
        return None
    spec = provider.mirror_spec()
    if spec is None:
        return None
    # The spec's own subdirectory, not a fixed one. This was ``work_dir()``
    # unconditionally, which put r2's copy in the hidden ``.work`` that radare2
    # refuses to open — BUG 10, every live r2 tool call answering "Failed to
    # open file."
    # Named by the job as well, so a server that names a program by its file
    # holds one program per job, not one per sample.
    host = sample_files.work_dir(spec.work_subdir) / sample_files.copy_name(
        sha256, extension, job_id
    )
    # The path the server opens is its own: under the mount its block
    # declares, or the host path for a server on this filesystem. One mount
    # for every server handed a second containerised server another one's.
    return host, path_in_server(spec, host)


def servers_this_job_binds(container: Any) -> set[str] | None:
    """The tool servers this job can call, or ``None`` when the job cannot say.

    One answer, ``composition.servers_a_job_calls``: the servers of every agent
    the team runs or can ask, the judge and report agents, the triage pack's
    reputation lookups and the generic static provider's server. A container
    with no profile to read answers ``None``.
    """
    keys = getattr(container, "analyst_keys", None)
    if not callable(keys):
        return None
    from maljan.agents.composition import servers_a_job_calls

    return servers_a_job_calls(container.config)


def mirror_server_samples(
    container: Any,
    *,
    temp_path: str,
    sha256: str,
    extension: str,
    copy_fn: Callable[[Path, Path], None],
    job_id: str = "",
    already: Iterable[Path] = (),
) -> tuple[list[Path], dict[str, str]]:
    """Copy the sample once for each tool server of this job that declares a ``sample_mount``.

    Only a server some agent of this job can reach (:func:`servers_this_job_binds`)
    is copied the sample; a server no agent binds gets nothing.

    A server that sees the samples directory at a mount of its own is handed
    the sample there, whether a static provider drives it or an agent is bound
    to it: the copy goes under its declared ``work_dir`` and the path it opens
    is that copy under its mount (``providers.base.path_in_server``), as a
    static provider's is. Returns the host copies this call wrote (a copy in
    ``already``, written for a static provider, is not written twice) and the
    path each server opens, by server key. A server that declares no mount
    reads the worker's own filesystem, or is staged to (``agents.sample_staging``),
    and gets nothing here. A failure is logged per server, and the rest go on.
    """
    from maljan.providers.base import MirrorSpec, path_in_server
    from maljan.tools.roots import add_sample_root

    from app.worker import sample_files

    written: list[Path] = []
    copied = set(already)
    paths: dict[str, str] = {}
    servers = getattr(getattr(container.config, "mcp", None), "servers", None) or {}
    bound = servers_this_job_binds(container)
    for key, cfg in servers.items():
        if not getattr(cfg, "enabled", True) or not str(getattr(cfg, "sample_mount", "") or ""):
            continue
        if bound is not None and str(key) not in bound:
            continue
        try:
            spec = MirrorSpec.of(cfg)
            host = sample_files.work_dir(spec.work_subdir) / sample_files.copy_name(
                sha256, extension, canonical_job_id(job_id)
            )
            # A directory the sidecars may read a path in, named before any
            # server starts (see ``mirror_static_samples``).
            add_sample_root(host.parent)
            if host not in copied:
                copy_fn(Path(temp_path), host)
                written.append(host)
                copied.add(host)
            paths[str(key)] = path_in_server(spec, host)
        except Exception as exc:  # noqa: BLE001 - one server never stops the others
            logger.warning(
                "Failed to mirror the sample for a tool server's declared mount (%s).",
                type(exc).__name__,
                extra={"job_id": job_id, "component": "sample-mirror"},
            )
            continue
        logger.info(
            "Mirrored sample to %s for tool server '%s' (%s).",
            host,
            key,
            paths[str(key)],
            extra={"job_id": job_id, "component": "sample-mirror"},
        )
    return written, paths


def place_server_file(
    container: Any,
    server_key: str,
    source: Path,
    sha256: str,
    name: str,
    *,
    job_id: str,
    held: list[Path],
) -> str | None:
    """Copy a file of the job's artefact store for ``server_key``'s mount; the path it opens it at.

    The file reaches a server that declares a ``sample_mount`` as the sample
    does (:func:`mirror_server_samples`): a private copy under the server's
    ``work_dir`` of the samples directory, named by its digest, this job and
    its name's suffix, held by this job and released with the job's other
    mirrors (``held``). The server's mount stays as the deployment made it
    (read-only where it is). ``None`` for a server that declares no mount, or
    a copy that failed, which is logged.
    """
    from maljan.providers.base import MirrorSpec, path_in_server

    from app.worker import sample_files

    servers = getattr(getattr(container.config, "mcp", None), "servers", None) or {}
    cfg = servers.get(server_key)
    if cfg is None or not str(getattr(cfg, "sample_mount", "") or ""):
        return None
    try:
        spec = MirrorSpec.of(cfg)
        host = sample_files.work_dir(spec.work_subdir) / sample_files.copy_name(
            sha256, sample_files.safe_suffix(name), canonical_job_id(job_id)
        )
        sample_files.held_copy(Path(source), host, job_id=canonical_job_id(job_id))
        held.append(host)
    except Exception as exc:  # noqa: BLE001 - a file not placed is said by the step
        logger.warning(
            "Failed to place an artefact for a tool server's declared mount (%s).",
            type(exc).__name__,
            extra={"job_id": job_id, "component": "sample-mirror"},
        )
        return None
    return path_in_server(spec, host)


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
                job_id=canonical_job_id(job_id),
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
    # The declarations an operator set are recorded; the rest are named by a
    # digest (``settings_overrides.trim_declarations``). The stored values are
    # read from ``overridden_keys`` when it is the overrides mapping itself.
    stored = overridden_keys if isinstance(overridden_keys, Mapping) else {}
    snap = trim_declarations(snap, core_settings, stored)
    # A report format declared under a built-in's name ran merged over the
    # built-in; the snapshot records that, not the bare fields it set.
    snap["sandbox.report_formats"] = declarations_in_effect(core_settings.sandbox.report_formats)
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
        # Characters written out of the queued events (``store_text``),
        # reported with the batch that carried them. ``_publish_event`` writes
        # them out before an event reaches any sink, so this is the table's
        # own guarantee and counts only what reached it some other way.
        self._nul_replaced = 0

    async def add(self, seq: int, event_type: str, data: dict[str, Any], ts: str) -> None:
        """Queue one event, writing the batch when it is full or old enough.

        A NUL or a lone surrogate in the type or the payload is written out
        first: PostgreSQL refuses both in text and jsonb, and one such event
        would drop the whole batch it was queued in.
        """
        from app.services import store_text

        event_type, in_type = store_text.without_nul(str(event_type))
        data, in_data = store_text.without_nul(data)
        async with self._lock:
            self._nul_replaced += in_type + in_data
            self._pending.append(
                {
                    "seq": int(seq),
                    "type": event_type[:64],
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
            replaced, self._nul_replaced = self._nul_replaced, 0
            self._last_flush = time.monotonic()
        if not rows:
            return
        if replaced:
            from app.services import store_text

            logger.warning(
                "%d refused character(s) in %d event(s) of job %s are stored written out "
                "(NUL as %s).",
                replaced,
                len(rows),
                self.job_id,
                store_text.NUL_WRITTEN,
                extra={"job_id": self.job_id, "component": "pubsub"},
            )
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

# Per job, how many characters the publisher wrote out of its events
# (``store_text``); read into the run summary when the report is stored and
# forgotten with the feed.
_EVENT_REPLACED: dict[str, int] = {}


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
    _EVENT_REPLACED.pop(job_id, None)
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
        await redis_conn.set(key, int(highest), nx=True, ex=STREAM_TTL_SECONDS)
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
            await redis_conn.expire(_seq_key(job_id), STREAM_TTL_SECONDS)
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


def _registration_failed(scope: str) -> None:
    """Hold finding rows to the whole scrub while ``scope``'s values are unread. Never raises."""
    try:
        from maljan.pipeline.events import secret_registration_failed

        secret_registration_failed(scope)
    except Exception as exc:  # noqa: BLE001 — the publisher's scrub still runs
        logger.debug("The scrub was not told of an unread scope (%s).", type(exc).__name__)


def remember_process_secrets(core_settings: Any = None) -> None:
    """Hand the scrub the secrets this worker holds from its start, kept for its life.

    The worker's own database, Redis and object-store credentials, and the
    core settings it starts with. Registered under the ``process`` scope, which
    a job never replaces. Never raises: a failure here leaves the shape rules.
    """
    try:
        from maljan.core.settings_catalog import configured_secret_values
        from maljan.pipeline.events import remember_secret_values

        sources = [get_settings()] + ([core_settings] if core_settings is not None else [])
        remember_secret_values(configured_secret_values(*sources), scope="process")
    except Exception as exc:  # noqa: BLE001 — the shape rules still run
        _registration_failed("process")
        logger.warning(
            "The worker's configured values were not handed to the scrub (%s).",
            type(exc).__name__,
        )


def remember_configured_secrets(core_settings: Any) -> None:
    """Hand the scrub the secret values of this job's settings, to be masked by value.

    Model API keys, sandbox, Ghidra and tool-server credentials. A value an
    operator chose can have any shape — a passphrase reads as words to every
    shape rule — so these are masked as themselves wherever the scrub runs in
    this process. Registered under the ``job`` scope, which the next job's
    settings replace: a secret no longer configured is not masked after it.
    The worker's own credentials are the ``process`` scope's
    (``remember_process_secrets``). The Windows function names the previous
    job's hash resolution read, which the scrub kept as written, are forgotten
    here too: the job scope starts empty. Never raises.
    """
    from maljan.pipeline.events import forget_resolved_names

    forget_resolved_names()
    try:
        from maljan.core.settings_catalog import configured_secret_values
        from maljan.pipeline.events import remember_secret_values

        remember_secret_values(configured_secret_values(core_settings), scope="job")
    except Exception as exc:  # noqa: BLE001 — the shape rules still run
        _registration_failed("job")
        logger.warning(
            "The job's configured values were not handed to the scrub (%s).", type(exc).__name__
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
    """Publish a pipeline progress event to Redis PubSub + Stream + the table. Never raises.

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
    try:
        import json

        seq = await _next_seq(redis_conn, job_id)
        if stamp is not None:
            stamp["seq"] = seq
        # Scrubbed here, once, for all three sinks. Seven producers build these
        # payloads and a new one cannot be relied on to remember; the publisher is
        # where the wire begins, so it is where the guarantee belongs. Producers
        # may still scrub, and this second pass changes nothing for two reasons:
        # the scrub repeats its passes until they change nothing, so it is
        # idempotent over its own output; and the producers that bound scrubbed
        # text — the argument and result summaries — cut it with
        # ``events._cut_whole``, which keeps a digest or an identifier whole and
        # moves a cut that a scrub would change (inside a URL, after a scheme word)
        # back to the start of its word. A producer that cuts scrubbed text any
        # other way has no such guarantee. The recorder's copy is
        # scrubbed where it is taken (``_make_event_sink``), not here: it is taken
        # before this coroutine is even scheduled, and on the paths the recorder
        # exists for this coroutine never runs.
        stamped = {**scrubbed(data or {}), "seq": seq}
        # Written out once, here, so the socket, the replay stream and the
        # table carry one payload (``store_text``): the table refuses a NUL or
        # a lone surrogate, and a live feed that differed from its replay
        # would be two records of one event. Counted for the run summary.
        from app.services import store_text

        stamped, _in_data = store_text.storable(stamped)
        event_type, _in_type = store_text.storable(str(event_type))
        _replaced = _in_data.total + _in_type.total
        if _replaced:
            _EVENT_REPLACED[job_id] = _EVENT_REPLACED.get(job_id, 0) + _replaced
            logger.warning(
                "The %s event of job %s carried %d character(s) PostgreSQL refuses; they "
                "are sent and stored written out (NUL as %s).",
                event_type,
                job_id,
                _replaced,
                store_text.NUL_WRITTEN,
                extra={"job_id": job_id, "component": "pubsub"},
            )
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
        if event_type == MODEL_USAGE_EVENT:
            # A model call's usage is committed as soon as this publish runs,
            # with whatever is queued before it: the run summary that would carry
            # it is built only at the end of the run, and a process killed before
            # then would otherwise take what the run spent with it. The publish
            # is scheduled from the call's own thread rather than awaited by it,
            # so the guarantee is "committed once the loop runs the publish",
            # normally milliseconds after the call is recorded; a process killed
            # inside that window loses that one call's row. One transaction per
            # model call, which takes seconds anyway.
            #
            # It is a record, not progress: the console draws nothing from it,
            # and the live socket and the 1,000-entry replay stream are left to
            # the events a reader follows. ``job_events`` keeps it, for as long
            # as it keeps the rest of the feed (``core.events.retention_days``).
            if buffer is not None:
                await buffer.flush()
            return
        await redis_conn.publish(f"analysis:{job_id}", message)
        # Persist into the bounded Stream so the live page can replay missed
        # events when it mounts after the worker already started publishing.
        try:
            await redis_conn.xadd(
                stream_key(job_id),
                {"payload": message},
                maxlen=1000,
                approximate=True,
            )
            # 24h TTL — every read keeps the key fresh; idle keys vanish.
            await redis_conn.expire(stream_key(job_id), STREAM_TTL_SECONDS)
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
    except Exception as exc:  # noqa: BLE001 — a lost feed never costs a run
        # Total, as every caller relies on: the run's own record is the
        # report, the ledger and the transcript, and a Redis that dropped its
        # connection must not take a finished report with it. Said, never
        # swallowed: the event is named with the reason it did not go out.
        logger.warning(
            "Could not publish the %s event of job %s (%s: %s); the run continues "
            "without it on the live feed.",
            event_type,
            job_id,
            type(exc).__name__,
            exc,
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
    out, ``waited_ms`` is how long it queued before it was sent and
    ``duration_ms`` is what it measured from then; their sum is the only moment
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
        waited = max(0.0, float(entry.get("waited_ms", 0) or 0) / 1000.0)
        duration = max(0.0, float(entry.get("duration_ms", 0) or 0) / 1000.0)
        return datetime.fromtimestamp(seconds + waited + duration, tz=UTC)
    except (OverflowError, OSError, ValueError):
        return None


def _job_spill(container: Any) -> Any:
    """The job's store for whole answers, as its container holds it; ``None`` without one."""
    getter = getattr(container, "get_evidence_spill", None)
    return getter() if callable(getter) else None


def _null_paths(value: Any) -> list[list[str]] | None:
    """A ledger entry's ``args_nulls_*`` paths as the row stores them; ``None`` for none."""
    if not isinstance(value, list) or not value:
        return None
    return [[str(part) for part in path] for path in value if isinstance(path, list)] or None


def _evidence_row(
    entry: dict[str, Any], *, job_id: uuid.UUID, written_at: datetime | None = None
) -> Any:
    """One ledger entry as the row that keeps it.

    Every one of the 31 fields ``maljan.schemas.evidence.LedgerEntry`` carries
    has a column here, which is what lets a reader of the stored ledger say why an output
    is empty instead of guessing. An absent value stays absent rather than
    becoming a default, for the same reason. ``written_at`` is the moment the
    ledger is stored, the ``created_at`` of a call the recorder never stamped;
    the stored ledger passes it so every column the row's digest covers is
    known before the insert.
    """
    from app.models.evidence import EvidenceEntry

    return EvidenceEntry(
        # When the call returned, which is what a reader of a ledger wants and
        # what the column could not say: the rows are written in one batch at
        # the end of the run, so every one of them carried the flush time — one
        # measured run's thirty entries had one distinct ``created_at`` between
        # them. The entry knows: ``started_at`` is the call's own clock and
        # ``duration_ms`` is how long it took. A row whose entry was never
        # stamped takes the moment the ledger is stored, which is what the
        # server default gave, rather than inventing a moment.
        created_at=_returned_at(entry) or written_at,
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
        waited_ms=int(entry.get("waited_ms", 0) or 0),
        seq=int(entry.get("seq", 0) or 0),
        args=entry.get("args") or {},
        args_repaired=bool(entry.get("args_repaired", False)),
        args_raw=(str(entry["args_raw"]) if entry.get("args_raw") else None),
        model=(str(entry["model"])[:300] if entry.get("model") else None),
        output=str(entry.get("output", "") or ""),
        structured=entry.get("structured"),
        function_ranges=entry.get("function_ranges") or None,
        # Why the output is empty, what the call was answered from, what it
        # was aimed at, and when it ran. ``LedgerEntry.started_at`` defaults to
        # 0.0 rather than to None, so an entry the recorder never stamped and
        # one that started at the epoch are one value; it is stored as NULL,
        # because 0.0 there means "not recorded" and a 1970 timestamp on a tool
        # call is not a fact about anything.
        truncated=bool(entry.get("truncated", False)),
        chars_dropped=int(entry.get("chars_dropped", 0) or 0),
        repeated_of=(str(entry["repeated_of"])[:32] if entry.get("repeated_of") else None),
        symbol=(str(entry["symbol"])[:200] if entry.get("symbol") else None),
        started_at=(float(entry["started_at"]) if entry.get("started_at") else None),
        # The seven fields the entry carries beside the call itself, whole and
        # uncut. Each is absent where the entry has none, and
        # ``structured_from_server`` is kept only when it is true, the rule
        # ``LedgerEntry``'s dump keeps.
        source=(str(entry["source"]) if entry.get("source") is not None else None),
        facts=entry.get("facts"),
        reputation=entry.get("reputation"),
        pack_step=entry.get("pack_step"),
        structured_from_server=(True if entry.get("structured_from_server") is True else None),
        agent_role=(str(entry["agent_role"]) if entry.get("agent_role") is not None else None),
        agent_tab=(str(entry["agent_tab"]) if entry.get("agent_tab") is not None else None),
        # The nulls the tool boundary dropped or the transport withheld, by
        # path segments; absent where the call had none.
        args_nulls_dropped=_null_paths(entry.get("args_nulls_dropped")),
        args_nulls_withheld=_null_paths(entry.get("args_nulls_withheld")),
        # The references to the parts of the answer kept whole, as the entry
        # carries them; absent where nothing was taken.
        spilled=(list(entry["spilled"]) if entry.get("spilled") else None),
    )


def rows_to_store(ledger: list[Any], *, job_id: str) -> list[dict[str, Any]]:
    """The ledger's entries as they are written: one per id and per ``seq``, in ``seq`` order.

    The table holds each ``entry_id`` and each ``seq`` once per job, and a
    second row under either would refuse the whole stored report. The first
    entry under an id or a position is kept, as the container's collection
    keeps it, and every one left out is named in a warning. The state holds
    the entries in node-completion order; written in ``seq`` order, the table's
    row order is the order the ids were issued in.
    """
    ids: set[str] = set()
    seqs: set[int] = set()
    kept: list[dict[str, Any]] = []
    repeated: list[str] = []
    for entry in ledger:
        if not isinstance(entry, dict):
            continue
        entry_id = str(entry.get("id", ""))[:32]
        seq = int(entry.get("seq", 0) or 0)
        if entry_id in ids or seq in seqs:
            repeated.append(f"{entry_id or '?'}/seq {seq}")
            continue
        ids.add(entry_id)
        seqs.add(seq)
        kept.append(entry)
    if repeated:
        logger.warning(
            "Evidence ledger of job=%s holds %d entr(y/ies) under an id or seq already "
            "stored; the first is kept, these are not: %s",
            job_id,
            len(repeated),
            ", ".join(repeated),
            extra={"job_id": job_id},
        )
    kept.sort(key=lambda entry: int(entry.get("seq", 0) or 0))
    return kept


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
# delivered anywhere else (``base_agent.CANCEL_DELIVERY_GRACE``).
PIPELINE_STOP_GRACE = CANCEL_DELIVERY_GRACE
EXIT_GRACE = CANCEL_DELIVERY_GRACE
# How long a worker shutting down gives the stopped job to keep what it
# produced — its partial report and run summary — before it goes on without
# them; the same grace. Measured at about 0.1 s of work on run 7 (a 342-entry
# ledger and a 2.1 MB report) plus one commit. A keep that does not fit leaves
# the row to the orphan sweep, as before.
STOP_KEEP_GRACE = CANCEL_DELIVERY_GRACE


def shutdown_budget_seconds() -> float:
    """The longest SIGTERM takes to end this worker with a job in flight.

    The pipeline's stop grace, keeping the stopped run, the job's teardown
    (``WORKER_TEARDOWN_TIMEOUT``), the closing of its two connections and the
    exit guard, in that order: 10 s + 10 s + 60 s + 2 × 10 s + 10 s as
    shipped. The compose file's ``stop_grace_period`` for the worker is this
    sum, so ``docker stop`` does not kill the worker inside it.
    """
    return PIPELINE_STOP_GRACE + STOP_KEEP_GRACE + _TEARDOWN_BUDGET + 2 * EXIT_GRACE + EXIT_GRACE


async def await_the_pipeline(task: asyncio.Task[Any], cancellation: Cancellation) -> Any:
    """The pipeline task's result, and a stop that reaches all of it when this job is cancelled.

    The job's own task being cancelled — the worker shutting down on SIGTERM —
    used to reach the pipeline only as a cancellation of
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


async def hold_queue_claim(redis_conn: Any, arq_job_id: str | None) -> bool:
    """Give arq's in-progress key for this job the owner heartbeat's life. Never raises.

    arq writes that key once, when it starts a job, to live for the job
    timeout plus ten seconds. With no job timeout (``WorkerSettings``) that is
    as good as for ever, and a worker killed mid-job would leave its job's
    queue entry claimed for good. Set to the owner TTL, the claim is a
    liveness lease: it lives exactly as long as a live worker renews it, and a
    killed worker's claim expires within ``JOB_OWNER_TTL_SECONDS``, after
    which arq ends the queue entry (``max_tries`` is one) instead of keeping
    it. PEXPIRE never creates a key.

    False when the key is gone (the job finished and arq removed it), which
    ends the renewal; True otherwise, a Redis that could not answer included,
    so a blip does not end a lease that is still wanted.
    """
    if not arq_job_id:
        return False
    try:
        from arq.constants import in_progress_key_prefix

        held = await redis_conn.pexpire(
            in_progress_key_prefix + arq_job_id, JOB_OWNER_TTL_SECONDS * 1000
        )
    except Exception as exc:  # noqa: BLE001 — the claim lives on its own TTL
        logger.debug(
            "Could not refresh the queue claim for job %s (%s).",
            arq_job_id,
            type(exc).__name__,
            extra={"job_id": arq_job_id},
        )
        return True
    return bool(held)


# Where a job's queue-lease renewal is kept in its arq context, from the job's
# start hook to its end hook.
_QUEUE_LEASE = "maljan_queue_lease"


async def _renew_queue_claim(redis_conn: Any, arq_job_id: str) -> None:
    """Renew the lease twice per TTL until the job ends or its key is gone."""
    while True:
        await asyncio.sleep(JOB_OWNER_REFRESH_SECONDS)
        if not await hold_queue_claim(redis_conn, arq_job_id):
            return


async def lease_queue_claim(ctx: dict) -> None:
    """arq ``on_job_start``: turn every job's queue claim into a lease, from its first moment.

    Every function on this worker — the analysis, an enrichment queued here,
    the nightly purge — runs under the no-deadline job timeout, so each one's
    in-progress key would otherwise live for years. The key is set to the
    owner TTL before the function is called and renewed by a task of its own
    until ``release_queue_claim`` ends it. Never raises.
    """
    redis_conn = ctx.get("redis")
    arq_job_id = ctx.get("job_id")
    if redis_conn is None or not arq_job_id:
        return
    await hold_queue_claim(redis_conn, str(arq_job_id))
    ctx[_QUEUE_LEASE] = asyncio.create_task(_renew_queue_claim(redis_conn, str(arq_job_id)))


async def release_queue_claim(ctx: dict) -> None:
    """arq ``on_job_end``: stop renewing the job's lease, before arq finishes it. Never raises."""
    task = ctx.pop(_QUEUE_LEASE, None)
    if task is None:
        return
    task.cancel()
    with suppress(asyncio.CancelledError, Exception):
        await task


async def hold_job_owner(redis_conn: Any, job_id: str) -> None:
    """Refresh this job's claim until the task running this is cancelled.

    Two refreshes inside one TTL, so a missed write — a Redis blip, a loop that
    was busy — does not expire the claim on its own. arq's own claim on the
    queue entry is a lease of the same life, held for every job by
    ``lease_queue_claim``.

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


async def queued_or_owned(redis_conn: Any, job_ids: list[str]) -> set[str] | None:
    """Which of these pending jobs something will still start.

    A job is held while arq keeps its queue entry (the job key, written under
    the job's own id by ``analysis_service._enqueue_analysis``) or its claim on
    that entry, or a worker writes an owner heartbeat for it. ``None`` when
    Redis cannot answer, as for :func:`live_owners`. One read for all of them,
    linear in their number.
    """
    if not job_ids:
        return set()
    from arq.constants import in_progress_key_prefix, job_key_prefix

    global _QUEUE_UNREADABLE_SAID
    keys = [
        key
        for job_id in job_ids
        for key in (
            job_owner_key(job_id),
            job_key_prefix + job_id,
            in_progress_key_prefix + job_id,
        )
    ]
    try:
        values = await redis_conn.mget(keys)
    except Exception as exc:  # noqa: BLE001 — an unreadable queue is not a verdict
        _log_unreadable_queue(type(exc).__name__)
        return None
    _QUEUE_UNREADABLE_SAID = False
    return {
        job_id
        for index, job_id in enumerate(job_ids)
        if any(value is not None for value in values[3 * index : 3 * index + 3])
    }


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
    this key behind, a worker shutting down does not, and the job timeout is
    the heartbeat's own reading of its clock.
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


async def mark_job_cancelled(
    db_session: async_sessionmaker, job_uuid: uuid.UUID, *, reason: str | None = None
) -> bool:
    """Record the operator's cancellation on a session of its own. Never raises.

    The same rule the failure marker follows, for the same reason: the session
    the run was writing through is the one a lost connection leaves unusable,
    and a cancelled job whose row still says ``running`` is the phantom this
    work exists to remove. Only a job that was still running is touched — a run
    that finished while the cancel was in flight keeps its result. ``reason``,
    when given, is what the row says about where the run was when it stopped.
    """
    from app.models.job import AnalysisJob

    values: dict[str, Any] = {"status": "cancelled", "completed_at": datetime.now(UTC)}
    if reason:
        values["error_message"] = reason[:2000]
    try:
        async with db_session() as db:
            await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_uuid, AnalysisJob.status.in_(("pending", "running")))
                .values(**values)
            )
            if reason:
                # The API's cancel writes ``cancelled`` itself before it sets
                # the flag this worker reads, so the row is usually already
                # cancelled here and the statement above matches nothing. The
                # reason still belongs on it: written to a cancelled row that
                # carries none, and never over a message already there.
                await db.execute(
                    update(AnalysisJob)
                    .where(
                        AnalysisJob.id == job_uuid,
                        AnalysisJob.status == "cancelled",
                        AnalysisJob.error_message.is_(None),
                    )
                    .values(error_message=reason[:2000])
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


def kept_report_note(failed_step: str, exc: BaseException, error_id: str) -> str:
    """What a report kept from a failed run says about itself.

    Where the run failed and the id the log entries are filed under, and the
    class of the exception, never its message: the same rule
    ``failure_reason`` follows for the job row.
    """
    return (
        f"This report was built and the run failed after it: {failed_step} raised "
        f"{type(exc).__name__} (error id {error_id}). The job is failed and this "
        "report is incomplete: nothing the run would have done after it is in it."
    )


# Where a run failed when the graph had returned and the worker then failed on
# its way to the store, as a kept report's note names it.
POST_GRAPH_STEP = "the worker storing the result the graph returned"


def storable_after_graph(result: Mapping[str, Any] | None, core_settings: Any) -> bool:
    """Whether ``result``, the graph's return, is a report the completed path would store.

    Not an absent analysis (``absent_analysis_message``), not a report node
    that raised (``report_error``), and carrying a report unless reporting is
    off for the job, the same three checks the completed path makes.
    """
    if not isinstance(result, Mapping):
        return False
    if absent_analysis_message(dict(result)) or result.get("report_error"):
        return False
    reporting = getattr(getattr(core_settings, "reporting", None), "enabled", True)
    return bool(result.get("malware_report")) or not reporting


def swept_while_running() -> Any:
    """A row the orphan sweep marked failed, which a finished run may still complete.

    The sweep marks a running job failed when its owner heartbeat expired
    (``_SWEPT_NO_OWNER``), which a Redis outage longer than the heartbeat's TTL
    does to a job that is still running. Its result is still this run's to
    record. A cancelled row, a completed one and one failed for any other
    reason stand.
    """
    from app.models.job import AnalysisJob

    return (AnalysisJob.status == "failed") & (AnalysisJob.error_message == _SWEPT_NO_OWNER)


def stored_after_note(row_status: str | None) -> str:
    """What a report stored under a job that was no longer running says about itself."""
    return (
        f"Stored after the job was {row_status or 'removed'}: the run finished and its "
        "report is kept, but the job row's status stands and the run was not recorded "
        "as completed."
    )


async def job_status_in(db: Any, job_uuid: uuid.UUID) -> str | None:
    """The job row's status as ``db`` reads it; ``None`` when there is no row."""
    from app.models.job import AnalysisJob

    result = await db.execute(select(AnalysisJob.status).where(AnalysisJob.id == job_uuid))
    value = result.scalar_one_or_none()
    return value if isinstance(value, str) else None


async def job_status_now(db_session: async_sessionmaker, job_uuid: uuid.UUID) -> str | None:
    """The job row's status on a session of its own. Never raises; ``None`` when unread."""
    try:
        async with db_session() as db:
            return await job_status_in(db, job_uuid)
    except Exception as exc:  # noqa: BLE001 — a read that fails decides nothing
        logger.warning(
            "Could not read the status of job %s (%s).",
            job_uuid,
            type(exc).__name__,
            extra={"job_id": str(job_uuid)},
        )
        return None


async def report_row_exists(db_session: async_sessionmaker, report_id: uuid.UUID) -> bool:
    """Whether the report row with ``report_id`` is stored.

    Read on a session of its own, by the id of the report this run stored.
    Never raises; a read that fails decides nothing (``False``).
    """
    try:
        from app.models.report import AnalysisReport

        async with db_session() as db:
            result = await db.execute(
                select(AnalysisReport.id).where(AnalysisReport.id == report_id)
            )
            return bool(result.scalar_one_or_none() == report_id)
    except Exception as exc:  # noqa: BLE001 — a read that fails decides nothing
        logger.warning(
            "Could not read the stored report %s (%s).",
            report_id,
            type(exc).__name__,
            extra={"report_id": str(report_id)},
        )
        return False


def completion_missed(result: Any) -> bool:
    """Whether a status update matched no row, as its driver result says.

    A result that does not say (no integer ``rowcount``) is taken as matched.
    """
    count = getattr(result, "rowcount", None)
    return isinstance(count, int) and count == 0


async def keep_the_built_report(
    db_session: async_sessionmaker,
    *,
    job_uuid: uuid.UUID,
    job_id: str,
    built: dict[str, Any],
    note: str,
    transcript: list[dict[str, Any]],
    core_settings: Any,
    override_keys: Any,
    hash_mismatch_reason: str | None,
    scale_record: Mapping[str, Any] | None = None,
    container: Any = None,
    sample_integrity: Any = None,
) -> bool:
    """Store a report a failed run built, marked incomplete. Never raises.

    ``built`` is the state the report node built its report from, with what
    it wrote merged in (``MaljanApp.built_report``). The report is stored the
    way a completed run stores one — findings, evidence ledger, transcript —
    with ``incomplete_reason`` set to ``note``, and the note is added to the
    degradation reasons the report and the run summary already carry, so every
    surface that shows a degraded run shows this one. The job row is not
    touched: it stays ``failed``. The ledger stored is the state's with every
    entry ``container``'s agents still held added (``with_undrained_evidence``).
    """
    try:
        from maljan.pipeline.state import with_undrained_evidence

        state = with_undrained_evidence(dict(built), container)
        malware_report = state.get("malware_report")
        if isinstance(malware_report, dict):
            malware_report = dict(malware_report)
            malware_report["degraded_mode"] = True
            malware_report["degradation_reasons"] = [
                *(malware_report.get("degradation_reasons") or []),
                note,
            ]
            state["malware_report"] = malware_report
        stix_bundle, run_summary = _report_inputs(
            state,
            core_settings=core_settings,
            override_keys=override_keys,
            hash_mismatch_reason=hash_mismatch_reason,
            scale_record=scale_record,
            sample_integrity=await ended_record(sample_integrity),
            sandbox_target=sandbox_target_of(container),
        )
        _end_the_token_ledger(container)
        run_summary["degraded_mode"] = True
        run_summary["degradation_reasons"] = [
            *(run_summary.get("degradation_reasons") or []),
            note,
        ]
        async with db_session() as db:
            report = await _store_the_report(
                db,
                job_uuid=job_uuid,
                job_id=job_id,
                pipeline_result=state,
                stix_bundle=stix_bundle,
                run_summary=run_summary,
                transcript=transcript,
                incomplete_reason=note,
                core_settings=core_settings,
                spill=_job_spill(container),
            )
            await db.commit()
            report_id = report.id
        logger.warning(
            "Kept the report the failed run built: report=%s job=%s. %s",
            report_id,
            job_id,
            note,
            extra={"job_id": job_id, "component": "report"},
        )
        return True
    except Exception as exc:  # noqa: BLE001 — the run has already failed
        logger.error(
            "Could not keep the report the failed run built (%s); job=%s.",
            type(exc).__name__,
            job_id,
            exc_info=True,
            extra={"job_id": job_id, "component": "report"},
        )
        return False


# ── A run stopped part-way ──────────────────────────────────────

# Why a run stopped before it finished, as the job row and the report say it.
STOP_TIMEOUT = "timeout"
STOP_CANCEL = "cancel"
STOP_SHUTDOWN = "shutdown"
# A cancellation that reached the pipeline while nobody stopped the job: no
# timeout, no cancel flag, and the job's own task not being cancelled.
STOP_UNEXPLAINED = "unexplained"

# The clock a job's timeout is measured on, from the moment the job starts. A
# name rather than a call written inline, so a test can move it hours
# ahead without waiting for them.
job_clock: Callable[[], float] = time.monotonic


def job_timeout_reached(limit: int | None, started: float, now: float) -> bool:
    """Whether a job that started at ``started`` has run for its whole ``limit``.

    ``None`` is no limit, and no length of run reaches it.
    """
    return limit is not None and now - started >= limit


def stop_note(kind: str, *, seconds: float, where: str, limit: int | None = None) -> str:
    """What a stopped job and its partial report say about the stop.

    Why it stopped, how far into the run, and where the pipeline was, in words
    this module wrote: ``where`` is ``Cancellation.where_stopped``, which names
    graph nodes and nothing a model or a tool wrote.
    """
    if kind == STOP_TIMEOUT:
        why = f"Stopped by the job timeout ({limit} s, core.job_timeout)"
    elif kind == STOP_CANCEL:
        why = "Cancelled by the operator"
    elif kind == STOP_SHUTDOWN:
        why = "Stopped because the worker running it shut down"
    else:
        why = (
            "Stopped by a cancellation inside the pipeline that neither the operator, the "
            "job timeout nor a worker shutdown made"
        )
    return (
        f"{why} {seconds:.0f} s into the run, {where}. The report kept is partial: it holds "
        "what the run produced before it stopped, and nothing the run would have done "
        "after it."
    )


async def keep_the_stopped_run(
    db_session: async_sessionmaker,
    *,
    job_uuid: uuid.UUID,
    job_id: str,
    app: Any,
    note: str,
    transcript: list[dict[str, Any]],
    core_settings: Any,
    override_keys: Any,
    hash_mismatch_reason: str | None,
    sample_integrity: Any = None,
) -> bool:
    """Store what a stopped run produced: its run summary and a partial report. Never raises.

    The state is what the run had when it stopped (``stopped_run.stopped_state``);
    the run summary is read as of the stop and the report is the one the run
    built or was building, or the deterministic one from the state
    (``stopped_run.partial_report``). Both carry ``note`` among their
    degradation reasons and the report row carries it as ``incomplete_reason``,
    so every surface that shows a degraded or incomplete run shows this one.
    The findings, the evidence ledger and the transcript are stored with it as
    a completed run's are. The job row is not touched here.
    """
    if app is None:
        return False
    try:
        from maljan.pipeline.stopped_run import (
            NO_VERDICT_DECISION,
            judge_ran,
            partial_report,
            stopped_run_summary,
            stopped_state,
        )

        state = stopped_state(app)
        container = getattr(app, "container", None)
        summary = stopped_run_summary(state, container, note=note)
        report_dump = partial_report(state, container, note=note)
        state["run_summary"] = summary
        state["malware_report"] = report_dump
        if not judge_ran(state):
            state["final_decision"] = NO_VERDICT_DECISION
        stix_bundle, run_summary = _report_inputs(
            state,
            core_settings=core_settings,
            override_keys=override_keys,
            hash_mismatch_reason=hash_mismatch_reason,
            scale_record=recorded_signature_scale(container),
            sample_integrity=await ended_record(sample_integrity),
            sandbox_target=sandbox_target_of(container),
        )
        _end_the_token_ledger(container)
        async with db_session() as db:
            report = await _store_the_report(
                db,
                job_uuid=job_uuid,
                job_id=job_id,
                pipeline_result=state,
                stix_bundle=stix_bundle,
                run_summary=run_summary,
                transcript=transcript,
                incomplete_reason=note,
                core_settings=core_settings,
                spill=_job_spill(container),
            )
            await db.commit()
            report_id = report.id
        logger.warning(
            "Kept what the stopped run produced: report=%s job=%s. %s",
            report_id,
            job_id,
            note,
            extra={"job_id": job_id, "component": "report"},
        )
        return True
    except Exception as exc:  # noqa: BLE001 — the stop is recorded whatever happens
        logger.error(
            "Could not keep what the stopped run produced (%s); job=%s.",
            type(exc).__name__,
            job_id,
            exc_info=True,
            extra={"job_id": job_id, "component": "report"},
        )
        return False


# The statuses a failure never overwrites: the operator's cancel, and a
# completion already recorded.
_FAILURE_LEAVES_ALONE: tuple[str, ...] = ("cancelled", "completed")


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
    whatever the run raised on its way down. A ``completed`` row is left alone
    too: a report stored and recorded as complete is never turned into a
    failure by a step after it. A row left alone is said in the log.
    """
    from app.models.job import AnalysisJob

    try:
        async with db_session() as db:
            result = await db.execute(
                update(AnalysisJob)
                .where(
                    AnalysisJob.id == job_uuid,
                    AnalysisJob.status.notin_(_FAILURE_LEAVES_ALONE),
                )
                .values(
                    status="failed",
                    error_message=reason[:2000],
                    completed_at=datetime.now(UTC),
                )
            )
            await db.commit()
        if completion_missed(result):
            logger.warning(
                "Job %s was not marked failed: its row is %s or gone (error_id=%s).",
                job_uuid,
                " or ".join(_FAILURE_LEAVES_ALONE),
                error_id,
                extra={"job_id": str(job_uuid), "error_id": error_id},
            )
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
    # An ATT&CK update the console ran since the last analysis replaced the
    # files a warm catalogue in this process was read from.
    from app.worker.attck_worker import drop_a_replaced_catalogue

    drop_a_replaced_catalogue()

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
    # The copies' readings against the intake digest (``sample_integrity``).
    _integrity: SampleIntegrity | None = None
    # L2 (live-run finding): set below when an attached sandbox report's
    # own claimed hash disagreed with the sample at upload time, so the
    # degradation makes it into both run_summary and the report banner
    # even though nothing in the pipeline itself reads the stored flag.
    _report_hash_mismatch_reason: str | None = None
    # The task that keeps this job's owner heartbeat alive, cancelled by the
    # ``finally`` below so it cannot outlive the run it speaks for.
    owner_task: asyncio.Task | None = None
    # The instant this job started, on the clock its timeout is measured on:
    # the job timeout covers the whole job — the reads, the sample download and
    # the pipeline — and a stop note's "seconds into the run" is read off the
    # same clock from the same instant, so the two numbers cannot disagree.
    job_started = job_clock()
    # The graph's result once it returned, so a failure on the way to the
    # store keeps the report rather than discarding it (``storable_after_graph``).
    post_graph_result: dict[str, Any] | None = None
    # Set once the completion is committed: from then on nothing may record
    # this job as failed.
    completion_recorded = False
    # The id of a report being stored under a job that was no longer running
    # (``stored_after_note``): set before that store's commit, so a commit
    # whose acknowledgement is lost can be told from one that never landed,
    # by that report's own row and never by what a report of the job says.
    stored_report_id: uuid.UUID | None = None
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
            sample_size = sample.file_size_bytes
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
            # the job's own config on top. Stored settings that cannot be read
            # fail the job before any pipeline starts: running on the shipped
            # defaults would drop the operator's spend cap, server map and
            # timeout without the run saying so. The class of the error is
            # logged, never its text (it can quote a connection string).
            #
            # Only an error of the database or of the connection to it is said
            # to be the database's. Any other failure of the read (the merge of
            # the stored rows, say) is no outage to wait out: it reaches the
            # failure path below as itself, named by its class with its
            # traceback in the log, and no pipeline starts either way.
            from app.services.settings_service import (
                load_core_overrides,
                refused_secrets_a_job_uses,
                refusing_undecryptable_secrets,
            )

            try:
                try:
                    with refusing_undecryptable_secrets():
                        overrides = await load_core_overrides(db)
                except StoredValueRefused as exc:
                    # Only a secret this job reads refuses it: a server's token
                    # the team never binds is dropped, as at submission.
                    still = await refused_secrets_a_job_uses(db, exc.refused, job_config)
                    if still:
                        # A stored secret this worker cannot decrypt is the
                        # operator's setting, unreadable: the run never takes the
                        # shipped default in its place. Neither the log nor the
                        # job's own message, which the owner reads, names the
                        # setting: an administrator's submission names it.
                        logger.error(
                            "Job %s refused: %d stored setting(s) it uses could not be read.",
                            job_id,
                            len(still),
                            extra={"job_id": job_id},
                        )
                        raise StatedFailure(
                            "A stored secret this job reads cannot be decrypted, so the job "
                            "did not run on a default in its place. An administrator can "
                            "enter it again in the console (Settings, Configuration); an "
                            "administrator's submission of the same job names the setting."
                        ) from None
                    overrides = await load_core_overrides(db)
            except StoredValueRefused as exc:
                raise StatedFailure(
                    "A stored setting value is refused ("
                    + "; ".join(f"{key}: {why}" for key, why in sorted(exc.refused.items()))
                    + "). Fix it or reset it in the console (Settings, Configuration); "
                    "the job did not run on a default in its place."
                ) from None
            except (SQLAlchemyError, OSError) as exc:
                logger.error(
                    "Failed to load the stored settings (%s); job %s fails rather than "
                    "running on defaults.",
                    type(exc).__name__,
                    job_id,
                    extra={"job_id": job_id},
                )
                raise StatedFailure(
                    "The stored settings could not be read from the database "
                    f"({type(exc).__name__}), so the job did not run on defaults in their "
                    "place. Run it again once the database answers."
                ) from None

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
                # The format the upload route recorded when it accepted the
                # report: the run reads the blob as that format, never sniffs
                # it again, so the row and the run cannot disagree.
                _attached_format = str(attached_report.format)

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

        # The plugin set this job runs with: the stored list read with its
        # settings, loaded off the event loop before the settings are built.
        await asyncio.to_thread(take_the_job_plugin_set, overrides)

        # Settings the model refuses fail the job, loudly and before any
        # pipeline starts. This used to retry on all shipped defaults, which
        # put a less safe value (no spend cap, the shipped server map, no
        # timeout) in place of the operator's without the run saying so; a
        # job runs on the settings it was given, or not at all.
        try:
            core_settings = build_job_settings(overrides, job_config)
        except StoredValueRefused as exc:
            raise StatedFailure(
                "A stored setting value is refused ("
                + ", ".join(sorted(exc.refused))
                + "). Fix it or reset it in the console (Settings, Configuration); "
                "the job did not run on a default in its place."
            ) from None
        except ValidationError as exc:
            # Not a stored key (``settings_from_store`` names those): the
            # job's own options, or a conflict between stored rows. The fields,
            # never the refused values.
            fields = sorted({".".join(str(x) for x in e["loc"]) for e in exc.errors()})
            raise StatedFailure(
                "The settings this job would run with are refused ("
                + ", ".join(fields)
                + "). Fix them in the console or in the job's options; the job did "
                "not run on defaults in their place."
            ) from None
        except JobSettingsRefused as exc:
            # The refusals ``build_job_settings`` writes from setting names and
            # registered ids: stated by setting, with why, as the arms above
            # state the keys and fields they name.
            stated = "; ".join(f"{key}: {why}" for key, why in sorted(exc.refused.items()))
            raise StatedFailure(
                f"The settings this job would run with are refused: {stated}. Fix them in "
                "the console; the job did not run on defaults in their place."
            ) from None
        except ValueError as exc:
            # Any other refusal: its class, never its text, which can quote the
            # value refused (a stored secret among them). The rule the job's
            # failure reason and the field-named arm above follow.
            logger.error(
                "The settings job %s would run with are refused (%s); it fails rather "
                "than running on defaults.",
                job_id,
                type(exc).__name__,
                extra={"job_id": job_id},
            )
            raise StatedFailure(
                f"The settings this job would run with are refused ({type(exc).__name__}). "
                "Fix them in the console; the job did not run on defaults in their place."
            ) from None
        # Agents, pipeline nodes and extractors read the process singleton
        # (``get_settings()``), not the config handed to MaljanApp. With
        # ``max_jobs = 1`` installing this job's Settings there is what
        # makes a UI override reach every consumer, not only the container.
        # The object stays installed after the job: ``enrich_threat_intel``
        # runs in this process too but reads only API settings and
        # ``runtime_config`` today; if it ever needs core config it must
        # install its own.
        install_settings(core_settings)
        remember_configured_secrets(core_settings)
        # Read once, from this job's own settings: a value saved while the job
        # runs applies to the next job, and this one keeps what it started with.
        _job_timeout: int | None = getattr(core_settings, "job_timeout", None)
        logger.info(
            "Job timeout: %s.",
            "none (no limit)" if _job_timeout is None else f"{_job_timeout} s",
            extra={"job_id": job_id},
        )
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
        # Whether the analysts run in parallel is decided from their
        # endpoints: a name resolved and a server's /props asked, which are
        # network round trips and do not belong on this loop.
        from maljan.pipeline.analyst_mode import resolve_for

        _analyst_mode = await asyncio.to_thread(resolve_for, core_settings, mock=_mock_active)
        app = MaljanApp(
            config=core_settings,
            mock=_mock_active,
            job_id=job_id,
            analyst_mode=_analyst_mode,
            # The job's secrets are registered above (``remember_configured_secrets``).
            remember_secrets=False,
            # Long-term memory is the job owner's alone.
            memory_owner=str(job.created_by),
            event_sink=_make_event_sink(
                redis_conn,
                job_id,
                asyncio.get_running_loop(),
                recorder=transcript,
            ),
        )
        # What the run shortens, blanks or drops from a ledger entry's answer
        # is kept whole in object storage under this job's prefix, and the
        # entry references it (``maljan.schemas.evidence_spill``).
        from app.services import object_store

        app.container.set_evidence_spill(await object_store.job_evidence_spill(job_id))

        # A job that names an attached report hands its bytes to the
        # sandbox provider before anything else runs: build_job_settings
        # already forced sandbox.provider="upload" above, so the provider
        # this container builds is the one that reads what the operator
        # brought instead of detonating anything. The row itself was read
        # and checked in the session above; what is left here needs the
        # container rather than the database.
        if attached_report is not None:
            from maljan.core.report_formats import UNREAD_FORMAT, UNREAD_RUN_REASON

            from app.api.v1.sandbox_reports import get_object

            # L2: the upload endpoint's mismatch warning promises "The
            # analysis will still run and will say so in its findings" —
            # nothing threaded the stored flag into the run until now. A
            # report accepted unread claims no target to compare: the run says
            # it was read unread instead.
            if _attached_format == UNREAD_FORMAT:
                _report_hash_mismatch_reason = UNREAD_RUN_REASON
            elif _attached_hash_matches is False:
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
            # can be a MockSandboxProvider, whose set_pending_blob only refuses.
            # Checked by capability, not by provider id, the same way every
            # other branch in this layer is: a raw error escaping to
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
            _attached_blob = await asyncio.to_thread(get_object, _attached_storage_path)
            try:
                sandbox_provider.set_pending_blob(
                    _attached_blob,
                    filename=f"{_attached_row_id}.json",
                    report_format=_attached_format,
                )
            except AttachedReportRefused as exc:
                # A recorded format no longer declared, or declared without a
                # reader: the attached evidence cannot be read, and the run
                # says so rather than going on without it, in the sentence the
                # platform composed from the format's name and its settings.
                raise StatedFailure(str(exc)) from None
            except ProviderError as exc:
                # Any other provider's own words (a plug-in sandbox's): its
                # class, never its text, which can carry a value; the rule the
                # job's other messages follow.
                logger.error(
                    "The sandbox provider refused the attached report of job %s (%s).",
                    job_id,
                    type(exc).__name__,
                    extra={"job_id": job_id},
                )
                raise StatedFailure(
                    "The configured sandbox provider could not read the attached sandbox "
                    f"report ({type(exc).__name__}); the job did not run without it."
                ) from None

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
        server_sample_paths: dict[str, str] = {}
        try:
            from app.services import object_store

            minio_client = object_store.client()
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
            # The suffix only where it is plain (``sample_files.safe_suffix``):
            # it names every copy a tool is handed.
            from app.worker.sample_files import safe_suffix

            _orig_ext = safe_suffix(sample_filename)
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
            # 0o600 on the file (``object_store.download``); the parent dir
            # is already 0o700 (owner-only) via ``sample_files.temp_dir()``,
            # so this file is unreachable to anyone but the worker's own user
            # either way.
            # Held for this job (``sample_files.hold_copy``): the name is the
            # sample's, so a second job on the same sample reaches it too, and
            # neither job's end may take it from the other.
            await asyncio.to_thread(
                sample_files.hold_copy,
                Path(temp_path),
                canonical_job_id(job_id),
                lambda target: object_store.download(minio_client, derived_path, str(target)),
            )
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
            # Off the loop: a copy of a large sample onto a slow volume stopped
            # the heartbeat and every other coroutine of this worker.
            new_mirrors, new_sample_paths = await asyncio.to_thread(
                functools.partial(
                    mirror_static_samples,
                    app.container,
                    temp_path=temp_path,
                    sha256=sample_sha256,
                    extension=_orig_ext,
                    copy_fn=functools.partial(
                        sample_files.held_copy, job_id=canonical_job_id(job_id)
                    ),
                    job_id=job_id,
                )
            )
            host_mirrors.extend(new_mirrors)
            static_sample_paths.update(new_sample_paths)
            # And for each tool server that declares a mount of its own, a
            # copy under it, whichever agent its tools are bound to.
            server_mirrors, server_sample_paths = await asyncio.to_thread(
                functools.partial(
                    mirror_server_samples,
                    app.container,
                    temp_path=temp_path,
                    sha256=sample_sha256,
                    extension=_orig_ext,
                    copy_fn=functools.partial(
                        sample_files.held_copy, job_id=canonical_job_id(job_id)
                    ),
                    job_id=job_id,
                    already=host_mirrors,
                )
            )
            host_mirrors.extend(server_mirrors)
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
        if temp_path:
            _integrity = SampleIntegrity(
                sample_sha256,
                copies_of(temp_path, host_mirrors),
                size=sample_size,
                job_id=job_id,
            )
            await _integrity.started()

        # Execute the asynchronous pipeline natively to
        # avoid "Event loop is closed" errors caused by threading mismatches.
        # Heartbeat task keeps the job alive in the DB and logs progress.
        heartbeat_stop_event = asyncio.Event()
        pipeline_task: asyncio.Task | None = None
        cancelled_by_user = False
        # Set by the heartbeat when it is what stopped the run: the job
        # timeout. The operator's cancel has ``cancelled_by_user``; a stop
        # neither of them made is the worker shutting down.
        stopped_by_timeout = False

        async def _heartbeat() -> None:
            # The heartbeat is also the cancellation
            # poller. `cancel_job` sets `analysis:{job_id}:cancel`; the
            # pipeline is a single long `await`, so cancelling that task is
            # the only way to stop the run. Previously the worker checked the
            # job status exactly once (before starting), so a cancel issued
            # mid-run was ignored and the finished pipeline overwrote the
            # `cancelled` row with `completed`/`failed`.
            #
            # It is also the job timeout's clock, read on the same poll: a
            # job with a ``core.job_timeout`` is stopped the way an operator's
            # cancel stops it, so it keeps what it produced, within one poll of
            # its limit. A job with none is never stopped here.
            nonlocal cancelled_by_user, stopped_by_timeout
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
                    if job_timeout_reached(_job_timeout, job_started, job_clock()):
                        stopped_by_timeout = True
                        logger.warning(
                            "Job timeout reached for job=%s (%s s) — stopping pipeline.",
                            job_id,
                            _job_timeout,
                            extra={"job_id": job_id, "component": "heartbeat"},
                        )
                        app.container.cancellation.cancel(
                            f"the job timeout of {_job_timeout} s was reached"
                        )
                        if pipeline_task is not None:
                            pipeline_task.cancel()
                        return
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
        # A file of the job's artefact store reaches a server that declares a
        # mount as the sample does: the worker's copy under that mount, held by
        # this job and released with its mirrors when it ends.
        app.container.place_for_server = functools.partial(
            place_server_file, app.container, job_id=job_id, held=host_mirrors
        )
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
                    server_sample_paths=server_sample_paths,
                    # The same instant this job's own duration is measured
                    # from, so the report's elapsed time and the job row
                    # cannot disagree.
                    started_at=start_time,
                    # What the analyst asked of the run, answered in the
                    # report (``reporting.question_round``); none asks nothing.
                    questions=job_questions(job_config),
                )
            )
            pipeline_result = await await_the_pipeline(pipeline_task, app.container.cancellation)
        except (asyncio.CancelledError, JobCancelled) as stop_exc:
            # Three things stop a run before it finishes, and each keeps what
            # the run produced. The job timeout is the heartbeat's own reading
            # of its clock. An operator's cancel leaves its flag in Redis — the
            # heartbeat may have read it already, or the cancel may have
            # arrived between two of its polls. Anything else is the worker
            # shutting down, which cancels this task and waits for it.
            heartbeat_stop_event.set()
            if not stopped_by_timeout and not cancelled_by_user:
                cancelled_by_user = await cancel_was_requested(redis_conn, job_id)
            # A shutdown is this task itself being cancelled, which is what
            # ``cancelling()`` counts; a cancellation that reached the pipeline
            # while nobody stopped the job is recorded as that, never as a
            # shutdown that did not happen.
            _current = asyncio.current_task()
            if stopped_by_timeout:
                _kind = STOP_TIMEOUT
            elif cancelled_by_user:
                _kind = STOP_CANCEL
            elif _current is not None and _current.cancelling():
                _kind = STOP_SHUTDOWN
            else:
                _kind = STOP_UNEXPLAINED
            # Worded from where the pipeline was: a check's own record when
            # one stopped it, otherwise the nodes that were running when the
            # task was cancelled under them.
            _stopped = app.container.cancellation.where_stopped()
            _into = max(0.0, job_clock() - job_started)
            _note = stop_note(_kind, seconds=_into, where=_stopped, limit=_job_timeout)
            logger.info(
                "Pipeline stopped (%s): job=%s (stopped %s, %.0f s into the run)",
                _kind,
                job_id,
                _stopped,
                _into,
                extra={"job_id": job_id},
            )
            # What the run produced is stored before the row says how it
            # ended: a console that sees the terminal status fetches the
            # report once, and must find it there. On sessions of its own,
            # like every other outcome this task records: the one it was
            # working through may be the one the cancellation came with.
            if job_uuid is not None:
                _keep = keep_the_stopped_run(
                    db_session,
                    job_uuid=job_uuid,
                    job_id=job_id,
                    app=app,
                    note=_note,
                    transcript=transcript,
                    core_settings=core_settings,
                    override_keys=overrides,
                    hash_mismatch_reason=_report_hash_mismatch_reason,
                    sample_integrity=_integrity,
                )
                if _kind == STOP_SHUTDOWN:
                    # A shutdown is waited on by ``docker stop``, whose grace
                    # is the sum of these bounds (``shutdown_budget_seconds``).
                    try:
                        await asyncio.wait_for(_keep, timeout=STOP_KEEP_GRACE)
                    except TimeoutError:
                        logger.error(
                            "Keeping the stopped run exceeded %.0fs on shutdown and was "
                            "abandoned; job=%s.",
                            STOP_KEEP_GRACE,
                            job_id,
                            extra={"job_id": job_id, "component": "report"},
                        )
                else:
                    await _keep
            if _kind == STOP_CANCEL:
                await _publish_event(
                    redis_conn,
                    job_id,
                    "cancelled",
                    {"stopped": _stopped, "seconds_into_run": round(_into, 1)},
                )
                if job_uuid is not None:
                    await mark_job_cancelled(db_session, job_uuid, reason=_note)
            else:
                await _publish_event(
                    redis_conn,
                    job_id,
                    "error",
                    {
                        "status": "failed",
                        "stopped_by": _kind,
                        "stopped": _stopped,
                        "seconds_into_run": round(_into, 1),
                        "message": _note,
                    },
                )
                if job_uuid is not None:
                    await mark_job_failed(
                        db_session, job_uuid, reason=_note, error_id=uuid.uuid4().hex
                    )
            # How this job ends depends on who stopped what. The operator's
            # cancel, the job timeout and an unexplained cancellation reach the
            # pipeline task, not this one: nothing outside is waiting for a ``CancelledError`` here,
            # and raising one puts arq on its retry branch — the job goes back
            # in the queue, is popped again and ends with "max retries
            # exceeded", which reads like a failure nobody had. A finished job
            # is what this is, so it returns like one.
            #
            # A worker shutting down cancels *this* task and waits for it, and
            # ``cancelling()`` is how a task knows that has happened. Then the
            # cancellation must carry on, or the shutdown waits for a task that
            # decided not to end. arq finishes a job it cancelled only on
            # ``CancelledError``; a ``JobCancelled`` reaching it would leave the
            # job unfinished in its bookkeeping, since it is no ``Exception``
            # either. The ``finally`` below runs on every path, so the feed is
            # flushed and the claim released either way.
            if _kind == STOP_SHUTDOWN or (_current is not None and _current.cancelling()):
                if not isinstance(stop_exc, asyncio.CancelledError):
                    raise asyncio.CancelledError from stop_exc
                raise
            if _kind == STOP_CANCEL:
                return {"status": "cancelled", "job_id": job_id}
            return {"status": "failed", "job_id": job_id, "error": _note}
        finally:
            heartbeat_stop_event.set()
            try:
                heartbeat_task.cancel()
                await heartbeat_task
            except asyncio.CancelledError:
                pass
        post_graph_result = pipeline_result

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
        # Every entry the job's counter issued is on the ledger that is
        # stored, including what no node drained (``with_undrained_evidence``);
        # gathered before the run summary below counts the ledger.
        from maljan.pipeline.state import with_undrained_evidence

        pipeline_result = with_undrained_evidence(pipeline_result, getattr(app, "container", None))
        post_graph_result = pipeline_result
        # The enrichment job queued after a stored report is named in its
        # disclosure block, with what it may reach, so that block never says
        # nothing left the machine while a lookup is still to come.
        stix_bundle_for_persist, _run_summary = _report_inputs(
            pipeline_result,
            core_settings=core_settings,
            override_keys=overrides,
            hash_mismatch_reason=_report_hash_mismatch_reason,
            scale_record=recorded_signature_scale(getattr(app, "container", None)),
            sample_integrity=await ended_record(_integrity),
            sandbox_target=sandbox_target_of(getattr(app, "container", None)),
            enrichment=(
                await enrichment_plan(core_settings)
                if pipeline_result.get("malware_report")
                else None
            ),
        )
        _end_the_token_ledger(getattr(app, "container", None))

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
            # ── 5. Mark job complete ─────────────────────────────
            # First in the transaction, so the row is held until the report
            # under it commits: a cancel that arrives meanwhile waits for the
            # commit and then finds the job completed, instead of the two
            # overwriting each other.
            # Use Python ``datetime.now(UTC)`` instead of Postgres ``NOW()``.
            # ``func.now()`` resolves to ``transaction_timestamp()`` which is
            # the START of the current transaction — that equals
            # ``started_at`` and produces a 0-second ``completed_at`` even
            # for a 20-minute pipeline. ``duration_seconds`` is computed in
            # Python anyway so a single clock source is correct.
            now = datetime.now(UTC)
            # The status travels in the statement rather than on a loaded
            # row: this session has never seen the job row, and the one that
            # read it was closed before the pipeline started. Only a row this
            # run still owns is completed: its running row, or the one the
            # orphan sweep took from it (``swept_while_running``). An
            # operator's cancel that landed first stands.
            done: dict[str, Any] = dict(
                status="completed",
                completed_at=now,
                # Round to one decimal so sub-second jobs (~0.7s) don't
                # collapse to zero; the column is ``Numeric(10,2)`` so
                # fractional values survive the round-trip.
                duration_seconds=round(float(elapsed), 1),
            )
            completion = await db.execute(
                update(AnalysisJob)
                .where(AnalysisJob.id == job_uuid, AnalysisJob.status == "running")
                .values(**done)
            )
            if completion_missed(completion):
                # The sweep's message goes with its ``failed``.
                completion = await db.execute(
                    update(AnalysisJob)
                    .where(AnalysisJob.id == job_uuid, swept_while_running())
                    .values(**done, error_message=None)
                )
                if not completion_missed(completion):
                    logger.warning(
                        "Job %s had been marked failed by the orphan sweep while it ran "
                        "(its owner heartbeat lapsed); its finished run completes it.",
                        job_id,
                        extra={"job_id": job_id, "component": "lifecycle"},
                    )
            row_status: str | None = None
            stored_note: str | None = None
            if completion_missed(completion):
                # The row moved on while the report was being built: an
                # operator's cancel, most likely. Its status stands, and the
                # report the run finished is stored under it saying so.
                row_status = await job_status_in(db, job_uuid)
                stored_note = stored_after_note(row_status)
                _run_summary = {
                    **_run_summary,
                    "degraded_mode": True,
                    "degradation_reasons": [
                        *(_run_summary.get("degradation_reasons") or []),
                        stored_note,
                    ],
                }
            report = await _store_the_report(
                db,
                job_uuid=job_uuid,
                job_id=job_id,
                pipeline_result=pipeline_result,
                stix_bundle=stix_bundle_for_persist,
                run_summary=_run_summary,
                transcript=transcript,
                incomplete_reason=stored_note,
                core_settings=core_settings,
                spill=_job_spill(app.container),
            )
            if stored_note is not None:
                stored_report_id = report.id
            await db.commit()
            # Read off the report while its session is still open, so nothing
            # below can send this function back to the database for a value.
            report_uuid = report.id
            report_verdict = report.verdict
            report_confidence = report.overall_confidence
            report_has_malware_report = bool(report.malware_report)

        if stored_note is not None:
            # Not announced as completed, nor remembered, nor enriched: the
            # job is what its row says. The feed is told where the report went.
            logger.warning(
                "Job %s was %s when its report was stored (report=%s); its status was "
                "left as it was and the run is not announced as completed.",
                job_id,
                row_status or "gone",
                report_uuid,
                extra={"job_id": job_id, "component": "lifecycle"},
            )
            await _publish_event(
                redis_conn,
                job_id,
                "status_change",
                {"status": row_status, "report_id": str(report_uuid), "note": stored_note},
            )
            return {
                "status": "not_running_at_completion",
                "row_status": row_status,
                "job_id": job_id,
                "report_id": str(report_uuid),
            }
        completion_recorded = True

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

        # The job is recorded as completed and announced: the long-term-memory
        # case its judge built, and the function hashes it filed under the
        # judge's family, may now teach the next run. Written here and not by
        # the judge, so a job that fails after its judge leaves neither behind;
        # after the ``completed`` event, so a slow store never holds the
        # console's completion back. Off the loop: the store may be Qdrant.
        await asyncio.to_thread(app.remember_the_run)

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
        if (
            not completion_recorded
            and post_graph_result is not None
            and job_uuid is not None
            and await job_status_now(db_session, job_uuid) == "completed"
        ):
            # The completion committed and only its acknowledgement was lost:
            # the complete report is stored, and an incomplete copy kept now
            # would supersede it.
            completion_recorded = True
        if (
            not completion_recorded
            and stored_report_id is not None
            and job_uuid is not None
            and await report_row_exists(db_session, stored_report_id)
        ):
            # The job was no longer running and its report was stored under
            # that note; only the commit's acknowledgement was lost. The report
            # stands: an incomplete copy kept now would supersede it, and the
            # row's own status (the operator's cancel) is not a failure to mark.
            row_now = await job_status_now(db_session, job_uuid)
            logger.error(
                "Job %s: the report stored under its %s row is committed and only the "
                "acknowledgement was lost (error_id=%s); it is kept as it is.",
                job_id,
                row_now,
                error_id,
                extra={"job_id": job_id, "error_id": error_id},
            )
            return {
                "status": "not_running_at_completion",
                "row_status": row_now,
                "job_id": job_id,
                "error_after_store": reason,
            }
        if completion_recorded:
            # The report is stored and the row says ``completed``; a step after
            # that (remembering the run, say) failed. The completion stands.
            logger.error(
                "Job %s failed after its completion was recorded (error_id=%s); the job "
                "stays completed.",
                job_id,
                error_id,
                extra={"job_id": job_id, "error_id": error_id},
            )
            return {"status": "completed", "job_id": job_id, "error_after_completion": reason}
        if job_uuid is not None:
            # A session of its own, always. The session this job read through
            # was closed before the pipeline started, and the one that was
            # writing when a failure happened is exactly the session that may
            # be unusable — a backend killed under it leaves every statement
            # on it raising ``PendingRollbackError``, which is how a run that
            # failed came to publish its ``error`` event and still leave the
            # row saying ``running``, with no error and no ``completed_at``,
            # for as long as the worker stayed up.
            # A report the report node finished is not lost because a later
            # step failed: it is stored against this failed job, marked
            # incomplete with where the run failed. Only when the graph itself
            # raised — a report a finished run produced and the worker then
            # refused (an absent analysis) is not a report to keep. Stored
            # before the row turns ``failed``: a console that sees the terminal
            # status fetches the report once, and must find it there. The keep
            # never raises, so the row below is always marked.
            built = getattr(app, "built_report", None) if app is not None else None
            failed_step = getattr(app, "failed_step", None) if app is not None else None
            # The graph returned and the worker failed on its way to the store:
            # the result the graph returned is the report to keep, when it is
            # one the completed path would have stored.
            if (
                not (built and failed_step)
                and post_graph_result is not None
                and storable_after_graph(post_graph_result, core_settings)
            ):
                built, failed_step = post_graph_result, POST_GRAPH_STEP
            if built and failed_step:
                await keep_the_built_report(
                    db_session,
                    job_uuid=job_uuid,
                    job_id=job_id,
                    built=built,
                    container=getattr(app, "container", None),
                    note=kept_report_note(failed_step, exc, error_id),
                    transcript=transcript,
                    core_settings=core_settings,
                    override_keys=overrides,
                    hash_mismatch_reason=_report_hash_mismatch_reason,
                    scale_record=recorded_signature_scale(getattr(app, "container", None)),
                    sample_integrity=_integrity,
                )
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
            # jobs that use them, on success, failure or cancellation alike
            # (H3, security hardening). Each copy goes with the last job
            # holding it (``sample_files.release_copy``), so a second job on
            # the same sample keeps its copies until it ends too. A no-op on
            # ``None`` (nothing was ever downloaded); never raises.
            from app.worker import sample_files

            sample_files.release_copy(temp_path, job_id=canonical_job_id(job_id))
            for _host_mirror in host_mirrors:
                sample_files.release_copy(_host_mirror, job_id=canonical_job_id(job_id))

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
            servers=container.config.mcp.servers,
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
    return {
        "bundle": judge_bundle_json(bundle),
        "labels": kept_labels,
        "as_written": False,
    }


def judge_bundle_json(bundle: dict) -> dict:
    """The judge's parsed bundle as a JSON column holds it.

    The pipeline keeps the bundle as a Python dump, timestamps as datetimes;
    a column stores JSON, in STIX's own timestamp form. Both columns that can
    hold the judge's bundle — its own record, and the report's bundle when no
    export was made — are written through here.
    """
    from maljan.schemas.stix_models import Bundle

    try:
        as_json = Bundle.model_validate(bundle).model_dump(mode="json")
    except Exception:  # noqa: BLE001 — a record kept in a weaker form, never a failed save
        as_json = json.loads(json.dumps(bundle, default=str))
    return {"spec_version": "2.1", **as_json}


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

# What a swept ``pending`` row says: nothing is left that would ever start it.
_SWEPT_NEVER_STARTED = (
    "This job was never started: its queue entry is gone (expired before a "
    "worker reached it, or ended when the worker that took it stopped before "
    "the run began) and no worker is holding it. Marked failed by the orphan "
    "sweep — re-submit the sample if needed."
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

    A ``pending`` row is repaired the same way, by what would still start it:
    its arq queue entry (the job key, queued under the job's own id) or arq's
    claim on it, or an owner heartbeat. A row with none of the three is one no
    worker will ever reach — the entry expired before a worker got to it, or
    the worker that took it stopped between taking it and starting the run —
    and is marked failed with that reason. A row younger than one TTL is left
    for the next pass, because the API commits it a moment before it queues it.
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
                select(
                    AnalysisJob.id,
                    AnalysisJob.started_at,
                    AnalysisJob.created_at,
                    AnalysisJob.status,
                ).where(AnalysisJob.status.in_(("running", "pending")))
            )
        ).all()
        await db.commit()

    def _since(row: Any) -> Any:
        # ``started_at`` is written with the status change; ``created_at`` is
        # the fallback for a row that somehow carries none, so a job cannot
        # stay ``running`` for ever by having no clock. A pending row has not
        # started: its clock is when it was created.
        if row[3] == "pending":
            return row[2]
        return row[1] or row[2]

    aged = [row for row in candidates if _since(row) is None or _since(row) < young_cutoff]
    if not aged:
        logger.debug("Orphan sweep: nothing old enough to judge.")
        return
    running = [str(row[0]) for row in aged if row[3] == "running"]
    pending = [str(row[0]) for row in aged if row[3] == "pending"]

    owners = await live_owners(redis_conn, running)
    if owners is None:
        return
    orphans = [job_id for job_id in running if job_id not in owners and job_id not in _OWNED_JOBS]
    held = await queued_or_owned(redis_conn, pending)
    if held is None:
        return
    never_started = [
        job_id for job_id in pending if job_id not in held and job_id not in _OWNED_JOBS
    ]
    if not orphans and not never_started:
        logger.debug("Orphan sweep: every running job has an owner, every pending one a queue.")
        return

    await _fail_swept(db_session, orphans, "running", _SWEPT_NO_OWNER)
    await _fail_swept(db_session, never_started, "pending", _SWEPT_NEVER_STARTED)


async def _fail_swept(
    db_session: async_sessionmaker, job_ids: list[str], status: str, reason: str
) -> None:
    """Mark these jobs failed with ``reason``, each only while it still has ``status``."""
    from app.models.job import AnalysisJob

    if not job_ids:
        return
    async with db_session() as db:
        result = await db.execute(
            update(AnalysisJob)
            .where(
                AnalysisJob.id.in_([uuid.UUID(job_id) for job_id in job_ids]),
                # Re-checked in the statement: a worker may have started or
                # finished one of these between the read above and this write.
                AnalysisJob.status == status,
            )
            .values(status="failed", completed_at=func.now(), error_message=reason)
            .returning(AnalysisJob.id)
        )
        affected = [str(row[0]) for row in result.all()]
        await db.commit()

    if affected:
        logger.warning(
            "Orphan sweep: marked %d unowned '%s' job(s) as 'failed': %s",
            len(affected),
            status,
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


# What a running analysis keeps for the whole process rather than for its job.
# Each is right only while one analysis runs in the process at a time, which
# ``WorkerSettings.max_jobs = 1`` is what guarantees.
PROCESS_WIDE_JOB_STATE = (
    "the job's settings, installed as the process's settings (install_settings)",
    "the configured values the event scrub masks by value (pipeline.events, scope 'job')",
    "the API names the job's hash resolution read (pipeline.events.remember_resolved_names)",
)


def concurrent_analyses_refusal(max_jobs: object) -> str | None:
    """Why the worker refuses to start with ``max_jobs``, or ``None`` for one job at a time."""
    if isinstance(max_jobs, bool) or not isinstance(max_jobs, int):
        return f"max_jobs is {max_jobs!r}, which is not a number of jobs; set it to 1."
    jobs = max_jobs
    if jobs == 1:
        return None
    return (
        f"max_jobs is {jobs}; the analysis worker runs one analysis at a time, because "
        + "; ".join(PROCESS_WIDE_JOB_STATE)
        + " are held for the whole process, and two analyses at once would read each "
        "other's. Set max_jobs to 1 and run more worker processes for more analyses at once."
    )


async def repair_long_term_memory() -> str:
    """The configured memory store's one-time repair, off the event loop; what was done.

    Never raises: memory that could not be repaired is tried again at the next
    start.
    """
    try:
        from maljan.memory.memory_repair import repair_memory
        from maljan.memory.store_factory import build_memory_store

        store = await asyncio.to_thread(build_memory_store, await runtime_config.core())
    except Exception as exc:  # noqa: BLE001 — a repair never costs a start
        logger.warning("Long-term memory repair skipped: no store (%s).", type(exc).__name__)
        return "skipped: no store"
    try:
        return await asyncio.to_thread(repair_memory, store)
    finally:
        with suppress(Exception):
            store.close()


async def startup(ctx: dict) -> None:
    """Called when the ARQ worker starts up."""
    # Initialize logging for the worker process first: the CRITICAL bootstrap
    # failure log below must go through the configured JSON stdout handler,
    # not the ``logging.lastResort`` stderr handler a bare logger falls back
    # to before ``setup_logging()`` attaches one.
    setup_logging()

    # Before any job, and so before any thread or the YARA engine loads: C code
    # in this process folds case by LC_CTYPE, and a Turkish one leaves a capital
    # I unfolded (``core.ctype_locale``).
    from maljan.core.ctype_locale import pin_character_classification

    pin_character_classification()

    # Refused before any job is taken: the state an analysis keeps per
    # process is not per job yet, so a second analysis at once is never run.
    refusal = concurrent_analyses_refusal(WorkerSettings.max_jobs)
    if refusal is not None:
        logger.critical(refusal, extra={"component": "worker.lifecycle"})
        raise RuntimeError(refusal)

    from app.bootstrap import BootstrapProblem, require_bootstrap

    try:
        require_bootstrap(get_settings())
    except BootstrapProblem as exc:
        logger.critical(str(exc))
        raise

    for line in retired_environment_lines(os.environ):
        logger.warning(line, extra={"component": "worker.lifecycle"})

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
        remember_process_secrets(core)
        from maljan.providers.registry import mirror_work_dirs

        subdirs = mirror_work_dirs(core)
        sample_files.sweep(subdirs=subdirs)
        # The directories this worker hands a sidecar a path into. A tool
        # server reads a path argument only inside the roots it was given, and
        # these are the ones the worker itself writes a sample to; without
        # them a sidecar would refuse the sample it was started for.
        sample_files.export_sample_roots(subdirs)
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
    # An empty audit anchor is given the current head, beside the start.
    from app.services import audit_anchor

    audit_anchor.start_anchoring(engine)
    await load_the_allowed_plugins(ctx["db_session"])
    await state_the_mirrors(ctx["db_session"])

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
    # One sweep of ``job_events`` as the worker starts, beside its slot rather
    # than in it. The nightly cron fires only in a process alive at 03:17, and
    # arq does not run a window it missed while no worker was up, so a worker
    # started for a run and stopped after it (a local stack) never swept, and
    # neither did a deployment whose worker restarted across the night's window.
    ctx["events_sweep_task"] = asyncio.create_task(purge_old_job_events(ctx))
    # Long-term memory kept before AUD-65, repaired once and beside the slot
    # (``maljan.memory.memory_repair``).
    ctx["memory_repair_task"] = asyncio.create_task(repair_long_term_memory())
    # The console's ATT&CK cache jobs, read beside this worker's one analysis
    # slot rather than in it: this is the process that holds the cache.
    from app.worker.attck_worker import start_attck_worker

    await start_attck_worker(ctx)

    logger.info(
        "Worker started: connected to DB and Redis",
        extra={"component": "worker.lifecycle"},
    )


async def shutdown(ctx: dict) -> None:
    """Called when the ARQ worker shuts down."""
    # Before the connections they use are closed under them.
    from app.worker.attck_worker import stop_attck_worker

    await stop_attck_worker(ctx, EXIT_GRACE)
    for name in ("sweep_task", "enrichment_watch_task", "events_sweep_task", "memory_repair_task"):
        task: asyncio.Task | None = ctx.get(name)
        if task is None:
            continue
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001 — a start task never stops the shutdown
            # Logged, not raised: the Redis close, the engine dispose, the exit
            # guard below and arq's own pool close run whatever a task did.
            logger.error(
                "Worker start task %s had ended with %s; the shutdown goes on.",
                name,
                type(exc).__name__,
                exc_info=(type(exc), exc, exc.__traceback__),
                extra={"component": "worker.lifecycle"},
            )

    # Each close is bounded: a connection that does not close would otherwise
    # hold the shutdown open before the process ever reaches its exit.
    redis_conn: aioredis.Redis | None = ctx.get("redis")
    if redis_conn:
        with suppress(TimeoutError):
            await asyncio.wait_for(redis_conn.aclose(), timeout=EXIT_GRACE)

    # Anchor writes already scheduled finish, bounded, before their engine goes.
    from app.services import audit_anchor

    await audit_anchor.drain(EXIT_GRACE)

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


# What this worker hands arq as its job timeout: none that a job can reach.
#
# arq reads ``job_timeout=None`` as "no deadline" (``asyncio.wait_for`` with no
# timeout), but only on a worker with exactly one function: its constructor
# takes ``max()`` over every function's timeout to size the in-progress key,
# and ``None`` beside ``None`` raises ``TypeError``. This worker has three —
# ``run_analysis``, ``enrich_threat_intel`` and the nightly ``job_events``
# purge — so the longest duration Python's ``timedelta`` holds stands in for
# none (about 2.7 million years; ``test_the_job_timeout_is_a_setting`` proves
# arq accepts it and that Redis can carry the in-progress key it derives). The
# in-progress key of every job on this worker is turned into a lease of the
# owner heartbeat's life before its function is called (``lease_queue_claim``,
# the ``on_job_start`` hook), so the stand-in never decides how long a dead
# worker's claim lingers; only the milliseconds between arq writing the key and
# calling the hook are not covered. A job's real limit, when an operator sets one, is
# ``core.job_timeout``, enforced by ``run_analysis``.
ARQ_NO_JOB_TIMEOUT = timedelta.max.total_seconds()


class WorkerSettings:
    """ARQ worker settings — configure connection and task functions."""

    functions = [run_analysis, enrich_threat_intel]
    # The one scheduled task this worker runs: the nightly sweep that bounds
    # ``job_events`` to ``core.events.retention_days``. Off-hour and off-minute
    # so it does not land on top of whatever else a deployment runs at 03:00.
    # ``startup`` runs the same sweep once more as the worker starts, outside
    # the job slot, for the nights no worker was up at that minute.
    cron_jobs = [cron(purge_old_job_events, hour=3, minute=17)]
    on_startup = startup
    on_shutdown = shutdown
    # Every job's queue claim is a lease of the owner heartbeat's life, from
    # before its function is called until it ends (``lease_queue_claim``).
    on_job_start = lease_queue_claim
    on_job_end = release_queue_claim
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
    #
    # ``max_jobs`` is arq's CONCURRENCY limit — how many jobs run at once — not
    # a "recycle the worker after N jobs" counter. arq has no such counter;
    # ``after_job_end`` above is what bounds process lifetime here. Any other
    # value is refused at startup (``concurrent_analyses_refusal``): the state
    # ``PROCESS_WIDE_JOB_STATE`` names is held per process, not per job.
    max_jobs = 1
    # No job timeout at arq's level: a job's limit is the operator's
    # ``core.job_timeout``, empty by default, which ``run_analysis`` reads from
    # the job's own settings and enforces itself, so a job stopped by it keeps
    # its run summary and a partial report. See ``ARQ_NO_JOB_TIMEOUT``.
    job_timeout = ARQ_NO_JOB_TIMEOUT
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
        # The superseded report's deletion on the audit chain, in this
        # transaction, as every path that deletes a stored report writes it.
        from app.services.audit_chain import DeletionNotChained, record_report_deletion

        try:
            await record_report_deletion(db, existing)
        except DeletionNotChained:
            # The re-run's own result must still be stored; the superseded
            # report's verification will say its deletion was not recorded.
            logger.warning(
                "The superseded report of job %s is deleted without its audit record.",
                job_id,
                extra={"job_id": str(job_id), "component": "report"},
            )
        await db.delete(existing)
        await db.flush()
    except Exception as exc:  # noqa: BLE001
        logger.warning("Could not check for a previous report on job %s (%s).", job_id, exc)


def _end_the_token_ledger(container: Any) -> None:
    """The run summary's token figures are final: a charge landing from now on is marked late.

    Idempotent, and never raises; the container's close is the backstop
    (``TokenLedger.end``).
    """
    try:
        ledger = container.get_token_ledger() if container is not None else None
        if ledger is not None:
            ledger.end()
    except Exception as exc:  # noqa: BLE001 — marking never fails a stored report
        logger.debug("The usage ledger was not marked ended (%s).", type(exc).__name__)


def _report_inputs(
    pipeline_result: dict[str, Any],
    *,
    core_settings: Any,
    override_keys: Any,
    hash_mismatch_reason: str | None,
    scale_record: Mapping[str, Any] | None = None,
    enrichment: list[dict[str, Any]] | None = None,
    sample_integrity: Mapping[str, Any] | None = None,
    sandbox_target: Mapping[str, Any] | None = None,
) -> tuple[dict | None, dict[str, Any]]:
    """The STIX bundle and the run summary a stored report carries.

    Read off the pipeline's state, whether the run completed or failed after
    its report was built: both store the report the same way. ``enrichment``
    is where the enrichment job queued after the report may send its
    indicators (:func:`enrichment_plan`), ``None`` when none is queued.
    """
    # Prefer the rich extended bundle produced by ``report_node``
    # (54+ objects with Identity/Indicator/ObservedData/Note/Report
    # SDOs) over the minimal judge bundle. The legacy field is the
    # fallback for callers that pre-date the MalwareReport refactor.
    stix_bundle_for_persist = pipeline_result.get("stix_bundle_extended")
    if not stix_bundle_for_persist:
        # Without the export (a run stopped inside its report node before the
        # node returned, or an export that was not made) the bundle is the
        # judge's, which the state keeps with datetimes in it.
        judge_bundle = pipeline_result.get("stix_output")
        stix_bundle_for_persist = (
            judge_bundle_json(judge_bundle)
            if isinstance(judge_bundle, dict) and judge_bundle
            else judge_bundle
        )
        if isinstance(stix_bundle_for_persist, dict):
            # The judge's draft, not the export: it did not pass the publish
            # rule, and whoever reads the stored bundle is told.
            # Without the run facts that name other runs' samples (the earlier
            # run, the similar cases): the judge's own stored bundle keeps them.
            from maljan.schemas.stix_models import (
                JUDGE_ONLY_PROPERTIES,
                UNPUBLISHED_NOTICE,
                UNPUBLISHED_PROPERTY,
            )

            stix_bundle_for_persist = {
                **{
                    key: value
                    for key, value in stix_bundle_for_persist.items()
                    if key not in JUDGE_ONLY_PROPERTIES
                },
                UNPUBLISHED_PROPERTY: False,
                "x_maljan_notice": UNPUBLISHED_NOTICE,
            }
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
    _run_summary["settings_snapshot"] = settings_snapshot(core_settings, override_keys)
    # The signature scale the sandbox provider declared for the job's report
    # (``report_formats.recorded_signature_scale``): the console reads a
    # signature's number on it, and a summary without it on its legacy table.
    _run_summary.update(scale_record or {})
    if hash_mismatch_reason:
        # Threaded in here rather than through the pipeline state:
        # the mismatch is known before the graph runs (it is on the
        # stored row, checked at upload time), and both the run
        # summary and the report banner read a plain list of
        # strings, so appending to each is the whole fix.
        _existing_reasons = _run_summary.get("degradation_reasons")
        _run_summary["degradation_reasons"] = [
            *(_existing_reasons if isinstance(_existing_reasons, list) else []),
            hash_mismatch_reason,
        ]
        _malware_report = pipeline_result.get("malware_report")
        if isinstance(_malware_report, dict):
            _report_reasons = _malware_report.get("degradation_reasons")
            _malware_report["degradation_reasons"] = [
                *(_report_reasons if isinstance(_report_reasons, list) else []),
                hash_mismatch_reason,
            ]
    _disclosed(_run_summary, pipeline_result, core_settings=core_settings, enrichment=enrichment)
    # The copies' readings at the job's start and end, said in the isolation
    # part (``sample_integrity``); a job that handed out no copy adds nothing.
    with_record(_run_summary, pipeline_result.get("malware_report"), sample_integrity)
    # A detonating sandbox's report that named another target than the sample
    # (``sandbox_target_of``), said in the same part; none adds nothing.
    from maljan.analysis.sample_integrity import SANDBOX_KEY

    with_record(
        _run_summary, pipeline_result.get("malware_report"), sandbox_target, key=SANDBOX_KEY
    )
    return stix_bundle_for_persist, _run_summary


def _disclosed(
    run_summary: dict[str, Any],
    pipeline_result: dict[str, Any],
    *,
    core_settings: Any,
    enrichment: list[dict[str, Any]] | None,
) -> None:
    """The run's disclosure record as the stored summary and report carry it, set in place.

    A record the run built names the enrichment job queued after the report
    and what it may reach, where ``enrichment`` holds that
    (``analysis.disclosure.with_enrichment``): in the run summary, and in the
    report payload every rendering of the report is made from. A summary
    without a record says why none was built (``analysis.disclosure.not_built``),
    so it is told apart from a run stored before the block existed.
    """
    from maljan.analysis.disclosure import not_built, not_built_reason, with_enrichment

    record = run_summary.get("disclosure")
    if not isinstance(record, dict) or "models" not in record:
        reporting = getattr(getattr(core_settings, "reporting", None), "enabled", True)
        run_summary["disclosure"] = not_built(
            not_built_reason(
                reporting=bool(reporting),
                summary_written=bool(pipeline_result.get("run_summary")),
            )
        )
        return
    if enrichment is None:
        return
    run_summary["disclosure"] = with_enrichment(record, enrichment)
    malware_report = pipeline_result.get("malware_report")
    if not isinstance(malware_report, dict):
        return
    held = malware_report.get("run_summary")
    if isinstance(held, dict) and isinstance(held.get("disclosure"), dict):
        if "models" in held["disclosure"]:
            malware_report["run_summary"] = {
                **held,
                "disclosure": with_enrichment(held["disclosure"], enrichment),
            }


async def enrichment_plan(core_settings: Any) -> list[dict[str, Any]] | None:
    """Where the enrichment job queued after a report may send its indicators; ``None`` when off.

    Read as that job reads it (``enrich_worker.enrich_threat_intel``): the
    ``enrichment_enabled`` switch, then the sources in force with their
    credentials, and the job's tool servers
    (``services.enrichment_sources.enrichment_reach``). Never raises: sources
    that cannot be read are named as such, never left out.
    """
    if not await runtime_config.get("enrichment_enabled"):
        return None
    from maljan.analysis.disclosure import registry_rows, unread_sources_row
    from maljan.enrichment.declared import ASKED_KINDS

    from app.services.enrichment_sources import (
        ENRICHMENT_SOURCES_PATH,
        enrichment_reach,
        read_setting_secret,
    )

    try:
        servers = getattr(getattr(core_settings, "mcp", None), "servers", None)
        return await enrichment_reach(
            await runtime_config.get(ENRICHMENT_SOURCES_PATH), read_setting_secret, servers
        )
    except Exception as exc:  # noqa: BLE001 — a plan that cannot be read still says so
        logger.warning(
            "enrich: the sources the follow-up job may ask could not be read (%s).",
            type(exc).__name__,
        )
        return [*registry_rows(), unread_sources_row(ASKED_KINDS)]


def evidence_budget_of(run_summary: Mapping[str, Any] | None, core_settings: Any = None) -> int:
    """The per-agent evidence budget the run ran with.

    Its settings snapshot in the run summary, else the job's own settings
    (``core_settings``, the ones the run was built with); with neither, no
    budget, and the last pass leaves the ledger as it is.
    """
    snapshot = (run_summary or {}).get("settings_snapshot")
    value = (
        snapshot.get("reporting.evidence_budget_bytes") if isinstance(snapshot, Mapping) else None
    )
    if value is None and core_settings is not None:
        value = getattr(getattr(core_settings, "reporting", None), "evidence_budget_bytes", 0)
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


async def _seal_the_ledger(
    db: Any,
    report: Any,
    job_uuid: uuid.UUID,
    rows: list[Any],
    key: Any,
    sealed_at: datetime,
) -> dict[str, Any]:
    """Chain ``rows``, seal them, write the seal into ``report`` and onto the audit chain.

    Each row's digest over every column it persists and its place in the
    job's hash chain in ``seq`` order (``ledger_chain``), taken from the rows
    exactly as they are inserted: what a verifier reads back. The seal (chain
    head, what it covers, key id, the stored report's digest) is written into
    the report row (the mark that the job's ledger is sealed), the report
    payload and the run summary column, and as a chained ``ledger.seal`` audit
    row, all in ``db``'s transaction. Nothing the models saw is touched; the
    run is over.
    """
    from app.services import audit_chain, ledger_chain

    head = ledger_chain.chain_rows(job_uuid, rows, key)
    # The rows and the report row go to the database first, so every column
    # the seal's report digest covers holds what is stored, and a failure of
    # theirs is never taken for the audit write's.
    await db.flush()
    core = ledger_chain.seal(
        job_uuid,
        rows,
        head,
        report_sha256=ledger_chain.report_digest(report),
        sealed_at=sealed_at,
        key=key,
        report_id=report.id,
    )
    landed = await audit_chain.append(
        db,
        action=audit_chain.LEDGER_SEAL,
        resource_type="job",
        resource_id=str(job_uuid),
        details={"report_id": str(report.id), "seal": core},
        key=key,
    )
    # The append's own result, known before this transaction commits, goes
    # into the keyed seal: a verifier then tells a deleted audit row from an
    # append that never landed.
    seal = ledger_chain.anchored(core, landed=landed is not None, key=key)
    report.ledger_seal = seal
    report.malware_report = ledger_chain.with_seal(report.malware_report, seal)
    report.run_summary = ledger_chain.with_seal(report.run_summary, seal)
    return seal


async def _store_the_report(
    db: Any,
    *,
    job_uuid: uuid.UUID,
    job_id: str,
    pipeline_result: dict[str, Any],
    stix_bundle: dict | None,
    run_summary: dict[str, Any],
    transcript: list[dict[str, Any]],
    incomplete_reason: str | None = None,
    core_settings: Any = None,
    spill: Any = None,
) -> Any:
    """Add the report and everything that cites it to ``db``, uncommitted.

    The report, the per-agent findings, the evidence ledger and the
    transcript go together because the report's sections cite the ledger's
    ids. ``incomplete_reason`` is set on a report kept from a run that
    failed after the report was built, and says so.
    """
    from app.models.report import AgentFinding, AnalysisReport

    report = AnalysisReport(
        job_id=job_uuid,
        verdict=pipeline_result.get("final_decision", "Unknown"),
        overall_confidence=_extract_confidence(pipeline_result),
        malware_category=_extract_category(pipeline_result),
        stix_bundle=stix_bundle,
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
                        arg.agent_name if hasattr(arg, "agent_name") else arg.get("agent_name", "")
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
                        getattr(arg, "note", "") if hasattr(arg, "finding") else arg.get("note", "")
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
            "consensus_applicable": pipeline_result.get("consensus_applicable", True) is not False,
            # True when at least one round failed outright, so consumers
            # can say "the negotiation did not run" rather than "the
            # agents did not agree".
            "mediation_failed": any(
                getattr(a, "status", "complete") in ("failed", "timeout")
                for a in (pipeline_result.get("discussion_history") or [])
                if getattr(a, "agent_name", "") == MEDIATOR_AGENT_NAME
            ),
            # Whether the last round's agreement was flagged as
            # sycophantic — agents converging without new evidence. It
            # reached the database only buried inside ``run_summary``
            # before, so nothing rendering the negotiation could tell
            # a genuine consensus from a manufactured one.
            "sycophancy_detected": bool(pipeline_result.get("sycophancy_detected", False)),
        },
        run_summary=run_summary,
        malware_report=pipeline_result.get("malware_report"),
        incomplete_reason=incomplete_reason,
    )
    # Every NUL and lone surrogate in a sample-derived string is written out
    # before anything is stored or digested (``store_text``): PostgreSQL
    # refuses both in text and jsonb, and one refused value would refuse this
    # whole transaction. Counted across every row below and recorded in the
    # run summary.
    from app.services import store_text

    _nul_replaced = store_text.sanitise_row(report)
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

        # Derive lifecycle status from the analyst's text
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
        _nul_replaced.add(store_text.sanitise_row(finding))
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
    from maljan.schemas.evidence import fit_structures_to_budget

    # The last pass before it is saved: each agent's kept bytes within its
    # budget, structures dropped first, texts untouched (a no-op for a ledger
    # with no structure kept beside a prose text, every built-in's).
    # A structure this pass drops is kept whole under the job's prefix first,
    # by the job's own store (``spill``, the container's) or, for a caller
    # without one, a store made now (``object_store.job_evidence_spill``).
    from maljan.schemas.evidence_spill import settle_refs

    from app.services import object_store

    _spill = spill if spill is not None else await object_store.job_evidence_spill(job_id)
    _dumps = [_entry for _entry in _ledger if isinstance(_entry, dict)]
    await asyncio.to_thread(
        fit_structures_to_budget,
        _dumps,
        evidence_budget_of(run_summary, core_settings),
        spill=_spill,
    )
    # The store writes in the background. Wait for it, off the loop and for a
    # stated time (``object_store.EVIDENCE_DRAIN_SECONDS``), then set every
    # reference to how its write ended: a write that failed, or had not
    # finished by then, loses its key and states why.
    _outcomes = await asyncio.to_thread(_spill.drain, object_store.EVIDENCE_DRAIN_SECONDS)
    # The ledger is final from here: the store takes no more parts and lets
    # its writers go, the fallback store made above included.
    _spill.close()
    _unkept = settle_refs(_dumps, _outcomes)
    if _unkept:
        logger.warning(
            f"{_unkept} evidence part(s) of job={job_id} were not kept; their references say why",
            extra={"job_id": job_id},
        )
    # Each row's digest over every column it persists, and its place in the
    # job's hash chain in ``seq`` order (``ledger_chain``), taken from the rows
    # exactly as they are inserted: what a verifier reads back.
    from app.services import ledger_chain

    # The chain is keyed by a key derived from the settings encryption key
    # (``ledger_chain.platform_key_status``). Without one nothing is sealed:
    # the rows are stored as before, and the warning names why.
    _key, _no_key = ledger_chain.platform_key_status()
    _written_at = datetime.now(UTC)
    _rows = [
        _evidence_row(_entry, job_id=job_uuid, written_at=_written_at)
        for _entry in rows_to_store(_ledger, job_id=job_id)
    ]
    for _row in _rows:
        _nul_replaced.add(store_text.sanitise_row(_row))
        db.add(_row)
    # The transcript rows are built here and added after the seal, as they
    # always were, so their replacements are counted in the run summary the
    # seal's report digest covers.
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
    _transcript_rows: list[Any] = []
    for index, message in enumerate(transcript):
        _stamped = int(message.get("seq") or 0)
        _transcript_rows.append(
            _transcript_row(
                message,
                report_id=report.id,
                seq=_stamped or (0 if _numbered else index),
            )
        )
    for _message_row in _transcript_rows:
        _nul_replaced.add(store_text.sanitise_row(_message_row))
    # What the live feed of this job had replaced by now, so the one count a
    # reader of the report sees covers the events too.
    _events_replaced = _EVENT_REPLACED.get(job_id, 0)
    if _nul_replaced.total or _events_replaced:
        report.run_summary = store_text.recorded(
            report.run_summary, _nul_replaced, events=_events_replaced
        )
        logger.warning(
            "Job=%s carried characters PostgreSQL refuses in what it stores (%s; events "
            "%d); each is stored written out (NUL as %s) and the run summary records the "
            "count under %s.",
            job_id,
            _nul_replaced.record(),
            _events_replaced,
            store_text.NUL_WRITTEN,
            store_text.RUN_SUMMARY_KEY,
            extra={"job_id": job_id, "component": "report"},
        )
    if _key is None:
        logger.warning(
            "The ledger of job=%s is not sealed: %s.",
            job_id,
            _no_key,
            extra={"job_id": job_id},
        )
    else:
        await _seal_the_ledger(db, report, job_uuid, _rows, _key, _written_at)

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
    # stream. See ``AgentMessage`` for the full rationale. Built and
    # numbered above, before the seal; added here.
    for _message_row in _transcript_rows:
        db.add(_message_row)

    logger.info(
        f"Saved {len(transcript)} transcript messages for report={report.id}",
        extra={"job_id": job_id},
    )
    return report
