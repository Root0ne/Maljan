"""Analysis job endpoints — create, list, get, cancel.

Uses AnalysisService for business logic separation.
"""

import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, status
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.user import User
from app.schemas.evidence import (
    CallMapResponse,
    EvidenceEntryResponse,
    EvidenceListResponse,
    LedgerVerificationResponse,
)
from app.schemas.job import (
    FollowUpListResponse,
    FollowUpRequest,
    FollowUpResponse,
    JobCreateRequest,
    JobListResponse,
    JobResponse,
    JobRoster,
    UnavailableTool,
)
from app.services import audit
from app.services.analysis_service import AnalysisService
from app.services.settings_service import SettingsService

logger = get_logger("api.jobs")

router = APIRouter(prefix="/jobs", tags=["Analysis Jobs"])


def _get_service(db: AsyncSession = Depends(get_db)) -> AnalysisService:
    return AnalysisService(db)


async def _known_profiles(db: AsyncSession) -> set[str]:
    """Every profile name a job may pick, stored map layered over the seeds."""
    from app.services.agent_map import effective_profiles

    return set(effective_profiles(await SettingsService(db).load_overrides()))


async def _disabled_analyst_in(db: AsyncSession, profile: str) -> str | None:
    """The first disabled analyst ``profile`` lists, or ``None`` if it lists none.

    A built-in profile may sit inactive with a disabled member — the settings
    model exempts it for exactly as long as it stays inactive (see
    ``AgentsConfig._seed_and_check``). Naming it here is what makes it active,
    so that exemption no longer applies: this refuses the job rather than
    letting the worker discover the conflict when the run actually starts.

    The members are read off the stages. ``analysts`` is the retired flat list
    that a stage-form profile leaves empty, so reading it made every refusal
    vacuous: the run started and the disabled member was discovered by the
    worker after all.
    """
    from app.services.agent_map import effective_definitions, effective_profiles

    overrides = await SettingsService(db).load_overrides()
    definitions = effective_definitions(overrides)
    for agent in _profile_agents(effective_profiles(overrides).get(profile, {})):
        member = definitions.get(agent, {})
        if not member.get("enabled", True):
            return str(agent)
    return None


def _profile_agents(profile: dict[str, Any]) -> list[str]:
    """Every agent a profile names, in order and without duplicates."""
    named: list[str] = [str(a) for a in (profile.get("analysts") or [])]
    for stage in profile.get("stages") or []:
        if isinstance(stage, dict):
            named.extend(str(a) for a in (stage.get("agents") or []))
    return list(dict.fromkeys(named))


async def _unprobed_models_for(db: AsyncSession, config: dict[str, Any]) -> list[str]:
    """Every model this job's agents would call that no probe has reached.

    Read off the team the job would actually run — the profile it names, or
    the stored default — because the gate is about the models a run will ask
    for, and a team nobody selected names models nobody will call.
    """
    from app.services.model_probes import unprobed_models
    from app.services.settings_service import effective_core_settings

    settings = await effective_core_settings(db)
    profile = str(config.get("profile") or settings.agents.profile)
    team = settings.agents.profiles.get(profile)
    if team is None:
        # An unknown profile is refused a few lines further on, with the list
        # of the ones that exist; saying it twice, differently, helps nobody.
        return []
    from maljan.agents.composition import called_assignments

    # Every model the job calls, each on the role its builder reads it on:
    # the analysts and every agent they can ask, the mediator of a debate,
    # the summariser while it is on, and the judge and the reporter on the
    # judge role (``composition.called_assignments``).
    return await unprobed_models(db, settings, called_assignments(settings, team.stages))


async def _undecryptable_secrets(
    db: AsyncSession, config: dict[str, Any] | None = None
) -> dict[str, str]:
    """The stored core secrets this job would read that this API cannot decrypt.

    Keyed by setting key. A secret the job never uses (a server its team does not
    bind, an evaluation arm's key) is not named: it is no reason to refuse.
    """
    from maljan.core.settings_overrides import StoredValueRefused

    from app.services.settings_service import (
        load_core_overrides,
        refused_secrets_a_job_uses,
        refusing_undecryptable_secrets,
    )

    try:
        with refusing_undecryptable_secrets():
            await load_core_overrides(db)
    except StoredValueRefused as exc:
        return await refused_secrets_a_job_uses(db, exc.refused, config)
    return {}


async def _unready_providers_for(db: AsyncSession, config: dict[str, Any]) -> list[str]:
    """Every agent of this job's team whose non-degrading static provider is not ready.

    The same team the probe gate reads — the profile the job names, or the
    stored default — and the static provider the job names, when it names one,
    because that is the one its agents without a provider of their own open.
    """
    from app.services.provider_readiness import unready_static_providers
    from app.services.settings_service import effective_core_settings

    settings = await effective_core_settings(db)
    profile = str(config.get("profile") or settings.agents.profile)
    static_provider = config.get("static_provider")
    return await unready_static_providers(
        settings,
        profile,
        global_provider=str(static_provider) if static_provider else None,
    )


async def _unavailable_tools_for(db: AsyncSession, config: dict[str, Any]) -> list[dict[str, Any]]:
    """Every tool this job would call that this host cannot run, with why and the remedy.

    A warning, never a refusal (``services.tool_availability``): the job is
    accepted and its answer names them, so an operator reads "capa is not
    installed" before the run rather than in its degraded block afterwards.
    A check that cannot be made names nothing and costs the submit nothing.
    """
    import logging

    from app.services.settings_service import effective_core_settings
    from app.services.tool_availability import as_rows, unavailable_tools

    try:
        settings = await effective_core_settings(db)
        profile = config.get("profile")
        static_provider = config.get("static_provider")
        return as_rows(
            unavailable_tools(
                settings,
                profile=str(profile) if profile else None,
                global_provider=str(static_provider) if static_provider else None,
                level=logging.WARNING,
            )
        )
    except Exception as exc:  # noqa: BLE001 — a warning is never worth the submit
        logger.debug(f"tool availability not checked ({type(exc).__name__})")
        return []


# The config keys an audit row may carry. A job config is operator-supplied and
# open-ended, so it is never copied wholesale: only these are named, and a
# credential someone put in it has no way through.
_AUDITED_CONFIG_KEYS = (
    "profile",
    "llm_provider",
    "static_provider",
    "sandbox_provider",
    "sandbox_report_id",
    "mock_mode",
    "ignore_earlier_runs",
)


def _job_details(sample_id: Any, config: dict[str, Any] | None) -> dict[str, Any]:
    details: dict[str, Any] = {"sample_id": str(sample_id)}
    for key in _AUDITED_CONFIG_KEYS:
        value = (config or {}).get(key)
        if value is not None:
            details[key] = str(value) if not isinstance(value, bool) else value
    return details


@router.post("", response_model=JobResponse, status_code=status.HTTP_201_CREATED)
async def create_job(
    request: Request,
    body: JobCreateRequest,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Start a new analysis job for an uploaded sample."""
    logger.info(
        f"Creating analysis job for sample={log_safe(body.sample_id)}",
        extra={"sample_id": log_safe(body.sample_id), "user_id": log_safe(user.id)},
    )
    undecryptable = await _undecryptable_secrets(db, body.config)
    if undecryptable:
        # The worker would refuse the run for the same keys; said now, the job
        # is never accepted only to fail when it starts. The setting keys are
        # an operator's detail: a non-admin is told only that one needs entering.
        named = (
            " (" + "; ".join(f"{k}: {why}" for k, why in sorted(undecryptable.items())) + ")"
            if user.role == "admin"
            else ""
        )
        remedy = (
            "Enter it again in the console (Settings, Configuration)"
            if user.role == "admin"
            else "Ask an administrator to enter it again"
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"A stored secret cannot be decrypted{named}. {remedy}; nothing runs on "
            "a default in its place.",
        )
    unprobed = await _unprobed_models_for(db, body.config or {})
    if unprobed:
        from app.services.model_probes import refusal_sentence

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=refusal_sentence(unprobed),
        )
    unready = await _unready_providers_for(db, body.config or {})
    if unready:
        from app.services.provider_readiness import refusal_sentence as provider_refusal

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=provider_refusal(unready),
        )
    profile = (body.config or {}).get("profile")
    if profile is not None:
        known = await _known_profiles(db)
        if str(profile) not in known:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"unknown profile {str(profile)!r}. Available: {', '.join(sorted(known))}",
            )
        disabled = await _disabled_analyst_in(db, str(profile))
        if disabled is not None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"profile {str(profile)!r} lists disabled analyst {disabled!r}",
            )
    unavailable = await _unavailable_tools_for(db, body.config or {})
    try:
        job = await svc.create_job(
            sample_id=body.sample_id,
            user=user,
            config=body.config,
        )
        logger.info(
            f"Job created: id={job.id} status={job.status}",
            extra={"job_id": str(job.id), "user_id": str(user.id)},
        )
        await audit.record(
            "job.submit",
            resource_type="job",
            resource_id=str(job.id),
            user_id=user.id,
            details=_job_details(body.sample_id, body.config),
            request=request,
        )
    except ValueError as exc:
        # Sample not found OR IDOR rejection — surface a 404 either way so
        # we do not leak existence information.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(exc),
        ) from exc
    except Exception as exc:
        from app.services.analysis_service import JobEnqueueError

        if isinstance(exc, JobEnqueueError):
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Analysis queue is unavailable. Please retry shortly.",
            ) from exc
        raise
    if not unavailable:
        return job
    # Outside the block above: a job that was accepted is never answered as a
    # missing sample, nor with a 500, because its warning did not validate.
    try:
        answer = JobResponse.model_validate(job)
        answer.unavailable_tools = [UnavailableTool(**row) for row in unavailable]
    except ValidationError as exc:
        logger.debug(f"job answered without its tool warning ({exc.error_count()} errors)")
        return job
    return answer


@router.get("", response_model=JobListResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    sample_id: uuid.UUID | None = Query(
        None, description="Only the runs of this sample, which is how a run finds its siblings."
    ),
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> dict:
    """List analysis jobs with pagination and optional status and sample filters."""
    result = await svc.list_jobs(
        user=user,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        sample_id=sample_id,
    )
    logger.debug(
        f"Listed jobs: page={log_safe(page)} filter={log_safe(status_filter)} "
        f"total={log_safe(result.get('total', 0))}",
        extra={"user_id": log_safe(user.id)},
    )
    return result


@router.get("/{job_id}", response_model=JobResponse)
async def get_job(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Get a specific job's status and details, with the roster of its team.

    The roster is here rather than only in the run's event feed because a
    reader who opens a finished run, or one whose feed has aged out, still
    needs names for the speakers. The labels live on the agent definitions,
    which only an admin may read through the settings endpoint; a job's own
    roster is as sensitive as the job, so it goes out with the job and a
    non-admin analyst sees "Lead analyst" instead of ``lead``.
    """
    job = await svc.get_job(job_id, user)
    if not job:
        logger.warning(
            f"Job not found: {log_safe(job_id)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    roster = JobRoster.model_validate(await _roster_for_job(db, job))
    return JobResponse.model_validate(job).model_copy(update={"roster": roster})


# One job's roster, remembered for a few seconds. The analysis layout polls
# this endpoint every 3 s, and the roster is a property of the team the run was
# composed from rather than of the run's progress — so rebuilding it on every
# poll spent a settings query and a full builtin-map merge per poll, per open
# run, on an answer that cannot change.
# Small, time-bounded and process-local: a restart or a settings change costs
# at most one stale roster for the length of the window.
_ROSTER_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_ROSTER_CACHE_SECONDS = 20.0
_ROSTER_CACHE_MAX = 256


def _cached_roster(key: str) -> dict[str, Any] | None:
    hit = _ROSTER_CACHE.get(key)
    if hit is None:
        return None
    written, roster = hit
    if time.monotonic() - written > _ROSTER_CACHE_SECONDS:
        _ROSTER_CACHE.pop(key, None)
        return None
    return roster


def _remember_roster(key: str, roster: dict[str, Any]) -> None:
    if len(_ROSTER_CACHE) >= _ROSTER_CACHE_MAX:
        # Drop what has already expired; if nothing has, drop the oldest.
        now = time.monotonic()
        stale = [
            cached
            for cached, (written, _) in _ROSTER_CACHE.items()
            if now - written > _ROSTER_CACHE_SECONDS
        ]
        oldest = min(_ROSTER_CACHE, key=lambda cached: _ROSTER_CACHE[cached][0])
        for evicted in stale or [oldest]:
            _ROSTER_CACHE.pop(evicted, None)
    _ROSTER_CACHE[key] = (time.monotonic(), roster)


def _profile_the_job_ran(job: Any) -> str:
    """The team this run actually used, as exactly as the job can say.

    The job's own config when it pinned one; otherwise the profile recorded in
    the run summary's settings snapshot, which is what the worker composed the
    team from. Only a run with neither — one still running, or one that failed
    before it wrote a report — falls through to the current default, and for
    those the current default *is* what the worker read.

    Without this, changing ``core.agents.profile`` renamed the roster of every
    finished run that had not pinned a profile.
    """
    pinned = str((getattr(job, "config", None) or {}).get("profile") or "")
    if pinned:
        return pinned
    report = getattr(job, "report", None)
    summary = getattr(report, "run_summary", None) if report is not None else None
    if isinstance(summary, dict):
        snapshot = summary.get("settings_snapshot")
        if isinstance(snapshot, dict):
            recorded = str(snapshot.get("agents.profile") or "")
            if recorded:
                return recorded
    return ""


def _delegation_depth(overrides: dict[str, Any]) -> int:
    """How far the roster follows an ``ask_<key>`` chain: what the asks get."""
    from maljan.core.config import AgentsConfig

    default = int(AgentsConfig.model_fields["delegation_depth"].default)
    try:
        return max(1, int(overrides.get("core.agents.delegation_depth", default)))
    except (TypeError, ValueError):
        return default


def _server_labels(overrides: dict[str, Any]) -> dict[str, str]:
    """Each tool server's display name in force: the built-ins', then the stored map's."""
    from maljan.core.settings_overrides import build_settings
    from maljan.pipeline.events import server_labels

    labels = {key: cfg.label for key, cfg in build_settings({}).mcp.servers.items()}
    stored = overrides.get("core.mcp.servers")
    if isinstance(stored, dict):
        for key, entry in stored.items():
            if isinstance(entry, dict) and "label" in entry:
                labels[str(key)] = str(entry.get("label") or "")
    return server_labels(labels)


async def _roster_for_job(db: AsyncSession, job: Any) -> dict[str, Any]:
    """Who can speak in this job's run, by key, label, role and stage.

    Read off the team the job ran, through the same effective maps the submit
    checks use — so the roster a reader is shown is the team the worker
    composed rather than a second reading of the settings.

    Never raises. A roster is how the console draws names; a job endpoint that
    500s because a stored profile will not validate would take the run's
    status down with the label.
    """
    from maljan.core.config import ProfileDefinition
    from maljan.pipeline.events import roster_payload

    from app.services.agent_map import effective_definitions, effective_profiles

    cache_key = str(getattr(job, "id", ""))
    cached = _cached_roster(cache_key) if cache_key else None
    if cached is not None:
        return cached
    try:
        overrides = await SettingsService(db).load_overrides()
        profiles = effective_profiles(overrides)
        name = _profile_the_job_ran(job) or str(overrides.get("core.agents.profile") or "default")
        document = dict(profiles.get(name) or profiles.get("default") or {})
        if not document.get("stages") and document.get("analysts"):
            # A team written as a flat analyst list has no stages in the
            # document and the model is where that conversion lives. A team
            # that already has stages is read as it stands rather than
            # validated, because a roster is a list of names: a stored profile
            # the model would reject — one missing a verdict stage, say — is a
            # team somebody is still editing, and its members are still the
            # ones who would speak.
            document = ProfileDefinition.model_validate(document).model_dump(mode="json")
        roster = roster_payload(
            document,
            effective_definitions(overrides),
            depth=_delegation_depth(overrides),
            servers=_server_labels(overrides),
        )
        if cache_key:
            _remember_roster(cache_key, roster)
        return roster
    except Exception as exc:  # noqa: BLE001 — a label is never worth a 500
        # The type and not the message: an exception raised while reading the
        # settings store can carry a stored value in its text, and this line
        # goes to a log an operator ships somewhere.
        logger.warning(
            f"Could not build a roster for job {log_safe(job.id)} ({type(exc).__name__})."
        )
        return {"agents": [], "stages": []}


@router.get("/{job_id}/events")
async def get_job_events(
    job_id: uuid.UUID,
    limit: int = Query(500, ge=1, le=1000),
    since: int | None = Query(
        None,
        ge=0,
        description="Return only events whose seq is greater than this. Omit for the whole feed.",
    ),
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """Return this job's pipeline events, in sequence order.

    The console uses this to back-fill before it attaches the WebSocket, and
    to resume after a navigation: ``since`` is the last ``seq`` it already
    holds, so a reconnect costs the events it missed rather than a re-read of
    the whole window.

    Events live in the Redis Stream ``analysis:{job_id}:events`` with a 24 h
    TTL and a 1 000-entry cap, and in ``job_events`` against the job for
    ``core.events.retention_days``. The stream is read first and the table
    answers what the stream can no longer reach — an expired stream, or a
    cursor older than the cap. ``seq`` is the ordering key; ``stream_id`` is
    still on an event the stream answered, for a client that keyed on it.

    The job's ``model_usage`` events, one per model call, are written to the
    table alone, never to the stream or the live socket; a page the stream
    answers is given the ones in its range from the table, so per-call usage
    is here while the stream lives as well as after. ``GET
    /jobs/{job_id}/usage`` totals them.
    """
    import redis.asyncio as aioredis

    from app.config import settings
    from app.services.job_events import read_events

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    redis_conn = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        events = await read_events(
            db,
            redis_conn,
            job_id,
            since=since,
            limit=limit,
            usage=True,
            # A job still publishing holds back a usage event past its last
            # progress event (``read_events``).
            running=str(getattr(job, "status", "") or "") in ("pending", "running"),
        )
    finally:
        try:
            await redis_conn.aclose()
        except Exception:  # noqa: BLE001
            pass

    return {"job_id": str(job_id), "events": events, "count": len(events)}


@router.get("/{job_id}/usage")
async def get_job_usage(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """What this job's model calls used and cost so far, from its ``model_usage`` events.

    The worker commits one event per model call as the call is recorded, so
    this answers during a run and after a worker that died before its run
    summary. ``tokens`` is the run summary's own block (input and output,
    cache reads and writes, reasoning, the provider-reported cost, per
    agent), built by the same code from the same calls; ``retries`` and
    ``failed_attempts`` count the records that are not calls. ``spend`` sums
    what the job's spend meter charged each call and each failed attempt
    when it was settled (``priced_usd`` on the record, a charge by stated
    estimate included), so it is what the run spent whatever prices are in
    force now; a record written before records carried their charge is
    priced again by the same meter code at the current ``llm.model_prices``
    over the vendored table and counted in ``repriced_calls``. Per agent too.
    The job's owner only, checked the way the events endpoint checks it: another
    account's job is not found, to an admin as to anyone else.
    """
    from maljan.analysis.run_summary import usage_totals
    from maljan.core.spend import SpendMeter, hour_cache_models

    from app.services.job_events import read_usage
    from app.services.settings_service import effective_core_settings

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    core = await effective_core_settings(db)
    # For a record that carries no charge: prices as ``SpendMeter.from_settings``
    # reads them, without the ceiling, since a total is not a run and nothing
    # here is admitted or refused.
    llm = core.llm
    prices = dict(llm.model_prices or {})
    hour_writes = hour_cache_models(core)
    totals = usage_totals(
        await read_usage(db, job_id),
        lambda: SpendMeter(None, prices, hour_writes=hour_writes),
    )
    return {"job_id": str(job_id), **totals}


@router.get("/{job_id}/evidence", response_model=EvidenceListResponse)
async def get_job_evidence(
    job_id: uuid.UUID,
    agent: str | None = Query(None, max_length=100),
    tool: str | None = Query(None, max_length=200),
    stage: str | None = Query(None, max_length=100),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """One page of the job's evidence ledger — the tool calls the report cites.

    Ownership is the job's, checked exactly the way the job's report endpoint
    checks it: a ledger is as sensitive as the report built from it. Ordered by
    ``seq``, which is the order the ids were issued in across the whole run,
    so paging walks the analysis rather than one agent at a time.

    The three filters are the three grains the console groups by: the stage a
    call belongs to, the agent that made it and the tool it called.
    """
    from sqlalchemy import func as sa_func
    from sqlalchemy import select as sa_select

    from app.models.evidence import EvidenceEntry

    job = await svc.get_job(job_id, user)
    if not job:
        logger.warning(
            f"Evidence requested for unknown job: {log_safe(job_id)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    filters = [EvidenceEntry.job_id == job_id]
    if agent:
        filters.append(EvidenceEntry.agent == agent)
    if tool:
        filters.append(EvidenceEntry.tool == tool)
    if stage:
        filters.append(EvidenceEntry.stage == stage)

    total = (
        await db.execute(sa_select(sa_func.count()).select_from(EvidenceEntry).where(*filters))
    ).scalar_one()
    rows = (
        (
            await db.execute(
                sa_select(EvidenceEntry)
                .where(*filters)
                .order_by(EvidenceEntry.seq)
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return EvidenceListResponse(
        job_id=job_id,
        entries=[EvidenceEntryResponse.model_validate(row) for row in rows],
        total=int(total),
        page=page,
        page_size=page_size,
    )


@router.get("/{job_id}/evidence/call-map", response_model=CallMapResponse)
async def get_job_call_map(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """The functions the run's code reading touched, what each calls and what calls it.

    Derived from the job's stored ledger when asked for
    (``maljan.reporting.call_map``), so a run stored before the map existed
    has one too; nothing is written, and it is derived again on each request
    (about 20 ms over a stored run of a hundred entries in a warm process). Ownership is the
    job's, checked exactly the way the evidence page checks it. Each row is
    read as the evidence page serves it, its absent columns left out, so the
    map is the one the served pages draw; a row that does not read as a ledger
    entry is left out.
    """
    import asyncio

    from maljan.reporting.call_map import call_map
    from maljan.reporting.follow_up import stored_ledger
    from sqlalchemy import select as sa_select

    from app.models.evidence import EvidenceEntry

    job = await svc.get_job(job_id, user)
    if not job:
        logger.warning(
            f"Call map requested for unknown job: {log_safe(job_id)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    found = await db.execute(
        sa_select(EvidenceEntry).where(EvidenceEntry.job_id == job_id).order_by(EvidenceEntry.seq)
    )
    orm_rows = list(found.scalars().all())

    def _derive() -> dict[str, Any]:
        rows = [
            EvidenceEntryResponse.model_validate(row).model_dump(mode="json", exclude_none=True)
            for row in orm_rows
        ]
        ledger, _unread = stored_ledger(rows)
        return call_map(ledger)

    # The rows are read, the ledger rebuilt and the listings parsed off the event loop.
    return CallMapResponse(job_id=job_id, **await asyncio.to_thread(_derive))


@router.get("/{job_id}/evidence/verify", response_model=LedgerVerificationResponse)
async def verify_job_evidence(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Recompute the job's ledger chain from its rows and check it against the seal.

    Ownership is the job's, checked exactly the way the evidence page checks
    it. The answer always says what it found (``services.ledger_verify``):
    ``verified``; ``broken`` with the reason and the first broken ``seq``;
    ``other_key`` when the seal names a key the platform cannot derive;
    ``unverifiable`` when the audit head or the job's own audit rows are under a key
    the platform cannot derive (after a key rotation); or
    ``not_sealed`` when the run predates sealing. Nothing is written.
    """
    from app.services.ledger_verify import verify_job

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    verdict = await verify_job(db, job_id)
    if verdict["status"] not in ("verified", "not_sealed"):
        logger.warning(
            f"Ledger of job {log_safe(job_id)} did not verify: {log_safe(verdict['status'])} "
            f"at seq {log_safe(verdict['first_broken_seq'])}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
    return LedgerVerificationResponse(**verdict)


@router.get("/{job_id}/package")
async def get_job_package(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """The job's verifiable package: a deterministic ``.tar.gz`` (``services.job_package``).

    It holds the stored run (report, evidence ledger, run summary, the judge's
    bundle), the Markdown report, the STIX bundle, the spilled parts with
    their digests, the ledger seal with its verification at build time and a
    manifest of every file's SHA-256 and size, signed with an HMAC under a key
    derived from the settings encryption key when the platform holds one. A
    part the job lacks is listed in the manifest as absent, with why. The
    sample file itself is not included; spilled tool answers may contain bytes
    from it. Ownership is the job's, checked exactly the way the evidence page
    checks it: 404 for anyone else. The rows and the seal's verification are
    read in one snapshot; the package is built into an anonymous temporary
    file and streamed from it. A file above ``upload_max_bytes`` is left out
    and listed in the manifest as absent with its SHA-256 and size; 422 only
    when the manifest itself would be above it. No limit
    of its own bounds concurrent builds: the platform's per-client request
    rate limit (``rate_limit_requests``) applies, as to every route.
    """
    import tempfile

    from app.services import job_package
    from app.services.report_service import ReportService

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    # The Markdown it holds is the one the report route serves.
    layout = await ReportService(db).report_layout()
    spool = tempfile.TemporaryFile()  # noqa: SIM115 — closed by the stream it feeds
    try:
        manifest = await job_package.build_for_job(db.bind, job_id, spool, layout=layout)
    except job_package.PackageError as exc:
        spool.close()
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from None
    except BaseException:
        spool.close()
        raise
    if manifest is None:
        spool.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    seal_status = str((manifest.get("seal") or {}).get("status") or "")
    if seal_status not in ("verified", "not_sealed"):
        logger.warning(
            f"Package of job {log_safe(job_id)} built with a ledger seal that reads "
            f"{log_safe(seal_status)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
    headers = {
        "Content-Disposition": f'attachment; filename="maljan-job-{job_id}.tar.gz"',
        "X-Package-Seal-Status": seal_status,
        "X-Package-Signed": "true" if "key_id" in (manifest.get("signature") or {}) else "false",
    }
    return StreamingResponse(
        job_package.copy_chunks(spool), media_type="application/gzip", headers=headers
    )


@router.get("/{job_id}/evidence/{entry_id}/objects/{part}")
async def get_job_evidence_object(
    job_id: uuid.UUID,
    entry_id: str = Path(..., max_length=32),
    part: str = Path(..., max_length=32),
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> StreamingResponse:
    """One part of a ledger entry's answer the entry does not keep whole, as it was kept.

    The entry's ``spilled`` reference names the part, its object key, byte
    length and SHA-256 (``maljan.schemas.evidence_spill``). Ownership is the
    job's, checked exactly the way the evidence page checks it. 404 when the
    job, the entry or the reference is not there, or the part was never kept
    (its reference states why); 502 when the store cannot hand the object
    back. The bytes are streamed with the recorded digest and length in the
    headers and hashed as they go (:func:`verified_chunks`); the last chunk is
    sent only once the digest matches, so the body is complete only when it
    does.
    """
    import asyncio

    from maljan.schemas.evidence_spill import CONTENT_TYPES, JSON
    from sqlalchemy import select as sa_select

    from app.models.evidence import EvidenceEntry
    from app.services import object_store

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    row = (
        await db.execute(
            sa_select(EvidenceEntry).where(
                EvidenceEntry.job_id == job_id, EvidenceEntry.entry_id == entry_id
            )
        )
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entry not found")
    ref = next(
        (held for held in row.spilled or () if isinstance(held, dict) and held.get("part") == part),
        None,
    )
    if ref is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="The entry keeps no such part"
        )
    key = ref.get("key")
    if not key:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"The part was not kept: {ref.get('error') or 'no key recorded'}",
        )
    # Only a key under this job's own prefix is read, whatever the row says.
    if not str(key).startswith(object_store.evidence_prefix(job_id)):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="The part was not kept for this job"
        )
    try:
        response = await asyncio.to_thread(object_store.open_object, object_store.client(), key)
    except Exception as exc:  # noqa: BLE001 — the store's failure is logged, not served
        logger.warning(
            f"Evidence object {log_safe(key)} could not be read: {log_safe(type(exc).__name__)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY, detail="The object store did not hand it back"
        ) from None
    expected = str(ref.get("sha256") or "")

    media = CONTENT_TYPES.get(part, "application/octet-stream")
    suffix = "json" if media == JSON else "txt"
    headers = {
        "Content-Disposition": f'attachment; filename="{row.entry_id}-{part}.{suffix}"',
        "X-Content-SHA256": expected,
    }
    if isinstance(ref.get("bytes"), int):
        headers["Content-Length"] = str(ref["bytes"])
    return StreamingResponse(
        verified_chunks(response, expected, key), media_type=media, headers=headers
    )


class EvidenceDigestMismatch(RuntimeError):
    """A kept part whose bytes end on another digest than its entry recorded."""


def verified_chunks(response: Any, expected: str, key: str) -> Any:
    """The object ``response`` streams, chunk by chunk, its last chunk only once it verifies.

    Read in ``EVIDENCE_CHUNK_BYTES`` and hashed as it goes, so no part is
    held whole; one chunk is always held back, and the last is handed over
    only after the whole object's digest matches ``expected``. Bytes that end
    on another digest raise :class:`EvidenceDigestMismatch` before the held
    chunk goes out: with ``Content-Length`` set, the client sees a short body
    and fails, and the body is complete only when it matches.
    """
    import hashlib

    from app.services import object_store

    digest = hashlib.sha256()
    held: bytes | None = None
    try:
        for chunk in response.stream(object_store.EVIDENCE_CHUNK_BYTES):
            digest.update(chunk)
            if held is not None:
                yield held
            held = chunk
    finally:
        response.close()
        response.release_conn()
    if digest.hexdigest() != expected:
        logger.warning(f"Evidence object {log_safe(key)} does not match its recorded digest")
        raise EvidenceDigestMismatch(key)
    if held is not None:
        yield held


@router.post(
    "/{job_id}/follow-ups",
    response_model=FollowUpResponse,
    status_code=status.HTTP_201_CREATED,
)
async def ask_follow_up(
    job_id: uuid.UUID,
    body: FollowUpRequest,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """Ask a finished job a new question, answered from what the run stored.

    The report's question round answers it from the job's stored report,
    ledger and run state (``services.follow_up``): no tool is called and
    nothing is analysed again, so a question the stored evidence cannot
    settle is "not determinable from this run" with the reason. The answer is
    kept as a record of its own beside the report, which is never changed, and
    goes onto the audit chain naming the report digest it was answered from.
    Ownership is the job's, checked exactly the way the evidence page checks
    it: 404 for anyone else. 409 for a job still pending or running, or one
    that stored no report; 422 for a report that cannot be read. No database
    transaction is held while the model answers.
    """
    from app.services import follow_up

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    try:
        prepared = await follow_up.prepare(db, job)
    except follow_up.FollowUpRefused as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None
    # The reads end here: the model's answer can take minutes.
    await db.commit()
    answered = await follow_up.answer(prepared, body.question)
    # The usage numbers are taken from the job's event counter before the job
    # row is locked: no Redis call waits under the lock.
    first = (
        await follow_up.reserve_seqs(prepared.job_id, len(answered.usage))
        if answered.usage
        else None
    )
    try:
        row = await follow_up.store(
            db, prepared, answered, body.question, user_id=user.id, first=first
        )
    except follow_up.FollowUpRefused as exc:
        await db.rollback()
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from None
    await db.commit()
    logger.info(
        f"Follow-up {log_safe(row.id)} on job {log_safe(job_id)} answered: {log_safe(row.outcome)}",
        extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
    )
    return FollowUpResponse.model_validate(follow_up.as_mapping(row))


@router.get("/{job_id}/follow-ups", response_model=FollowUpListResponse)
async def list_follow_ups(
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
    db: AsyncSession = Depends(get_db),
) -> Any:
    """The follow-up questions asked of the job and their answers, oldest first.

    Ownership is the job's, checked exactly the way the evidence page checks it.
    """
    from app.services import follow_up

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")
    rows = await follow_up.list_for(db, job_id)
    return FollowUpListResponse(
        job_id=job_id,
        follow_ups=[FollowUpResponse.model_validate(follow_up.as_mapping(r)) for r in rows],
    )


@router.delete("/{job_id}", status_code=status.HTTP_204_NO_CONTENT)
async def cancel_job(
    request: Request,
    job_id: uuid.UUID,
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> None:
    """Cancel a pending or running job."""
    try:
        await svc.cancel_job(job_id, user)
        logger.info(
            f"Job cancelled: {log_safe(job_id)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        await audit.record(
            "job.cancel",
            resource_type="job",
            resource_id=str(job_id),
            user_id=user.id,
            request=request,
        )
    except ValueError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found") from None
    except RuntimeError as exc:
        logger.warning(
            f"Job cancel rejected: {log_safe(exc)}",
            extra={"job_id": log_safe(job_id), "user_id": log_safe(user.id)},
        )
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
