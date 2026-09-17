"""Analysis job endpoints — create, list, get, cancel.

Uses AnalysisService for business logic separation.
"""

import time
import uuid
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.database import get_db
from app.deps import get_current_user
from app.logging_config import get_logger
from app.logsafe import log_safe
from app.models.user import User
from app.schemas.evidence import EvidenceEntryResponse, EvidenceListResponse
from app.schemas.job import JobCreateRequest, JobListResponse, JobResponse, JobRoster
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
    named = [agent for stage in team.stages for agent in stage.agents]
    return await unprobed_models(db, settings, _everyone_the_run_can_reach(settings, named))


def _everyone_the_run_can_reach(settings: Any, named: list[str]) -> list[str]:
    """The stages' agents, and every agent they can ask, and so on.

    The lead team names one agent in its only analysis stage: the specialists
    that do the work sit in no stage and are reached through ``ask_<key>``.
    Checking the stages alone would skip exactly the definitions most likely
    to carry a model of their own. The reference graph is acyclic — the
    settings model refuses a self-reference and the run refuses a cycle — so
    the closure terminates; it is written as one anyway, because a set that
    grows is the honest way to say "and so on".
    """
    definitions = settings.agents.definitions
    reached = list(dict.fromkeys(named))
    pending = list(reached)
    while pending:
        definition = definitions.get(pending.pop())
        for ref in getattr(definition, "tools", None) or []:
            callee = str(getattr(ref, "agent", "") or "")
            if getattr(ref, "kind", "") != "agent" or not callee or callee in reached:
                continue
            reached.append(callee)
            pending.append(callee)
    return reached


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
    unprobed = await _unprobed_models_for(db, body.config or {})
    if unprobed:
        from app.services.model_probes import refusal_sentence

        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=refusal_sentence(unprobed),
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
        return job
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


@router.get("", response_model=JobListResponse)
async def list_jobs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status_filter: str | None = Query(None, alias="status"),
    user: User = Depends(get_current_user),
    svc: AnalysisService = Depends(_get_service),
) -> dict:
    """List analysis jobs with pagination and optional status filter."""
    result = await svc.list_jobs(
        user=user,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
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
# this endpoint every 3 s and the live view every 5 s, and the roster is a
# property of the team the run was composed from rather than of the run's
# progress — so rebuilding it on every poll spent a settings query and a full
# builtin-map merge per poll, per open run, on an answer that cannot change.
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
            key
            for key, (written, _) in _ROSTER_CACHE.items()
            if now - written > _ROSTER_CACHE_SECONDS
        ]
        for k in stale or [min(_ROSTER_CACHE, key=lambda k: _ROSTER_CACHE[k][0])]:
            _ROSTER_CACHE.pop(k, None)
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
            document, effective_definitions(overrides), depth=_delegation_depth(overrides)
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
    """
    import redis.asyncio as aioredis

    from app.config import settings
    from app.services.job_events import read_events

    job = await svc.get_job(job_id, user)
    if not job:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    redis_conn = aioredis.from_url(settings.redis_url, decode_responses=True)
    try:
        events = await read_events(db, redis_conn, job_id, since=since, limit=limit)
    finally:
        try:
            await redis_conn.aclose()
        except Exception:  # noqa: BLE001
            pass

    return {"job_id": str(job_id), "events": events, "count": len(events)}


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
