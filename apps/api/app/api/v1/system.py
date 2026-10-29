"""System administration endpoints.

Lightweight endpoints that expose pipeline-mode gates (so dashboards can
render warning banners) and admin-only memory maintenance (so operators
can purge low-signal LTM entries that pre-date the write-time quality gate).
"""

from __future__ import annotations

import asyncio
import uuid
from typing import TYPE_CHECKING, Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Request, status
from maljan.core.settings_masking import masked_text
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app import observability
from app.auth.throttle import throttle_state
from app.config import settings
from app.database import end_read_transaction, get_db
from app.deps import optional_current_user, require_admin, require_admin_session
from app.logging_config import get_logger
from app.models.user import User
from app.runtime_config import runtime_config
from app.services import audit

if TYPE_CHECKING:
    from maljan.memory.long_term_memory import MemoryStore

logger = get_logger("api.system")

router = APIRouter(prefix="/system", tags=["System"])


# ---------------------------------------------------------------------------
# /system/status — exposed without auth so the dashboard can render before
# the first authenticated request. Returns only the safe, non-secret flags.
# ---------------------------------------------------------------------------


class EnrichmentSourceStatus(BaseModel):
    key: str
    label: str
    configured: bool


class UnavailableToolStatus(BaseModel):
    """A tool the stored team would call that this host cannot run, with why and the remedy."""

    server: str
    tool: str
    reason: str
    remediation: str = ""
    still_answers: str = ""
    degradation_reason: str
    manifest_code: str = ""


class SystemStatusResponse(BaseModel):
    app_name: str
    app_version: str
    mock_mode_allowed: bool = Field(
        description=(
            "When True, the worker accepts MALJAN_MOCK_MODE=true or "
            "job.config.mock_mode=true and short-circuits the real pipeline. "
            "Dashboards should surface a banner so operators notice."
        )
    )
    enrichment_enabled: bool = Field(
        description="Whether post-pipeline threat-intel enrichment runs.",
    )
    enrichment_worker: str = Field(
        default="not_required",
        description=(
            "Where enrichment runs and whether anything is there to run it: "
            "'not_required' when it is queued beside the analyses, 'up' when "
            "its own worker is reading its queue, 'down' when that worker is "
            "expected and absent (enrichments stay queued), 'unknown' when the "
            "queue could not be read."
        ),
    )
    enrichment_configured: int | None = Field(
        default=None,
        description=(
            "How many enrichment sources are configured (enabled, holding the "
            "credential they need, and their server on for a server source). "
            "Omitted when the sources could not be read."
        ),
    )
    enrichment_sources: list[EnrichmentSourceStatus] | None = Field(
        default=None,
        description=(
            "Every enrichment source in force, in the order they are asked: its key, "
            "its label and whether it is configured. Never a credential. Signed-in "
            "callers only — omitted for anonymous requests, and when the sources "
            "could not be read."
        ),
    )
    unavailable_tools: list[UnavailableToolStatus] | None = Field(
        default=None,
        description=(
            "Every tool the stored default team would call that the host running "
            "its server cannot run: the server, the tool, the server's own reason, "
            "the remedy, what it still answers and the words a run's degraded block "
            "would use. Checked without starting anything (an import path lookup, "
            "an executable looked for). Signed-in callers only — omitted for "
            "anonymous requests, and when the settings could not be read."
        ),
    )
    throttle: dict[str, object] | None = Field(
        default=None,
        description=(
            "Auth throttle store availability; degraded means refresh fails "
            "closed. Admin callers only — omitted for anonymous requests."
        ),
    )
    audit_write_failures: int | None = Field(
        default=None,
        description=(
            "Audit rows this process could not write since start. Admin "
            "callers only — omitted for anonymous requests."
        ),
    )
    jwt_grace_secret: dict[str, object] | None = Field(
        default=None,
        description=(
            "The signing-secret rotation in progress, if any: the previous "
            "key id, the moment it stops being accepted, whether it is still "
            "accepted, and whether an end was written down at all. An "
            "unbounded window is accepted and never ends, which is a "
            "different state from a lapsed one and is why `bounded` is here "
            "beside `accepted`. A rotation nobody finishes leaves a retired "
            "key accepted, so it is on the status an operator reads. Admin "
            "callers only — omitted for anonymous requests, and omitted "
            "entirely when no previous secret is set."
        ),
    )


# One client for this module, reused by every status call. The console polls
# this endpoint, and a connect-and-close per poll is a connection the pool was
# there to avoid; the worker's own check reuses its context's client the same
# way.
_redis_client: Any = None


async def _redis() -> Any:
    """The shared Redis client for the status read, built once."""
    global _redis_client
    if _redis_client is None:
        _redis_client = aioredis.from_url(settings.redis_url)
    return _redis_client


async def _enrichment_worker_state() -> str:
    """Whether the process the enrichment is queued for is there.

    A dashboard that says enrichment is enabled while every enrichment sits in
    a queue nobody reads is telling half the truth. Cheap: one Redis key,
    written by arq itself, and never an error — a status endpoint that fails
    because it could not reach Redis tells an operator less than one that says
    it does not know.
    """
    from app.worker.enrich_worker import enrichment_worker_is_alive

    try:
        if not await runtime_config.get("enrichment_dedicated_worker"):
            return "not_required"
        alive = await enrichment_worker_is_alive(await _redis())
    except Exception as exc:  # noqa: BLE001 — a status line never fails a request
        logger.debug("system status: enrichment worker unknown (%s).", type(exc).__name__)
        return "unknown"
    if alive is None:
        return "unknown"
    return "up" if alive else "down"


def _grace_secret_state() -> dict[str, object] | None:
    """The rotation window, or ``None`` when no previous secret is configured.

    A rotation is two steps and a wait, and the wait is where one is forgotten.
    Naming the moment here is what lets an operator see, without reading a
    bootstrap file, that the deployment is still carrying a retired key and
    when it stops carrying it — or that nobody said when, which is the state
    ``bounded`` exists to tell apart from a window that has run out.

    The key id is here and in no log line: this answers an authenticated admin
    on request, which is not the same as writing an operator\'s label into a
    file on disk. Nothing here opens the secret\'s box — ``grace_secret_configured``
    is the one place that does, and it answers yes or no.
    """
    from app.auth.jwt import (
        grace_secret_configured,
        grace_secret_is_live,
        grace_secret_not_after,
    )

    if not grace_secret_configured():
        return None
    not_after = grace_secret_not_after()
    return {
        "key_id": str(getattr(settings, "jwt_previous_key_id", "")),
        "not_after": not_after.isoformat() if not_after else None,
        "accepted": grace_secret_is_live(),
        "bounded": not_after is not None,
    }


async def _enrichment_sources() -> list[EnrichmentSourceStatus] | None:
    """Each source in force, asked order, with whether it is configured: booleans, no key.

    ``None`` when the sources could not be read: the status is polled without
    authentication and must answer with what it knows rather than fail.
    """
    try:
        from app.services.enrichment_sources import (
            ENRICHMENT_SOURCES_PATH,
            asks_a_server,
            read_setting_secret,
            ready_sources,
            reputation_servers_on,
        )

        stored = await runtime_config.get(ENRICHMENT_SOURCES_PATH)
        reputation_servers = await reputation_servers_on()
        # The tool servers are read only where a source is asked through one.
        servers = None
        if asks_a_server(stored, reputation_servers=reputation_servers):
            servers = (await runtime_config.core()).mcp.servers
        ready = await ready_sources(
            stored, read_setting_secret, servers, reputation_servers=reputation_servers
        )
    except Exception as exc:  # noqa: BLE001 — the status degrades, it never fails
        logger.warning("enrichment sources could not be read (%s)", type(exc).__name__)
        return None
    ready.sort(key=lambda s: s.source.order)
    return [
        EnrichmentSourceStatus(key=s.key, label=s.label, configured=s.configured) for s in ready
    ]


async def _unavailable_tools() -> list[UnavailableToolStatus] | None:
    """The tools the stored team would call that this host lacks; ``None`` when unknown.

    The same check ``POST /jobs`` makes for the job it accepts
    (``services.tool_availability``), here for the team a job gets when it
    names none, so the console says it before anyone submits.
    """
    try:
        from app.services.tool_availability import as_rows, unavailable_tools

        found = unavailable_tools(await runtime_config.core())
    except Exception as exc:  # noqa: BLE001 — the status degrades, it never fails
        logger.warning("tool availability could not be read (%s)", type(exc).__name__)
        return None
    return [UnavailableToolStatus(**row) for row in as_rows(found)]


@router.get("/status", response_model=SystemStatusResponse, response_model_exclude_none=True)
async def system_status(
    user: User | None = Depends(optional_current_user),
) -> SystemStatusResponse:
    """Return non-secret pipeline-mode flags for dashboards.

    No API keys leave the server — only booleans indicating whether keys
    are configured. Safe to expose without authentication.

    The throttle/audit fields reveal operational state (whether the auth
    store is currently degraded, how many audit rows were dropped) that is
    harmless to an operator but is still internal detail; they are populated
    only for an authenticated admin caller and omitted from the response
    entirely for everyone else.
    """
    is_admin = user is not None and user.role == "admin"
    sources = await _enrichment_sources()
    return SystemStatusResponse(
        app_name=settings.app_name,
        app_version=settings.app_version,
        mock_mode_allowed=bool(await runtime_config.get("mock_mode_allowed")),
        enrichment_enabled=bool(await runtime_config.get("enrichment_enabled")),
        enrichment_worker=await _enrichment_worker_state(),
        enrichment_configured=(
            None if sources is None else sum(1 for s in sources if s.configured)
        ),
        # Source keys and labels are an operator's own names: signed-in callers only.
        enrichment_sources=sources if user is not None else None,
        # Which libraries the host lacks is an operator's detail: signed-in callers only.
        unavailable_tools=await _unavailable_tools() if user is not None else None,
        throttle=throttle_state() if is_admin else None,
        audit_write_failures=observability.counters.audit_write_failures if is_admin else None,
        jwt_grace_secret=_grace_secret_state() if is_admin else None,
    )


# ---------------------------------------------------------------------------
# /system/ltm/purge — admin-only retrospective cleanup of low-quality LTM
# entries that pre-date the write-time quality gate.
# ---------------------------------------------------------------------------


class LTMPurgeRequest(BaseModel):
    max_total_techniques: int = Field(
        default=1,
        description=(
            "Cases with total_techniques less than or equal to this are "
            "eligible (set to -1 to disable the technique-count branch and "
            "only purge analyst-error cases)."
        ),
    )
    require_uncorroborated: bool = Field(
        default=True,
        description=("When True, also require corroborated_count == 0 before purging."),
    )
    include_analyst_errors: bool = Field(
        default=True,
        description=(
            "When True, additionally purge cases recorded with any analyst [ERROR] output."
        ),
    )
    dry_run: bool = Field(
        default=False,
        description="When True, return the count that *would* be purged without deleting.",
    )


class LTMPurgeResponse(BaseModel):
    removed: int
    backend: str
    dry_run: bool


async def _build_memory_store(db: AsyncSession) -> MemoryStore:
    """The configured MemoryStore, built by the factory every caller uses.

    Built from the UI-configured settings, not the environment's: the worker
    reads and writes the UI-configured store, and purging another one would be
    destructive and silent.
    """
    from maljan.core.plugins import ALLOW_LIST_PATH
    from maljan.core.settings_overrides import build_settings
    from maljan.memory.store_factory import build_memory_store

    from app.services.plugins import load_in_background
    from app.services.settings_probes import TIMEOUT
    from app.services.settings_service import load_core_overrides

    overrides = await load_core_overrides(db)
    # The selected backend, when it is an allowed plugin, is the code a purge
    # runs: that plugin alone, loaded off the event loop, waited for at most a
    # connection test's budget.
    selected = str(overrides.get("memory.backend") or "").strip().lower()
    await load_in_background(overrides.get(ALLOW_LIST_PATH), [f"memory:{selected}"], TIMEOUT)
    return build_memory_store(build_settings(overrides))


@router.post("/ltm/purge", response_model=LTMPurgeResponse)
async def ltm_purge(
    body: LTMPurgeRequest,
    request: Request,
    admin: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
) -> LTMPurgeResponse:
    """Purge low-quality cases from the long-term memory store.

    Requires admin role. The dry-run mode counts matches without deleting
    so operators can preview the blast radius before committing.
    """
    try:
        store = await _build_memory_store(db)
    except Exception as exc:
        # The store's own error names the URL it was built with, and that URL
        # may carry an API key or a password: masked in the log and the answer.
        said = masked_text(f"{type(exc).__name__}: {exc}")
        logger.warning("ltm_purge: failed to build memory store: %s", said)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=masked_text(f"memory store unavailable: {exc}"),
        ) from exc

    # The settings that name the store have been read; the purge itself may
    # talk to a server and walk the whole store, which is no reason to
    # hold a transaction on Postgres. Outside the block above, so a database
    # that refused the commit is not reported to the operator as a memory
    # store that is unavailable.
    await end_read_transaction(db)

    details: dict[str, Any] = {
        "backend": type(store).__name__,
        "max_total_techniques": body.max_total_techniques,
        "require_uncorroborated": body.require_uncorroborated,
        "include_analyst_errors": body.include_analyst_errors,
    }
    before = None if body.dry_run else await _count_of(store)
    try:
        # The store's client is synchronous and a purge walks the whole store:
        # on the loop it stopped every other request, WebSocket frame and the
        # worker's heartbeat for as long as the walk took.
        answer = await asyncio.to_thread(_purge, store, body, admin)
    except BaseException as exc:
        # A purge that fails partway has still deleted some cases: the row
        # says so, with what the store lost (its count before and after) and
        # the class of the error, never its text.
        if not body.dry_run:
            after = await _count_of(store)
            await audit.record(
                "ltm.purge",
                resource_type="memory",
                user_id=admin.id,
                details={
                    **details,
                    "outcome": "failed",
                    "error": type(exc).__name__,
                    "removed": before - after if before is not None and after is not None else None,
                },
                request=request,
            )
        raise
    finally:
        await asyncio.to_thread(store.close)
    # A purge deletes the operator's accumulated cases, so it leaves a row
    # (a dry run deletes nothing and leaves none).
    if not answer.dry_run:
        await audit.record(
            "ltm.purge",
            resource_type="memory",
            user_id=admin.id,
            details={**details, "outcome": "completed", "removed": answer.removed},
            request=request,
        )
    return answer


async def _count_of(store: MemoryStore) -> int | None:
    """How many cases the store holds, or ``None`` when it cannot say."""
    try:
        return int(await asyncio.to_thread(store.count))
    except Exception:  # noqa: BLE001 - a count for the audit row is best effort
        return None


def _purge(store: MemoryStore, body: LTMPurgeRequest, admin: User) -> LTMPurgeResponse:
    backend_name = type(store).__name__

    if body.dry_run:
        # Read-only: the store counts what the same gate would remove.
        removed_estimate = store.purge_low_quality(
            max_total_techniques=body.max_total_techniques,
            require_uncorroborated=body.require_uncorroborated,
            include_analyst_errors=body.include_analyst_errors,
            dry_run=True,
        )
        return LTMPurgeResponse(removed=removed_estimate, backend=backend_name, dry_run=True)

    removed = store.purge_low_quality(
        max_total_techniques=body.max_total_techniques,
        require_uncorroborated=body.require_uncorroborated,
        include_analyst_errors=body.include_analyst_errors,
    )
    logger.info(
        "ltm_purge: admin=%s backend=%s removed=%d",
        getattr(admin, "id", "?"),
        backend_name,
        removed,
    )
    return LTMPurgeResponse(removed=removed, backend=backend_name, dry_run=False)


class LTMAdoptRequest(BaseModel):
    user_id: uuid.UUID = Field(
        description="The existing user who takes the memory written before owners existed."
    )


class LTMAdoptResponse(BaseModel):
    owner: str
    backend: str
    cases: int
    function_hashes: int
    dropped_cases: int
    dropped_function_hashes: int
    skipped_cases: int
    skipped_function_hashes: int


@router.post("/ltm/adopt", response_model=LTMAdoptResponse)
async def ltm_adopt(
    body: LTMAdoptRequest,
    request: Request,
    admin: User = Depends(require_admin_session),
    db: AsyncSession = Depends(get_db),
) -> LTMAdoptResponse:
    """Adopt the ownerless long-term memory under one existing user.

    Memory written before owners existed is never adopted automatically (an
    owned job does not read it). This is the explicit action: every ownerless
    case and function hash is filed under the named user. Idempotent (a second
    call finds nothing ownerless and says 0), a bearer-session admin only, and
    audited with the actor, the target owner and the counts. Where the owner
    holds the same case, the copy with the later ``created_at`` is kept; a
    sample's function hashes are kept from one side only. Best run while no
    jobs are running: a job storing for the owner meanwhile is not locked out.
    A failure part way is audited with ``outcome=failed`` and the counts so far.
    """
    target = await db.get(User, body.user_id)
    if target is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No such user.")
    try:
        store = await _build_memory_store(db)
    except Exception as exc:
        said = masked_text(f"{type(exc).__name__}: {exc}")
        logger.warning("ltm_adopt: failed to build memory store: %s", said)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=masked_text(f"memory store unavailable: {exc}"),
        ) from exc
    await end_read_transaction(db)
    backend = type(store).__name__
    owner = str(target.id)

    def _details(counts: dict[str, int], outcome: str, **more: Any) -> dict[str, Any]:
        return {
            "actor": str(admin.id),
            "owner": owner,
            "backend": backend,
            "outcome": outcome,
            **counts,
            "count": counts.get("cases", 0) + counts.get("function_hashes", 0),
            **more,
        }

    adopt = getattr(store, "adopt_unowned", None)
    if not callable(adopt):
        await asyncio.to_thread(store.close)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"The {backend} memory backend keeps no owners, so it cannot adopt.",
        )
    try:
        counts = await asyncio.to_thread(adopt, owner)
    except Exception as exc:
        partial = getattr(exc, "counts", None) or {}
        cause = exc.__cause__ if partial and exc.__cause__ is not None else exc
        await audit.record(
            "ltm.adopt",
            resource_type="memory",
            user_id=admin.id,
            details=_details(partial, "failed", error=type(cause).__name__),
            request=request,
        )
        raise cause from None
    finally:
        await asyncio.to_thread(store.close)
    await audit.record(
        "ltm.adopt",
        resource_type="memory",
        user_id=admin.id,
        details=_details(counts, "completed"),
        request=request,
    )
    return LTMAdoptResponse(
        owner=owner,
        backend=backend,
        cases=counts["cases"],
        function_hashes=counts["function_hashes"],
        dropped_cases=counts["dropped_cases"],
        dropped_function_hashes=counts["dropped_function_hashes"],
        skipped_cases=counts["skipped_cases"],
        skipped_function_hashes=counts["skipped_function_hashes"],
    )
