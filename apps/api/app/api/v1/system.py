"""System administration endpoints.

Lightweight endpoints that expose pipeline-mode gates (so dashboards can
render warning banners) and admin-only memory maintenance (so operators
can purge low-signal LTM entries that pre-date the write-time quality gate).
"""

from __future__ import annotations

from typing import Any

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from maljan.core.settings_overrides import redact_url
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app import observability
from app.auth.throttle import throttle_state
from app.config import settings
from app.database import end_read_transaction, get_db
from app.deps import optional_current_user, require_admin
from app.logging_config import get_logger
from app.models.user import User
from app.runtime_config import runtime_config

logger = get_logger("api.system")

router = APIRouter(prefix="/system", tags=["System"])


# ---------------------------------------------------------------------------
# /system/status — exposed without auth so the dashboard can render before
# the first authenticated request. Returns only the safe, non-secret flags.
# ---------------------------------------------------------------------------


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
    has_virustotal_key: bool
    has_abuseipdb_key: bool
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
    vt_key = await runtime_config.get_secret("virustotal_api_key")
    abuse_key = await runtime_config.get_secret("abuseipdb_api_key")
    is_admin = user is not None and user.role == "admin"
    return SystemStatusResponse(
        app_name=settings.app_name,
        app_version=settings.app_version,
        mock_mode_allowed=bool(await runtime_config.get("mock_mode_allowed")),
        enrichment_enabled=bool(await runtime_config.get("enrichment_enabled")),
        enrichment_worker=await _enrichment_worker_state(),
        has_virustotal_key=bool(vt_key),
        has_abuseipdb_key=bool(abuse_key),
        throttle=throttle_state() if is_admin else None,
        audit_write_failures=observability.counters.audit_write_failures if is_admin else None,
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


async def _build_memory_store(db: AsyncSession) -> object:
    """Build a MemoryStore the same way the pipeline does.

    Kept local to avoid coupling the API router to internal container
    initialisation. Returns whichever backend the operator configured
    (Qdrant in production; InMemoryStore in tests / local).
    """
    from maljan.core.settings_overrides import build_settings
    from maljan.memory.in_memory_store import InMemoryStore

    from app.services.settings_service import load_core_overrides

    # The worker reads and writes the UI-configured collection; purging the
    # environment-configured one would be destructive and silent.
    cfg = build_settings(await load_core_overrides(db))
    backend = cfg.memory.backend.lower()
    if backend == "qdrant":
        from maljan.memory.qdrant_store import QdrantStore

        return QdrantStore(
            url=cfg.memory.qdrant_url,
            collection=cfg.memory.qdrant_collection,
            api_key=(
                cfg.memory.qdrant_api_key.get_secret_value() if cfg.memory.qdrant_api_key else None
            ),
        )
    return InMemoryStore()


@router.post("/ltm/purge", response_model=LTMPurgeResponse)
async def ltm_purge(
    body: LTMPurgeRequest,
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
        logger.warning("ltm_purge: failed to build memory store: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            # The store's own error names the URL it was built with, and that
            # URL may carry an API key or a password.
            detail=redact_url(f"memory store unavailable: {exc}"),
        ) from exc

    # The settings that name the collection have been read; the purge itself
    # talks to Qdrant and scrolls the whole collection, which is no reason to
    # hold a transaction on Postgres. Outside the block above, so a database
    # that refused the commit is not reported to the operator as a memory
    # store that is unavailable.
    await end_read_transaction(db)

    backend_name = type(store).__name__

    if body.dry_run:
        # Dry-run is approximated by snapshotting the current count, running
        # the purge against a transient view, and reporting what would have
        # been removed. The Qdrant backend implements purge directly; to
        # avoid actually deleting we instead simulate by checking how many
        # entries would match. Cheapest path: invoke with max_total_techniques
        # set to a sentinel that the implementation treats as no-op? Not
        # available — so we explicitly walk the store via a temporary
        # in-memory copy for InMemoryStore and a scroll for Qdrant.
        if backend_name == "QdrantStore":
            # Reuse the scroll loop directly. Read-only.
            from qdrant_client.models import Filter  # noqa: F401 (typing only)

            qstore = store  # type: ignore[assignment]
            removed_estimate = 0
            offset = None
            if not getattr(qstore, "_collection_exists", lambda: False)():  # type: ignore[attr-defined]
                return LTMPurgeResponse(removed=0, backend=backend_name, dry_run=True)
            while True:
                try:
                    points, offset = qstore._client.scroll(  # type: ignore[attr-defined]
                        collection_name=qstore._collection,  # type: ignore[attr-defined]
                        limit=256,
                        offset=offset,
                        with_payload=True,
                        with_vectors=False,
                    )
                except Exception as exc:
                    logger.warning("ltm_purge: dry-run scroll failed (%s).", exc)
                    break
                for pt in points:
                    payload = pt.payload or {}
                    if body.include_analyst_errors and bool(
                        payload.get("has_analyst_errors", False)
                    ):
                        removed_estimate += 1
                        continue
                    if body.max_total_techniques < 0:
                        continue
                    total = int(payload.get("total_techniques", 0) or 0)
                    corroborated = int(payload.get("corroborated_count", 0) or 0)
                    if total > body.max_total_techniques:
                        continue
                    if body.require_uncorroborated and corroborated > 0:
                        continue
                    removed_estimate += 1
                if offset is None:
                    break
            return LTMPurgeResponse(removed=removed_estimate, backend=backend_name, dry_run=True)
        # In-memory backend: read-only walk over case list.
        removed_estimate = 0
        for case, _vec in getattr(store, "_cases", []):  # type: ignore[attr-defined]
            if body.include_analyst_errors and case.has_analyst_errors:
                removed_estimate += 1
                continue
            if body.max_total_techniques < 0:
                continue
            if case.total_techniques > body.max_total_techniques:
                continue
            if body.require_uncorroborated and case.corroborated_count > 0:
                continue
            removed_estimate += 1
        return LTMPurgeResponse(removed=removed_estimate, backend=backend_name, dry_run=True)

    removed = store.purge_low_quality(  # type: ignore[attr-defined]
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
