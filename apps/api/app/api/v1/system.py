"""System administration endpoints.

Lightweight endpoints that expose pipeline-mode gates (so dashboards can
render warning banners) and admin-only memory maintenance (so operators
can purge low-signal LTM entries that pre-date the LTM-01 quality gate).
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from app.config import settings
from app.deps import require_admin
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
    has_virustotal_key: bool
    has_abuseipdb_key: bool


@router.get("/status", response_model=SystemStatusResponse)
async def system_status() -> SystemStatusResponse:
    """Return non-secret pipeline-mode flags for dashboards.

    No API keys leave the server — only booleans indicating whether keys
    are configured. Safe to expose without authentication.
    """
    vt_key = await runtime_config.get_secret("virustotal_api_key")
    abuse_key = await runtime_config.get_secret("abuseipdb_api_key")
    return SystemStatusResponse(
        app_name=settings.app_name,
        app_version=settings.app_version,
        mock_mode_allowed=bool(await runtime_config.get("mock_mode_allowed")),
        enrichment_enabled=bool(await runtime_config.get("enrichment_enabled")),
        has_virustotal_key=bool(vt_key),
        has_abuseipdb_key=bool(abuse_key),
    )


# ---------------------------------------------------------------------------
# /system/ltm/purge — admin-only retrospective cleanup of low-quality LTM
# entries that pre-date the LTM-01 write-time gate (audit 2026-05-17).
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


def _build_memory_store() -> object:
    """Build a MemoryStore the same way the pipeline does.

    Kept local to avoid coupling the API router to internal container
    initialisation. Returns whichever backend the operator configured
    (Qdrant in production; InMemoryStore in tests / local).
    """
    from maljan.core.config import Settings as MaljanSettings
    from maljan.memory.in_memory_store import InMemoryStore

    cfg = MaljanSettings()
    backend = (cfg.memory.backend or "in_memory").lower()
    if backend == "qdrant":
        from maljan.memory.qdrant_store import QdrantStore

        return QdrantStore(
            url=cfg.memory.qdrant_url,
            collection=cfg.memory.qdrant_collection,
        )
    return InMemoryStore()


@router.post("/ltm/purge", response_model=LTMPurgeResponse)
async def ltm_purge(
    body: LTMPurgeRequest,
    admin: User = Depends(require_admin),
) -> LTMPurgeResponse:
    """Purge low-quality cases from the long-term memory store.

    Requires admin role. The dry-run mode counts matches without deleting
    so operators can preview the blast radius before committing.
    """
    try:
        store = _build_memory_store()
    except Exception as exc:
        logger.warning("ltm_purge: failed to build memory store: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"memory store unavailable: {exc}",
        ) from exc

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
