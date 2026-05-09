"""Maljan API — FastAPI application factory.

Wires together all route modules, middleware, and lifecycle events
into a single FastAPI application instance.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.logging_config import get_logger, setup_logging

# Initialize logging before anything else
setup_logging()

logger = get_logger("main")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application lifecycle: startup and shutdown events."""
    # ── Startup ──────────────────────────────────────────────
    logger.info("Starting Maljan API server...")

    from app.database import async_engine

    # Verify database connectivity
    try:
        async with async_engine.begin() as conn:
            await conn.execute(__import__("sqlalchemy").text("SELECT 1"))
        logger.info("Database connection verified successfully")
    except Exception as exc:
        logger.critical(
            f"Database connection failed: {exc}",
            exc_info=True,
            extra={"component": "database"},
        )
        raise

    # Verify Redis connectivity
    try:
        import redis.asyncio as aioredis

        redis_conn = aioredis.from_url(settings.redis_url)
        await redis_conn.ping()
        await redis_conn.aclose()
        logger.info("Redis connection verified successfully")
    except Exception as exc:
        logger.warning(
            f"Redis connection failed (non-critical): {exc}",
            extra={"component": "redis"},
        )

    logger.info(
        f"Maljan API v{settings.app_version} started successfully",
        extra={"component": "lifecycle"},
    )

    yield

    # ── Shutdown ─────────────────────────────────────────────
    logger.info("Shutting down Maljan API...")
    await async_engine.dispose()
    logger.info("Database connections closed")


def create_app() -> FastAPI:
    """Build and configure the FastAPI application."""
    app = FastAPI(
        title=settings.app_name,
        description=(
            "Maljan — Multi-Agent Malware Analysis Platform. "
            "Professional-grade malware analysis powered by LangGraph, "
            "adversarial multi-agent debate, and STIX 2.1 intelligence output."
        ),
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── Logging Middleware (must be added first) ─────────────
    from app.middleware.logging_middleware import RequestLoggingMiddleware

    app.add_middleware(RequestLoggingMiddleware)

    # ── CORS ─────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routes ───────────────────────────────────────────────
    from app.api.v1.audit import router as audit_router
    from app.api.v1.auth import router as auth_router
    from app.api.v1.dashboard import router as dashboard_router
    from app.api.v1.jobs import router as jobs_router
    from app.api.v1.reports import router as reports_router
    from app.api.v1.samples import router as samples_router
    from app.api.ws import router as ws_router

    api_prefix = "/api/v1"
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(audit_router, prefix=api_prefix)
    app.include_router(jobs_router, prefix=api_prefix)
    app.include_router(samples_router, prefix=api_prefix)
    app.include_router(reports_router, prefix=api_prefix)
    app.include_router(dashboard_router, prefix=api_prefix)

    # WebSocket routes (no API prefix)
    app.include_router(ws_router)

    # ── Health Check ─────────────────────────────────────────
    @app.get("/health", tags=["System"])
    async def health_check() -> dict:
        return {
            "status": "healthy",
            "service": settings.app_name,
            "version": settings.app_version,
        }

    logger.info(
        f"FastAPI app created with {len(app.routes)} routes",
        extra={"component": "setup"},
    )

    return app


# Module-level app instance for uvicorn
app = create_app()
