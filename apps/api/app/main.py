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

    # Alembic upgrade is OFF by default — run migrations as a deploy step.
    # Multi-worker uvicorn deployments would otherwise race on `alembic upgrade head`.
    if settings.run_migrations_on_startup:
        try:
            import asyncio
            from pathlib import Path

            from alembic import command
            from alembic.config import Config

            alembic_ini = Path(__file__).resolve().parent.parent / "alembic.ini"
            alembic_cfg = Config(str(alembic_ini))
            await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
            logger.info("Database migrations applied successfully")
        except Exception as exc:
            logger.error(
                "Alembic migration on startup FAILED: %s",
                exc,
                extra={"component": "database"},
            )
            raise
    else:
        logger.info(
            "Skipping Alembic auto-upgrade (run_migrations_on_startup=False). "
            "Run `alembic upgrade head` from your deploy pipeline instead."
        )

    if settings.auth_disabled:
        try:
            import uuid as _uuid

            from sqlalchemy import select as _select
            from sqlalchemy.ext.asyncio import async_sessionmaker as _async_sessionmaker

            from app.models.user import User, UserRole

            session_factory = _async_sessionmaker(async_engine, expire_on_commit=False)
            dev_uuid = _uuid.UUID(settings.auth_disabled_user_id)
            async with session_factory() as session:
                existing = (
                    await session.execute(_select(User).where(User.id == dev_uuid))
                ).scalar_one_or_none()
                if existing is None:
                    session.add(
                        User(
                            id=dev_uuid,
                            email=settings.auth_disabled_user_email,
                            full_name=settings.auth_disabled_user_full_name,
                            hashed_password="!disabled-auth-bypass!",
                            role=UserRole.ADMIN,
                            is_active=True,
                        )
                    )
                    await session.commit()
                    logger.warning(
                        "AUTH_DISABLED is active — seeded dev admin user %s (%s). "
                        "Do NOT run with this flag outside local development.",
                        settings.auth_disabled_user_email,
                        dev_uuid,
                    )
                else:
                    logger.warning(
                        "AUTH_DISABLED is active — every request will be attributed to %s.",
                        settings.auth_disabled_user_email,
                    )
        except Exception as exc:
            logger.critical("Failed to seed dev user for AUTH_DISABLED: %s", exc, exc_info=True)
            raise

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

    # ── Rate Limiting ────────────────────────────────────────
    from app.middleware.rate_limit_middleware import RateLimitMiddleware

    app.add_middleware(
        RateLimitMiddleware,
        redis_url=settings.redis_url,
        enabled=settings.rate_limit_enabled,
        max_requests=settings.rate_limit_requests,
        window_seconds=settings.rate_limit_window_seconds,
        whitelist=settings.rate_limit_whitelist,
    )

    # ── CORS ─────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=settings.cors_allow_methods,
        allow_headers=settings.cors_allow_headers,
        max_age=600,
    )

    # ── Security Headers ─────────────────────────────────────
    # SEC-CORS-HEADERS-01 (audit 2026-05-19): bare CORS leaves browsers
    # without the standard hardening header set. The middleware below
    # installs OWASP-recommended defaults (CSP / X-Frame-Options /
    # X-Content-Type-Options / Referrer-Policy / Permissions-Policy)
    # without touching API semantics. HSTS stays off in dev (HTTP).
    from app.middleware.security_headers_middleware import SecurityHeadersMiddleware

    app.add_middleware(
        SecurityHeadersMiddleware,
        enable_hsts=not settings.debug,
    )

    # ── Routes ───────────────────────────────────────────────
    from app.api.v1.audit import router as audit_router
    from app.api.v1.auth import router as auth_router
    from app.api.v1.dashboard import router as dashboard_router
    from app.api.v1.jobs import router as jobs_router
    from app.api.v1.reports import router as reports_router
    from app.api.v1.samples import router as samples_router
    from app.api.v1.system import router as system_router
    from app.api.ws import router as ws_router

    api_prefix = "/api/v1"
    app.include_router(auth_router, prefix=api_prefix)
    app.include_router(audit_router, prefix=api_prefix)
    app.include_router(jobs_router, prefix=api_prefix)
    app.include_router(samples_router, prefix=api_prefix)
    app.include_router(reports_router, prefix=api_prefix)
    app.include_router(dashboard_router, prefix=api_prefix)
    app.include_router(system_router, prefix=api_prefix)

    # WebSocket routes (no API prefix)
    app.include_router(ws_router)

    # ── Health Check ─────────────────────────────────────────
    @app.get("/health", tags=["System"])
    @app.get("/healthz", tags=["System"])
    async def health_check() -> dict:
        # Two paths so both bare ("/health") and Kubernetes-style
        # ("/healthz") liveness probes succeed without extra config.
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
