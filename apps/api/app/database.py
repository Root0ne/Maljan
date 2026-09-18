"""Async SQLAlchemy engine and session factory.

Provides:
  - async_engine: AsyncEngine instance for database operations.
  - async_session_factory: sessionmaker bound to async_engine.
  - get_db(): FastAPI dependency that yields an AsyncSession per request.
  - Base: Declarative base class for all ORM models.
"""

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import settings
from app.logging_config import get_logger

logger = get_logger("database")

async_engine = create_async_engine(
    settings.database_url,
    # This used to be ``settings.debug``, and since the
    # deployed .env sets DEBUG=true every SQL statement was echoed — twice, once
    # raw and once through the coloured formatter. Worker/API logs became
    # unreadable: tracing which pipeline stage a job was in required grepping
    # the noise away. SQL echo is a targeted debugging tool, not something a
    # general DEBUG flag should switch on, so it now has its own opt-in.
    echo=settings.sql_echo,
    pool_size=settings.db_pool_size,
    max_overflow=settings.db_max_overflow,
    pool_pre_ping=True,
    pool_recycle=settings.db_pool_recycle_seconds,
)

async_session_factory = async_sessionmaker(
    async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy ORM models."""

    pass


async def end_read_transaction(session: AsyncSession) -> None:
    """End whatever transaction this session is holding, before a slow await.

    A request-scoped session is in a transaction from its first statement —
    which, on every authenticated route, is the dependency that resolved the
    caller — and stays in it until the handler returns. A handler that then
    awaits something slow leaves a backend ``idle in transaction`` for the
    length of that await: a model probe may spend five minutes on a
    third-party endpoint, and the transaction it leaves behind holds its locks
    against every migration and every reader for all of it.

    Called where the reads are finished and the slow part begins. The session
    stays usable: the next statement opens a transaction of its own, which is
    what the handler's remaining writes want anyway.

    It is a commit, not a rollback, because the request may already have
    written something it meant to keep — an ``X-API-Key`` caller has
    ``api_key.last_used_at`` stamped on this session by the dependency that
    resolved them (``deps.hash_api_key``'s caller), and that key *was* used.
    So a caller of this function is saying two things: the reads are done, and
    anything already written is final whatever the slow part answers. A handler
    that wants a write held until the end must do it after this call.
    """
    await session.commit()


async def get_db() -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency: yield an async DB session, auto-close on exit."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception as exc:
            logger.error(
                f"Database session error, rolling back: {exc}",
                exc_info=True,
                extra={"component": "database"},
            )
            await session.rollback()
            raise
        finally:
            await session.close()
