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
    # Audit 2026-07-26 (Ö6): this used to be ``settings.debug``, and since the
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
