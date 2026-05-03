"""Create all database tables from ORM models."""

import asyncio

from app.database import Base, async_engine
from app.models import *  # noqa: F401, F403


async def init() -> None:
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await async_engine.dispose()
    print("All database tables created successfully.")


if __name__ == "__main__":
    asyncio.run(init())
