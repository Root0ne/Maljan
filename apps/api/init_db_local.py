import asyncio

from app.database import Base, async_engine
from app.models import *


async def init():
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await async_engine.dispose()


asyncio.run(init())
