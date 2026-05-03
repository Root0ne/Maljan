import asyncio
import os
import sys

sys.path.insert(0, os.path.abspath("apps/api"))
sys.path.insert(0, os.path.abspath("src"))
from app.database import async_engine
from sqlalchemy import text

from maljan.app import MaljanApp
from maljan.core.config import Settings


async def run_test():
    async with async_engine.connect() as conn:
        result = await conn.execute(text("SELECT sha256, original_filename FROM samples LIMIT 1"))
        sample = result.first()

    if not sample:
        print("No sample found")
        return

    print(f"Running analysis for {sample.sha256}")
    try:
        app = MaljanApp(config=Settings(), mock=False)
        res = await app.arun(file_hash=sample.sha256, file_name=sample.original_filename)
        print("Success:", res)
    except Exception:
        import traceback

        traceback.print_exc()
        import traceback

        traceback.print_exc()


asyncio.run(run_test())
