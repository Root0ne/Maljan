import asyncio
import os
import sys

# Yolu ayarlayalım
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "apps", "api")))

from app.database import async_session_factory
from app.models.job import AnalysisJob
from sqlalchemy import select


async def get_latest_job():
    try:
        async with async_session_factory() as session:
            result = await session.execute(
                select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(1)
            )
            job = result.scalar_one_or_none()
            if job:
                print(f"Job ID: {job.id}")
                print(f"Status: {job.status}")
                if hasattr(job, "error_message"):
                    print(f"Error: {job.error_message}")
                elif hasattr(job, "error"):
                    print(f"Error: {job.error}")
                else:
                    print(f"No error attribute. Dict: {job.__dict__}")
            else:
                print("No jobs found.")
    except Exception as e:
        print(f"DB Error: {e}")


if __name__ == "__main__":
    asyncio.run(get_latest_job())
