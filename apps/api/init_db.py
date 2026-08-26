"""Run Alembic migrations to bring the database schema to the latest version.

This replaces the legacy Base.metadata.create_all() approach with proper
versioned migrations managed by Alembic.
"""

import asyncio
from pathlib import Path

from alembic import command
from alembic.config import Config


async def init() -> None:
    """Apply all pending Alembic migrations."""
    alembic_ini = Path(__file__).resolve().parent / "alembic.ini"
    alembic_cfg = Config(str(alembic_ini))
    await asyncio.to_thread(command.upgrade, alembic_cfg, "head")
    print("Database migrations applied successfully.")


if __name__ == "__main__":
    asyncio.run(init())
