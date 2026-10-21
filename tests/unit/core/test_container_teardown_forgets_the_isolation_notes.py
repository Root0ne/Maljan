"""A job's container, closed, forgets what the job noted of its sample's readers.

Each tool server a job starts notes how its process was started under the
job's key (``maljan.analysis.isolation``), for the run's disclosure record. The
notes are the job's: they are dropped at teardown, so a worker that is not
recycled starts the next job with none.
"""

from __future__ import annotations

import asyncio

from maljan.analysis import isolation
from maljan.core.config import Settings
from maljan.core.container import ServiceContainer


def test_closing_the_container_forgets_the_notes_of_its_job() -> None:
    container = ServiceContainer(Settings(_env_file=None), mock=True)
    other = ServiceContainer(Settings(_env_file=None), mock=True)
    try:
        isolation.note_in_process(container.job_key(), "mcp:analysis", "the worker")
        isolation.note_in_process(other.job_key(), "mcp:analysis", "the worker")
        assert isolation.noted(container.job_key()) != {}

        asyncio.run(container.aclose())

        assert isolation.noted(container.job_key()) == {}
        # Another job's notes are not this job's to drop.
        assert isolation.noted(other.job_key()) != {}
    finally:
        asyncio.run(other.aclose())
    assert isolation.noted(other.job_key()) == {}
