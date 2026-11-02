"""Whose long-term memory a job reads and writes, read from the job's row.

The analysis worker hands the owner to the job's container; the enrichment of
the job's report reads similar samples under it. Both derive it here, from the
job's creator, its id and its config, so one job has one owner in both
(``long_term_memory.memory_owner_for`` states the rule). A job submitted with
``isolated_memory`` has an owner of its own: a benchmark series run under one
account then reads nothing another run of the series stored, for any sample.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from maljan.memory.long_term_memory import memory_owner_for

# The job option that files a job's long-term memory under the job alone
# (``app.schemas.job._KnownJobConfig``).
ISOLATED_MEMORY_OPTION = "isolated_memory"


def isolated(config: Mapping[str, Any] | None) -> bool:
    """Whether the job's config asks for memory of its own; only ``true`` does."""
    return isinstance(config, Mapping) and config.get(ISOLATED_MEMORY_OPTION) is True


def job_memory_owner(created_by: Any, job_id: Any, config: Mapping[str, Any] | None) -> str:
    """The owner of the job's long-term memory: its creator's, or its own when isolated."""
    return memory_owner_for(created_by, job_id, isolated(config))
