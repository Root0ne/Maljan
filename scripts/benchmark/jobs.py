"""The job config every benchmark run is submitted with.

A benchmark series runs the same sample again and again. The product keeps
what a run on a sample found and shows the next run on that sample its
technique list as hypotheses (``long_term_memory.earlier_run_block``): a
feature for an analyst, and for a series a leak, since each run's score is
then partly the run before it. So every benchmark run starts without an
earlier run's memory (the job option ``ignore_earlier_runs``), and its run
summary says so (``earlier_runs_ignored``). Nothing stored is read for it.
Once it completes, its own case is stored as any job's is, replacing the case
its owner (the account that submitted it) held for the sample, so a series is
best submitted under an account of its own. A run may keep earlier runs only
when the caller says so (``earlier_runs=True``), and the score then has to
state it (``scripts.benchmark.earlier_runs``).

    python scripts/benchmark/run.py job-config [--profile NAME] [--with-earlier-runs]

prints the config to POST with a job (``{"sample_id": ..., "config": ...}``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# The job option that starts a job without an earlier run's memory of its
# sample (``app.schemas.job._KnownJobConfig``).
IGNORE_EARLIER_RUNS = "ignore_earlier_runs"


def job_config(
    options: Mapping[str, Any] | None = None, *, earlier_runs: bool = False
) -> dict[str, Any]:
    """``options`` as a benchmark run's job config: without earlier runs unless asked.

    The switch is set last, so an option of the same name in ``options``
    never turns it off; only ``earlier_runs=True`` does.
    """
    config = dict(options or {})
    config.pop(IGNORE_EARLIER_RUNS, None)
    if not earlier_runs:
        config[IGNORE_EARLIER_RUNS] = True
    return config
