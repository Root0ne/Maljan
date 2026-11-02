"""The job config every benchmark run is submitted with.

A benchmark series runs the same sample again and again. The product keeps
what a run on a sample found and shows the next run on that sample its
technique list as hypotheses (``long_term_memory.earlier_run_block``): a
feature for an analyst, and for a series a leak, since each run's score is
then partly the run before it. So every benchmark run starts without an
earlier run's memory (the job option ``ignore_earlier_runs``), and its run
summary says so (``earlier_runs_ignored``). Nothing stored is read for it.

The leak is not only the same sample's: the judge's similar cases, the
attribution's similar samples and the function-hash families read every case
the account stored, so run k of a series would still read what runs 1..k-1
stored for the other samples. So every benchmark run also has memory of its
own (the job option ``isolated_memory``): its long-term memory is filed under
the job alone, none of those readers reads another job's case, and its own
case, stored once it completes, never replaces the case its owner (the
account that submitted it) held for the sample. Its run summary says so
(``isolated_memory``). A run may keep the account's memory, earlier runs and
the series' other runs alike, only when the caller says so
(``earlier_runs=True``), and the score then has to state it
(``scripts.benchmark.earlier_runs``).

    python scripts/benchmark/run.py job-config [--profile NAME] [--with-earlier-runs]

prints the config to POST with a job (``{"sample_id": ..., "config": ...}``).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

# The job option that starts a job without an earlier run's memory of its
# sample, and the one that files its long-term memory under the job alone
# (``app.schemas.job._KnownJobConfig``).
IGNORE_EARLIER_RUNS = "ignore_earlier_runs"
ISOLATED_MEMORY = "isolated_memory"
SWITCHES = (IGNORE_EARLIER_RUNS, ISOLATED_MEMORY)


def job_config(
    options: Mapping[str, Any] | None = None, *, earlier_runs: bool = False
) -> dict[str, Any]:
    """``options`` as a benchmark run's job config: without earlier runs, memory of its own.

    The switches are set last, so an option of the same name in ``options``
    never turns one off; only ``earlier_runs=True`` does, and it leaves both
    out: a job with memory of its own reads no earlier run either.
    """
    config = dict(options or {})
    for switch in SWITCHES:
        config.pop(switch, None)
    if not earlier_runs:
        config.update(dict.fromkeys(SWITCHES, True))
    return config
