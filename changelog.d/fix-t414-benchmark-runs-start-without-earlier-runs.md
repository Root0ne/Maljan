### Added

- **A job can start without an earlier run's memory of its sample (T-414).** The job option `ignore_earlier_runs` (`POST /api/v1/jobs` config) and `maljan analyze --ignore-earlier-runs` keep the "AN EARLIER RUN ON THIS SAMPLE" block out of every prompt and the earlier run out of the judge's bundle; nothing stored is read for the job. Once it completes, its own case is stored as any job's is, which replaces the case its owner held for the sample, as before. The run summary says `earlier_runs_ignored: true` for such a job and is unchanged for every other. Case memory stays on by default for analysts.

### Fixed

- **Benchmark runs no longer see the run before them (T-414).** A series run on one sample was shown the previous run's technique list, so each score was partly the earlier run's. Every benchmark run is now submitted with `ignore_earlier_runs` (`scripts/benchmark/jobs.py`; `python scripts/benchmark/run.py job-config` prints the config, and the intel-off arm's job config carries it). `score` and `gate` read the run summary stored beside each key score and name, under `EARLIER RUNS NOT RULED OUT`, every run that neither says `earlier_runs_ignored: true` nor states `**Earlier runs:** used` in its score. A job form in the console cannot set the switch; benchmark runs are submitted through the API.
