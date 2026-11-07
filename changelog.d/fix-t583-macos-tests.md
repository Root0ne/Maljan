### Fixed

- **A host without a process table is told the worker cannot reap a stdio server's child.** The worker names the child a stdio server runs as from `/proc/self/task`; where that table is absent (macOS) it read as a process with no children, and the last-resort reap and the isolation measure did nothing without a word. It now logs once that the child cannot be identified, so it is not reaped when its transport's own shutdown does not run and its isolation is not measured. Linux behaves as before.
- **The unit and API suites run on macOS.** The tests no longer assume a Linux host: the compose tests find docker wherever it is installed, the ELF readers are tested on an ELF image built as bytes instead of a system binary, child processes are checked through `ps` and `/dev/fd` instead of `/proc`, the capa child's environment check allows the one variable macOS adds to every process, the legacy-path scan reads source files itself instead of parsing grep's output, and the Turkish case-folding tests run only where the C library folds that way. Tests of what is Linux's own (`prlimit`, `/proc`) are skipped elsewhere, each naming the test that shows what the code says there instead. The Linux results are unchanged.

### Added

- **A macOS test job.** `.github/workflows/macos.yml` runs `tests/unit` and `tests/api` on `macos-15` (Apple Silicon) on every push and pull request; it is not a required check.
