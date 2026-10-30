### Fixed

- **Three linear-time tests no longer fail on a loaded runner (T-470).** The guard for a long chain of left-out pack steps and two reporting guards (crypto finding entries, a decompile answer read as code) timed each size once on the wall clock, so one scheduler stall on a shared runner turned a linear reader into a failure. They now take the best of several CPU-time runs through the shared `assert_scales` and, for the pack-step chain, hold two size steps; a quadratic reader still fails. Tests only; no run changes.
