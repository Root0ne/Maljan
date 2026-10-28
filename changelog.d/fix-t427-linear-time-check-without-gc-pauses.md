### Fixed

- The linear-time check on claiming colliding tool names times the merge alone: the collector is held off inside the timed span and the best of three runs is compared, so a loaded CI runner can no longer fail it (T-427).
- The test session freezes what it built while collecting (`gc.freeze()` after collection), so a full collection inside a test no longer walks the whole suite's heap; two further linear-time checks had failed on a loaded runner for that reason (T-427).
