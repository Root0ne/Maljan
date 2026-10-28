### Fixed

- The linear-time check on claiming colliding tool names times the merge alone: the collector is held off inside the timed span and the best of three runs is compared, so a loaded CI runner can no longer fail it (T-427).
