### Added

- **The readers of untrusted input are fuzzed.** Atheris harnesses under `fuzz/` cover the sandbox-report JSON reader, the reader that takes JSON out of a model's answer, the analyst findings block, the PE reader and the archive and document readers. ClusterFuzzLite builds them from `.clusterfuzzlite/` and runs them for five minutes on every pull request that touches the code, and for an hour every night.
