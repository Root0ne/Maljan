### Fixed

- **`ghidra-mcp` builds from a fresh clone and its server starts (T-582).** The pinned tag v5.6.0 builds against Ghidra 12.0.4 while its Dockerfile downloaded 12.0.3, and its headless server registered `/create_folder` and `/delete_file` twice, which stopped it at start. `scripts/dev/fetch_external.sh` now applies `scripts/dev/patches/ghidra-mcp-v5.6.0.patch` after the checkout: once on a fresh tree, left alone on a tree that already carries it, and a stop with the reason when it neither applies nor is in place. The compose file passes `GHIDRA_VERSION` and `GHIDRA_DATE` as build arguments. When the pin moves, the script takes its own patches off before the checkout and stops with the reason when local changes are in the way. It also takes target names (`fetch_external.sh ghidra-mcp`; a name that is no target stops it) and `MALSPARK_EXTERNAL_DIR`.
- **The `unblob-mcp` image resolves again (T-582).** Its hashed requirements pin lzallright 0.2.6 and plotext 5.3.2, the releases jefferson, ubi-reader and unblob accept; every other pin is unchanged.
- **FLOSS is reported available only when the pinned build runs on the host (T-582).** The probe asks the build for `--version` once per file, under a wall clock, in addition to checking its sha256. An executable that cannot start, exits non-zero or does not answer is reported unavailable with the reason, so a host where the build cannot run, such as an arm64 backend without x86-64 emulation for it, no longer offers a FLOSS that fails on every run. A failure of the probe itself is a reason, never an exception, and only answers the same file gives every time are remembered.

### Added

- **A CI workflow that builds the `ghidra-mcp` image and waits for its healthcheck (T-582).** It starts the image through the compose file, with its runtime settings and the volume `volume-init` hands over, and runs when the fetch script, its patches or the compose file change, weekly, and on demand.

### Documentation

- **Apple Silicon: Rosetta is required (T-582).** Under QEMU user-mode emulation some multi-threaded sidecar programs crash, GoReSym among them. The guide also says that the backend's FLOSS is x86-64 only, may not run on an arm64 backend, and is then reported unavailable with the reason.
