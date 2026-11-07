### Changed

- **Five sidecars and the backend's FLOSS run natively on arm64 (T-573).** `yarax-mcp`, `jadx-mcp`, `webcrack-mcp` and `unblob-mcp` pick the pinned release asset for the architecture they are built for (yara-x's aarch64 build, Temurin's aarch64 JRE, Node's linux-arm64 build, sasquatch's arm64 package), each under a sha256 of its own, and stop on any other; amd64 keeps the assets and digests it had. GoReSym's release has no arm64 build, so an arm64 `goresym-mcp` compiles the pinned tag's source with the digest-pinned Go toolchain and checks the binary against the sha256 that build gives. The backend image keeps FLARE's verified standalone FLOSS build on amd64 and, on arm64, installs FLOSS 3.1.1 from PyPI by hash (`scripts/floss/requirements.txt`) behind a launcher; the analysis server accepts the launcher's pinned sha256 on arm64 only and the standalone build's everywhere else, so the amd64 check is unchanged. Those five services no longer declare `platform: linux/amd64`; `ghidra-mcp` and `die-mcp` still do, since neither program has an arm64 Linux build. These images need BuildKit, which Compose and `docker buildx` use.

### Added

- **A CI workflow that builds the native images on amd64 and arm64 runners (T-573).** The backend and the five sidecars are built for each architecture on a runner of its own, without pushing, and each image's program is asked its version; the backend also runs the FLOSS probe. It runs when those Dockerfiles, their requirements or the compose file change, weekly, and on demand.

### Documentation

- **Apple Silicon: which services are native and which stay emulated (T-573).** The deployment guide's table now lists each sidecar's arm64 build or the reason it has none, and Rosetta is needed only for the emulated `ghidra-mcp` and `die-mcp`.
