### Fixed

- **The default stack starts on Apple Silicon (T-581).** The services whose image carries an x86-64-only program (`ghidra-mcp`, `die-mcp`, `goresym-mcp`, `yarax-mcp`, `webcrack-mcp`, `unblob-mcp`, `jadx-mcp`) declare `platform: linux/amd64`, so an arm64 host runs them emulated rather than not at all; on an amd64 host nothing changes. The core services keep the host's architecture.

### Documentation

- **Apple Silicon (arm64) in the deployment guide.** How to turn on x86-64 emulation in Docker Desktop or Colima, the VM memory the default profiles need, which services run emulated, and how a model server on the Mac becomes reachable from the containers.
