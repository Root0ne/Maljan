# die-mcp

Detect It Easy over MCP: the packers, compilers, linkers, protectors,
installers and libraries Detect It Easy's signatures name in any file it reads
(PE, ELF, Mach-O, APK, DEX, archives, installers). One tool around
`diec --json`, in an image of its own with Detect It Easy 3.21 (MIT) from its
release's Debian 13 package, checked against the release's sha256. The shared
plumbing is `../cli-sidecar`.

Shipped as the built-in server block `die`, switched off, reached at
`http://die-mcp:8090/mcp` under the compose profile `die`.

## Tools

| tool | arguments | answer |
| --- | --- | --- |
| `die_scan` | `path`, `deep_scan=true`, `heuristic_scan=false`, `recursive_scan=false`, `all_types=false` | `file_types`, `detections` (one row per detected item: `file_type`, `part`, `type`, `name`, `version`, `info`, `string`), `detection_count` |
| `capabilities` | | the capability manifest |

The platform declares `die_scan` of kind `identification`, its rows at
`/detections/*` with the values `name`, `type`, `version` and `file_type`. The
triage pack's `die_scan` step runs it on every sample, and the ILSpy and
GoReSym steps run on its `name` value.
