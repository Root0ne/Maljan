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

The server declares `die_scan` of kind `identification`, its rows at
`/detections/*` with the values `name`, `type`, `version`, `file_type` and
`runtime`: the code runtime a detection's name is, in the platform's words
(`dotnet` for `.NET Framework` and `.NET Core`, `go` for `Go`; `RUNTIMES` in
`server.py`), set only on a detection that names one. The triage pack takes
it as a step on every sample by that declaration, and a tool that declares the
one runtime it reads (`runtimes`, as ILSpy's and GoReSym's do) runs on its
`runtime` value.
