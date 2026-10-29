# goresym-mcp

GoReSym over MCP: a Go binary's functions, build facts, types and strings,
read from the Go runtime's own tables (pclntab, moduledata, build info) in PE,
ELF and Mach-O files, stripped or not. Tools around GoReSym 3.4.1 (MIT), the
release's static Linux build, checked against the release's sha256 and the
binary's own, in an image of its own. The shared plumbing is `../cli-sidecar`.

Shipped as the built-in server block `goresym`, switched off, reached at
`http://goresym-mcp:8092/mcp` under the compose profile `goresym`.

## Tools

Every tool takes `path`, and `go_version` to override the detected Go version
(a stripped binary may need it).

| tool | arguments | answer |
| --- | --- | --- |
| `go_symbols` | `standard_library=false`, `file_paths=false` | `go_version`, `build_id`, `arch`, `os`, `pclntab`, `build_info`, `functions` (`name`, `package`, `start`, `end`, `standard_library`), `function_count`, `files` |
| `go_types` | | the build facts, `types`, `interfaces` and their counts |
| `go_strings` | | the build facts, `strings` (`Str`, `Start`), `string_count` |
| `capabilities` | | the capability manifest |

A file with no Go table GoReSym can read is answered `unsupported_format`.
The platform declares `go_symbols` of kind `function_list`, `go_types` of kind
`type_list` and `go_strings` of kind `embedded_strings`, each reading the `go`
runtime (`runtimes`). The triage pack takes `go_symbols` and `go_types` as
steps by their kinds, on a PE, ELF or Mach-O sample whose identification
answer names the `go` runtime.
