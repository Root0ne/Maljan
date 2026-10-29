# ilspy-mcp

ILSpy over MCP: a .NET assembly's types, resources, metadata tables and C#
(or IL) source. Tools around `ilspycmd` 11.1.0.9782 (MIT), whose NuGet package
is checked against a pinned sha512 and run on the .NET 10 runtime in an image
of its own. ilspycmd reads the assembly's metadata and IL; it never loads the
assembly into the runtime. The shared plumbing is `../cli-sidecar`.

Shipped as the built-in server block `ilspy`, switched off, reached at
`http://ilspy-mcp:8091/mcp` under the compose profile `ilspy`.

## Tools

Every tool takes `path`, and `bundle_entry` for the assembly inside a
single-file bundle.

| tool | arguments | answer |
| --- | --- | --- |
| `dotnet_types` | `kinds="cisde"` | `types` (`type_kind`, `name`), `type_count` |
| `dotnet_decompile_type` | `type_name`, `il=false` | `source`, `language`, `decompilation_errors`, `type_name` |
| `dotnet_decompile_member` | `member` (documentation id or token), `il=false` | as above, with `member` |
| `dotnet_decompile_assembly` | `il=false` | the whole assembly in one answer |
| `dotnet_resources` | | `resources` (`name`), `resource_count` |
| `dotnet_metadata_table` | `table` (name or number) | `rows`, `row_count` (or `dump`) |
| `capabilities` | | the capability manifest |

The platform declares `dotnet_types` of kind `type_list`, the two single
decompilers of kind `decompile`, and `dotnet_decompile_assembly` of kind
`decompile_batch` as their aggregate form; every tool declares the runtime it
reads, `dotnet` (`runtimes`). The triage pack takes `dotnet_types` as a step by
its kind, on a PE sample whose identification answer names the `dotnet`
runtime.

A host that installs the tool globally (`dotnet tool install --global
ilspycmd`) runs `ilspycmd` from `PATH`; the image sets `ILSPYCMD_DLL` to the
tool's assembly instead.
