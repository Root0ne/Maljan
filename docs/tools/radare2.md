# radare2

The `r2` static provider attaches r2mcp, radare2's MCP server, over stdio. It is
a [generic MCP](generic-mcp.md) provider with radare2-specific defaults, and
like it, it degrades: a missing r2mcp costs the run its tools and is named in
the run summary, rather than failing the job.

## Install and connect

```bash
r2pm -ci r2mcp
```

```
core.static.provider     = r2
core.static.r2.enabled   = true
core.static.r2.binary_path = r2mcp
```

## Where r2mcp is looked for

`r2pm -ci r2mcp` installs under radare2's own prefix and does not touch PATH, so
the provider resolves the name when it starts. A value with a directory in it
is used as it is; a bare name is looked up on the worker's PATH, then in
`$R2PM_BINDIR`, `$R2PM_PREFIX/bin` and `radare2/prefix/bin` under the user's
data directory (`$XDG_DATA_HOME`, else `~/.local/share`). Nothing past those is
guessed. Not found, the log names every place looked, and the run summary
carries `static provider 'r2' unavailable: …` with the remedy. Setting
`binary_path` to the executable's absolute path is the sure way. See [Where
r2mcp is looked for](../configuration.md#where-r2mcp-is-looked-for).

## The mirror directory

r2 reads the sample from a copy the worker makes under the samples directory:
`core.static.r2.mirror_dir`, `data/samples/r2-work` by default (only its last
segment is used). The copy is hardened like every mirror — a 0o700 directory, a
0o600 file — and removed when the job ends.

!!! warning "The mirror directory may not be hidden"

    radare2 rejects any path with a `/.` segment, so an r2mcp handed a sample
    under a hidden directory answers "Failed to open file." to every call. The
    setting refuses a hidden segment and says why.

The same directory is how r2mcp on another host can read the sample through a
shared volume; see [Tool servers on another
host](../configuration.md#tool-servers-on-another-host).

## One tool, one analyst

The importable all-tools team runs `all_tools_static_r2` with
`static_provider: "r2"` beside two other static analysts, each reading a tool
of its own. See [An all-tools team](../configuration.md#an-all-tools-team).
