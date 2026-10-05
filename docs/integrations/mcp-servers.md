# MCP servers

Maljan is an MCP client. Every analysis capability its pipeline uses is also a
tool on an MCP server, and any MCP server an operator adds is called the same
way. This page is for someone connecting or writing a server: the transports,
how the sample reaches a server on another host, and the conventions that make
a server a better citizen of a run. Adding a server from the console is
described in [Generic MCP servers](../tools/generic-mcp.md).

## Transports

| Transport | Reached through | The sample is handed over as |
| :-- | :-- | :-- |
| `stdio` | a child process of the worker (`command`, `args`, `env`, `cwd`, `env_allow`) | a path: the child reads the worker's filesystem |
| `http`, `streamable-http`, `sse` | `url`, with `auth_token` stored encrypted | an upload, when the server advertises `put_sample`; otherwise a path, which needs a shared volume |

The transport decides, not the manifest: a stdio sidecar is never uploaded to,
because it can already open the file.

## A server on another host

Every path-taking tool assumes the server can open the path it is handed. For a
server elsewhere there are two ways to make that hold.

=== "A shared volume"

    Mount the same directory into both, and point the provider's mirror at it —
    `static.r2.mirror_dir` is the worked example. The worker copies the sample
    there (a 0o700 directory, a 0o600 file, removed when the job ends) and the
    server reads it from its own mount. Nothing is uploaded, and the path both
    sides use has to agree.

=== "The `put_sample` convention"

    A server reached over HTTP advertises `put_sample` on its manifest, and
    Maljan uploads the sample to it before the agent's first tool call:

    | Tool | Arguments | Returns |
    | :-- | :-- | :-- |
    | `put_sample` | `filename`, `content_b64`, `sha256` | `{"path": ...}` |
    | `put_sample_begin` | `filename`, `sha256`, `size` | `{"upload_id": ...}` |
    | `put_sample_chunk` | `upload_id`, `seq`, `content_b64` | `{"seq": ...}` |
    | `put_sample_finish` | `upload_id` | `{"path": ...}` |

    Samples over 8 MiB go through the three chunked calls when the manifest
    carries all of them. The returned path is what that server's tools are then
    called with, and uploads are cached per server and sha256 for half an hour.

Staging never fails a run: an upload that goes wrong is recorded as a
degradation reason, and the server is called with the local path. These
primitives are never shown to the model. See [Tool servers on another
host](../configuration.md#tool-servers-on-another-host).

## The capability manifest

A tool named `capabilities`, taking no argument, answers what the server can do
on the host it runs on:

```json
{"server": "analysis", "version": "1.0.0",
 "tools": [{"name": "document_info", "optional_dependency": "olefile",
            "available": false, "reason": "olefile is not installed",
            "timeout_s": null,
            "remediation": "install the optional tool libraries on the host that runs this server: uv sync --extra tools",
            "without": "the PDF and OOXML halves"}]}
```

Compute it when the server starts, by probing — an import, a `which`, an
environment variable — never by asserting. The registry reads it once per job,
the connection test returns it, and the console's server card lists the
unavailable tools with their reason before any run. `timeout_s` is the tool's
real timeout, and the platform waits that long for it.

## Errors that name their remedy

A tool that cannot answer returns, never raises:

```json
{"error": {"code": "missing_dependency",
           "message": "olefile is not installed",
           "remediation": "install the optional tool libraries: uv sync --extra tools"},
 "tool": "document_info"}
```

The codes are `missing_dependency`, `timeout`, `bad_argument`, `no_such_file`,
`unsupported_format`, `not_configured` and `tool_failed`; a code of your own is
kept as written. A returned error is a failed ledger entry with its remedy, and
the report header lists each distinct failure once. See [Writing a tool
server](../configuration.md#writing-a-tool-server).

## What the platform does around every call

- **Every call is ledgered**, with its arguments as the model wrote them, its
  result, whether it succeeded and how long it took.
- **Quoted search arguments are read unquoted** on the built-in sidecars, and the
  answer says what each argument was read as.
- **A server that keeps failing is rested.** After three unanswered calls in a
  row, calls are answered with a `server_resting` error for 60 s. See [A tool
  server that keeps failing is
  rested](../configuration.md#a-tool-server-that-keeps-failing-is-rested).
- **Calls are capped per server** at four at once by default
  (`core.mcp.breaker.max_concurrent_calls`).
