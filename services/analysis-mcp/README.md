# analysis-mcp

Static analysis over stdio MCP. Every tool delegates to `maljan.tools`, which
the sidecar imports directly — it runs in the same uv environment as the
pipeline, so there is one implementation and no copy to drift.

Launched by `maljan.core.config._builtin_servers()` as the `analysis` server —
`sys.executable services/analysis-mcp/server.py`, cwd `services/analysis-mcp`,
with only `MALJAN_STAGING_DIR` and `MALJAN_STAGING_TTL_HOURS` passed through.
It is registered with `agents: []` and reaches the static analyst solely
through the `ToolRef`s in the built-in agent definitions, so a definition that
drops the reference really runs without these tools.

## Tools

### Identity

| tool | arguments |
| --- | --- |
| `identify_file` | `path` |
| `hashes` | `path` |
| `signing_info` | `path` |

### Strings

| tool | arguments |
| --- | --- |
| `strings` | `path`, `min_len=6`, `encodings=["ascii","utf16le"]`, `limit=2000`, `offset=0` |
| `iocs_from_text` | `text`, `kinds=null` |
| `iocs_from_file` | `path`, `kinds=null` |

### Structure

| tool | arguments |
| --- | --- |
| `pe_info` | `path`, `sections`, `imports`, `exports`, `resources`, `overlay`, `pdb` |
| `elf_info` | `path` |
| `macho_info` | `path` |
| `apk_info` | `path`, `manifest`, `permissions`, `certs`, `components`, `native_libs`, `dex_strings=false`, `limit=500` |
| `carve_payloads` | `path`, `out_dir=""` (defaults to the staging directory) |
| `archive_list` | `path`, `limit=500` |
| `document_info` | `path` |

### Rules

| tool | arguments |
| --- | --- |
| `yara_scan` | `path=""`, `text=""`, `ruleset="default"`, `timeout_s=60` |
| `sigma_match` | `events`, `ruleset="default"` |
| `sigma_match_sandbox` | `report`, `ruleset="default"` |
| `capa` | `path`, `timeout_s=300`, `backend="auto"` |

### Sample delivery

| tool | arguments |
| --- | --- |
| `put_sample` | `filename`, `content_b64`, `sha256=""` |
| `put_sample_begin` | `filename`, `sha256`, `size` |
| `put_sample_chunk` | `upload_id`, `seq`, `content_b64` |
| `put_sample_finish` | `upload_id` |

`put_sample*` is what lets this server run on another host. Maljan uploads only
to servers reached over HTTP: as a stdio sidecar this one shares the worker's
filesystem and is handed the path instead, so these four tools sit unused in
the default deployment and exist for the operator who runs this same file
behind an HTTP transport. See the "Tool servers on another host" section of
`docs/configuration.md`.

| variable | default | meaning |
| --- | --- | --- |
| `MALJAN_STAGING_DIR` | a `maljan-analysis-mcp` directory under the system temp dir | where uploads land |
| `MALJAN_STAGING_TTL_HOURS` | `24` | how long a staged sample is kept; `0` disables pruning |

The directory is created with mode 0o700 and refused if what is already at that
path is a symlink or is owned by another user — the default name is predictable
and the system temp directory is shared with every other local account. Files
are created with `O_CREAT|O_EXCL|O_NOFOLLOW` at 0o600 rather than written and
then chmodded, uploads are capped at 2 GiB, an unfinished chunked upload is
evicted after fifteen minutes, and every `put_sample*` call prunes staged files
past the TTL.

## Optional dependencies

Install with `uv sync --extra tools`. Each is optional and its absence costs
one tool, never the server:

| library | tool | without it |
| --- | --- | --- |
| `androguard` | `apk_info` | zip-level facts (dex count, ABIs, cert files) and `error` |
| `macholib` | `macho_info` | `{"error": "macholib is not installed"}` |
| `olefile` | `document_info` (OLE2) | magic-level macro presence and `error` |
| `py7zr` | `archive_list` (7z) | `{"error": "py7zr is not installed"}` |

`pefile`, `pyelftools`, `yara-python`, `pySigma` and `flare-capa` come from the
main dependency set; `flare-capa` needs `uv sync --extra capa`.

No tool raises. Anything unexpected comes back as `{"error": ..., "tool": ...}`
so a model can route around it instead of retrying a failed transport call.
