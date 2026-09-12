# analysis-mcp

Static analysis over stdio MCP. Every tool delegates to `maljan.tools`, which
the sidecar imports directly — it runs in the same uv environment as the
pipeline, so there is one implementation and no copy to drift.

Launched by `maljan.core.config._builtin_servers()` as the `analysis` server —
`sys.executable services/analysis-mcp/server.py`, cwd `services/analysis-mcp`,
no environment variables passed through except `MALJAN_STAGING_DIR` — and its
tools are bound to the `static` analyst by the built-in definitions.

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

Uploads land under `$MALJAN_STAGING_DIR` (a private temp directory when it is
unset), the directory 0o700 and each file 0o600. `put_sample*` is what lets
this server run on another host: see the "Tool servers on another host" section
of `docs/configuration.md`.

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
