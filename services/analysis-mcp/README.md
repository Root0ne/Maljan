# analysis-mcp

Static analysis over stdio MCP. Every tool delegates to `maljan.tools`, which
the sidecar imports directly — it runs in the same uv environment as the
pipeline, so there is one implementation and no copy to drift.

Launched by `maljan.core.config._builtin_servers()` as the `analysis` server —
`sys.executable services/analysis-mcp/server.py`, cwd `services/analysis-mcp`,
with only `MALJAN_STAGING_DIR`, `MALJAN_STAGING_TTL_HOURS` and
`MALJAN_SAMPLE_ROOTS` passed through, plus the one directory name the spawn
composes for the job it is starting this server for (`MALJAN_STAGING_JOB`).
It is registered with `agents: []` and reaches the static analyst solely
through the `ToolRef`s in the built-in agent definitions, so a definition that
drops the reference really runs without these tools.

## Tools

### Identity

| tool | arguments |
| --- | --- |
| `identify_file` | `path`, `carved_path=""` |
| `hashes` | `path`, `carved_path=""` |
| `signing_info` | `path`, `carved_path=""`, `file_type` |

### Strings

| tool | arguments |
| --- | --- |
| `strings` | `path`, `carved_path=""`, `min_len=6`, `encodings=["ascii","utf16le"]`, `limit=2000`, `offset=0` |
| `iocs_from_text` | `text`, `kinds=null` |
| `iocs_from_file` | `path`, `carved_path=""`, `kinds=null` |

### Structure

| tool | arguments |
| --- | --- |
| `pe_info` | `path`, `carved_path=""`, `sections`, `imports`, `exports`, `resources`, `overlay`, `pdb` |
| `elf_info` | `path`, `carved_path=""` |
| `macho_info` | `path`, `carved_path=""` |
| `apk_info` | `path`, `carved_path=""`, `manifest`, `permissions`, `certs`, `components`, `native_libs`, `dex_strings=false`, `limit=500` |
| `carve_payloads` | `path`, `carved_path=""` (carved files land in `<staging>/carved/<sha256>/`, never where the model says) |
| `archive_list` | `path`, `carved_path=""`, `limit=500` |
| `document_info` | `path`, `carved_path=""` |

### Rules

| tool | arguments |
| --- | --- |
| `yara_scan` | `path=""`, `carved_path=""`, `text=""`, `ruleset="default"`, `timeout_s=60` |
| `sigma_match` | `events`, `ruleset="default"` |
| `sigma_match_sandbox` | `report`, `ruleset="default"` |
| `capa` | `path`, `carved_path=""`, `timeout_s=300`, `backend="auto"` |

### Decoded strings

| tool | arguments |
| --- | --- |
| `floss` | `path`, `carved_path=""`, `min_len=4`, `kinds=null`, `limit=150`, `offset=0`, `pattern=null`, `timeout_s=600` |

`floss` recovers the strings a PE only builds at run time — decoded, stack and
tight strings — by emulating the sample's own decoding and string-building
functions under vivisect. The sample is never executed. FLOSS runs as FLARE's
pinned standalone Linux build (see *Optional dependencies*), in a child process
of its own session with an address-space limit of 4 GiB, its whole group killed
at `timeout_s`. Each run gets a directory of its own under `floss/` inside this
job's staging directory, as its home, temporary and working directory, and no
other environment; the directory, with the ~63 MB the build unpacks into it, is
removed when the run ends, however it ends. Either bound, when hit, is
answered as "no result within its budget". Each row carries its `kind`, the
`string`, the `function` that
decoded or built it with `function_rva` (the same address relative to the
image base FLOSS loaded at, which is what a disassembler agrees with), and for
a decoded string the `called_at` call site and the `address` it was written
to. `counts` gives how many of each kind FLOSS found and `meta` its version,
image base and how many functions it discovered and emulated. The answer is
paged like `strings` — `next_offset`, `total_matched`, `kinds` and `pattern`
narrow it — and the result document is kept per file (path, size, mtime), and
one emulation of a file runs at a time, so only the first call emulates and a
concurrent second call waits for its result. The tool concludes nothing from
what it returns. A file without an `MZ` header is refused before FLOSS runs,
and so is a file with a saved vivisect workspace (`<file>.viv`) beside it:
vivisect would load that pickle in place of the file.

The triage pack runs the same function once on every PE, in the worker, and
every agent reads its first strings in the pack; the tool's description says to
call it when a PE's strings look encrypted or are missing, for the rest of the
answer (`offset`) or to search it (`pattern`). The pack's run is the worker's
own, so a call here emulates the file once more for this server's kept result.

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
| `MALJAN_STAGING_DIR` | a `maljan-analysis-mcp` directory under the system temp dir | the base uploads land under |
| `MALJAN_STAGING_JOB` | empty | the one directory name inside that base this job writes in; composed by the spawn, never set by hand |
| `MALJAN_STAGING_TTL_HOURS` | `24` | how long a staged sample is kept; `0` disables pruning |
| `MALJAN_SAMPLE_ROOTS` | empty | the other directories a path argument may name, separated by `:` |

Staging is per job: uploads, carved payloads and the sandbox captures fetched
for that job (in a `captures/` child) land in `<base>/job-<id>/`, the job's
owner removes that directory when the run ends, and the TTL sweep prunes a job
directory whole once the newest file in it is past the cutoff — unless the job
is still running, which it says by keeping its own directory's mtime current. A
server started without `MALJAN_STAGING_JOB` — by hand, or by a settings probe —
writes in the base itself. The name cannot be set in a server's `env` or
`env_allow`: settings validation refuses it and the spawn clears it, because a
stored value would point that server at another job's bytes.

The sweep also takes what an earlier release left in the shared capture
directory, `maljan-cape-pcap` under the system temp directory. Nothing writes
there now.

Every `path` argument is resolved (symlinks followed) and refused unless it
lands inside *this job's* staging directory or one of `MALJAN_SAMPLE_ROOTS` —
another job's staged bytes are refused even where a sample root contains the
base; `ruleset` is held the same way to the `data` tree and to
`MALJAN_YARA_RULES_DIR` / `MALJAN_SIGMA_RULES_DIR`.

`carved_path` is the one file argument a model chooses, and it is held to
`<staging>/job-<id>/carved/<sha256 of the file the call is pinned to>/` plus
that file itself — **not** the staging base, and not `MALJAN_SAMPLE_ROOTS`. A
base-wide bound let a run read another run's carved payload or another run's
`put_sample` upload; the digest is what `carve_payloads` writes under and what
this server can derive from the bytes it was handed, so a run reaches
everything it produced and nothing any other run produced. Two jobs on the same
sample carve into two directories and neither can name the other's.

The absolute path `carve_payloads` returned works, and so does the tail of it
relative to this job's staging directory or to the tree. The resolved path must be a
**regular file** inside that tree: a directory, a FIFO, a device or a socket is
refused as `bad_argument` with its own sentence. Give it and that file is read
in place of `path`, and the answer carries `read_path` saying which file it was;
leave it out and the sample is read. A payload carved out of a carved payload
nests under the sample's own tree rather than opening one of its own.

It exists because `path` itself is not advertised to the model on this server
(see *The sample's path is not the model's to give* in `docs/architecture.md`):
the sample is the platform's to supply, and which of the payloads
`carve_payloads` wrote is worth reading is an analysis decision. A refusal is `{"error": {"code":
"path_outside_roots", ...}}` and names no host path. The worker exports the
directories it puts samples in, so a default deployment sets nothing; see
"Which directories a sidecar may read" in `docs/configuration.md`.

`pattern` on `strings` and `floss` is read the same way `carved_path` is: a
pair of quotes enclosing the whole pattern is not part of it, so
`"CreateMutex"` finds `CreateMutexW`. Nothing else is rewritten, a value
without a surrounding pair is passed through exactly, and an answer to a call
whose pattern was read this way carries `read_as` first — the pattern it
searched for. The shared reading is `maljan.tools.arguments`; the knowledge and
threatintel servers apply it to their lookup arguments too.

The directory is created with mode 0o700 and refused if what is already at that
path is a symlink or is owned by another user — the default name is predictable
and the system temp directory is shared with every other local account. Files
are created with `O_CREAT|O_EXCL|O_NOFOLLOW` at 0o600 rather than written and
then chmodded, uploads are capped at 2 GiB — measured on the encoded argument
before it is decoded, so an oversized one is refused rather than materialised
twice — at most 32 chunked uploads may be in flight at once, an unfinished one
is evicted after fifteen minutes, and every `put_sample*` call prunes staged
files past the TTL — the carved trees included, which the sweep used to skip
because it deleted files and stepped over directories, so every payload a run
carved stayed on disk for the life of the host. A tree left empty by the sweep
goes with the payloads it held; a symlink is never followed.

`timeout_s` on `yara_scan`, `capa` and `floss` is a request, not an instruction: the
value the `capabilities` manifest declares (60 s, 300 s and 600 s) is the ceiling, so
a caller asking for more is given that. Asking for less is honoured.

### Capabilities

| tool | arguments |
| --- | --- |
| `capabilities` | — |

Answers `{server, version, tools: [{name, optional_dependency, available,
reason, timeout_s}]}`, computed when the server starts by probing each optional
module. A tool that cannot answer returns `{"error": {"code", "message",
"remediation"}, "tool"}` (`maljan.tools.errors`); see *Writing a tool server*
in `docs/configuration.md`.

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

`floss` runs FLOSS (Apache-2.0) as FLARE's standalone Linux build, not as a
Python package, so nothing of it is in the lockfile. The build is pinned:
release `v3.1.1`, asset `floss-v3.1.1-linux.zip`, sha256
`40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666`; the executable
inside it has sha256
`d71b9ea4fe3b2de974dc1ae3c5d0f67569921bc118dcb02ed72e905a662411cb`. The release
publishes no digest, so both were computed when it was pinned.

The tool looks for the executable at `MALJAN_FLOSS_PATH` (set in this server's
`env`) and, when that is unset, in the user tools directory and then on `PATH`,
and runs it only when its sha256 is the pinned one: each run copies the executable
into the run's own directory, hashing the bytes as it writes them, and runs that
copy, so a file changed after it was checked is refused rather than run.
`scripts/install_floss.sh`
downloads the asset, checks both digests and installs the executable at
`~/.local/share/maljan/tools/floss-3.1.1/floss`, the first
place looked. The backend image does the same in a build stage and puts it at
`/usr/local/bin/floss`. Without it the manifest marks `floss` unavailable with
the reason (not installed, or not the pinned build) and the remedy, and a call
answers the same.

No tool raises. Anything unexpected comes back as `{"error": ..., "tool": ...}`
so a model can route around it instead of retrying a failed transport call.
