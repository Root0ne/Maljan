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

### Resolved hashes and decoded blobs

| tool | arguments |
| --- | --- |
| `resolve_api_hashes` | `path`, `carved_path=""`, `hashes=null`, `algorithms=null`, `offset=0`, `limit=null` |
| `decode_string_blobs` | `path`, `carved_path=""`, `min_len=8`, `schemes=null`, `offset=0`, `limit=null`, `include_unreferenced=false` |

Both read a PE's bytes and nothing else; nothing is run or emulated, and both
answer in seconds. Their addresses are offsets from the image base, and "the
function around" an address is the one the file's own function table (the x64
exception directory, `.pdata`) lists; an entry whose unwind data chains to
another is a fragment, stated with the start of the function the chain leads to
or with none when it cannot be followed. An x86 image has no such table: the
triage pack hands both tools capa's function starts when capa ran, and each
place then carries the nearest start at or before it in the same section under
`after_function_start` (with `function_source`), never under `function`: capa
lists where functions start and not where they end, so the pack writes it as
"(after capa's function start 0x…)", not as containment. Otherwise, and on a
direct call, an x86 address is stated alone. No start is guessed. The exception directory's bytes
are not read as program data. Neither limits its answer by default: `limit`
pages it only when the caller asks.

`resolve_api_hashes` names the 32-bit values a PE holds that are hashes of
Windows function names — the values a program compares with the hash of each
name in a loaded module's export table instead of importing the function. The
names are `data/windows_export_names_v1.json`: the named exports of 27 common
DLLs (kernel32, kernelbase, ntdll, user32, advapi32, ws2_32, wininet, winhttp,
shell32, ole32, crypt32, iphlpapi, msvcrt and others), generated from the Wine
project's DLL spec files at release tag `wine-9.0` by
`scripts/knowledge/build_windows_export_names.py`, which records each spec's
URL and sha256 and the license the names are held under (LGPL-2.1-or-later
spec files; the file holds only the exported names); no DLL binary is read or
shipped. The same file carries a module-name set, generated by the same script:
each DLL's file name with and without `.dll`, in lower and upper case, which a
resolver that walks the loaded-module list hashes to find a module before its
exports. Module names are hashed under every algorithm but the one that adds a
module hash to a function hash. The algorithms are
`data/api_hash_algorithms_v1.json`: CRC-32 of the ASCII and of the UTF-16LE
name, each also lower-cased; ror13; ror13 of the name with its NUL added to
ror13 of the upper-cased UTF-16LE module name with its NUL (the form common
position-independent code uses); djb2 and FNV-1a 32, each also lower-cased.
The ids an answer carries are the algorithms' plain names (`crc32_ascii`,
`fnv1a32_lower`, …). They and the decoder's scheme names are the tools' own
catalogue identifiers. The leak test lets them through by a named allowance
(`TOOL_CATALOGUE_IDENTIFIERS`, built from this data file and
`string_blobs.SCHEMES` alone), only in the entries that render tool output and
only where a renderer writes one: the bracketed algorithm of a hash reading and
the leading scheme token of a decoded blob. The same id written as a word in
any instruction or sentence is still flagged. Each algorithm's `description` is
developer-facing and is not scanned; a test holds that no description appears
in a tool answer, a server tool description or a pack line.
With `hashes` the caller's values are resolved, and the answer adds
`unresolved` and `unreadable`. Without, the candidates are the 32-bit
immediates of every byte pattern encoding `push imm32`, `mov r32, imm32`,
`mov r/m32, imm32`, `cmp eax, imm32` or `cmp r/m32, imm32` in executable
sections, and every four-byte-aligned value of the other sections, leaving out
values below 0x10000 and virtual addresses inside the image. Every reading of a
value is reported (algorithm, the set it came from — `exports` or `modules` —,
the name and, for an export, the DLLs exporting it); a value two names or two
algorithms give carries both. Every place the value is stored is listed
with its RVA, section and function. With about ten thousand names and ten
algorithms an arbitrary value matches one by chance about once in forty
thousand, so in a scan a value whose algorithm resolves no other value in the
file is reported under `lone_hits` rather than `hits`. Measured on 54 benign
PEs on this project's host: 2 hits in all (both in one launcher binary, low
values that are coincidences), at most three lone hits in a file.

`decode_string_blobs` tries a stated set of generic static encodings over every
non-executable section that is not discardable: `xor8` (one key byte),
`xor8_rolling` (a key byte rising by one per byte), `xor_keyed_header` (a
repeating key of up to 32 bytes in front of the text: key length, key, text to
a decoded NUL; or key length, key, a two- or four-byte text length, text),
`xor8_rolling_header` (a 32-bit seed, a 16-bit length stored plain or XOR the
seed's low half, the rising key starting at the seed's low byte or one past
it) and `base64`, alone among the plain strings or as a layer on top of any of
them (`layers`). A decoding is reported only when it passes the test the answer
states in `readable_test`, in two halves.

A span whose header states its length, ends exactly in the text's own
terminator (one NUL, or a NUL pair for UTF-16LE) and holds no other NUL carries
its own structure: it is accepted when its characters are printable, at least
half letters or digits, not a repeated pattern, changed by the key at half its
bytes or more, and three characters or more under the seed-and-length header
(tried four ways at each offset) or six under a stored key (tried at every key
length). Format strings, command lines and user-agent strings pass.

Any other decoding: printable throughout (UTF-16LE where a header gives the
length); at least `min_len` (8) characters when only the bytes around the text
bound it, four under a seed-and-length header and six under a stored key; half
letters or digits; no character over half the text (a third from eight on) and
no three-character pattern at over a quarter of a long text's positions; few
changes of character class; no evenly spaced run; and encoded bytes that hold
no zero byte and do not already read as text. That last rule has a price,
stated in the answer: a key below 0x40 over letters leaves them printable,
plain text under such a key "decodes" just as readily, and nothing in the bytes
says which is the writing, so such a string whose encoded bytes are printable is
not decoded here.
A span one scheme reads under two keys is dropped (`ambiguous_spans`), and of
two decodings of overlapping bytes the one a header placed, else the longer, is
kept. `results` holds the decodings some code or data refers to — a scan for
RIP-relative displacements in x64 code and absolute virtual addresses anywhere
that land on the blob or its text — or that FLOSS recovered too in this
process (`floss`, with FLOSS's routine and call site; FLOSS's kept result is
read, never run); the rest are counted under `unreferenced` and listed with
`include_unreferenced`. Where a reference loads the address of the text's
encoded bytes as a call argument, the reference carries `passed_to` (and
`address_of`: `blob` or, past a header, `text`): the call's address, the argument
position (and, on x64, the register) and the callee — the import the file's
import table puts in the slot the call or a jump thunk goes through, the
function at a direct call's target, or the slot a runtime pointer is read from.
It is read statically and generically: an x64 `lea` into `rcx`, `rdx`, `r8` or
`r9`, or an x86 `push` of the address or a store to `[esp+n]`, confirmed as an
instruction by decoding its function from the start, then decoded instruction
by instruction to the first call in the same function. A jump or return
before the call, an undecodable byte, the function's end, a write to the
argument register, another stack move for a pushed argument, a call through a
register, or no function table around the reference leave it absent. That
call is usually the program's own decoding routine, and it receives the
encoded bytes. After that call, the walk follows to the next call in the same function that
receives one of two things (`output_passed_to`, x64): the one frame slot whose
address the call was given as another argument, else its return value in `rax`.
It is said as a fact about the slot or the register ("the frame slot [rsp+0xa0],
given to that call as argument 2, is then argument 2 of the call at …"; "that
call's return value in rax is then …"), never as what the first call does with
it, and nothing is followed past that later call. The walk tracks registers and
frame slots, ends tracking of a slot any store overlaps (sized by the store's
width, SSE and VEX stores included; within 16 bytes where the width cannot be
read), follows unconditional jumps and falls through conditional ones (said),
and is absent at a return, an undecodable byte, a jump back, the function's end
or a stack or frame pointer write.
On the two x64 launchers vendored with this project's
Python environment every function in the function table decodes exactly to its
end, and every join checked against `objdump -d` agrees. Measured on 54 benign PEs on this project's host
(launcher and runtime binaries, DirectX and Wine-built system DLLs, the five
above): 6 results in all, none written by the program as encoded text.

The triage pack runs both on every PE as its last two steps, and every agent
reads their lines in the pack.

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
