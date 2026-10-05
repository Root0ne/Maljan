# Analysis and knowledge sidecars

Four tool servers ship built in, each a single-file stdio MCP server under
`services/`, launched with the same interpreter the worker runs on. Their
implementations live in `src/maljan/tools/` as plain functions, so the same code
backs the triage pack's in-process calls and an agent's calls through the
sidecar.

| Server | Bound to | How | Offers |
| :-- | :-- | :-- | :-- |
| `analysis` | `static` | definition `tools` | Identity and hashes, strings and typed IOCs, PE/ELF/Mach-O/APK structure, archive and document inspection, payload carving, YARA, Sigma, capa and emulated string decoding (FLOSS). |
| `knowledge` | every analyst and the judge | definition `tools` | ATT&CK lookup, validation and ranking, the API-behaviour catalog, the LOLBin table, family and prior-case retrieval. |
| `network` | `network` | role binding | DNS, HTTP and packet views of a capture, plus the whole-capture summary. |
| `threatintel` | `judge` | role binding | VirusTotal and AbuseIPDB reputation lookups over their REST APIs. |

A fifth built-in, [VirusTotal](virustotal.md), is VirusTotal's own server over
HTTP.

## Two rules every tool keeps

- **Facts, not verdicts.** A packer section name is a match, not "packed".
- **A missing dependency costs one answer, never the server.** Each sidecar
  answers `capabilities`, naming the tools that need an optional library, a
  binary or a setting and whether each is present. A tool marked unavailable is
  kept out of the list the model is given, and the run records it with its
  remedy.

## How a server reaches an agent

`network` and `threatintel` are bound by role (`MCPServerConfig.agents`).
`analysis` and `knowledge` carry `agents: []` and are bound only by the tool
references in the agent definitions, which is what makes a definition's tool
list authoritative: a clone of the static analyst without the `analysis`
reference really runs without the analysis tools. See [Tools, and the
measurement baseline](../configuration.md#tools-and-the-measurement-baseline).

## Optional libraries and FLOSS

- **Per-format parsers.** `apk_info`, `macho_info`, the OLE2 half of
  `document_info` and the 7z half of `archive_list` rest on the `tools` extra
  (`uv sync --extra tools`; the backend image installs it). Without it they
  answer that the module is not installed, or fall back to what they can read.
- **FLOSS.** `floss` runs FLARE's pinned standalone Linux build outside the
  Python environment. The backend image installs it checksum-verified;
  `scripts/install_floss.sh` installs it on a host. The pin, the paths and
  `MALJAN_FLOSS_PATH` are in [Tools, and the measurement
  baseline](../configuration.md#tools-and-the-measurement-baseline).

## The sample's path is the platform's

On the built-in sidecars, an argument that means the file under analysis —
`path`, `file`, `sample` and the rest — is taken out of the schema the model
sees and filled by the platform with the path that server can open. A file an
earlier call produced, such as a carved payload, is named with `carved_path`,
held to the carved tree of the job's own sample. See [Built-in tool
servers](../architecture.md#built-in-tool-servers).

## Which directories a sidecar may read

A sidecar child process receives only the environment names its entry lists in
`env_allow`, plus its own `env`. The built-ins `analysis` and `network` are
always passed the sample roots and the staging directory, whatever the stored
registry holds, because a child without them refuses the run's own sample. See
[Which directories a sidecar may
read](../configuration.md#which-directories-a-sidecar-may-read).

## A server that keeps failing is rested

After three calls in a row that a server did not answer, it rests for 60
seconds: calls are answered with a `server_resting` tool error instead of being
sent, and the rest is recorded in the run. See [A tool server that keeps
failing is rested](../configuration.md#a-tool-server-that-keeps-failing-is-rested).
