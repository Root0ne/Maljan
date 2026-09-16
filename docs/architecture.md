# Architecture

Maljan is a FastAPI service, an arq worker and a Next.js console over Postgres,
Redis and MinIO. The service owns requests and state; the worker owns analysis
runs and everything an analysis talks to — language models, static analysis
tools, sandboxes, long-term memory and threat-intelligence lookups. This
document describes the components, what happens during a run, and the pieces an
operator can reconfigure.

![Maljan runtime components](assets/architecture.svg)

## Components

| Component | Role |
| :-- | :-- |
| Console (`apps/web`) | Next.js interface: dashboard, analyses, samples, settings. Talks HTTP to the API and subscribes to the job WebSocket. |
| API (`apps/api/app`) | FastAPI application. Authentication, samples, jobs, reports, the audit trail, the settings store and the probes. |
| Worker (`apps/api/app/worker`) | arq process. Takes an analysis job, runs the pipeline, writes the report and publishes progress events. |
| Core (`src/maljan`) | The analysis package: agents, the LangGraph pipeline, the deterministic evidence layers, the provider layer, memory and reporting. |
| Postgres | Users, samples, jobs, reports, audit rows and the settings store. |
| Redis | The arq queue, the per-job event stream, and rate-limit counters. |
| MinIO | Sample bytes, in the bucket named by `MINIO_BUCKET`. |
| Qdrant | Long-term memory: past analyses and family fingerprints as vectors. |
| Tool servers (`services/`) | stdio MCP sidecars bound to one agent each: PCAP tooling for the network analyst, VirusTotal and AbuseIPDB for the judge. |

## Request and job lifecycle

1. The console authenticates and uploads a sample. The API streams it through
   `UPLOAD_TEMP_DIR`, hashes it, stores the bytes in MinIO and the metadata in
   Postgres, and writes an audit row.
2. `POST /api/v1/jobs` creates the job row and enqueues `run_analysis` on arq
   under the same identifier, so the queue job and the database row cannot
   drift apart. An optional `config` object may override a handful of pipeline
   values, including `profile`, which is validated against the profiles the
   store actually holds.
3. The worker takes the job, re-reads the configuration from the settings
   store, downloads the sample from MinIO and mirrors it into `SAMPLES_DIR`
   so the Ghidra container can read it through its bind mount.
4. The pipeline runs. Each stage publishes an event on the Redis channel for
   that job; the API relays it to the console over
   `/ws/analysis/{job_id}`. Publishing is best effort — the database row is
   always written first, so a Redis outage costs progress updates, never the
   record.
5. The report is written to Postgres and becomes available under
   `/api/v1/reports/...` in every rendering the report service supports.
6. Threat-intelligence enrichment runs afterwards as its own job, so it never
   delays the verdict.

## Format routing

The platform never refuses a sample for its format. The first thing a job does
is read the sample's magic bytes into a file type and a platform
(`src/maljan/extractors/sample_identity.py`), and everything downstream routes
on that answer: which sandbox package or VM profile is asked for, which tools
an analyst is given, which rules the Sigma and YARA layers keep,
which ATT&CK domain a technique id belongs to, and which artefacts the analyst
prompts are told to look for. A format nothing recognises routes to the neutral
path — a raw-byte sweep and a report that says so — rather than to a rejection.
Deterministic code decides the routing; the analysis itself is the agents'
work over whichever tools the operator connected for that format.

## The pipeline

A LangGraph `StateGraph` over one shared state (`src/maljan/pipeline/`). The
triage pack runs first; the analyst stage after it has two shapes and
`parallel_analysts` chooses between them:

```
START
  │
triage_pack   the deterministic tools, run by the pipeline, one ledger entry each
  │
  ├─ parallel_analysts = False  (the default)
  │     static_analyst -> dynamic_analyst -> network_analyst
  │
  └─ parallel_analysts = True
        START fans out to all three, then fans in
  │
negotiation  <-------- revision
  │  (consensus, or the iteration cap)   ^
  └─ no consensus -----------------------┘
  │
judge
  │   inside this node: the evidence summary, the degradation note, then
  │   the STIX 2.1 bundle and the judge's own severity, category and family
  │
report  ->  END
```

Sequential is the default because a single local model server has one slot, and
fanning out three analysts onto it produces queue thrash rather than speed. Set
`parallel_analysts` when each request gets its own slot, as with a hosted API.

### The triage pack

Before any analyst starts, the pipeline runs the deterministic tools itself
(`src/maljan/pipeline/triage_pack.py`) and writes each result to the evidence
ledger as an ordinary entry under `agent="pipeline"`, `server="pipeline"`. A
human analyst runs the same dozen commands on every sample before opening a
disassembler, and the live runs showed the local model rarely asks for any of
them; a fact a model may or may not ask for is not a fact a run can rely on.

The pack is the same code the `analysis` sidecar serves, called in-process, in
a fixed order so the ids a sample produces are the same from one run to the
next: `identify_file` and `hashes`; `signing_info`; the format tool the routed
type selects (`pe_info`, `elf_info`, `macho_info`, `apk_info`, `document_info`
or `archive_list`, which carry the section entropies, the packer signature
hits and the import rows); a `strings` head capped by `triage.strings_head`
and `iocs_from_file`; `yara_scan`, `capa` under the static provider's budget
and, when a sandbox report exists, `sigma_match_sandbox`; `api_capability`
over the import set and `lolbin_lookup` over the sandbox's command lines; the
sandbox projections at summary level (processes, network, signatures, dropped
files, channels) and `pcap_summary` when a capture was fetched; one reputation
lookup on the sha256 (`get_file_report` on `virustotal` when it is enabled,
else `check_hash` on `threatintel`), made through the tool server exactly as
an agent's call is and recorded under that server; and `function_matches` when
a Qdrant function-hash store and a provider that hashes functions are both
present.

The pack states facts and draws no conclusion, and it never fails a job: a
tool that raises or answers with an error is an entry with `ok=False` and a
degradation reason `triage.<tool>_failed`, the next tool runs, and a
reputation lookup that has no enabled server is an entry saying so rather than
a silence. Four of its facts — `has_signature`, `reputation_malicious`,
`yara_hits`, `capa_hits` — are readable by every later stage's `when`
condition as `triage.<field>`, and `run_summary.triage` records how many
entries it wrote, how many failed and how long it took. It declines, with the
reason recorded, when `triage.enabled` is off, when the stage withholds the
built-in tools, or when there is no sample on disk to read. The `measurement`
baseline has no triage stage at all.

Agents exchange structured `AgentISR` objects — claims with an `evidence_ref`
and a confidence — rather than raw text. Objects are built and cached in one
composition root (`src/maljan/core/container.py`), and agents are discovered
through the `@register_agent` decorator in `src/maljan/agents/registry.py`.

The organising rule is that the agent decides and the code says what is wrong
with the decision. No component rewrites a claim, a technique id, a confidence,
a severity, a category or a family behind the producer's back; a finding is put
back to the producer as feedback and it gets one turn to fix it. What it will
not fix stays on the record. `tests/unit/test_no_silent_overrides.py` enforces
this by scanning the source for the writes it forbids.

## Validation loops

`src/maljan/pipeline/validation.py` is where a wrong answer is dealt with. A
`Violation` carries a code, a message written for the producer to read, and the
path it applies to. `retry_with_feedback` appends the model's own answer plus
"Your previous answer had these problems: … Fix them and answer again in the
same format", re-runs once, and *returns* whatever is still wrong rather than
raising it.

Two producers use it:

* **Analysts** (`agents/base_agent.py`) — `validate_isr` reports a technique id
  the ATT&CK catalogue does not have (with up to three suggestions from
  `tools.knowledge.resolve_technique`), a confidence outside `[0, 1]`, and a
  claim citing no evidence. An id that survives the retry keeps the analyst's
  spelling and is flagged `technique_id_valid=False`; the report, the STIX
  minting step and the FP linter read the flag.
* **The judge** (`agents/judge_agent.py`) — `validate_verdict_bundle` reports an
  indicator whose pattern names a value no tool in the run saw, an
  attack-pattern with an unresolvable id, a severity outside the enum, and a
  family named with no evidence ids. An ungrounded indicator that survives the
  retry is dropped, because a STIX consumer has no way to read a caveat — and
  recorded, because the false positive is a fact about the run.

What the judge decides is the judge's: `severity` (with its rationale),
`malware_category` and `family` come back on the bundle under
`x_maljan_assessment` and the report prints them as answered. A severity nobody
assessed prints as "not assessed" rather than defaulting to Informational; a
family the judge could not cite evidence for is kept and flagged unverified
rather than silently zeroed.

Two metrics record the outcome:

* `run_summary.validation` — how many feedback retries the run spent, a count
  per violation code, and every finding that stayed unresolved with the agent
  that owns it.
* `run_summary.corroboration` — per technique id, the sources that named it:
  analysts by name and tools by tool name. A count of distinct sources, not a
  combined confidence. The same collection builds the judge's evidence-summary
  block, so the metric and what the judge read cannot disagree.

A degraded run is not capped. The judge is told in the prompt why the run is
thin — no sandbox report, an analyst that failed, a container nothing could
open — and sets its own confidence; the report header states the same reasons.

## Agents and teams

Eight agent definitions ship built in. Five have a class behind them: the
`static`, `dynamic` and `network` analysts, the `judge` and the `reporter`.
Three are generic — `triage`, `android_static` and `reverser` — which means
they are a prompt and a tool list and nothing else, and are what the `mobile`
and `deep_static` teams are built from. Each definition carries its role,
whether it is enabled, the tools it may call, the data it reads and — for an
analyst — the static provider it reads through. The judge and the reporter are
not analysts: a team names them from its verdict and report stages, and no
analysis stage may hold either.

A team (`agents.profiles.<key>`) is an ordered list of **stages**, which is how
a human analysis team works: triage, then static, then dynamic if the sample is
worth detonating, then reversing, then the network and threat-intel pass, then
correlation, then the report. A stage says what it is (`kind`), who is in it
(`agents`), what it runs after (`depends_on`), whether it runs at all (`when`),
whether its members run at once or in turn (`mode`), what it is told about the
stages before it (`inject_upstream`), how hard it argues if it is a debate
(`debate`) and whether its agents keep the built-in tool servers
(`builtin_tools`).

The five kinds are the pipeline itself. A `triage` stage names no agent: it is
the pipeline running the deterministic tools over the sample and writing the
results to the ledger (see *The triage pack* above). An `analysis` stage runs
the agents it names. A `debate` stage runs the mediation loop over the analysis
stages upstream of it. The one `verdict` stage runs the judge. The optional
`report` stage, always last, builds the report.

### The teams that ship

Four teams are seeded, and every one of them is editable only in its debate
options, its built-in tool switches and `exclude_servers`. The rest of a
seeded team is a claim the product makes about how the analysis is arranged,
so changing it means cloning the team.

**`default`** is the triage pack in front of the pipeline as four stages —
`triage_pack` → `analysis` (static, dynamic, network) → `debate` → `verdict` →
`report` — the four being the architecture this project measured itself on.

![The default team](assets/team-default.svg)

**`measurement`** is the same four without the pack, with every tool server
withheld and the static provider forced to `none`: the baseline for what the
ensemble contributes on its own, with nothing established for it. It is a team
rather than three tool-free clones of the definitions, so the agents it
measures cannot drift from the ones `default` runs.

**`mobile`** is a team for a mobile sample. After the pack, `triage` reads the
facts it wrote and says which artefacts matter; `android_static` reads the manifest, the
permissions, the components, the DEX strings and the native libraries, and runs
only when the sample really is one — `when: file_type in ("apk", "dex")`;
`dynamic` detonates when a sandbox report reached the run. On a PE the Android
stage is still in the graph, still declines and still says why, so the console
shows what the team chose not to do rather than nothing at all.

![The mobile team](assets/team-mobile.svg)

**`deep_static`** is a team that reads the code. The pack, `triage`, then the
built-in `static` stage, then `reversing` — a generic `reverser` agent that is handed
the static stage's findings and asked to confirm or refute each of them at
function level, with the tools of whichever static provider is configured — and
then `network`, conditional on there being a capture or a sandbox report to
read.

![The deep_static team](assets/team-deep-static.svg)

The diagrams are generated from the seeded profiles by
`scripts/goldens/render_team_graphs.py`, and
`tests/unit/scripts/test_render_team_graphs.py` fails if the committed SVGs
stop matching the teams, so a stage that moves cannot leave the page behind.

The three generic agents these teams are built from — `triage`,
`android_static` and `reverser` — are seeded definitions like any other, with
their prompts in `src/maljan/agents/prompts/`. A generic agent is a definition
and a prompt and nothing else, which is what makes a team something an operator
can write rather than something that needs a class.

### The stage graph

`pipeline/builder.py` turns a team into a LangGraph workflow and
`pipeline/topology.py` names the nodes. An analysis stage contributes one node
per agent, `<agent>_analyst`; a parallel one also contributes a barrier
`<stage>__join` when its dependents start at more than one node. A debate stage
contributes `negotiation` and `revision`, prefixed `<stage>__` only when a team
holds more than one debate. The verdict stage is `judge` and the report stage
is `report`. A triage stage is one node named after the stage itself. Edges
follow `depends_on`; a stage with no dependency starts at `START`, a stage
nothing depends on ends at `END`, and a debate's way out is the router's
conditional edge — with one rule on top: a triage stage that has no dependency
is where the graph starts, and every other stage without a dependency follows
it instead of `START`, so a team gains the pack by having the stage inserted
and nothing else rewritten.

The default team therefore builds exactly the graph the project has always
built, node for node and edge for edge — `tests/fixtures/golden/graph_default.json`
pins it in both analyst modes.

**A stage's condition never changes the graph.** `when` is evaluated inside the
stage's nodes at run time, so a stage that declines to run is still a node and
still writes a `StageResult` saying it did not run and why. A topology that
depended on the sample could not be drawn, compared or reasoned about before
the sample arrived. What each stage did lands in `state["stage_results"]` and
reaches the reader as `run_summary.stages`.

Each stage also announces itself live, once: `stage_started` from its first
node, `stage_skipped` from that node instead when the condition is false, and
`stage_finished` from the one node that runs after everything in it is done.
That last node is usually the stage's own — a sequential chain's tail, a
barrier, the judge, the report — and for the two shapes with no single terminal
node of their own, a fan-out without a barrier and a debate that loops, it is
the single node of the next stage. Nothing replays the events at the end, so a
run with reporting disabled still terminates every stage it ran.

An agent whose stage was skipped reaches neither the debate nor the judge: both
read the roster from `stage_results` rather than from the profile, so a stage
the condition turned off does not arrive as three empty reports. A debate whose
upstream analysis stages all skipped skips itself and says so.

A custom agent runs as a `ConfigurableAnalyst` with the tools its definition
names. A team may not put one agent in two analysis stages — the node name is
the agent's — may not name the judge or the reporter as an analyst, and may not
name a disabled agent while it is the active team.

## Built-in tool servers

Every analysis capability the pipeline used to run in-process is also a tool an
agent may call. Four stdio sidecars ship built in, each a single-file `FastMCP`
server under `services/`, launched with the same interpreter the worker runs on
and registered in `_builtin_servers()`. A fifth entry is registered there
without being a process of this deployment at all: VirusTotal's own server,
reached over HTTP and off until an operator registers an agent token.

| Server | Bound to | How | Offers |
| :-- | :-- | :-- | :-- |
| `analysis` | `static` | definition `tools` | Identity and hashes, strings and typed IOCs, PE/ELF/Mach-O/APK structure, archive and document inspection, payload carving, YARA, Sigma and capa. |
| `knowledge` | every analyst and the judge | definition `tools` | ATT&CK lookup, validation and ranking, the API-behaviour catalog, the LOLBin table, family and prior-case retrieval. |
| `network` | `network` | role binding | DNS, HTTP and packet views of a capture, plus the whole-capture summary. |
| `threatintel` | `judge` | role binding | VirusTotal and AbuseIPDB reputation lookups over their REST APIs. |
| `virustotal` | `network`, `judge`, `triage` | definition `tools` | VirusTotal's own MCP server over streamable-HTTP: file, URL, domain, IP, analysis and submission reports. Disabled until an agent token is registered. |

The two tool sidecars carry `agents: []` and are bound only by the `ToolRef`s
in the agent definitions, so the definition's tool list is the single binding
and a clone that drops a reference really loses those tools. Both bindings are
composed the same way for every agent — role-bound servers first, then the
definition's references, under one collision rule.

The implementations live in `src/maljan/tools/` as plain functions — explicit
arguments, JSON-serialisable returns, no `Settings` access — so the sidecar is
a `@mcp.tool()` wrapper and nothing more, and the same code backs an in-process
caller. Two rules hold across all of them: they report facts rather than
verdicts (a packer section name is a match, not "packed"), and an optional
dependency that is missing costs one tool's answer, never the server.

The `dynamic` analyst's tools are the exception: its sandbox report is already
in the worker's memory, so `ToolRef(kind="sandbox")` resolves to in-process
tools over that report (`src/maljan/providers/sandbox_tools.py`) with no
transport to open — the process tree, the network activity, the sandbox's own
signatures, the files written, the registry keys touched, the API-call
histogram, the mutexes held, the services and scheduled tasks arranged, the
platform channels, and a bounded reader for any section the rest do not model.

A tool server reached over HTTP does not share the worker's filesystem, so it
is handed the sample rather than a path to it; a stdio sidecar is handed the
path. See the remote-delivery section of
[configuration.md](configuration.md).

## Providers

The provider layer (`src/maljan/providers/`) puts one interface in front of
each class of external tool, so the choice is configuration rather than code.

- **LLM** — `openai`, `anthropic`, `ollama`, `gemini`. Each has its own
  credentials, endpoint and model names; only the selected provider is used.
  Separate model choices exist for the analysts and for the judge.
- **Static** — `ghidra` (Ghidra MCP), `r2` (radare2 MCP), `capa_yara`,
  `generic_mcp` for a server of your own, and `none`.
- **Sandbox** — `mock` (the default), `cape2`, `triage`, `upload` for a report
  produced elsewhere, and `rest`, a mapping-driven adapter for a sandbox
  Maljan has never heard of.
- **Tool servers (MCP)** — additional servers declared in the settings store,
  each with the tools it is allowed to expose and the agents allowed to call
  it.

Every provider that can be reached over the network has a probe behind a Test
button in the console; see [configuration.md](configuration.md).

## Memory

Past analyses and family fingerprints are vectorised and stored in Qdrant, and
retrieved by similarity during a run (`src/maljan/memory/`). The collections,
the neighbour count and the Qdrant endpoint are settings. The ATT&CK corpus and
its embeddings are cached on disk; on the compose stack that cache is a named
volume, because rebuilding it costs the judge node about a gigabyte of resident
memory and a minute and a half on the first analysis.

## The evidence ledger

Every tool call an analysis makes is written down as it happens. The tool loop
wraps each tool, times the call, records the arguments, the outcome and the
result — parsed when the tool answered JSON — and hands the answer back to the
model with the entry's id stamped on the front:

```
[ev_0007]
{"machine": 332, "sections": [...], "imports": [...]}
```

Ids (`ev_0007`) are monotonic across the whole job. The triage pack's calls
are the first entries of every run that has one, under `agent="pipeline"`, and
the judge's own calls — threat intel on a disputed indicator, a knowledge
lookup — go through the same recorder under `agent="judge"`, so a verdict that
leans on one can cite it.
That stamp is what makes a report checkable: the model can cite the call it read
a fact from, a report section lists the entries it was built from, and `GET
/api/v1/jobs/{id}/evidence` serves those entries back.

Two bounds keep the ledger from becoming the thing it records. Each output is
trimmed on the way in, and each agent gets a byte budget
(`report.evidence_budget_bytes`); past the budget an entry keeps its arguments,
its outcome and its timing and drops its output, and the count of what was
dropped reaches the run summary. The ledger lands in the pipeline state as an
append-only list and is persisted with the report, in the same transaction.

## The findings block

An analyst may end its answer with a fenced `maljan-findings` block holding
JSON: `artifacts` (a kind, a label, and either a value or columns and rows) and
`findings` (a title, techniques, a confidence), each naming the ledger ids it
came from. It is optional in both directions — an analyst that emits nothing
loses no claim, and the CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE contract the
negotiation runs on is untouched. What the block adds is the *table* a claim
cannot carry: the import list, the permission set, the endpoints.

Anything that fails validation is dropped and counted rather than repaired, and
the block is stripped before the prose reaches the transcript or the report.

## Reporting

Every run emits a structured `MalwareReport` (`src/maljan/reporting/`), and it
is assembled from what the run gathered rather than recomputed beside it:

* `reporting/ledger_report.py` turns the ledger into `report.sections` — a
  builder per known tool, generic fallbacks (a JSON object becomes a key/value
  block, an array of objects a table, anything else a capped text block) for a
  tool nobody has written yet, the agents' artifacts grouped by kind, and their
  findings as one table. Every section carries the entry ids behind it.
* `reporting/ledger_projection.py` fills the typed blocks — `static`,
  `dynamic`, `network`, `persistence` — from the same ledger, because several
  layers still read them. A tool that was never called leaves its block empty
  and every layer downstream of it degrades to silence.
* Identity comes from `identify_file` and `hashes` when they ran, and from the
  routing minimum (format, platform, and hashes the builder computes) when they
  did not.
* Severity, malware category and family attribution are the judge's, read off
  `x_maljan_assessment` on its bundle. Nothing in the builder computes a
  replacement — the CVSS-shaped sum that used to print a score out of ten was
  arithmetic over constants chosen in the builder, by code that had read no
  evidence.
* The capability matrix is a projection of the judge's technique list and the
  analysts' claims, carrying each source's own confidence unadjusted.
* `run_summary.evidence` counts the calls and `run_summary.sections_without_
  evidence` counts the sections that can name neither an entry nor a finding —
  the number that says whether the report is standing on anything.
* `qa/fp_linter.py` runs last and reports; it changes nothing. Its findings land
  in `run_summary.fp_warnings`, including C6 (a section or TTP row with nothing
  citable behind it) and C7 (a technique id the validation loop could not get
  resolved).

The API renders the report as Markdown, HTML and PDF, and exposes the STIX 2.1
bundle, a MITRE view, the extracted indicators, the detection signatures that
fired and a timeline. Post-hoc enrichment fills VirusTotal, AbuseIPDB, WHOIS and
GeoIP reputation into the indicator set after the verdict has shipped.
