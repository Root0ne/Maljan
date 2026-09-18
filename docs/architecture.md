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
| Worker (`apps/api/app/worker`) | arq process. Takes an analysis job, runs the pipeline, writes the report and publishes progress events. One job at a time. |
| Enrichment worker (`apps/api/app/worker/enrich_worker.py`) | A second arq process on a queue of its own, for the post-verdict reputation lookups. Two at a time by default, and off unless the deployment turns it on (see below). |
| Core (`src/maljan`) | The analysis package: agents, the LangGraph pipeline, the deterministic evidence layers, the provider layer, memory and reporting. |
| Postgres | Users, samples, jobs, reports, audit rows and the settings store. |
| Redis | The arq queue, the per-job event stream, and rate-limit counters. |
| MinIO | Sample bytes, in the bucket named by `MINIO_BUCKET`. |
| Qdrant | Long-term memory: past analyses and family fingerprints as vectors. |
| Tool servers (`services/`) | stdio MCP sidecars bound to one agent each: PCAP tooling for the network analyst, VirusTotal and AbuseIPDB for the judge. |

## Request and job lifecycle

1. The console authenticates and uploads a sample. The API streams it through
   `UPLOAD_TEMP_DIR`, hashes it, stores the bytes in MinIO and the metadata in
   Postgres, and writes an audit row. The object store's client is synchronous,
   so every call into it — the sample, an uploaded sandbox report, a delete —
   is made from a worker thread: a hundred megabytes sent from the event loop
   is a hundred megabytes during which the process answers nothing else, its
   own health check included.
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
6. Threat-intelligence enrichment runs afterwards as its own job, on the
   enrichment worker's queue, so it delays neither the verdict nor the next
   analysis.

### The two worker processes

    uv run arq app.worker.analysis_worker.WorkerSettings
    uv run arq app.worker.enrich_worker.EnrichmentWorkerSettings

The analysis worker reads arq's default queue and runs **one job at a time**:
two analyses on one host would share a model, a sandbox and a memory budget
sized for one. The enrichment worker reads `arq:queue:enrichment` and runs two
at a time (`ENRICHMENT_MAX_JOBS`), because a reputation lookup waits on
somebody else's HTTP.

They were one process, and the single slot was the cost: a measured enrichment
spent 451.98 s at VirusTotal while the next analysis sat `pending` for 4 m
33 s. Nothing about that lookup needed the rule it was subject to.

**Which one a deployment gets.** `api.enrichment_dedicated_worker` decides, and
it ships **off**: a release that is taken and run unchanged keeps one process,
with the enrichment queued beside the analyses and deferred until none is
running — the old behaviour and the old delay, but nothing stops working
because a process nobody started is missing. The compose stack runs the second
worker and sets `ENRICHMENT_DEDICATED_WORKER=true` beside it, which is the
default the setting falls back to; an operator's saved value wins over both.
Turn it on wherever the second process actually runs.

When it is on and nothing is reading the enrichment queue — arq's own
per-queue health key is absent one health interval after the analysis worker
boots — the worker logs one warning naming the queue and the command that
reads it, and `GET /api/v1/system/status` reports `enrichment_worker` as
`down`. Queued enrichments are kept, not dropped: they run when a worker
starts.

The task is registered on both workers so the single-process default has
something to run it, and the nightly `job_events` purge stays on the analysis
worker: one owner per scheduled task. The enrichment worker runs
`ENRICHMENT_MAX_JOBS` (default 2) at a time — more than one because each job
waits on somebody else's HTTP, not many more because they share one VirusTotal
key and one AbuseIPDB key and a provider's rate limit is per key.

### What the worker holds while a run is in flight

No database transaction. The worker opens one session before the models start
— the job row, its sample, the stored settings, any attached sandbox report,
and the move to `running` — and closes it again before the pipeline is built.
The run's writes open sessions of their own: the event feed's batches as they
fill, and one transaction at the end for the report, the agent findings, the
evidence ledger, the transcript and the completion, which go together because
the report's sections cite the ledger's ids.

A session held for the length of an analysis is a backend sitting `idle in
transaction` for as long as the run takes. One was measured at 13 minutes 51
seconds, holding an `AccessShareLock` on `analysis_jobs`, `analysis_reports`
and `runtime_settings`: a migration's `ALTER TABLE analysis_reports` queued
behind it, every read of that table queued behind the ALTER, and
`GET /api/v1/jobs/{id}` timed out for four minutes while `/health` answered in
milliseconds. The enrichment task follows the same rule — it reads the
report's payload, closes, spends as long as the reputation lookups take
(452 s on one measured report), and opens a second session to write the
result.

A failed run records its failure through a session of its own. The session the
run was writing through is the one most likely to be unusable — a terminated
backend leaves every statement on it raising `PendingRollbackError` — and that
is how a job came to publish its `error` event and still read `running`, with
no error and no `completed_at`, for as long as the worker stayed up. What the
row then says is the class of the exception and the id of the log entry
holding the rest: `error_message` is a field of `JobResponse`, so an
exception's own message put there is published, and a failure names a path or
a connection string as readily as anything else. The exception to that is
`StatedFailure` and its subclasses — the failures this module words itself,
from constants and from ids this system issued — whose sentence is the answer
and travels whole: an absent analysis, an attached report that belongs to
another sample, a sandbox provider that cannot take one.

### Who owns a running job

The worker that is running it says so, and keeps saying so. While
`run_analysis` runs it holds `maljan:job-owner:<job id>` with its own id in it,
for 90 seconds, refreshed every 30 by a task of its own; the key is dropped on
success, failure and cancellation alike. A `running` row whose key is absent is
a row nobody is working on.

Neither of arq's own keys can answer that question. The in-progress claim
(`arq:in-progress:<job id>`) is written once and lives for the job timeout, so
it outlives the process that wrote it by hours; the health key is queue-wide
and lives 31 seconds past its last write, so a worker killed a moment ago still
looks alive — and a restarted container looks at it within seconds of that
kill, which is exactly the case the sweep exists for.

The sweep therefore runs on its own clock rather than at the instant of
startup: one owner TTL after the worker boots, so a crashed worker's last
heartbeat has certainly expired, and every ten minutes after that — which is
also what reaches a job a still-running worker gave up on, the case that left
one job reading `running` for an hour. Two rules point the other way, both
towards leaving a job alone: a row younger than one TTL is left for the next
pass, because a worker may have claimed it a moment ago, and a job this process
is running is never swept whatever Redis says. If Redis cannot be read, nothing
is touched and the reason is logged once, because ownership cannot be
established without it and guessing costs somebody else's run.

A run that ends in `CancelledError` is told apart by the cancel flag the API
writes when somebody presses stop (`analysis:{job_id}:cancel`, which the
heartbeat also polls). The flag is there: the operator asked, so the task
writes `cancelled` on the row through a session of its own, whether the
heartbeat noticed or the cancel landed between two of its polls. No flag: arq's
`job_timeout` or a worker shutting down, where the process is going away and
writing a row races its own teardown — the heartbeat goes with it, so the next
sweep pass marks the job failed within ten minutes.

### What a request holds while it waits on somebody else

Nothing either. A request-scoped session is in a transaction from its first
statement — on an authenticated route, the dependency that resolved the caller
— and stays in it until the handler returns, so a handler that then waits on a
third party leaves a backend `idle in transaction` for the length of that
wait. The routes that do wait end the read first, through
`database.end_read_transaction`: the three probes (`/settings/test/{probe}`,
`/test/mcp`, `/test/agent`, up to five minutes at a model endpoint), the
VirusTotal registration, and the long-term-memory purge, which scrolls a whole
Qdrant collection. The session stays usable; the next statement opens a
transaction of its own.

The WebSocket route holds no session across the stream at all. The handshake
reads the account and the job's owner inside a session, closes it, and then
accepts or rejects; a resume reads one page of the feed per session and sends
it after that session has closed, because the send goes at the client's pace
and a thousand frames to a slow reader is not something to hold a transaction
across. The account re-check on the clock opens a session of its own each
time.

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
next: `identify_file` and `hashes`; `signing_info` for the routed format alone
(Authenticode for a PE, the APK signing block for an APK, `LC_CODE_SIGNATURE`
for a Mach-O, and for anything else the fact that it has no signing scheme);
the format tool the routed type selects (`pe_info`, `elf_info`, `macho_info`,
`apk_info`, `document_info` or `archive_list`, which carry the section
entropies, the packer signature hits and the import rows); a `strings` head
capped by `triage.strings_head` and `iocs_from_file`; `yara_scan`, `capa`
under the static provider's budget and, when a sandbox report exists,
`sigma_match_sandbox`; `api_capability` over the import set (the behaviour map
is Windows-only, so an ELF or Mach-O import table yields no profile and no
rule hit) and `lolbin_lookup` over the sandbox's command lines; the sandbox
projections at summary level (processes, network, signatures, dropped
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

**Every model reads it.** `triage_pack.render_pack` turns the entries into one
line each — `[ev_0001] identity: pe windows, 4,486,656 bytes, …`,
`[ev_0003] signature: none`, `[ev_0007] yara: 2 hits of 30 rules (…)`,
`[ev_0008] capa: 6 capabilities, ATT&CK T1027, T1055 (rule-asserted)`,
`[ev_0017] reputation: VirusTotal 31/75 malicious, labels Filisto` — cut at
`reporting.upstream_findings_max_chars` with a last line saying how many
entries were left out and that their full output is a tool call away. Under
the heading *Facts established before analysis (ledger ids in brackets; cite
them)* the block leads every analyst's first human turn (analysis and
revision alike), the mediator's and the verdict's human turns, the narrative
prompt and every composer section. The report's identity block and signature
rows come from the same entries when no model cited them. And because every
agent was shown the pack, the pack's ids are citable by every agent:
`isr.ungrounded_technique` no longer exempts an analyst whose own ledger is
empty when a pack is present — only a run with nothing citable at all (the
measurement baseline) is exempt.

**The run-state block.** `pipeline/run_state.py` derives a dozen lines from the
state — the sample, the identity, hashes, signature and reputation lines out
of the pack, which stages ran or were skipped and why, how many ledger entries
exist and which tools failed, and the steps and seconds a tool loop has left —
and puts them in the system turn between `=== RUN STATE … ===` markers. It is
regenerated on every model turn of a tool loop (the executor's prompt hook
rewrites the budget line) and replaced rather than appended, so a prompt
carries exactly one block; the forced-synthesis trim keeps the system turn and
the first human turn, so neither the block nor the pack is ever what gets cut.
It is read-only to the model: nothing a model says is written into it.

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
  recorded, because the false positive is a fact about the run. Two symmetric
  rules ask what a verdict over zero analyst claims rests on:
  `verdict.unsupported_benign` asks for the entry that establishes Benign (a
  signature is the usual one) and `verdict.unsupported_malware` for the entries
  that establish Malware (a reputation entry, a rule hit); either way the
  alternative offered is Suspicious with an inconclusive rationale, the judge
  is asked once, and the second answer is kept as given.

### The technique check

Four parts, all in `pipeline/validation.py` and `tools/knowledge.py`, none of
them a rewrite: the check produces violations and annotations, and the id an
analyst wrote stays the id in the report.

This is a change of method from the tree the paper was evaluated on (tag
`paper-2026-09`). That tree carried a re-grounding pass,
`ATTCKValidator.correct_isr_reports`, which replaced an analyst's technique id
with the alignment index's best candidate whenever the gate disagreed, so the
identifiers in a report were valid because the pass had made them so. Here
what holds by construction is that no invalid id goes unflagged: every id is
checked against the vendored catalogue, and one the catalogue lacks is
reported, flagged `technique_id_valid=False` and kept as written — an invalid
id can be kept, and then it is kept marked. The technique choice is the
model's, made under deterministic challenges: an id
the catalogue does not have, a domain or platform the sample cannot have, an
alignment the index disputes, and a corroboration count that says who else
named the technique. The gate is one of those challenges; it no longer
decides.

1. **Validity** (`attck.unknown_id`, exact). Every id against the vendored
   catalogue. When the catalogue cannot be read the check says so instead of
   answering "nothing unknown": `run_summary.validation.not_run` lists
   `attck.unknown_id` and the run carries a degradation reason.
2. **Domain and platform consistency** (`attck.platform_mismatch`, exact). The
   catalogue's domain and platforms for the id against the routed sample —
   a Windows PE is `enterprise`/Windows, an APK `mobile`/Android, an ELF
   `enterprise`/Linux, a Mach-O `enterprise`/macOS, an unknown platform is no
   check. Raised in the analyst's loop and on the judge's attack-patterns;
   the feedback names the technique, its domain and platforms and the
   sample's. `CapabilityCell` carries `domain` and `platforms` from the
   catalogue and the FP linter's C1 reads them.
3. **Alignment** (`attck.weak_alignment`, the paper's gate, heuristic). For
   every technique an analyst keeps, the claim text is ranked against the
   hybrid ATT&CK index; the claimed id's own TF-IDF gate score and the index's
   top candidates are written on the claim (`ClaimEvidence.alignment`). The
   violation is raised only when the index neither ranked the id among its
   candidates nor scored it at or above `validation.alignment_threshold`
   (0.05); the feedback lists the candidates and says the analyst may keep
   the id and say why. The ranking lives on the ISR record
   (`ClaimEvidence.alignment`) and in the judge's `TECHNIQUE CHECK` block; the
   report shows it only for a technique the gate questioned and the analyst
   kept. It runs only when the index is warm in this worker
   (`validation.alignment_gate = auto`); `validation.alignment_gate_build`
   lets the first run that wants it start the build on a thread and go
   without. The index never substitutes an id.
4. **Corroboration** (exact). Per technique in the run, `asserted_by` — the
   deterministic sources carrying their own ATT&CK ids: capa's `attck`
   field, a Sigma rule's technique tags, a YARA TTP rule's
   `meta.technique_id`, `lolbin_lookup` — and `claimed_by`, the agents.
   `api_capability` is not among the sources: the API catalogue associates a
   technique with an import set (BitBlt and CreateCompatibleDC read as screen
   capture on any GUI program), so its associations travel under
   `associated_by`, shown in a Catalogue column for reference and counted for
   nothing. An asserted id the catalogue has retired
   (upstream Sigma rules and the case corpus still name a few) is marked
   `retired in ATT&CK 19.2` in the table. Two flat lists in
   `run_summary.corroboration`, rendered as a table in the report and shown
   on the console's technique cards. No weights, no score; a technique
   nothing asserted keeps its row with the empty list showing, which is the
   firing-rate reading the paper argues for.

What the check questioned and the analyst kept reaches the judge as a
`TECHNIQUE CHECK` block beside the evidence summary, and the report's
validation section lists the unresolved rows with their messages.
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
* `run_summary.corroboration` — per technique id, the two lists item 4 of
  the technique check describes, `asserted_by` and `claimed_by`, with no
  score. The same collection builds the judge's evidence-summary block, so
  the metric and what the judge read cannot disagree.

A degraded run is not capped. The judge is told in the prompt why the run is
thin — no sandbox report, an analyst that failed, a container nothing could
open — and sets its own confidence; the report header states the same reasons.

One more repair belongs here because it decides whether an analyst's answer
exists at all. A tool loop that ends on a turn that is not a report is asked
once more for one (the final-answer nudge). A live loop ended on an assistant
turn whose tool call carried arguments that never parsed; no tool ran, and
sending that turn back made the server fail rendering it ("Failed to parse
tool call arguments as JSON", HTTP 500). The nudge and the forced synthesis now
send the transcript without such a call — the turn's own words stay — and when
the plain request still fails, the nudge asks once more with the loop's tools
bound and `tool_choice="none"`, the one other shape the server accepts.
`run_summary.nudge.retry_mode` names which analysts needed which repair.

## Agents and teams

Nine agent definitions ship built in. Five have a class behind them: the
`static`, `dynamic` and `network` analysts, the `judge` and the `reporter`.
Four are a prompt and a tool list and nothing else: the three generic agents —
`triage`, `android_static` and `reverser` — that the `mobile` and `deep_static`
teams are built from, and `lead`, whose role is `lead` and whose tools are the
other analysts (see *Delegation* below). Each definition carries its role,
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

Five teams are seeded, and every one of them is editable only in its debate
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

**`team_lead`** is a team led by one agent: the pack, then a `lead` stage whose
only agent is `lead`, then the verdict and the report. The specialists —
`static`, `dynamic`, `network`, `reverser` and `triage` — are the lead's tools
rather than stages, so which of them work on a sample, in what order and how
often is the lead's decision rather than a fixed sequence. Their tool calls are
in the ledger under their own keys and their answers are in the transcript,
addressed to the lead.

It is the one seeded team with no debate stage. A debate is agents arguing
with each other, and this team has one analyst: the stage would hand the lead
its own report, ask it to revise against nobody, and cost a second full loop —
with the asks that loop makes — for a round that cannot change a position. The
disagreement happens in the lead's own asks instead, where a specialist that
contradicts it does so in the answer it reads.

![The team_lead team](assets/team-team-lead.svg)

The diagrams are generated from the seeded profiles by
`scripts/goldens/render_team_graphs.py`, and
`tests/unit/scripts/test_render_team_graphs.py` fails if the committed SVGs
stop matching the teams, so a stage that moves cannot leave the page behind.

The three generic agents these teams are built from — `triage`,
`android_static` and `reverser` — and the `lead` are seeded definitions like
any other, with their prompts in `src/maljan/agents/prompts/`. A generic agent
is a definition and a prompt and nothing else, which is what makes a team
something an operator can write rather than something that needs a class.

### Delegation

An agent may ask another agent for work the way it calls a tool, because it
*is* a tool. `ToolRef(kind="agent", agent="static")` on a definition puts
`ask_static` in that agent's toolbox, with one required argument `task` and an
optional `context`, described from the static analyst's label and role. Any
analyst may carry such a reference — a lead that gives out work, a static clone
that checks a point with the network analyst — and an agent with none cannot
ask anyone, which is what keeps the `default` team's analysts what they were.

Calling it runs the named agent under the same job: the same container, the
same sample paths (its own provider's mirror first, as a stage agent gets), the
same triage pack at the head of its first turn and the same run-state block in
its system turn. The callee's human turn is the task, with the context after it
and the claim format it answers in; it runs its own tool loop, its answer is
parsed into claims and checked by the technique check in its own conversation,
and the resulting ISR text — the claims with the ledger ids they cite — is the
tool result, word for word. Nothing between the callee and the caller edits a
claim, a confidence or a technique id (`tests/unit/test_no_silent_overrides.py`
holds for `agents/delegation.py` like for everything else).

Everything the exchange did is in the machinery every other tool call is in.
The callee's own calls are ledger entries under the callee's key, handed to the
caller's buffer so the stage node that drains the caller writes them all. The
ask itself is a ledger entry under the caller's key with `server="team"`,
`tool="ask_<key>"`, the task and context as its arguments, the answer as its
output and the callee's wall clock as its duration — so a report can cite the
ask (`ev_0012`) or what the specialist looked at (`ev_0009`). The callee's turns
carry a budget of their own (`core.agents.delegation_steps`,
`core.agents.delegation_timeout_seconds`): the caller's step budget is not
spent by its specialists' work, only its wall clock is, and an ask is cut to
the time the caller has left and refused when that is below what a first model
turn needs. A callee that reaches its step cap writes up what it gathered, the
way an analyst at its own cap does. Two `agent_message`
events carry the exchange, each with `stage`, `round` and `addressed_to`: the
caller's ask, addressed to the callee, and the callee's answer with its claims,
addressed to the caller. The console draws the arrow live, and in the replay
window the events are still in; `agent_messages` has no column for `stage` or
`addressed_to` yet, so a transcript read after the events expire shows the
lines without the arrow until the event model carries them.

What the callee's answer is checked against is the task plus what the callee's
own tool calls returned, read from its ledger entries — which the ledger has
already trimmed to its per-entry cap. A stage agent's answer is checked against
its full data chunk, so with `use_claim_consistency_gate` on a delegated claim
citing something past that cap is dropped where the same claim in a stage
survives.

Four guards, each a tool error the model reads rather than a job failure. A
callee that is not defined, or is disabled, is refused by name. An ask that
would nest deeper than `core.agents.delegation_depth` (2: a stage's agent asking
a specialist is depth 1, that specialist asking another is depth 2) is refused
with the chain that reached it; the depth bounds the nesting, never how many
times an agent may ask. An ask back up the chain — the callee asking its
caller, or anyone already waiting on this answer — is refused as a cycle. And
an ask that would come back with a server the asking stage withholds is refused
naming the stage and the servers: a callee's effective tool set is everything
it is bound to — the `mcp` references on its own definition and the servers
whose `agents` list names it — narrowed by the tool policy of the stage doing
the asking, so a stage with `builtin_tools=False` cannot reach `knowledge` or
`network` through a colleague that no stage narrows, whichever way that
colleague was bound to them. The settings model refuses the static cases
at save time: a reference to an agent that does not exist, to the definition
itself, to the judge or the reporter, or on the judge or the reporter.

One agent does one thing at a time, on both sides. A caller's asks take its own
lock, so two `ask_*` calls in one assistant turn — which langgraph gathers and
runs at once — go one after the other rather than putting two nested loops on
one llama-server slot. An ask of an agent, a second ask of it and its own stage
run take *its* lock, because all three drive the same buffers and the same call
chain. The two are different objects, which is what lets an ask made from
inside an ask still nest. A caller waits for a busy callee only as long as it
can still read an answer in, and one that does not free up in that time is a
refusal like the others. An agent asked twice with the same task is served the
second time and refused the third, by the same repeat guard every tool has.

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

Each sidecar also answers `capabilities`: which of its tools need an optional
library, a binary or a setting, and which of those are present on its host,
probed when the server starts. The registry keeps the manifest on the server's
entry when it attaches, the settings probe returns it so the console's server
card names the unavailable tools before a run, and an analysis stage records
each bound tool the manifest marks unavailable as
`server.<key>.<tool>_unavailable(<reason>); <remedy>` when it starts. A tool
that cannot answer returns an error with a code and an authored remediation
(`maljan.tools.errors`) rather than raising, and the sidecars' guards rewrite
an implementation's flat error into that shape. See *Writing a tool server* in
[configuration.md](configuration.md).

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
leans on one can cite it. An agent's ask of another agent is an entry under
`server="team"`, `tool="ask_<key>"`, and the calls the asked agent made are
entries under its own key (see *Delegation*).

A call that failed is an entry with `ok` false whichever way it failed: a
tool that raised, and a tool that returned an error. The entry keeps the
message in `error` and, when the tool authored one, the remedy in
`remediation`; `run_summary.evidence.failures` lists each distinct failure
once with its count and the report header prints that list. The console does
not read that summary — its evidence row shows the message and the remedy
under the call itself, from the ledger entry.

The tool loop also meters itself. `budget_tick` events carry an agent's steps
against its cap and seconds against its limit every five steps and at the end
of each loop; `stage_ended_at_cap` says which cap ended the work when one did
(`steps`, `time`, `repeats`, or the triage pack's `budget_seconds`); and
`run_summary.budget` sums the spend per agent, with the caps it hit, so a
reader learns that an analyst ran out of steps from the summary and the
pipeline panel rather than from a log line.
That stamp is what makes a report checkable: the model can cite the call it read
a fact from, a report section lists the entries it was built from, and `GET
/api/v1/jobs/{id}/evidence` serves those entries back.

Two bounds keep the ledger from becoming the thing it records. Each output is
trimmed on the way in, and each agent gets a byte budget
(`report.evidence_budget_bytes`); past the budget an entry keeps its arguments,
its outcome and its timing and drops its output, and the count of what was
dropped reaches the run summary. The ledger lands in the pipeline state as an
append-only list and is persisted with the report, in the same transaction.

An entry that lost its output that way says so with `truncated`, and the
column is the only thing that says it: a call that failed carries an empty
output too, so a reader inferring the trim from the emptiness explains a
failure with a cause that did not happen. `truncated` is persisted alongside
`repeated_of` (the earlier identical call a repeat was answered from), `symbol`
and `started_at`, and the evidence endpoint returns all four.

The rows are written in one batch when the run ends, so `created_at` used to be
the flush for every one of them — thirty entries of one run had one distinct
value between them, and a ledger sorted by it said nothing about when anything
happened. It is now the moment the call returned, `started_at + duration_ms`,
computed as the row is built. A call the recorder never stamped keeps the write
time, which is honest about being the batch's.

## Events

A run narrates itself. Every node, every tool wrapper and every retry loop
emits events through one sink (`src/maljan/pipeline/events.py`), the worker
publishes them (`_publish_event` in `apps/api/app/worker/analysis_worker.py`),
and the console draws the running analysis from them.

| Event | Emitted by | Payload |
|---|---|---|
| `status_change` | the worker | `status` |
| `pipeline_started` | the worker | `agents`, `sample_filename`, `sha256` |
| `roster` | the worker, once, before anybody speaks | `agents[{key, label, role, stages, via}]`, `stages[{key, label, kind, agents}]` |
| `agent_progress` | the worker and the analyst nodes | `agent`, `phase` |
| `phase_change` | the worker | `phase` |
| `stage_started` / `stage_skipped` / `stage_finished` | the stage nodes | `stage`, `kind`, and `agents` / `reason` / `ran`, `duration_ms` |
| `agent_message` | every speaking node | `speaker`, `role`, `round`, `status`, `text`, `kind`, and optionally `stage`, `addressed_to`, `display_name`, `confidence`, `claims`, `dissent`, `report`, `report_truncated` |
| `agent_message_delta` | the analyst loop, behind `core.events.stream_deltas` | `stage`, `agent`, `text_delta` |
| `tool_call_started` | the evidence recorder | `stage`, `agent`, `tool`, `server`, `args_summary` |
| `tool_call_finished` | the evidence recorder, as each entry is written | `stage`, `agent`, `tool`, `server`, `evidence_id`, `ok`, `duration_ms`, `summary` |
| `validation_feedback` | `pipeline/validation.retry_with_feedback` | `stage`, `agent`, `code`, `message`, `retry_index` |
| `judge_question` | the judge's ReAct loop | `stage`, `text`, `addressed_to` |
| `budget_tick` / `stage_ended_at_cap` | the budget meter | see *The evidence ledger* |
| `enrichment_complete` | the enrichment worker, after the run | `report_id`, `domains_enriched`, `ips_enriched`, `similar_samples` |
| `completed` / `error` / `cancelled` | the worker | the outcome |

`agent_message.kind` is one of `says`, `tool_call`, `tool_result`,
`validation_feedback`, `judge_question`, `verdict`, `system`,
`delegation_ask`, `delegation_answer`. An ask and its answer are the last two,
with `addressed_to` naming the other side, which is what draws a delegated
exchange as an arrow between two participants rather than as two lines to the
room.

**Sequence.** The publisher stamps every event with `seq`, a per-job counter
taken from a Redis `INCR`. Nothing in `src/maljan` numbers anything: the core
does not know which job it is running under, and a second counter would order
one conversation two ways. `seq` is the ordering key, the dedupe identity and
the cursor a client resumes from — `?since=<seq>` on `/ws/analysis/{id}` and
on `GET /api/v1/jobs/{id}/events` return only what is newer, in order.

The stored transcript row carries the payload its event carried: its `kind`,
the `stage` it was said in, the addressee of a delegated line and the
`display_name` its speaker was known by. A replay therefore groups by stage and
keeps the arrow between an ask and its answer, rather than re-deriving a kind
that cannot distinguish the two. A run recorded before those columns existed
carries none of them, and the console falls back to deriving what it can.

The stored transcript row is written with the number its event went out under,
so a live message and its replayed twin are one message. That changed what
`agent_messages.seq` means: it used to be the message's position within the
report, `0, 1, 2, …`, and it is now the publisher's run-wide count, so it is
**monotonic and sparse** — a conversation of twelve lines in a run that
published four hundred events has twelve numbers scattered through 1..400.
Ordering is unchanged, and `ORDER BY seq` is still exactly the order the
messages were said in; what is no longer true is that the numbers are
contiguous or that they start at zero. A run recorded before this release
keeps its old contiguous numbers, which still sort correctly among themselves;
because those are a *different* number from the same run's live events, the
report endpoint sends them as `null` rather than let a client mistake one for
a publisher number. It tells the two apart from the rows themselves: a
numbered run's largest `seq` is at least its row count, and the old
`enumerate` numbering's is exactly one less.

**Two stores.** Events go to the PubSub channel `analysis:{job_id}` for the
live fan-out, to the Redis stream `analysis:{job_id}:events` (1 000 entries,
24 h), and to `job_events` against the job, written in batches of fifty events
or two seconds. The table is what makes a failed or cancelled run readable: no
report is written for one, so before it the whole conversation vanished with
the stream. Both readers ask Redis first and the table second — when the
stream has expired, and when the cursor is older than the capped stream
reaches. `core.events.retention_days` (default 30) bounds the table; the
worker sweeps it nightly. The transcript, the agent findings and the evidence
ledger are kept by the report and the job and are not touched by the sweep.

**The count is the last number.** Every event takes a sequence number from the
run's counter, so the rows stored for a job equal the last number issued for
it — that is what the events endpoint pages by and what the console checks its
history against. `enrichment_complete` is published after the run has ended,
by the other worker, so the enrichment task opens the job's feed for that one
line and closes it again; otherwise the number would be issued and the row
never written, which is what one measured run's 71 published and 70 stored
was. The console already tolerates an event that arrives after the run.

The counter itself is a Redis key with the stream's 24-hour life, and the rows
outlive it by `core.events.retention_days`. So before that late event is
numbered, the counter is seeded from the table — the highest `seq` the job
holds, set only when Redis has none — and the number continues where the run
left off instead of starting again at 1 and colliding with the row that has it
(`uq_job_events_job_seq`). Enriching a month-old report is exactly that case.

**What never travels.** Tool arguments and results go out as short summaries,
and every string of every event — a message's text and its report, a
correction, a cap's detail, a summary — is scrubbed once by the publisher, for
all three sinks at once: anything shaped like a credential is replaced, a URL
keeps its scheme and host only, and every path is cut to its file name. A
producer may scrub as well; the publisher is what makes it a guarantee rather
than a habit, and the transcript's copy is scrubbed as it is taken, so a
replayed run reads exactly as the live one did.

The fields that *name* something rather than say something are exempt, by
field name (`analysis_worker.IDENTITY_FIELDS`): the ids this system issues
(`report_id`, `job_id`, `sample_id`, `error_id`, `evidence_id`,
`technique_id`), the agent, stage, server and tool keys (`speaker`, `agent`,
`agents`, `addressed_to`, `stage`, `stages`, `via`, `server`, `tool`, `key`,
`profile`), the labels an operator typed (`label`, `display_name`) and the
words the console switches on (`role`, `kind`, `status`, `phase`, `cap`,
`code`, `verdict`). Nothing is exempt for the *shape* of its value beyond a
digest and a canonical UUID, because a credential does not become safe by
being lowercase.

A failed call travels as the remedy the tool offered, not as its error text,
and a failed node travels as the class of its exception, never its message.
The arguments and the output as they were are on the ledger entry, behind the
same ownership check as the report.

**Names.** `roster` carries the label an operator gave each agent, and `GET
/api/v1/jobs/{id}` carries the same roster, so a reader who is not an admin —
and cannot read the agent definitions through the settings endpoint — still
sees "Lead analyst" rather than `lead`, on a live run and on a finished one.

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
