# Changelog

Notable changes to Maljan. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); dates are the day a
change landed on `main`.

## Unreleased

### Added

- **The live conversation of a run, sequenced, kept and resumable.** Six new
  event types beside `agent_message`: `tool_call_started` /
  `tool_call_finished` (the latter carrying the evidence-ledger id the result
  is filed under, emitted as the recorder writes each entry, so the triage
  pack streams too), `validation_feedback` from
  `pipeline/validation.retry_with_feedback`, `judge_question` from the judge's
  ReAct loop, `agent_message_delta` from the analyst loop behind
  `core.events.stream_deltas`, and `roster` at pipeline start.
  `agent_message` gains `kind` (`says`, `tool_call`, `tool_result`,
  `validation_feedback`, `judge_question`, `verdict`, `system`,
  `delegation_ask`, `delegation_answer`), `display_name` and `seq`; an ask and
  its answer carry the delegation kinds with `addressed_to`.
  The publisher stamps every event with a per-job `seq` from a Redis `INCR`,
  and `?since=<seq>` on `/ws/analysis/{id}` and on
  `GET /api/v1/jobs/{id}/events` returns only what is newer. Events are now
  written to a `job_events` table against the job in batches of fifty or two
  seconds (revision `20260925000000`), so a failed or cancelled run — which
  writes no report — keeps its conversation; both readers take Redis first and
  the table second, which is what replays a run whose stream has expired.
  `core.events.retention_days` (30) bounds the table and the worker sweeps it
  nightly. `GET /api/v1/jobs/{id}` now carries the roster, so a non-admin
  reader sees the labels an operator gave the agents without the admin-only
  settings endpoint. Tool arguments and results travel as short scrubbed
  summaries — credential shapes replaced, URLs cut to scheme and host, paths
  cut to file names, a failure carrying its remedy rather than its error text.
  The same revision adds `agent_messages.addressed_to`, and the stored
  transcript row is written with the `seq` its event went out under, so a live
  message and its replayed twin are one message.
- **Changed:** `agent_messages.seq` is now the publisher's run-wide event
  number rather than the message's position within the report, so it is
  monotonic and **sparse** — it no longer starts at zero and no longer counts
  `0..n`. Ordering is unchanged and `ORDER BY seq` still yields the order the
  messages were said in; a query or fixture that assumed contiguous per-report
  numbering needs updating. Rows written before this release keep their old
  numbering and the report endpoint sends their `seq` as `null`, so a client
  cannot mistake a position for a publisher number and draw the line twice; it
  tells the two apart from the rows themselves, so the answer does not change
  when the event feed ages out.

- **Each tool server says what it can do on its host, before a run.** The four
  built-in sidecars answer a `capabilities` tool — per tool, its optional
  library, binary or setting, whether it is present, the reason it is not and
  its timeout — computed by probing when the server starts
  (`maljan.tools.capabilities`). The registry reads it once per job and keeps
  it on the server's entry; `POST /api/v1/settings/test/mcp` returns it under
  `details.capabilities` and the console's server card lists the unavailable
  tools with their reason; an analysis stage records each bound tool its
  server's manifest marks unavailable as
  `server.<key>.<tool>_unavailable(<reason>); <remedy>` when it starts, once,
  and such a reason does not make the run degraded by itself.
- **A tool failure names its remedy.** Sidecar tools return
  `{"error": {"code", "message", "remediation"}, "tool"}` with codes
  `missing_dependency`, `timeout`, `bad_argument`, `no_such_file`,
  `unsupported_format`, `not_configured` and `tool_failed`
  (`maljan.tools.errors`); the guards map exceptions to codes and rewrite an
  implementation's flat `{"error": "<text>"}` into the shape, which is still
  accepted from any server. A returned error is now a failed ledger entry
  (`ok` false, `error` the message, the new `remediation` the hint; revision
  `20260922000000` adds the two columns), `run_summary.evidence.failures`
  lists each distinct failure once with its count, the report header prints
  the list with the remedies, and the console's evidence row shows both.
- **The budget meter.** `budget_tick` events (per agent: steps used and cap,
  elapsed and limit, prompt chars, ledger entries) every five steps and at
  the end of each tool loop; `stage_ended_at_cap` when a cap ended the work
  (`steps`, `time`, `repeats`, or the triage pack's `budget_seconds`);
  `run_summary.budget` per agent (loops, steps, seconds, delegated steps, the
  caps hit); the console's conversation names the cap that ended an agent's
  work where it ended.
- **An agent can ask another agent, as a tool call.** `ToolRef(kind="agent",
  agent=<key>)` on a definition binds a tool `ask_<key>` (`task`, optional
  `context`) described from the callee's label and role. Calling it runs the
  callee under the same job — same container, sample paths, triage pack and
  run state — with the task as its human turn, checks its answer the way a
  stage answer is checked, and returns its ISR text verbatim. The callee's tool
  calls are ledger entries under its own key; the ask is an entry under
  `server="team"`, `tool="ask_<key>"`, with the callee's wall clock as its
  duration; two `agent_message` events carry the exchange with `stage`,
  `round` and `addressed_to`. An ask carries a budget of its own —
  `core.agents.delegation_steps` (12) and `core.agents.delegation_timeout_seconds`
  (300) — cut to the time the caller has left and to nothing else: a caller's
  own step budget is not spent by its specialists' work, only its wall clock
  is. Guards, each a readable tool error: `core.agents.delegation_depth` (2),
  a cycle back up the call chain, a callee that is undefined or disabled, a
  callee whose servers the asking stage withholds, and not enough time left to
  ask. The settings model and the API refuse a reference to an unknown agent,
  to the definition itself, to the judge or the reporter, and any such
  reference on those two. A new seeded definition
  `lead` (role `lead`, `src/maljan/agents/prompts/lead.md`) references
  `static`, `dynamic`, `network`, `reverser` and `triage`; a new seeded team
  `team_lead` runs it as its one analysis stage, with no debate stage — a
  debate over a single analyst hands the lead its own report, asks it to
  revise against nobody and costs a second full loop, with the asks that loop
  makes, for a round that cannot change a position; the disagreement happens
  in the lead's own asks instead
  (`tests/fixtures/golden/graph_team_lead.json`, `docs/assets/team-team-lead.svg`).
  The `default` team is unchanged. The console's agent editor offers **Ask
  another agent** in the Tools tree and the transcript draws the addressee
  arrow on an ask and its answer.
- **An id retired by a catalogue move is reported as retired, not invented.**
  `data/attck_retired_ids.json` — per id, its domain and the ATT&CK release
  that retired it — is written by the autoupdate script from the catalogue it
  is about to overwrite; `attck_validate` and `attck_lookup` carry
  `retired_in`, and `attck.unknown_id` and the judge's attack-pattern message
  add "(retired in ATT&CK 19.2)" so a stored report or a prompt still naming
  `T1562.001` reads honestly. The id stays as written.
- **The ATT&CK platform map ships beside the id catalogue.**
  `data/attck_platforms.json` carries, per technique, its domain and MITRE
  platforms, written by `scripts/knowledge/prepare_attck_malware_fixtures.py`
  from the same bundles as `data/attck_valid_ids.json`. `attck_loader.platforms_for`
  answers from it and consults the cached bundles only for a real id the map
  lacks; `tools.knowledge.attck_scope` gives a technique's domain and platforms
  from the two vendored files alone, and `attck.platform_mismatch` asks it, so
  a validation turn loads no STIX bundle and touches no network. A technique
  whose only platform is `PRE` is exempt from the platform half of the check.
  Both vendored files now come from ATT&CK 19.2.
- **The triage pack: the deterministic facts exist before any analyst starts.**
  A new stage kind `triage` runs the tools in `src/maljan/tools` in-process
  over the sample and writes each result to the evidence ledger as an ordinary
  entry under `agent="pipeline"`, `server="pipeline"`, in a fixed order:
  `identify_file`, `hashes`, `signing_info`, the format tool the routed type
  selects, a capped `strings` head and `iocs_from_file`, `yara_scan`, `capa`,
  `sigma_match_sandbox` when a report exists, `api_capability` over the import
  set, `lolbin_lookup` over the sandbox's command lines, the sandbox
  projections at summary level and `pcap_summary` when a capture exists, one
  reputation lookup on the sha256 through whichever reputation server is
  enabled (recorded under that server), and `function_matches` when a
  function-hash store is present. A tool that fails is an entry with
  `ok=False` and a degradation reason `triage.<tool>_failed`, never a failed
  job; the pack rewrites nothing a model says. The stage (`triage_pack`) is
  seeded first in `default`, `mobile` and `deep_static`, not in
  `measurement`; a stored team gains it through alembic revision
  `20260919000000`, which `downgrade` removes again. The builder starts the
  graph at a dependency-free triage stage and hangs every other root off it.
  Conditions may read `triage.has_signature`, `triage.reputation_malicious`,
  `triage.yara_hits` and `triage.capa_hits`; `run_summary.triage` carries
  `{entries, failed, duration_ms}`. Settings: `triage.enabled`,
  `triage.strings_head` (300) and `triage.reputation` (`auto` | `off`); the
  console's stage editor offers the kind.
- **Every model reads the pack, and a run-state block, on every turn.**
  `render_pack` turns the pack into one line per entry with its ledger id in
  brackets, cut at `reporting.upstream_findings_max_chars` with a line saying
  how many entries were left out; under the heading *Facts established before
  analysis (ledger ids in brackets; cite them)* it leads every analyst's first
  human turn, the mediator's and the verdict's prompts, the narrative prompt
  and every composer section, and the report's identity and signature rows
  come from the same entries when no model cited them. `pipeline/run_state.py`
  derives a compact block from the state — sample, identity, signature,
  reputation, stages run or skipped and why, ledger count, failed tools,
  remaining steps and seconds — and puts it in the system turn between
  markers, regenerated on every model turn of a tool loop and never trimmed.
  With a pack present, `isr.ungrounded_technique` no longer exempts an analyst
  whose own ledger is empty: the pack's ids are citable by every agent.
- **The ATT&CK technique check comes back in four parts, none of them a
  rewrite.** Validity keeps `attck.unknown_id` and, when the catalogue cannot
  be read, records `validation.not_run` and a degradation reason instead of
  an empty result. `attck.platform_mismatch` puts the catalogue's domain and
  platforms against the routed sample in the analyst's loop and on the
  judge's attack-patterns; `CapabilityCell` carries `domain` and `platforms`
  and the FP linter's C1 reads them. `attck.weak_alignment` is the paper's
  gate: on a warm ATT&CK index the claim text is ranked, the id's gate score
  and the top candidates are written on the claim and shown to the judge and
  in the report, and an id the index neither ranked nor scored above
  `validation.alignment_threshold` is questioned once — never substituted.
  `run_summary.corroboration` becomes `{technique: {asserted_by, claimed_by}}`,
  the deterministic sources that carry their own ids (capa, sigma, lolbin,
  api_capability) beside the agents, with no weights; the report renders the
  table and the console's technique cards show the two lists. Settings:
  `validation.alignment_gate` (auto | off), `validation.alignment_gate_build`
  (false) and `validation.alignment_threshold` (0.05).
- **A Malware verdict over a run nobody analysed is challenged, like Benign.**
  `verdict.unsupported_malware` asks the judge to cite the entries that
  establish it — a reputation entry, a YARA or capa hit — or to return
  Suspicious with an inconclusive rationale; one retry, the survivor recorded,
  nothing rewritten.
- **VirusTotal's own MCP server ships as a built-in tool server.**
  `virustotal` is seeded in `_builtin_servers()` on the streamable-HTTP
  endpoint `https://ai.virustotal.com/mcp`, disabled until an operator
  registers. **Connect VirusTotal** in the tool-server setup guide calls
  `POST /api/v1/settings/virustotal/register`, which obtains an agent token
  without a browser and without a VirusTotal API key, stores it encrypted like
  any other tool-server credential and enables the server. The six read-only
  lookups are ticked by default; `submit_file` is advertised and left unticked,
  because uploading a sample to VirusTotal is a disclosure the operator opts
  into. The `network` analyst, the judge and the seeded `triage` agent
  reference the server, and a disabled server costs them nothing.
  `services/threatintel-mcp` is unchanged and still serves deployments with a
  VirusTotal API key; `submit_local_file` remains available by running the same
  server over stdio, which `docs/deployment.md` documents.
- **Two more teams ship: `mobile` and `deep_static`.** `mobile` is triage, an
  Android static pass conditional on `file_type in ("apk", "dex")`, detonation
  conditional on a sandbox report, then the debate, the verdict and the report.
  `deep_static` is triage, the static pass, a `reversing` stage handed the
  static stage's findings and asked to confirm or refute each at function
  level, then a network stage conditional on a capture or a sandbox report.
  Both are built from three seeded generic agents — `triage`, `android_static`
  and `reverser` — whose prompts live in `src/maljan/agents/prompts/` and name
  no Windows artefact. Submitting a PE under `mobile` produces a run whose
  Android stage declines and says which condition it failed, rather than one
  that shows nothing.
- **The evidence ledger is a console tab.** `analysis/{id}/evidence` is the
  ledger itself: one row per tool call with its stage, agent, server, tool,
  arguments, duration and outcome, narrowable by stage, agent or tool, paged,
  and expandable to the full output and the parsed result. Every citation in
  the report renders as a chip linking to `?evidence=ev_0007`, which opens that
  row and scrolls to it, and the summary tab counts what the report is standing
  on. `GET /jobs/{id}/evidence` gains the `stage` filter the panel groups by.
- **Report sections lead the analysis tabs.** `ArtifactTable` renders an
  `EvidenceSection` from its own declared shape — table, key/value, list or
  prose — with the ledger ids behind it, so a tool server nobody wrote this
  console against reaches the report with its citations intact. Each typed tab
  draws its sections first and falls back to the extractor's own table only
  where no section covers the same ground.
- **The console draws a run as its stages.** The pipeline panel builds one row
  per stage — key, kind, agents, running or done or skipped with the reason,
  duration — from the live stage events while the run happens and from
  `run_summary.stages` afterwards, with the analyst rows nested inside the
  stage that ran them. The live page shows the same strip, and the agents table
  groups by stage and counts each agent's tool calls from the ledger. A run
  stored before the team was stages keeps the flat chain it always had.
- **A team that cannot use the tools it names says so.** A stage whose agents
  read the static provider's tools on a deployment where `static.provider` is
  `none` gets a non-blocking warning on its card, keyed by the same dotted path
  a validation error uses and carried on the settings PATCH response.
  `deep_static`'s reverser is the case it was written for: the stage runs, and
  the prompt it runs is written around a decompiler it will not have.
- **A stage condition is checked as it is typed.** `POST
  /api/v1/settings/validate-condition` runs the same `pipeline.conditions`
  parser against one expression and stores nothing; the stage editor calls it
  per blur, so a typo is answered under the box rather than at apply time.
- **The team diagrams are generated.** `scripts/goldens/render_team_graphs.py`
  draws each seeded team from the profile itself into `docs/assets/`, and a
  smoke test fails if the committed SVGs stop matching the teams.
- **A team is a list of stages, not a list of analysts.** A profile
  (`core.agents.profiles.<key>`) is now an ordered list of dependent,
  conditional stages — the way a human analysis team works: triage, static,
  dynamic, reversing, network and threat intel, correlation, report. Each stage
  says what it is (`analysis`, `debate`, `verdict` or `report`), who is in it,
  what it runs after, whether it runs at all (`when`), whether its members run
  at once or in turn, what it is told about the stages before it, how hard it
  argues if it is a debate, and whether its agents keep the built-in tool
  servers. `pipeline/builder.py` builds the graph from the stages;
  `pipeline/topology.py` names the nodes, and the default team's graph is the
  graph it always was, node for node and edge for edge.
- **A condition language for stages.** `pipeline/conditions.py` evaluates a
  stage's `when` against the sample and the stages before it, using Python's
  own parser with an allow-list on top: comparisons, boolean operators,
  literals, and `stages.<key>.<field>` — no calls, no arithmetic, no attribute
  access anywhere else. A condition that does not parse is refused when the
  team is saved, per stage and per field; one that fails at run time skips its
  stage with the reason recorded rather than failing the job. A stage that
  declines to run is still a node in the graph, so the topology is a property
  of the configuration and never of the sample.
- **What each stage did, recorded and announced.** `state["stage_results"]`
  carries a per-stage record — whether it ran, why not, the claims and
  techniques it produced, who was in it and how long it took — merged per stage,
  with a chain's durations adding up and a fan-out's taken as its slowest
  member. It reaches the reader as `run_summary.stages`, and evidence ledger
  entries now carry the stage they were made in. Each stage also announces
  itself live exactly once: `stage_started` from its first node,
  `stage_skipped` instead when its condition is false, and `stage_finished`
  from the one node that runs after everything in it is done — its own last
  node, or the next stage's first node for a fan-out with no barrier and for a
  debate that loops. Every producer's ledger entries name their stage: an
  analyst's, the judge's mediation and verdict calls, and the report's own
  capa/YARA rows, which all recorded the constant `analysis` before.
- **A stage can hand its findings to the next one.** `inject_upstream`
  (`none`, `findings`, `full`) gives a stage the upstream stages' claims — and
  optionally their prose — capped by the new
  `core.reporting.upstream_findings_max_chars`. The block goes in as a field of
  the stage's first chunk when that chunk is a JSON document, so a static or
  generic agent keeps the `analysis_file_path` contract its tools read, and
  never in front of it. It also cannot hide a missing input: the no-data guard
  runs on what the loaders produced.
- **An agent reads the data it is pointed at.** `agents.definitions.<key>.data_sources`
  names slices from `sample.path`, `sample.chunks`, `sandbox.target`,
  `sandbox.behavior`, `sandbox.network` and `sandbox.full`. Empty keeps the
  slice the agent's role has always read, so nothing changes until it is set.
- **`reporter`, a built-in definition.** The narrative and composer step has an
  LLM entry (`llm.agents.reporter`) and a prompt of its own instead of
  borrowing the judge's, and a report stage names it the way every other stage
  names its agents. With no entry set it falls back to the judge role, which is
  the model those rounds already ran on. The console treats it as the built-in
  it is: read-only, no Clone, `report` absent from the role list for a new
  definition, and not counted as a custom analyst on the setup hub.
- **Debate options per stage.** `max_rounds`, `consensus_threshold` and
  `sycophancy_check` belong to the debate stage that uses them, seeded from
  the global negotiation settings, so a team with two debates can run them
  differently.

- **Validation loops in place of silent overrides.**
  `src/maljan/pipeline/validation.py` turns "this answer is wrong" into a
  `Violation` the producer is shown, in the same conversation that produced the
  answer, with one turn to fix it. Analysts are told about a technique id the
  ATT&CK catalogue does not have (with up to three suggestions), a confidence
  outside `[0, 1]` and a claim citing no evidence; the judge is told about an
  indicator naming a value no tool saw, an attack-pattern with an unresolvable
  id, a severity outside the enum and a family named with no evidence ids.
  What is still wrong after the retry is returned rather than raised, and lands
  in `run_summary.validation` — the retry count, a count per code, and every
  unresolved finding with the agent that owns it. An unresolved technique id
  stays on the claim as the analyst wrote it, flagged `technique_id_valid`.
- **The judge decides severity, malware category and family.** Its verdict
  prompt asks for them and they come back on the bundle under
  `x_maljan_assessment` — severity with the rating and the rationale behind it,
  category as free text, family with the evidence ids the name was read from.
  The report prints what the judge answered: a severity nobody assessed prints
  as "not assessed", and a family the judge could not cite evidence for is kept
  and flagged unverified.
- **An evidence summary in place of a cascade score.** The judge's prompt
  carries, per technique id, every source that named it and each source's own
  confidence (`pipeline/evidence_summary.py`). Nothing is combined. The same
  collection is reported as `run_summary.corroboration`, so the metric and what
  the judge read cannot disagree.
- **A guard against the whole class of bug.**
  `tests/unit/test_no_silent_overrides.py` AST-scans `src/maljan` for writes to
  `technique_id`, `confidence`, `severity`, `malware_category` and `family` on
  objects that already exist, outside `schemas/`, `tools/` and
  `pipeline/validation.py`.

- **An evidence ledger.** Every tool call an analysis makes is written down as
  it happens — the agent, the tool server, the arguments, the timing, whether
  it worked, the result text and the parsed result when the tool answered JSON
  — and the result the model reads is stamped with the entry's id (`[ev_0007]`)
  so it can cite what it read. Ids are monotonic across the job. The ledger
  reaches the pipeline state as an append-only `evidence_ledger`, is persisted
  beside the report in one transaction, and is served by `GET
  /api/v1/jobs/{job_id}/evidence` (filters `agent` and `tool`, paged, the job's
  own ownership rules). `reporting.evidence_budget_bytes` caps what one agent
  may keep: past it an entry keeps its call record and drops its output, and the
  count reaches the truncation ledger, the job's stored run summary and the
  report's own header, so a reader is told what they are not being shown. The
  judge's tool calls go through the same recorder under `agent="judge"`.
- **A structured findings channel.** An analyst may end its answer with a fenced
  `maljan-findings` block holding JSON — `artifacts` (a kind, a label, a value
  or columns and rows) and `findings` (a title, techniques, a confidence), each
  naming the ledger ids it came from. Optional in both directions, validated
  item by item with the failures dropped and counted, and stripped from the
  prose before it goes anywhere. The three built-in prompts ask for it; the
  CLAIM/EVIDENCE/CONFIDENCE/TECHNIQUE contract is unchanged.
- **The report is assembled from that evidence.** `MalwareReport.sections` is
  built by `reporting/ledger_report.py` — one builder per known tool, generic
  fallbacks for a tool nobody has written yet, the agents' artifacts grouped by
  kind and their findings as one table — and every section carries the entry
  ids it was built from. `MalwareReport.evidence_index` lists the calls behind
  them without repeating their output, the renderers print the sections
  generically after the typed ones, and `run_summary.sections_without_evidence`
  counts anything that can name neither an entry nor a finding.
- **`network.icmp` is modelled.** A sample whose only outbound traffic was an
  ICMP probe rendered as a sample with no network activity at all; the CAPE
  render was dropping the list.
- **Every analysis capability is a tool.** `src/maljan/tools/` holds the
  implementations as plain functions — identity and hashes, strings and typed
  IOCs, PE/ELF/Mach-O/APK structure, archives, documents, payload carving,
  YARA, Sigma, capa, PCAP summaries and the ATT&CK / API-behaviour / LOLBin /
  retrieval lookups — and two new built-in stdio sidecars expose them:
  `analysis` (bound to the static analyst) and `knowledge` (bound to every
  analyst and the judge). Both carry `agents: []` and are bound only by the
  `ToolRef`s in the agent definitions, so a definition's tool list is what
  decides which tools an agent gets. `network-mcp` gains `pcap_summary`. They report facts
  rather than verdicts, and a missing optional library costs one tool's answer
  rather than the server. Install the per-format parsers with
  `uv sync --extra tools`.
- **The sandbox report as tools.** `ToolRef(kind="sandbox")` resolves to
  in-process tools over the job's report — processes, network, signatures,
  dropped files, registry operations, the categorised API-call histogram,
  mutexes, services and scheduled tasks, platform channels and a raw section
  reader — so the dynamic analyst can ask for what it needs instead of being
  handed the whole report as chunked text. The registry, API, mutex and
  service answers project into `report.dynamic.registry_mods`,
  `notable_apis` and the persistence list, which is what feeds the persistence
  tab and the generated Sigma rule's registry selection.
- **A measurement baseline profile.** `measurement` runs the same three
  analysts as `default` with every tool server withheld, the in-process sandbox
  tools withheld and the static provider forced to `none`.
  `ProfileDefinition.exclude_servers`, `exclude_sandbox_tools` and
  `static_provider` make that a profile rather than three cloned definitions
  that could drift from the ones being measured. The exclusion is `["*"]`, so a
  server an operator adds later cannot quietly rejoin the baseline, and
  `exclude_servers` is the one field editable on a built-in profile.
- **Remote sample delivery.** A tool server that cannot see the worker's
  filesystem advertises `put_sample` (with `put_sample_begin` /
  `put_sample_chunk` / `put_sample_finish` above 8 MiB) and is handed the bytes
  before the first tool call; the path it returns is what its own tools are
  then called with, per server. Staging never fails a run — a failure is a
  degradation reason and the local path is used — and the paths used are
  recorded on the run as `remote_sample_paths`, which stays empty on a default
  install. Only HTTP transports stage — a stdio sidecar shares the worker's
  filesystem and is handed the path — so nothing is copied unless a server is
  genuinely remote. The `analysis` sidecar implements the convention for the
  operator who runs it behind HTTP, writing under `MALJAN_STAGING_DIR` with
  `MALJAN_STAGING_TTL_HOURS` pruning.

- **A model is probed before a job may name it.** Both probes end by asking
  the model for one short answer — one turn, eight tokens, at the endpoint and
  on the model the run will use, through each provider's own completion API —
  and only a call that came back is written down as a passing `(endpoint,
  model)` row (`model_probes`, revision `20260924000000`). Submitting a job
  reads that record for every model the run can reach, the delegation targets
  of its team's agents included, and refuses with 422 naming the agent, the
  model, the endpoint and the probe's last message; saving a per-agent model is
  refused with the same sentence, and the console shows it as written in both
  places. A changed endpoint or model finds no row and is refused until it is
  probed. Where a call goes is worked out once, in
  `maljan.core.model_assignments`, for the probe and the gate alike, so a
  vendor API and a base URL with a trailing slash file and resolve under one
  spelling. The `llm` probe asks each pair once and one at a time, ninety
  seconds per call and five minutes for the whole probe; a pair there was no
  room left to ask is named as not tried and files no row, and a failing pair's
  sentence prints its endpoint as scheme and host.
  `core.llm.require_probe` is on; turning it off is the only way past, for an
  air-gapped batch run. The probe's OpenAI-compatible turn sends the same
  thinking switch the agents' provider sends, at every endpoint it asks, and
  reads a reasoning-only reply as an answer.
- **The same indicator or finding said twice is written once.**
  `reporting.dedupe` says what makes two indicators one — the kind and the
  value with its case, its padding and its defanging undone — and both the
  report's indicator table and the STIX bundle's integrity pass read it. A
  finding is fingerprinted on its first technique id and its normalised title.
  A fold keeps the first occurrence's words, its confidence and every other
  number as written, and grows only the set-shaped cells: the ledger ids, the
  agents, an indicator's labels. `run_summary.dedupe` states what was folded.
- **A tool call the model ran out of room to finish is closed off.** langchain
  marks a call whose arguments never parsed invalid and langgraph ignores it,
  so nothing ran and the loop ended holding a turn it paid a step for. The
  quote and the brackets the arguments are missing are appended — never
  removing, substituting or inserting anywhere but the end — and the call is
  made when the result parses; a trailing comma, a key with no value or a
  missing colon is still left to the path that drops it. The ledger entry
  carries `args_repaired` and `args_raw` (revision `20260923000000`).
- **The run, as one conversation.** A new CONVERSATION tab on an analysis
  (`/analysis/{id}/conversation`) draws a run as the group exchange it is,
  live and replayed by the same view: participants named by the label their
  operator gave them, messages grouped by stage and round, tool calls as one
  line each with the ledger id their result is filed under, validator
  corrections and cap notices as room notes, the judge's questions and
  delegated asks and answers with an arrow to the agent addressed, the verdict
  as a closing card, and streamed text appending into the speaker's open
  bubble until the message that closes the turn replaces it. Filters narrow it
  by participant and by kind; the stream follows the newest message while the
  reader is at the bottom of it and offers a way back when they are not.
- **What a reputation service said about the sample.** A run asks one service
  about the file's hash — `get_file_report` on VirusTotal's own MCP server, or
  `check_hash` on the threat-intel sidecar — and the console dropped the
  answer. IDENTITY now draws it beside the hashes, under the name of the
  service that gave it, with its engine counts, the labels the industry gives
  the file and when it was first and last seen. It is read from that service's
  ledger entry and from nothing else, so a configured service that was never
  asked draws no section.
- **One store and one socket per run.** `apps/web/src/lib/runStore.ts` holds a
  run's events, roster, stages, connection and cursor in a module-level map
  keyed by job id, opens the single socket a job gets, back-fills from
  `GET /api/v1/jobs/{id}/events` and resumes with `?since=<last seq>`. Leaving
  the analysis and coming back re-renders from what is already held instead of
  redialling and re-reading; the socket outlives the page by a grace period.
  Events order and dedupe on the publisher's `seq`, and a run recorded before
  the numbering existed keeps the order its events arrived in.
- **The dashboard says when enrichment has nobody to run it.**
  `GET /api/v1/system/status` reports `enrichment_worker`, and the console
  draws one notice for the single state an operator can act on: enrichment
  queued for a worker of its own with nothing reading that queue, which leaves
  every finished analysis holding its VirusTotal and AbuseIPDB lookups while
  the report reads as though there were none to make. The notice names what is
  waiting and the setting it is waiting on, `api.enrichment_dedicated_worker`.
  Nothing is drawn where enrichment runs beside the analyses, where its worker
  is up, or against an API that does not answer with the field.
- **An agent carries its own step and time budget.** `max_steps` and
  `timeout_seconds` on an agent definition, drawn on its card in the console as
  **Steps per loop** and **Seconds per loop**; blank inherits the deployment's
  `react_agent_max_steps` / `react_agent_timeout`. The seeded lead's 40 steps
  and 1800 s move onto its definition, so a clone of a team arrives with the
  budget its agents need rather than with five specialists to ask and the
  default ten steps to ask them in. Alembic revision `20260927000000` moves a
  stored override onto the definition it belongs to.
- **A JWT rotation's grace period has a written end.**
  `JWT_PREVIOUS_SECRET_NOT_AFTER` is the moment a token signed with the
  previous secret stops being accepted; `GET /api/v1/system/status` reports the
  rotation to an admin caller under `jwt_grace_secret` (the previous `kid`,
  when it lapses, whether it is still accepted), the API logs the same line at
  every start, and once it has lapsed the startup check warns until both
  settings are cleared. `docs/deployment.md` has the three-step runbook.
  Nothing rotates on its own.
- **Per-tool-call timing, per agent.** The run summary carries `tool_latency`
  — for each agent how many tool calls it made, what they cost together, and
  the single slowest with the tool that answered it, computed from the clock
  each ledger entry already carried — and the summary's header draws a **Tool
  calls** line beside **Per stage**. The analyst-latency log line names that
  slowest call, so a run that overran says whether the model was slow or a
  tool was.

### Changed

- **A previous JWT signing secret must say when it stops being accepted.**
  `JWT_PREVIOUS_SECRET_KEY` set without `JWT_PREVIOUS_SECRET_NOT_AFTER` now
  refuses the start, naming both, because a grace secret nobody remembers to
  clear is a retired key the deployment honours for good. If you are mid
  rotation, set `JWT_PREVIOUS_SECRET_NOT_AFTER` to an ISO-8601 moment a little
  past your refresh-token lifetime (read as UTC when it carries no offset)
  before upgrading, or clear the previous secret.

- **Deprecated: `react_agent_max_steps_overrides` and
  `react_agent_timeout_overrides`.** A budget belongs to the agent that spends
  it, so it is set on the agent's definition now. Both maps are still read for
  an agent whose definition sets neither, and a definition's own value wins
  over them; move any budget you keep in them onto the agent's card, because a
  later release drops them. The seeded entries for `lead` are already gone —
  the lead's budget is on its definition.

- **A run's watchers are no longer drawn as members of its team.** The
  mediator and the sycophancy detector publish as `pipeline` with
  `kind: "system"` and name themselves in the line, so the console draws a
  notice instead of adding a participant the operator never composed; the
  judge publishes under its agent key with its configured `display_name`,
  which is the key its roster entry carries, so a run draws one judge rather
  than two.
- **An analysis offers only the tabs the run filled.** A tab is drawn when the
  report carries what it draws — a ledger section routed to it, or its own
  typed block — so twelve tabs no longer stand ready for ten of them to
  apologise. SUMMARY, CONVERSATION and EVIDENCE are always offered, and a
  running job offers those three alone until the report fills the rest. Inside
  a tab the same rule reaches every panel: a run with no observed traffic
  draws no empty Domains table, and the only empty states left are the two
  that say something — a string filter that matched nothing, and a sandbox
  that traced no process because the sample detected it.
- **A row that says nothing is not drawn.** Across the report tabs, a
  key/value row whose value is empty, `-` or an empty list is dropped, and a
  key/value section whose every row said nothing is not drawn at all. IDENTITY
  applies it twice over: the `identity` section's hashes move into the File
  hashes block, which lists only the fingerprints a tool produced rather than
  a dash per field the extractor has, and its three signing rows — one per
  format `signing_info` knows about, of which all but one are that tool's
  untouched defaults — become the one for the format the run routed on, as a
  sentence rather than as `present=no`. SUMMARY's severity card is drawn only
  when the judge assessed a rating or named a category.
- **One list of analyses.** A report is a completed job, so `/reports` is gone
  and lands on `/jobs` with its status filter applied; the verdict it carried
  is a column on the row it belongs to, the search palette offers samples and
  analyses rather than three lists, and the dashboard shows the five latest
  runs as a way into the list rather than a second copy of it. On SUMMARY the
  verdict and the confidence are the header's, the techniques and the
  endpoints are counts that open the tab holding the lists, the threat-intel
  enrichment button is here once instead of on NETWORK and ATTRIBUTION both,
  and a Run record disclosure carries the job's configuration and what the run
  spent.
- **Settings open on what a first run needs.** Before a language model is
  connected the hub lists the four guides a first analysis needs and the
  configuration console is not offered — its route only bounced back to the
  guides — and a non-admin sees the two entries they can use rather than four,
  two of them permanently disabled. The LLM guide drops its Limits step, which
  staged five keys the console already renders. An analyst is drawn under the
  name its operator gave it, with its key beside it only where the two differ,
  in the stage list, the agent list and the run's stage strip.
- **One icon set, and no colour that eases into another.** `lucide-react`
  replaces the nineteen hand-drawn inline SVGs the console had and gives the
  navigation, the analysis tabs, the settings rail, the guide cards and the
  verdict badge an icon at 16 or 18 px in `currentColor`. Every one of the
  eighty-four `transition-colors` and the one `backdrop-blur` are gone: a
  hover state arrives with the pointer. A unit test reads the tree for
  gradients, colour transitions and the blur.
- **The nine retired analysis routes redirect from the server.** They were
  client components that mounted only to replace the URL; `next.config.ts`
  answers with a 308 instead.
- **The LIVE and PROCESS tabs are gone**, along with their duplicate socket,
  duplicate back-fill and second status poll. `/live`, `/process`, `/agents`,
  `/pipeline` and `/timeline` redirect to CONVERSATION, the per-agent results
  table sits under the conversation and states what each agent concluded while
  the participants strip above it states how much work each one did — one
  number, counted from the run's own feed and falling back to the ledger only
  for a run recorded before the feed carried tool calls — and the stage strip
  moved to the analysis header, where every tab reads the same one. The Pipeline and Timeline panels are removed: the
  discussion history, the confidence history and the agent reports they held
  are the conversation itself, drawn in the order they happened.


- **The report's capability profile is the pack's `api_capability` entry,
  cited by id.** `StaticAnalysis.api_capabilities` is counted from the entry's
  rows and `api_capabilities_evidence_ids` names the entry; the Markdown
  profile line, the console and the narrative prompt show the id. A technique
  rule from that entry is a row under the derived-technique table only when
  the APIs it matched clear its floor, with the entry id beside it, and the
  YARA draft takes its import strings from those rows as bare names. capa's
  namespaces are no longer counted as import capabilities; its technique hits
  stay. The family-feature profile carries the import names in the binary's
  order; a fingerprint catalogue built against the old vocabulary needs a
  rebuild with `scripts/knowledge/build_family_feature_kb.py`.
- **A debate hands over to exactly one node, and the settings say so.** A team
  whose debate feeds two stages — or one parallel analysis stage with two
  agents, which is two nodes — is refused when it is saved, per stage, instead
  of building cleanly and then failing every job in the graph builder after the
  sample was uploaded and detonated. The builder still refuses it, as the
  backstop for a document that reached it out of band.
- **The debate stage's consensus threshold decides something.** It was
  validated, migrated, round-tripped and editable, and nothing read it: the
  mediator used the global `negotiation.consensus_threshold`. A stage that sets
  one now argues to its own bar, and a stage that sets none still uses the
  global one it was seeded from.
- **A migrated team keeps following the global analyst-mode and round-limit
  keys.** The alembic revision marks the stages it writes as derived, so a
  database that was migrated and a fresh install produce the same team. Without
  the mark a team froze whatever those keys said on migration day, and an
  operator moving from a hosted API back to the single-slot local model would
  have kept running analysts in parallel. The console clears the mark on the
  first stage edit.
- **The settings console edits teams, not profiles.** `StagesEditor` replaces
  `ProfilesEditor`: a card per team, a card per stage, with the key, kind,
  agents, dependencies, condition, run mode, upstream setting, debate options
  and built-in tool switch on each, and move up/down that refuses a move which
  would put a stage above something it depends on. The setup guide's last step
  is "Add to a stage". `20260916000000_migrate_profiles_to_stages` gives every
  stored profile the stage list its analysts have always meant, using the
  stored `llm.parallel_analysts` and `negotiation.max_iterations`, and keeps
  the analyst list so the downgrade can put it back.
- **A degraded run is explained to the judge instead of capped afterwards.**
  The reasons a run is thin — no sandbox report, a failed analyst, a container
  nothing could open, anti-emulation behaviour — go into the verdict prompt and
  the judge sets its own confidence. The fixed 0.60 ceiling the report node
  applied afterwards is gone: it made every kind of thinness look identical and
  told the judge nothing.
- **The capability matrix is a pure projection.** It is built from the judge's
  technique list and the analysts' claims, and carries each source's own
  confidence. The cap that halved an obfuscation or injection claim whose
  supporting static evidence the module could not find is gone; an analyst that
  over-claims is told so in its own loop.
- **The indicator corpus check is feedback, not a filter.** An indicator whose
  pattern names a value no tool in the run saw comes back to the judge as
  `stix.ungrounded_indicator`, with the reason in words. Only what survives the
  retry is dropped, and the drop is recorded in
  `run_summary.validation.unresolved` — an ungrounded IOC in a STIX bundle is a
  false positive a reader is entitled to see.
- **The FP linter's C6, and a new C7.** C6 was "the Sigma/YARA platform filter
  reported no counters"; it is now "a report section or TTP row with neither an
  evidence id nor a tool entry behind it". C7 names technique ids the validation
  loop could not get resolved.
- **The rule corpora are configured on the `analysis` tool server.**
  `MALJAN_SIGMA_RULES_DIR` and `MALJAN_YARA_RULES_DIR` in that server's `env`
  replace `analysis.sigma_rules_dir`; a stored override for the old key moves
  automatically on upgrade.
- **Parsers format and nothing else.** The dynamic parser no longer labels an
  observation `[HIGH]`/`[MEDIUM]` from a keyword table, nor tells the analyst to
  emit a T1497 claim, and the network parser no longer prints a `[Suspicious]`
  verdict beside a DNS query. Both state what the sandbox recorded; what it
  means is the analyst's reading.

- **The report is built from the ledger, not recomputed beside it.**
  `MalwareReportBuilder` no longer calls an extractor per section. Identity
  comes from the `identify_file` and `hashes` calls when they ran and from the
  routing minimum when they did not; `static`, `dynamic`, `network` and
  `persistence` are projections of the same ledger
  (`reporting/ledger_projection.py`) and stay empty when the matching tool was
  never called. A typed section nobody filled is left out of the rendered
  report rather than printed as an apology.
- **capa and YARA reach the report as tool calls.** The evidence-only static
  provider writes its own ledger entries (`agent="capa_yara"`), so its rule hits
  print as sections like any other tool's and its capability counters still
  reach the layers that read `report.static`.
- **The static analyst's head chunk carries context, not a paste.** It keeps the
  analysis path, the host path, the toolchain and the routing verdict, and drops
  the pre-parsed section table, imports and strings — the analyst calls
  `pe_info` and `strings` for those, and the ids their results carry are what
  the report cites.
- **The provider goldens freeze the sandbox tools' answers** over the same
  98-report CAPE corpus, rather than the extractors' output, because that is the
  normalisation contract now: what an agent sees when it asks.
- **Tool-argument path pinning is shared.** The bare-filename guard moved from
  `ConfigurableAnalyst` to `agents/tool_pinning.pin_paths`, called by every
  analyst through `BaseAnalyst`, and now substitutes a different path per
  server. It matches three spellings of the sample — the worker path, its
  basename, and the basename of the staged copy — because a server that stored
  the sample under a name of its own would otherwise only be corrected for a
  name the model was never shown. `ServerRegistry.merge_tools` stamps each tool
  with the server it came from so the right path can be chosen.
- **The string and IOC scan moved** from `extractors/pe_extractor` to
  `maljan.tools.strings`; the extractor imports it and its output is unchanged.

- **Per-format sandbox submission options.** `sandbox.cape2.package_by_format`
  maps a detected file type to a CAPE analysis package (`*` is the fallback)
  and `sandbox.cape2.submit_options` is sent verbatim as further form fields;
  `sandbox.triage.profile_by_format` picks a Triage VM profile per format with
  `sandbox.triage.profile` behind it; `sandbox.rest.submit.submit_fields`
  passes extra multipart fields through the REST DSL. The CAPE guest platform
  is sent when CAPE has a name for it and left unset otherwise.
- **ATT&CK Mobile and ICS.** `data/attck_valid_ids.json` carries one technique
  id list per domain and the loader downloads and caches the Mobile and ICS
  STIX bundles beside Enterprise, exposing `valid_ids`, `domain_of` and
  `platforms_for`. A Mobile technique id now validates instead of being
  reported as a hallucination. Enterprise is required; the other two are
  additive and their absence costs coverage, not a run.
- **Open sandbox report channels.** `SandboxReport.channels` keeps what the
  schema has no field for, namespaced by platform (`android.permissions`,
  `linux.systemd`, `macos.launchd`). CAPE's non-Windows blocks are lifted into
  it, and the REST DSL gains `mapping.channels`, an operator-named
  name-to-JSONPath map.

- **A per-agent LLM base URL.** `llm.agents.<agent>.base_url` points one agent
  at its own OpenAI-compatible or Ollama server while the rest keep the global
  endpoint, with the provider's API key still shared.
- **Dependency submission for `uv.lock`.** A workflow posts the resolved Python
  packages to GitHub's dependency graph on every push to `main`, so Dependabot
  alerts close when the lockfile moves instead of lingering on the first parse.
- **Repository security posture.** CodeQL (Python, TypeScript, Actions;
  `security-extended`), dependency review on pull requests, OpenSSF Scorecard,
  Dependabot updates for every dependency surface, actions pinned by commit,
  `SECURITY.md` with private vulnerability reporting, `CONTRIBUTING.md`,
  code owners, issue and pull request templates. Secret scanning with push
  protection and Dependabot security updates are enabled on the repository.
- **Environment-free configuration.** Every application setting — LLM
  provider, sandbox, static analyst, tool servers, agents, rate limits,
  enrichment, memory — now lives in the settings store and is edited from
  Settings → Configuration. The catalog carries each entry's type, bounds,
  choices, description and when it takes effect, and a read-only Deployment
  group shows the values the process was started with
  ([#31](https://github.com/Root0ne/Maljan/pull/31),
  [#32](https://github.com/Root0ne/Maljan/pull/32),
  [#33](https://github.com/Root0ne/Maljan/pull/33)).
- **A bootstrap contract, validated once.** The API and the worker read a small
  fixed set of process-environment variables — database, Redis, MinIO, the two
  secrets, a handful of mount paths — documented in `bootstrap.env.example`.
  Validation happens at startup and reports every problem in one
  `bootstrap: ...` line instead of failing on whichever one an import reached
  first ([#31](https://github.com/Root0ne/Maljan/pull/31)).
- **Configuration export and import.** `GET /api/v1/settings/export` produces a
  `maljan-settings/1` JSON document and `POST /api/v1/settings/import` accepts
  it, with a preview in the console. The document carries no credential:
  secrets are skipped, masks nested inside composite settings are stripped at
  any depth, server `env` values are masked, and everything omitted is listed
  in `secrets_omitted` ([#32](https://github.com/Root0ne/Maljan/pull/32)).
- **Secret storage for nested credentials.** An MCP server's `auth_token` and a
  frontier arm's `api_key` are stored as their own Fernet-encrypted rows rather
  than inside the composite value, and are merged back on read; a startup
  repair moves any that an older version left inline
  ([#33](https://github.com/Root0ne/Maljan/pull/33)).


- **Built-in analysts honour a definition's own prompt.** The static, dynamic and
  network analysts now take their system prompt from the resolved agent
  definition on every run, so an operator's explicit `prompt` on a built-in
  role applies, and the format fragment for the sample's platform reaches the
  model. The module constants remain only as the neutral fallback.
- **The platform vocabulary is open.** `reporting.models.Platform` is a plain
  string with `KNOWN_PLATFORMS` beside it — `windows`, `linux`, `macos`,
  `android`, `ios`, `multi`, `unknown` — rather than a three-value literal.
  File-type detection recognises Mach-O, APK, DEX, JAR, IPA, OLE2, OOXML, PDF,
  LNK, the script formats and the archive formats, and returns lowercase
  routing labels. The persistence extractor selects its platform scanners
  positively, so the Windows registry sweep no longer runs for an Android or
  macOS sample.
- **Analyst prompts are platform-neutral plus a format fragment.** The built-in
  heads no longer name Windows artefacts; `agents/prompt_fragments` supplies
  the paragraph naming what to look for on the sample actually in hand, and
  `composition.builtin_prompt` assembles head, format fragment, provider
  fragment and tail for every built-in role.

- **PyJWT signs and verifies the API's tokens.** `python-jose` is gone from both
  projects; it was the only route by which `ecdsa` (an unfixed timing-attack
  advisory) reached the lockfile. Token format, claims and the dual-secret
  rotation window are unchanged.
- **Request-derived values are sanitised before they are logged.** Every job,
  sample, report and audit identifier that reaches a log line from a path, a
  query string or a request body now passes through `log_safe`, which escapes
  newlines and other control characters and bounds the length, so a caller
  cannot forge a second log record. The container images pin their bases by
  digest and the console's Node line moves to 22 across the images and CI.
- **Dependencies brought current.** The uv workspace is relocked to today's
  releases (cryptography 50, starlette 1.6, langchain-core 1.6, mcp 1.30 with
  2.x held back as a separate migration, pillow 12.3, pyjwt 2.14, urllib3 2.7,
  weasyprint 70 and the rest), and the console moves to Next.js 16.3.5 and
  vitest 4 with a regenerated lockfile. This clears every Dependabot alert
  that has a fix; the two without one (`ecdsa`, `diskcache`) are recorded in
  the alert list with the reason.
- The process refuses to start without a valid `SETTINGS_ENCRYPTION_KEY`, so
  there is no mode in which stored secrets sit unencrypted
  ([#31](https://github.com/Root0ne/Maljan/pull/31)).
- `APISettings` no longer discovers or reads a `.env` file; configuration comes
  from the process environment alone
  ([#31](https://github.com/Root0ne/Maljan/pull/31)).
- Pytest detection no longer consults the environment, so no variable can hand
  a real deployment the published test secret
  ([#33](https://github.com/Root0ne/Maljan/pull/33)).
- A settings reset in the console waits for its own page before touching the
  header, fixing a flaky interaction in the group editors
  ([#35](https://github.com/Root0ne/Maljan/pull/35)).
- Documentation is now a maintained set under `docs/`, and the historical
  design record — the former `docs/plans`, `docs/specs` and `docs/superpowers`
  trees — is read from git history instead of the working tree
  ([#38](https://github.com/Root0ne/Maljan/pull/38)).
- **`/reports/{id}/iocs` says where each row came from, and what it may
  publish.** The service attached a `source` to every domain row and `IOCEntry`
  did not declare it, so `response_model` dropped it and an uncorroborated
  string-derived name shipped looking exactly like one the sandbox had watched.
  The field is declared, along with a `published` flag, and mirrored in the
  console's client with its shape assertion. The feed is one other systems act
  on, so it now returns what the publish rule would publish by default;
  `include=all` returns everything and `include=unpublished` only the withheld
  rows. The console's IOC export asks for `all`, because an operator reading
  them wants the distinction rather than a shorter list.
  **Upgrading:** a consumer that expects every row from
  `GET /reports/{id}/iocs` must now ask for `include=all`, which returns
  exactly what the route returned before.

### Fixed

- **Enrichment stopped taking the slot an analysis was waiting for.** The
  post-verdict reputation lookups were queued beside the analyses, where the
  worker's one-job-at-a-time rule — which exists so two analyses never share a
  model — applied to them as well: a measured enrichment spent 451.98 s at
  VirusTotal while the next analysis sat `pending` for 4 minutes 33 seconds.
  Enrichment now has a queue and a worker of its own
  (`arq app.worker.enrich_worker.EnrichmentWorkerSettings`, in
  `docker-compose.yml` as `enrichment-worker`), and the analysis worker
  reads only its own queue. A deployment that would rather run one process
  reads only its own queue. The setting ships **off**, so a release taken and
  run unchanged keeps one process rather than queueing for a worker nobody
  started — and on that shared queue the enrichment now yields: it re-enqueues
  itself a minute later while an analysis is waiting, up to half an hour, after
  which it runs anyway, so the analysis no longer waits out an enrichment that
  was queued a second before it; the compose stack runs the second worker and
  turns it on beside it, and an operator's saved value wins over both. With it
  on and nothing reading the queue, the worker logs one warning naming the
  command that reads it and `GET /api/v1/system/status` reports
  `enrichment_worker: "down"` — the queued enrichments are kept and run when a
  worker starts. Concurrency is `ENRICHMENT_MAX_JOBS` (default 2), sized
  against the reputation providers' per-key rate limits rather than per job.
- **The enrichment's own event is kept with the rest of the run's.** Every
  event takes a sequence number from the job's counter, so the rows stored for
  a job have to equal the last number issued — the invariant the events
  endpoint pages by. `enrichment_complete` is published after the run has
  ended and the feed has been closed, so it took a number and stored nothing:
  one measured run published 71 events and kept 70, and the missing one was
  gone for good once the Redis stream expired. The enrichment task now opens
  the job's feed for that one line and closes it again, and seeds the job's
  sequence counter from the table first: the counter is a Redis key with the
  stream's 24-hour life, so enriching an older report used to start again at 1,
  collide with the row that already held that number and lose the event the
  same way.
- **A reasoning model on Ollama can be selected again.** The probe gives a
  model eight tokens and reads its answer; a reasoning model spends them in its
  thinking channel and answers with an empty `response`, so every one of them
  failed — and with `core.llm.require_probe` on, the API then refused to create
  any job at all. The probe reads Ollama's `thinking` as an answer now, the way
  it already read an OpenAI-compatible `reasoning_content`, and
  `core.llm.ollama.disable_thinking` sends `think: false` so the budget is
  spent on the answer instead. It is off by default, because Ollama refuses the
  field for a model with no thinking mode, and the same value is sent by the
  agents' calls and by the probe.
- **The evidence ledger can be read as a timeline.** Every row carried the
  flush time as its `created_at`, because the ledger is written in one batch
  when the run ends: one measured run's thirty entries had a single distinct
  value between them. A row is now stamped with the moment its call returned
  (`started_at + duration_ms`, both already on the entry), and a call the
  recorder never stamped keeps the write time rather than an invented one.
- **An upload no longer stops the process while it travels.** The MinIO client
  is synchronous and was called straight from the request handlers, so a sample
  of a hundred megabytes — or a slow store — held the event loop for the whole
  transfer: no other request, no WebSocket frame, not even `/health`. The
  sample upload, the sandbox-report upload and read, the deletes and the
  worker's own sample download all go through a worker thread now, and a
  source guard fails the build if a new one is added on the loop.
- **A cancel between two heartbeat polls still writes its row.** The worker
  polls the cancel flag every fifteen seconds; a cancellation that arrived
  between two polls reached the task as a bare `CancelledError` and was
  re-raised with nothing recorded. The task now reads the same flag where the
  cancellation lands: the operator's cancel writes `cancelled` through a
  session of its own, and a cancellation with no flag — arq's job timeout, a
  worker shutting down — is left to the periodic sweep, which is what repairs
  a row whose worker is gone.
- **An audit row says who did it.** `AuditLogResponse` carries the actor's
  display name, or the local part of their e-mail when the account has no
  name — what the admin users list already shows an admin — so the log's actor
  column no longer reads as eight characters of a UUID. One query names a whole
  page; an event with no authenticated principal, and a user who has since been
  deleted, both leave it empty. The console draws that name and keeps the id as
  the cell's title, so two people under one display name stay apart, and it
  falls back to the short id where the endpoint has no name to give.
- **A probe that could not read a catalogue says where it tried.** "model list:
  connection refused" was the same sentence whichever endpoint was configured.
  It now names the endpoint as scheme and host through `endpoint_label`, which
  drops the path and any credential in front of it.
- **The console stopped clipping itself.** `main` is a flex item, so its
  `min-width: auto` let it grow to its content's min-content width instead of
  constraining it: the Detection tab's Suricata block took it to 2542 px
  inside a 1440 px window and the shell's `overflow:hidden` cut off 1120 px
  with no scrollbar anywhere to reach it, and the Conversation tab lost its
  right edge the same way. `min-w-0` on the column and on `main` makes every
  `overflow-x-auto` inside them engage as it was meant to.
- **A phone-width layout, and a test that keeps one.** Twenty-one
  unconditional multi-column grids meant the dashboard kept four stat columns
  at 375 px with every label clipped, twenty-seven elements past the viewport
  and no document scroll to reach them. Every grid now starts at one or two
  columns and widens at a breakpoint, the jobs filter rail stacks, and
  `styleRules.test.ts` fails on an unconditional `grid-cols-3` or wider.
- **A custom agent can be saved.** The agents editor staged the whole
  definition map, so adding one agent re-sent every built-in exactly as it had
  come back from `GET /settings`, and the API compares a built-in in the body
  field by field against its seed. A store written before a seed's tool list
  changed holds `tools: []` on every built-in; the settings model reads that as
  "not set" and `agent_map.validate_definitions` did not, so every save
  touching the agent map was refused with "'judge' is built in; clone it to
  change it" on the four built-ins whose seed has tools. Both halves are
  fixed: the validator applies the same normalisation the settings model does,
  and the console stages a built-in as the only two things that may be changed
  about it — its role and its switch — while drawing the stored entry behind
  it.
- **Validation re-runs on the edit.** `useSettings` cleared only the error
  keyed at the leaf it staged, so a composite leaf's field messages
  (`core.agents.definitions.ahmet.prompt`) survived every later edit and "a
  generic agent needs a prompt" went on being printed under a prompt that had
  one. The review panel also counted rows rather than fields, announcing "1
  field needs attention" above five messages joined with semicolons into one
  run-on sentence for a screen reader; the count is of fields and the messages
  are a list.
- **The verdict and the severity of a run are reconciled where they
  disagree.** A run headlined Malicious · 0.95 over a severity card reading
  Informational 0.5/10 and prose calling the sample legitimate. Neither is
  overruled — both are the judge's — but the header now names the
  disagreement once, "Judge: Malicious 0.95 · Severity: Informational", with
  the sentence that says to read the severity card before quoting either.
- **Facts printed twice, printed once.** The filename was the `h1` and the
  "Sample:" line under it; the confidence was `92/100` in the header and
  `Confidence 0.92.` in the summary paragraph; the search palette printed each
  row's verdict twice and gave eight runs of one file no way to tell them
  apart; the agents list printed the key as the key and again as the role; a
  stage card printed its key in its header and in its Key field; `size`
  appeared in both of IDENTITY's tables. Each is now in one place, and the
  palette's rows carry the run's age and its id.
- **The enrichment banner stopped announcing the past.** The analysis layout
  walked the event feed from zero, so every `enrichment_complete` in a
  finished run's history re-toasted "Threat intel enrichment finished" in the
  present tense on every visit. The refetch still happens; the toast is for
  events that arrive while the page is open.
- **WCAG 2.1 AA on the primary button, and the controls a keyboard could not
  reach.** White on `--accent` measured 3.09:1 on every primary button in the
  console, so filled buttons use a new `--accent-fill` (4.63:1) and `--accent`
  keeps its borders, icons and washes. The upload zone was a bare `div` with
  its file input hidden by `display:none` — unreachable by keyboard and absent
  from the accessibility tree — and is a button over a visually-hidden input;
  the analyze dialog returns focus to what opened it; the settings badges move
  off `--border`, which is the one surface the text-tier contrast analysis
  never covered; message timestamps move off the disabled tier; every page
  gains a skip link and an `h1`; every table header gains `scope`; the guide's
  step chips carry `aria-current` on the button rather than on the list item;
  and the search palette's rows have ids the combobox names with
  `aria-activedescendant`.
- **The audit log says who did it.** It had no actor column at all, a raw
  action key, a Resource column reading "settings" on every row and an IP
  column of em dashes, over 1766 entries with no filter. The action is read as
  a sentence, the actor is drawn, a column every row on the page leaves empty
  is not drawn, and the action filter goes to the endpoint, which narrows the
  whole log rather than the twenty rows on screen.
- **Machine names and machine values are read back before they are drawn.** A
  section with no typed panel had its tool's own keys as column headers
  (`optional_dependency`, `technique_ids`) beside hand-written ones, and the
  binary header tables printed the constants the file format stores — `machine
  34404`, `subsystem 2`, `timestamp 1566949827`, `entry point 321264`. They
  now read as sentences and as their named constants, a human size, a UTC date
  and a hex entry point, and a field nothing knows is drawn as it arrived. The
  analyze dialog's provider and team menus are labelled rather than keyed, the
  evidence ledger runs its stage through the same reading as the stage strip,
  and its Agent and Server columns — "pipeline" on fifteen of forty rows — are
  one column.
- **A column that says nothing is not a column.** A column whose every row
  holds the same value is stated once above the table; one that is empty on
  every row is dropped. The NETWORK indicator table spent two of its four
  columns on one evidence id and forty dashes.
- **Sign out is offered where it works.** Under `NEXT_PUBLIC_AUTH_DISABLED`
  the handler is an explicit no-op and the header drew the button anyway, so
  pressing it left the reader on the same page as the same user with nothing
  said.
- **The QA warnings box shows that it opens.** `display:flex` on the
  `<summary>` suppresses Chromium's disclosure triangle, so the box gave no
  sign of being a disclosure while the RUN RECORD beside it did; the shared
  explanation is stated once for the group instead of repeated verbatim under
  each warning, and the field a warning names is named in its sentence rather
  than restated under it.
- **The fallback narrative stopped contradicting itself.** It reported "11
  ATT&CK techniques:" and then listed five, with no ellipsis and no "and 6
  more"; it pointed the reader at "the Static, Dynamic and Network sections
  below" whether or not the run filled them, and called tabs sections; and it
  restated a confidence the header above it already carried, in a different
  notation. It now says which of the five it is naming, names the tabs the
  report actually has, and leaves the confidence to the one place that prints
  it.
- **The console minors the walkthrough named.** A finished conversation is no
  longer a live region, so changing a filter does not queue a 23,000-character
  transcript for re-announcement, and the filter reports "n of m shown" as a
  status; the jobs list moves the verdict and its labelled confidence inside
  the link, so dozens of runs of one file are no longer dozens of identically
  named links, and announces the filtered count; a failed probe says what a
  `ConnectError` means before quoting it; the two destructive actions on a
  secret row say what each of them destroys; the "more" toggles say what they
  are more about; the per-row destructive actions have a button's box and
  clear the 24 px minimum; a rule key no longer rides in front of the sentence
  it already reads as; two participants who share a name carry their keys; the
  DEFENSE tab has a heading; the 404's two links are styled alike; the
  attribution card's empty rows are one sentence; and the profile form carries
  `autocomplete` and states its password rule before it is broken.
- **Six places where the web tree and the code it mirrors had drifted.** A
  `delegation_answer` left its speaker drawn as working for the rest of the
  run although it is the callee's own closing line; `EvidenceSummary` did not
  declare the `failures` the report header prints; `AgentMessageEventData` did
  not declare the five fields the conversation view reads on a tool line; the
  section map's comment counted sixteen catalog groups where there are
  seventeen; the redirect table's comment counted twelve tabs and five where
  neither number is in the tree; and `REPUTATION_TOOLS` knew two of the three
  tool names the pipeline recognises.
- **`core.agents.profiles` is titled "Team definitions".** Its page is already
  called Teams, so the two headings sat on top of each other.
- **The worker no longer holds a transaction while the models run.** The
  analysis task kept one session open for the whole job: it read the settings,
  and the backend then sat `idle in transaction` for as long as the analysis
  took — 13 minutes 51 seconds on the run that found it — holding an
  `AccessShareLock` on `analysis_jobs`, `analysis_reports` and
  `runtime_settings`. A migration's `ALTER TABLE analysis_reports` queued
  behind it, every read of that table queued behind the ALTER, and
  `GET /api/v1/jobs/{id}` timed out for four minutes while `/health` answered
  in milliseconds. The task now reads the job, its sample, the stored settings
  and any attached sandbox report in one short session, closes it before the
  pipeline is built, and opens another for the report, findings, evidence,
  transcript and completion — which stay in one transaction, because the
  report's sections cite the ledger's ids. The enrichment task is the same
  shape: it reads the payload, closes, spends as long as the reputation
  lookups take (452 s on one measured report) with no session open, and writes
  through a second one. Cancellation is unchanged, including the feed flush a
  cancelled run ends with.
- **A failed job says so, even when its own session is gone.** The failure
  path wrote through the session the run had been using, which is exactly the
  session a terminated backend leaves raising `PendingRollbackError`: the run
  published its `error` event, arq recorded the task as failed, and the row
  still read `running` with no error and no `completed_at` an hour later. The
  failure is now recorded through a new session, and what the row says is the
  class of the exception and the id of the log entry holding the rest, because
  `error_message` is a field of `JobResponse` and an exception's message names
  host paths and connection strings. A `cancelled` row is left alone.
- **No request path waits on a third party inside a transaction.** A
  request-scoped session is in a transaction from the dependency that resolved
  the caller, so a handler that then waited on somebody else left a backend
  `idle in transaction` for the length of that wait. The three probes (up to
  five minutes at a model endpoint), the VirusTotal registration and the
  long-term-memory purge now end the read first, through
  `database.end_read_transaction`. The WebSocket route holds no session across
  the stream: the handshake decides inside a session and accepts or rejects
  outside it, and a resume reads one page per session and sends it once that
  session has closed, rather than holding one open while a thousand frames go
  out at the client's pace.
- **A running job says who owns it, and the sweep believes only that.** The
  sweep marked every `running` row older than five minutes as failed, on the
  reasoning that this process is the worker and has just booted — true of a
  single-worker deployment and false of any other, where it would fail a run
  another worker was performing. Ownership is now a heartbeat the owner writes
  about the job it is running: `maljan:job-owner:<job id>`, carrying the
  worker's own id, 90 seconds long, refreshed every 30 and dropped on success,
  failure and cancellation alike. arq's keys cannot say it — its in-progress
  claim outlives the process that wrote it by the job timeout, and its
  queue-wide health key outlives a killed worker by 31 seconds, which is
  exactly when the restarted container reads it, so an OOM-killed run's row
  survived the very sweep meant to repair it. The sweep now runs one TTL after
  startup and every ten minutes after that (which also reaches a job a
  still-running worker gave up on), leaves a row younger than one TTL for the
  next pass, never touches a job this process is running, and touches nothing
  at all when Redis cannot be read, logging that once.
- **A refusal this worker worded reaches the operator whole.** "The attached
  sandbox report does not belong to this sample" and "the configured sandbox
  provider cannot accept an uploaded report" are sentences this module writes
  from constants, not exception text from a driver or the filesystem. They are
  now raised as `StatedFailure` — the class `AbsentAnalysisError` already
  belonged to — and only that class keeps its message on `job.error_message`;
  everything else still arrives as its class name plus the error id. A
  `StatedFailure` whose message the event scrubber would change is marked
  unpublishable rather than refused: the job says the class name, the sentence
  goes to the log under the same error id, and a test walks every site that
  raises one so a bad sentence fails a build rather than a job.
- **The sample roots reach a configured deployment's sidecars, not only a
  fresh one.** The `analysis` and `network` sidecars read a path argument only
  inside the directories `MALJAN_SAMPLE_ROOTS` names, and they learn them from
  their own `env_allow` — but the registry of tool servers is stored as a
  single row holding every server, written whole each time anything in it is
  saved, and a built-in that was already in that row kept every field it had
  been saved with. A deployment that had configured its servers before the
  confinement shipped therefore went on starting both sidecars without the
  variable, and every analyst tool call on the run's own sample came back
  refused with `path_outside_roots` — the error meant for a path the sample's
  author chose. A built-in's `env_allow` now always carries the names its
  sidecar cannot run without — the sample roots, the staging directory and its
  retention — on load, on save, in the editor's own view and in the connection
  test, which launches the server a run launches, so a name a sidecar gains
  reaches a deployment that has been configured rather than a fresh install
  alone. The Configuration tab draws those names above the box as always
  passed, so an admin can no longer delete one, be told the map was saved, and
  go on believing a sidecar was narrowed. Every other shipped name stays the
  operator's: a
  `threatintel` whose `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` an admin has
  cleared keeps them out of the child, and the sidecar answers from its mock as
  it does on a host that never held a key. A server an operator added is
  untouched: it sees the roots only when its own `env_allow` lists them, and
  the general-purpose environment every child gets is unchanged. Proven through
  the real spawn path — a live sidecar started the way the registry starts one
  reads a file under an exported root and still refuses one outside every root.
- **The repeat guard's notice is a message to the model and nothing else.** A
  refused third call to the same tool with the same arguments was written to
  the evidence ledger as a *successful* call — `ok=true`, `duration_ms=0` —
  which inflated the ledger, inflated the report's "tool call(s) recorded, N
  failed" line, and handed the model a citable evidence id for an entry holding
  no evidence. No tool ran, so nothing is recorded, nothing is announced to the
  console, and the notice points at the earlier entry and says whether that
  entry was an answer or a failure: one live notice sent a model to `[ev_0017]`
  for "the result", and `ev_0017` had raised.
- **A report section is no longer lost to a key its schema does not declare.**
  The sections forbid unknown keys, so one invented field took the whole
  section with it: two audited runs shipped with no conclusion and no technical
  analysis, and nothing in the report said so. The fields the schema declares
  are kept, the ones it does not are named as a degradation reason, and a
  section that is genuinely lost — its shape still wrong after the retry, its
  round timed out or failed — is named in the report's notes with the reason.
- **A lead that never wrote its report no longer takes its specialists'
  answers with it.** A lead's report is the only channel its chunk has out of a
  stage, so a loop that ended without one lost every completed ask: one audited
  chunk spent 1,830 s, had six specialist asks answered and 52 evidence entries
  recorded, and merged zero claims. The answers are kept on the caller as the
  specialists' own ISRs; a lead that produced no claims is given one bounded
  turn to write its report from them — the forced synthesis the analysts
  already use — and when that turn produces nothing either, the specialists'
  ISRs are promoted into the stage's merge with their claims and confidences
  exactly as they made them. Every answered ask is promoted, in order and
  keyed by the agent and the ask's number (`deep_static#2`): three asks to one
  specialist are three answers, and keyed by the agent alone the second and
  third were dropped. Nothing is promoted beside a report that exists.
- **Every violation a run recorded reaches the conversation, with what became
  of it.** Only the batch that triggered a correction turn was published, so a
  reader watching a run saw neither the violations that survived the retry nor
  the ones the retry introduced — two `validation_feedback` events in one run's
  feed beside a summary recording ten unresolved findings. Each violation now
  carries a `state`: `retried` where the producer is shown it, then `resolved`
  or `survived` once the loop knows which, and a violation the retry introduced
  is published once, as `survived`, and so are the findings the judge records
  after its loop, which reached the run summary and never the conversation.
  The fields the console keys on — `code`, `agent`, `stage`, `retry_index` —
  are unchanged; `path` is added beside them, so `(agent, code, path)` folds
  the two lines about one violation together and keeps two violations of one
  code on different claims apart.
- **One source for the techniques a report publishes.** A report's three
  technique surfaces were built from three sources and disagreed inside single
  runs: one run exported ten techniques and a STIX bundle with no
  `attack-pattern` at all; another served three techniques from
  `/reports/{id}/mitre` with an empty `technique_id`, none in `ttp_mappings`,
  and three attack-patterns carrying no ATT&CK reference and ids copied out of
  the STIX documentation; a third published `T1063` — which the validator had
  already reported as absent from the catalogue — in the report, in the bundle
  and in the References section. `ttp_mappings` is now the published list and
  carries no id the catalogue check rejected (the id stays in the capability
  matrix, marked, spelled as the producer wrote it), the bundle's
  attack-patterns are minted from that list with ids derived from the technique
  id and an ATT&CK external reference each, the References section and the
  `mitre_techniques` column are built from the same list, and no entry without
  a technique id is stored as a technique. The judge's own `uses` relationships
  travel with their techniques: each is re-linked to the rebuilt attack-pattern
  of the same id with its confidence, evidence basis and contributing agents
  unedited — both ends of the ref, so one sourced at a technique moves too —
  and the uncertainty annotation that makes these bundles worth exporting is no
  longer pruned as dangling. A relationship whose technique the checks rejected
  is taken out with that technique and recorded in `run_summary.validation` as
  `stix.unlinked_technique`, so it is counted once, as the technique's loss,
  and not again as a defect of the judge's bundle. An
  attack-pattern with a name and no id is asked for one (`attck.missing_id`)
  instead of skipping every ATT&CK check — which is why the Mobile-domain
  check never ran on an Android sample's techniques — and one that survives is
  reported as a behaviour, in the new `MalwareReport.unmapped_behaviours` and
  under its own heading in the markdown.
- **The ATT&CK alignment gate scores inside the sample's own scope, and asks
  nothing unless it is turned on.** The index that ranks a claim's text is
  domain-blind, so a technique claim about a Windows PE was answered with
  Mobile and ICS candidates, and it scores a correct id near zero often enough
  that the check questioned 81 of 92 technique claims in one audited run and 33
  of 33 in another — each batch a full extra model turn. The candidates are now
  narrowed to the routed sample's ATT&CK domain and platforms before anything
  is recorded or proposed; a claim is questioned only when its id scores under
  `validation.alignment_threshold` and an in-scope candidate from neither its
  own technique family nor any of its tactics beats it by the new
  `validation.alignment_margin` (0.20); and at most one weak-alignment batch is
  sent per agent turn. The question itself is behind the new
  `validation.weak_alignment`, which is off: the ranking is still recorded on
  every claim and shown to the judge. An index that ranked the claimed id
  itself in scope questions nothing, wherever it ranked it. Over the audit's
  own 105 distinct rankings, replayed as a fixture, the narrowed rule questions
  none of the 36 claims whose id the audit read as right for its sample and 5
  of the other 69, and none of the 105 derived rows that put the claimed id
  back into its own ranking; docs/architecture.md carries the measurement.
- **A judge that never answered no longer produces the verdict "Malware".** The
  bundle the pipeline builds when the judge's answer was not a bundle carried a
  `malware` object whatever verdict it was carrying, and the pipeline read the
  verdict back off the objects — so the "Suspicious" the extraction had read
  out of the judge's own text was overridden by the bundle's shape, and a
  signed sample with a clean reputation entry in its own pack, no analyst claim
  and no technique was reported as Malware because the verdict round timed out.
  The fallback bundle now states its verdict in `x_maljan_fallback_verdict`
  (`extracted` from the judge's own text, or `pipeline` when there was nothing
  to read, which is what a timeout leaves), its object set follows that verdict
  — no `malware` object for a verdict that is not Malware, and a `note`
  carrying the degraded-path record instead — and `decide_from_bundle` reads
  the statement rather than counting objects. `verdict.unsupported_benign` and
  `verdict.unsupported_malware` run over that bundle on the timeout path too,
  where the loop used to return before they could be asked; they annotate and
  change nothing, and they run on every way the round can end: a bundle, a
  malformed answer the retry fixed, prose the model stood by twice, JSON that
  is not a bundle, and no answer at all. Such a verdict also takes the path a
  judge that raised already took: `overall_confidence` is `null`, the header
  reads "not assessed", and the run summary carries the code once rather than
  twice — asked off the bundle's own mark rather than off the violation codes,
  so a fallback built from JSON that was not a bundle is one too.
- **Every modern APK was reported unsigned.** The APK Signing Block opens with
  its own size, and the walk over the id-value pairs began on that size field
  rather than eight bytes later on the first pair. One field out of step is
  enough that no scheme id is ever recognised, so an APK signed only with
  schemes v2 and v3 — which is how Android has signed packages for years —
  came back with `present: false, schemes: []`, and an analyst reading the pack
  wrote that the application was unsigned and therefore probably repacked. The
  walk now starts on the first pair, stays inside the block rather than inside
  the file, and refuses to read a block whose two size fields disagree, because
  a footer that does not agree with itself was not a block footer.
- **A run of bytes shaped like a hostname was published as infrastructure.**
  The string sweep over one PE returned twenty-five domains, fifteen of them
  fragments of longer names (`rosoft.com` out of a resource that had been cut
  short before `microsoft.com`), rows of a detection-name table (`jector.SA`,
  `Bifrose.IE`) or identifiers. Each was exported as a STIX indicator and each
  cost a reputation lookup — 452 s of the enrichment slot for one report. The
  domain pattern now takes an underscore as a token boundary; a name that is
  the tail of a longer one found in the same sample is dropped unless it ends
  at a label boundary, so `sectigo.com` under `crl.sectigo.com` is kept and
  `rosoft.com` is not; a candidate that is nothing but a public suffix
  (`co.uk`, `ne.jp`) is not a name; and a lowercase label wearing a shouted
  country code is read as a table row rather than a host. Every row the scan
  produces now carries `source: "strings"`, `NetworkDomain` records where the
  name came from, and a name only the byte image knows is neither exported as
  an indicator nor sent to a paid provider until a second source — the
  sandbox, an analyst artefact or a reputation record — knows it too. A Tor
  address is the exception and has to be: `.onion` does not resolve, so no
  sandbox can ever confirm one, and the rule made the strongest string-derived
  indicator there is unpublishable by any path. Its own syntax is the second
  source — a v3 address is admitted only when the checksum and version byte in
  its last three bytes check out against the first thirty-two, a v2 one on its
  length and alphabet — it stays labelled `strings`, it is still never sent to
  a paid provider, and the indicator's description says why it was let
  through. One
  predicate decides that, and both paths that mint a domain indicator ask it:
  the network block's own, and the string rows, which reach the bundle as
  `interesting_strings` and were still being published after the first gate
  went in. The name is still in the report, labelled with where it came from:
  the Markdown network table has a Source column, and the console's domain
  card a badge that says whether the sandbox resolved the name or the byte
  image merely contained it.
  Which of two names is a fragment is decided by where the matches sit rather
  than by how they are spelled, so a longer look-alike no longer deletes the
  real name — `microsoft.com` beside `xmicrosoft.com`, and
  `000webhostapp.com` beside `M000webhostapp.com`, are two names each. An
  address no longer yields a bare host beside itself — `admin@example.com` was
  one string and two indicators — and the case rule asks for the shouted
  two-letter country code it was written for, so `Evil.COM` is a hostname
  again.
- **The catalogue called drawing a window keylogging.** `BitBlt`,
  `CreateCompatibleBitmap`, `CreateCompatibleDC`, `GetDC` and `GetDIBits` were
  filed under `keylogging` at tier `high`, so every program that puts pixels
  on a screen came back with `catalog_flags: ["suspicious"]` — on a signed SSH
  client that was one of the two entries the only analyst that spoke cited
  behind a Malware verdict. The GDI blit calls are now `screen_capture` and
  the message pump `message_loop`, both `informational`, and both name the
  APIs that would give them weight — hooks, raw input, the clipboard beside a
  capture — in a new `corroborated_by` field that `api_capability` puts on the
  row. The T1113 association is untouched: it is shown as a catalogue
  association, which is what it always was.
- **Thirteen rules asserted a technique about a benign GUI network client;
  none asserts one now.** The corpus was swept rule by rule against two
  fixtures built from names and words rather than from any sample. Four shapes
  were doing the damage: a pattern that is a substring of a benign API name
  (`RegSetValue`, `CreateService`, `ExecuteA`), a pattern that is an English
  word (`encrypt`, `macro`, `shortcut`), a pattern too short to be evidence
  (`#24`, the highest authored confidence in the file, and `.scr`, which
  matches `.scrollbar`), and a pattern the MSVC CRT links into most benign PEs
  (`IsDebuggerPresent`). Eight rules now want the artefact — a ransom note's own wording, a
  `rundll32` command line, `comsvcs.dll MiniDump`, a policy key path, a VBA
  project stream. Five could not be made specific statically and have left the
  technique-asserting set: `web_client_apis`, `file_enumeration_apis`,
  `user_activity_apis`, `service_control_apis` and `scripted_runtime_markers`
  say what is in the file and carry no technique and no confidence, because
  importing an HTTP client or enumerating files is what ordinary software
  does. A rule file entry may now omit `technique_id`, and one that does may
  not carry a confidence either; it may also carry an `all_of` group, which
  fires only when every string in it is present, for a technique that is a
  pair rather than a string; one matcher answers which of a rule's strings
  count, so the layer and the tool that `yara_scan` falls back to cannot
  disagree about a group, and neither engine lists half a pair among the
  strings that fired a rule. Two more rules followed: `lsass_dump` asserts
  T1003.001 on the mimikatz string or a `comsvcs.dll MiniDump` invocation, and
  on `MiniDumpWriteDump` **together with** `lsass.exe` — either of those two
  alone is now a `process_dump_apis` note, because a crash reporter imports
  the one and every process lister carries the other. `ransomware_indicators`
  loses the bare `.locked` and `.encrypted`, which made `notes.encrypted` read
  as T1486 at 0.88, and `ransomware_extensions` becomes the
  `encrypted_file_extensions` note: what makes an extension evidence is the
  renaming, and this file cannot say "together with" across two groups. Its
  `.onion` pattern is gone with it — it had been tagging every Tor address in
  every sample as ransomware.
- **Three shipped YARA rules fired on words rather than on facts.**
  `registry_run_keys` (T1547.001 at 0.88) listed `RegSetValueEx` beside the Run
  key paths, so it matched any program that writes a registry value — on a
  signed SSH client the hit was in the pack every agent read. It now wants a
  Run, RunOnce, RunServices or Startup path. `obfuscation_indicators` (T1027 at
  0.82) and `software_packing` (T1027.002) listed `UPX`, `AES`, `RC4`, `XOR`,
  `Base64`, `packed` and `compress`, which fire on every implementation of a
  transport: the same client matched on fourteen occurrences of `aes` and on
  `uPX` inside a longer word. Both now want a packer section name or a packer's
  own banner. The section entropies that are the other half of the packing
  signal are reported by the format tool beside these hits, as before.
- **A tool that answered less than it wanted to was recorded as having failed.**
  `apk_info` without androguard returns the zip-level facts — the manifest
  member, the dex count, the ABIs, the certificate members — and returned them
  beside an `error` key. Every consumer reads `error` as "this call produced
  nothing", so the ledger recorded the call as failed and the pack printed none
  of them: an Android run had no container channel at all although the archive
  had been read. A degraded answer is now a success carrying `degraded` (the
  library that is missing, and what was answered without it) and the
  remediation, the same for `document_info` without olefile, and the pack
  contributes `triage.<tool>_degraded` rather than `triage.<tool>_failed`. That
  reason never makes a whole run degraded, because the facts are there and what
  is missing from them is said beside them. The sentence the judge reads says
  the tool answered a smaller set than it wanted to, not that the pack could
  not run it — the same prompt carries the facts it did produce.
- **A container that had been opened was reported as never opened.** The
  degradation reason "container was not parsed — no format-aware extraction
  exists for it; findings come from a raw-byte string sweep only" was decided
  from the file type alone, so a ZIP whose members `archive_list` had listed —
  with sizes and CRCs, printed in the report, cited by the analyst — carried it
  anyway, and the run capped its confidence on the strength of it.
  `unparsed_container_reason` now asks the evidence ledger whether the routed
  format's own tool produced a result, and speaks only when it did not, which
  is still the true answer for a package whose `apk_info` could not load its
  library. The routed type's tool is the one that counts: an APK, a JAR and a
  macro document are all zips, and an analyst listing an Android package's zip
  members has not read its manifest, its permissions or its components.
- **The timestamp authority was named as the publisher.** A timestamped PE
  carries the timestamp service's chain in the same PKCS#7 certificate set as
  its own, so the set has two leaves and "the certificate that issued none of
  the others" picked whichever the producer wrote first: over the local corpus
  that named a time-stamping certificate as the publisher on four signed
  binaries out of seventeen. The publisher is now the certificate the
  `SignerInfo` names, by issuer and serial number, read with a small
  definite-length DER walk; failing that, the leaf whose extended key usage
  carries code signing and not time stamping; and failing that, no publisher
  at all, because a name that might be the timestamp service's is worse than
  none. The file is still reported as signed either way.
- **A signed binary reached the pack anonymous.** `signing_info` reported
  `authenticode present` and left the subject and issuer for "an enrichment
  step", and no such step exists — so the strongest benign fact a run could
  hold named nobody, and on a signed, 0/74-clean binary the only analyst that
  spoke never had a publisher to weigh. The signer's subject, issuer and SHA-1
  thumbprint are now read out of the PKCS#7 blob in the certificate table, the
  signer being the certificate in the bundle that issued none of the others.
  No chain verdict is claimed: `signature_valid` stays unset, because deciding
  whether a certificate is trusted needs a root store this process does not
  have. `SignatureInfo` gains `signer_thumbprint`.
- **A tool the host cannot run is no longer offered to the model.** One run
  reported `22/22 tools exposed` while `apk_info`, `archive_list`,
  `document_info` and `macho_info` were unavailable on that host: the
  degradation was logged and recorded, and the model was handed the tool
  anyway, spent a step on it and got a failure back. The registry now drops a
  tool the server's own manifest marks unavailable from the list the model is
  given, unless the manifest says what the tool still answers without its
  library — `archive_list` without py7zr still lists a zip, and withholding it
  would cost an archive analysis to save a 7z failure. The manifest is
  unchanged and still names every tool with its reason and remedy, and the
  degradation reason is now said where the tool is withheld rather than where
  it would have been bound, so the degraded block reads as it did before.
- **Every pipeline line was written to stdout twice.** The `maljan` logger
  installs a handler of its own so a CLI caller with no logging set up still
  sees something, and it also propagates to the root handler the API and the
  worker install — so once either had started, each line went out once plain
  and once through the root formatter. A live worker log held 3 306 coloured
  lines with every unique message appearing exactly twice. `setup_logging`
  now calls `hand_over_to_root`, which takes away the package's own handler
  and leaves the root's; propagation stays on, because that handler is the
  structured one in production and is also where a test's capture is attached.
  A caller who configured nothing keeps the handler and sees no change.

- **Four documented facts that had drifted from the code.** The delegation
  section said a lead's 1800 s stage had room for five asks where
  `_asks_that_fit` computes six and the `ask_<key>` description gives the model
  six; the events table omitted `via` from the roster row, `ran` from
  `stage_finished`, `report_truncated` from `agent_message` and the
  `enrichment_complete` row entirely; the evidence paragraph credited the
  console with reading `run_summary.evidence.failures`, which it does not; and
  the roster cache's comment justified itself with a live view that no longer
  exists. The participants strip's own documentation now says that a
  specialist reached through `ask_<key>` has its state inferred from its lines,
  because no stage names it and `agent_progress` is published per stage.
- **A long agent key inside a published sentence.** A key of 24 characters or
  more has the shape of a credential, and nothing is exempt from that rule for
  being lowercase, so such a key reads as `***` inside the prose of an event —
  never in the identity fields the line is filed under, which travel whole, so
  attribution and the operator's label are unaffected. The scrubber is a pure
  function shared by every job on the worker and is deliberately not told which
  roster is publishing. `docs/configuration.md` now says to keep agent keys
  short, and a test pins the behaviour so the next reader finds the trade
  rather than the symptom. No shipped key is close to the floor.
- **The guard on published failures follows a renamed import and a line
  handed on twice.** The AST walk that keeps
  `base_agent.describe_exception_for_log` away from every publish site knew one
  spelling of the name and one hop from a local. It now resolves an aliased
  import — which is the shape the mistake most recently took here — walks the
  taint to a fixed point, and sees a tuple, annotated or augmented target as
  the binding it is. The floor under both rule engines' timeouts is pinned by
  calling them with zero and reading what they pass down, rather than by
  counting a line of their source.
- **`signing_info` answers about the sample, not about itself.** It reported
  all three schemes on every file, so a PE carried "apk present=no" and "macho
  present=no" beside its Authenticode row — statements about what the tool
  looks for, which the identity table and the report then drew as findings
  about the sample. It now answers for the routed format alone (Authenticode
  for a PE, the APK signing block for an APK, `LC_CODE_SIGNATURE` for a
  Mach-O), and for a format with no such scheme it says that instead of three
  absences. The tool takes the routing answer from its caller — the triage
  pack passes it, the `analysis` sidecar takes it as an optional `file_type` —
  and reads the bytes only when it is called with nothing else, which also
  stops a `.docx` being asked about Android signing because it is a zip. The
  console keeps choosing between three blocks as a fallback for reports
  recorded before this. The identity table shows one signing row, for the
  routed format, and none at all for a format with no signing scheme —
  the routed `format` and the `applicable` flag are facts about what the tool
  looks for, so neither is drawn as a row, in the export or in the console.
  A JAR or an IPA, which used to reach the APK check because they are zips,
  now reports no signature rather than an Android one.
- **A verdict no model produced no longer carries a confidence.** When the
  judge's body raised, the pipeline wrote a conservative "Suspicious" verdict
  of its own — correctly, so a run is not lost — and the report then filled the
  missing confidence from the mean of the analysts' confidence in their *own
  claims*, printing 0.92 on the front page beside a decision none of them made.
  The comment at the failure site still said the report node capped it, which
  it has not done since the cap was removed. Such a verdict now carries
  `overall_confidence` `null`, the report header reads "not assessed" and says
  the judge did not answer, and the run summary records the note under
  `verdict.fallback` with the class of the failure — in the summary the API
  stores as well as in the report's own copy, so the SUMMARY tab's Run record
  and an evaluation script reading `analysis_reports.run_summary` both see it.
  The console's header shows
  "Confidence: not assessed" rather than 0/100, and
  `analysis_reports.overall_confidence` is nullable (`20260926000000`) so the
  distinction survives being stored.
- **The run-summary golden pins the summary a run is stored with.** It pinned
  `RunSummary.to_dict()` while its docstring claimed to cover "what the API
  stores", which is that dict plus four keys written onto it afterwards:
  `dedupe`, `evidence`, `sections_without_evidence` and `fp_warnings`. `dedupe`
  was pinned by nothing at all, so a rename of `indicators_merged` or
  `findings_merged` would have kept every test green. The golden now covers the
  stored dict, is regenerated by
  `scripts/goldens/capture_run_summary_golden.py`, and the summary's evidence
  block is built by one function (`pipeline.nodes.evidence_summary`) rather
  than by a literal the golden could only agree with by hand.
- **An empty tool output is no longer explained by a cause that did not
  happen.** The evidence panel printed "The output was dropped to keep this
  agent inside its byte budget" for *any* entry whose `output` was empty — a
  failed call included, directly under the failure row it had just drawn —
  because the flag that records a budget trim was dropped at persistence.
  `truncated`, `repeated_of`, `symbol` and `started_at` are now columns
  (`20260926000000`), the worker writes them, `GET /jobs/{id}/evidence` returns
  them, and the sentence is shown only for an entry that says it was trimmed.
  A call that simply answered with nothing now reads as that.
- **A replayed conversation is the conversation again, not a reconstruction of
  it.** `agent_messages` kept none of `kind`, `stage` or `display_name`,
  although the live `agent_message` payload has carried all three and both the
  model and the response schema are documented as mirroring that payload field
  for field. A run read back from its rows therefore lost the arrows between a
  delegated ask and its answer — the kind had to be re-derived, and the
  derivation can only return `says`, `system` or `verdict` — put every line
  into one unnamed stage, and named agents by their registry keys where the
  live view had used the operator's labels. The three are columns
  (`20260926000000`, all nullable), the recorder writes them, the report
  endpoint returns them and the console prefers them, falling back to its
  derivation for a run recorded before they existed.
- **The two tables a reader meets first say what the code says.**
  `docs/configuration.md` counted sixteen settings groups and listed sixteen
  rows where the catalogue holds seventeen: **Live events**, the group
  `core.events.stream_deltas` and `core.events.retention_days` belong to, was
  missing from the only place that enumerates them. The README's teams table
  dropped `triage_pack` from all four seeded teams that open on it, and showed
  `mobile` and `deep_static` opening on `triage` — the triage *agent*, which is
  a different stage. Both tables are now checked against `GROUP_ORDER` and
  `_builtin_profiles()` by a test, so the next drift fails rather than ships.
- **Semgrep covers the frontend.** The scan ran over `src/ apps/api/ services/
  scripts/` with `.semgrepignore` excluding `apps/web/`, so every file of the
  console was outside it and covered by CodeQL alone. The job and `make
  semgrep` now add `apps/web/src/` with the `p/typescript` and `p/react`
  rulesets; `.semgrepignore` keeps out only what is not source — build output,
  the Playwright suite (`apps/web/e2e/*.spec.ts`) and the vitest specs
  (`__tests__/*.test.ts`), which are named differently and so are excluded
  separately. 287 rules over 416 files, no findings.
- **The `readonly` role is documented as the label it is.** It is enforced
  nowhere — no route distinguishes it from `analyst`, so such an account can
  upload a sample, submit a job and cancel its own — and `docs/security.md` and
  the model now say so instead of listing it beside the two roles that decide
  something. It is not removed: a stored row carrying the value would not load
  against an enum without it, and dropping it silently would widen those
  accounts rather than narrow them.
- **Three API responses that could carry a connection string.** The probe
  route's outer fence, the LTM purge's memory-store failure and the enrichment
  queue's 503 each answered with `f"{type(exc).__name__}: {exc}"`, and the
  exceptions that reach them come from arq, Redis and Qdrant, which name the
  DSN they were configured with — password included. All three go through
  `redact_url`, which the probe's own transport paths have always used.
- **A sidecar decides what it will read before it reads it.** `put_sample`
  base64-decoded its whole argument and then applied the 2 GiB ceiling, so an
  oversized upload was materialised twice before being refused; the encoded
  length is now checked first, and so is a chunk's. At most 32 chunked uploads
  may be in flight. `yara_scan` and `capa` clamp `timeout_s` to the value their
  own `capabilities` manifest declares, so the structure whose premise is that
  it was computed stays true. Every `network` tool takes a `packet_limit` and
  holds it to 5000, where `extract_dns` and `extract_http` used to call
  `rdpcap` with no count and read the whole capture into memory. The digest
  that names a carve directory is read in 1 MiB blocks rather than whole.
- **Every probe leaves an audit row.** `run_probe` backfills any input the
  caller did not stage from the decrypted store, so `POST /settings/test/llm`
  with a staged `base_url` sends the stored API key to whatever host the caller
  named — a secret the console deliberately never shows in the clear — and
  `/settings/test/*` wrote nothing, unlike `save` and `import`. Each of the
  three probe routes now writes one `settings.probe` row naming the probe, the
  endpoints it was pointed at (as labels: scheme and host), the keys that were
  staged and whether it succeeded. No staged value is in the row.
- **A probe refusal names the server, not its credentials.** The sentence the
  submit gate answers a job with interpolated the endpoint as configured, and
  that 422 is reachable by any authenticated user — so a base URL such as
  `http://user:pw@llm.internal:8080/v1`, the ordinary shape for a llama.cpp
  behind basic auth, showed a non-admin the endpoint's credentials. It now uses
  the endpoint's label (scheme and host), which has moved to
  `maljan.core.model_assignments` beside the endpoint it labels. The label also
  cuts an address typed without a scheme instead of handing it back whole, and
  answers `(unparseable endpoint)` for something that is no address at all.
- **One server, one probe key.** `normalised_endpoint` trimmed and dropped a
  trailing slash, so `HTTP://BOX:8080/v1`, `http://box:8080/v1`,
  `http://box:80/v1` and `http://box/v1` were four keys for one server and a
  probe filed under one did not satisfy the gate under another. It now folds
  the way a URL folds: lower-case scheme and host, the scheme's default port
  dropped, trailing slash removed, with the path and any userinfo kept exactly
  as typed — this value is the address a call is made to. The failure was
  always closed (a spurious refusal, never a bypass); a row written under an
  old spelling needs its probe re-run.
- **The analysis socket checks the account, at the handshake and while it
  streams.** `/ws/analysis/{job_id}` decoded the token and went straight to the
  ownership query, so it never read the `User` row and never saw `is_active` —
  an account an admin had just deactivated kept the full live feed of its own
  jobs until the access token expired half an hour later. The handshake now
  reads the account first, before it says anything about the job, and closes
  with 1008 when it is missing or deactivated; a streaming socket re-reads it
  every 60 seconds and closes the same way. The job id is canonicalised
  directly after it is parsed, so a socket opened with the uppercase or
  unhyphenated spelling of a job id shares the bucket, the listener and the
  Redis connection of the one the publisher writes to instead of getting its
  own and receiving nothing.
- **A delegation guard that reads both ways an agent is bound to a server.**
  `servers_withheld_from` computed what a callee brings from the `mcp`
  references on its definition alone, but the shipped binding mechanism is the
  other one — `core.mcp.servers.<key>.agents` naming the agent, which is how
  the default map binds every built-in. A stage with `builtin_tools=False`
  could therefore ask a stage-less specialist and get back a `knowledge`,
  `network` or `threatintel` answer, which is the guarantee
  `docs/architecture.md` states. The callee's effective set is now the union of
  both, minus what the profile withholds from the callee itself; a disabled
  server brings nothing.
- **The publisher scrubs every event, so a producer that forgets cannot leak.**
  `scrub` was applied by two of the seven producers, so
  `agent_message.text`/`report`, `validation_feedback.message` and
  `stage_ended_at_cap.detail` went out untouched — a credential the model
  echoed was redacted while it streamed as a delta and then published in the
  clear in the closing message, its `job_events` row and the stored transcript.
  `_publish_event` now applies it once to every string field of every payload,
  recursively through nested lists and dicts and leaving keys alone, before the
  event reaches Redis, the socket and the table; the transcript recorder's copy
  is scrubbed where that copy is taken, so a replayed run reads exactly as the
  live one did even when the publish never happens.
  Prose keeps its own line breaks and indentation (`scrub_keeping_layout`), so
  a report is not flattened into a wall of text on its way out. The fields that
  *name* something rather than say something — the ids this system issues, the
  agent, stage, server and tool keys, the labels an operator typed and the
  words the console switches on — are exempt by **field name** in the
  publisher, so a `completed` event can still be opened by its `report_id` and
  a long agent key still speaks under its own name. Nothing is exempt for the
  shape of its value beyond a digest and a canonical UUID: a lowercase run is a
  credential like any other.
- **A published failure says what kind it was, never what it said.** Every
  failure handler in `pipeline/nodes.py` put `str(exc)` into an `agent_message`
  — the analyst failure and crash paths, the mediator, the revision hand-back
  and the judge's verdict, whose own `judge_report` carried it into the report
  as well — and that message reaches every connected browser, the Redis stream
  and the `job_events` table for the whole retention window. An `OSError`
  names the sample's host path, a transport error names the request URL, and a
  base URL configured with userinfo carries the credential into the text.
  Every one of them now goes through `events.describe_exception`, which says
  the exception's class (qualified with its module where the bare name is
  ambiguous), the remedy when the failure carries one, and nothing else. So
  does the reason a custom analyst records when its loop fails, which is both a
  degradation reason on the run summary and that agent's own report. The
  operator's log still gets the message — through
  `base_agent.describe_exception_for_log`,
  renamed so the two cannot be confused, since the wrong import fails open —
  and the ledger still keeps the verbatim text behind the report's ownership
  check.
- **Three runs the scrubber ended in the middle of a value.** A UNC path
  carrying credentials (`\\user:pass@server\share\x`) travelled whole,
  because the marker did not admit `:` or `@` in its host; a URL whose
  userinfo held a `;` had its run cut in front of the `@`, so the user was
  read as the host and the real host, the fragment and the password stayed in
  the text; and a path with a punctuated directory in the middle
  (`/home/op/a;b/c/x.exe`) lost its prefix and kept a tail naming the
  directories in between. The authority of a URL now ends where an authority
  ends, a path run ends only at whitespace or a quoting character, and a UNC
  path loses everything in front of its last `@`. A run that is a single
  rootless word is no longer treated as a path at all: `</token>` in a tool
  result was being rewritten to `<token>`, corrupting the XML the model read
  back.
- **Four key shapes the event scrubber could not see.** A credential run was
  anchored to `[A-Za-z0-9_-]`, so a standard base64 key (`+` and `/` in the
  alphabet), a bare JWT — this project's own access-token shape — a key behind
  the `\"` of nested JSON and one behind a Unicode dash or quotation mark all
  travelled verbatim in `args_summary` and `summary`. The value run now ends at
  a backslash and at anything outside ASCII, the length rule reads the standard
  base64 alphabet, and a three-segment run whose head really is a JOSE header
  is replaced. Digests, MIME types and host paths are unchanged: a digest is
  what the analysis is about, a MIME type is long enough for the widened rule
  (`application/octet-stream` is exactly 24 characters), and a path is still
  cut to the file name a reader needs rather than replaced outright.
- **A tool server reads the sample it was given, and nothing else on the host.**
  Every `path`, `pcap_path` and `ruleset` argument of the `analysis` and
  `network` sidecars is now resolved with symlinks followed and refused unless
  it lands inside the staging directory or one of the directories
  `MALJAN_SAMPLE_ROOTS` names (`:`-separated, empty by default); a `ruleset` is
  held to the `data` tree and the two rule-directory variables instead. A
  sample is adversary-authored content that the analyst model reads, so an
  instruction inside it could point `iocs_from_file` — a tool whose purpose is
  extracting typed secrets — at any file the sidecar could open, and the answer
  went to the ledger, the report and the event feed. A refusal is the ordinary
  structured error with the code `path_outside_roots` and a remedy, and it
  names no host path. The worker exports the directories it writes samples to
  (the download directory, each static provider's mirror and the directory a
  sandbox capture is fetched to), so a default deployment configures nothing;
  a sample that lives anywhere else needs the variable. `put_sample` and the
  carve destination keep their own write confinement.
- **The capability manifest says only what it knows about this host.** A
  missing module is reported in the import's own words; a broken install or a
  shared library that will not load is reported by exception type alone, so no
  absolute path reaches a probe response, the console, the run summary or the
  judge's prompt. `timeout_s` is declared from the constant the tool itself
  uses — 60 s for `yara_scan`, 300 s for `capa`, 15 s for every threatintel
  lookup — and a test asserts the two match for every tool of every sidecar. A
  degradation reason now says what the tool still answers without its library,
  each requirement is probed once per cell, and `capabilities()` hands back a
  copy nothing can reach into.
- **The threatintel sidecar answers a failure as one.** Its four lookups
  returned prose for a timeout, a bad status and an invalid key, which every
  consumer read as an answer; they now return the structured error with its
  code and remedy, while a lookup that simply found nothing stays an answer.
  The `put_sample` family returns `bad_argument` in the same shape, and a
  missing credential is no longer read as a missing file.
- **The budget meter counts the loop that was cut off.** A loop that ended at
  its wall clock recorded `steps_used: 0` — the one run the meter exists to
  explain; it now reads the budget's own count. The judge runs the same meter
  as the analysts, so the one loop with a hard timeout says which cap ended
  it, and budget rows are drained on every path that drains a ledger: the
  stage node, the revision node, the delegation hand-over and the judge. A
  tick before the last one counts the calls made so far. A stage-start check
  now finds a tool the collision rule renamed, the failure list says when it
  cut and trims a message, and one place decides what a failure looks like.

- **An ask has a budget of its own.** Deriving a callee's steps from what its
  caller had left starved both: the live proof watched a specialist die at a
  recursion limit of five before it had made a tool call, later asks refused
  with "0 s and 3 steps remain", and the lead close with no techniques.
  `agents.delegation_steps` (12) and `agents.delegation_timeout_seconds` (300)
  are what one ask gets, bounded by the caller's remaining wall clock and by
  nothing else; the caller's own step budget is not reduced by what its
  specialists spend, and an ask is refused only when the caller has less time
  left than a first model turn needs. A loop that reaches the graph's own step
  cap writes up what it gathered instead of raising a recursion error. A budget
  row counts its own agent's turns and nothing else, with what its specialists
  spent beside it as `delegated_steps`, so `steps_used` can no longer pass
  `max_steps`. The seeded `lead` gets 40 steps and a 1800 s stage, and the
  `ask_<key>` tool's description and `lead.md` both tell the model that an ask
  has a budget of its own and costs it wall clock.
- **A caller asks one agent at a time.** langgraph gathers a turn's tool calls,
  so a model that emitted two `ask_*` calls ran two nested loops at once — two
  analysts against one llama-server slot, which is the re-prefill timeout this
  project has diagnosed once already. A per-caller lock serialises them, and it
  is a different object from the per-callee one so an ask made from inside an
  ask still nests. A callee's unavailable tools are recorded when it is asked,
  the way a stage records them when it starts, and a budget row is filed under
  the agent that ran the loop rather than the one that handed it over, so a
  lead's step cap is the lead's and a specialist's is the specialist's. The
  judge counts its own turns, so its time-capped loop no longer records zero
  steps. A refused ask is no longer listed as a broken tool.
- **A delegated round is drawn once.** Recorded rows and live events now share
  one identity — who spoke, in which round, and a digest of what was said —
  because the addressee is the one thing only the live copy has, and putting it
  in the id drew every ask twice on a job that had both a report and events
  still inside the stream's TTL.
- **The argument repair never finishes a value.** It closes brackets and
  nothing else: a call cut in the middle of a string is refused with the
  message it was already refused with, because closing the quote would hand
  the tool a path that exists nowhere or a different search. A call that was
  closed off says so in the result the model reads, not only in the ledger.
- **Two findings with different techniques are two findings**, and a STIX
  indicator keeps its case wherever the case is part of the value — a URL path
  is case-sensitive, and folding one away removes a fact from a report. A
  failed threat-intel lookup is never cached, and `check_ip_reputation` answers
  two sources as one answer or one failure rather than a JSON document glued to
  a sentence.

- **A delegated ask stays inside the stage that made it.** A callee's
  effective tool set is its own definition narrowed by the tool policy of the
  stage doing the asking, so a stage with `builtin_tools=False` can no longer
  reach a built-in server through a specialist that no stage narrows; the ask
  is refused naming the stage and the servers. A profile that excludes every
  server withholds the `ask_*` tools too. The callee's hard cap stops at the
  ceiling its caller set, so it cannot outlive the caller waiting for it, and
  a hand-over to a caller whose loop has already ended drains the callee
  without folding anything onto an agent that is done with. Each agent's lock
  is now taken by its own stage run as well as by an ask of it, so the two
  cannot drive one instance's buffers at once, and a caller waits for a busy
  callee only as long as it can still read an answer in. The brief written
  onto a callee is given back afterwards, its findings and artifacts travel to
  the caller with the callee named as their source, and a `lead` may carry a
  provider reference like the generic agent it otherwise is.
- **The transcript draws a delegated round once.** Every line is identified by
  who spoke, in which round, and a digest of what was said — never by a counter
  taken before the duplicate check, and never by the addressee, which only the
  live copy has — so the stream back-fill, the live socket and the stored rows
  all collapse onto one line. Two recorded rows that say the same thing in the
  same round carry their own `seq`. The agent editor offers **Ask another
  agent** only where a reference can be saved.
- **The budget a model is told is in model turns.** The run-state line
  reported graph steps as turns, about twice the truth (a tool round is two
  graph steps); `model_turns_left` counts what langgraph counts and the
  initial framing, the per-turn refresher and the final-answer nudge share
  it. **The ISR parser keeps every technique id as written**: the
  1001–1700 range guard and the placeholder set are gone, and
  `attck.unknown_id` does the challenging. **The static provider does not run
  capa and YARA again** when the triage pack recorded them. **`api_capability`
  is a catalogue association, not a source**: its rows travel under
  `associated_by`, shown in a Catalogue column and on the pack line as
  "API catalogue associations (reference)", never in `asserted_by`; the
  judge's zero-corroboration note counts the analysts' claimed techniques
  and states rule matches no analyst claimed separately. YARA TTP rules are
  the fifth asserting source (`yara`), an asserted id the catalogue retired is
  marked in the table, a skipped lookup is not a failed tool in the run
  state, and a budget-trimmed pack entry says its output was dropped.
- **Our own rule files assert only live ids.** Two API-to-technique rules and
  one YARA rule carried ids the catalogue retired (T1562.001, T1562.006,
  T1574.002); they now name what the 19.2 bundle's `revoked-by` points at
  (T1685, T1574.001), the composer's evasion filter learns T1685, and a test
  holds every technique id in `data/api_attck_map_v1.json` and
  `data/yara_ttp_rules.yaml` to `valid_ids()`.
- **`api_capability` cites the same spelling in every process.** The matcher
  walked a set, so which of an ANSI/wide pair was cited — and the YARA draft's
  strings — changed with the hash seed; the set is walked sorted and both
  spellings cite the rule. Revision `20260920000000` also deletes the stored
  `preprocessing.use_api_behaviour_map` and `api_behaviour_map_path` rows. The
  three vendored ATT&CK files carry `_meta.attck_version`, ICS techniques no
  longer declare the platform "None", and the derived-technique table is
  ordered by source and id.
- **The ledger keeps the full parsed result.** `build_entry` parsed
  `structured` from the output it had already cut at `MAX_OUTPUT_CHARS`, so a
  pack result longer than six thousand characters was stored with no
  structured payload and corroboration, the projections and the evidence
  sections saw nothing of it; on the live proof that hid a real rule hit.
  `structured` is now the whole result and `output` the text a model reads;
  `apply_budget` counts what is stored against the per-agent evidence byte
  budget.
- **The signature facts come from the pack's `signing_info` entry, cited by
  id.** `identity.signing` was never filled from the ledger, so a signed
  sample read `Signed: no`; the projection now reads presence, subject and
  issuer (a chain verdict only when the tool reports one) and the `Signed`
  row prints the entry id.
- **One helper decides which API rules fired.** `api_capability_hits` applies
  a rule's `min_apis` over the pooled matched APIs; the report's projection
  and the corroboration collector both read it.
- **Corroboration reads the ids capa and Sigma really write.** The extractor
  behind `asserted_by` matched a whole string against `T1234`, so capa's
  decorated `attck` strings and a Sigma match's `attack.t1055.012` tags never
  counted and two of the four sources the table names could not appear in it.
  One reader, `analysis.technique_ids`, takes the shapes as the tools emit
  them, and the corroboration table, the persistence projection, the evidence
  sections and the pack's capa line go through it. The Sigma ledger fixture
  carried an invented `meta.technique_ids` key and now carries the `tags`
  `sigma_match` writes.
- **`api_capability` matches the import set as a whole.** Every rule in the
  vendored API-to-technique map needs two or more APIs and the tool matched one
  name at a time, so no rule could ever fire and the pack's entry listed no
  technique on any sample. Each API's row now cites the rules the set clears
  whose evidence includes it, with the APIs matched and the rule's floor.
- **A corroboration row is read in one place, in either shape.** The CLI
  counted a row's keys as its sources, and a summary stored before the two
  lists crashed `to_markdown` and `to_dict` when the CLI rebuilt it directly;
  `corroboration_row` normalises on construction and every reader goes through
  it. From the same review: the judge node records its own unchecked
  attack-patterns under `validation.not_run`; the index warmer checks and sets
  under one lock and remembers a failed build; a reputation lookup that was
  skipped renders as not done and one that broke as failed; the alignment gate
  ranks the claim's own words; the judge's platform message drops its
  duplicated subject; the report's corroboration table sits under its own
  heading; a node-level test shows a capa failure alone leaves a run
  undegraded.
- **Carved payloads land under the sidecar's staging directory, never where the
  model says.** `carve_payloads` took a model-chosen `out_dir`, so a tool could
  write live malware anywhere the analysis sidecar could write; a live run
  passed the two-character string `""` and a directory literally named `""`
  with a carved PE body in it appeared in the sidecar's own cwd. The argument
  is gone: files land in `<staging>/carved/<sha256 of the sample>/`, created
  private like the staging directory. A string of nothing but quote characters
  now counts as an absent value for every optional string argument on that
  server, as a blank one already did.

- **An API-call row carries what the sandbox recorded.** `sandbox_api_calls`
  copied the import table's category and a suspicious flag onto every row and
  filtered by that category. Rows now carry the API, the module the sandbox
  resolved it from when known, the processes that made it, the count, and the
  first call's arguments and time; a `name` substring filter replaces the
  `category` one. The report's section bundles no longer list imports by
  capability category either; the capability counts stay.

- **The sample's identity grounds an indicator only by exact match.** The
  identity values had been unioned into the substring haystack, so a value
  written inside the submitted file name, or a slice of the sha256, grounded
  an indicator the run never saw. A literal equal to one of the sample's own
  hashes or its name, case-insensitively, is grounded; nothing less is.

- **An import row states what the import table states.** `pe_info` and
  `elf_info` copied the old capability table's category onto every import row
  (`BitBlt` came back as `keylogging`), and on a signed PuTTY the static
  analyst wrote the label up as its first claim and the judge said Malware. A
  tool that labels an import has done the analysis. Rows now carry library,
  name or ordinal, hint and address; what an API is used for is the knowledge
  server's `api_capability` question, asked when the model decides it matters.

- **The sample's own identity values are grounded indicators.** The identity
  block gave the judge the sha256, the judge emitted it as an indicator, and
  the grounding check rejected it on a run that never called `hashes`. The
  sha256, sha1, md5 and file name the router established ground an indicator
  the way a ledger entry does; every other value still needs one.

- **The citation checks read the run's own ids.** `EV_0002` is the same entry
  as `ev_0002`; an `ev_9999` the run never issued is a citation of nothing; an
  evidence line longer than the field keeps the id the cut used to drop; and a
  Benign verdict over a run that recorded no entries at all is not asked to
  name one, since the pipeline already calls that run inconclusive.

- **A repeated tool call that raises counts as a repeat.** The guard counted a
  repeat after the call returned, so a tool that throws on the same arguments
  every time ended the loop one call late.

- **A repeating ReAct loop is actually ended.** The guard counted only the
  repeats it served, which is reachable once per call, so an analyst that asked
  one tool sixteen times counted one repeat and ran to its step budget. Every
  repeated call counts now, served or refused, and the guard resets when a
  connection error replays the conversation.

- **The judge is given the sample it is told to look up.** Both the mediator
  and the verdict prompts carry an identity block from the router — sha256, md5
  and size where known, file name, type and platform — and the lookup sentence
  names the sha256. A run whose analysts produced no prose left the judge with
  no hash anywhere in its conversation.

- **The final-answer nudge survives a tool call the server cannot render.** A
  live static loop ended on an assistant turn whose tool call carried
  arguments that never parsed; the nudge sent the turn back and the server
  answered 500 ("Failed to parse tool call arguments as JSON"). The nudge and
  the forced synthesis now send the transcript without such a call, and when
  the plain request still fails the nudge asks once more with the loop's tools
  bound and `tool_choice="none"`; `run_summary.nudge.retry_mode` names which
  analysts needed which repair.

- **A Benign verdict over a run nobody analysed is challenged.**
  `verdict.unsupported_benign` asks the judge to cite the entry that
  establishes it — a valid signature is the usual one — or to return Suspicious
  with an inconclusive rationale. The verdict is recorded, never rewritten.

- **A technique claim that cites nothing is challenged.** A signed PuTTY
  produced eighteen technique ids, sixteen of which said in their own evidence
  field that they were speculative, and the judge read them as eighteen
  techniques. `isr.ungrounded_technique` asks the analyst once to name the
  ledger entry it read the technique from or to drop it, records what survives,
  and tells the judge which techniques the run does not establish. Nothing is
  rewritten, and an analyst with no tools is exempt.

- **A ReAct loop that only repeats itself is ended.** An analyst spent 16 of
  its 19 steps calling one tool with identical arguments. The second served
  repeat now says the loop is about to end, the third ends it, and what was
  gathered goes to the same forced synthesis a spent step budget takes.

- **Forced synthesis keeps the evidence it is asked to synthesise.** The
  budget comes from the model's context window where `llm.openai.context_size`
  (or the Ollama window) declares one, with the old fixed 16,000 characters as
  a floor; trimming drops whole tool call and result pairs oldest first, and
  assistant prose before any pair, so a result is never dropped while the call
  that referenced it stays; and the instruction names the ledger ids still in
  the window.

- **A bound reputation server is actually consulted.** VirusTotal connected for
  the judge, offered six tools and was never called: the judge opens its tool
  loop on explicit dissent alone and the static analyst held no reference to
  the server, so the run closed with a family of None and nineteen ledger
  entries that were all local analysis calls. Every agent that reads the file
  carries the reference now, their prompts say to look the hash up once and to
  treat the answer as one source, and the judge asks the identity question when
  nothing in the run has asked it.

- **The `strings` page fits the answer the model is shown.** The default page
  was 2000 runs, which came back as hundreds of kilobytes and was cut to 8000
  characters before the model saw it; the page is 150 runs, the answer carries
  `total_matched` and a `next_offset` that is `null` at the end of the set, and
  the description says where the next page starts. Optional arguments arriving
  as the literal "null", "None" or "" are read as absent by the analysis
  server's guard, so a model that fills in a filter it does not want is
  answered rather than argued with.

- **A verdict may not contradict its own severity.** A live run returned
  Malware at 0.6 with a severity of Informational whose rationale read "no
  evidence of malicious functionality". `verdict.assessment_conflict` puts both
  fields to the judge once and asks which it meant; a contradiction that
  survives is recorded, and neither field is ever rewritten.

- **One Qdrant credential instead of two.** The enrichment worker and the
  health probe read `api.qdrant_*` while the analysis path read
  `core.memory.qdrant_*`, so filling in either left the other empty — the 401
  in every enrich run. Both read the `core.memory` keys now, the `api.*` keys
  are gone, and `20260918000000_unify_qdrant_settings` carries a stored value
  across before removing the duplicate row.

- **A run nobody performed is no longer reported as a result.** A hosted
  endpoint refusing every call with 402 produced a job that said "completed"
  with verdict Suspicious, confidence 0.0, no evidence and an empty error
  message; a run whose analysts all failed produced an empty STIX bundle, which
  the verdict heuristic read as Benign at 0.10. A run with no evidence and no
  analyst claim is now Suspicious with the reason "inconclusive: no analysis
  was performed" in the degraded banner, and a run in which no analyst answered
  *and* the judge never answered fails, carrying the provider's error class and
  status, with no report persisted.

- **A provider answering "not now" costs a retry, not the run.** The retry
  helper covered a dropped socket only, so one 500 or 503 from a hosted
  endpoint took the analyst, the negotiation, the verdict and every report
  section with it. The transient statuses (408, 409, 429, 500, 502, 503, 504)
  share the connection error's attempt budget and backoff and honour a
  `Retry-After` within it; every other status is answered once.

- **The 400 self-heal heals the model the job is holding.** The healed model is
  remembered by the wrapper that healed it and swapped into the container's
  cache, so an endpoint that refuses the llama.cpp extras is asked with them
  exactly once instead of on every call — which had been building a new client,
  and leaking its connection pool, each time.

- **A report of absence is not a capability claim.** "No persistence mechanism
  was observed" and "there is no evidence of command-and-control communication"
  were recorded as over-claims and fed back for correction. A negation cue in
  the term's own clause clears it; a claim after the clause ends is still
  reported.

- **A hosted OpenAI-compatible endpoint is no longer sent llama.cpp's request
  fields.** The provider added a repetition penalty, an `n_predict` echo of the
  output cap and `chat_template_kwargs` whenever `base_url` was set, conflating
  "custom endpoint" with "llama.cpp server": the first run against
  `https://integrate.api.nvidia.com/v1` failed on
  `400 Unsupported parameter(s): n_predict` before an analyst ran. The new
  `llm.openai.compat` setting says which dialect the endpoint speaks —
  `llama_cpp`, `standard`, or `auto`, which reads the host and treats loopback,
  link-local and private addresses as local. An endpoint that rejects one of
  the extras anyway is retried once without them and remembered for the rest of
  the process.

- **A name the product later seeds no longer breaks the configuration.** An
  operator's own agent or team stored under `triage`, `android_static`,
  `reverser`, `mobile` or `deep_static` was refused as tampering with a
  built-in — on every read, which is to say at boot, by an API and a worker
  that then could not be repaired from a console needing the configuration to
  load. Such an entry is renamed to `<key>_custom` on load and by
  `20260917000000_rename_colliding_agent_keys`, with every reference moved with
  it: the teams that named it, `llm.agents`, each server's `agents` binding and
  both `react_*_overrides` maps. Names reserved since there was a settings
  store, and names typed after a seed exists, are still refused.
- **Sections routed to the identity tab were drawn nowhere.** `identity` and
  every `<format>_header` table — the header of every binary-info tool — were
  routed to a tab that had no renderer, and were therefore also excluded from
  the evidence tab's catch-all, so they were built, persisted, counted in the
  evidence metrics and shown on no page. The identity tab draws them now, and
  the catch-all is keyed on whether a tab actually renders sections rather than
  on a hand-kept list, so the next tab added without a renderer costs a section
  its page and never loses it.
- **The heatmap counted the judge differently from the backend.** The console
  matched the layer name case-insensitively and trimmed; `capability_matrix.py`
  compares exactly, and a layer name is a validated agent key. The two could
  therefore disagree about the same run — the one thing a shared rule exists to
  prevent. The console compares exactly.
- **A stage announced its end once per node.** Two shapes had no node of their
  own that runs after everything in them is done — a parallel analysis stage
  nothing depends on, whose agents all end at once, and a terminal debate,
  which leaves through a conditional edge — so every one of their nodes
  announced `stage_finished`, each carrying only the half of the merged result
  that node could see. Both now get the barrier they were missing, and the
  announcement is claimed once per stage, which also turns the report node's
  closing rollup back into the repair for a crashed run that it was meant to
  be.
- **The console stopped presenting Windows shapes as the default.** The imports
  table names the format's own container instead of saying Module for every
  sample, the registry panel appears because something touched a key rather
  than because the sample is a PE, the persistence labels cover macOS and
  Android as well as Windows and Linux, the ATT&CK matrix counts the judge as a
  source and not as a corroboration — exactly as `capability_matrix.py` does —
  an id the catalog does not have is printed with a marker instead of reading
  as a normal row, and the severity prints the judge's own reasoning under the
  rating rather than a rating with no argument behind it.
- **Sigma Layer 0 was contributing nothing.** 272 of the 4241 rules under
  `data/sigma_rules` parse into a detection object with no `parsed_condition`,
  and reading that attribute raised out of the first such rule every scan
  reached; the pipeline caught the error, logged "scan failed" and carried on,
  so the layer had been silently dead on every run with sandbox telemetry. The
  evaluator now reads the attribute defensively, `scan_events` and
  `scan_log_lines` skip a rule that raises rather than abandoning the corpus,
  and the count is exposed as `SigmaLayer.last_rule_errors`, as `rule_errors`
  in the `sigma_match` tool, and logged once per scan.


- **No fragment of the LangSmith API key is logged.** Enabling tracing logged
  the key's last four characters; it now records only that tracing is on and
  which project it writes to.
- **The Ghidra connection test proves the token.** The probe read the
  unauthenticated health endpoint, so a wrong bearer token passed the test and
  every job then failed with 401 on the tool schema. It now fetches the schema
  itself and lists the tools it found.
- **A failed run points at its error id.** The worker publishes no exception
  text — a message it did not write itself can name a host path — so a failure
  reaches the console as the class of the exception, or the sentence the worker
  composed, followed by the id its log entries are filed under. The run header
  showed none of it and the conversation simply stopped. Both now draw the
  failure, with the id as its own labelled, selectable value beside a copy
  control and one sentence saying that the API and worker logs carry the rest
  under it.
- **One violation is one line in the conversation.** A validator finding is
  published as the producer is shown it and again as the retry fixes it or
  fails to, and the console drew the three states identically — one violation
  reading as two or three unrelated notices. The conversation now folds them
  on `(agent, code, path)` into the first line's place, says in words where
  the violation ended up, and keeps the earlier states under it as that
  line's history. A run that published no locator folds on `(agent, code)`.
- **A run longer than one page is replayed whole.** The console's back-fill
  made one call and the events endpoint caps a read at a thousand events, so a
  finished run with more than that rendered as its first thousand and stopped
  mid-debate with nothing saying so. It now pages on `since` until a page
  comes back short of the cap, and a page that does not advance the sequence
  ends the read and says on the conversation that what is drawn is only part
  of the run.
- **The verdict a run publishes is the one the judge stated.** A signed,
  0/74-clean PuTTY was published as `Malware, confidence 1.00` over a judge
  whose severity was `Informational`, whose category was `legitimate-utility`
  and whose own rationale read *"the 'malware' classification is used here
  strictly as a container for the object type in STIX, but the assessment
  confirms it is benign"*: `decide_from_bundle` read the verdict off the
  *presence* of a `malware` object, the pipeline detected the contradiction,
  fed it back once, and published the shape's answer when it survived. The
  judge now states the verdict in `x_maljan_assessment.verdict` — Malware,
  Suspicious or Benign, with its own confidence beside it — the prompt asks for
  it and says a `malware` object is written only for a sample it concludes is
  malware, and `pipeline.outcome.decide_from_bundle` reads that statement
  first. The statement has three answers and only one of them lets the object
  set speak. A word the pipeline knows is the verdict, read through one
  normaliser the report builder shares: the whole value has to *be* one of the
  three words once whitespace, case and the decoration a model wraps a word in
  are taken off, so `Malware.`, `**Benign**` and `"Suspicious"` are the words
  they are wrapped in and nothing else is interpreted — not a qualifier, not a
  parenthesis, not a question mark, which is doubt rather than decoration. The
  field accepts any type, because a judge answering `["Malware"]` to a field
  with three allowed values would otherwise fail the whole bundle exactly as a
  misplaced block did; a value that is not one of the three words — `Clean`,
  `Not malware`, `malware-free`, `Malware (false positive)`, `["Malware"]` — is
  `verdict.unrecognised`: asked about once, quoting what the judge wrote, and
  if it survives the run publishes the inconclusive verdict with the judge's
  own answer printed beside it and no confidence, because a judge that wrote
  something has already kept the objects out of it. The object set is read only
  for a bundle whose field is *absent*, which is every stored run and a model
  that omitted it, and that reading is fed back once as `verdict.unstated` and
  recorded when it survives. The conflict check
  now compares the stated verdict with the severity rating, the category and
  the presence of a `malware` object, one row per disagreeing fact; when it
  survives the stated verdict is published, the conflict is in
  `run_summary.validation.unresolved` — and a `malware` object under a stated
  Benign verdict is not written into the exported STIX bundle, recorded as
  `stix.malware_object_under_benign`, with the relationships that would dangle
  pruned by the integrity pass and the judge's own bundle unchanged. The
  published confidence is the judge's own number for the verdict the judge
  itself stated, and it is published only together with one: on the fail-safe
  and unrecognised paths the verdict is not the judge's, so there is no number
  to print beside it. How the verdict was read is recorded rather than
  inferred: `run_summary.verdict_reading` is `stated`, `unrecognised`,
  `unstated` or `fallback`, the report endpoint carries it, and the console
  draws the matching one-line note beside the verdict and says in its degraded
  banner whose confidence — the judge's own or none at all — the number above it
  is. A judge that states a verdict and puts no number on it gets the sentence
  for a run with no confidence, because the header reads "not assessed" there
  and a banner describing the confidence shown above would describe nothing. Replaying the PuTTY run's recorded answer — which has no
  `verdict` field, because there was none to write — now publishes Malware from
  the objects with `verdict.unstated` recorded and **no confidence**, where it
  used to print the judge's `1.00`.
- **A STIX note is about something.** `object_refs` is required on a note and
  on a report and a required list may not be empty, and a bundle that breaks
  that is rejected whole by a conformance-checking consumer rather than losing
  one object. A Benign verdict has no malware object for the summary note to be
  about, so the note is about the indicator carrying the sample's own hash,
  which the indicator cap keeps in a band of its own; a bundle holding nothing
  the note could truthfully refer to emits no note and keeps the summary in the
  report, and a bundle with nothing to report on emits no report object.
- **The sample's own indicator says what the verdict says.** It was typed
  `malicious-activity` whatever the run concluded, so a Benign export told
  every blocklist that the sample's hash is malicious activity, with the run's
  own note saying Benign attached to it — a stronger contradiction than the
  malware object the same export declines, because a consumer blocks on the
  indicator and reads the objects afterwards. The type now follows the
  published verdict through STIX 2.1's own `indicator-type-ov`: Malware is
  `malicious-activity`, Suspicious `anomalous-activity`, Benign `benign`, and a
  verdict the mapping does not name is `unknown`. An indicator for anything
  else — a domain, an address or a URL the analysts observed — keeps the type
  it already had.
- **An address in the sample's bytes is not an address it reached for.** The
  domains got this rule and then the URLs; the addresses were the one network
  kind with nothing asked of them at all, so every run of digits the string
  sweep read as an address was published as an indicator, charged to a
  reputation provider, and ranked at the export's cap as though a sandbox had
  watched it. One live bundle carried `6.0.0.0`, a version number out of the
  strings table; on a report shaped like the ones the live runs produced,
  fourteen such values displaced every observed C2 endpoint. `NetworkIP` now
  records its source the way a domain and a URL do — labelled where the ledger
  projection adds it, shown in the report and on the console's card — and goes
  through the same publish predicate. Loopback, unspecified, link-local,
  multicast, broadcast, reserved and the ranges a document is written with are
  never indicators; a private address — and the shared address space
  `100.64.0.0/10`, which `is_private` answers False for and which is therefore
  named on its own — is published only when somebody watched the sample reach
  it, which is lateral movement rather than a version number typed with dots in
  it. A string-derived address costs no reputation lookup
  either, as a string-derived domain already did not.
- **One misplaced extension object no longer costs the judge its whole
  bundle.** The prompt asks for `x_maljan_assessment` beside `objects`; a model
  that wrote it inside the list failed `Bundle.model_validate` with twenty-one
  errors, and a live run lost all twenty-five of its objects to a
  text-extracted verdict, twice. The block is now moved to the property it
  belongs to before validation, unchanged, and recorded as
  `verdict.assessment_relocated` with the state `resolved` and no retry spent;
  a top-level block already present wins and the inner copy is set aside. Any
  other item whose `type` is not a STIX type the bundle can hold is set aside
  under `stix.unknown_object` and fed back once, and the rest of the bundle is
  read.
- **A technique from an ATT&CK domain the sample cannot host is not published
  as one of its techniques.** An APK run's `ttp_mappings`, `/mitre` and STIX
  bundle all carried enterprise-only `T1027` and `T1005` with
  `attck.platform_mismatch` unresolved on both after the feedback turn. Such a
  technique now joins the rule an unresolvable id already follows: it stays in
  the capability matrix, spelled as the producer wrote it, with the check's own
  sentence in the new `CapabilityCell.not_published`; it is absent from the one
  validated list all three surfaces and the attack-pattern rebuild are built
  from; and the report lists it under *Claims that were not published as
  techniques* with the reason in words. The question is asked with the same
  `platform_mismatch_message` the analyst and the judge were shown and falls
  open for a sample whose platform is unknown or cross-domain. That check's
  `PRE` carve-out is now asked before its domain comparison rather than after
  it: a technique that happens before any host is touched cannot be
  contradicted by a sample's platform *or* by its domain, and since ATT&CK
  files every PRE technique in the enterprise matrix and mobile has none,
  asking the domain first made each of them cross-domain on an APK — a warning
  while the check only annotated, and a lost technique once the report read it
  to decide what to publish. An `isr.ungrounded_technique` alone stays
  advisory.
- **A truncated URL is not an indicator, and the indicator cap holds.** One
  bundle published `http://localho`, `http://schq`, `https://q`,
  `http://3271` and `https://fs01n5.sends` — string-sweep cut-offs — as
  `url:value` indicator objects. URLs now record where they came from, the way
  domains already did, and go through the one publish predicate, plus one
  question no source can answer for: whether the host could exist at all. That
  question is syntax rather than membership in a list of known TLDs — a valid
  Tor address on its own checksum, an address literal that is not loopback,
  unspecified or link-local, or a name whose labels are labels and whose last
  one is a suffix rather than a word — so `gov`, `edu`, `mobi`, punycode and
  every ccTLD pass it, `http://.com` and `https://q` do not, and a
  sandbox-observed request to a university host is exported rather than
  silently dropped. Whether an endpoint that *could* exist is published stays
  the corroboration rule's decision, so `https://fs01n5.sends` from the string
  scan alone is held back for want of a second source, which is the reason the
  report gives for it. Every minting path asks both, and there is now one place
  that asks and one that writes:
  `network_publish_reason` answers for a domain, an address or a URL alike, and
  `network_pattern` is the only function that builds a `domain-name`, `url`,
  `ipv4-addr` or `ipv6-addr` pattern string. That was three rules over four
  paths, and the fourth — a string row of kind `ip`, which the deterministic
  extractor produces on every sample — asked none of them, so an address the
  network block refused was exported by the string scan two sections later,
  typed `malicious-activity`; a test walks the tree for a second place building
  one of those four patterns and fails when one appears. The judge writes
  patterns rather than minting them, and its own indicator objects are asked
  the host question for all three kinds — a name, a URL's host and an address,
  the last with the judge counted as having observed it, so one it cites out of
  the sandbox's evidence stays and loopback never does. Asked of URLs alone, a
  judge bundle exported `[domain-name:value = 'localhost']` and
  `[ipv4-addr:value = '127.0.0.1']` unrecorded while every other path refused
  the same two values. A pattern is not one comparison, so every value in one
  is asked and an indicator with a single unpublishable endpoint in it is
  declined whole. An object type is read whatever case it is written in, and a
  comparison whose right-hand side is not an endpoint — a regular expression, a
  wildcard, a subnet — is declined with a sentence saying the pipeline could not
  read the pattern's endpoint rather than one about a host that could not exist.
  The corroboration half is still not asked of the judge,
  because the judge's own assertion is the source and "the judge said so" is
  not a second source this code will assert on its behalf; whether any evidence
  holds an endpoint up stays `stix.ungrounded_indicator`'s question. A row that fails is
  not exported, and the decline is recorded as `stix.unpublishable_url` or
  `stix.unpublishable_domain` when a sandbox, an analyst or the judge is the one
  that recorded the row, because those are the rows a reader is owed a reason
  for; the string sweep's own cut-offs are not findings — a report carries up to
  forty of them and forty unresolved rows nobody can act on bury the ones
  somebody can. The console draws both codes as the export's decision rather
  than as something the judge left unfixed, which only the URL one did.
  The suffixes that name a private network's own machines are one list now,
  read by the export and by the enrichment's lookup gate alike. They kept their
  own, and the two answering differently stopped being a tidiness problem the
  moment the projection stopped dropping observed rows: a sandbox that resolved
  `x.alt` or `localhost.localdomain` was held out of the bundle and sent to a
  public reputation provider in the same run. `.lan`, `.home`, `.corp` and
  `.intranet` join the reserved ones, because none of the four has ever been
  delegated. The one name the two still answer differently is a Tor address:
  the export carries it on its own checksum and no provider can resolve a
  hidden service. A row held back only for want of a second source is the rule
  working and is not a finding either, and a row that records no source at all
  is read as string-derived, which is what the export's cap ranks it as. The
  host question is an export decision and is made where the indicator is
  minted: applied at the projection instead it erased the observation, and a
  sandbox-observed `fileserver.corp.internal` never reached the report's network
  block at all, so an analyst reading a lateral-movement case could not see
  which internal host the sample resolved. Nothing a sandbox, an analyst or the
  judge observed is dropped at the projection now; the projection still holds
  back a name only the byte image knows, because a run of bytes ending in
  `.local` is not an observation of anything. Every model-written value the verdict path puts
  into a validation row, a degradation reason or an export decline goes through
  the scrubber the events use and a length bound — a validation row is not an
  event, so none of them was covered by the scrubbing the publisher does, and a
  model echoing a credentialled URL into the verdict field put the credential
  in the stored report and drew it on the analysis page. A guard test reads the
  validation module and fails on a violation message that interpolates a name
  the code does not own without wrapping it, so the next row added is covered
  by the rule rather than by having been remembered.
  `MAX_TOTAL_INDICATORS` is applied over every indicator that would be in the
  bundle rather than over the ones the renderer minted, in the linter's stated
  priority order, so the two read one constant and agree: a run whose bundle
  carried two of the judge's indicators and fourteen of the renderer's shipped
  sixteen against a ceiling of fifteen, and the report's own C4 rule said so.
  The dedupe and the integrity pass run *before* the cap, so no slot is spent
  on a row that is deleted afterwards and a bundle over the cap ships exactly
  at it; the bands are the sample's own hashes, the network indicators ordered
  by how strong their origin is, the other hashes the judge carried, then the
  file names.
- **The console names the export for a decision the export made.** The Run
  record drew every unresolved row as "{agent} left {code} unfixed". That is
  the truth for a producer that was corrected and answered the same way twice,
  and the opposite of it for a row about the export: the judge wrote the
  object and the export declined to carry it.
- **A cached ATT&CK embedding says what produced it.** The embedding cache
  keyed on version, dimension and corpus, and the file it wrote recorded
  version and dimension — but `embeddings` has two backends, and the
  bag-of-words projection it falls back to when the sentence model cannot be
  loaded has the model's own 384 dimensions, because the vector store's schema
  is shared. So a process that could not load the model wrote a bag-of-words
  corpus into `~/.cache/maljan/attck`, deleted every other file there as
  stale, and the next process on that host logged "reused cached embeddings"
  and ranked techniques against it. `embeddings.active_backend` is one fact
  and three decisions read it: it is in the key, it is in the stored header,
  and a file whose backend is not the one in use is ignored with a line saying
  so — a file written before the field existed included, which is an
  unrecorded backend rather than this one. A fallback run writes nothing and
  deletes nothing: a model that failed to load once is a condition of that run
  and must not outlive it, and the stale-file sweep now removes only what its
  own backend wrote and what predates the field.
- **Every `arq` line is written once.** The worker's entry point is arq's own
  CLI, which configures a handler on the `arq` logger before the application
  configures the root one, and that logger still propagates: a measured worker
  log carried 19 lines with the `[arq.worker]` prefix against 21 bare
  `HH:MM:SS: ` ones. `setup_logging` now hands arq's logger over to the root
  the same way it already did the application's, so one handler writes each
  line in the application's format. A handler an operator added is left alone.
- **A participant whose stage has finished does not read "waiting".** The
  reporter writes the report and emits no `agent_message`, so its chip in the
  conversation's participant strip read `Reporter — waiting` on every finished
  run, under a Report stage marked DONE with its duration beside it. A
  participant that has said nothing now takes its state from its own stages:
  running is working, finished is done, and anything else leaves it where the
  feed put it.
- **The report's own elapsed time is the run, not the verdict stage.** The run
  summary started its clock inside the judge node, so a 473 s job published
  `Elapsed: 66.0s` and a reader quoting the report got a wall clock five to
  seven times short. The worker's own start now reaches the pipeline as
  `state["run_started_at"]` and the report node closes the figure when the
  report is composed, so it measures the same span the job row does; the
  per-stage durations are printed beside it from `run_summary.stages`, the
  list the console's stage headers are drawn from. Stored reports keep the
  figure they were written with.
- **One publish rule for every indicator the platform mints, not only the
  network ones.** The predicate covered `url`, `domain` and `ip`; every other
  kind the string sweep produces fell past it into the cap's file-name band and
  was exported with nothing asked. A run that concluded a signed PuTTY is
  Benign published ten SSH algorithm identifiers (`aes128-gcm@openssh.com` and
  its kind) as `malicious-activity` e-mail indicators, and a PE run published a
  third party's address lifted out of embedded library source.
  `indicator_publish_reason` now answers for every kind in `STRING_IOC_KINDS`:
  the value has to be the thing it claims to be — a host that could exist, a
  mailbox whose domain part passes the host rule, a path that names a file
  rather than a directory — and something other than the sample's own bytes has
  to know it: a sandbox observation, a persistence mechanism, a reputation
  record, or a ledger entry that is **not** the string sweep's and that an
  analyst cited in an artefact or a finding — quoting the sweep's own table
  back is one source said twice, and one analyst sentence carrying a parse
  artefact out of embedded source would otherwise have published it. What
  counts as present is a whole value, never a slice of a longer one. A mailbox
  the sweep read out of a file answers one question more than one the judge
  asserted: whether its domain part reads as a host at all, which is what tells
  `openssh.com` from `D.setdefault` and `r.Regsvr`. `indicator_pattern` is the
  one place any of those patterns is written, and the guard test fails on a
  second.
  An uncorroborated address a person owns stays in the report and reaches
  neither the bundle, nor `/reports/{id}/iocs`, nor an enrichment lookup, nor
  an event.
- **Nothing the platform mints is `malicious-activity` by default.** One
  function, `minted_indicator_type`, decides for every kind: the sample's own
  hash indicator is the verdict's word, and every other row is
  `anomalous-activity` unless it was flagged suspicious under a Malware
  verdict. A URL used to claim malicious activity whatever the run concluded.
- **A digest is its algorithm's length, a file name names a file, and one path
  is one row.** A run exported `[file:hashes.'MD5' = '32066ff6369a7bd7']`,
  sixteen of thirty-two characters, because the grounding check found the
  truncated prefix inside the real digest; it now matches a digest as a whole
  token and asks the length question first, and the export declines a
  malformed one as `stix.malformed_hash`. Every check in that function is a
  veto rather than an acceptance, asked of every comparison in the pattern
  rather than of whichever one the pattern started with — a grounded digest
  beside `[url:value = …]` used to turn off the URL denylist and the file-name
  anchor rule for the whole expression. A hash the algorithm table gives no
  length for — an ssdeep, a TLSH — is asked the corpus question rather than
  skipped: skipping it told a judge that the ssdeep the `hashes` tool had just
  reported "appears nowhere in the evidence", which spent the one retry and
  then dropped the object. A `file:name` naming a directory or
  a root (`/Users/`) is declined as `stix.unpublishable_artefact`, as is an
  `email-addr` that is not a mailbox. The judge's own objects are declined and
  recorded, never rewritten; the platform mints none of them. Dedupe compares
  normalised paths — separators, runs of them, a trailing one, and the case of
  a Windows path — so the same directory written twice is one indicator.
- **A technique the report prints is published, or the report says it is not.**
  An ISR carries technique ids in two places, and only one of them was ever
  questioned: `claims[].technique_id`, which the validator and the capability
  matrix read, and `findings[].technique_ids`, which the report's Findings
  table and the corroboration metric are built from. An Android run whose final
  claims carried no id at all fired no domain check anywhere and printed
  `T1027`, `T1055` and `T1071` — enterprise-only — in two tables and a count,
  with nothing saying they were not published. The findings' ids are now
  collected into the capability matrix with every other one and asked the
  domain and catalogue questions there; each `run_summary.corroboration` row
  carries `not_published` with the check's own sentence; the Findings table
  writes `claimed, not published` beside such an id; the summary counts "N
  claimed, M published"; and the console's ATT&CK tab draws from the capability
  matrix so the claim is visible there, in words, with the reason under it,
  and its tactic columns count what was published with the rest named beside
  it. An id that arrived on a finding and on no claim is printed everywhere and
  **published nowhere**: a claim is questioned in its analyst's own loop and a
  finding is not, so a finding citing no evidence and carrying no confidence
  would otherwise have put a technique into `/mitre`, the STIX attack-patterns
  and the report's ATT&CK section. The same id on a claim is judged as the
  claim's.
- **The sample's path is not the model's to give.** A static analyst typed it
  by hand, dropped three characters out of the sha256 in it, then spent its
  whole step budget guessing directories; nineteen of that run's thirty-five
  tool calls failed. The correction that existed recognises the spellings the
  model was shown and the sample's own basename in the wrong directory, and a
  mistyped name is neither. On the three built-in sidecars, an argument whose
  name means the file under analysis is now taken out of the schema the model
  binds to and filled by `pin_paths` with the path that server can open — the
  sidecar's own signature unchanged, only the model-facing copy narrowed. A
  qualified path argument (`pcap_path`, a rule file, a member inside an
  archive) names something other than the sample and stays the model's. The
  delivery primitives `put_sample`, `put_sample_begin`, `put_sample_chunk` and
  `put_sample_finish` are not offered to the model at all.
- **A file an earlier call produced can still be analysed.** Hiding the
  sample's path would have taken the carved payloads with it: `carve_payloads`
  writes each embedded payload under the staging directory and returns the
  paths, and nothing was left to pass one to. `carved_path` is a new optional
  argument on the fourteen analysis tools that read a file — `identify_file`,
  `hashes`, `signing_info`, `strings`, `iocs_from_file`, `pe_info`, `elf_info`,
  `macho_info`, `apk_info`, `carve_payloads`, `archive_list`, `document_info`,
  `yara_scan`, `capa`. It is confined to `<staging>/carved/<sha256 of the file
  the call is pinned to>/` and to that file itself — not the staging base,
  which one server process shares across every job it handles, and not
  `MALJAN_SAMPLE_ROOTS`. A run therefore reaches the payloads it carved and
  nothing another run carved or uploaded; two runs of the same sample share
  one tree, which is the same bytes read twice. The absolute path
  `carve_payloads` returned and the tail of it both work; a traversal, a path
  outside the tree or a symlink out of it meets the existing
  `path_outside_roots` refusal, and a value that resolves onto a directory, a
  FIFO, a device or a socket is refused as `bad_argument` rather than opened.
  Given, that file is read in place of the sample and the answer carries
  `read_path`; left out, the sample is read. It is qualified, so the path
  pinning leaves it alone. A payload carved out of a carved payload nests
  under the sample's own tree rather than opening one of its own.
- **Carved payloads expire.** The analysis sidecar's TTL sweep deleted files
  under the staging directory and stepped over directories, and everything
  `carve_payloads` writes lives a level down in `carved/<sha256>/` — so no
  carved payload ever expired and a long-lived host accumulated them
  indefinitely. The sweep now prunes those trees on the same
  `MALJAN_STAGING_TTL_HOURS`, removes a tree the pruning leaves empty, and
  never follows a symlink.
- **The report composer shows each section the object it has to answer with.**
  Six runs on two unrelated models authored zero professional sections between
  them, answering every section with renamed or superset keys. On the
  manual-parse path — the primary path on a local server, because structured
  output is skipped there — the prompt said "conform to the provided JSON
  schema" and provided none, and the only key name a model ever saw was the
  bundle's opening line, `SECTION: <name>`. The exact object is now built from
  the section's own schema and printed in the prompt, and the heading is a
  sentence. One shape is accepted as a move: `{"<section name>": "the prose"}`
  goes into the field that holds the section's prose; anything that needs
  interpreting is still dropped and named.
- **The judge is shown the answer's whole shape.** `x_maljan_assessment` was
  asked for in a bullet among ten, with "Return ONLY a valid JSON STIX 2.1
  Bundle" last — and a STIX bundle is `{type, id, objects}`. The default model
  omitted the block on its first attempt in three runs of three and spent its
  one verdict retry on it every time. The prompt now ends with the skeleton,
  `x_maljan_assessment` beside `objects`, with the three accepted verdict words
  written where the verdict is asked for. Prompt text only.
- **A reasoning model on Ollama is told which setting to turn on.** It fails
  the connection test at the shipped default — the answer goes into the
  thinking channel and the probe reports that it answered nothing — and with
  `core.llm.require_probe` on, the API then refuses every job. The default is
  unchanged, and the failure and the timeout now carry a sentence naming
  `core.llm.ollama.disable_thinking` and what it does; the Ollama setup guide
  says the same, and `docs/getting-started.md` documents `gemma4:12b` with that
  setting as a measured low-memory option.
- **`carved_path` reads the value a model actually writes back.** On its first
  live contact an analyst failed six calls out of six: it passed the path
  `carve_payloads` had returned wrapped in the double quotes it had read it
  between, which is not absolute, so it took the relative branch and missed;
  once it passed the payload's display `name` instead. One matching pair of
  surrounding quotes — double, single or backtick — and surrounding whitespace
  now come off before the argument is resolved, and nothing else is rewritten:
  no unescaping, no globbing, no case folding, and the confinement question is
  asked of the result exactly as before. A quoted absence word is an absence. A
  payload's display `name` is accepted when it names exactly one file in this
  sample's carved tree, through the writer's own naming rule, and two payloads
  sharing a label are refused rather than chosen between. Every entry
  `carve_payloads` returns now carries a `carved_path` field holding the value
  to pass back, and the tool descriptions say so.
- **A failed tool call no longer asks for a parameter that does not exist.**
  The `no_such_file` and `path_outside_roots` remediations said to "pass the
  absolute sample path the prompt names" — a parameter the path pinning had
  taken out of the schema, so a live analyst was sent after a field it could
  not see on all six of its failures. Both now name a path a tool in this run
  handed back, and every `carved_path` failure carries that argument's own
  remediation, listing the file names this run did carve when the miss is
  inside the tree.
- **The conversation no longer shows a green tick for a failed tool call.**
  Whether a call succeeded is decided in one place — `build_entry`, which is
  the only thing that reads a *returned* structured error and turns it into a
  failure — and the recorder published its event from the `ok` it had been
  handed instead, which for a returned error is always true. Six live calls
  read "succeeded" beside an error payload while their ledger rows said they
  had failed. The event and its summary are now taken from the entry.
- **What is served is rendered from the final report.** The run summary's last
  fields — the validation block, which of the named techniques were published,
  the stage rollup and the run's elapsed time — were written after the report
  node had already rendered its markdown and taken the snapshot the worker
  stores, so a served report printed `24 claimed, 24 published` over four
  published techniques, carried no section naming the twenty it did not
  publish, and gave 311.7 s as a 396.3 s run's elapsed time. Both now happen
  after every field they read is final, and the stage rollup reaches the
  report's own summary as well as the state's column. Renderings are made on
  request from the stored report, so there is no second copy to go stale; a
  report stored before this keeps the figures it was stored with, and its
  run-summary column — what the console draws — was always the final one.
- **A late event continues its job's numbering whoever publishes it.** The
  per-job sequence counter lives 24 hours and the rows it numbers do not, so a
  task publishing for an older job — enrichment was the only one, and it
  carried its own seeding call — started again at 1, collided with that job's
  first stored event and lost the row to a feed that never fails a run. The
  seeding now happens in the publisher, once per job, before the first number
  it hands out for a job whose feed is being persisted; no call site has to
  remember it.
- **An endpoint label keeps its IPv6 brackets.** `http://[::1]:8080/v1` was
  named `http://::1:8080` in the submit gate's refusal and on the console — an
  address that cannot be typed back in and whose port cannot be told from its
  last group, so an operator could not find the failing pair. The label is now
  re-bracketed; it still carries no userinfo, path or query.
- **The model probe's five minutes covers the catalogue listing.** The budget
  was taken after the provider's model list came back, so the real wall was
  five minutes plus the listing per provider and the sentence naming untried
  pairs understated it. The deadline is now taken as the probe begins.
- **The Ollama probe's failure detail reads as two sentences.** It joined
  "answered nothing" to the remedy with no separator.
- **A carved-file answer names the file before anything a cut would take.** The
  analysis sidecar puts `read_path` first in every answer to a `carved_path`
  call. It was appended, so an answer wider than the caller's output guardrail
  lost it: one measured run's `strings` over a carved PE came back with 150
  rows, was cut at six thousand characters before anything recorded it, and
  stored no `read_path` while its shorter siblings each carried one.
- **The console reads the required environment names from the API.** The names
  a built-in sidecar is always started with were written down a second time in
  TypeScript with nothing pinning the two lists together, so a change on the
  Python side would have left the editor drawing the wrong names as fixed and
  silently restoring ones it had offered as removable. The server-map catalog
  entry now carries `required_env`, resolved from `REQUIRED_ENV_ALLOW` the way
  `choices` is resolved, and the console's copy is gone.

### Removed

- **The static analyst's case-prior hint and its settings.**
  `StaticAnalyst._compute_attck_case_hint`, `analysis.attck_case_rag` and the
  five `preprocessing.attck_case_*` settings; alembic revision
  `20260920000000` deletes the stored rows. `similar_cases` stays.
- **The in-process case-prior retrieval in the judge node.** The block that
  retrieved ATT&CK techniques from similar prior cases inside the judge node,
  the `attck_case_candidates` state channel and `FamilyAttribution` field, the
  advisory table in the report and on the console, and the row helper only it
  used. Prior cases remain reachable through the knowledge tool
  `similar_cases`, which an analyst calls and cites.
- **Import labelling in the extractor.** `pe_extractor.classify_import`, the
  hand-picked suspicious-import table, the ELF list, `ImportRow.is_suspicious`
  and `ImportRow.category`, the extractor-built capability counter, the
  Markdown "Suspicious Imports" table, the narrative prompt's suspicious-import
  list and the console's "suspicious only" filter. A report written while the
  labels existed still loads: `ImportRow` and `FamilyAttribution` ignore the
  retired keys. Settings `preprocessing.use_api_behaviour_map` and
  `preprocessing.api_behaviour_map_path` go with them; the knowledge tool
  reads the catalogue directly.
- **The three-layer TTP cascade** (`analysis/ttp_cascade.py`). It weighted every
  claim by a table of per-layer constants and cross-layer multipliers nobody
  could derive from anything, handed the judge one number per technique, and the
  judge deferred to it. With it go `run_summary.cascade` and every cascade
  setting.
- **The ATT&CK autocorrect pass** (`ATTCKValidator.correct_isr_reports` and the
  `preprocessing.use_attck_autocorrect*` settings). It rewrote a claim's
  technique id in place against a TF-IDF index, so the report printed an id no
  analyst had produced, attributed to the analyst. The check runs in the
  analyst's own loop now.
- **The Layer-0 ISR producers.** `analysis/import_capability_layer.py`,
  `analysis/tool_artifact_layer.py`, the YARA/Sigma/LOLBin/DGA ISR builders and
  the judge node's inline rule scans. Every capability behind them is a tool an
  agent calls (`yara_scan`, `sigma_match`, `capa`, `api_capability`,
  `lolbin_lookup`); what a match means is the analyst's reading of it, not a
  claim minted at a fixed confidence behind the analyst's back. The
  `preprocessing.use_tool_artifacts` setting and its catalog go with them.
- **The severity arithmetic, the category classifier and the family veto.**
  `MalwareReportBuilder._severity_assessment` summed constants chosen in the
  builder into a score out of ten; `analysis/schema_pruner.py` and
  `analysis/semantic_category.py` guessed a malware category from analyst prose;
  `attribution._is_family_grounded` zeroed the confidence of any family no
  deterministic layer had already named. All three are the judge's answer now.
  `preprocessing.category_inference_backend` goes with them, and
  `MalwareReport.severity` is nullable.
- **`_reconcile_with_cascade`** from the judge post-processor, which added and
  removed attack-patterns to make the bundle match the cascade's technique set.

- **The report-only extractors.** `extractors/dynamic_extractor` and
  `extractors/persistence_extractor` are deleted, and so are
  `network_extractor.build_network_iocs` with its extraction helpers,
  `sample_identity.build_sample_identity`,
  `capa_yara.merge_static_evidence` and `pipeline/nodes._compact_static_summary`.
  Each re-read the sample or the sandbox report inside the report builder and
  reached its own conclusions, which is how a report could describe an import
  table no analyst had looked at. What they classified and scored is kept —
  format and platform detection, the packer and language signatures, the DGA
  scorer and the homograph check, the emittable-address rules — and is applied
  to what a run actually observed.
- **`MAX_OUTPUTS_PER_AGENT`.** The per-agent cap of 40 captured tool outputs is
  replaced by the byte budget above. `schemas/tool_evidence.CapturedToolOutput`
  remains for one release as a converter (`LedgerEntry.to_captured` /
  `from_captured`).
- **The format reject gate.** `app.arun` no longer refuses a sample whose magic
  bytes name a non-Windows, non-Linux executable, and
  `sample_identity.unsupported_os_reason`, its foreign-format tables and
  `core.exceptions.UnsupportedSampleError` are gone with it. Routing decides
  where a sample goes, never whether it goes anywhere.

- **The paper evaluation tree and its reproducibility gates.**
  `tests/evaluation/`, `scripts/paper/`, the CI evaluation-diff gate, the
  prompt byte-identity pins under `tests/fixtures/prompts/`, the revision
  prompt golden, the benchmark and `make paper` targets and the deprecated
  `mcp.ghidra` / `mcp.cape` compatibility view are gone from the working line.
  The published evaluation is preserved at the git tag `paper-2026-09`; see
  [docs/paper.md](docs/paper.md).
- **Tool-count limits on MCP servers.** The Ghidra tool-selection modes
  (`curated`, a fixed 20-tool allow-list; `dynamic`, a per-sample relevance cut
  capped at 40) and the `use_all_tools` override are gone, as are the radare2
  read-only allow-list and the 13-tool "essential" list for the CAPE MCP
  server. Every tool a server offers now reaches the model, minus whatever the
  operator unticks in that server's own tool list. Tool descriptions are no
  longer cut at 100 characters. A migration removes the two retired settings
  from stored server entries. Expect larger per-step prompts on a local model.
- **Legacy settings-name aliases.** The compatibility layer that translated old
  setting names into current ones is gone; the Alembic revision that renames
  operator data carries its own frozen table, as a migration should
  ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- **The one-shot `.env` import.** A new deployment starts on the catalog
  defaults and is configured from the console or from a JSON export; there is
  no automatic import of a previous `.env` deployment, and the marker table it
  needed has been dropped ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- **The legacy sandbox adapter.** The CLI path drives the sandbox provider
  interface directly instead of going through a compatibility shim
  ([#37](https://github.com/Root0ne/Maljan/pull/37)).
- **Two dependencies.** `fastmcp` left with the CAPE MCP wrapper script, and
  `networkx` left with the CFG orderer that was its only user
  ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- Dead code found by vulture, ruff and knip, and a duplicated structural
  `deepEqual` in the settings console, now one implementation
  ([#36](https://github.com/Root0ne/Maljan/pull/36)).
- Machine-local operator scripts (`llm_server.sh`, `night_guard.sh`,
  `run_with_restarts.sh`) and the retired annotation seeder left `scripts/`;
  what remains is what the Makefile, CI and the tests call.
- Process tags in source comments — dated audit identifiers, ticket numbers and
  phase labels. The reasoning stays, the bookkeeping goes
  ([#38](https://github.com/Root0ne/Maljan/pull/38)).

### Upgrading

An existing `.env` deployment is not migrated automatically. Move the bootstrap
variables into the process environment (or `docker/.env` and `bootstrap.env`),
start the stack, and enter the remaining settings once in Settings →
Configuration — or import a JSON export from another instance. Keep
`SETTINGS_ENCRYPTION_KEY` stable: there is no re-encryption step, and a changed
key makes every stored secret unreadable. See
[docs/configuration.md](docs/configuration.md).

A JSON export taken before the tool-selection modes were removed may carry
`core.static.ghidra.tool_selection`, `core.static.r2.tool_selection` or the
`use_all_tools` counterparts; the import refuses keys the catalog no longer
knows, so delete those entries from the file first. Stored overrides are
cleaned up by the migration.

The same applies to an export carrying the judgement-layer settings —
`core.preprocessing.use_attck_autocorrect` and its thresholds,
`core.preprocessing.use_tool_artifacts`, `core.preprocessing.tool_artifacts_path`
and `core.preprocessing.category_inference_backend`. `core.analysis.sigma_rules_dir`
is not dropped but moved: it becomes `MALJAN_SIGMA_RULES_DIR` in the `analysis`
tool server's `env`, and the migration moves a stored value across for you.
