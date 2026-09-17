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
  caps hit); the console's pipeline panel names the cap beside the step.
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

### Fixed

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

### Changed

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

### Changed

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

### Fixed

- **No fragment of the LangSmith API key is logged.** Enabling tracing logged
  the key's last four characters; it now records only that tracing is on and
  which project it writes to.
- **The Ghidra connection test proves the token.** The probe read the
  unauthenticated health endpoint, so a wrong bearer token passed the test and
  every job then failed with 401 on the tool schema. It now fetches the schema
  itself and lists the tools it found.

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
