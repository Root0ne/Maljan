# Changelog

Notable changes to Maljan. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); dates are the day a
change landed on `main`.

## Unreleased

### Added

- **Every analyst claim in force reaches the report: cited, named, or
  listed.** Each composer section and, new, the narrative round show every
  claim in force under its label (`static claim 15`: the analyst and the
  claim's number in its answer in force); the narrative round is handed every
  claim whole. After the body is composed, `reporting.claim_coverage` lists
  every claim not cited by its label whose code locations (function names) or
  API-style names the body does not all name, with the names it lacks (a
  claim naming none is read by its words). It is stored
  (`MalwareReport.claims_not_discussed`), counted
  (`run_summary.claims_not_discussed`) and printed under §13.1 "Claims whose
  code locations or API names the body does not name".
- **An encoded string is joined to the call its bytes go to, and that call's
  output to its consumer.** `decode_string_blobs` states `passed_to` beside a
  reference: the call the address of the encoded bytes is passed to (usually
  the program's decoder) with its callee (an import, a function address, or
  the slot a runtime pointer is read from) and argument position, read
  statically by `tools.call_sites` from an x64 `lea` into an argument register
  or an x86 push or stack store; and on x64 `output_passed_to`, the next call
  in the function that receives the frame slot that call was given as another
  argument, else its return value, said as a fact about the slot or the
  register, with nothing followed past it. Absent wherever the code does not
  show it. The triage pack's decoded-string line and the IOC
  provenance say both.
  `pe_image` reads the import table.

- **The platform resolves API hashes and decodes encoded strings, by address.**
  Two analysis-server tools, run by the triage pack on every PE as its last two
  steps and shown in the pack every agent reads. `resolve_api_hashes` names the
  32-bit values a PE holds that are hashes of Windows function names: the
  named exports of 27 common DLLs are vendored
  (`data/windows_export_names_v1.json`, generated from the Wine project's DLL
  spec files by `scripts/knowledge/build_windows_export_names.py`, which
  records the tag and each spec's sha256), and the algorithms are data
  (`data/api_hash_algorithms_v1.json`: CRC-32 of the ASCII and UTF-16LE name,
  ror13 with and without the module-name addition, djb2, FNV-1a, case-folded
  variants), over function names and a module-name set (each DLL's file name
  with and without `.dll`, lower and upper case); each reading names its set.
  Values the caller gives, or the push/mov/cmp immediates in code
  and the aligned values in data; every reading of a value and every place it
  stands, with the start of the function the x64 function table puts around
  it; a value whose algorithm resolves nothing else is a `lone_hits` row.
  `decode_string_blobs` undoes one key byte, a rising key byte, a repeating
  key stored in front of the text, a seed-and-length header before a rising
  key and base64 on top or alone, over the non-executable sections; only text
  passing a stated readability test is reported, and the results are the
  decodings some code refers to by address or FLOSS recovered too, each with
  the function around each reference. The reverser is told to name the
  function and the text in its findings. Nothing is run or emulated.

- **The operator sets how long the Triage VM runs the sample.**
  `sandbox.triage.analysis_seconds` (empty by default: nothing is sent and
  Triage's own default applies) is sent as the submission's
  `defaults.timeout`. Settings validation refuses a
  `sandbox.triage.timeout_seconds` that does not outlast it. A refusal is
  reported in Triage's own words and names the setting. The run-time limit
  Triage set for its behavioural tasks is `SandboxReport.run_limit_seconds`, and the
  run summary states it as the run-time limit Triage set for the task
  (`run_summary.sandbox_run_limit`, **Sandbox run-time limit**): a limit, not a
  measured duration. `timeout_seconds` must also cover Triage's processing; no
  margin for it is guessed.
- **Prices carry their time windows.** A `llm.model_prices` row (and a
  vendored `prices` row) may carry `windows`: spans of the day in UTC, on
  named weekdays, with their own prices and source. The vendored DeepSeek rows
  now carry DeepSeek's documented peak hours (01:00-04:00 and 06:00-10:00 UTC,
  Monday to Friday) over its off-peak rate, and the legacy name
  `deepseek-v4-flash` the page still accepts is priced as `deepseek-flash`.

- **The worker states the Ghidra samples path it uses.** One line at start,
  `Ghidra samples path: <path> (<source>)`, with the source either
  `GHIDRA_CONTAINER_SAMPLES_PATH` or the default.
  [configuration.md](docs/configuration.md) and
  [deployment.md](docs/deployment.md) say that the variable is the path INSIDE
  the Ghidra container (`/data/samples` with the shipped Compose file) and name
  the common mistake, the host directory.
- **An all-tools team to import.** `docs/examples/profiles/all-tools.json` is a
  settings import document: the triage pack and triage; one static stage of
  three analysts on three tools (`static` on the sidecars, `all_tools_static_r2` on
  radare2 with the analysis and knowledge servers, `all_tools_qu1cksc0pe` on the
  `qu1cksc0pe` server); `all_tools_reverser_ghidra`, the seeded reverser prompt on
  Ghidra; detonation, network, debate, verdict and report. A test validates it
  as the import endpoint does and resolves every agent against stub servers
  and a stub Ghidra. [configuration.md](docs/configuration.md) says how to
  merge it into an export before importing.
- **A team that needs Ghidra waits for it.** `POST /jobs` answers 422, before
  the job exists, when a static provider that does not degrade (Ghidra) is not
  ready for an agent of the chosen team: its schema endpoint with the
  configured token did not answer below 400, or it is switched off for an
  agent that names it. The refusal names the agent, the provider and its
  address as scheme and host. The shipped default (Ghidra switched off as the
  global provider) is not refused.
- **capa says where a rule matched.** capa's rows carry `addresses`, offsets
  from the image base capa analysed at, and the pack's capa line names them
  beside each rule.
- **The Ghidra container's JVM options, memory limit and restart policy are
  variables:** `GHIDRA_JAVA_OPTS`, `GHIDRA_MEM_LIMIT` (memory and swap) and
  `GHIDRA_RESTART`, defaulting to `-Xmx4g -XX:+UseG1GC`, `6g` and
  `unless-stopped`.
- **An operator's spend ceiling.** `llm.max_spend_usd_per_job` (no default:
  none) and `llm.model_prices` (empty) price every recorded call from its
  provider-reported cached input, input and output tokens at the answering
  model's prices; the vendored model table carries DeepSeek's documented peak
  prices for `deepseek-flash` and `deepseek-v4-pro`, with their page, as data.
  At the ceiling every running tool loop ends its tool phase and its agent
  writes its answer from what it gathered; a loop that starts afterwards
  answers once without tools, an ask is refused, and the verdict and the
  report still run. A degradation reason says so, `run_summary.spend` carries
  the ceiling, the spend, whether it was reached and where each price came
  from, and the budget meter's cap is `spend`. A model with no price is named
  once in the log and in `run_summary.spend.unpriced_models`, and its calls
  are not counted.
- **The judge decides the techniques its bundle does not carry.** After the
  verdict the judge is asked once, in one tool-free question sized like the
  verdict call, about each technique an analyst claimed that its bundle
  carries on no attack-pattern and no edge, and each one named only on a
  finding, with the claim or finding text and its evidence ids: keep or drop,
  with a reason. The question shows what it asks the judge to decide from:
  the analysts' reports as the verdict call sees them, the verdict and the
  techniques its bundle carries, and the text of every evidence entry a claim
  or finding in question cites — shortened to the judge's window, when it does
  not fit, with a notice in the question and on the record. The answer is asked
  for as a JSON array (read from the schema where the provider has structured
  output, from a function call's arguments, or asked once in text when a
  provider refuses the schema) and read tolerantly otherwise: table rows, a
  technique name after the id, arrows and a "Decision:" label; a `<think>`
  block is taken out first and the last answer per id wins. The decision is
  read from its position — a JSON `decision` of one whole word, or the word
  straight after the id's separator, else the last standalone keep or drop —
  never from a word inside the reason, and a slash-written sub-technique is
  the same id. Each cited entry is shown as stored, with its tool, marked
  when the run holds only part of it or only its lower-cased search copy. The answer is kept on the judge's bundle
  (`x_maljan_technique_review`) and the capability matrix publishes per it. A
  dropped technique reads "not published: the judge dropped it (<reason>)"; a
  kept one is published, a finding's technique included, with the judge's
  reason on its row. With no answer nothing is withheld: each technique is
  what it was before, and a published one is marked "not confirmed by the
  judge". An id the catalogue rejects or the sample cannot host is not asked
  about and is recorded as "not asked: <reason>".
- **A call that reports no usage is named.** The token ledger records the
  agent, the call and the model of every call whose provider reported no
  usage; `run_summary.tokens.unreported` carries the rows beside
  `unreported_calls`, and the token sentence names them.
- **DeepSeek's declared maximum output.** `deepseek-flash` and
  `deepseek-v4-pro` have `max_output` rows of 393,216 (384K on
  https://api-docs.deepseek.com/quick_start/pricing) in the vendored table.
- **`llm.openai.reasoning_effort`**: sent as the request's `reasoning_effort`
  field, exactly as written, so each API's own levels work (DeepSeek: `low`,
  `high`, `max`). Empty, the shipped value, sends nothing. The `llm` connection
  test asks with it.
- **`llm.openai.compat: deepseek`**: DeepSeek's API ignores
  `max_completion_tokens`, the only cap field OpenAI's clients send (measured:
  a cap of 5 came back as 88 and 138 tokens), so no output cap reached it. The
  dialect sends the cap as `max_tokens` as well, which DeepSeek honours with
  reasoning counted, and `disable_thinking` as DeepSeek's `thinking.type`. It is
  explicit rather than read from the host, because OpenAI's own API refuses
  `max_tokens` beside `max_completion_tokens` for its reasoning models.
  It also keeps each assistant turn's `reasoning_content` exactly as DeepSeek
  returned it and sends it back on that turn in every later request that
  carries tools, which DeepSeek's thinking-mode guide requires (400 otherwise)
  and which the OpenAI client does in neither direction; the window budget
  counts it. A cap bound for one call reaches DeepSeek too. `compat` is global,
  per-agent `openai` entries included.
- **Cached input and reasoning tokens are recorded where reported.**
  `run_summary.tokens` (and each agent's row) carries `cached_input_tokens` and
  `reasoning_tokens`, each with the calls that reported it, from the client's
  usage details or DeepSeek's `prompt_cache_hit_tokens`; the token sentence
  names them. Absent where no call reported them.
- **An analyst answer cut at its output cap is asked for a whole shorter one**
  (`isr.cut_at_output_cap`), as the judge's and a report section's are: the
  question states the cap, the characters the answer ran to, the CLAIM blocks
  it began and the length it was cut at as the bound to stay under. The cut
  answer is described rather than sent back, the question is asked only when
  it and an answer of the cap's size fit the model's window, and a whole answer
  that comes back is kept even with fewer claims. The cap is unchanged. A
  reference static analyst's 42 claims ended at exactly its 4,096 tokens; its
  retry spent the cap again, returned no claim, and fourteen questions went
  unanswered.
- **A technique only the judge named says why it is published.** Its ATT&CK
  row carries "stated by the judge and claimed by no analyst; a technique the
  judge states is published as its own claim" — the rule it is published by.

- **A claim whose sentence does not describe its technique is asked about.**
  A claim carrying a technique id whose sentence shares no term with that
  technique — no capability term listing the id, no word of its catalogue
  name (compared with common endings off, so "obfuscation" shares a term with
  "Obfuscated Files or Information"), no tactic as a category phrase — is
  asked once (`attck.claim_does_not_describe`) to keep the technique only if
  the sample does it. The analyst's answer stands and a kept id is published
  as stated. An absence claim and a platform mismatch are asked their own
  question instead. A reference run had published OS Credential Dumping on
  "accesses the PEB … to bypass sandboxing" and Valid Accounts on "a
  Trojan/Backdoor that performs system reconnaissance".

- **A claim that reads as absence is asked about its technique id.** A claim
  carrying a technique id is asked once (`attck.absence_claim`) whether the
  behaviour is absent (`TECHNIQUE: NONE`) or the sample does it when every
  place it names the technique's behaviour — a capability term listing the
  id, the catalogue name, or a tactic name followed by a word such as
  "mechanisms" — is read as absence: a negation cue in the same clause with no
  comma or coordinator ("and", "instead", "only", "but") between them and not
  one that opens an assertion ("no longer", "not merely", "never stops"); an
  item of a noun list such a cue negates, the list ending at its head noun
  ("does not contain persistence, lateral movement, or exfiltration
  mechanisms"); or the subject of "is absent", "is not present" or "was not
  observed". A text that never names the behaviour is not asked. The claim and
  its id are never edited, and the platform never withholds a technique the
  analyst keeps: it is published with a note ("the claim naming it reads as
  absence; the analyst kept the technique when asked") in the ATT&CK table and
  the judge's summary. The capability check also reads "is not present" and
  "was not observed" after the term as absence.
- **A section answer with alike rows is asked once whether they are repeats**
  (`composer.repeated_items`), compared on the fields that tell items apart,
  and kept as written if it stands; it is never told to remove a row. The
  cut-at-cap question now says, per text field, how many of the items begun at
  least repeat a value. A host-identifier answer had begun 161 items of which
  at most 19 differed.
- **Two capability terms**: anti-analysis and anti-forensics, read by the
  report's capability check and by the absence reader.

- **A report sentence the checks left standing is marked where it stands.** A
  sentence the capability check or the rule-match check asked about, and the
  retry kept, is recorded on the report (`flagged_statements`) and the
  Markdown and HTML reports print a mark after it; its words are unchanged.
  One run printed fifteen flagged sentences with nothing on them.
- **A technique only a rule match stands behind is not written as an
  action.** Every section's and the summary's list of published techniques
  carries its rule-match-only note; a sentence naming one as something the
  sample does is asked about once (`report.rule_match_as_action`). A report
  had written "The sample dumps credentials from the target system" for a
  one-string YARA match.

- **The report model states the host identifiers it read.** The report
  contract gains a composer section, `host_identifiers`
  (`HostIdentifier{kind, value, purpose, evidence_refs}` on
  `technical_analysis`): what a responder can search a host for, each value as
  the entry the model read it in records it, with the entry cited. The model
  decides what goes in; the platform copies no string in. An identifier citing
  no entry of the run is asked about once (`report.identifier_uncited`). The
  Markdown prints the rows in §9 under the report model's voice, unpublished;
  the console draws them in the technical-analysis panel. A benchmark report
  had printed nine such items only as raw rows of its decoded-strings dump.
- **A value cited to the wrong entry is asked about.** A value a report
  sentence states verbatim — in quotes or backticks, or a record's `value` or
  `endpoints` — is looked for in the entries the sentence cites, as the run
  holds them (`validation.EntryTexts`). Held only by another entry, the report
  model is asked once with that entry named (`report.citation_wrong_entry`);
  held by none, nothing is said. The id is never rewritten. A benchmark report
  cited the reputation lookup for strings only the decoded-strings entry held,
  in four sections.
- **A technique written with another technique's name is asked about**
  (`report.technique_name`), from the vendored ATT&CK table, with the
  catalogue's name and the id the written name belongs to.

- **What changed between two runs.** `GET /api/v1/reports/diff?a=&b=`
  (`by=job` for job ids) compares two stored analyses section by section:
  verdict, confidence, severity and family with who stated each; ATT&CK
  techniques published; indicators by kind and value; key findings, analyst
  findings, persistence, configuration, commands, C2 channels and the
  capability profile; YARA, Sigma and capa rule matches; STIX objects by type
  and an identifying property rather than by id; and run facts — profile,
  models, token figures, wall time, tools called, degradation reasons. Each
  section names the key its rows are paired by, and a row the record does not
  key stably is listed as present in one run, never paired by guess, and rows
  under one key pair as a multiset, so a run compared with itself shows no
  difference. Rows cite each run's evidence-ledger ids where the record holds
  them in an id field, and never an id read out of prose. It is read only from the two
  stored records, says whether the SHA-256 is the same, and answers 404 unless
  the caller may read both runs. The console's analysis header gains "Compare
  with another run", which offers the same sample's runs first and then any
  run, and a printable compare page. `GET /jobs` takes `sample_id`. The one
  implementation is `maljan.reporting.run_diff.diff_runs`.

- **A team is checked before it is saved, and shown as the graph it is.** The
  rules the settings model applies to a team are now problem lists
  (`stage_list_problems`, `stage_member_problems`, `stage_condition_problem`,
  `builtin_profile_changed` in `maljan.core.config`): the model raises the
  first, and the new team lint (`maljan.core.team_lint`) reports all of them,
  each on the stage it concerns, adding a named cycle and warnings that never
  block apply — a stage the verdict does not wait for or that runs after it, a
  condition false for every sample, a condition reading a stage the team lacks
  or has not run yet, an enabled agent nothing uses. The apply path refuses
  from the lint, so the preview and apply say the same sentences, and a test
  holds every model refusal to a lint error word for word.
  `POST /api/v1/settings/lint-teams` (admin) serves the findings and each
  team's layout; the team editor calls it as a team is edited and draws the
  stage graph beside it, findings marked on the stage and listed in words.
  The layout is `maljan.core.team_layout`, which the architecture-page team
  diagrams now use too; the triage pack's adoption of a root stage is one rule,
  `pipeline.topology.adopted_roots`, read by the builder and the layout.
  A team has no size limit, so every pass over one is linear in its stages
  and edges and none recurses: loops are found by an iterative Tarjan pass,
  rows by Kahn's method, and the model's debate checks in one pass each. The
  lint route and the agent-map half of `PATCH /settings` run in a worker
  thread. A `when` nested too deeply for Python's parser is refused as a
  condition error instead of escaping as a server error.
- **Changed:** apply's team refusals now carry the settings model's own
  sentences — a member error and a condition error name their stage (and a
  member error its team), a debate's hand-over error and the verdict-judge
  error are the model's wording — and a stage's field error is keyed by the
  stage key rather than its position, like every other stage error. A loop
  is written out once, as a real dependency path, on its first-declared
  stage; every other stage on it points to that stage.
- **The STIX bundle as a relationship graph.** DETECTION's STIX section gains
  Graph and Table views beside the JSON, all three reading the bundle the
  `/reports/{id}/stix` export serves. Nodes are the bundle's objects, an
  unrelated one included; edges are its `relationship` and `sighting` objects
  labelled with their own type, with a confidence only where the bundle
  states one. Containers no relationship names and relationships to objects
  the bundle does not hold are listed in the table with the reason rather
  than drawn. Flat colour by STIX type from the console tokens, keyboard
  focusable nodes, a table under the graph for screen readers, the object's
  JSON and its evidence-ledger ids on selection, SVG and PNG export. A bundle
  above 300 objects opens on the table. No new dependency: the layout is a
  small deterministic force layout in `components/analysis/stixGraph.ts`.

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
  stored override onto the definition it belongs to — only a value the field
  accepts, so a `0` or a negative left in an old override map stays there and
  is named in the migration's log rather than making every later settings read
  raise — and the save review names a budget edit like any other field. A
  stored budget the field would refuse is read as absent, with the reason
  logged, so one agent's number cannot take a deployment down.
- **A JWT rotation's grace period can be given a written end.**
  `JWT_PREVIOUS_SECRET_NOT_AFTER` is optional; when it is set it is enforced,
  and past that moment a token signed with the previous secret is refused.
  `GET /api/v1/system/status` reports the rotation to an admin caller under
  `jwt_grace_secret` (the previous `kid`, when it lapses, whether it is still
  accepted, and whether an end was written down at all), and the API says the
  same at every start. A grace secret with no end is accepted as before and
  warned about at every start; one whose window has run out is warned about
  until both settings are cleared. `docs/deployment.md` has the three-step
  runbook. Nothing rotates on its own.
- **Per-tool-call timing, per agent.** The run summary carries `tool_latency`
  — for each agent how many tool calls it made, what they cost together, and
  the single slowest with the tool that answered it, computed from the clock
  each ledger entry already carried — and the summary's header draws a **Tool
  calls** line beside **Per stage**. The analyst-latency log line names that
  slowest call, so a run that overran says whether the model was slow or a
  tool was.
- **A technique's name, tactics, domain and platforms are a file read.**
  `data/attck_techniques.json` ships beside the id catalogue, written from the
  same three bundles by
  `scripts/knowledge/prepare_attck_malware_fixtures.py`: per active technique
  id its domain, its name, its tactic slugs and its MITRE platforms, plus the
  tactic catalogue per domain. `tools.knowledge.attck_lookup`,
  `attck_validate`, `attck_scope` and the capability matrix's name and tactic
  resolution all answer from it and build nothing; only `resolve_technique` and
  the alignment gate, which rank, still load the STIX bundles. A cold worker
  and a cold CI runner no longer fetch fifty-eight megabytes to answer a
  dictionary question, and `tests/unit` needs no network at all. Mobile and ICS
  rows carry their tactics, which the enterprise-only kill-chain filter had
  always dropped.
  `data/attck_retired_ids.json` gains `revoked_by` per row where the bundle
  names a successor, which is what lets a data builder retarget a retired id
  mechanically.
- **An ELF's symbols have a behaviour catalogue.**
  `data/api_behaviour_map_v1.json` gains a `linux` block of nine groups over
  182 libc, syscall, OpenSSL and libcurl names, and `data/api_attck_map_v1.json`
  two Linux technique rules, each naming an id the vendored table declares
  for Linux. Every tier and every rule was measured against the 1911 ELF
  binaries with a dynamic symbol table on the machine it was written on, with
  `scripts/knowledge/measure_api_behaviour_block.py`, which ships so the
  measurement can be repeated: eight of the nine groups are informational
  associations carrying `corroborated_by`, the ninth is labelled only when a
  second name says the sample reaches into another process (`flags_with`, a new
  key the Windows block does not use), and the worst technique rule appears on
  0.16% of those binaries. Each Linux rule carries `ordinary_use`, one sentence
  naming the software that is not a sample and imports the same symbols. The vocabulary is
  deliberately narrower than the Windows one: `registry` has no counterpart,
  and `persistence`, `keylogging`, `screen_capture`, `credential` and `evasion`
  are absent because their honest Linux evidence is a path or an X11 call
  rather than a symbol name. The catalogue is asked one platform at a time —
  `tools.knowledge.api_capability` and the knowledge sidecar's tool take
  `platform`, and the triage pack passes the routed format's — so a name in
  both blocks (`connect`, `send`, `system`) is answered about the system the
  sample actually runs on, and a format with no block (Mach-O, an APK) is not
  asked at all rather than asked about Win32.
  **Upgrading:** a caller of `api_capability`, `load_api_behaviour_db` or
  `load_api_attck_map` that wants ELF answers must pass `platform="linux"`;
  the default stays Windows, so nothing that exists changes. A technique rule
  now carries `rule` beside `name`, and `name` is the ATT&CK name for the id:
  the two `T1685` rules no longer print a name the catalogue does not use.
- **The API capability builder regenerates its own data file.** Its curated
  source still named two ids ATT&CK 19.2 retired, and its own check refused
  them, so `data/api_attck_map_v1.json` had no working generator. A retired id
  is now followed to the id the vendored set's `revoked_by` names, or dropped
  and listed when it names none, and two rules may share an id where a release
  folded two sub-techniques into one. `make prepare-api-db` reproduces both
  shipped data files byte for byte.
- **A failed ATT&CK index build is retried.** It is remembered with the moment
  it happened and re-attempted after `validation.index_retry_seconds` (default
  900; 0 never re-attempts, which is the previous behaviour). One unreachable
  moment used to leave every later job in that worker without the index, with
  nothing saying why. Concurrent lookups still start one build, not a storm.
  The value reaches the knowledge sidecar — the process where the build
  actually happens — as `MALJAN_INDEX_RETRY_SECONDS`, which that server is
  allowed to read and applies once at start-up.
- **The served context window, learned for free and shown where it matters.**
  `GET /api/v1/settings/context-window` answers with the window the configured
  models serve, the four-word source it was learned from (`declared`, `probed`,
  `table`, `fallback`), the sentence behind that word, the characters-per-token
  figure, the tokens held back for a reply and the cap one tool answer would
  get on an empty conversation. It spends no tokens: behind it are the metadata
  endpoints in `maljan.llm.context_window`, cached per provider, endpoint and
  model, and an endpoint that says nothing falls to the vendored table and then
  to the stated fallback rather than to an error. The Settings page prints it
  beside `core.preprocessing.max_tool_output_chars`, with the source word
  itself, and says which setting would fix an unknown window.
- **A documentation site, built from the same pages `docs/` already carries.**
  `mkdocs.yml` at the repository root builds them with MkDocs Material — light
  and dark palettes, built-in search, edit links against `dev` — with no page
  written twice. `.github/workflows/docs.yml` builds it on a pull request that
  touches `docs/**` or `mkdocs.yml` and deploys it to GitHub Pages on a push to
  `main`; a `docs` dependency group keeps MkDocs Material out of the product's
  own dependencies.
- **The dashboard answers at a glance.** Each of the latest runs carries its
  verdict as a chip, in the shared verdict colours and in words; a run with no
  verdict yet shows its status. A "Tools used" list draws the tools the
  caller's last 20 completed runs called as flat bars with the counts printed,
  from the new authenticated `GET /api/v1/dashboard/tools?limit=` (default 20,
  at most 100), which sums each run's `run_summary.evidence.by_tool`. Its
  `runs` counts only the runs whose report carries that per-tool record, and
  `read` every completed run it looked at, so a report older than the record
  is said on the dashboard rather than counted as a run that called nothing.
- **Copy a row's SHA-256 and job id.** Every row of the analyses list copies
  its sample's SHA-256 and its job id in one press each, with the confirmation
  announced to a screen reader. The IDENTITY hash rows and the DETECTION rule
  cards use the same control and now announce it too.
- **Time per stage on the Summary.** Each stage that took time is listed with
  its duration and a bar against the run's total elapsed, from the same rows
  and formatter as the header's stage strip.
- **A per-tool table for a tool server.** Settings → tool servers draws a
  tested server's tools as a table with a search, "Select all" / "Select none"
  over the rows shown, a live "enabled N of M" and, where the capability
  manifest marks a tool unavailable, its reason and remedy on its own row. It
  edits the existing per-server tick list; there is no new setting.

- **An agent may name models to fall back to, tried only when a provider
  fails.** `llm.agents.<key>.fallbacks` is an ordered list of models, each
  written like the entry's first one (provider, model, optional temperature and
  — for `openai` and `ollama` — base URL). The next model answers a turn only
  when the one before failed as a provider: a refused or dropped connection, a
  timeout, HTTP 5xx, 408 or 429, a model the server does not have, a refused
  credential, or a refusal the provider reports as an error. An answer the
  validation loop rejects is still sent back to the model that wrote it, and a
  guard case in `tests/unit/test_no_silent_overrides.py` proves it is never
  asked of another model. Every turn records which model gave it: the ledger
  entry of each call it asked for carries `model` (revision `20260928000000`),
  `agent_message_delta` carries `model` and `tokens`, a new `model_fallback`
  event names the switch with its reason in words (whether or not deltas
  stream), and `run_summary.models` counts turns per agent and model with every
  fallback's reason. Each fallback passes the probe gate the first model does — the
  `agent` probe asks every model on the list, the `llm` probe the ones its
  provider serves, and the gate names a missing one as the model the agent
  *falls back to* — and the context-window budget counts every model on every
  list, the smallest window governing. The Agents page edits the list (add,
  remove, move up and down).
- **What a run spent, in tokens.** `run_summary.tokens` sums the usage every
  provider reported — prompt and completion tokens, and the cost an
  OpenAI-compatible router reports where it reports one — for the run and per
  agent (`per_agent`), counts the calls whose provider reported nothing as
  `unreported_calls`, and carries the `sentence` the report prints. The
  report's run summary and the console's "What the run spent" gain that
  tokens line. There is no price table.
- **A tool server that keeps failing is rested, and says so.** Per job and per
  server, `core.mcp.breaker.failures_to_open` (3) transport failures in a row —
  a timeout, a refused connection, the server's process gone — rest the server
  for `core.mcp.breaker.cooldown_seconds` (60). A call made while it rests is
  answered by the platform with a structured tool error (`server_resting`)
  naming the server, that it is resting and when it will be tried again; after
  the cooldown one call is let through and a success ends the rest. A tool
  that answers with its own error never counts.
  `core.mcp.breaker.max_concurrent_calls` (4) caps how many calls one server
  has in flight for one job. Each rest is published as `tool_server_rested`,
  drawn in the conversation, and kept in `run_summary.server_rests`, which the
  report and the console print. Every default's origin is written beside it
  in `docs/configuration.md`; all three are judgements, because no recorded
  live run had a tool server fail at the transport.
- **An emulating string decoder on the analysis server.** `floss` recovers the
  decoded, stack and tight strings of a PE by emulating the sample's own
  decoding and string-building functions under vivisect (FLOSS, FLARE's pinned
  standalone build run as a child process with a 600 s ceiling and a 4 GiB
  address-space limit; the sample is never executed). Each row names
  the function that decoded or built the string, as a virtual address and
  relative to the image base, and a decoded string its call site. The answer is
  paged like `strings`, with `kinds` and `pattern` filters, and only the first
  call on a file emulates. On an encrypted-string loader it recovered 81
  strings in 38 s — the mutex name, the install directory and file names, the
  scheduled-task name, both C2 URLs, the User-Agent, the beacon format and the
  command words that a plain `strings` pass cannot see.
- **The tool-definition size is on the record.** The context budget counted
  every tool definition with every request and never wrote the figure down,
  so a run whose answer cap shrank could not show how much of that was the
  definitions. Each loop's budget record, every `budget_tick` and each agent's
  `run_summary.budget` row now carry `tool_definition_chars` (the largest of an
  agent's loops in the summary), for the analysts and the judge alike.

- **Key findings, an execution flow, a configuration table and a command
  table, written by the report model.** The narrative round answers two to
  six key findings, each with the ledger entries it cites; the composer writes
  the execution flow (each step marked *observed* or *assessed*), the
  configuration it recovered with how each value was obtained, the commands
  the sample accepts, prose for API and string resolution, command and control
  and payloads, and C2 channels with their endpoints. Each is asked for as the
  exact JSON object with an example and printed as written. New validation
  codes, fed back once and recorded when they survive: `narrative.ungrounded_finding`,
  `report.flow_voice`, `report.configuration_uncited`.
- **`reporting.defang`.** `defang(value, kind)` writes network indicators the
  way analysts exchange them (`hxxps://`, `[.]`, `[:]`, `[@]`) and leaves every
  other kind unchanged; `ProseDefanger` applies it to exactly the run's own
  indicators inside prose.
- **`pe_info` reports export ordinals and addresses, the export directory's
  name and the version resource's naming strings** (`export_rows`,
  `export_name`, `version_info`). The report's identity gains `architecture`,
  `is_dll`, `export_name` and `internal_name`, and the compile timestamp is
  read from the header.

### Changed

- **Analysts run in parallel on a hosted API and one after another on a
  single-slot local server, decided per job.** `llm.parallel_analysts` is now
  `auto` (the default), `true` or `false`. `auto` resolves each analyst
  model's endpoint on a thread before the job is built: Ollama, and an
  OpenAI-compatible host that is a loopback, private, link-local or
  shared-range address (written or resolved) or a name only a local resolver
  answers (`host.docker.internal` and its kin), runs them one after another
  unless its llama.cpp `/props` reports more than one slot; a host that
  resolves only to public addresses runs them in parallel; a host that does
  not resolve runs them one after another, saying it could not be told
  whether it is hosted. One such model makes the whole job sequential. The
  mode, the fact that decided it, and what every analysis stage and every
  revision round ran in (set on the stage, the job's, one node for a debate
  handover, or the stages a revision revises) are logged and in
  `run_summary.profile.analyst_mode`. A stage's own `mode` wins;
  `StageDefinition.mode` is unset by default and an unset analysis stage
  follows the job. A revision round follows the stages it revises. The
  console's run-mode selector has an `auto` choice. In a 2.00 USD DeepSeek
  run every stage ran its agents one after another although the API serves
  requests concurrently.
- **The reserve for the verdict and the report is the tail's real size, retries
  included.** Each planned call is kept at what its admission demands, at the
  prompt it will be sent (the largest of its kind, else the largest
  single-shot prompt, else a conversation's opening prompt, bounded by the
  window allowance, which alone is used only before any prompt was sent) and
  at the answer this job measured (the verdict's largest single-shot answer;
  a report call's mean report or other single-shot answer, which is also the
  smallest answer its admission demands). Each also keeps its validation
  retries: one per planned call until a call of its kind is made, then
  `(retries + 1) / (calls + 1)` of this job's own count; a retry is planned
  with the answer it corrects in its prompt. Each row of
  `run_summary.spend.reserve` adds `retries`, `retries_from`,
  `retry_prompt_tokens` and `expected_usd`, its charge at the measured
  cache-hit share. A 2.00 USD DeepSeek run kept 0.90 USD for a tail of 27
  calls costing about 0.42; the same shape now keeps about 0.72 at the
  revision round, and all 27 calls are made on it.
- **The reverser reaches every branch of a dispatcher it finds.** The seeded
  reverser prompt, and the example team's reverser, ask of a switch or a table
  over command or message ids that each branch's handler be decompiled or
  listed as not reached with the reason, one line per id with the handler's
  address.
- **The spend ceiling counts what a call was charged and is a hard bound**
  against the platform's prompt estimate (characters over three). A call is
  settled at the cost its provider reported with the answer, else at the rates
  in force when its request was sent (every model client stamps the send time
  on its answers), and is reserved at the highest rate in force before its
  deadline. Every model call is admitted first: tool-loop turns, revisions,
  the mediator's fast path and extraction, the judge's salvage, the verdict,
  report sections, the narrative and the function summariser. Before a call its
  output cap is held to what the spend it may use pays for; it is refused only
  when that is below the smallest answer it can give (the largest of its group
  this job has measured of the model: tool-loop turns for a loop turn,
  single-shot and verdict/report answers otherwise; its configured cap until
  one is measured). A model that takes no per-call output cap is admitted only
  at its whole cap. `MIN_ANSWER_TOKENS` and its 8,192-token overshoot are gone.
  Calls in flight reserve their worst case until their cost is on the ledger,
  and a loop's turn keeps room for its closing answer. The verdict and report
  calls are planned at the start of the job with their window allowance and
  output cap; the reserve keeps the verdict at what its admission demands, the
  first report call uncached and the report calls after it at the job's
  cache-hit share, measured only over calls that are not the first of their
  conversation (the cached rate until one is), (`run_summary.spend.reserve`),
  and a planned call spends only above the share of the ones after it. A call
  is priced over its own request deadline.
  `run_summary.spend.prices_from` lists every rate a model's calls were priced
  at.
- **Under a spend ceiling the composer and the narrative round use the manual
  path.** The structured-output path takes no per-call cap, so its calls could
  not be held to what the spend pays for; with a ceiling set every section and
  the narrative go by the manual JSON path, where the held cap is sent with the
  call. Without a ceiling nothing changes.
- **A report call's log line names the limit that set its cap**: the section's
  output budget, what the window leaves after the prompt, or the spend
  ceiling's hold. It used to name the window whatever set it.

- **The reverser reads the code where the static tools pointed.** The seeded
  prompt starts it at the addresses the pack gives, asks it to confirm or
  refute each upstream finding at function level, then to look for command
  dispatch, environment checks, persistence and cleanup, the logic of contact
  with a remote host and the decoding routines.
- **The sink-reachability pre-pass follows the agent's own provider.** It runs
  for every agent on Ghidra over http — a static clone on Ghidra under another
  global provider, and a generic agent given Ghidra's tools, which now reads
  the priority functions on its first turn — and for no agent on another
  provider.
- **A clone with no tool list takes its role seed's.** An operator's
  definition with no `tools` key gets the list of its role's seed (`static`,
  `dynamic`, `network`, `report`, `lead`); a list that is present, empty
  included, is kept as written.
- **No agent loop has a default step or time limit.** `react_agent_max_steps`
  (was 10) and `react_agent_timeout` (was 180 s) are empty, the deprecated
  `react_agent_*_overrides` maps ship empty (were static 40 steps / 1,500 s,
  network 6 steps / 300 s, dynamic 600 s, judge 600 s), the seeded `lead`
  carries no budget (was 40 / 1,800 s) and an ask's `agents.delegation_steps`
  / `delegation_timeout_seconds` are empty (were 12 / 300 s). An operator's
  value anywhere is still kept to. `None` is no limit end to end: the loop's
  budget, langgraph's recursion limit, the hard cap, an ask's ceiling and its
  tool description, the fallback turn deadline, the validation turn, the
  salvage and the nudge. The run-state block says "no step limit" / "no time
  limit" in words; the budget meter's `max_steps` / `timeout_s` are `null`. A
  loop ends when its model answers, at the repeat guard, at its room, or at
  the spend ceiling, with the job timeout last; each model call waits what
  its answer takes at the measured pace.
- **The judge's loop reads its own budget** through `loop_limits("judge")`,
  so the override map's `judge` entry reaches it; it read the deployment-wide
  numbers.
- **The judge's prompts are sized from its window.** Each analyst report (was
  cut at 500 characters), the evidence summary (2,000; it also named at most
  25 techniques and 6 sources each), the negotiation history (800) and each
  remembered case (200) are whole when the judge's window, less its output
  cap, holds them; otherwise the largest parts are shortened first, the
  prompt says which and to what width, and a degradation reason records it.
  The technique question shares the same reports and rule.
- **The triage pack shows everything its room holds.** Its fixed heads (six
  names, 120 characters of text, 100 decoded strings in 3,000 characters at
  120 each, 20 detection labels at 80 each) are gone: every line is whole when
  the pack fits, and otherwise one detail level derived from the room applies,
  each line saying what it left out and that the rest is a tool call away.
- **capa and FLOSS on the analysis server have no wall clock of their own**
  (were 300 s and 600 s): a call runs for the timeout its caller passes, the
  triage pack passing `static.capa.timeout_seconds` for capa — which the
  server's 300 s used to cut — and what is left of `triage.budget_seconds` for
  FLOSS. The manifest declares `timeout_s: null` for both.
- **Nothing a model wrote is dropped for a count.** A chunked analyst's merged
  ISR keeps every claim (it kept 20), every schema complaint is fed back (six
  were), the capability matrix and its table show each statement whole (six
  statements, 200 characters, 160 in the table), a callee's claimless answer
  reaches its caller whole (2,000 characters), and the dynamic analyst's
  network table lists every DNS, HTTP, TCP, host and domain row (ten of each).
- **The Ghidra sink pre-pass** waits one tool call's deployment budget, or as
  long as Ghidra takes when none is set (was 120 s per request).
- **An analyst's input is sized from its window.** `max_token_limit` (was
  128,000 tokens, cut with a log line) is empty by default: the input may take
  the window's room before the reply less the prompt around it; an operator's
  number wins. Input over it is shortened as a document (JSON keeps its keys,
  text its head ending in `…`), the model reads a note saying so, and the run
  records a degradation reason. The function summariser's prompts (were 8,000
  and 12,000 characters) are held to the same room and say when they are
  shortened; the PE loader's markdown lists every import, export and string
  (were 10, 10, 20 and 50); the generic MCP provider's prompt names every tool
  (was 20); the capa and YARA evidence tables carry every hit (were cut at
  6,000 characters mid-row).
- **What the page leaves out, it says.** Every list the markdown report shows
  in part ends "N more … not shown here; the JSON report carries every one", a
  cut table value ends in `…` and the methodology appendix says where it is
  whole, the JA3, packer, resolution and environment lists are whole, the
  evidence sections say how many rows they left out and under which ids the
  evidence endpoint carries them, a cut text section says where it is whole, a
  figure's legend counts what it did not draw, a drafted YARA or Suricata rule
  says in a comment how many published indicators it leaves to the IOC table,
  the STIX export carries every process root (was 20), a job's failure message
  is marked where it is cut, and a validation question naming a holder list
  counts the rest.
- **The report stage writes up to the model's own maximum.** A composer section
  and the narrative round take, in order, the operator's
  `reporting.composer_section_max_tokens` (sections) or `llm.judge_max_tokens`
  (the reporter's cap; `llm.expert_max_tokens` no longer reaches the report
  stage), else the model's declared maximum output, else the analysts'
  quarter-of-the-window derivation — never more than the model's maximum, the
  reasoning room included. On a 1,048,576-token model that declares 393,216 a
  section was held at 262,144; it now gets 393,216 and the rest of the window
  for its evidence. Each section logs its budget and where it came from.
  A learned window is never overrun: a section's evidence room is the window
  less the budget, never below zero, and a call whose budget would not fit
  beside its prompt is sent with what the window leaves, under the field each
  server reads (`max_output_tokens` on Gemini, llama.cpp's `max_tokens` and
  `n_predict` extras); Ollama, whose client takes no per-call cap, keeps its
  built cap. A prompt larger than the whole window is recorded, because
  Ollama cuts such a prompt from the front, system prompt included, without a
  word. On llama.cpp a cap set for one call now reaches the server's own
  fields, so a view answer bound to its view's cap is held there where the
  server used to write on to the built cap. The 8,192-token fallback window a
  failed probe leaves sizes nothing. The narrative round's wait is sized from its
  budget and the measured pace like a section's, where it was a fixed 600 s
  (`narrative:round` in Appendix B).
  **Upgrading:** a deployment that set `llm.expert_max_tokens` above
  `llm.judge_max_tokens` and relied on the larger for report sections now gets
  the judge's. A local deployment that sets `llm.judge_max_tokens` now gives
  each section that whole cap rather than a quarter of the window, so a
  section's evidence room shrinks — on a 16,384-token window with 8,192 set,
  from 36,864 to 24,576 characters, and to none once the cap reaches the
  window.
- **No report schema or prompt sets an upper size.** A section's prose
  (`_ProseOut.body`, 2,500 characters) and introduction (`_IntroOut.text`,
  1,800), and the narrative's executive summary (1,200), key findings (six) and
  recommendations (eight) lose their upper bounds; the lower bounds stay. The
  prompts no longer ask for a number of sentences, characters or entries, nor
  to be concise; the narrative prompt states the lower bounds the schema
  holds ("at least 120 characters", "at least two", "at least three"). A live
  run's evasion section was dropped for running past 2,500 characters after
  its one retry.
- **Every list a report model writes is kept whole.** The composer kept the
  first 20 flow steps, 30 configuration items, 40 commands, 30 flags and 6 C2
  channels, and silently the first 8 citations of a prose subsection; the
  report's ATT&CK external references and the Sigma drafts' tags took the
  first 10 techniques. None of them cuts anything now.
- **The report models see every published fact.** The narrative round was shown
  at most 8 techniques (each with its first quote cut to 120 characters), 5
  sandbox signatures, 8 import categories, 5 capability rules of 4 APIs each, 3
  domains, 3 IPs, 3 persistence entries (cut to 100 characters) and 5
  obfuscation indicators; a composer section at most 24 imported DLLs. Each is
  shown whole now, and the DLL list is always the complete list. The run-state
  block names every failed tool rather than eight. A narrative prompt larger
  than what the window leaves after its budget is recorded in the report's
  degradation reasons, and its calls are held to what the window leaves.
- **A request's timeout is sized from its output cap and the measured pace.**
  Every derived wait was held under 1,800 s, the client's request timeout, and
  that timeout — which httpx reads as the longest silence, not a deadline for
  the whole answer — ended an answer on a server that sends nothing until it
  has finished, such as a non-streaming llama.cpp server; streamed answers and
  DeepSeek's keep-alive'd ones were not ended by it. Once a model's rate is
  measured, an OpenAI-compatible (chat completions or Responses API),
  Anthropic or Gemini request whose output cap takes longer at that pace than
  its client allows carries that time as its own timeout, with the existing
  margin; any other request keeps its client's. The derived waits are no
  longer capped: the analysis job's 8-hour arq timeout is the last resort.
  Gemini's client timeout was a fixed 90 s and is now the 1,800 s every
  provider has. The function summariser's wait follows its request's, and a
  model rebuilt by the llama.cpp self-heal keeps the job's rate meter.
  `run_summary.generation` reports `unmeasured_request_timeout_s` in place of
  `ceiling_s`, and Appendix B no longer prints "at most 1800s".
- **`reporting.upstream_findings_max_chars` ships at 0, derived from the served
  window** like the tool-answer cap, for the upstream findings block and the
  triage pack; the documented 6,000 applies only when no window was learned. A
  positive value is the operator's. **Upgrading:** a stored 0 used to mean
  "no cut" and now means "derived".
- **The run-state block rides at the end of the last message, so a request's
  front stays the same.** A tool loop's block, with the budget line that counts
  down every turn, used to be rewritten at the end of the system turn, and a
  changed byte there voids a provider's prefix cache (measured on DeepSeek: 0
  cached tokens of 3,884 with only that line changed, 3,712 with it unchanged)
  and makes a local server read the whole conversation again. It now ends the
  request's last message — the task, the latest tool answer, or the question a
  nudge, a synthesis or a retry asks — and comes off it again, byte for byte,
  once the message is no longer last: each request is the previous one without
  its block, plus the new turns and the new block. No request has two user
  turns in a row or a turn holding only the block. The text is the same.
- **A question asked right after a user turn ends that turn.** The retries
  after an answer cut at its cap (an analyst's, a report section's, the
  verdict's) leave the cut answer out, and a forced synthesis whose trim kept
  only the task follows the task directly; each used to send its question as
  a second user turn in a row. The question, its text unchanged, now ends the
  user turn before it after a blank line (`pipeline.turns.with_question`); after
  a model's turn or a tool answer it is still a turn of its own.
- **The analysts' and the judge's output caps are derived from the window.**
  `llm.expert_max_tokens` and `llm.judge_max_tokens` ship at 0, which derives
  each agent's cap in three cases: the model's declared maximum output (a model
  list entry, or a vendored `max_output` row sourced from the vendor's page)
  bounded by a quarter of its window; a quarter of the window for a runtime we
  run, known by the probe's answer from its own `/props`, `/api/show` or `/info`
  and never by a loopback address alone; the documented 8,192 for a hosted API that declares no maximum. The
  derivation is recorded in `run_summary.generation.output_caps`. A value above
  0 is used as set. The reply reserve and the composer's section budget follow
  the same rule; a window nobody reported keeps the documented 8,192.
- **The official STIX pattern validator decides at runtime, alone.** Its
  verdict is the whole answer where it can be imported; `==` and `NOT EXISTS`
  are accepted. `stix2-patterns`
  2.1.2 moved from the development group into the runtime dependencies; the
  pattern grammar in `schemas.stix_pattern` is the fallback where it is absent.

- **The judge writes a compact bundle.** The verdict contract asks for the
  JSON on one line, the confidence, basis and credits on the relationship only
  (never repeated on the indicator or attack-pattern it relates), an
  attack-pattern with at most one sentence of description, and no
  `pattern_type` (always `stix`, filled in); created, modified, spec_version
  and valid_from were already left out. Every relationship is still the
  judge's own, and an indicator is related only to what it indicates. The
  question after a cut names the answer's characters, the objects it began by
  type and its indented lines, and asks for the compact bundle. A reference
  judge's answer was cut at its 8,192-token output cap twice and the verdict
  fell back to text extraction; only its first 2,000 characters are stored,
  pretty-printed, with a relationship's annotations repeated on its indicators.
  The output cap is unchanged.

- **A composer section's output budget is derived, not fixed.**
  `reporting.composer_section_max_tokens` ships at 0, which gives each model
  of the reporter's list the room an analyst's reply is given on it: the
  larger of `llm.expert_max_tokens` and `llm.judge_max_tokens`, at most a
  quarter of the context window the model serves
  (`llm.context_window.reply_budget`). The run summary prints the derivation
  beside the section's wait. A positive value is an operator's own budget, as
  before. The fixed 900 dropped a live report's payloads section.
- **One publish decision for the judge's values.** The export asks every
  value a judge indicator names the one publish rule, as the report's own row
  for it is asked, and the judge's assertion is not a second source; a
  refused value declines the indicator (`stix.indicator_not_published`). The
  IOC table and `/iocs` ask the same rule of the same values (stored on the
  report as `judge_indicators`) and print the same answer. The rule now
  answers a hash (publishable when a whole digest a second source knows) and a
  command line (never published). `/iocs` may serve `email`, `path`,
  `registry`, `mutex` and `command` rows, and a `hash` of another file, with
  source `judge`.
- **A network value recovered by emulation is its own publish source.** A
  domain, address or URL the run's FLOSS entry holds as a decoded, stack or
  tight string is publishable when it passes every other check of the rule
  and is not a well-known benign host, with the reason "recovered by emulation
  (decoded strings), ev_NNNN"; never under a Benign verdict or a verdict the
  judge did not state with a confidence, and a value the static string sweep
  read — alone, or as a whole value in its plain strings beside a decoded row —
  stays the sweep's. The record is built from the ledger at build time and
  stored on the report (`emulated_strings`), and says when it is partial. A
  benign host is read by its registered name (`*.co.uk`), and a public
  resolver's address is benign. The export, the IOC table and `/iocs` read it
  through the one rule.
- **A draft detection rule matches only what the run publishes.** YARA
  strings and Suricata alerts are drawn from the IOC table's published rows,
  and a Sigma selection from published rows and what a sandbox recorded; the
  drafts are generated after the export. Import names are no longer YARA
  strings. A Benign verdict gets no draft, and §10.2 says why. A registry key
  is compared without its hive or value name on both sides, and the
  twelve-value cap on each Sigma selection is gone. A Sigma registry
  selection names the key without its hive, so it matches Sysmon's
  `HKU\<SID>\...` events.
- **Every analyst claim reaches its composer section.** The fixed claim cuts
  (ten per prompt; twelve, eight and fourteen in three bundles) are gone; the
  claims share the window's room with the tool answers. A section's facts
  enter whole (the fixed cuts on techniques, network values, user agents,
  process lines, command lines, persistence, capabilities, packers and carved
  files are gone), and a section whose facts alone exceed the window records a
  degradation.
- **A citation check asks about a whole digest and a word spelled with hex
  letters**; only `0x` hex, a hex run with a digit, or a bare number is
  undecidable. The version-word check before an address reads a bounded
  look-back.
- **A technique only a rule match stands behind is marked** in the ATT&CK
  table ("rule match only (yara `rule`, N string(s)), no analyst claim") and
  grounds no capability word. The publish rule is unchanged.
- **A section's tool answers share the reporter model's window** after the
  section's output budget and the rest of its prompt, instead of a fixed 1,200
  characters (and 2,500 before that); the host-identifier section and its
  bundle carry no fixed row cap.
- **A composer section is shown the techniques the report publishes and,
  after each analyst claim, the entries that hold the values the claim
  quotes.** A section shown only a claim had called it unsupported while a
  strings entry held the value and the report published the technique.
- **Every section's contract** (`composer.section_contract`) says a list item
  is written only with a value, never with nulls, and a value is a JSON
  string, numbers included; the prompt-leak test now reads every contract.
- **FLOSS runs beside capa in the triage pack** when the host's available
  memory, less capa's peak as this worker measured it and FLOSS's 4 GiB bound,
  stays at or above the new `triage.memory_floor_mb` (10,240 MiB), and the
  worker's cgroup limit, where it has one, holds both; otherwise the two run
  in turn as before, and `run_summary.triage.floss` says which and why. Its
  entry is still last, with its own clock. On PuTTY: 312 s → 183 s, peak
  resident memory of the pack's process tree 1.6 GB → 2.3 GB.
- **The prompt reading rate is measured** beside the generation rate, from
  Ollama's `prompt_eval_count`/`prompt_eval_duration` and llama.cpp's
  `timings.prompt_n`/`prompt_ms`, and recorded in `run_summary.generation`.

- **The STIX export cites the ledger.** An exported object now carries the
  ledger entries the run's record ties to it, as `x_maljan_evidence_refs`
  (`ev_` ids, each once, in ledger order): the sample's `uses` edge to a
  technique carries the entries an analyst finding naming it cites and the
  entries of the asserting tools whose structured output names it, and a
  malware object minted from the family name carries the family's
  `family_evidence_ids`. Nothing is inferred: no id is read out of a claim's
  sentence, no object is matched by value, an id the ledger does not hold is
  left out, and an object the record ties to nothing has no such property.
  A run with no ledger entries exports no ids, and a family id the ledger
  does not hold is recorded as `stix.evidence_ref_not_in_ledger`. The property
  is the platform's: a judge object that writes it is read without it and
  recorded as `stix.property_not_carried`, with no retry. The console's
  relationship graph and its table read only this property.
- **Staging is per job.** The sidecars' staging directory held every job the
  server process ever ran: `put_sample` uploads landed flat in it under
  sixteen hex characters and the original file name, every sample's carved tree
  sat beside every other's, and two runs of the same sample shared one tree, so
  the only thing keeping one run out of another's files was the shape of the
  carved tree rather than the directory. `MALJAN_STAGING_DIR` is now the
  **base**, and each job writes into `job-<its id>` inside it: its uploads, its
  `carved/<sha256>/` trees, and nothing another job can name by any spelling.
  The spawn composes that one directory name and passes it to the child as
  `MALJAN_STAGING_JOB` — a leaf, not a path, so an operator's configured base
  stays the base; the sidecar joins the two. A path argument resolving into
  another job's directory is refused even where a sample root contains the
  base. The job's owner removes the directory on success, on failure and on an
  operator's cancel, and the `MALJAN_STAGING_TTL_HOURS` sweep now prunes a job
  directory whole — by the newest mtime inside it, following no link — as well
  as the files inside a directory still in use. **What an operator does:**
  nothing. The flat uploads and the single `carved/` tree of the previous
  release are swept by the same TTL where they lie; a host you want clean at
  once can have that directory emptied while no job is running. A sidecar
  started by hand or by a settings probe gets no leaf and writes in the base
  exactly as before.

- **A tool answer too big for the prompt is shortened, not cut in half.** A
  JSON result over `preprocessing.max_tool_output_chars` was cut as text, which
  ended the document mid-array: the model got a prefix with none of the
  answer's own metadata (`total`, `next_offset`, `read_path`) and the ledger
  got prose it could not parse, so `structured` was empty. Every reader of the
  record — the evidence sections, corroboration, the triage pack — skips an
  entry with no `structured`, so an analyst's *largest* answers, the ones that
  found the most, contributed nothing to the report and nothing said so. Such
  an answer is now shortened as a document: elements come off the end of its
  largest lists until it fits, no key is ever dropped, `truncated` is set and
  each shortened list says how many rows came back (`<key>_returned` beside a
  `total` the tool already emits, otherwise `<key>_omitted`). **What changes
  for a consumer:** a large result now reads as valid JSON with fewer rows and
  a stated count rather than as a cut-off string, and `structured` is populated
  for those entries for the first time — so evidence sections, corroboration
  and the triage pack begin to see calls they have never seen, and a report
  over the same sample can carry more than it did. A large **string** value is
  shortened the same way, which is the decompilation shape. Bookkeeping goes
  under one reserved top-level key, `shortened`, mapping each shortened value's
  path to `kept`/`omitted` (or `kept_chars`/`omitted_chars`); nothing is written
  into the tool's own vocabulary but the `truncated` flag it already has, and a
  tool that already uses the name keeps it. Anything that is not a JSON object
  (decompilation as plain text, any prose) reaches the `FunctionSummarizer` and
  then the same character cut as before, byte for byte — but a JSON object no
  longer reaches the summariser, because its answer is prose and prose is what
  leaves the record with nothing structured in it. The run summary's truncation
  block counts the new outcome as `tool_output_shortened`, and a shortening that
  ran past its wall as `tool_output_shortening_timeouts`. The report says in a
  sentence above the section's table, rather than as a row in it, that an
  answer was shortened and by how much.

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

- **One code for one export decision about an endpoint.** A URL, a name and an
  address the host question refuses are one class of decline, and the run
  summary recorded them under `stix.unpublishable_url` and
  `stix.unpublishable_domain` — with the second of the two also covering
  addresses, which is not what it is called. All three are now
  `stix.unpublishable_endpoint`, and the sentence beside the row names the
  kind. Nothing is migrated: a run stored before this keeps the code it wrote,
  and the console reads all three as the export's own decision.
  **Upgrading:** a consumer filtering `run_summary.validation` on
  `stix.unpublishable_url` or `stix.unpublishable_domain` must also accept
  `stix.unpublishable_endpoint` to keep seeing new runs.

- **A `directory:path` indicator now needs the run's own evidence, not only a
  filesystem anchor.** A directory whose literal began with one of the
  OS-resource prefixes — `C:\`, `/data/`, `%TEMP%`, a registry hive — used to
  be admitted on that alone, with no corpus question asked. Shape is not
  evidence: the anchor now answers only whether the literal could be a place,
  and the literal is then asked, as every other literal is, whether this run
  recorded it. A judge that writes a real directory the run did not happen to
  write down is told so and spends its one retry there.
  **Upgrading:** a run whose evidence does not name a directory it claimed will
  carry a `stix.ungrounded_indicator` row for it where it carried none before,
  and the indicator is dropped after the retry rather than exported.
- **Everything the exported STIX bundle loses now leaves under a name.** The
  total indicator cap removed indicators with a log line and nothing else, and
  the integrity pass trimmed a report's or a note's `object_refs` without
  recording it, so what the **export** removed could not be totalled. Both are
  counted: `truncation.indicator_cap_removed` and
  `truncation.integrity_refs_trimmed` on the run summary, two rows in the
  report's Bounds Hit table, and one sentence in the console's run record
  naming each reason with its own count. What reconciles is the export's own
  figures: the objects the assembled bundle lost equal
  `integrity_objects_removed` plus `indicator_cap_removed`. The judge path runs
  the same pass once per verdict *attempt*, discarded retries included, so its
  removals are counted apart under `judge_integrity_*` and are not part of that
  total.
  **Upgrading:** `run_summary.truncation` carries six new keys
  (`indicator_cap_invocations`, `indicator_cap_removed`, `integrity_refs_trimmed`,
  `judge_integrity_invocations`, `judge_integrity_objects_removed`,
  `judge_integrity_dropped`); a summary stored before this release has none of
  them and reads as zero. `integrity_objects_removed` no longer counts the judge
  path's own passes, so on a run with a judge retry it is smaller than before.

- **A finding row handed up a chain of delegations stays inside its limit.**
  Each hand-over put the callee's name in front of the row, and nothing bounded
  the result, so a row five levels deep was longer than the eight hundred
  characters every validator's own row is held to. The chain is cut instead,
  oldest step first and marked with an ellipsis; the finding's own sentence is
  never cut. The route and the sentence are carried as two values, so the bound
  can only ever shorten the route.
- **A UNC share written the way a judge writes it reads as a place.** A STIX
  literal `'\\server\share'` is unescaped by the pattern reader to
  `\server\share`, and the directory check refused a single leading backslash,
  so the judge was told its own valid path could not be a directory. One
  backslash or two is a root now. In the other direction the check no longer
  admits a drive-relative `C:Windows`, which names no place on the analysed
  machine, nor a URL's fragment or query read as a step (`/#frag`, `/?q=1`).
- **An absence over evidence the run knows is partial says so.** The output
  shortener hands one string to the model and to the ledger, so a value in
  neither is a value the model never saw and the grounding rule is unchanged.
  What changes is the feedback: when an entry the grounding check searched came
  back shortened, the `stix.ungrounded_indicator` row names the tools whose
  answers were handed over with rows missing, so the judge can narrow one and
  ask again instead of guessing.
- **The two deprecated per-agent budget maps name the release they go in, and
  cannot hold a budget nothing can use.** `react_agent_timeout_overrides` and
  `react_agent_max_steps_overrides` are deleted in the release after the next
  promotion to main, said identically in the two source comments and in
  `docs/configuration.md`. A map entry that is not a whole number of at least
  one — the bound a definition's own budget fields already carry — is dropped
  when the settings are built, with the agent and the value logged. Dropped
  rather than refused: a settings build that raises is a deployment that
  cannot serve, and the agent falls back to the deployment's own budget, which
  is what the reader did with such a value anyway. The bound runs before
  pydantic's coercion, so a `2.5`, a `"lots"` and a nested dict are dropped too
  rather than raising, while a `"40"` written through the environment is kept.
- **Two import rules for one technique are two rows again.** `api_capability_hits`
  keyed a row by technique id and name, and the catalogue's own name is on both
  of the `T1685` rules, so they pooled: one rule's matched APIs counted toward
  the other's `min_apis`, and a technique could be asserted on a combination no
  single rule ever cleared. A row is a rule — the rule's own label is part of
  the key and is on the row, and the report's import-technique table carries a
  **Rule** column, as does the console's ATT&CK-from-imports table.
  Corroboration keys on the technique id and is unchanged, and so is every
  count of techniques: the console's heading, the narrative's prompt and the
  report's facts count distinct technique ids rather than rows.
- **The ATT&CK index retry interval reaches a sidecar from any entry point.**
  `MALJAN_INDEX_RETRY_SECONDS` was exported in `MaljanApp.arun` alone, so a
  knowledge sidecar started from a container built anywhere else kept the
  module default. It is announced by the container, beside the tracing values,
  which is the one place a sidecar's environment is decided from settings.
- **A grounding check searches what the run saw, not what the ledger kept.**
  `reporting.evidence_budget_bytes` blanks an entry's output after the model has
  read it, so the judge could be told that a C2 a tool really returned "appears
  nowhere in the evidence this run collected" — and the indicator was dropped
  from the exported bundle over it. The container now keeps every tool answer as
  the model received it, in memory, for the length of the job, bounded by the new
  `reporting.evidence_corpus_bytes` (64 MB); the judge's grounding corpus and the
  export's second-source test read that.
  **Upgrading:** nothing to do. The corpus is never persisted and never enters
  the graph state; set `reporting.evidence_corpus_bytes` lower to cap the memory,
  and to zero to keep none — which makes every absence advisory, below.
- **The platform does not assert an absence over evidence it knows is partial.**
  When the corpus hit its ceiling, when there is no corpus (a report rebuilt
  later, a run resumed in another process), or when the stored entries fell back
  on include one the byte budget blanked, a `stix.ungrounded_indicator` row is
  **advisory**: it says how many answers were not searched and from which tools,
  it is fed back once like any finding, and the judge's object is not dropped for
  it. `Violation` carries the flag and `drop_ungrounded_indicators` honours it.
- **A grounding corpus that kept nothing is still the corpus.** Asking it only
  when it held something threw away the verdict of one that kept nothing —
  which is exactly what `reporting.evidence_corpus_bytes = 0` produces — and
  the check fell back to the stored ledger, was told the evidence was whole,
  and dropped the judge's object, the opposite of what the setting says. The
  corpus is consulted whenever it has anything to say, and how whole the
  searched evidence is, is the conjunction of the sources searched: a fallback
  to stored entries inherits the state of the corpus it fell back from and
  never launders it into "complete".
- **A run whose grounding went advisory says so where an operator looks.**
  `run_summary.truncation` carries `evidence_corpus_missing_answers`,
  `evidence_corpus_missing_tools` and `evidence_corpus_partial_reason`; a
  degradation reason names which of the three reasons it was; the report prints
  it under Bounds Hit and the console draws it in the run record beside the
  degraded banner. `advisory` survives `record_unresolved`, so a row the
  platform declined to act on is no longer stored and drawn as a producer's
  unfixed finding.
- **The report and the console describe a bundle's losses in one wording.** The
  report's Bounds Hit line printed `integrity_objects_removed` as "objects
  repaired away" with the indicator cap's orphaned relationships inside it, and
  said 10 where the console said 4 about the same run. Both build the sentence
  the same way now, pinned on both sides against one fixture of the eight
  measured bundle shapes.
- **The grounding corpus costs what its ceiling says.** The run's record was
  copied three more times on the way to a check — a joined cache, a token-set
  element, and the string the check searched — so one check over 400 answers of
  6,000 characters allocated 6.01 MB on top of a 2.4 MB corpus. The text is held
  once, lower-cased at the moment it is recorded, and a check searches each
  answer where it lies: the same check now allocates **0.01 MB**.
  **Upgrading:** `reporting.evidence_corpus_bytes` defaults to **16 MB** rather
  than 64, which is about 2,700 tool answers at the output cap against the few
  hundred a whole team makes — the ceiling now bounds the process cost rather
  than a quarter of it.
- **The grounding check runs on whichever record the run has.** It was gated on
  the sandbox token corpus alone, and the run's own tool answers had moved
  beside that corpus rather than into it — so on every run with no sandbox
  network block (mock mode, a static-only team, a failed submission, a sample
  that made no network call) the `stix.ungrounded_indicator` check did not run
  at all and an invented indicator was exported with nothing said about it. It
  runs on either source now. With **neither** — no sandbox block and no tool
  answers — nothing was searched, and a check that searched nothing may not
  conclude from it: the row is written, it is advisory, and the judge keeps its
  object, which is the same answer a partial corpus gets.
  **Upgrading:** a run with no evidence at all now spends one correction turn
  on an indicator it used to export unquestioned, and carries an advisory row
  for it in `run_summary.validation.unresolved`. Nothing is dropped for it.
- **How much of a tool answer a model sees is the model's window, not a
  constant.** `core.preprocessing.max_tool_output_chars` was 6,000 characters,
  and every argument for that number was an argument about one deployment: a
  local server started with a 131,072-token window and a forty-step reversing
  loop. On a model served with 32,768 it does not fit; on one with a million it
  throws information away for nothing. The setting now defaults to **0**, and 0
  means the cap is worked out at the moment of each call from the window the
  served model was found to have, less what the conversation already holds and
  the room kept back for the model's own reply, converted at three characters
  per token — measured, from a recorded conversation of 114,000 characters the
  server reported at 38,868 tokens — and multiplied by the eighth of what is
  free that one answer may take. An answer is measured against what is free,
  what it takes is charged as soon as it is handed out — a turn may call
  several tools at once — and the next one is measured again, so the answers of
  one conversation sum to less than the room it began with on every window the
  vendored table ships. **A cap never exceeds the room that is really left:** a
  floor of 2,000 characters applies while the room affords it, and where what
  is left cannot hold an answer at all the model is handed no answer and one
  sentence saying the conversation has no room left, with the whole answer
  still on the evidence ledger under the call's id and the outcome counted as
  `tool_output_no_room`. That sentence is said once and charged like any
  answer, and the agent's tool phase ends there: further calls are not run, the
  run-state block carries the fact every turn, and the loop is salvaged into an
  answer from what it already gathered with `no_room` on its budget record.
  Both notices come out of the tool budget — the window less the room kept back
  for the model's reply — and are withheld when they would not fit, so the
  reserve the forced synthesis writes its answer in is never spent on saying
  that the room ran out. The `[OUTPUT TRUNCATED]` marker is kept back out of
  the cap rather than appended after it, so what reaches the model from a
  character cut is the limit, marker included. A positive value is an explicit operator cap and
  behaves exactly as this setting always did. The window itself is learned free
  of charge and without asking the operator anything:
  llama.cpp's `/props`, Ollama's `/api/show`, an OpenAI-compatible
  `/v1/models` for vLLM and OpenRouter, Text Generation Inference's `/info`,
  then a vendored table keyed by model family
  (`data/model_context_windows_v1.json`). A settings-named window short-
  circuits none of that: where one was also probed the smaller of the two wins,
  so a model that holds less than `num_ctx` asks for, and a `context_size` left
  behind by a server restarted smaller, cannot overflow the real window. Where
  **nothing** answered, nothing is derived — the documented 6,000-character cap
  applies and every surface says the window is unknown and names the setting
  that would fix it. A reported window is believed only up to ten million
  tokens; past that the figure is refused with the reason in words, because a
  proxy reporting its window in bytes produces a cap larger than any answer
  there will ever be and switches the guardrail off for a whole run. No
  generation call is ever made, and a guard test drives both probe entry points
  themselves through a transport that records every request, refusing any path
  but the four metadata suffixes and any method but GET except the one metadata
  POST. `run_summary.truncation` carries the window, where it was learned, the
  characters-per-token figure and the smallest and largest cap that applied;
  the report's Bounds Hit section says the same in a sentence; and the Settings
  page prints the detected window beside the field.
  **Upgrading:** the default changes behaviour. On a 32,768-token window one
  answer may now take **9,216** characters where it took 6,000, and on a
  131,072-token window **46,080** — richer observations, and a conversation
  that fills faster. A deployment whose window cannot be learned keeps exactly
  today's 6,000, and the only change it sees is that the run summary and the
  settings page now say the window is unknown; setting
  `core.llm.openai.context_size` turns that into a derived cap.
  `run_summary.truncation` gains four keys (`tool_output_limit_smallest`,
  `tool_output_limit_largest`, `tool_output_no_room`, `context_window`); a
  summary stored before this release has none of them.
- **The two memory ceilings are re-argued against the derived cap, and not
  scaled with it.** `reporting.evidence_budget_bytes` (512 KiB per agent) and
  `reporting.evidence_corpus_bytes` (16 MB per run) were both sized against
  answers of at most 6,000 characters. The replacement arithmetic is the
  derivation's own property: one loop's answers come to at most
  `(window - reply reserve) x 3` characters. Half a megabyte therefore holds a
  loop's whole tool output up to a window of about 183,000 tokens, and 16 MB
  holds six such loops at 131,072 tokens and about five and a half at a
  million. Neither number moved: they bound the worker's memory and a JSONB
  column, not the model's context, and answering a bigger window by holding a
  proportionally bigger corpus in RAM is how a machine that also runs the model
  runs out of it. **Upgrading:** nothing to do on any window this platform has
  been run on. A deployment on a very large window that wants every answer kept
  whole raises `reporting.evidence_budget_bytes`; one that wants the grounding
  corpus to hold a whole run raises `reporting.evidence_corpus_bytes`. Past
  either, what happens is what has always happened and is still said out loud:
  the ledger entry keeps the call and drops the output and the report says how
  many, and the corpus reports itself incomplete so an absence measured against
  it is advisory.
- **The evidence ledger stores the answer the model was handed, whole.** Every
  stored output was cut at 6,000 characters on the way in — a trailing ellipsis,
  no `truncated` flag, nothing counted — which was defensible while the
  tool-output guardrail handed the model the same 6,000. It no longer does, and
  for a plain-text answer (a decompilation, a `strings` dump) the stored prefix
  is the entire durable record: what `GET /api/v1/jobs/{id}/evidence` serves,
  what the report sections are built from, and what an `ev_0007` citation
  points at. A model that read 46,080 characters left a record of the first
  6,000 and nothing said so. `reporting.evidence_budget_bytes` is now the one
  storage decision, and it announces itself: past it the entry keeps the call,
  drops the output, sets `truncated` and is counted. A caller that passes a
  ceiling of its own still gets a cut, and that entry is flagged too.
  **Upgrading:** stored evidence entries get larger, up to the per-agent byte
  budget, and that budget now binds where the silent cut used to pre-empt it —
  so a deep reversing loop on a large window may report trimmed entries where it
  previously reported none. Measured on a 131,072-token window: an entry can
  hold 46,080 bytes, so 512 KiB holds 11 entries of 20 where the silent 6,000
  cut let about 87 through. A trimmed entry loses its parsed `structured`
  result as well as its text, so the report sections built from `structured`
  lose data they previously kept — the in-run grounding corpus is unaffected.
  Raise `reporting.evidence_budget_bytes`, or set it to `0` to keep every
  output. `reporting.upstream_findings_max_chars` is a
  third copy of the same constant and is deliberately unchanged: it bounds a
  prompt rather than a record, the block it cuts says so, and the whole findings
  stay in the run state and the report.
- **The Windows import block says what it measured, or it says nothing.** The
  Linux half of the API catalogue was cut to what a measurement justified; the
  Windows half never had been. Measured through the production loader over
  2,730 freely distributed Windows binaries from 25 independent vendors and 201
  Windows malware samples — 123 distinct import profiles, deduplicated, with
  every combination chosen on the older half and scored on the newer — the
  Windows behaviour block labelled **97.73% of ordinary software against 93.50%
  of malware**. That is not a weak signal; it is no signal, stated as a fact.
  Its nine labelled categories are informational now and each names in
  `corroborated_by` what would give it weight; `keylogging` alone keeps a label
  and carries `flags_with`, so it waits for the input hook, raw-input device or
  whole-keyboard read that is the capture rather than the key-state poll a game
  does every frame. The block now labels **2.01% of ordinary software and
  21.14% of malware**.
  **Eighteen of the forty-seven technique rules are gone**, against two bars.
  Fifteen carried no information at all: within the size-matched band their
  names fired no more often on malware than on ordinary software (T1003, T1016,
  T1027, T1049, T1053.005, T1071.004, T1087, T1106, T1140, T1222, T1546.003,
  T1555, T1620 on Windows, and the two rules on the scanning and tracing
  provider calls that ATT&CK 19.2 folded into T1685). Three more were above 4%
  of ordinary Windows software with a size-matched lift under 3, which is the
  shape that gets a rule re-argued rather than a threshold that deletes it —
  the rate is carried precisely so a common association can ship honestly — and
  each went on its own argument. **T1083** (6.41%) is the sole row on *zero*
  malware profiles: every profile it fires on already carries another row, so
  its 175 benign rows buy a reader nothing. **T1622** (7.51%) is weak on its own
  numbers, a likelihood ratio of 1.84 over the whole corpus and the sole row on
  one profile. **T1497.003** (9.56%) fails the same test that decides whether a
  name may be taken out of a rule, applied to the whole rule: the evasion is the
  *duration* a program waits and no import carries a duration, so the act its
  names describe is not the act the technique describes. That one costs
  something — it is the only one of the three with unique coverage — and it is
  deleted anyway, because a rule that cannot be made right does not ship.
  **Fourteen of the twenty-nine that remain keep a narrower combination**, and a
  name was removed from one only where the act it names is not the act the
  technique describes — `TerminateProcess` ends a process and not a service,
  `MoveFileEx` renames a file and does not delete it, `IsProcessorFeaturePresent`
  is the C runtime asking about the processor at startup. Eight further
  combinations were written, measured and **not** applied, because the only
  argument for them was that they happened to separate these two corpora best.
  T1095 keeps one name: the ten Berkeley and Winsock names label one benign
  binary in twenty and more than a third of everything that touches a network,
  and a raw socket and a TCP socket are the same import, so what is left is
  `IcmpSendEcho`, which is ICMP by construction. Over the same corpora the rule
  set now fires on **14.40% of ordinary software and 45.53% of malware**,
  against 25.71% and 63.41% before.
  **Every surviving association carries the rate it was measured at**, under
  `measured`: `seen_on_benign_percent` is the share of the named corpus the
  association fired on, `seen_on_benign_files` the count behind that share, and
  `held_out_malware_profiles` how many profiles the combination was not chosen
  on that it fires on — `0` where it fires on none, said rather than left out,
  because an absent count and a count of zero read the same and mean opposite
  things. The Linux block carries the same field from its own measurement. The
  rate reaches the model in the `api_capability` answer, the report's
  import-technique table and the console's cell, so a reader weighs an
  association instead of reading it as a finding. Every Windows rule also gains
  the `rule` label and the `ordinary_use` sentence the two Linux rules already
  had, and the builder refuses a rule missing either, or missing its held-out
  count.
  Read the rates in the one direction they were measured in: they say how often
  a rule fires on software that is not a sample, and none of them is a
  probability that a given sample is benign — which is why every key names what
  was counted. Neither malware corpus carries technique-level ground truth, so
  what was measured is that a combination separates binaries already known to be
  bad from binaries already known to be good, never that a sample performs the
  technique. 29.2% of the malware corpus imports nothing an import rule can see,
  and the combinations are tuned to this pair of corpora.
  `scripts/knowledge/measure_api_behaviour_block.py` gains `--platform windows`
  so the whole measurement is one command: it reads PE import tables with
  `pefile` exactly as `extractors/pe_extractor.py` does, records an ordinal-only
  import as `Ordinal_<n>`, deduplicates by content, takes a directory or an
  inventory file, and `--write-inventory` saves what it read so the same corpus
  can be measured again after the files are gone.
  **Upgrading:** eighteen technique ids disappear from the Windows import layer
  and fourteen more fire on fewer samples, so a saved report and a live run will
  show fewer rows in the import-derived ATT&CK table and fewer catalogue
  associations in the corroboration table; a dashboard counting those rows will
  read lower for the same sample. The three the second bar removed —
  T1497.003, T1622 and T1083 — are the ones most likely to be missed, because
  they fired on more samples than anything else in the block; they fired on
  ordinary software at nearly the same rate, which is why they are gone.
  `catalog_flags: ["suspicious"]` now appears on a Windows import only where the
  `keylogging` gate is met, so an `api_capability` consumer that treated the flag
  as its trigger sees it on roughly one binary in fifty rather than on nearly
  every one. A generated YARA rule carries fewer import strings for the same
  sample, because `reporting/detection_signatures.py` draws its `$s` strings
  from the matched imports of the rules that fired.
  The `api_capability` answer gains `measured` on a technique row,
  `behaviour_rates` per category and `corpora` at the top; `api_technique_hits`
  rows gain `benign_rate`, a sentence carrying the share, the file count and the
  held-out support, absent on a producer with no measurement — absent means not
  measured, never "never fires". `StaticAnalysis` gains
  `api_capability_rates` and `api_capability_corpus`, both empty on a report
  stored before them, and the profile line then prints the counts alone as it
  always did. The knowledge sidecar's `api_capability` description is now the
  in-process docstring verbatim rather than a two-sentence summary, so the
  caveats reach the model that actually reads it — 2.3 kB, with the
  field-by-field glossary dropped because every key in the answer names its own
  direction and `corpora` ships the corpus sentences; what a payload cannot say
  for itself stays. The tool's name, arguments and answer shape are unchanged.
  Every row of every Markdown table in the report is now built by one helper
  that escapes each cell as it composes the separators, and a guard fails the
  build if anything else in the renderer writes a `|` into a string: an import
  name and a PE section name are both the sample's own bytes, and a pipe in one
  used to add a column while a newline cut the row in half. An HTML or PDF
  export renders the escape back to a plain `|`; only someone reading the raw
  `.md` sees the backslash, and only on a value that really carries a pipe.
  A cell whose value was missing used to print Python's `None` into the report
  and now prints the placeholder the column intends.
  The Linux block's rates were re-measured after the
  same change gave the ELF walk content deduplication, so its corpus descriptor
  reads `1837` where it read `1842` and five category shares move by one
  rounding place; no Linux rule's rate moves at all. No behaviour category was
  renamed or removed, so a consumer reading `category` alone is unaffected.
- **One severity ladder in the console.** Severity order and colour live in
  `apps/web/src/lib/severity.ts`, and the Summary, DETECTION, DYNAMIC and the
  header's verdict-against-severity rule read it. A guard fails the unit suite
  on a severity coloured, compared by its spelling (either way round or in a
  `switch`) or sorted by its label anywhere else.
- **DETECTION shows the rules a current run fired, with each Sigma rule's own
  level.** DETECTION read only the old deterministic layers' claims, which no
  current run writes, and turned their confidence — the rule's maturity status
  as a number — into "High" or "Medium". It now reads the `yara_matches` and
  `sigma_matches` report sections the rule tools build, shows each Sigma rule's
  declared level labelled as the rule's level, and sorts and dots the rows by
  it on the severity ladder. The two sections moved from STATIC to DETECTION;
  STATIC links there. A run stored before those tools is still read from its
  layer claims, which say "level not recorded", and their confidence is printed
  as the number it is. `SigmaMatch` also carries the rule's `level` as a field;
  its claim text is unchanged.
- **DYNAMIC colours a signature's number only where its scale is known.** The
  run's recorded sandbox provider says which scale the number is on: CAPEv2's
  1 to 3 or Triage's 1 to 10 signature score, each drawn on the ladder by what
  it means, printed in words beside the number ("High, 8/10"). An uploaded,
  REST or unknown provider's number, and one outside its scale, is drawn in
  one neutral tone as it came, beside the word "unrated".
- **One colour per run status.** `apps/web/src/lib/status.ts` colours
  completed, running, pending, failed and cancelled for the dashboard, the
  analyses list, the search palette and the analysis header, and a stage's or
  participant's running and done; the search palette's running job is blue like
  everywhere else, not orange. A dashboard run that has a report but did not
  complete shows its status beside the verdict chip.
- **A tested tool server's unavailable tools are said on their own rows.** The
  separate list above the Tools section is drawn only where the tool table is
  not, and a tick list the table writes keeps the manifest's order rather than
  the order the boxes were ticked in.
- **The console's style guard covers charts.** `styleRules.test.ts` also fails
  on an SVG gradient, on Tailwind's bare `transition` class, and on a colour
  transition written as an arbitrary `transition-[…]` class, an inline style or
  a stylesheet declaration.
- **A token count is what a provider reported, and nothing else.** A call
  whose provider reported no usage used to be counted with a
  four-characters-per-token estimate folded into the same sums, flagged only by
  `run_summary.tokens.estimated_calls`. It is now counted as a call and as
  `unreported_calls`, adds no tokens, and the report and the console say "not
  reported" for it. `estimated_calls` is no longer written. A consumer reading
  `run_summary.tokens` should read `unreported_calls` where it read
  `estimated_calls`, and treat `input_tokens` / `output_tokens` as the reported
  figures alone.

- **Every tool server is driven with at most four calls in flight per job.**
  `core.mcp.breaker.max_concurrent_calls` (4) queues a job's fifth concurrent
  call to one server until one of the four answers; set it to `0` to drive
  every server uncapped as before.
- **A model on a fallback list has a turn deadline, and every provider a
  request timeout.** A model that is not the last on its agent's list is
  treated as stalled after `core.llm.fallback_turn_share` (0.5) of the agent's
  loop budget, and the list moves on; the model that answered then stays for
  the rest of that loop. The Ollama client is now built with the same 1800 s
  request timeout the OpenAI client always had, and Anthropic's is named rather
  than left to its SDK. A tool call is sent with a deadline
  (`core.mcp.breaker.call_timeout_seconds`, derived from capa's budget by
  default) and a call that passes it is a transport failure the breaker counts.
- **A quoted search argument searches for what is inside the quotes.** Every
  argument a sidecar tool searches for or looks up by — `pattern` on `strings`
  and `floss`; `text`, `technique_id`, `ids`, `api_names` and `query` on the
  knowledge lookups; `ip_address`, `domain` and `file_hash` on `threatintel` —
  is read without one matching pair of surrounding quotes, as `carved_path`
  already was, and each tool's description says the argument is the raw text,
  unquoted. A pattern sent as `"CreateMutex"` with its quotes used to match
  nothing although `CreateMutexW` was among the strings. Nothing else is
  rewritten, and the repair is recorded: the ledger keeps the arguments as the
  model wrote them and a structured answer carries `read_as` first, the value
  each argument was read as.
  **Upgrading:** a consumer that reads the first key of a `strings`, `floss` or
  knowledge answer will find `read_as` there when a quoted argument was read;
  an unquoted call's answer is unchanged.
- **The triage pack's reputation line states the detection labels.** A
  VirusTotal answer that carries `detections` (one result label per engine,
  as VirusTotal's own MCP server answers) and no popular threat classification
  used to render as `VirusTotal 52/75 malicious` and nothing else, although
  the labels named a family eight times. The line now counts the labels
  exactly as written and names up to twenty with how many engines gave each,
  most first, with the number of distinct labels it left out. Nothing is
  merged, normalised or read for a family.
  **Upgrading:** the reputation line of a pack is longer (about 700 characters
  for 50 labels) and counts against `reporting.upstream_findings_max_chars`
  like every other line.
- **No sandbox observation is stated where no sandbox ran.** The mock
  sandbox's empty stand-in for a sample it has no fixture for used to reach
  the triage pack as "sandbox processes: 0 processes" and "no network activity
  recorded", and a report built on it spoke of what the sample did during
  sandbox execution. Where no sandbox ran — no report, or the stand-in — the
  pack now writes one `sandbox_status` entry that says so in one sentence and
  none of the sandbox views, `sigma_match_sandbox` or `lolbin_lookup`; the run
  carries the degradation reason `no sandbox ran …`; `run_summary.sandbox`
  holds `{status, statement}` and the report's run summary prints it; and the
  entry becomes the report's *Sandbox* section, on the console's dynamic tab.
  A report the mock read from a fixture file is marked `recorded_fixture` and
  said to be a recorded fixture, not a live detonation, before its contents.
  A live sandbox's report is read as before.
  **Upgrading:** the pack's ledger ids move, differently per case (a PE's pack
  as the example). With no sandbox report, `sandbox_status` is added before the
  reputation lookup, which moves by +1 (`ev_0010` → `ev_0011`). With the mock's
  stand-in, `sigma_match_sandbox`, `lolbin_lookup` and the five sandbox views
  (seven entries) give way to the one `sandbox_status`, so the reputation lookup
  moves by −6 (`ev_0017` → `ev_0011`). With a recorded fixture, `sandbox_status`
  comes before the sandbox views, so every sandbox view, the capture summary
  when there is one, and the reputation lookup move by +1. A stand-in run is now
  marked degraded with its reason, as a run with no report already was;
  `run_summary` has a `sandbox` key (`null` when a sandbox observed the run).

- **The exported STIX bundle names its producer, in STIX's vocabulary.** The
  platform's `identity` was `identity_class: "software"` under a new random id
  every run, the report object was typed `"malware-analysis"`, and no object
  carried `created_by_ref` — in all forty stored exports, with an OASIS warning
  for each word. The identity is now `identity_class: "system"` under one
  derived id, `identity--9f9e2570-073b-5b46-b156-05d12a086911` in every export;
  every other object carries `created_by_ref` naming it, and the report is
  typed `"malware"`. **What a consumer does:** a filter on `report_types`
  containing `malware-analysis` or on `identity_class: software` stops matching
  new exports; match `malware` and `system`, or the producer's
  `created_by_ref`.

- **The judge's prompt asks for what the judge decides and agrees with the
  checks.** It said *"Omit technique ID if unsure"* while `attck.missing_id`
  asks for the id or for the object to go — the code the judge's one retry was
  spent on in ten of the twenty-four stored runs that retried. It now says an
  attack-pattern names its technique in `external_references` and a behaviour
  with no id belongs in `severity.rationale`. It no longer asks for
  `created`, `modified`, `spec_version` or `valid_from`, which are stamped after
  the answer (about a fifth of what the judge wrote for its objects, beside the
  ids, which are minted now too), names the two relationship types the bundle
  uses, and says a relationship credits sources by the names the evidence
  summary gives them. **What changes for a reader:** an unmapped behaviour is
  more often in the severity rationale than in the report's unmapped-behaviour
  list, and an indicator's `valid_from` is the analysis time rather than a
  date copied out of the STIX documentation.
- **The report reads as a vendor's malware analysis.** The Markdown, HTML and
  PDF follow one numbered layout — key findings, sample overview, verdict and
  assessment, execution flow, technical analysis by capability, observed
  behaviour, static properties, ATT&CK, indicators, detection,
  recommendations, attribution, limitations and four appendices — and every
  H2 names its voice: Measured, Observed in sandbox, Assessed by the judge or
  Written by the report model. A confidence prints as its number, a fixed word
  for it and its producer. The title names the family and category when the
  judge named a family. The tool failures and evidence counts move from the
  header to §13; the header keeps one line pointing there. A reader or a
  script that finds sections by their old headings (`## Sample
  Identification`, `## Severity & Impact`, `## Executive Summary`, `##
  Network IOCs`, `## Evidence`, `## Run Summary`, …) must look for the new
  numbered ones.
- **Network indicators in the Markdown, HTML and PDF are defanged by kind**,
  in tables, in model prose and in the evidence appendix. The JSON report,
  the STIX bundle, MISP and `/reports/{id}/iocs` stay live.
- **`consolidated_iocs` stores live values with their kind, source, context
  and the publish rule's answer** (`published`: `yes` or `no: <reason>`), and
  the report prints it as its indicator section. A consumer that read the old
  defanged `value` now reads the live one.
- **With no narrative, the report writes no prose.** The fallback no longer
  fills the executive summary, capability paragraphs and a recommendation from
  a template; the report records `the report model wrote no summary: <why>`
  among the degradation reasons and says it in §1. A mock run's summary and
  recommendations are empty.
- **The recommendation category is the model's own.** It was re-derived from
  the action's wording and overwrote the model's answer.
- **The console's SUMMARY tab draws the key findings and the technical
  analysis**, labelled as the report model's; IDENTITY adds the header facts,
  STATIC the export ordinals and addresses, ATTRIBUTION who named the family
  and the entries cited.

- **The judge's verdict call and each composer section wait as long as their
  answer takes at the model's measured pace.** At 3.8 tokens a second a 600 s
  verdict call could receive about 2,280 of `judge_max_tokens`' 8,192 and a
  120 s section about 456 of its 900. Every model the container builds now
  carries a meter that reads each answer's generation count and time as it
  returns — Ollama's `eval_count`/`eval_duration`, otherwise the output token
  count over the call's wall clock — and those two calls wait
  `max(configured, min(max_tokens / rate × 1.5, 1800 s))`
  (`llm.generation_rate`), a composer section twice that for its one
  validation retry. With no rate yet the configured value stands. Rates are
  kept per model and server, and each answer of a model list counts against
  the model that gave it. The 1,800 s ceiling is the providers' shared request
  timeout. The verdict call starts its model list on its own wait; the report
  stage starts the reporter's list once and each section measures its turn
  deadline against the section's wait with the job's share, so a switch holds
  for the whole report stage and a stalled first model is not waited out again
  in every section.
  `run_summary.generation` records each model's rate and source and each sized
  call's configured, derived and applied seconds, and the report's Run Summary
  and the run summary's markdown print them.
  **Upgrading:** a slow model's verdict call and composer sections can now run
  up to 1,800 s each where they were cut at 600 s and 120 s, so a job on such a
  model can take longer before a section is dropped; a fast model's timeouts
  do not change. `run_summary.generation` is a new key, absent on a run that
  measured no answer.

- **A composer section is capped at `composer_section_max_tokens`, and an
  Ollama model at its configured output cap.** The composer ran on the
  reporter's model, built with `judge_max_tokens` (8,192), so a section could
  generate nine times the 900 tokens its setting names; its model is now built
  with `core.reporting.composer_section_max_tokens` as its output cap, plus
  `judge_max_tokens` of room for reasoning where the model's provider has not
  been told to keep reasoning out (`disable_thinking`), each model of the
  reporter's list by its own provider. And `ChatOllama`
  drops a `max_tokens` it is handed, so on Ollama no cap reached the server at
  all — not the judge's, the analysts' or a section's; the Ollama provider now
  passes it as `num_predict`. A section the cap cut is recorded as cut at that
  cap, the verdict call records whether it reached `judge_max_tokens`, and
  Ollama's `done_reason: "length"` counts as a cut.
  **Upgrading:** a model's reasoning counts against these caps — Ollama's
  `num_predict` and llama.cpp's `n_predict` include the thinking channel. A
  composer section longer than its cap is now cut by the model server, and on
  Ollama the judge's answer at `judge_max_tokens` and an analyst's at
  `expert_max_tokens`, reasoning included. With a reasoning model, set
  `disable_thinking` or raise the cap where a section or verdict comes back
  empty or cut.

- **A PE's decoded strings are in the triage pack.** A static analyst offered
  `floss` among thirty-six tools never called it, so the configuration an
  analyst recovers from an encrypted-string loader reached no model. The pack
  now runs FLOSS once on every PE, last, through the function the sidecar's
  tool serves (the pinned build, its wall clock and memory limit), with the
  `analysis` server's environment and a directory in the job's staging
  directory, and every agent reads one line of it: the counts, then up to 100
  strings in 3,000 characters, each with the routine that produced it and its
  offset from the image base, the bound and its reason stated when it cut, and
  a statement that the strings are the sample's own text: data, not
  instructions, ledger entries or findings.
  Without a build the entry says so with the remedy and is not a failure; a run
  stopped by its clock or its memory is a failed entry that says which. On the
  reference loader the line carries all 81 strings and adds about 28 s to the
  pack. The tool's description now says to call it when a PE's strings look
  encrypted or are missing.
  **Upgrading:** a PE's pack has one more entry, `floss`, after every other;
  the pack's own ids do not move, and every id after the pack (the analysts',
  the judge's) moves by +1 on a PE. A test suite that runs the pack sets
  `MALJAN_FLOSS_PATH` to a missing file unless a test names a build.

### Fixed

- **A confidence is read through the punctuation after it.** A CONFIDENCE
  value is the number that opens it, from 0 to 1, or a percentage: `0.9.` read
  as no number, and one analyst's 18-claim revision reached the run as 3
  claims with nothing unread. A label with anything else after it is an unread
  claim whose value the unread reason quotes and the validation turn asks
  about; a bare number above one is no longer held to 1.0.
- **A revision is checked like a first answer, and one with fewer claims is
  stated.** A revision round's answer now passes the consistency gate and the
  validation turn (claim count, confidence, technique lines). A revision the
  model made with fewer claims still replaces the answer in force, and
  `run_summary.negotiation.revision_replacements` states it.
- **Names resolved at runtime from hashes are not imports.** `api_capability`
  takes `resolved_names` and marks them; the triage pack records one more
  lookup after `resolve_api_hashes` with the resolved names the import table
  lacks; the report's projection also reads
  the ledger's `resolve_api_hashes` answers and counts such names apart
  (`static.api_capabilities_resolved`, `resolved_apis` on a rule row). The
  ATT&CK table no longer prints them as "imports". A rule that matched only
  such names is named as a source "rule match on names resolved at runtime from
  hashes only, no import; not counted as corroboration", and each analyst
  statement naming its technique is printed verbatim beside it.
- **An ATT&CK row no longer says "claimed by no analyst" of a technique
  analysts named on a finding.** The row names those analysts, the sources the
  run's corroboration record lists.
- **One refused call no longer ends the job.** A refusal used to latch the
  spend as exhausted: in a 2.00 USD DeepSeek run one mediation turn refused at
  its whole cap stopped every revision after it with 0.12 USD still
  spendable. A refusal is now recorded (`run_summary.spend.refused_calls`,
  and the run summary's spend lines) and its caller takes its salvage path. A
  call that does not fit only because other calls in flight hold their worst
  case waits for them to settle, for as long as its own deadline allows. The
  spend is exhausted only when the ceiling is reached, or when, with no call
  in flight, no call of any kind made since the latest stage began would
  still be admitted at the smallest prompt it was sent with.
- **The judge's mediation turns are held like an analyst's.** The mediation
  loop handed the bare model to the ReAct executor, which bound the tools
  itself, so no turn could be held and each was admitted only at its whole
  cap. The model is bound to its tools before the loop and each turn's held
  cap is set on that binding.
- **An indicator the static decoder read stands where FLOSS's would.** The
  publish record (`emulated_strings`) reads `decode_string_blobs` results as
  a second source of hidden text the platform recovered: each domain, address
  or URL the existing parsers read in a result's text or in a base64 layer
  under it is recorded with the decoder's entry and asked the one rule's
  questions exactly as a FLOSS decoded string is, with the reason "decoded
  from the file's own bytes (decode_string_blobs), ev_NNNN". A value the
  static string sweep also read stays the sweep's, and a decoded text holding
  no indicator is no candidate. The record keeps every tool that recovered a
  network value (`recovered_by`: tool, entry, scheme, file offset, functions
  and the addresses of the code that uses the text, each tool with its own
  facts only; a FLOSS decoded string reads "routine X, called at Y"), and the
  IOC table states it on the row (`ConsolidatedIOC.recovered_by`, printed in
  the report's Context cell); `/iocs` carries the same words as an optional
  `recovered_by`, which the web `IOCRow` type declares. The refusal for a
  value the sweep also read now ends "so not a value the sample hid", since
  it answers for both tools. A recovered value still only gives standing to a
  row the sandbox, the sweep, an analyst or the judge recorded; it creates no
  row.
- **FLOSS strings are read by the same indicator reader.** A FLOSS decoded,
  stack or tight string is still kept whole in the record, and each domain,
  address or URL the reader finds inside it is now recorded too (in the
  ledger record and in the kept-rows reading of an older report). A
  `host:port`, a `Host:` line or a URL inside a sentence recovered by FLOSS
  was missed and now gets the standing the same text from the static decoder
  gets, so such a value named by a model may now publish where it did not.
  Replayed offline on the benchmark's 23 stored runs (their evidence and
  report, under each run's own verdict and again with the verdict forced to
  malicious), the one reader added and dropped no published row: on the
  benign control it finds only a value already kept whole, and on the other
  runs the hosts it finds were already published through their URLs. No
  stored run holds a `decode_string_blobs` entry, so the decoder half is not
  measured by that replay.
- **A stored reverser row saved under an earlier release loads as the seed again.** The two
  reverser prompts shipped before the dispatcher-branch and resolved-hash paragraphs were not
  listed in `FORMER_SEED_PROMPT_DIGESTS`, so a database that had saved the definition map under
  either of them held a `reverser` row that no longer matched its seed, and every settings save
  was refused ("'reverser' is built in; clone it to change it"). Both digests are listed, and a
  test pins them.
- **Every claim an analyst begins is read, or the run says it was not.** The
  base analyst's reader split an answer only on `---` lines and kept the first
  `CLAIM:` of each block, so claims separated by blank lines were read as one:
  a revision of 13 claims and an answer of 21 each became one, silently. Every
  path now reads claims through one reader (`base_agent.read_claim_blocks`),
  which splits at every claim heading, plain, numbered or marked
  (`agents/claim_headings.py`), and counts the headings the model began
  against the claims read. Claims begun and not read (a block the reader could
  not split, one the static, dynamic and network analysts' stricter reading
  turns away for want of an EVIDENCE line) are logged and recorded as a
  degradation reason naming the analyst and both numbers, for the answer in
  force; a block that stated no confidence is counted apart and asked about,
  as before. Every heading opens a block, so a claim is never read with the
  next claim's CONFIDENCE, TECHNIQUE or EVIDENCE; list-marker headings count;
  fields are read in the block's tail, from the first line-start field label,
  where a label also counts after whitespace (EVIDENCE, CONFIDENCE and
  TECHNIQUE on one line are all read), and never from the claim sentence.
  EVIDENCE runs to the next field label that starts a line when one follows,
  so a label word inside the evidence never cuts it or drops an id after it. The DISPUTES section opens at
  its case-sensitive label or heading, a one-line `DISPUTES: NONE` opens none,
  and claims under it are recorded when none of the answer's own was read;
  beside the answer's own claims, the analyst is asked once whether they are
  its own (`isr.claims_under_disputes`). Kept there when asked, they are the
  analyst's answer, recorded in the validation findings as answered (listed
  "(answered)", not counted as left unresolved, drawn muted in the console)
  and not a degradation; an answer the question was never put to says so as a
  degradation reason. The reason is kept on the answer and carried only for
  the answers in force.
- **A technique line is one id, or it is kept whole and asked about.**
  `TECHNIQUE: T1027.002 not supported` was read as a claim of T1027.002, and
  `T1055, T1106` as T1055 alone. A line that is more than one id or `NONE`
  now claims no id, is kept on the claim as `technique_line`, and the
  analyst is asked once for one id per claim (`isr.technique_line_unread`).
- **No request sends a tool call without its reply, on any provider the
  pipeline builds its models from.** A turn whose call had arguments cut
  mid-string kept that call in `invalid_tool_calls`, which the tool node does
  not run and the OpenAI client still writes into the request; DeepSeek
  answered the next request of a revision loop with 400 ("An assistant message
  with 'tool_calls' must be followed by tool messages …") and the analyst was
  lost for the round. The Responses API (a `function_call` needs a
  `function_call_output`), Anthropic (a `tool_use` needs a `tool_result` at the
  front of the next user turn) and Gemini (a `functionCall` needs a
  `functionResponse`) refuse a call left unanswered the same way. One module
  (`maljan.llm.tool_replies`) now completes every provider's request in its
  own shape: a call with no reply anywhere in the conversation gets one saying
  no reply was recorded, and that it was not run when its arguments did not
  parse, in the turn's call order — after DeepSeek's reasoning passback on
  `openai` chat completions, as a `function_call_output` item on the
  Responses API, as a `tool_result` block on `anthropic`, as a tool reply the
  Gemini client pairs with the right call, and as a `tool` message on
  `ollama`. A reply that was recorded is never said missing: where a chat
  shape needs it right after its turn and it stands further on with only
  platform messages between, it is moved to its call; after a later model
  turn it is neither moved nor replaced, and a warning names the call. The
  completion never changes who speaks last in the request. The call stays in
  the turn as the model wrote it, and a
  well-formed history is sent as it was. The evaluation harness's frontier
  comparison arm, built outside the providers, is not completed.
- **A guest's desktop process is not the sample.** Where Triage's `orig` mark
  and the submitted file's own process tree (its name or digest) disagree
  about a process, the flow's attribution is absent rather than `true`; where
  they agree it is `true`, and a listed process neither names is `false`. A
  desktop process that ran none of the sample's files and descends from none
  of its processes had been read as the sample on the mark alone. Such a flow
  is refused by the one publish rule unless a model keeps the address, and the
  `no:` and the IOC table's context name the process and both facts
  (`… StartMenuExperienceHost.exe (procid 105), which Triage marks as the
  sample's but which runs none of the submitted file's names …`); STIX,
  `/iocs`, YARA, Suricata and Sigma read that one answer. A mark that names a
  process the file's tree does not is no longer the answer on its own.
- **Each model call is paired with its own admission.** The guard over model
  calls counted any admission before a call, so one covered any number of
  calls after it. It now pairs calls one to one in source order (two branches
  of one choice are one call; a call in a loop needs an admission in the same
  loop's body), and the judge's technique question in text, asked after a
  refused schema, is admitted on its own.
- **A stage-named analyst's debate line reads as a place:** "from analyst 2 of
  3 in the analysis stage", where it read "from the analysis analyst 2 of 3
  layer".

- **A revision that is not made leaves the analyst's answer in force.** A
  revision that failed (a refusal by the spend ceiling among them), wrote no
  answer (a composed analyst whose loop was not started) or carried no
  structured report used to replace the analyst's first answer with an empty
  one, and the judge then weighed no technique. The answer in force now stands
  whole, the revision's ledger entries and budget rows are still kept, and the
  debate line names the analyst by its label with its real claim count: a
  25-character agent key was published as `***` inside the sentence. An agent
  with no label and a key of 24 characters or more is named by its stage and
  its place in it (reversing analyst 1 of 2), so no two agents are named alike.
- **Numbered claims are read.** The claim parser reads `CLAIM 3:`,
  `CLAIM 4 (REVISED):` and `CLAIM 5 -` headings and claims written one after
  another with no `---` line between them; a revision written that way was
  read as having no claims. A heading opens a block only where one can begin
  (first, after the open block's CONFIDENCE line, or after a separator line),
  and nothing under DISPUTES is read as the analyst's own claim.
- **A report section cut with no text is not asked again at the same cap.** It
  is asked again only when the second call has more room, and is otherwise
  recorded as not written, with the limit that applied and its source.

- **A stage runs once, after every stage it depends on.** The builder wired one
  edge per upstream tail, and in LangGraph separate edges into one node are
  separate triggers. In the all-tools team, detonation (after static and
  reversing) ran twice and network (after static, reversing and detonation)
  three times, the first passes without the reverser's findings; negotiation
  ran three times, the judge twice, and the report shared a superstep with the
  second judge, so the run ended in `InvalidUpdateError` on `run_summary`
  after the report was built. A node with more than one upstream tail is now
  entered through one list edge that waits for all of them, and a debate whose
  next stage also depends on another stage leaves through its own
  `<stage>__join`. The seeded teams' graphs are unchanged. `run_summary` keeps
  no reducer: two verdicts must never be merged into one.
- **A report that was built survives a later step failing.** The graph ran
  with `ainvoke` and no checkpointer, and the worker stored a report only on
  success, so a run that failed after its report node finished lost the report
  (in the all-tools run, 234,362 characters and 55 STIX objects). The graph now
  runs as a stream in the modes `ainvoke` uses, the app keeps what the report
  node returned the moment it returns, and a job whose graph then raises stores
  that report against the failed job with `analysis_reports.incomplete_reason`
  (migration `20261001000000`): where the run failed, the exception's class and
  the error id. The sentence is also among the report's degradation reasons,
  and the console shows it in the analysis header. The job stays `failed`.
- **The long-term-memory case is written once, for a completed job.** The
  judge wrote the case from inside its node, so a failed job still taught the
  next run its verdict, and a judge that ran twice wrote it twice with two
  different categories. The judge now holds the case and the worker writes it
  after the completed row is committed and the `completed` event is published.
  The function hashes the judge files under its family in the attribution
  corpus are held and written the same way, so a failed job files none.
- **radare2's logged errors are failed calls.** r2mcp hands back what radare2
  logged inside a `<log>…</log>` envelope, and `<log> [ERROR] Cannot find
  function in 0x00003ce4 </log>` was recorded as a successful
  `decompile_function`. A reply that is only such an envelope, of radare2 log
  lines with an `[ERROR]` or `[FATAL]` among them, is now a failed call whose message is
  radare2's lines.
- **The tool-call threshold is worded as the warning it is.** The log line read
  "spent 83 tool calls (budget=20 …)", an overrun of a limit that does not
  exist; it now reads "made 83 tool calls, past the tool-call warning threshold
  of 20 (not a limit; …)".
- **The MCP close from another task says what it means.** Every job ended with
  "MCP cleanup cancel-scope warning (non-fatal)" once per server. A test that
  opens a stub stdio server and closes it from another task shows the server
  process gone (one that ignores its closed stdin is terminated by the
  transport) and no task left, so nothing leaks: the refusal is anyio's
  task-group bookkeeping. The line is now an info line saying the connection
  was closed from a different task and the transport's own shutdown still ran.
- **A Ghidra that cannot open the job's sample stops its agent.** With
  `GHIDRA_CONTAINER_SAMPLES_PATH` set to a host path the container cannot see,
  `load_program` answered HTTP 200 with `{"error": "File not found: ..."}`,
  every call after it answered "No program loaded", the sink pre-pass was
  skipped quietly, and with no default loop limits a reverser would have
  called Ghidra with nothing loaded until the spend ceiling. The load the
  pre-pass makes is now the precondition of an agent's loop on Ghidra over
  http, made whether or not the pre-pass is on: a load that opens nothing, or
  a request that fails, raises `SampleNotOpened` with "Ghidra could not open
  the job's sample: <the server's words>; check GHIDRA_CONTAINER_SAMPLES_PATH
  / the container mount" before any model turn. Inside a loop the pinned
  `load_program` of the held path that answers with an error is filed as a
  failed call and ends the loop at once, with nothing salvaged. The provider
  remembers the path, so no later loop of the job (another chunk, an ask)
  calls Ghidra for it. The stage records the agent as failed with the
  sentence, the run's degradation reasons name the analyst failure, the rest
  of the team runs, and an agent that asked the stopped one reads a failed
  ask. The live feed keeps the variable's name in the sentence
  (`GHIDRA_CONTAINER_SAMPLES_PATH` is no longer read as a credential).
  A load that got no answer from Ghidra (a connection that failed twice, a
  5xx, a refused token) says so instead, naming Ghidra's address and
  `core.static.ghidra.auth_token`, is retried once for a failed connection,
  and is not remembered, so a Ghidra that comes back is asked again. The
  failed entry of a pinned load records the path sent, and a stopped agent is
  left out of the debate's rounds rather than failing each one.
- **Every Ghidra error reply is a failed call on the ledger.** A bare
  "No program loaded" answer (the whole answer, case aside) and an HTTP error are handed on as JSON markers
  (`tool_error_marker`) with the server's words, the way the MCP client hands
  on an error reply, so the ledger files them `ok=false`; a
  `{"error": ...}` reply already was.
- **The console's context window read the fallback for a model whose server
  lists its own.** `GET /api/v1/settings/context-window` probes on the API's
  loop, and its answers stream asynchronously; the body was read with the
  synchronous reader, the error was swallowed and the probe learned nothing,
  so DeepSeek showed 8,192 (fallback) where the worker learned 1,048,576. The
  async probe reads its answers with an async reader under the same bound.
- **A reverser on Ghidra under another global provider had no sample to
  load.** The worker mirrored the sample only for the global provider and the
  `static` role's; a generic agent with a provider reference, and an agent a
  lead can ask, now count, so the mirror exists for every provider the team
  opens.
- **r2mcp installed by r2pm was not found.** `static.r2.binary_path` is
  resolved when the provider starts: a path as it is, a bare name on PATH and
  then under `R2PM_BINDIR`, `R2PM_PREFIX/bin` and `radare2/prefix/bin` in the
  user's data directory. Not found, the run summary says so with the remedy and
  the log names every place looked; the connection test resolves the same way.
- **A seeded definition saved before its prompt changed was renamed.** A stored
  seeded row whose prompt is one the seed shipped with earlier
  (`FORMER_SEED_PROMPT_DIGESTS`) loads as the seed instead of becoming
  `reverser_custom` with every reference rewritten.
- **A degrading static provider that did not attach was a log line only.** It
  is now a degradation reason on the run summary, with its remedy.
- **A model call's whole-call deadline is that call failing, not the loop's
  clock.** In a loop with no time limit a lone model that ran past it ended
  the analyst with "exceeded hard cap of none" and its gathered evidence
  unwritten; the tool phase ends there now, the salvage writes the answer, and
  the budget record's detail says "model call deadline". A fallback list still
  moves on to its next model.
- **The spend is exhausted at the first call refused or held for it.** Every
  gate (new tool loops, chunks, asks, negotiation rounds) and the degradation
  reason read that latch, not only the ceiling being reached;
  `run_summary.spend` records `exhausted`, `exhausted_at_usd` and
  `exhausted_by` ("reached" or "a worst-case refusal"). A held call — the
  verdict, a report section or a loop's closing answer — is given what the
  remaining spend pays for and never less than 8,192 output tokens (or its own
  cap when smaller); the overshoot is listed in `held_calls`. A call refused
  for spend is reported as the ceiling's reason, not as an analyst failure.
- The streamed-call deadline applies per chunk, so a consumer between chunks
  sees `ModelCallDeadline` and no task is left cancelling; the judge's spend
  admission counts tool calls, reasoning and tool definitions as the analysts'
  does; a process-group kill never signals the server's own group and skips a
  child already reaped; a capa worker that exits without an answer is logged
  as such; the MCP request id is read in one helper with a test pinned to the
  installed client.
- **Every model request has a whole-call deadline.** Maljan enforces the
  request's sized timeout (its output cap at the measured pace, or the
  client's own 1,800 s where nothing is measured) over the whole call; the
  client's timeout is only the longest silence httpx waits through, which a
  server trickling keep-alive bytes never reaches. Ollama is held to it too.
- **The judge's tool loop has the analysts' repeat guard**, and its running
  turns are priced under its own model label, so they move the spend and trip
  the ceiling (a lone model's unstamped turns were priced at nothing).
- **capa and FLOSS on the analysis sidecar**: the client waits for them with
  no deadline unless the operator set one, their timeouts and cancellations
  are not breaker failures, a call the client gives up on or a job that ends
  is cancelled at the server, which kills the child process with its process
  group, and a retry of the same run joins the running one.
- **String IOCs are all returned.** The 120-row cap and the per-kind quotas in
  `iocs_from_text` / `iocs_from_file` and the static extractor are gone; the
  tool-answer sizing and paging carry the rest. The report's IOC table grows
  with them on a sample carrying many paths or URLs; that is intended. `apk_info` states the full
  count of every list its `limit` cut, a YARA match states its length beside
  its hex, a sandbox API row states how many processes called it and marks
  the arguments it cuts, and a carved-file refusal counts the names it does
  not list.
- **The spend ceiling ends the run's rounds.** Once it is reached no further
  negotiation round, chunk or tool loop starts; before any call, one whose
  worst case would pass the ceiling is not made unless it is the verdict, a
  report section or a loop's closing answer, which are held to the output the
  remaining spend pays for and recorded in `run_summary.spend.held_calls`.
  Price keys keep the model's tag; unreported usage is counted and the spend
  said as "at least"; the summariser's shortened prompt is a degradation
  reason; a no-clock delegation wait stops when its job is cancelled.
- **A chunked analyst's validation turn runs under the agent's lock**, as the
  single-chunk path's does, so a delegated ask of the same agent cannot land
  between the findings buffer's mark and slice.
- **A claim is kept whole.** Both claim parsers stored a claim cut to 300
  characters with no mark; in a paid run 26 of 40 claims were cut mid-word and
  every `attck.claim_does_not_describe` question was asked over a cut
  sentence. The claim is stored as written. A model value quoted in a finding
  row is still bounded where it is shown, and now ends in the cut mark. A
  claim's evidence reference cut to its width writes back every id the cut
  removed, not the first three.
- **An analyst's validation retry answers in claims.** The retry was shown the
  first answer as a summary of its parsed claims and told to "answer again in
  the same format"; the model answered in the summary's shape, the parser read
  no claim, and the first answer was kept with its findings unresolved. The
  first answer now goes back as the model wrote it, CLAIM blocks and findings
  block included, the closing line names the block format the parser reads,
  the retry's text is logged at debug and its claim count is recorded on the
  loop's budget record (`validation_retry`). Tool-call markup is left out of
  the replay; with the consistency gate on, the answer is replayed whole and
  the question names the claims the gate set aside.
- **Findings follow the answer that is kept.** A retry's findings block was
  read into the agent's buffer before the kept answer was chosen, so a
  discarded retry's findings were published with the first answer. They now
  travel on the retry's own ISR and go with it only if it is kept; a kept
  retry that carries none while the first answer had some is logged, and
  `validation_retry` carries both counts.
- **The judge's text is kept whole.** The fallback verdict's reasoning was cut
  to 2,000 characters with its line breaks folded, and the text mediation
  summary to 500, neither with a mark. Both are stored as written.

- **The network analyst gets the capture.** With exactly one capture in the
  job, `pcap_path` is hidden from the schema the built-in network tools are
  bound with and filled in, like the sample's own path; with several it stays
  the model's, a relative name is read inside the job's directory, and a
  refusal lists the job's captures (`captures/<file>`) or says there is none,
  instead of telling the model to leave out an argument the tool requires. A
  live network analyst lost 8 of its 20 calls inventing capture names. The
  pack's capture entry and the sandbox report's network section name the
  capture relative to the job, never by host path, and a filled-in capture the
  server cannot read is said to be the platform's, by its job-relative name.
- **Every capture tool reads the whole capture.** The network server read the
  first 5,000 packets by default and the in-process summary the first 200,000.
  All of them stream the capture (`analysis.pcap_summary.each_packet`),
  `packet_limit` has no default, and every answer states the packets read and
  the packets in the capture (`pcap_summary` as `packets_read`,
  `packets_in_capture`, `packet_limit`, beside its protocols, every external
  conversation, SNI names and periodic contacts). `read_pcap_summary` with no
  limit answers those facts; with one it lists packets from `offset`, paged.
- **The pack shows what the capture holds.** Its capture line carries the
  packet count, the protocol counts and the external conversations heaviest
  first, cut only by the pack's own room with the cut said, where it printed the
  summary's heading alone and a report then said the entry held only a header
  line. A key-finding or section sentence whose subject names a cited entry
  (its id, or a word for a recorded answer beside the entry's tool) and says it
  holds nothing or one line is checked against that entry and asked once when
  it holds more (`report.entry_contents_misstated`); a sentence about the
  sample is never judged, and no sentence is rewritten.
- **Sandbox background traffic is not published as the sample's C2.** Triage
  flows carry `procid`, `pid` and AS facts, and each tcp/udp row states
  `sample_process_tree`: true for the process Triage marks `orig` (only it,
  when it marks one; otherwise a process running a file named exactly as the
  submission or the sample's digest) and its descendants, false for another
  named process, absent when the report does not say. The sandbox view marks
  public resolvers, and the network block, projected from the job's whole
  report, carries the attribution, the resolver fact, `kept_by` and
  `mentioned_by`. A sandbox address the sample's tree did not make, and a
  well-known benign name the guest resolved, is published only when a model
  keeps it as an indicator (an analyst's artifact, or the judge's indicator);
  a claim that mentions it keeps nothing and is named in the reason. Only an
  `endpoints`, `network`, `iocs` or `c2` artifact keeps; in it a row's one
  type cell ("C2 domain", "ip:port" and aliases read by their last word)
  types one value cell, a row typed as a file, path or hash keeps nothing, and
  every other cell is read untyped, only in an endpoints or C2 list and never
  as a file name there; a name typed as a
  domain, host or URL is the model's statement and is kept whatever its TLD. The value is read
  tolerantly (a port, IPv6 brackets, case, a URL's host), the judge's URL
  indicator keeps its host, and the analysts' findings block states the
  `endpoints` row shape. Otherwise
  the IOC table carries it as `no: <reason>, and no model kept it as an
  indicator`, and the STIX bundle, `/iocs` and the YARA, Sigma and Suricata
  drafts read that answer. **Upgrading:** CAPE, REST and mock reports carry no
  process on a flow, so every address they record now waits for a model to
  keep it; expect fewer sandbox addresses in `/iocs` on those deployments. A
  live run published a public resolver and a connectivity check as C2.
- **A published URL carries its name.** The host of every URL the publish rule
  publishes follows the URL's decision, unless it is a well-known benign host
  no model kept; the IOC table, the export and `/iocs` add it as a domain row
  and indicator where nothing else did. A live run published two C2 URLs from
  the judge's bundle and neither host.
- **Nothing cuts the sandbox views or the export.** The sandbox tools answer
  every row unless a caller pages them (`offset`, `limit`, with the total and
  the next offset stated), where they cut every view at 200 rows, and their
  answers go through the same guardrail and context-budget charge as an MCP
  tool's, so a large view is shortened with a notice naming `offset` and
  `limit` rather than filling the window. The STIX
  export carries every value the publish rule publishes — every `yes` row of
  the IOC table — with no total cap, no band ranking that drops, no cap on
  file names and no slice of the network block or the string rows. An address
  a sandbox watched is kept whatever its class, answered `no:`.
  **Upgrading:** an export used to carry at most 15 indicators
  (`MAX_TOTAL_INDICATORS`) and 10 file names; a consumer that relied on that
  bound now receives every published indicator. The two numbers are now only
  the linter's C4 counts, which warn and drop nothing, and the run summary's
  "STIX indicators over the cap" reads 0.
- **Any MCP error reply is a failed ledger entry.** The client's failure
  markers are JSON (`mcp_client.tool_error_marker`); an `isError` reply was
  written as a Python repr and an exception message with a quote broke the
  marker, and both were filed as ok.
- **A Sigma rule title is never a registry key.** A Sigma match is a
  persistence row only when it names a T1547 technique and its event names the
  key (kind by the key, then by the sub-technique); one naming no technique had
  its title filed as a `registry_run` key and printed in section 9.
- **An identifier's purpose.** The host-identifier section is asked for a
  purpose where the evidence or an analyst claim says what the value is for,
  and an empty purpose prints as `not stated` rather than `-`.
- **An r2mcp error reply is a failed ledger entry.** r2mcp answers a refused
  call (an invalid regex, no open file) with an ordinary text result, which
  the ledger filed as ok; the provider now hands such a reply on in the
  structured failure shape with r2mcp's own message.
- **An analyst is told the truth about its tools.** With `static.provider =
  none` the static analyst's system prompt said "You have no analysis tools in
  this configuration" while the same request carried 36 tools from the
  `analysis`, `knowledge` and `virustotal` servers; the model believed the
  prompt, answered in one turn and called nothing. A provider's fragment now
  says only what the provider is (`none`: no disassembler or decompiler comes
  with the analyst; a configured provider whose tools did not attach: that it
  is configured and not attached), and one sentence about tools is built from
  the list the request carries — the servers and in-process sources it names,
  or that there are none. Every built-in analyst, the generic and lead
  agents and the mediator's tool turn build it the same way, and a
  tools-free call — a revision, the validation turn, a lead's synthesis — is
  told it carries none, and the final-answer nudge and the forced synthesis,
  which resend the loop's conversation, say in the system turn that no tool
  can be called in this turn. The static human turn offers
  "decompile, xrefs" only when a decompiling tool is in the list and names
  `load_program` only when that tool is; the dynamic prompt carries the CAPE
  workflow only when the sandbox's own server attached; the network PCAP turn
  names only the packet tools it has; the seeded reverser and lead prompts no
  longer promise a decompiler or `ask_` tools unconditionally. Nothing forces
  a tool call: a model that answers from the evidence it was handed is a
  recorded outcome. A guard test resolves every built-in agent under every
  static and sandbox provider, in the default and measurement teams, through
  `aresolve_agent` and the analyst's own prompt builder, and fails on a "no
  tools" sentence beside a tool list, a tool family the list does not hold, or
  a generic tool-use instruction ("use the tools") beside an empty list. A
  provider's fragment is in two parts: its tool workflow, sent only with its
  tools, and its guidance about claims, sent with every call — a Ghidra
  revision or validation retry keeps the verification discipline and its
  confidence caps. The seeded triage and Android prompts no longer say "use
  the tools"; every seeded prompt asks for the evidence id a fact came from.
  The sentence is built from the list the loop binds, so a server offering
  only the sample-delivery tools is not named.
- **The validation turn stays tools-free, and says so.** It is one call over
  the evidence text that asks for a fix to an answer — its time is what the
  loop left, measured against one answer's pace, and the answer it gets is
  parsed and kept or refused as a whole — not a second loop with its own
  budget, ledger and recorder. Its system prompt now states that the request
  carries no tools instead of repeating the loop's tool sentence.
- **An analyst skipped for want of sandbox data is said to be skipped.** The
  degradation reason reads "analysts skipped (no sandbox data): dynamic,
  network" instead of "analysts produced no claims", which read as if they had
  run; "analysts produced no claims:" names only analysts that ran. The worker
  log says "skipped: no sandbox data" where it said "no data chunks available".

- **A pattern is kept whatever its comparison operator.** The judge's
  integrity pass kept only patterns containing `=`, so every `LIKE` a judge
  wrote was dropped as `empty_pattern` with its relationships — twelve of a
  reference judge's thirteen indicators, its command-and-control hosts among
  them. The pass now drops only an empty pattern. Whether a pattern is one the
  official validator accepts is `stix_pattern.pattern_refusal`, the STIX 2.1
  pattern grammar over the one reader (and the pinned validator where it is
  installed); it agrees with the validator on acceptance. A pattern it refuses
  is asked once (`stix.pattern_refused`) and, kept, declined — never exported
  invalid. A `LIKE` value is grounded by the text between its wildcards (four
  characters at least), lists no row in the IOC table or `/iocs`, and is
  declined from the export with the reason when it names an endpoint or a kind
  the publish rule answers for; one whose fixed text is a value the run holds
  is first asked whether the judge means that value
  (`stix.shape_names_a_value`). A quoted value with a backslash the grammar
  cannot read is asked about (`stix.unescaped_backslash`) and, kept, declined.
- **Every value a judge pattern names is put to the one publish rule, whatever
  the operator.** An `IN` list, a `!=` or a `>` over a kind the rule covers
  reached the export with nothing asked, so a value refused as `=` was
  published inside one. Each member and operand is asked now; the IOC table
  and `/iocs` still read `=` alone.
- **The fallback's export is valid.** A non-Malware fallback wrote a note with
  no `object_refs`, which STIX requires, and the report object named the
  sample's hash indicator twice once the judge's copy was folded into the
  export's. The note names the objects the fallback bundle holds and is not
  written when it holds none; each reference is listed once; an object about
  others that the export leaves naming nothing is declined with a record.
- **The judge's retry after a cut answer no longer carries the cut answer.**
  Its prompt grew by exactly the cap, and at temperature 0 a benign control's
  judge answered with a response one byte shorter than the one it was asked
  about. The retry is the first prompt and the question, which now states the
  length the answer was cut at as the bound and the kind of object it began
  most of.
- **A record says the judge was asked only when it was.** A finding the judge
  was never shown — first raised by the answer to its only retry — is recorded
  `"asked": "false"`, and the export's credit and `is_family` records say "the
  judge was not asked about it" instead of "kept … when asked". "Asked" is
  decided by the code and what the finding is about (the technique a credit is
  for), so a credit renamed in answer to the question counts as asked.
- **VirusTotal's count is written in words.** The triage pack wrote
  "VirusTotal 0/75 malicious", and a benign control's summary turned it into
  "verified clean by 75/75 AV engines". The pack line and the report's network
  reputation cell say "0 of 75 engines flag it".

- **A fallback verdict keeps the indicators its answer wrote whole.** After
  the judge's answer was cut twice the fallback bundle carried no indicator,
  so the decoded C2 hosts the answer had written whole were never put to the
  publish rule and `/iocs` and STIX held only the hashes. Each indicator the
  answer's bundle wrote whole among its own top-level `objects` (read as
  written, no repair; never from reasoning, a string or a nested object) is
  kept with a minted id,
  asked what a bundle's indicator is asked — the findings recorded, an
  ungrounded one dropped — and the export, the IOC table and `/iocs` read the
  one publish rule's answer for it, emulation record and verdict included.
- **The capability check marks claims, not values or absences.** It reads no
  word inside a value — a code span, a quoted string, a path, a registry key,
  or the words of a record's own value that its other fields restate — and no
  section heading. A term ending the subject of "are absent" or "is not
  supported", or the object of a negated verb ("does not import the registry
  APIs required for persistence"), and a term after "rather than", "instead
  of" or "prevents confirmation of", is read as absence, by the absence
  question and the mark alike. capa's and YARA's rule names no longer ground a
  capability word (their sections still count by key), and a sentence whose
  assertion is only that a rule matched ("YARA rule X matched", "capa reports
  the rule Y") is not a claim; one that draws a conclusion from a rule ("Based
  on YARA results, the sample steals credentials") is checked as before. A
  slash-joined list of words is read; only a path-shaped run is a value. A
  negated verb of need ("does not require administrator rights for
  persistence") claims its purpose. The anti-analysis term reads evading
  detection or analysis and packing. A benign control's four marks had sat on
  a configuration path row and two absence sentences, while its keylogging,
  evasion, anti-debugging and "repacked" over-claims went unmarked.
- **A finding the retry's answer first raised is recorded as not asked.** A
  report section's one retry asks every finding of its first answer in one
  question; a finding only the retry's answer raises is recorded with "Not
  asked: it first appeared in the answer to the section's one retry …" and its
  marks say not asked, instead of reading as a question the model left
  unfixed.

- **Techniques are no longer published from absence claims without the
  analyst being asked.** A benign control run published thirteen ATT&CK
  techniques — Rootkit, Credentials from Password Stores, Remote Services
  among them — from claims that said the behaviour was not there, and no one
  asked. The analyst is now asked, and decides. Long-term memory stores as a
  past case's techniques only ids with no absence note and a valid catalogue
  entry, and a noted claim never displaces a positive one when chunk answers
  are merged.
- **The conversation and the run summary agree on a kept answer.** An analyst
  whose retry lost claims keeps its first answer; the conversation used to
  publish its findings as `resolved` while §13 listed them unresolved (an
  unknown id asked four times and kept). The kept answer is checked again
  before any outcome is published.
- **A capability word is grounded only by what the run found.** The words of
  a claim that deny a behaviour, a matrix row the run did not publish, the API catalogue's reference
  rows and the words of the sample's own strings no longer ground one, and a
  word in the evidence grounds only where it is said rather than denied. A
  benign report's "establish persistence", "credential harvesting" and
  "anti-forensics" sentences had gone neither asked nor marked.
- **The STIX report object's type follows the verdict.** `malware` under a
  Malware verdict, `threat-report` under Suspicious or Benign; a Benign export
  had been typed `malware`.
- **A job reaches the queue only after its row is committed.** The API
  enqueued before the request committed; a worker that dequeued first read
  "Job not found" and the row stayed `pending` for ever. A failed enqueue now
  commits the row as `failed`; a worker that finds no row reads again over a
  bounded backoff (about 15 s) and marks a late row `failed` with the reason.
- **A report section the output cap cut is asked once for a shorter answer**
  (`composer.cut_at_output_cap`), instead of being told only that its answer
  was not JSON; how far each cut answer got is recorded. The question
  replaces the cut answer and is sent only when it fits the window beside the
  section's output budget. Both host-identifier
  answers of two benchmark runs ran to exactly 8,192 tokens and the section
  was dropped. The host-identifier contract asks for each value once and the
  kind by what the entry shows (configuration-panel paths had been typed as
  registry keys).
- **The triage pack prints digests whole.** It printed 16-character prefixes
  and the judge copied them out as MD5 indicators.
- **llama.cpp's own timings reach the measured rates.** The OpenAI-compatible
  client dropped `timings`, so no prompt reading rate was recorded on the
  default provider and the generation rate came from the wall clock.
- **An unquoted value cited to the wrong entry is asked about**, where its
  shape makes it an indicator (a digest, a URL, a path or registry key, a
  mailbox, a host, a file name); technical vocabulary and a paraphrase stay
  undecided.
- **A negation is not read as a claim.** "does not perform lateral movement",
  "to prevent lateral movement" and "Lateral movement is absent from the
  evidence", "There is no evidence that the sample exfiltrates data" and "No
  evidence of … such as C2 callbacks or exfiltration endpoints" no longer raise
  `narrative.ungrounded_capability`; a negation reaches only the term it
  governs in its own clause. A mark on a finding the model was never asked
  about (structured output) ends in "; not asked".
- **A derived timeout times the prompt read.** Where the reading rate is
  measured, a composer section's and the verdict's wait is (prompt tokens /
  reading rate + output budget / generation rate) × 1.5.
- **A job whose row already ended is not run.** An enqueue that raised after
  the queue accepted the job leaves the row `failed`; the worker no longer
  runs it.
- **A cancelled job is recorded where the pipeline was.** The worker wrote
  "stopped before any check was reached" for runs cancelled minutes in; the
  record and the `cancelled` event now name the node that was running (or the
  check that stopped it) and carry `seconds_into_run`.

- **A value is grounded however the tool's answer spells it.** A tool answers
  in JSON and the triage pack quotes decoded strings with its own escapes; the
  grounding search compared the plain value a judge wrote with that text and
  called a quoted command line and a Windows path the pack had shown it absent
  from the evidence. `utils.written_forms` names every spelling and the
  haystack asks each of them.
- **A STIX pattern the grammar refuses is asked about, then declined.** A key
  written in brackets (`extensions['windows-pebinary-ext']`) and a property an
  extension does not define are now path problems: the judge is asked through
  `stix.unknown_object_path`, and an indicator that keeps the pattern is
  declined by the export with its record instead of failing the official
  validator.
- **A cut text says it was cut.** A claim's stored evidence, a tool answer in
  a section's bundle, a procedure quote in the ATT&CK table and a claim in the
  live transcript end in `…` where they are shortened (`utils.marked_cut`); a
  report had printed "… This suggests" as the model's sentence.
- **A version number is not an address.** The string sweep read the dotted
  numbers after a version word (`version="6.0.0.0"`, `FileVersion`, `v…`) as
  an IPv4 address; a benign tool got a "C2 IP" alert for one.
- **`NONE` is not an ATT&CK row.** A word for no technique in a finding's or a
  claim's technique field makes no row; the findings table prints it as
  written without calling it a claim.
- **The string sweep's own network rows ground no capability.** A network
  block of swept hosts and addresses let "lateral movement" through the
  ungrounded-capability check; a block grounds a capability only when
  something other than the sweep recorded a row of it.
- **A configuration section is no longer dropped for nulls the contract
  allowed.** Its items carried `"value": null`, which the contract's own line
  permitted and the schema refused twice.
- **A cancelled job stops.** A cancel reached the pipeline as a task
  cancellation, the bridge to the agent loop turned it into an ordinary error,
  a node caught that as a failed mediation, and the graph went on to the judge
  and the report while the worker held connections to the model server and
  ignored SIGTERM until SIGKILL. Each job now carries a cancellation
  (`maljan.core.cancellation`): every graph node checks it on the way in,
  every model call checks it before anything is sent, every call in flight on
  the agent loop is cancelled with it, and a check raises `JobCancelled`, which
  no `except Exception` reads as a failure. The worker sets it on an operator's
  cancel and on its own shutdown, waits for the pipeline at most 10 s, names in
  the `cancelled` event where the pipeline stopped. The revision rounds and
  the view and tier turns now use the model's async call too, so they are
  cancelled in flight like the tool loop. At the process's own exit a thread
  still blocked in a call that cannot be cancelled is left after 10 s, named,
  with status 1; nothing happens when nothing is blocked, and calling the
  shutdown hook does not end the calling process.
- **A mediation that failed states no agreement.** Its round recorded a
  consensus of 0.0 that the run summary published as the final confidence; it
  now records none, with the failure on the mediator's argument, and the run
  summary's `termination_reason` is `mediation_failed`.
- **The validation turn keeps to the loop's time.** It was given the loop's
  whole timeout again after the loop; it now gets what the loop left, and is
  not asked, with a record, when that cannot hold one answer at the loop's
  measured pace.
- **Right or absent, everywhere a confidence is printed.** A packer match read
  from `pe_info` carried a flat 0.50 printed under "Measured", capa technique
  hits carried 0.6 and 0.70, a family the judge named without a number was
  printed "low confidence, 0.00", a YARA rule with no authored confidence got
  0.75 and one below 0.70 was raised to it, and the API catalogue clamped
  authored numbers under 0.65. None of these is stated any more: the packer
  table shows a confidence column only where a match states one, the family
  prints "not assessed", the YARA rule keeps what its author wrote or none.
- **A claim's evidence line is stored at the width the window allows one
  answer**, instead of a fixed 200 characters.
- **The time-cap salvage is sized to finish.** It re-sent the whole
  conversation to a slow model that had to read it all again, and ran into its
  hard cap on every PE sample of the benchmark's small model, still generating
  on the server after the worker gave up. It now sends the task, the pack and
  the latest tool results in what the time left can read and answer at the
  model's measured generation and prompt reading rates, is not sent when not
  even the task fits, and cancels its request at its timeout. What it sent and
  how it ended is in `run_summary.budget.<agent>.salvages`.
- **A second loop's answer counts.** An analyst with no claim was run again
  from scratch through the text path with a fresh copy of its whole budget,
  and what that loop wrote stayed prose. The second loop is now the ISR path,
  runs only when what is left of the analyst's stage holds a turn and a final
  answer at the pace its first loop measured, and runs under that remainder;
  otherwise the stage record's `agent_reasons` says why it did not.
- **An unparsed analyst answer is prose, not claims at 0.50.** It was cut into
  sentences — headings included — each a claim at a confidence nobody stated,
  and the run did not call it a degradation. It is asked once for the claim
  format (`isr.unparsed_answer`); what is still prose is the analyst's report,
  the analyst has no claims, and the degradation reasons name it. A CLAIM block
  with no confidence is counted and asked about
  (`isr.claim_without_confidence`) instead of being given 0.5.
- **A verdict the output cap cut off is told so.** The judge wrote a bundle
  larger than `judge_max_tokens` twice and was told only that the answer was
  not JSON. The prompt now states the budget, a cut answer is asked about
  under `verdict.cut_at_output_cap`, and after a failed retry the fallback
  keeps the assessment the answer stated whole — verdict, confidence,
  severity, family — read through the bundle's own readers.
- **A tool argument that names its own parameter is asked about.** A call
  such as `strings` with `"pattern": "\"pattern\""` is not run; the model is
  asked for the value it meant, the question is counted under
  `tool.argument_names_its_parameter`, and a repeat of it counts as a repeat.
  The unquoted-argument sentence in the tool descriptions no longer reads
  "the raw text or pattern itself".

- **A sandbox capture belongs to the job it was fetched for.** The capture was
  written into one directory under the system temp directory, shared by every
  job and every worker on the host, world-readable, named as a readable
  directory for every sidecar started after it, and removed by nothing — while
  `pcap_path` is a qualified argument the *model* writes. A sample carrying one
  instruction could therefore have a later job read an earlier job's whole
  detonation: the operator's addressing, the C2 exchange, whatever the malware
  sent in the clear. Every provider that fetches one (CAPE, the REST DSL,
  Triage) now writes into a `captures/` child of the job's own staging
  directory, 0600 inside a 0700 tree; the directory is named as a readable root
  for that job's sidecars alone and the root is dropped when the job ends; both
  file-reading sidecars refuse another job's capture by every spelling; and the
  whole thing goes with the job's staging directory. **What an operator does:**
  nothing. What an earlier release left in `maljan-cape-pcap` under the system
  temp directory is swept on the staging TTL, and nothing writes there any more.
  A capture is created 0600 with `O_NOFOLLOW` rather than written and then
  chmodded, and a fetch that fails or returns too few bytes to be a capture
  leaves none behind.

- **A run with no job id of its own removes what it staged.** The command line,
  a settings probe and any script that builds a container used to compose a
  staging directory and leave it for the TTL — and the name was derived from
  the process, so a second run that drew a recycled pid inside that window
  inherited the first one's uploads, carved payloads and capture. The name is
  now per run, the container takes its directory away as the last thing it
  closes, and `maljan analyze` releases the run in a `finally` that covers a
  completed analysis, a failed one and an interrupted one alike.

- **A retirement of the shared agent loop no longer costs a grace period per
  abandoned tool server.** When that loop is retired, every handle bound to it
  is abandoned and its child reaped — and the reap ran serially: SIGTERM, a
  two-second wait, SIGKILL and a log line for each handle in turn, on a daemon
  watchdog thread. One recorded retirement walked sixty-one of them. The set is
  now signalled together, the grace is waited out once, the survivors are
  killed, and the whole set is one log line naming the servers and the counts.
  A test's tool servers are also closed with the test now, so a session no
  longer hands a retirement every earlier test's handles.

- **A process that has finished its work is not ended by its own watchdog.** The
  cancel watchdog is a daemon thread with a ten-second fuse: when a run ends
  inside that fuse it woke afterwards, reaped the sidecars of the loop it was
  retiring — two seconds of grace per handle — and logged. Writing to a stream
  the process had already closed is an error `logging` prints and swallows, and
  holding the stderr buffer lock while the interpreter finalises is a fatal
  error and a non-zero exit on a run where everything had passed. Once
  `sys.is_finalizing()` is true the watchdog retires nothing, reaps nothing and
  says nothing, and nothing it does can leave its thread; the children it would
  have killed are the operating system's to collect a moment later.

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

- **One reader of a STIX pattern, and it reads an escaped quote.** The
  validator and the STIX renderer each split a pattern on its quotes, and
  neither undid an escape: `[file:name = 'it\'s.exe']` was read as the value
  `it\`, the judge was told its own row appears nowhere in the evidence, and
  it spent its one retry on that. They had also drifted about what a quoted key
  is — one decided it structurally, the other from the property name. Both now
  ask `schemas.stix_pattern.read_comparisons`, which gives the object path, the
  operator and the literal of every quoted value, keeps `file:hashes.'MD5'` and
  `file:extensions['pe']` as keys, leaves a `START '…' STOP '…'` qualifier's
  timestamps out of the comparison before it, and reports what it cannot read
  as unreadable so it is declined rather than guessed at. The digest check
  (`malformed_hash_in`) reads through it too, and the dead fourth reader in
  `judge_postprocess` is gone, so the pattern really is read in one place. That
  check also reads `IN (…)`: `[file:hashes.'MD5' IN ('deadbeef', …)]` asserts
  every member is an MD5, and the length rule used to ask the `=` form alone.

- **An endpoint written through a reference is asked the host question.** A
  judge-written `[network-traffic:dst_ref.value = '127.0.0.1']` reached no
  check at all, so loopback, private and documentation addresses in that
  pattern shape were exported with nothing in the run summary saying so.
  `network-traffic:src_ref.value`, `dst_ref.value` and the
  `resolves_to_refs[*].value` shapes are now asked the same question as the
  four direct kinds, and asked whichever of host or address fits the value.

- **A directory is asked whether it is a place, and then whether this run saw
  one.** The grounding check put `directory:path` in the `file:name` branch, so
  the judge read *"has no file extension, no filesystem anchor … so nothing
  says it is a real path"* about a directory it had written, retried on it and
  lost the row. A directory is now asked two questions and told which one it
  failed. Validity: it has a root — a POSIX slash, a drive with either
  separator, a share, an environment variable, a home tilde, a registry hive —
  and at least one named step under it, every step written the way a name is
  rather than as whitespace or as a format specifier the sample was compiled
  with. `/tmp` passes where it used to be refused; `/`, `C:\`, `/%s/%s` and
  `/ /` do not. Grounding: the literal is then asked the corpus question every
  other literal is asked, as a whole value and under the spellings that mean
  the same location, so a shape alone no longer stands in for evidence.

- **A value is found at its own boundaries in the evidence.**
  `whole_value_in` read `/`, `\` and `:` as part of a label, so a host written
  inside a URL, a host written before its port, a mailbox after `mailto:` and
  an address at the end of a sentence were all reported as appearing nowhere
  and the row was withheld from the bundle with a sentence saying nothing
  corroborates it. Those three characters join the parts of a compound value
  rather than extend a part, so each of them now bounds a part, and a `.` that
  nothing continues is the sentence's full stop. A `.` that something
  continues is still the value's, so `168.1.1` is still not found inside
  `192.168.1.1` and `evil.com` is still not found inside `notevil.com`,
  `sub.evil.com` or `evil.com.br`.

- **What the indicator cap orphans is counted.** The integrity pass runs a
  second time after the cap to sweep the relationships it left pointing at
  nothing, and that run was given no truncation ledger, so the aggregate
  under-reported what had left the bundle and a reader could not reconcile the
  object count. It reports now, under `cap_orphan` — its own reason, because it
  is the cap's loss rather than a defect of anybody's bundle.

- **The finding-row guard looks at every place a row is built.** It read the
  `message=` keyword in `validation.py` alone, so seven `Violation`
  constructions in four other modules were never inspected, a row written as
  `Violation(code, message)` was invisible, and a local spelled like a message
  builder was trusted for its name. It now walks every module in the tree that
  builds one, matches positional arguments, resolves the constructor under an
  import alias (the resolution shared with the sibling guard that already did
  it), revokes a module-level name the moment a function binds that spelling
  itself, trusts a local only for the value it was given, and fails if a sixth
  module starts building rows.

- **A run that shortens an answer says so.** Every attach but the static
  provider's opened its toolkit with no truncation ledger and no tool-output
  limit, so the guardrail on a tool server's answer counted on nothing and cut
  at the signature's own 8000 characters rather than at
  `core.preprocessing.max_tool_output_chars`. A run whose analysts met six
  shortened answers reported `tool_output_shortened = 0` and
  `any_bound_hit = false`, and the Bounds Hit table, the console's "what the
  run spent" and the `truncation_rate` aggregate were all built from those
  zeros. The server registry now carries the job's ledger and the job's limit
  onto every toolkit it opens, and an agent's own static provider is attached
  the same way. The Bounds Hit section says in words what its call count
  counts, because the per-call latency table also holds calls answered in
  process, which no guardrail sees.
  **Upgrading:** a tool server's answer is now cut at
  `core.preprocessing.max_tool_output_chars` (6000 by default) rather than at
  8000, so an operator who relied on the wider cut should raise the setting.

- **The shortening notice names the way to narrow.** The sentence a model reads
  on a shortened answer said what was missing and offered every optional
  argument the call had not set, so a model that met the same 116-of-150 answer
  three times re-issued the identical call each time. It now says that an
  identical call returns the identical shortened answer and names the
  arguments of *that* tool that narrow or page it, read off the schema the tool
  offered; a tool with no such argument is said to have none, and nothing more
  is offered. The repeat notices name the same list, so one tool no longer has
  two answers to "ask it differently". A parameter name is a tool server's own
  text, so only a plain identifier of at most forty characters is named, at
  most six of them, and anything else is left out; both guardrails — the MCP
  toolkits' and the Ghidra HTTP client's — reserve the room the sentence needs
  through one shared `shorten_target`, capped so no schema can shrink the
  budget its own answer is shortened into, so an answer and its notice together
  stay inside the limit the answer was cut to. No code re-issues a call or
  edits an argument.

- **The grounding corpus records what it held, not only what it missed.**
  `run_summary.truncation` gains `evidence_corpus_answers`,
  `evidence_corpus_bytes_held` and `evidence_corpus_bytes_ceiling`, read off
  the corpus while the container still has one, so a reader can see how close
  a run came to `core.reporting.evidence_corpus_bytes` rather than only that it
  did not reach it. The report's Bounds Hit section and the console's "what the
  run spent" print one sentence for them where it says something — a corpus
  that went partial, or one past half its ceiling — and stay quiet otherwise.
  **Upgrading:** the three keys are **absent**, not zero, on a summary stored
  before they existed or on a run resumed without its corpus; a consumer must
  read a missing key as "not recorded" rather than as a corpus that held
  nothing.

- **A Benign verdict is asked about an indicator typed `malicious-activity`.**
  On a run that concluded Benign for a signed vendor utility the judge typed
  the vendor's own project domain `malicious-activity`, and the export — which
  keeps a judge-written type by design — published it, so the domain reached a
  consumer as malicious activity under a verdict saying the opposite. The new
  validator `stix.indicator_type_contradicts_verdict` puts that to the judge
  once, through the single retry the other verdict checks already share,
  naming the indicator, the verdict's own word and the vocabulary's `benign`,
  `anomalous-activity` and `unknown`, and saying the type may be kept. Whatever
  the judge answers is published: nothing retypes an indicator and nothing
  drops one. A type that is kept stays in `run_summary.validation.unresolved`
  and is printed with the other unresolved findings. The mirror case — a
  Malware verdict beside an indicator typed `benign` — is not a contradiction
  and is not asked about.
  **Upgrading:** a Benign run carrying such an indicator now spends its one
  verdict correction turn on it and may carry a new code in
  `run_summary.validation.unresolved`; a consumer that partitions on validation
  codes should know the name.

- **Out of room, an agent's tool phase now ends where the room did.** Once a
  conversation had no room left for a tool answer, every later call was refused
  without running a tool, but nothing stopped the graph: a live analyst that
  kept asking spent about nineteen more steps and five minutes on refusals, was
  stopped by the step limit, and its budget record, `stage_ended_at_cap` event
  and `run_summary.budget` said `steps`. Two causes: the stream loop broke only
  for a repeating loop, and the no-room mark was read after the loop had
  forgotten its conversation, which clears the mark. The stream now breaks on
  the step at which the agent is out of room, exactly as it does for repeated
  calls, the mark is read before it is cleared, and the three surfaces say
  `no_room`; the forced synthesis still writes the answer from what was
  gathered. langgraph's step-limit sentence ("Sorry, need more steps to process
  this request.") is no longer published as the agent's words in the
  conversation feed, no longer sent back to a model as the agent's own turn in
  the salvage or the nudge, and no longer returned as the judge's mediation
  reasoning. Where a loop a cap ended produced no answer and the salvage wrote
  none either, the agent's answer is now empty and its status `no_claims`,
  instead of the graph's sentence or a tool's notice handed on as the agent's
  answer; why the loop ended is on the budget record and the
  `stage_ended_at_cap` event. A judge loop that ends the same way returns no
  reasoning, and mediation reads that as no agreement without asking a model to
  extract a verdict from nothing. The analysis node no longer runs an analyst
  that ended `no_room` a second time over the same material.

- **A JSON answer over the cap only because of its indentation is handed over
  whole.** The document shortener measured an indented answer at its compact
  size, found it already inside the target, cut nothing and handed back the
  indented text, which the guardrail then cut as characters: on a live run
  `elf_info` (8,628 characters indented, 5,577 compact, cap 8,486) and
  `strings` (8,442 against 7,334) both reached the model ending in
  `[OUTPUT TRUNCATED]` and the ledger with `structured: null`, so neither
  reached the report. A JSON answer whose compact form fits the cap is now
  handed over in that form — every value the tool's, parseable, with no
  shortening notice — on both the MCP toolkit and the Ghidra HTTP client, and
  counted as the new `tool_output_compacted` in the truncation ledger,
  `run_summary.truncation` and the report's Bounds Hit table. When the compact
  form still does not fit, the structural shortener now acts on it, and every
  document it returns is written compactly, where an indented answer used to be
  shortened in the library's spaced form.
  **Upgrading:** `run_summary.truncation.tool_output_compacted` is new and is
  one of the outcomes counted under `tool_output_over_limit`; a summary stored
  before it reads 0. `tool_output_chars_dropped` includes the whitespace a
  compacted answer lost, though no value was.

- **The context budget counts what a request carries besides its messages, and
  a full window ends the tool phase instead of the agent.** On a live run the
  static analyst reached step 36 of 40 with the budget holding 61,762
  characters — inside the 73,728-character tool budget of a 32,768-token window
  with 8,192 kept for the reply — when llama answered HTTP 500 "context shift is
  disabled"; the run said `tool_output_no_room 0` and the analyst's work was
  lost. The count left out the definitions of the loop's tools, which go with
  every request: 35 tools, about 20,500 characters, 28% of the tool budget.
  They are now counted with the conversation, and where the server reported the
  token count of the last request, that count plus what the conversation gained
  since is a floor under the measure, so content that tokenises worse than three
  characters a token cannot hide the room that is gone. A provider's own answer
  that the window is full ("context shift is disabled", "exceeds the available
  context size", "maximum context length", "prompt is too long"), met after the
  loop has gathered at least one tool answer, now ends that agent's tool phase
  with `no_room` and the detail "the model server reported its context window
  full", and the forced synthesis writes the answer from what was gathered. The
  same sentence on the first request, a reply cap at least as large as the
  window, an error that is not a provider's, and any other server error still
  fail the agent; vLLM's wording of a full conversation, which names the reply
  cap beside the input-token count, counts as full. After the server reported
  the window full the final-answer nudge is no longer sent. The judge's tool loop
  is now accounted the same way under its own name — its conversation and tool
  definitions counted, its answers capped from its own room, its loop streamed
  and ended on `no_room`, and its reasoning then written once from what it
  gathered — where before every judge answer was capped against whatever
  conversation happened to be live, usually none. "context shift" also joins the
  wordings that retire a learned window. The forced synthesis, the analysts' and
  the judge's, now trims its conversation from the window the budget counts on
  (the smaller of the declared and the probed one) rather than from the declared
  size alone, and the judge's gets only what is left of its loop's time.
  **Upgrading:** a derived cap reaches zero sooner for an agent with many tools,
  so a run on a small window ends tool phases earlier than before and says
  `no_room` where it used to overflow; unticking the tools an agent does not
  need in the Tools step gives the room back.

- **Every id in an exported STIX bundle is a UUID the platform minted.** The
  judge was asked for random UUIDs, which a model cannot produce, and the id
  check accepted any eight-four-four-four-twelve hex. The judge copied
  documentation-shaped runs instead: one malware id appeared in fourteen stored
  runs of six different samples, so a consumer merging on id folded those
  analyses into one object, and its version digit is one no RFC 4122 UUID has,
  so the OASIS validator refused every object that carried or named it — 22 of
  40 stored exports. The judge now writes `<type>--<label>` ids unique in its
  bundle, a short label being enough, and the post-processor mints every
  published id under the object's own type and rewrites every reference to
  match.

- **An indicator over an object type STIX does not have is asked about, and
  not exported unasked.** A live export carried
  `[ipv-addr:value = '82.157.13.47']` — the type is `ipv4-addr` — which no
  consumer can match, and because the export's endpoint question reads only the
  paths it knows, the address was never asked it: the same misspelling around
  `127.0.0.1` would have published a loopback. The judge is now asked
  `stix.unknown_observable_type`, with the type the value is named where the
  value or the spelling says; the pattern is never rewritten, and one it keeps
  is declined from the export as `stix.unpublishable_pattern`, which the
  console draws as the export's decision. `indicator_types` outside STIX's
  vocabulary (`ip-addr`, `file` — the kind of value where the vocabulary says
  what it indicates) is asked about under `stix.indicator_type_vocabulary` and
  published as the judge answers. The prompt names the Cyber-observable types
  and the vocabulary, which it never did.

- **A technique the judge named is published with the judge's own number, and
  the judge's credits are not sources.** The capability matrix read a judge
  relationship's technique only from `x_maljan_technique_id`, which the prompt
  never asks for and no stored judge relationship carried, so every number the
  judge put on a technique was dropped: all twenty judge-only techniques in the
  stored runs were published at confidence 0.0 in `ttp_mappings`, the
  report's ATT&CK section and the narrative's prompt — T1490 on the ELF run at
  0.0, while the bundle's own `uses` edge carried the judge's 0.95.
  The technique is now read from the attack-pattern the relationship points
  at. The agents the judge credits (`STATIC ANALYST` for T1490, which the static
  analyst never claimed) stay on the relationship as written and are no longer
  counted as contributing layers, which would have made one analyst's claim
  read as corroborated. Relationship annotations nobody wrote are absent rather
  than `0.5` / `unknown`, and the text fallback's edges name the agents whose
  claims they carry instead of stating a 0.5 the judge never gave.

- **A judge relationship that credits an agent with a technique it never named
  is asked about.** The ELF run published `malware uses T1490` and
  `uses T1048.001` crediting `STATIC ANALYST`; the static analyst claimed
  neither and no tool named either, and nothing asked. The judge node now
  passes the evidence summary as data, and `stix.credit_without_claim` tells
  the judge which sources did name the technique, by the names the summary
  gives them (a parent or sub-technique counts). The credit is never
  rewritten in the judge's own bundle; one the judge keeps is left off the
  export's copy of the relationship and recorded as
  `stix.unpublishable_credit`, so no surface prints an agent as having named a
  technique it never named.

- **Nothing is written into a judge object that the judge did not write.** An
  indicator with no `indicator_types` was published as `malicious-activity`
  and, under a Benign verdict, the judge was then asked about that word; it now
  stays untyped (the property is optional in STIX 2.1). A malware object with
  no `is_family` was published as `false`; the judge is now asked
  (`stix.is_family_missing`), and a judge's `is_family: true` is published as
  written — the renderer used to force it to `false`. A relationship annotation
  outside the schema — a confidence of `1.5` or `95`, a basis such as
  `static+dynamic+network` — used to parse as a plain relationship and lose the whole annotation silently; it
  is now kept as written and asked about (`stix.annotation_out_of_schema`), and
  no reader puts a number off the 0–1 scale on a technique.

- **A label the judge repeats is asked about, never resolved.** Two objects
  sharing an id had every reference rewired onto the first, and the integrity
  pass folded the second object's edges away. The label is now a
  `stix.duplicate_label` question naming both objects, and no reference naming
  it is rewired onto either. Feedback names the judge's own positions and
  labels (`objects[3] 'indicator--2'`) rather than positions in the
  post-processed list.

- **A technique nobody put a number on is published without one.** The
  matrix printed `conf=0.00` for a technique no source numbered — every
  technique the judge names alone under a Suspicious or Benign verdict, where
  there is no malware object to hang a numbered edge on.
  `CapabilityCell.confidence` and `TTPMapping.confidence` are now `null` there,
  and the report and the narrative's prompt print "not given".

- **The export's observed data is STIX 2.1, and the official validator gates
  every export shape.** The process tree was a deprecated `objects` dictionary
  of processes with no id and a `name` 2.1 does not define, with the process
  count in `number_observed`; the OASIS validator crashed on it. It is now
  `process` and `file` observables named by `object_refs`, with
  `number_observed: 1`. `stix2-validator` is pinned at 3.2.0 (3.3.1 ships no
  schemas and validates nothing), and a test renders a rich, a sandbox and a
  Benign export and fails on any validator error.

- **The judge's own bundle is kept, and the export says who did what.**
  `analysis_reports.judge_stix_bundle` (migration `20260929000000`) holds the
  judge's bundle and the map from each label it wrote to the published id,
  served at `/reports/{id}/stix?source=judge` — the bundle every decline row
  says an object "is unchanged in". A network-block row the export declines is
  filed under the source that recorded it rather than under the judge; a
  text-fallback bundle credits the analysts whose claims it carries rather
  than the judge; a producer the export names in place of one it cannot hold
  is recorded (`stix.unpublishable_producer`). A pattern over a path its type
  does not have, or a type written in the wrong case, is asked
  (`stix.unknown_object_path`) and declined as `stix.unpublishable_pattern`. A
  technique id is read only from a MITRE ATT&CK reference, and the judge's
  bundle and the export derive technique ids in one namespace.

- **A cyber-observable the judge writes never costs the rest of its bundle,
  and the export never publishes an object the standard refuses.** A judge
  `file` without a `name` failed the bundle model and sent the judge's whole
  answer to the text fallback, its verdict read from prose and its confidence
  lost; a named `file` dropped its `hashes` and a `process` its `name`, with
  nothing recorded. Every property STIX 2.1 defines for a `file` or a `process`
  is now kept as written, and every judge object is read on its own first: one
  carrying a property its type does not define, or a value the model cannot
  hold, is set aside as `stix.unknown_object` and the rest is read. A file with
  neither `hashes` nor `name` is asked `stix.file_unidentified`; kept, it and a
  malware object without `is_family` are declined as `stix.unpublishable_object`
  and the platform's own sample object stands in.

- **A declined judge malware object's relationships move onto the object that
  stands in for it.** Declining the judge's malware object dropped its `uses`
  and `indicates` edges with it, so the technique the judge numbered was
  published unrelated while the report published it at the judge's
  confidence, and the judge's indicators indicated nothing. The edges now move
  onto the platform's sample object unchanged and the decline sentence says
  so. A test checks over every Malware export shape that each technique is
  used by a malware object, that every `indicates` edge is the judge's own or
  the sample hash's (any other indicator is related to nothing and listed in
  the report's `object_refs`), and that the export and the report publish the
  same techniques at the same numbers.

- **What the export does not carry of the judge's bundle is recorded, and the
  judge's own record holds it.** The domain-object models ignore properties
  they do not declare, so an indicator's `valid_until` and
  `kill_chain_phases`, a relationship's `description` and a malware object's
  `aliases` left the judge's bundle with no row, and the stored judge bundle, a
  model dump, lost them as well. Each object's undeclared keys are now a
  recorded `stix.property_not_carried` row that does not spend the judge's
  retry, `analysis_reports.judge_stix_bundle` stores the judge's JSON as
  written, and a malware object's `sample_refs` is carried into the export.
- **What a run measured reaches its report, once and from the right source.**
  The header's timestamp, machine and library flag reach the sample overview —
  from the identity, or on a stored report from the format tool's own section.
  One binary read twice (the triage pack's pe_info and the analyst's, capa run
  twice) is one section table, one import table, one export list and one set of
  rule rows. A similar sample is named by the id it carries rather than `?`. A
  technique's source is every producer that named it — the rules that asserted
  it, the analysts, the judge's verdict — and a confidence no producer stated
  (a technique whose `confidence` is `None`) prints "not given" or "rule
  match", never "0.00, judge"; a stated one names its producer, and an
  unresolved `stix.credit_without_claim` prints beside its row. Every identity hash `/iocs` publishes is in the indicator table.
- **An empty sandbox answer is not an observation.** The report speaks in the
  sandbox's voice only over what a sandbox recorded; a sandbox whose tools
  answered with nothing — a mock with no fixture — gets one sentence in the
  run's own voice saying nothing shows the sample was executed, with the reason
  the run recorded. The report models are told the same in their prompts.
  An execution-flow step marked observed may cite only a sandbox answer that
  recorded something; one citing an empty answer is asked about, and the report
  prints the `report.flow_voice` note beside any step marked observed in a run
  with no observation.
- **Every numbered section is printed.** A section or a §5, §10 or §12
  subsection with nothing in the run prints one line in the platform's voice
  saying whether nothing was found or nothing looked; the table subsections of
  §6, §7 and §9 are unnumbered headings. A script that looked for `### 6.1
  Process tree`, `### 7.5 Rule hits`, `### 9.1 File and host indicators` and
  their siblings must look for the unnumbered titles.
- **A degraded run's header is one reader sentence.** It is built from the
  analysts' and the sandbox's states and points to §13, which now lists every
  degradation reason verbatim with its remedy and each analyst's state; no
  reason code or install command is on the first screen, and §3 does not claim
  consensus among analysts that claimed nothing.
- **Every printed number has an owner.** A technique's confidence prints with
  its producer (new `CapabilityCell.confidence_source`), or "producer not
  recorded" on a stored row; an unstated one prints "not given"; a packer,
  function-hash, similarity or carved-payload field with no value prints "not
  recorded"; a similar sample with no distance is counted, not listed; §2 states
  the reputation lookup's engine count ("VirusTotal: 52 of 75 engines flag it as
  malicious"), which `ledger_report` now lifts into rows.
- **The measured proof sits beside the prose.** §5.1 and §5.2 print the capa
  rules that support them with their evidence ids; in §8 a rule naming a
  technique a row already holds is folded into that row, and a rule-only
  technique is one row with the catalogue's tactic and name.
- **Voices name who spoke.** The platform's no-summary fallback, the platform
  read from the file format (now a §2 row) and a family named by the sandbox
  are no longer tagged as a model's or the judge's, in the report and in the
  console; the title names a family only when the judge cited evidence for it;
  the report model's unresolved findings print under §1.
- **A value cannot break a line or open a heading.** List items, steps and
  headings are built by one helper each, prose cannot open a heading or a code
  fence, and a guard test fails the build on a hand-built bullet. The HTML
  anchors and contents are the section titles without the voice tag, a model's
  private address is marked in §5.7, prose never leaves `http://` live before a
  defanged host, and the console defangs a channel's endpoints.
- **A model's list is cut only with a record**, and a missing parser degrades a
  run only for a sample of the format it parses (no Mach-O note on a PE).
- **The report models' contracts, prompts and instructions carry no evaluation
  answer.** The narrative contract and its citation rule use the invented
  class's technique ids, the composer's instructions are module data with a
  neutral configuration checklist, and the leak test reads all of them.
- **Model prose cannot open a setext heading or a table**: a line of `=` or `-`
  and a table delimiter row are escaped like `#` and fences.
- **`Finding.confidence` is `None` when the analyst gave none** (was 0.0); the
  findings table prints "not given" and the matrix records no number for it.
- The degraded header says an analyst was *skipped* when its record says so,
  from the stage and agent records; an empty capability subsection names the
  tools that ran over the file; PEB access is listed once; the unscored
  similarity line reads "No similarity measure was recorded for these
  samples."
- **A family-specific section needs its family.** An encryption scheme with no
  file-encryption field prints beside the anti-analysis prose rather than under
  a ransomware heading, and a block of placeholder values ("none", "unknown")
  is not content. A Malware Behavior Catalog id claimed as a technique is listed
  under the ATT&CK table as a behaviour, not as an unresolved technique row.

- **The Ollama probe loads the model the way the job will.** The `llm` and
  `agent` probes asked Ollama with no `num_ctx` and no `keep_alive`, so the
  model was left loaded at the server's default 4,096-token context and the
  job's first call reloaded it at `core.llm.ollama.num_ctx` (32,768 by default)
  out of the first analyst's time budget. Both probes now send
  `options.num_ctx` and `keep_alive` from `core.llm.ollama.num_ctx` and
  `core.llm.ollama.keep_alive`, staged values included. The other providers'
  bodies are unchanged.

- **A reference lookup is not an assertion.** The corroboration rows counted
  any ledger tool that returned a technique id as a deterministic source, so an
  analyst that looked up twenty ids with `attck_lookup`, and a `similar_cases`
  call returning other samples' techniques, made a report print "29 asserted by
  a deterministic source" where capa had asserted two — six of them ids the
  lookup itself answered `valid: false`. Only capa, Sigma, YARA, `lolbin_lookup`
  and a sandbox signature assert now (`evidence_summary.ASSERTING_SOURCES`); a
  lookup adds no row and no count, and an id any ledger entry of the run marks
  invalid is never counted as asserted. The import rules (`api_capability`)
  stay a reference association and count for nothing, as before. The report's
  TTP line, its corroboration table, the run summary's per-source attribution and
  `techniques_by_layer`, the judge's evidence block and the console's
  Capabilities page all read the same rows.
  **Upgrading:** `run_summary.corroboration` on a new run has fewer rows and
  no `attck_lookup`, `similar_cases`, `resolve_technique` or other lookup name
  in `asserted_by` or `techniques_by_layer`; a report stored before this keeps
  the rows it was written with.

- **No consensus among analysts who said nothing.** A run whose only analyst
  timed out went to the mediator with nothing to compare, the mediator answered
  "no analyst provided a substantive report … agreement_confidence: 1.0", and
  the run recorded "Consensus reached (confidence=1.00)", a `consensus`
  termination and a final confidence of 1.000. Agreement is now measured only
  when at least two of the debate's analysts produced claims, on the model
  path, the text fallback, the mock mediator, a failed mediation round and a
  debate stage that did not run alike. Otherwise the mediator still speaks, but
  no agreement value is extracted, the confidence series gets nothing, and the
  router goes to the judge rather than asking the same analysts to revise.
  **Upgrading:** on such a run the pipeline state and the stored
  `negotiation_log` carry `is_consensus: null` and `consensus_applicable:
  false`, a mediator argument's `confidence_score` (and the stored
  `confidence`) is `null`, `run_summary.negotiation.termination_reason` is
  `not_applicable` with **no** `final_confidence` or `converged_early` key, the
  report's `negotiation_summary` has no `final_confidence`, and the negotiation
  timeline's `reached_consensus` is `null`. The mediator's words are kept
  whole in the argument's `finding`, and the platform's "not applicable"
  sentence is in its own `note` field (stored as `note` beside each negotiation
  entry). A consumer must read an absent or
  `null` value as "not measured", never as 0.0 or as no consensus. A mock run's
  analysts file no claims, so a mock run now takes this path too.

- **The time cap salvages, like the step cap and a full window.** A static
  analyst on a model at about 100 s a turn reached its 1,500 s budget at step 28
  of 40 and was aborted ("exceeded the 1530s hard cap; aborting this analyst"),
  and everything it had gathered was lost with no final-answer turn. The soft
  timeout was reported as the hard cap and handled like it. The loop now times
  its own turns — answer to answer, tools included — per answering model,
  leaving out the turn a model list switched on, and ends its tool phase once
  the time left cannot hold the longest turn plus a final-answer reserve: 1.5 ×
  the larger of that turn and a 1,000-token answer at the model's measured
  rate, at least the salvage's 60 s floor. The salvage writes the answer from
  what was gathered. At that pace with one 240 s turn and 3.8 tokens a second,
  the reserve is about 395 s and the tool phase ends once under 635 s are left.
  The last turn's calls that never ran are taken off the transcript the final
  answer is sent — from `tool_calls`, from `additional_kwargs` (OpenAI's
  `tool_calls`, Gemini's `function_call`) and from the content's `tool_use`
  blocks, since hosted providers refuse an unanswered call — its text kept
  and the record saying they did not run; a model list's deadline is held at
  the reserve for that turn; the answer asked for after it gets only what that
  turn left. A turn longer than any measured that still reaches the budget
  ends the phase there, with what was gathered kept, rather than failing the
  analyst; a budget that runs out with nothing gathered says so instead of
  naming the hard cap. The budget record, the `stage_ended_at_cap` event and
  `run_summary.budget` say `time`, with a detail naming the time left, the
  answering model's longest turn and the reserve.
  **Upgrading:** an analyst on a slow model now stops calling tools before its
  budget and returns claims where it used to fail with a `TimeoutError`, so
  such a run makes fewer tool calls and has one more analyst reporting; the
  hard cap is unchanged.

- **The run's token total counts every model call.** A smoke run counted 20
  calls while the model server served 22. The mediator's fast path, the
  mediator's structured extraction and the judge's verdict (and its retry)
  recorded nothing, nor did the three built-in analysts' revision rounds, the
  function summariser, or the turns of a tool loop its hard cap or a failure
  stopped (a judge loop's included), or an attempt abandoned on a connection
  error; the step-cap stop sentence the loop appends was counted as a call; the narrative's and the composer's calls were recorded under no
  model, and their structured paths not at all. Each path now records its usage
  under its agent and the model that answered: the mediator's against the
  expert model, the report's against the reporter's, the summariser's under
  `summarizer`. A structured call asks for the raw turn beside the parsed
  answer (`with_structured_output(..., include_raw=True)`).
  **Upgrading:** `run_summary.tokens.llm_calls` and the per-agent figures rise
  for the same work, `per_agent` gains `judge` and, when the summariser is on,
  `summarizer`, and `run_summary.models.reporter` names the reporter's model;
  a comparison across this release compares different counts.
- **A citation is an evidence id or it is asked about.** The composer cited
  "[BINARY FACTS]" and "[DETERMINISTIC FACTS]" — its own prompt's block
  headings — beside real evidence ids, and nothing checked a citation. The
  narrative and every composer section now get `report.citation_not_evidence`
  for each bracketed item in their prose that is not an id the run's ledger
  issued, with a sentence naming the ids they may cite. Only prose fields are
  read, never a record field or a code span; ATT&CK and MBC ids, IPv6 literals,
  markdown links and a bracket that is part of a token are left alone, and a
  numbered reference such as `[1]` is asked about. An id inside a sample's own
  decoded string is never citable. The citation is never rewritten:
  one the retry does not fix prints as written and is recorded unresolved, and
  the section is kept.

### Removed

- **`reporting.narrative_max_tokens`.** It was described as a hard output cap
  for the narrative round, but its value only reached a constructor argument
  (`NarrativeAgent.max_input_tokens`) that nothing read; both are gone. The
  round's budget is the report stage's (see Changed). Alembic revision
  `20260930000000` deletes a stored row. **Upgrading:** nothing to do; a
  stored value is ignored when the settings are built, and the migration
  removes it so an import does not refuse it as an unknown key.
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

- **`data/attck_platforms.json`.** `data/attck_techniques.json` replaces it and
  carries everything it did — per technique id, its domain and its MITRE
  platforms — beside the name and the tactic slugs it did not, plus the tactic
  catalogue per domain. Nothing in the tree reads the old path; a deployment or
  a script of your own that reads it by name must be pointed at the new file,
  whose rows are keyed the same way and carry the same two keys.
- **The severity score** (`severity.overall_score`), the rating read through
  a fixed table and printed as a number out of ten nobody stated. A stored
  report's score is ignored on load.
- **The capability paragraphs and the conclusion as sections.** The narrative
  round and the composer no longer write `capabilities_narrative` or
  `conclusion`; a stored report prints its paragraphs under the technical
  analysis and its sophistication rating beside the verdict.
- **`reporting.builder.defang`**, replaced by `reporting.defang.defang(value, kind)`.

### Documentation

- **The benchmark is published** in `docs/benchmark/`: the method (samples,
  models, the mock sandbox and the scoring key), the default model across four
  iterations, a small model, the reference sample scored against Bitsight's
  published Latrodectus analysis, the disassembler run, the PuTTY
  false-positive control and the limitations, with the five item-by-item score
  files. The README has a short "How Maljan compares" section that links to it.
  Iterations 5 and 6 are added to both, with their score files: the reference
  score plateaued within rerun noise (12–15 found, none wrong), the remaining
  gap is on the model's side, and iteration 6 published seven techniques on the
  benign PuTTY control after its verdict fell back.

### Upgrading

**Analysts run in parallel on a hosted API.** `llm.parallel_analysts` is `auto`
by default. A deployment that never set it and calls a host resolving only to
public addresses now runs its analysts, and the revision round, in parallel;
one on Ollama, on a local address or name (`host.docker.internal`, a compose
service name) or on a host that does not resolve keeps running them one after
another unless the server's `/props` reports more than one slot. A stored
`true` or `false` keeps its meaning. The database revision `20261002000000`
takes the `sequential` the old default wrote off every analysis stage of a
written team, so the stage follows the job, except where
`llm.parallel_analysts` is stored `true`; it names each team and stage it
rewrote at WARNING, and `sequential` picked on a stage card pins a stage
again. Consumers of stage documents should read a missing or `null` `mode` as
"follows the job", and `run_summary.profile` may carry `analyst_mode` with a
`stages` list.

**Spend.** The ceiling still has no default: an unset
`llm.max_spend_usd_per_job` is no ceiling, and nothing is held or refused for
spend. With one set, a refused call no longer exhausts the spend by itself
(`run_summary.spend.exhausted` means nothing more fits with no call in
flight, or the ceiling was reached), a call may wait for calls in flight to
settle before it is made, `run_summary.spend` may carry `refused_calls`, and
each reserve row carries `retries`, `retries_from`, `retry_prompt_tokens` and
`expected_usd`. The reserve follows this job's own call sizes and plans the
tail's validation retries; before any single-shot answer is measured it holds
the verdict at its whole cap with one retry, and it shrinks as calls are
measured.

**The spend ceiling.** `llm.max_spend_usd_per_job` is now a hard bound and
counts the charged price: the same ceiling allows about twice the work it did
off-peak on DeepSeek, where the vendored table used to count every call at the
peak rate, and a job no longer spends past it (it used to by up to 8,192
output tokens a call once the ceiling latched). A job's report sections may
now be recorded as not written for the ceiling where they used to be written
past it; raise the ceiling if the report matters more than the bound. An
operator's `llm.model_prices` row keeps working as it is; add `windows` to it
for a vendor's peak or off-peak rate. Consumers of `run_summary.spend` should
read `prices_from` values as a `; `-joined list of rates, and may find
`reserve_usd` and `reserve`.

**Triage run time.** Nothing changes until `sandbox.triage.analysis_seconds`
is set. When setting it, keep `sandbox.triage.timeout_seconds` above it with
room for Triage's processing, or the settings are refused.

**Importing the all-tools team.** The document holds two whole-map settings,
and an import replaces what it names, so merge it into an export first (the
`jq` line is in [configuration.md](docs/configuration.md), *An all-tools
team*). Its agents are all keyed `all_tools_*` and its team `all_tools`, so
none of your own definitions or teams is replaced. A job
naming a team with an agent on Ghidra is now refused while Ghidra is not
answering — start it before submitting.

**Loops have no default limit.** A deployment that relied on the old defaults
— ten steps and 180 s per loop, the static analyst's 40 steps and 1,500 s, the
network analyst's six steps, the dynamic analyst's 600 s, the judge's 600 s,
the lead's 40 steps and 1,800 s, an ask's 12 steps and 300 s — now runs each
loop until its model answers or a stop that is not a count ends it, bounded by
the job timeout. To keep a bound, set it: on an agent's card (**Steps per
loop**, **Seconds per loop**), in `react_agent_max_steps` /
`react_agent_timeout`, in the deprecated maps (the only place for the built-in
judge), or in `agents.delegation_steps` / `delegation_timeout_seconds`. On a
paid provider, set `llm.max_spend_usd_per_job` (and `llm.model_prices` for a
model the vendored table does not price). Stored values are untouched; no
migration runs. Consumers of `budget_tick` events and `run_summary.budget`
should read `max_steps` / `timeout_s` as nullable. The analysis server's
manifest now declares `timeout_s: null` for capa and FLOSS, so the MCP call
deadline for them is the deployment's (`mcp.breaker.call_timeout_seconds`, or
the capa budget it derives from).

**The judge's technique question adds a call.** Whenever the analysts named a
technique the verdict's bundle does not carry, or one only on a finding, the
judge is asked about it once after the verdict — on every profile and every
provider, with no switch. It is one judge call sized like the verdict, so a
run's wall-clock time and call count move by one judge turn; the token ledger
names it `technique question`.

**Degradation reasons for claimless analysts.** An analyst skipped for want of
input is now named under `analysts skipped (no sandbox data): <names>` (or
`analysts skipped (no input data): <names>` for a sample-fed role), and
`analysts produced no claims: <names>` names only analysts that ran. A run
used to carry `analysts produced no claims: dynamic, network` for the two
analysts a static-only run skipped; it now carries `analysts skipped (no
sandbox data): dynamic, network`. `run_summary.agent_stats[*].no_data` is
unchanged. A reader that partitions degradation reasons on the old prefix —
to set skipped analysts apart from failed ones — needs to read the new one
too.

**An operator's prompt gains the platform's sentence about tools.** An
operator-written prompt (a generic or lead agent, or any definition with its
own prompt) is now sent with one sentence appended: the tools the request
carries, or that there are none. The agent probe's `prompt`, `prompt_chars`
and `prompt_sha256` include it; the new `authored_prompt` is the operator's
text alone (for a built-in role, its assembly without the provider fragment
and the sentence), and the console seeds a clone from it.

`llm.expert_max_tokens` and `llm.judge_max_tokens` ship at 0, which now means
"derived from the window" — no longer "unbounded". A stored setting keeps its
value; a deployment that relied on 0 for no cap should set a value instead.
On a 32,768-token window the derived cap is the 8,192 that shipped before; on a
smaller window it is smaller, on a local larger one larger (32,768 on a
131,072-token window), on a model with a declared maximum at most that (16,384
on the shipped gpt-4o), and on a hosted model that declares none 8,192. The
composer's derived section budget and the reply reserve follow the same rule,
so on a large window both grow and the tool budget is correspondingly smaller;
an unknown window keeps 8,192. `stix2-patterns==2.1.2` is a runtime
dependency. `run_summary.generation` may carry
`output_caps`. Three more validation codes: `stix.pattern_refused`,
`stix.shape_names_a_value` (both counted in `run_summary.validation`), and a
judge indicator with an empty pattern is the only one the integrity pass drops,
so `empty_pattern` no longer counts a cut pattern. An unresolved row may carry
`subject`. `x_maljan_fallback_verdict` may carry `reasoning`. The network
reputation cell reads "N of M engines flag it as malicious".

Two validation codes are new, `isr.cut_at_output_cap` and
`stix.unescaped_backslash`, and `stix.indicator_not_published` also records a
`LIKE` or `MATCHES` over a kind the publish rule answers for. A judge indicator whose pattern has an operator
other than `=` now reaches the checks and the export instead of being dropped;
a `LIKE` endpoint's decline sentence says it names every endpoint that fits it.
A `run_summary.validation.unresolved` row of the judge's carries `"asked":
"false"` when the judge was never shown it, and `Violation` has an `asked`
field. `x_maljan_fallback_verdict` may carry `model_only_technique_ids`; a
non-Malware fallback bundle with nothing for a note to name carries no note.
`retry_with_feedback_sync` takes `drop_answer_for`. A capability matrix cell's
`note` may hold the judge-only marker. The triage pack's reputation line reads
"VirusTotal: N of M engines flag it as malicious".

The judge is asked to leave `pattern_type` out of an indicator (the model
fills in `stix`) and to write its annotations on relationships only. A
fallback bundle may carry indicator objects. `attck.claim_does_not_describe`
is a new validation code, counted in `run_summary.validation`; the not-asked
path appends "Not asked: …" to it as to `attck.absence_claim`. The
`verdict.cut_at_output_cap` question states the answer's size by characters,
objects and indented lines. The capability check asks about more report
sentences where only capa's or YARA's rule names had grounded a word, and about
fewer where a value, a heading or an absence had been read as a claim. A
section's findings first raised by its retry — a new sentence under a term
already asked included — are recorded ending `composer.ONLY_IN_THE_RETRY`, and
a `run_summary.validation.unresolved` row of a finding never shown to its
producer carries `"asked": "false"`.

An analyst claim carries `kept_after_absence_question` (false on a stored ISR,
which is read as before), and a capability matrix cell carries `note` (empty
when there is none). A capability question names two of its term's technique
ids instead of three. Two validation codes are new, `attck.absence_claim` and
`composer.repeated_items`, both counted in `run_summary.validation`. The
exported STIX report object of a Suspicious or Benign run is typed
`threat-report` instead of `malware`. `retry_with_feedback_sync` takes an
optional `keep(first, last)` that chooses the answer kept before outcomes are
published. The capability check asks about more report sentences than before:
see "A capability word is grounded only by what the run found".

The `cancelled` job event always carries `stopped` now, and a new
`seconds_into_run`. A report carries `flagged_statements` (empty on a report
stored before it existed, which renders unmarked). On the `openai` provider
against llama.cpp, `run_summary.generation` records a prompt reading rate and
the server's own generation rate (source `llama.cpp timings.predicted_n/
predicted_ms`) instead of the wall clock's. A call that gives its prompt size
is timed as its prompt read plus its answer at those two rates; without a
reading rate the rate that includes the prompt read is used as before. A
derived timeout is never below the configured value. A queued job whose row
already ended returns `status: skipped` from the worker.

`reporting.composer_section_max_tokens` now ships at 0, meaning derived from
each reporter model's context window. A deployment that stored 900 (or any
positive value) in its settings keeps that value; set it to 0 to take the
derived budget. The report stage learns each reporter model's window when it
builds the composer, the way the analysts' tool-output cap does (metadata
endpoints only, cached per model and endpoint).

A derived section budget can be many times the old 900 tokens, so a section
on a slow model may wait far longer: its wait holds two calls of the budget at
the model's measured pace, up to the 1,800 s request ceiling each, and a report
has about eleven sections. Set `composer_section_max_tokens` to bound it.

`/reports/{id}/iocs` and `consolidated_iocs` may carry rows whose `source` is
`judge`, of kinds the feed never served before (`email`, `path`, `registry`,
`mutex`, `command`, and a `hash` of another file). A consumer that switches on
`kind` should expect them. A judge indicator the publish rule refuses is no
longer exported: an export may carry fewer judge indicators than before, each
decline recorded as `stix.indicator_not_published`. A report stored before
`judge_indicators` existed shows no judge rows.

A report now stores `emulated_strings`. A report stored before it existed
reads its emulation record from its kept section rows, and a value published
from it says "(the record is partial: …)"; re-render it from a new run for a
whole record. A Sigma draft may carry more than twelve values in a selection,
and its registry selection names keys without a hive (`\Software\...`), not
`HKCU\Software\...`. A composer section's prompt may be longer, since its
facts are no longer cut.

Draft detection rules are no longer generated for a Benign verdict, and a
YARA draft no longer carries import names as strings; a Suricata draft alerts
only on published network values. `technical_analysis.host_identifiers` is a
new optional field; a report stored before it renders without the rows.
`run_summary.validation` may carry `report.citation_wrong_entry`,
`report.identifier_uncited` and `report.technique_name`. A Sigma draft is no
longer generated from an analyst's persistence target alone.
Operators see these changes in a run's record, and nothing needs migrating:
`run_summary.budget.<agent>.salvages` lists each salvage (what it sent, what it
was sized by, how it ended); `run_summary.generation.models.<model>` gains
`prompt_tokens_per_second`, `prompt_tokens`, `prompt_seconds` and
`prompt_sources`; `run_summary.triage` gains `floss`; a new setting,
`triage.memory_floor_mb` (10,240), needs no action; `validation.by_code` can carry `isr.unparsed_answer`,
`isr.claim_without_confidence`, `verdict.cut_at_output_cap` and
`tool.argument_names_its_parameter`; the degradation reasons can name
"analyst answers kept as prose"; a stage's `agent_reasons` says when an
analyst was not given a second loop; and the `cancelled` event can carry
`stopped`. An analyst answer with no CLAIM block no longer yields claims at
0.50, so a run that used to show such claims shows none, with the analyst's
prose as its report; reports stored before this change keep what they
recorded. A judge fallback whose answer stated its assessment whole now
publishes that assessment's confidence, severity and family.

Record shapes that change with this: `attribution.family_confidence` and the
judge's `family.confidence` are `null` where nothing was stated (they were
`0.0`), and the console's attribution tab prints "not assessed" for it;
`static.packer_matches` rows from the pack carry no `confidence` and name the
matched sections under `evidence`; capa's `technique_hits` and
`api_technique_hits` rows carry no `confidence`; a YARA rule's `confidence` is
`null` where its author wrote none; `overall_confidence` defaults to `null`;
`run_summary.budget.<agent>.validation_not_asked` lists validation turns a
loop's time could not hold; a failed mediation round has `is_consensus: null`,
an empty confidence series and `termination_reason: mediation_failed`, with no
`final_confidence`, and the report projection no longer borrows the verdict's
confidence or a 0.0 for a negotiation that stated none. Reports stored before keep what they recorded.

A stored STIX bundle keeps the shape it was stored with: `x_maljan_evidence_refs`
appears only in exports rendered after this change, so the relationship graph
of an older run shows no ledger ids until that run is analysed again.

An existing `.env` deployment is not migrated automatically. Move the bootstrap
variables into the process environment (or `docker/.env` and `bootstrap.env`),
start the stack, and enter the remaining settings once in Settings →
Configuration — or import a JSON export from another instance. Keep
`SETTINGS_ENCRYPTION_KEY` stable: there is no re-encryption step, and a changed
key makes every stored secret unreadable. See
[docs/configuration.md](docs/configuration.md).

`data/attck_platforms.json` is gone and `data/attck_techniques.json` stands in
its place, with the same `{technique_id: {domain, platforms}}` rows plus `name`,
`tactics` and a `_tactics` catalogue per domain. Regenerate it, the id
catalogue and the retired set together with
`uv run python scripts/knowledge/prepare_attck_malware_fixtures.py`. Nothing in
this repository reads the old filename; only a deployment or a script of your
own can be affected, and pointing it at the new file is the whole change.
Mobile and ICS technique rows now carry their tactics, which they never did:
a capability cell for one of those techniques shows its real matrix column
instead of an empty one.

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

The evidence ledger gains a `model` column (revision `20260928000000`); run
`make migrate` before starting a worker on this release. Rows written before it
name no model, and read as such. `llm.agents` entries need no migration: an
entry without `fallbacks` is the single-model form it always was. A stored run
summary written before this release still carries `tokens.estimated_calls`, and
the console says such a run's figures had estimates mixed in rather than
printing them as a count. `core.mcp.breaker.*` are new settings with defaults;
set `core.mcp.breaker.max_concurrent_calls` to `0` to drive every tool server
uncapped as before.

`core.llm.fallback_turn_share` and `core.mcp.breaker.call_timeout_seconds` are
new settings with defaults. A tool server that legitimately takes longer than
the longest tool budget configured for this deployment (capa's, 300 s by
default) needs `core.mcp.breaker.call_timeout_seconds` set, or its tools to
declare their budget in the server's `capabilities` manifest.

`floss` runs FLOSS 3.1.1 (Apache-2.0) as FLARE's standalone Linux build, not
as a Python dependency: the lockfile does not change. The backend image
downloads the release zip in a build stage, checks it against its pinned sha256
and installs the executable at `/usr/local/bin/floss`. On a host outside the
image, run `scripts/install_floss.sh`, which does the same into
`~/.local/share/maljan/tools/floss-3.1.1/`, or name a copy of
the pinned build in `MALJAN_FLOSS_PATH` in the `analysis` server's `env`.
Without it the capability manifest marks `floss` unavailable and the model is
not offered the tool.

A consumer of the exported STIX bundle that filters on the platform's own
words should update the filter: the producer identity is now
`identity_class: system` under the one id
`identity--9f9e2570-073b-5b46-b156-05d12a086911`, named by `created_by_ref` on
every other object, and the report object's `report_types` is `malware`. A
bundle stored before this change keeps `software`, `malware-analysis` and a
per-run identity id; nothing is rewritten.

A consumer of the exported STIX bundle or of the report's technique rows
should know what else moved. `x_maljan_confidence` and `x_maljan_evidence_basis`
are absent on a relationship whose writer gave none, where they used to be
present as `0.5` and `unknown`; read them as optional, and do not assume a
number or a list: an annotation outside the schema is kept as the judge wrote
it (`x_maljan_confidence` may be `95` or `"high"`, `x_maljan_contributing_agents`
a single string) beside a `stix.annotation_out_of_schema` row. `contributing_layers`
no longer lists the agents a judge relationship credits, so `is_corroborated`
is true only when two analysts named the technique themselves — a dashboard
counting corroborated techniques moves down. A technique's `confidence` in
`capability_matrix` and `ttp_mappings` is `null` when no source gave one. The
judge's malware, indicator and relationship ids are fresh per run: the
documentation-copied ids some runs shared were stable by accident, and a
consumer that merged on them sees new objects. An untyped judge indicator
carries no `indicator_types`, and a judge malware object marked
`is_family: true` keeps it. Observed data carries `object_refs` to `process` and
`file` objects instead of an `objects` dictionary. New codes in
`run_summary.validation` and the export's rows, for a consumer that partitions
on them: `stix.unknown_observable_type`, `stix.unknown_object_path`,
`stix.indicator_type_vocabulary`, `stix.credit_without_claim`,
`stix.annotation_out_of_schema`, `stix.duplicate_label`,
`stix.is_family_missing` (questions the judge is asked) and
`stix.unpublishable_pattern`, `stix.unpublishable_credit`,
`stix.unpublishable_producer` (the export's own decisions). Apply migration
`20260929000000` for `analysis_reports.judge_stix_bundle`; a report stored
before it has none, and `/reports/{id}/stix?source=judge` answers
`{"kept": false, "reason": …}` for it (404 only for a report that does not
exist); a kept record carries `"kept": true`, and a label the judge gave two
objects maps to a list of ids. Violation paths on the judge's rows now read
`objects[i] 'label'` — the judge's own position and the id it wrote — where
they read `objects[i]` over the post-processed list; a consumer parsing `path`
should read the index up to the closing bracket. Judge-written `file` and
`process` objects now reach the export with every property the standard
defines; one carrying a property it does not define is set aside as
`stix.unknown_object`, a file with neither `hashes` nor `name` is asked
`stix.file_unidentified`, and a malware object kept without `is_family` or
such a file is declined as `stix.unpublishable_object`, two more codes for a
consumer that partitions on them. The judge's relationships from a declined
malware object name the platform's sample object instead. `stix.property_not_carried` is a new recorded row on the judge's
findings (an export decision, never fed back). `judge_stix_bundle` records now
carry `as_written`: `true` when the bundle is the judge's JSON as written (it
may then carry properties the models do not declare, and the judge's own
labels rather than the published ids — read those through `labels`), `false`
for a record kept as the parsed bundle. A `/reports/{id}/stix?source=judge`
answer with `"kept": false` now covers a run whose judge produced no bundle
too. Malware objects may carry `sample_refs`.

Reports are not migrated. A report stored before the vendor layout renders in
it with the sections it has: its score is ignored, its capability paragraphs
print under the technical analysis, its conclusion's rating beside the verdict
and its indicator table is rebuilt from its own blocks. A consumer reading
`severity.overall_score`, `capabilities_narrative`, `conclusion` or the old
defanged `consolidated_iocs[].value` must stop: the score is gone, the two
prose fields are written by nothing, and the value is live. Scripts that parse
the Markdown by heading must use the new numbered headings, and a pipeline
that expected a summary on a mock run must expect `executive_summary` empty
and read the degradation reason instead.

The triage pack runs `floss` on every PE, so a worker host needs the pinned
FLOSS build as the `analysis` server's host does; the backend image has it.
Without it the pack's entry says the build is missing and names the remedy,
and the run goes on.
