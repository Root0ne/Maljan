# Configuration

Maljan is configured in two places and no others. A small bootstrap contract
comes from the process environment and is validated once at startup; every
other application setting lives in the settings store in Postgres and is edited
from the web console. This document describes both, the export and import
format, and how secrets are stored.

## The bootstrap contract

`apps/api/app/config.py` builds `APISettings` from the process environment
only — no `.env` file is discovered or read. Construction never refuses;
`apps/api/app/bootstrap.py` performs every refusal at startup and raises one
`bootstrap: ...` line naming every problem at once, so a misconfigured
deployment does not have to be restarted once per missing variable.

The full surface is documented in
[`bootstrap.env.example`](../bootstrap.env.example). The table below is the
same contract in short form.

| Variable | Required | Default | Notes |
| :-- | :-- | :-- | :-- |
| `DATABASE_URL` | yes | `postgresql+asyncpg://maljan:maljan_dev@127.0.0.1:5433/maljan` | Async driver. |
| `REDIS_URL` | yes | `redis://127.0.0.1:6379/0` | Job queue, events, rate-limit counters. |
| `MINIO_ENDPOINT` | yes | `127.0.0.1:9000` | Host and port, no scheme. |
| `MINIO_ACCESS_KEY` | yes | `minioadmin` | |
| `MINIO_SECRET_KEY` | yes | — | Refused outside debug while unset or left at `minioadmin`. |
| `SETTINGS_ENCRYPTION_KEY` | yes | — | Fernet key; an invalid or missing key aborts startup. |
| `JWT_SECRET_KEY` | outside debug | — | Refused when unset, under 32 characters, or a known placeholder. |
| `DB_POOL_SIZE` | no | `5` | |
| `DB_MAX_OVERFLOW` | no | `10` | |
| `DB_POOL_RECYCLE_SECONDS` | no | `1800` | |
| `RUN_MIGRATIONS_ON_STARTUP` | no | `false` | Leave off in production; migrate as a deploy step. |
| `MINIO_BUCKET` | no | `maljan-samples` | |
| `MINIO_SECURE` | no | `false` | |
| `JWT_ALGORITHM` | no | `HS256` | |
| `JWT_ISSUER` | no | `maljan-api` | |
| `JWT_AUDIENCE` | no | `maljan-clients` | |
| `JWT_KEY_ID` | no | `v1` | `kid` stamped on new tokens. |
| `JWT_PREVIOUS_SECRET_KEY` | no | — | Accepted alongside the current secret during a rotation window. |
| `JWT_PREVIOUS_KEY_ID` | no | `v0` | |
| `APP_NAME` | no | `Maljan` | |
| `APP_VERSION` | no | `0.1.0` | |
| `DEBUG` | no | `false` | Also enables `/docs`, `/redoc` and `/openapi.json`. |
| `SQL_ECHO` | no | `false` | Independent of `DEBUG`. |
| `CORS_ORIGINS` | no | `["http://localhost:3000","http://127.0.0.1:3000"]` | JSON list. |
| `CORS_ALLOW_METHODS` | no | `GET, POST, PUT, PATCH, DELETE, OPTIONS` | JSON list. |
| `CORS_ALLOW_HEADERS` | no | `Authorization, Content-Type, X-Correlation-Id, X-API-Key` | JSON list. |
| `COOKIE_SECURE` | no | inverse of `DEBUG` | `Secure` flag on the refresh cookie. |
| `AUTH_DISABLED` | no | `false` | Local development only; refused when `DEBUG` is false. |
| `AUTH_DISABLED_USER_ID` / `_EMAIL` / `_FULL_NAME` | no | seeded dev admin | Only read when the bypass is on. |
| `SAMPLES_DIR` | no | `data/samples` | Host directory bind-mounted into the Ghidra container. |
| `UPLOAD_TEMP_DIR` | no | `data/uploads/.tmp` | Scratch directory for uploads and worker tempfiles. |
| `GHIDRA_CONTAINER_SAMPLES_PATH` | no | `/data/samples` | Must match the samples bind mount in `docker/docker-compose.yml`. |

One warning does not block startup: `COOKIE_SECURE` false outside debug, which
means the refresh cookie crosses the wire unencrypted unless a trusted proxy
terminates TLS.

Outside Compose, keep these in the gitignored `bootstrap.env` at the repository
root. `make dev-up`, `make dev-down`, `make dev-logs` and `make migrate` source
it; for a bare process, `set -a; . ./bootstrap.env; set +a` first.

## Settings → Configuration

Everything else is a catalog entry. The catalog is derived from the core
`Settings` model (`src/maljan/core/config.py`) plus the editable and read-only
API fields (`apps/api/app/services/settings_catalog_api.py`), and each entry
carries its own title, description, type, bounds, choices and the group it
belongs to (`src/maljan/core/settings_annotations.py`).

The backend exposes sixteen groups, in this order:

| Group | Covers |
| :-- | :-- |
| LLM & model | Which backend the analysts and the judge call, and the per-call limits. |
| Providers | Credentials, endpoints and model names per LLM vendor. |
| Frontier arms | Evaluation-only comparison endpoints and their cost accounting. |
| Static analysis provider | The static analyst's provider and its connection details. |
| Sandbox provider | Where samples are detonated, or which uploaded report stands in. |
| Tool servers (MCP) | The servers agents may call and the tools each may expose. |
| Memory / LTM (Qdrant) | Backend, collections and how many neighbours are recalled. |
| Analysis layers | Deterministic pre-analysis layers, reference data and thresholds. |
| Negotiation | Rounds and the consensus condition. |
| Chunking | How large inputs are split before they reach a model. |
| Reporting | Report contents and the metadata stamped on it. |
| Agents | The analysts, the active profile and the ReAct limits. |
| Tracing | LangSmith tracing of model calls. |
| Enrichment / threat intelligence | Lookups for the indicators a report names. |
| API | Request limits and login protection; applied immediately. |
| Deployment (read-only) | Bootstrap values, shown for reference. |

The console maps them onto five sections — Models, Analysis tools, Agents and
pipeline, Layers and reporting, Platform — and adds one synthesised group,
Profiles, carved out of Agents
(`apps/web/src/app/(app)/settings/configuration/sections.ts`). A backend group
the console does not list explicitly falls through to Platform, so a new group
appears without a frontend change.

### Editing, review and apply

Edits are staged in the browser, not written per keystroke. The toolbar shows
what is staged, the review step lists each change as a before/after pair, and
applying sends one `PATCH /api/v1/settings` with the whole set. Each entry
declares when it takes effect: `live`, `next_job`, or `restart` for read-only
deployment values.

An entry that has an override can be reset: `DELETE /api/v1/settings/{key}`
removes one override, `DELETE /api/v1/settings` removes a whole group's. The
value then falls back to the catalog default and the console shows it as such.

### Per-agent model overrides

`llm.agents` holds one optional override per agent key — provider, model,
temperature and base URL — so the analysts and the judge need not share a
single model. It is a JSON leaf of its own and is ordinarily edited from the
Agents page, one agent at a time.

The base URL is per agent, and applies to the `openai` and `ollama` providers
only: Anthropic and Gemini are vendor APIs with no endpoint to override, and an
override set against them is rejected on save. Two agents can therefore sit on
two different local OpenAI-compatible servers (llama.cpp / ik_llama.cpp) or two
different Ollama hosts, while the global `llm.openai.base_url` and
`llm.ollama.base_url` stay the fallback for everything that sets none. The
credential is not per agent: an `openai` entry with its own endpoint still
authenticates with `llm.openai.api_key`. A per-agent endpoint gets the same
treatment a global one does — the llama.cpp sampler keys and the structured
output the local servers handle badly are decided from the endpoint the agent
will actually call.

### Which dialect an OpenAI-compatible endpoint speaks

`llm.openai.compat` says whether the endpoint behind `base_url` is llama.cpp or
a hosted OpenAI-compatible API, because the two disagree about what a request
body may contain. Three llama.cpp-only fields exist for good reasons — the
repetition penalty that stops a small local model looping on ATT&CK id recall,
the `n_predict` echo of the output cap that llama.cpp reads where it ignores
`max_completion_tokens`, and `chat_template_kwargs.enable_thinking` — and a
hosted API answers all three with `400 Unsupported parameter`.

| Value | What is sent |
| --- | --- |
| `auto` (default) | `llama_cpp` when the base URL host is loopback, link-local, `.local` or a private address; `standard` otherwise |
| `llama_cpp` | the three extras, whatever the host — for a local server reached through a public name |
| `standard` | OpenAI-standard fields only — for a hosted API, or a local vLLM that validates its body |

An endpoint that rejects one of the extras anyway is retried once without them,
recorded for the rest of the process, and named in a warning that says to set
this value explicitly. `base_url` unset means api.openai.com, which never
receives them in any mode.

### Setup guides

**Settings → Setup** offers seven guided flows
(`apps/web/src/app/(app)/settings/setup/guides.ts`): `llm`, `static`,
`sandbox`, `tool-server`, `agent`, `memory`, `enrichment`. A guide walks
provider choice, credentials, a connection test and a review step, and applies
the result as one write, so a half-configured provider is never left behind.

### Connection probes

Thirteen probes back the "Test" buttons
(`apps/api/app/services/settings_probes.py`): `llm`, `ghidra`, `r2`, `capa`,
`mcp`, `agent`, `cape2`, `triage`, `rest`, `qdrant`, `redis`, `virustotal`,
`abuseipdb`. They are reached at `POST /api/v1/settings/test/{probe}`, with
`/test/mcp` and `/test/agent` taking a body naming the server or agent. A probe
that fails answers 200 with the failure as data — a connection test that fails
is an answer, not an error.

### Format routing and the sandbox

No sample is refused for its format. Routing detects the file type from magic
bytes (`pe`, `elf`, `mach-o`, `apk`, `dex`, `ipa`, `jar`, `ole2`, `ooxml`,
`pdf`, `lnk`, the script types, the archive types) and maps it to a platform.

The platform vocabulary is `windows`, `linux`, `macos`, `android`, `ios`,
`multi` and `unknown`. It is a plain string rather than a closed set: an
unlisted value degrades the rule filtering that reads it and nothing else.
`multi` is a sample that does not bind to one OS — a JAR, a macro document, a
PDF — and `unknown` is the honest answer when the bytes did not say.

Each sandbox is asked for the options its format needs:

- **CAPEv2.** `sandbox.cape2.package_by_format` maps a file type to a CAPE
  analysis package, e.g. `{"apk": "apk", "elf": "generic", "pdf": "pdf",
  "ooxml": "doc"}`. `*` is the fallback key; a format with no entry is
  submitted without a package, so CAPE picks one. The guest platform is sent
  when CAPE has a name for it (`windows`, `linux`, `android`) and left unset
  otherwise. `sandbox.cape2.submit_options` is sent verbatim as further form
  fields (`machine`, `tags`, `options`, `timeout`, anything else
  `tasks/create/file` accepts).
- **Hatching Triage.** `sandbox.triage.profile_by_format` maps a file type to a
  VM profile, with `*` as its fallback and `sandbox.triage.profile` behind
  that, so an operator who never touches the map keeps the profile they had.
- **The REST DSL.** `sandbox.rest.submit.submit_fields` is passed through
  verbatim as extra multipart fields, beside the existing `extra_fields`.
  `sandbox.rest.mapping.channels` maps an operator-chosen channel name to a
  JSONPath for anything the report schema has no field for; namespace the name
  by platform, e.g. `{"android.permissions": "$.apk.permissions[*]"}`. Those
  rows land in `SandboxReport.channels` and are capped and counted like every
  other channel.

### ATT&CK domains

The technique universe spans all three ATT&CK domains. `data/attck_valid_ids.json`
carries one sorted id list per domain (`enterprise`, `mobile`, `ics`), and
`src/maljan/memory/attck_loader.py` downloads and caches each domain's STIX
bundle under `~/.cache/maljan/attck/` (or `MALJAN_ATTCK_CACHE`). Enterprise is
required; Mobile and ICS are additive, and a box that can reach neither keeps
working with a narrower catalog. Regenerate the id lists with
`uv run python scripts/knowledge/prepare_attck_malware_fixtures.py`.

### Rule corpora

The Sigma and YARA corpora belong to the `analysis` tool server, which is what
runs the scans. Point it at your own with two environment entries on that
server (Settings → Tool servers → `analysis` → `env`):

| Name | What it names | Default |
| :-- | :-- | :-- |
| `MALJAN_SIGMA_RULES_DIR` | Directory of Sigma rule YAML, loaded recursively. | `data/sigma_rules` |
| `MALJAN_YARA_RULES_DIR` | The YARA rule file the scan compiles. | `data/yara_ttp_rules.yaml` |

An unset value means the corpus the project ships; a path that does not exist
means an empty corpus and no matches, not a failure. `analysis.sigma_rules_dir`
was the previous name for the first of these — a stored override moves into the
server's `env` automatically on upgrade.

### The evidence budget

`reporting.evidence_budget_bytes` (512 KiB by default) is how many bytes of
tool output one agent may keep in the evidence ledger. Entries past it still
record the call — the tool, the arguments, the outcome and the timing — and
carry no output, and the report states how many were trimmed. Raise it for a
deep reversing loop whose decompilation is the evidence; set it to `0` to keep
every output, which is a supportable choice on a machine with room for it and
a way to fill a JSONB column and a context window on one that has not.

### Read-only deployment group

The Deployment group shows the bootstrap values the process is running with —
debug, the auth bypass, CORS origins, the database, Redis and MinIO endpoints,
the cookie flag and the two sample paths. They are not editable from the
console (`editable=false`, reason "set in the deployment environment; restart
required"), and DSNs are redacted before they are shown. Change them by
redeploying with a different environment.

## Tools, and the measurement baseline

Four tool servers are enabled out of the box, and a fifth (`virustotal`)
ships ready to enable. What each offers is in
[architecture.md](architecture.md); what an operator changes here is the
binding, the exposure (`tools`) and whether the server runs at all (`enabled`).

There are two ways a server reaches an agent, and the built-ins use both.
`network` and `threatintel` are bound by role (`MCPServerConfig.agents`), as
they always have been. `analysis` and `knowledge` carry `agents: []` and are
bound only by the `ToolRef`s in the agent definitions — `analysis` and
`knowledge` on the static analyst, `knowledge` on the dynamic and network
analysts and on the judge. That is what makes a definition's tool list
authoritative: a clone of the static analyst with the `analysis` reference
removed really runs without the analysis tools, which could not be true if the
server also bound itself to the role.

The per-format tools of `analysis` rest on optional libraries. Install them
with `uv sync --extra tools` (the backend image already does); without them
`apk_info` falls back to the zip-level facts and `macho_info`, the OLE2 half of
`document_info` and the 7z half of `archive_list` answer
`{"error": "<module> is not installed"}`. Nothing else changes, and the server
starts either way.

Four teams ship built in; they are listed under **Teams** below. `default` is
the three analysts with their tools.
`measurement` is the same three analysts with `exclude_servers: ["*"]`,
`exclude_sandbox_tools` on and `static_provider` forced to `none` — the
baseline for measuring what the ensemble contributes without any tool. Select
it from Settings → Agents and pipeline like any other team; a run under it
resolves each analyst to a prompt, a model and no tools at all.

The wildcard is deliberate. A fixed list of the four built-in keys would still
hand the baseline any server an operator added afterwards, and a measurement
claim that quietly acquires tools is worse than no baseline. `exclude_servers`
is also the one field an operator may edit on a built-in profile, so a
deployment that needs a variant of the baseline can write one without cloning
it; every other field stays locked.

A team's three fields are honoured in `agents/composition.resolve_agent` and
in the analysts' own attach path, so they apply to a custom team too:
`exclude_servers` withholds servers by key or `"*"` for all,
`exclude_sandbox_tools` withholds the in-process sandbox tool set, and
`static_provider` overrides every member's provider at once. A single stage can
withhold every built-in server from its own agents with
`builtin_tools: false`, which stacks on top of whatever the team excludes.

### VirusTotal's own MCP server

`virustotal` is a fifth built-in and the only one that is not a process of
this deployment: it is VirusTotal's server, reached over streamable-HTTP at
`https://ai.virustotal.com/mcp`. Nothing is installed for it and no VirusTotal
API key is involved. It ships **disabled**, because it needs a credential that
only a registration produces.

Register from Settings → Setup guides → Add a tool server → **Connect
VirusTotal**. The button calls
`POST /api/v1/settings/virustotal/register`, which asks VirusTotal for an
agent token, stores it as this server's `auth_token` (its own encrypted row,
like every other tool-server credential), turns the server on and answers with
the masked state and the public handle VirusTotal now knows this deployment
by. Registering again replaces the token. Until a token is stored, the Test
button answers "no agent token" rather than dialling out.

The lookups are ticked by default and are read-only:
`get_file_report`, `get_url_report`, `get_domain_report`, `get_ip_report`,
`get_analysis` and `get_submission`. `submit_file` is advertised and stays
**unticked**: uploading a sample publishes it to VirusTotal, which is a
disclosure an operator opts into, so it takes a deliberate tick in the Tools
step. See [security.md](security.md) for what that changes.

The token is subject to VirusTotal's published quotas. Over quota, the server
answers the tool call with a 429 carrying `Retry-After`; the analyst records
that answer and carries on without it, exactly as it does for any tool that
declines.

`virustotal` is referenced by the `network` analyst, the `judge` and the
seeded `triage` agent. A disabled server contributes no tools and no
degradation reason, so those references cost nothing until it is registered.

`services/threatintel-mcp` is unchanged: it still offers VirusTotal and
AbuseIPDB lookups over their REST APIs with `VIRUSTOTAL_API_KEY` and
`ABUSEIPDB_API_KEY`. Where both are on, `virustotal` supersedes its VirusTotal
half — it is VirusTotal's own server, richer and maintained by them — while
the AbuseIPDB half stays the only source for IP abuse reports. A deployment
with an API key and no agent token keeps working exactly as before.

**The stdio alternative.** The same server runs locally as `vt-mcp`, reading
the same agent token from `VTAI_TOKEN`, and that form offers one tool the
remote one cannot: `submit_local_file`, which uploads by path. The remote
server has no view of this host's filesystem, so it offers `submit_file`
(the bytes, base64) instead. Operators who want the local-path upload install
it as described in [deployment.md](deployment.md) and add a second server
entry with transport `stdio`.

## Teams and stages

A team (`core.agents.profiles.<key>`, edited under Settings → Agents and
pipeline → Teams) is an ordered list of stages. Each stage is:

| Field | Meaning |
|---|---|
| `key` | Slug, unique in the team. Names the stage everywhere it is reported. |
| `label` | Display name; empty means the key. |
| `kind` | `analysis`, `debate`, `verdict` or `report`. |
| `agents` | Definition keys this stage runs. Empty on a debate stage. |
| `depends_on` | Earlier stage keys this one runs after. |
| `when` | Condition deciding whether it runs. Empty means always. |
| `mode` | `sequential` (default) or `parallel`, for an analysis stage. |
| `inject_upstream` | `none`, `findings` (default) or `full`. |
| `debate` | Round limit, consensus threshold and sycophancy check, for a debate stage. |
| `builtin_tools` | `false` withholds every built-in server (`analysis`, `knowledge`, `network`, `threatintel`, `virustotal`) from this stage's agents. |

### The teams that ship

| Team | Stages | What it is for |
| :-- | :-- | :-- |
| `default` | `analysis` (static, dynamic, network) → `debate` → `verdict` → `report` | The general case. |
| `measurement` | The same four, with every tool server withheld | What the ensemble contributes with nothing to call. |
| `mobile` | `triage` → `android_static` → `dynamic` → `debate` → `verdict` → `report` | An APK or a DEX. |
| `deep_static` | `triage` → `static` → `reversing` → `network` → `debate` → `verdict` → `report` | Reading the code. |

`mobile` and `deep_static` are built from three seeded generic agent
definitions — `triage`, `android_static` and `reverser` — whose prompts live in
`src/maljan/agents/prompts/`. A generic agent has no class: it is a definition,
a prompt and a tool list, which is what makes a team of your own something to
write rather than something to build. Clone one of these as the starting point.

Their conditions are the interesting part. `android_static` runs on
`file_type in ("apk", "dex")` and `dynamic` on `has_sandbox_report`, so
submitting a PE under `mobile` produces a run where the Android stage is a row
that declined with the condition it failed printed beside it — the team was
applied and the console shows what it chose not to do, rather than showing
nothing. `deep_static`'s `network` stage runs on
`has_pcap or has_sandbox_report`, and its `reversing` stage depends on `static`
with `inject_upstream: findings`, so the reverser is handed each static finding
and asked to confirm or refute it at function level.

`reverser` takes `ToolRef(kind="provider")` rather than a named server, which
means the tools of whichever static provider this deployment configured. On a
deployment with `static.provider = none` that reference resolves to nothing:
the stage still runs, and its prompt still asks it to open a decompiler, so
what comes out is a confident ungrounded answer rather than a visible failure.

Saving such a team is allowed and says so. A team validated against a runtime
provider setting could not be saved before the provider was configured, and the
order those two happen in is the operator's — so the settings API answers a
successful write with a **warning** on that stage instead of refusing it, and
the console draws it on the stage card: *"reverser reads the static provider's
tools, and this deployment's static provider is 'none'."* A stage whose agents
have no other tools at all is named as running with nothing to call; one that
also holds a tool server, as `deep_static`'s reverser does, is named as running
without the decompiler.

Like every built-in team, all four are editable only in their debate options,
their `builtin_tools` switches and `exclude_servers`. Everything else means
cloning the team, which the console does in one click.

### A name a later release takes

Seeding a built-in takes a name. `triage`, `android_static`, `reverser`,
`mobile` and `deep_static` were all legal names for an operator's own agent or
team before they were seeded, and a stored entry under one of them would
otherwise be refused as tampering with a built-in — on every read, which is to
say at boot.

So a stored entry under one of those five names that is not the seed is renamed
out of the way on load: `reverser` becomes `reverser_custom`, and every
reference to it moves with it — the teams that named it, the per-agent model
entry under `llm.agents`, each server's `agents` binding and both
`react_*_overrides` maps. The rename is logged once at warning level, and
`alembic upgrade head` writes it into the stored document so the console shows
the new name rather than renaming the same document on every read.

This applies only to names a release newly reserved. `static`, `dynamic`,
`network`, `judge`, `reporter`, `default` and `measurement` have been reserved
for as long as there has been a settings store, so a stored document that edits
one of those is still refused, and a name typed into the console after the seed
exists is still refused per field while it is being typed.

A team needs exactly one `verdict` stage and at most one `report` stage, which
is always last. A stage may only depend on a stage declared **above** it, which
makes the card order the run order and a cycle impossible to write down rather
than merely detected. A debate stage needs an analysis stage upstream of it,
and an analysis stage needs at least one agent. An agent belongs to one
analysis stage.

A debate stage hands over to exactly one **node**. It leaves through a
conditional edge, and a conditional edge has one destination per branch, so a
debate may not feed two stages — and may not feed a parallel analysis stage
with more than one agent, which is two nodes even though it is one stage. A
sequential stage of any size is one node and is fine. This is refused when the
team is saved, not when the first job builds its graph.

A team stored as a plain list of analysts — every team written before stages
existed — is read as the four stages that list has always meant: `analysis`
(those analysts, in `llm.parallel_analysts`' mode) → `debate` (with the round
limit and threshold from `negotiation.*`) → `verdict` (the judge) → `report`
(the reporter). The stored `analysts` list is kept alongside the stages it
produced; the model reads the stages.

Such a team is marked `derived_from_analysts`, and while the mark is set *and*
its stages are still the plain conversion of its analyst list, they are rebuilt
from that list and those two global keys on every load. The mark is checked
rather than believed: it travels in the stored document, so it also arrives
from an import, a script's PATCH or a hand-edited export, and a team whose
stages someone has written is left as written and the mark cleared. That is what keeps a team nobody has opened following
`llm.parallel_analysts`: an operator who moves from a hosted API back to the
single-slot local model changes one setting and the team follows, instead of
running analysts in parallel forever because it happened to be migrated on a
day when parallel was on. The console clears the mark on the first stage edit
— from then the stages are the operator's, and nothing rewrites them.

### Conditions

`when` is an expression in a small language evaluated on the worker. It is
Python's own grammar with an allow-list on top: comparisons (`==`, `!=`, `in`,
`not in`, `<`, `<=`, `>`, `>=`), `and`, `or`, `not`, literals, and tuples or
lists of literals. There are no function calls, no arithmetic, no
comprehensions and no attribute access except into `stages`. A condition that
does not parse is refused when the team is saved; one that fails at run time
skips its stage with the reason recorded rather than failing the job. The
console checks each condition box against the same parser as it loses focus
(`POST /api/v1/settings/validate-condition`), so a typo is answered next to the
box it was typed into rather than when the whole team is applied.

The names it may use:

| Name | Meaning |
|---|---|
| `file_type` | The detected type, e.g. `PE32 executable`. |
| `platform` | The canonical platform, e.g. `windows`, `linux`, `android`. |
| `mime` | The sandbox report's media type, when there is one. |
| `size` | Size in bytes, when the sandbox report carries it. |
| `extension` | The submitted file name's extension, lowercased, without the dot. |
| `sandbox_available` | Whether a sandbox report reached this run. |
| `has_sandbox_report` | The same fact, named for readability. |
| `has_pcap` | Whether the report carries a non-empty network block. |
| `stages.<key>.<field>` | A stage result: `ran`, `reason`, `claim_count`, `technique_ids`, `finding_count`, `agents`. |

`stages["triage"].ran` is the same lookup as `stages.triage.ran`. A stage the
run never reached reads as one that did not run, so naming a stage that was
itself skipped is not an error.

Examples:

```
platform == "windows"
extension in ("apk", "dex")
has_pcap and stages.triage.claim_count > 0
"T1055" in stages.static.technique_ids
not stages.detonate.ran
size > 10485760
```

### What a stage reads

`inject_upstream` decides what a stage is told about the stages it depends on.
`none` tells it nothing, which is what the default team uses — its analysts
have never seen each other's work before the debate. `findings` gives it each
upstream agent's claims with their technique, confidence and evidence id.
`full` adds each upstream agent's prose report. Both are capped by
`core.reporting.upstream_findings_max_chars` (6000 by default), and a block
that is cut says so.

The block arrives as an `upstream_findings` field inside the stage's first
chunk when that chunk is a JSON document, and in front of it when it is not. A
static or generic agent's first chunk is JSON with a contract on it — the
container-visible `analysis_file_path` is read back out of it, and putting
prose in front would leave the agent inventing a path again.

Injection never changes whether a stage has data. An agent whose loaders
produced nothing but a "no data available" placeholder is still skipped, with
or without a block to read.

Which slice of the job an agent reads is its own setting,
`agents.definitions.<key>.data_sources`. Empty means the slice the agent's
*role* has always read: the parsed sample for a static analyst without a
sandbox report and the report's `target` block with one, the behaviour log for
a dynamic analyst, the network block for a network analyst, and the sample plus
the whole report for a generic one. A non-empty list is taken literally and in
order, which is the point — a clone of the static analyst can be pointed at the
network block without becoming a network analyst:

| Source | What it contributes |
|---|---|
| `sample.path` | The container-visible path the agent's tools open the sample at. |
| `sample.chunks` | The parsed sample profile. |
| `sandbox.target` | The sandbox report's `target` block. |
| `sandbox.behavior` | The behaviour log, through the dynamic parser. |
| `sandbox.network` | The network block, through the network parser. |
| `sandbox.full` | The whole sandbox report. |

A source with nothing behind it contributes nothing — an agent that asked for
the network block on a sample nobody detonated has no network block, and the
analyst node reports that once as a no-data stage rather than once per source.

## Tool servers on another host

Every path-taking tool assumes the server can open the path the worker hands
it. That holds for a local stdio sidecar and for nothing else. There are two
ways to make it hold elsewhere.

**A shared volume.** Mount the same directory into both, and point the
provider's mirror at it — `static.r2.mirror_dir` is the worked example: the
worker copies the sample there (0o700 directory, 0o600 file, removed when the
job ends) and the server reads it from its own mount. Nothing is uploaded, and
the path both sides use has to agree.

**The `put_sample` convention.** A server reached over HTTP advertises
`put_sample` on its manifest, and Maljan uploads the sample to it before the
agent's first tool call:

| tool | arguments | returns |
| :-- | :-- | :-- |
| `put_sample` | `filename`, `content_b64`, `sha256` | `{"path": ...}` |
| `put_sample_begin` | `filename`, `sha256`, `size` | `{"upload_id": ...}` |
| `put_sample_chunk` | `upload_id`, `seq`, `content_b64` | `{"seq": ...}` |
| `put_sample_finish` | `upload_id` | `{"path": ...}` |

Samples over 8 MiB go through the three chunked calls when the manifest carries
all of them, and through the single call otherwise. Chunks are keyed by `seq`
rather than streamed, so a transport that retries one cannot corrupt the file.
The returned path is what that server's tools are then called with —
`agents.tool_pinning.pin_paths` substitutes per server, so one agent can hold a
local sidecar's tools and a remote server's at the same time and each gets the
path it can open. Uploads are cached per `(server, sha256)` for half an hour.

**The transport decides, not the manifest.** Staging runs for `http`,
`streamable-http` and `sse` transports only. A stdio sidecar is a child process
of the worker reading the same filesystem, so it is handed the path: uploading
to it would write a second copy of the sample — a full read plus base64 in the
worker's memory and malware bytes accumulating on disk — to tell the server
about a file it can already open.

Staging never fails a run. An upload that goes wrong is recorded as
`sample staging failed for '<server>': <reason>` on the run's degradation
reasons, and the server is called with the local path exactly as before. The
paths that were used are recorded on the run under `remote_sample_paths`, which
stays empty on a default install because every built-in server is stdio.

The path substitution is per server and matches three spellings of the sample:
the worker path in full, its basename, and the basename of the staged copy. A
server that stored the sample under a name of its own — the `analysis` sidecar
prefixes the digest — is therefore still corrected when the model repeats the
name the prompt showed it.

The built-in `analysis` sidecar implements `put_sample*` even though it ships as
a stdio server, because an operator may run that same file behind an HTTP
transport on another host. Two environment variables configure it, and they are
the only ones it is allowed to see:

| variable | default | meaning |
| :-- | :-- | :-- |
| `MALJAN_STAGING_DIR` | a `maljan-analysis-mcp` directory under the system temp dir | where uploads land |
| `MALJAN_STAGING_TTL_HOURS` | `24` | how long a staged sample is kept; `0` disables pruning |

The directory is created with mode 0o700 and refused if what is already at that
path is a symlink or belongs to another user — the default name is predictable
and the system temp directory is shared. Each file is created with
`O_CREAT|O_EXCL|O_NOFOLLOW` at 0o600 rather than written and then chmodded, and
every `put_sample*` call prunes entries past the TTL, so a long-lived server
does not accumulate samples without bound.

## Export and import

`GET /api/v1/settings/export` (admin) returns the configuration as JSON and
sets `Content-Disposition: attachment; filename=maljan-settings.json`:

```json
{
  "format": "maljan-settings/1",
  "exported_at": "2026-09-12T00:00:00Z",
  "values": { "core.llm.provider": "openai" },
  "secrets_omitted": ["core.llm.openai.api_key"]
}
```

- Only keys the store actually holds are exported — values still on their
  catalog default are left out, as are read-only entries.
- No credential is ever written to the document. Secret entries are skipped,
  masked values nested inside a composite (an MCP server's `auth_token`, a
  frontier arm's `api_key`) are stripped at any depth, and every value in a
  server's `env` map is masked while its variable names stay.
- `secrets_omitted` names each credential the document does not carry, so an
  operator can see what has to be re-entered on the other side. Those paths are
  informational, not catalog keys.

`POST /api/v1/settings/import` (admin) accepts the same document. A `format`
other than `maljan-settings/1` is rejected with 422; unknown or read-only keys
are rejected with 422 and a per-key error, and nothing is applied when any key
fails. A successful import writes one audit row (`settings.import`) naming the
applied keys. The console previews the document against the current
configuration before sending it.

## Secrets

Secret settings are encrypted with Fernet under `SETTINGS_ENCRYPTION_KEY` and
stored as `enc:v1:<token>` (`src/maljan/core/settings_secrets.py`). The API and
the worker both read the key from their own environment, so both can open the
same rows.

Credentials nested inside composite settings are never kept inside the
composite row. An MCP server's `auth_token` and a frontier arm's `api_key` are
split into their own encrypted rows and merged back when the value is read, and
a startup repair moves any that a previous version left inline
(`apps/api/app/services/composite_secrets.py`). The console never echoes a
stored credential: it shows a mask and a short hint.

**Rotation caveat.** There is no re-encryption step and no multi-key reader. If
`SETTINGS_ENCRYPTION_KEY` changes, existing secret rows can no longer be
opened: the service logs a warning per row and the setting falls back to its
default, while the console still reports the secret as set. Re-enter each
secret after a key change, or restore the previous key.
