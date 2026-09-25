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
[`bootstrap.env.example`](https://github.com/Root0ne/Maljan/blob/dev/bootstrap.env.example).
The table below is the
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
| `JWT_PREVIOUS_SECRET_KEY` | no | — | Accepted alongside the current secret during a rotation window; set `JWT_PREVIOUS_SECRET_NOT_AFTER` beside it to give that window an end. |
| `JWT_PREVIOUS_KEY_ID` | no | `v0` | |
| `JWT_PREVIOUS_SECRET_NOT_AFTER` | no | — | ISO-8601 moment (UTC when it carries no offset) after which a token signed with the previous secret is refused. Unset means the window has no end, which the startup check warns about at every start; a value that does not read as a moment is refused at startup. |
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
| `GHIDRA_CONTAINER_SAMPLES_PATH` | no | `/data/samples` | The samples directory as the Ghidra container sees it: the path INSIDE the container, the right-hand side of the samples bind mount (`../data/samples:/data/samples` in `docker/docker-compose.yml`). Not the host directory. |

`GHIDRA_CONTAINER_SAMPLES_PATH` is the one path in this table that names a place
inside another container. The worker copies each sample under `SAMPLES_DIR` on
its own host and hands Ghidra the same file under this path, so it has to be
where the Ghidra container sees that directory. The common mistake is setting
it to the host directory (for example `/home/<user>/Maljan/data/samples`) when
the worker runs outside Compose: Ghidra then answers every load with
`File not found`, and the Ghidra agent stops with "Ghidra could not open the
job's sample". With the shipped Compose file the value is `/data/samples`
whether or not the worker itself runs in Compose. The worker states the value
it uses, and whether it came from the environment or the default, in one line
at start (`Ghidra samples path: ...`).

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

The backend exposes seventeen groups, in this order:

| Group | Covers |
| :-- | :-- |
| LLM & model | Which backend the analysts and the judge call, and the per-call limits. |
| Providers | Credentials, endpoints and model names per LLM vendor. |
| Frontier arms | Evaluation-only comparison endpoints and their cost accounting. |
| Static analysis provider | The static analyst's provider and its connection details. |
| Sandbox provider | Where samples are detonated, or which uploaded report stands in. |
| Tool servers (MCP) | The servers agents may call and the tools each may expose. |
| Memory / LTM (Qdrant) | Backend, collections and how many neighbours are recalled. The enrichment worker and the API's health probe read these same keys; there is no second, API-side copy of them. |
| Analysis layers | Deterministic pre-analysis layers, reference data and thresholds. |
| Negotiation | Rounds and the consensus condition. |
| Chunking | How large inputs are split before they reach a model. |
| Reporting | Report contents and the metadata stamped on it. |
| Agents | The analysts, the active profile and the ReAct limits. |
| Live events | The conversation feed the console draws a running analysis from, and how long the record of one is kept. |
| Tracing | LangSmith tracing of model calls. |
| Enrichment / threat intelligence | Lookups for the indicators a report names, and whether they run on the enrichment worker or beside the analyses. |
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

An entry may also name the models the agent falls back to, in order, under
`fallbacks` — each one a provider, a model and, for `openai` and `ollama`, a
base URL of its own, written exactly like the entry's first model. A fallback
with no temperature takes the entry's. The Agents page edits the list under
the model override (add, remove, move up and down). The next model is asked
**only when the one before failed as a provider**: a refused or dropped
connection, a timeout, an HTTP 5xx, 408 or 429, a model the server does not
have, a refused credential, or a refusal the provider reports as an error.
Never on what a model said: an answer the validation loop rejects is sent back
to the model that wrote it, and a parse or validation error a model's answer
raises reaches the loop rather than the next model. A timeout is a provider
failure because every model on a list but the last has its own turn deadline —
`core.llm.fallback_turn_share` (0.5) of what is left, at that turn, of the
budget the current loop runs under (never less than one second), so inside an
ask it is a share of the ask's clock and a stall late in a loop is still
replaced before the loop cancels it; a share of the loop because the loop is
what would otherwise cancel a stalled model first. The reporter's list starts
over before the narrative round, against its 600 s, and again before the
composer sections, against `core.reporting.composer_per_section_timeout` —
and every provider's client has a 1800 s request timeout until the model's
pace is measured, after which each request is sized for its own output cap
(see *A call waits as long as its answer takes*). A 429 or 503 whose
`Retry-After` (seconds or an HTTP date) asks for at most thirty seconds is waited out on the same model
once before the list moves on. Once the list has moved, the model that answered
stays for the rest of that loop (a stalled first model costs one deadline, not
one per turn), and the next loop starts at the first model again.
A model named twice in one list is refused on save. An entry without
`fallbacks` is the single-model form every entry had before, unchanged.

Which model answered is recorded on every turn — on the ledger entry of each
call the turn asked for and per agent in `run_summary.models` — and the switch
is recorded once, with the reason in words: in the run summary and as a
`model_fallback` event the conversation draws whether or not deltas stream.

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
| `deepseek` | DeepSeek's API: the output cap as `max_tokens` as well, and `disable_thinking` as `thinking.type: disabled`; none of the llama.cpp extras |

An endpoint that rejects one of the extras anyway is retried once without them,
recorded for the rest of the process, and named in a warning that says to set
this value explicitly. `base_url` unset means api.openai.com, which never
receives them in any mode.

`deepseek` is a value of its own because no one body serves both APIs. OpenAI's
clients send the output cap as `max_completion_tokens`, which DeepSeek's chat
completions ignore (measured: a cap of 5 came back as 88 tokens with thinking
off and 138 with it on, both ending `stop`); DeepSeek reads `max_tokens`, with
reasoning counted against it, which OpenAI's own API refuses beside
`max_completion_tokens` for its reasoning models. Under `auto` a DeepSeek base
URL is a hosted API like any other, so no cap reaches it: the value is set, not
guessed from the host. DeepSeek also accepts `chat_template_kwargs` and ignores
it, so `deepseek` is the only value under which `disable_thinking` reaches it.

A DeepSeek thinking model returns its reasoning as `reasoning_content` beside
`content`, and on a request that carries tools that reasoning has to be sent
back on its assistant turn in every later request: DeepSeek's thinking-mode
guide (https://api-docs.deepseek.com/guides/thinking_mode, on tool calls) says
the API answers 400 otherwise. The OpenAI client reads it from no answer and
writes it into no request, so under `deepseek` the provider keeps each turn's
`reasoning_content` exactly as returned and sends it back on that turn, on
every request that carries tools. A request without tools is sent without it:
the guide says it is not needed there and is ignored if sent, so it would only
be input read for nothing. The answer's `content` is untouched, and a turn sent
again is sent byte for byte, so the request's front stays what DeepSeek has
cached. The reasoning sent back counts toward the conversation's size in the
window budget, and its tokens are in the run's counts (`reasoning_tokens`); its
text stays with the turn in the loop's conversation and is not published. The
cap goes out as `max_tokens` on each request, so a cap bound for one call
reaches DeepSeek as the model's own does.

`llm.openai.compat`, like every `llm.openai` setting, is global: it applies to
every model built on the `openai` provider, per-agent entries and fallbacks at
their own endpoints included. Under `deepseek`, an `openai` entry pointing at a
local llama.cpp server gets DeepSeek's fields and none of the llama.cpp extras,
so a run that mixes the two keeps its local entries on another provider
(`ollama`) or runs them under `llama_cpp` in a separate configuration.

### Reasoning effort

`llm.openai.reasoning_effort` is sent as the request's top-level
`reasoning_effort` field, on every request of every dialect, exactly as written:
DeepSeek takes `low`, `high` and `max` (its thinking-mode guide,
https://api-docs.deepseek.com/guides/thinking_mode, maps `xhigh` to `high` and
`ultra` to `max`), OpenAI's reasoning models `minimal` to `high`. Empty, the
shipped value, sends nothing and leaves the endpoint's own default (`high` on
DeepSeek). A value the endpoint does not know is its own 400, and the `llm`
connection test asks with the value, so it is found there rather than on a
job's first call. The setting is global, sent to every `openai`-provider model
including per-agent entries and fallbacks: a per-agent model entry names a
provider, a model and an endpoint, and carries none of the provider's request
settings.

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

A probe runs against the staged values on top of the stored ones, so an input
the caller did not stage comes from the store — including the credential. That
means a staged endpoint is sent the stored key for that provider, which is a
secret the console never shows in the clear. Every probe therefore writes one
audit row (`settings.probe`) naming the probe, the endpoints it was pointed at
(as labels: scheme and host), the keys that were staged for it and whether it
succeeded. The values themselves are never in the row. The routes are
admin-only, as they have always been; what was missing was the record.

### Where the enrichment runs

`api.enrichment_dedicated_worker` decides whether a report's reputation lookups
are queued for the enrichment worker or beside the analyses, and it ships off:
a deployment that runs one process keeps working. On the shared queue the
enrichment yields — it re-enqueues itself a minute later whenever an analysis
is waiting, up to a total of 30 minutes, after which it runs anyway — so an
analysis submitted after an enrichment does not wait for the whole of it, and
the enrichment is never starved. Turn it on where the second process actually runs
— the compose stack starts one and sets the default beside it. With it on and
nothing reading that queue, the analysis worker logs one warning at startup and
`GET /api/v1/system/status` reports `enrichment_worker` as `down`; the
enrichments stay queued and run when a worker appears.

Flipping the setting takes effect on the next enrichment: an arq job id is one
per report *and queue*, so a report queued under the old setting can be queued
again for the other worker straight away, and two triggers for one report on
one queue still coalesce into one job. What does not move is an enrichment
already sitting in the queue it was put in — it runs when that queue's worker
runs, which for the analysis queue is between analyses.

One consequence of that, if a flip happens while an enrichment is still queued:
the report can be enriched twice, once from each queue. Both runs read the
report and write the same fields, and both completion events take their own
sequence numbers, so the feed's count still matches its last number; what it
costs is a second set of provider lookups against a rate-limited key and two
completion events for one report. Flipping the setting when nothing is queued
avoids it.

That worker runs `ENRICHMENT_MAX_JOBS` (default 2) at a time. More than one
because each job waits on somebody else's HTTP; not many more because they
share one VirusTotal key and one AbuseIPDB key, and those providers rate-limit
per key rather than per job. `api.enrichment_max_lookups` still caps each
report; this multiplies how many reports are in flight against the same limit.

### A model is probed before a job may name it

**What the probe does.** Both the `llm` and the `agent` probe end by asking for
one short answer — one turn, eight tokens, at the endpoint and on the model the
run will use, through each provider's own completion API (`/chat/completions`
for an OpenAI-compatible server, `/api/generate` for Ollama, `/v1/messages` for
Anthropic, `:generateContent` for Gemini). Listing a provider's catalogue comes
first and is not enough on its own: a server can offer a name it will not load,
a key can be refused for one model and not another, and a misspelling can land
on a name the catalogue happens to hold. A call that came back with nothing in
it — an empty `choices`, a candidate that was filtered away — is a failure too.
The OpenAI-compatible body carries the same `chat_template_kwargs.enable_thinking`
switch a run would send, under the same `llm.openai.compat` rule and at every
endpoint asked, and a reply whose only text is `reasoning_content` counts as an
answer: a model that reasoned is a model that loaded on a key that was accepted.
Ollama is asked the same way and read the same way. Its thinking arrives in its
own `thinking` field, which counts as an answer for the same reason — without
that, every reasoning model served by Ollama failed the probe, because eight
tokens are spent thinking and `response` comes back empty, and with
`llm.require_probe` on the deployment could then create no job at all.
`llm.ollama.disable_thinking` sends `think: false`, so the budget is spent on
the answer instead; it is off by default, because Ollama refuses the field for
a model that has no thinking mode. A model whose thinking field is empty as
well — some do not fill it at eight tokens — still comes back as *answered
nothing*, so that failure and a timeout both carry a sentence naming the
setting and what it does. A measured 12B reasoning model failed the probe in
55 s at the default and passed in 243 ms with the setting on; with
`llm.require_probe` on, every job is refused in between. See the low-memory
option in [getting-started.md](getting-started.md).
Ollama's body also carries `options.num_ctx` and `keep_alive` from
`llm.ollama.num_ctx` and `llm.ollama.keep_alive`, the two fields a run sends
with every call that decide which instance Ollama keeps loaded. Ollama loads a
model at the context size the request names and reloads it when a later
request names another, so a probe asked at the server's default (4,096) left
the model at that size and the job's first call paid a full reload out of its
analyst's time budget.
The completion gets ninety seconds of its own, because a local server reloads a
model it had unloaded and a large one is not a ten-second load.

**What is written down.** One row per `(endpoint, model)` pair the probe
actually completed a call with, carrying the provider, whether the model
answered and the sentence it came back with. The `llm` probe completes one call
per pair it will file: the selected provider's **expert** model at its own
endpoint, and every per-agent override at *its* own endpoint, which is how a
second llama.cpp or a second Ollama host is proved. Anthropic and Gemini have
one endpoint apiece, named rather than addressed, so a per-agent entry there
differs only in its model — and each is still asked, because a key may be
refused for one model and not another. The same pair named twice is one call
and one row. The judge model is listed and never called, so it is not filed.
The `agent` probe files the pairs its agent would use: its first model, and
every model it falls back to, one after another — the agent passes only when
every model on its list answered. The `llm` probe asks the fallbacks served by
the selected provider along with the per-agent entries.

Where a call goes is worked out in one place (`maljan.core.model_assignments`)
for the probe and for the gate alike, and folded there the way a URL folds —
lower-case scheme and host, the scheme's default port dropped, no trailing
slash — so `http://box:8080/v1/`, `HTTP://BOX:8080/v1` and `http://box:80/v1`
file and resolve under one spelling instead of four.

A call that ran out of time leaves **no** row at all — neither a pass nor a
failure. Nothing was learned about that pair, and writing a cold model down as
a missing one would lock the operator out of their own jobs; the probe says so
and asks to be run again once the model is warm.

**What it costs.** The `llm` probe asks its pairs one after another — a single
local server told to load several models at once is the failure this project
has already diagnosed — with ninety seconds for each call and five minutes for
the whole probe, counted from the moment the probe starts, so the catalogue
listing in front of the calls comes out of the same five minutes rather than
being added to them. A pair there was no room left to ask is named in the answer as
not tried and files no row, exactly as a timeout does; pressing **Test** again
asks it. In a failing pair's sentence an endpoint is printed as its scheme and
host, so a base URL that carries credentials does not reach the screen or the
stored row.

**Where the gate stands.** Submitting a job reads that record for every model
the run can reach — fallbacks included, each named in the refusal as the model
the agent *falls back to* — the agents its team's stages name, and every agent those
can ask through `ask_<key>`, and so on — and refuses with 422 when one of them
has no passing row, naming the agent, the model, the endpoint and the probe's
last message. The endpoint appears there as its label — scheme and host — and
never as the value a call is made with: that refusal is read by whoever
submitted the job, not only by an admin, and a base URL configured with
userinfo would otherwise show them the endpoint's credentials. Saving a
per-agent model (`core.llm.agents.*`) is refused with
the same sentence, because an operator who saves a model nothing can reach has
made the mistake the gate is about and the settings page is where it can be
fixed. The console shows the sentence as written in both places.

The pair is also the invalidation. A changed endpoint or a changed model is a
different question, finds no row, and is refused until it is probed: nothing
has to expire a result, because a result is never read for a pair it was not
taken against. The endpoint half of the pair is folded the way a URL folds —
lower-case scheme and host, the scheme's default port dropped, no trailing
slash — so one server typed four ways is one key rather than four. A row
written before that folding existed is filed under the spelling of the day it
was taken; re-run the probe if the gate refuses a model you have tested.

`core.llm.require_probe` is on, and turning it off is the only way past the
gate — neither a job nor a save can ask to skip it. It is there for an
air-gapped batch run, where the endpoint is known good and nobody is at a
console to press a button.

### A team that needs Ghidra waits for it

A static provider that degrades (r2, a generic MCP server, capa/YARA) costs a
run some evidence when it is missing, and the run says so. Ghidra does not
degrade: a static run with no decompiler is a confident report grounded in
nothing, so the agent that needs it fails the run when it starts — minutes and
a paid model call after the sample was accepted.

So `POST /api/v1/jobs` asks first, in the same place as the model gate and
with the same 422 (`apps/api/app/services/provider_readiness.py`). Every agent
the chosen team can run — its stages' agents and every agent they can ask —
that opens a static provider is resolved to the provider it would open, as the
run resolves it: the team's forced provider, the definition's own
`static_provider`, the job's `static_provider`, or `core.static.provider`.
Each distinct provider that does not degrade is asked whether it is ready:
Ghidra over http answers when `GET <url>/mcp/schema` with the configured token
returns below 400, which loads and analyses nothing. Ghidra over stdio is
started by the job itself, so what is checked is that `core.static.ghidra.command`
is set and names an executable the API host finds (by its last path segment in
the refusal). The check runs where the API runs, on its PATH and filesystem, so for a worker on another host or in another container it says only what the API can see. The shipped transport is `stdio` with no command, so an operator
who switches Ghidra on without setting `transport` to `http` is told that here
rather than when the agent starts. The refusal
names each agent, the provider and its address as scheme and host:

```
A static provider this team needs is not ready, and a run without it fails when
that agent starts. Start it, switch it on or correct its address, or choose a
team that does not need it. agent 'all_tools_reverser_ghidra' needs static provider
'ghidra' at http://ghidra-mcp:8089, which is not ready: ConnectError: ...
```

Ghidra switched off (`core.static.ghidra.enabled` false) attaches nothing and
fails nothing, and it is the shipped default, so it is refused only for an
agent that was given it by name — by its definition, by the team or by the
job's `static_provider`. The loud failure inside the run stays; this is a check
before it.

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
  `sandbox.triage.analysis_seconds` is how long the VM runs the sample, sent
  as the submission's `defaults.timeout`; empty, the default, sends nothing
  and Triage's own default applies. `sandbox.triage.timeout_seconds`, how long
  the platform waits for the report, must be longer: the wait covers the run
  and Triage's processing of it, and settings validation refuses one that is
  not; no margin for the processing is guessed, so leave room for it. A value
  the account does not allow is refused by Triage, and the submission error
  quotes Triage's own words and names the setting. The run summary states the
  run-time limit Triage set for the task (its behavioural tasks' `timeout` in
  the overview): a limit, not a measured duration, and never the value that was
  asked for.
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
`data/attck_techniques.json` carries, per technique id, its domain, its name,
its tactic slugs and its MITRE platforms, plus the tactic catalogue (slug to
TA-id and display name) per domain. The two files come from the same bundles
and the same script, so they never disagree about which domain an id belongs
to. Mobile and ICS techniques carry their own matrices' tactics: each bundle
files its kill-chain phases under its own name, and the extractor reads all
three. Between them they answer every dictionary question the pipeline asks about
a technique — validity, name, tactics, domain, platforms — with no network and
no bundle load: `tools.knowledge.attck_lookup`, `attck_scope`, `attck_validate`
and the capability matrix all read them and build nothing.
`data/attck_retired_ids.json`, written by the same script from the catalogue it
overwrites, names the ids a previous release had, the release that retired them
and, where the bundle states one, the id that revoked them — so an older
report's `T1562.001` is reported as retired rather than as an invented id, and
the data builders can retarget it mechanically.
`src/maljan/memory/attck_loader.py` downloads and caches each domain's STIX
bundle under `~/.cache/maljan/attck/` (or `MALJAN_ATTCK_CACHE`) for the ranked
index alone — `tools.knowledge.resolve_technique` and the alignment gate — and
consults it for platforms only when a real id is missing from the vendored
table. Enterprise is required; Mobile and ICS are additive, and a box that can
reach neither keeps working with a narrower catalog. Regenerate all three files
with `uv run python scripts/knowledge/prepare_attck_malware_fixtures.py`.

A failed index build is remembered for `validation.index_retry_seconds`
(default 900) and then attempted again, so one unreachable moment does not cost
a worker its index for the life of the process; 0 never re-attempts. The value
travels to the knowledge tool server — the process where the build happens — as
`MALJAN_INDEX_RETRY_SECONDS`, which is on that server's `env_allow` and cannot
be taken off it.

### The API catalogue

`data/api_behaviour_map_v1.json` and `data/api_attck_map_v1.json` are written
by `scripts/knowledge/build_api_capability_db.py` (`make prepare-api-db`) from
the curated tables in its source; no hand edits. Both carry one block per
platform — `windows` for a PE's imports, `linux` for an ELF's dynamic symbols —
and a caller asks one at a time, because the two vocabularies share names
(`connect`, `send`, `system`). `tools.knowledge.api_capability` takes
`platform` and the triage pack passes the routed format's, so an ELF's symbols
are never given Win32 categories. A routed format with no block — a Mach-O, an
APK — is not asked at all: the catalogue answering about the wrong system is
worse than it saying nothing, and the import table is in the format entry
either way.

The Linux block is narrower on purpose: there is no registry, and persistence,
keylogging, screen capture and credential access have no unambiguous libc
vocabulary to author from.

**Both blocks are measured rather than judged, and both read alike.** A group
whose bare presence would label ordinary software is an informational
association carrying `corroborated_by` — the names that would give it weight —
instead of a tier the catalogue calls suspicious. One group per platform keeps
a label and each carries `flags_with`, so the label waits for the combination
that makes the group mean something: `process_injection` on Linux waits for a
name that reaches into another process, `keylogging` on Windows for the input
hook, raw-input device or whole-keyboard read that is the capture rather than
the key-state poll a game does every frame. A technique rule is kept only where
its combination is the act the technique describes.

**One bar, and one trigger for a second look.** The bar asks whether a rule
carries information: one whose size-matched lift over a known-bad corpus is at
or below 1.5 fires no more often on malware than on ordinary software, and it
goes. The trigger is a rule above 4% of ordinary Windows software whose lift is
under 3 — not a threshold that deletes it, because the measured rate is carried
precisely so a common association can ship honestly and let the reader weigh it,
but a sign that the rule should be argued on its own terms. Three were, and each
went for a different reason: one was the sole row on no malware profile at all
and so told a reader nothing another row did not; one was weak on its own
numbers; one failed the test that decides whether a name belongs in a rule,
applied to the whole rule, because the act its names describe is not the act the
technique describes. A rule is deleted when one of those arguments carries, and
not for its rate.

**Every association carries the rate it was measured at**, under `measured`:
`seen_on_benign_percent` is the share of a named benign corpus the association
fired on, `seen_on_benign_files` the count behind that share, and — on Windows —
`held_out_malware_profiles` how many profiles the combination was not chosen on
that it fires on, stated as `0` where it fires on none, because an absent count
and a count of zero read the same and mean opposite things. The rate reaches the
model in the `api_capability` answer, the report's import-technique table and
the console's cell, and a reader weighs it.

Read those numbers in the one direction they were measured in: they say how
often a *rule* fires on software that is not a sample, and none of them is a
probability that a given sample is benign. There is no technique-level ground
truth for either malware corpus, so what a malware number says is that a
combination separates binaries already known to be bad from binaries already
known to be good, never that a sample performs the technique; roughly three
malware samples in ten import nothing an import rule can see at all, because
they are packed, .NET, or resolve everything at runtime. An association that has
not been measured carries no `measured` block, and the surfaces say so rather
than printing a zero.

A technique id in either block is retargeted, or dropped and listed, against
the vendored catalogue's `revoked_by` when a release retires it. Every rule
carries `name` — the catalogue's name for the id — a `rule` label saying which
of two rules on one technique matched and what combination it keys on, and
`ordinary_use`: one sentence naming the software that is not a sample and
imports the same names, because a mechanism with ordinary users that does not
say so reads as an accusation. Almost every rule needs two or more names; one
keys on a single name that is the act itself, which the row states by setting
`min_apis` to one.

Rerun the measurement after an ATT&CK refresh, after adding a group or a rule,
or against software that is not what the block was written against:

```
uv run python scripts/knowledge/measure_api_behaviour_block.py \
    --fail-over 1 /usr/bin /usr/sbin /usr/lib/systemd
uv run python scripts/knowledge/measure_api_behaviour_block.py --platform windows \
    --fail-over 1 --write-inventory corpus.jsonl.gz /srv/windows-corpus
uv run python scripts/knowledge/measure_api_behaviour_block.py --platform windows \
    corpus.jsonl.gz
```

A Linux run reads the dynamic symbol imports of the ELF files under those
directories; a Windows run reads PE import tables with `pefile`, the way
`extractors/pe_extractor.py` does, recording an ordinal-only import as
`Ordinal_<n>` so a binary that resolves everything by ordinal stays in the
denominator. Either way the corpus is deduplicated by content, so a suite that
ships the same runtime DLL in twenty packages counts once. It prints per group
and per rule how many binaries each appears on and labels, and names the ones
carrying a label or a technique row so a reader can judge whether that
population is the one the technique describes. `--fail-over` exits non-zero
when anything is above that share. `--write-inventory` saves what was read as
gzipped JSON lines, so the same corpus can be measured again after the files
are gone, and a Windows run takes such a file in place of a directory. It needs
`pyelftools` or `pefile`, reaches no network, and no test runs it over real
binaries: a test that read a host's software would answer differently on every
machine.

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

A rule in the YARA corpus fires when any of its patterns is in the sample's
bytes, and its confidence travels with the hit into every agent's pack. A
pattern must therefore be a fact about a sample rather than a word that
describes one: the persistence rules name key paths and not the API that writes
a value, and the packing rules name section names and packer banners and not
the words `AES`, `packed` or `compress`, which any program that speaks a
protocol carries.

A rule may also carry an `all_of` group beside its `patterns`: the patterns
fire one at a time, the group fires only whole. That is for a technique that
is a pair rather than a string — `MiniDumpWriteDump` is in a crash reporter
and `lsass.exe` is in every process lister, and only the two together are
credential dumping.

A rule that cannot be made that specific is written as a note: it omits
`technique_id`, and a rule with no technique may not carry a `confidence`
either. It fires, it says in its description what is in the file, and it
asserts nothing — which is what `web_client_apis` and `file_enumeration_apis`
are for. Importing an HTTP client is a fact; calling it a command-and-control
channel is a claim no substring can support.

### How much of a tool answer a model sees

`core.preprocessing.max_tool_output_chars` is **0** by default, and 0 does not
mean "no cap" — it means the cap is worked out at the moment of each call from
the context window the served model was found to have. A positive value is an
explicit operator cap and behaves as this setting always did: that many
characters, on every answer, whatever the window.

The arithmetic lives in one function (`maljan.llm.context_window`) and reads:
the served window, less the tokens held back for the model's own reply (the
larger of `core.llm.expert_max_tokens` and `core.llm.judge_max_tokens` where an
operator set them, never more than a quarter of the window, and a quarter of it
where both are 0), less what the conversation already holds,
converted at **3 characters per token**, times the **eighth** of what is left
that one answer may take. Three characters per token is measured rather than
assumed — a recorded conversation of about 114,000 characters was reported by
the server at 38,868 tokens — and is deliberately denser than the four the
token estimate uses for prose, because what this bounds is JSON and decompiled
C.

**A cap never exceeds the room that is really left.** Below **2,000
characters** the share stops falling and the floor applies, but only while the
room affords it; where it does not, the cap is what is left. Because each
answer is measured against what is free *at that moment*, and because what it
takes is charged as soon as it is handed out — a model turn may call several
tools at once — the answers of one conversation add up to less than the room it
started with, on every window the vendored table ships.

The share decides how large the first answer is and how quickly they shrink: at
32,768 tokens the first is 9,216 characters and about twelve clear the floor;
at 131,072 the first is 46,080; at a million, 371,928. At the floor the answer
meets the structural shortener exactly as any other does and carries the same
notice naming the arguments that would narrow it.

An answer over the cap only because of its whitespace is not shortened. A tool
that indents its JSON spends a quarter or more of its characters on layout, and
a derived cap makes that gap the common case: a recorded `elf_info` was 8,628
characters indented and 5,577 compact against a cap of 8,486. Such an answer is
handed over whole, written without the whitespace — parseable, every value the
tool's, and with no notice, because nothing was left out — and the run summary
counts it as `tool_output_compacted`. Only a compact form that still does not
fit meets the shortener, and what the shortener then cuts is the compact form.

**When the room runs out, the tool phase ends.** Below about a thousand
characters an answer cannot survive its own notice, so nothing of it is handed
over. The model is told once, in one sentence, that the conversation has no
room left for a tool answer; the whole answer stays on the evidence ledger
under the call's id, and the run summary counts it as `tool_output_no_room`.
From there that agent's tool calls are **not run** — a server's time is not
spent on an answer with nowhere to go — and a call made anyway returns one
short line. The run-state block carries the same fact on every model turn,
replaced rather than appended, so it costs the same whether the loop reads it
once or forty times. The loop then ends on that same step, the way a repeating
loop does, whatever the model asks next: `no_room` on its budget record with
the reason, on the `stage_ended_at_cap` event and under the agent's `caps` in
`run_summary.budget`, and the forced synthesis turns what was gathered into the
answer. The graph's own step-limit sentence ("need more steps") is never shown
or handed on as an agent's words, and the platform writes none of its own in
their place: where a loop a cap ended leaves no answer and the salvage writes
none, the agent's answer is empty and its status `no_claims`, and why is on the
budget record and the `stage_ended_at_cap` event. The node does not run such an
analyst a second time over the same material, which would meet the same full
window.

Both notices come out of the **tool budget** — the window less the room kept
back for the model's reply — and are withheld when they would not fit. So does
the marker a character cut leaves behind, which is kept back out of the cap
rather than appended after it, the way the shortener already reserves room for
its own notice. That is what leaves the reply reserve whole: the forced
synthesis above is this design's answer to a full conversation, and spending
its room on saying that the room ran out would take it from the one thing left
to do. Measured by driving the guardrail itself over every window the vendored
table ships, at twenty, forty and sixty rounds, with a chunk preloaded and at
fan-outs of thirty-two and a hundred and twenty-eight: the tool budget is never
exceeded, and the whole reserve survives — 8,192 tokens on a 131,072-token
window, 2,048 on 8,192, 1,024 on 4,096.

What is outside that guarantee is the model's own output: its tool requests and
its prose are not the platform's to cap, and on a very small window they reach
the window before the platform's text does.

What a conversation is measured at is what its next request will weigh, not the
messages alone. The definitions of the loop's tools go with every request, and
they are counted: a static analyst holding the default toolset — 35 tools
from the analysis, knowledge and VirusTotal servers — carries about 20,500
characters of them, 28% of a 32,768-token window's 73,728-character tool
budget, and a count that left them out said there was room until the server
refused. With the framing, about 46,000 characters (63%) are left for answers
and the model's own turns. On a small window, or with a large toolset, untick
the tools an agent does not need in each server's tick list in the Tools step:
that list is the only thing that narrows what a server sends an agent, and
every unticked tool is its definition's characters back on every request. Where the
server reported how many tokens the last request really took, that figure,
converted at the same three characters per token, plus what the conversation
gained since, is a floor under the measure, so content that tokenises worse
than three characters a token — pages of `strings` noise do — or the template
the server wraps each message in cannot hide room that is gone.

And where a server says the window is full anyway — llama.cpp's "context shift
is disabled" or "the request exceeds the available context size", an
OpenAI-compatible "maximum context length", Anthropic's "prompt is too long" —
after the analyst's loop has gathered at least one tool answer, that agent's
tool phase ends with `no_room` ("the model server reported its context window
full" on the record and the stage event), and the forced synthesis writes the
answer from what was gathered, rather than the agent failing and its work being
lost. Only an error the provider's SDK raised for the server's answer counts.
A server that names the reply cap is read by its numbers. vLLM words a full
conversation as "'max_tokens' … is too large: 8192. This model's maximum
context length is 32768 tokens and your request has 24808 input tokens": the
cap fits the window on its own and the prompt grew until the two together did
not, so that is a full window. A cap at least as large as the window, or one
named with no numbers to read, is a configuration fault no conversation could
avoid. The same full-window sentence on the first request, before anything was
gathered, means the framing alone does not fit; and an error that is not a
server's answer is the platform's own. Each of those faults still fails the
agent, because there is nothing to salvage and the failure is the true
statement. After the server has said the window is full, the final-answer
nudge is not sent — it would re-send the conversation the server just refused
— while after the platform's own budget ended the phase it still is, because
that conversation is inside the tool budget with the reply reserve whole.

The judge's tool loop is accounted the same way, under the judge's own name:
its conversation and its tool definitions are measured before every model
turn, with the server's reported count as a floor; its answers are capped from
its own room; its loop is streamed, ends on the step it runs out of room, and
ends with `no_room` on the same strict full-window answer once it has gathered
something. Its reasoning is then asked for once, with no tools, from what it
gathered, and mediation reads the verdict from that; a judge loop that fails
before gathering anything fails as before. Both salvages re-send the
conversation trimmed to two fifths of the window the budget counts on — the
smaller of the declared and the probed one, so a `context_size` left larger
than the served window cannot size a salvage close to the request the server
just refused — and each gets only what is left of its loop's time. An
analyst's salvage is also held to what that time can read and answer at the
model's measured rates, and is not sent when not even the task fits (see the
time cap in [architecture](architecture.md)).

The window itself is learned free of charge and without asking the operator
anything. In order:

| Source | Where it comes from |
|---|---|
| `declared` | `core.llm.ollama.num_ctx`, which the provider sends with every call, or `core.llm.openai.context_size` where an operator has set it. It does **not** short-circuit the probe: where a window was also probed, the smaller of the two wins, so a model that holds less than `num_ctx` asks for — and a `context_size` left behind by a server restarted smaller — cannot overflow the real window |
| `probed` | llama.cpp `GET /props` (`default_generation_settings.n_ctx`, then `n_ctx_per_seq`); an OpenAI-compatible `GET /v1/models` (`max_model_len` for vLLM, `context_length` for OpenRouter); Ollama `POST /api/show` (`model_info.<arch>.context_length`, with a Modelfile `num_ctx` winning); Text Generation Inference `GET /info` (`max_total_tokens`) |
| `table` | `data/model_context_windows_v1.json`, keyed by model-id family, for the vendor APIs that publish a window without serving it |
| `fallback` | nothing answered, and **nothing is derived from it**: one tool answer is capped at the documented 6,000 characters — exactly what this platform did before the window was learned at all — and every surface says the window is unknown |

No generation call is ever made — the probe reads metadata endpoints only, a
guard test drives both entry points through a transport that records every
request, and a probe that fails never fails a run and never blocks a settings
save. One question is asked per `(provider, endpoint, model)` rather than per
agent, both outcomes are remembered for fifteen minutes, and the whole plan
runs under one four-second wall clock.

A window an endpoint reports is untrusted input and is believed only up to ten
million tokens. Past that the figure is refused rather than clamped, with the
reason in words, because a proxy reporting its window in bytes produces a cap
larger than any answer there will ever be — and a cap that large makes every
answer fit, which switches the shortener, the summariser and the character cut
off for the whole run.

A run whose agents sit on different models takes the **smallest** of their
windows, because one cap is handed to every tool server the job opens. The
models an agent falls back to count as models it sits on: a fallback with a
smaller window than the first model governs the cap, because the turn it
answers reads the same conversation.

Where to see what applied: the Settings page prints the detected window beside
the field, with the source word itself, and `run_summary.truncation` records
the window, its source, the characters-per-token figure and the smallest and
largest cap the run used. A run that landed on `fallback` is the one to act on
— set `core.llm.openai.context_size` to the window the server was started with,
and the cap is derived from then on.

### A call waits as long as its answer takes at the model's pace

Two calls have an output budget of their own: the judge's verdict
(`core.llm.judge_max_tokens`, derived from the window by default, under the judge's
own time limit where an operator set one — none by default) and each composer section
(`core.reporting.composer_section_max_tokens`, under
`core.reporting.composer_per_section_timeout`, 120 s). A timeout chosen for a
fast model cuts a slow one off: at 3.8 tokens a second only about 2,280 of the
judge's tokens fit in 600 s.

**The analysts' and the judge's output caps are derived too.**
`core.llm.expert_max_tokens` and `core.llm.judge_max_tokens` ship at **0**,
which derives each agent's cap in three cases (`context_window.derived_reply`): where the model's maximum
output is declared — by the probe's model list (`max_output_tokens`,
`max_completion_tokens`, OpenRouter's `top_provider.max_completion_tokens`) or
by a vendored `max_output` row, each carrying the vendor page it is documented
on (gpt-4o and gpt-4o-mini 16,384, gpt-4.1 32,768, DeepSeek's `deepseek-flash`
and `deepseek-v4-pro` 393,216, written 384K on DeepSeek's Models & Pricing page)
— the smaller of that and a
quarter of the window; for a runtime we run — one that answered the window
probe as a runtime: llama.cpp `/props`, Ollama `/api/show` or TGI `/info` — a
quarter of the window, since no API limits its output (a loopback address alone
is not one: a gateway on `localhost:4000` forwarding to a hosted API has that
API's limit); and for a hosted API that declares
no maximum, the documented fallback of 8,192 (never above a quarter of the
window), which a quarter of a hosted model's window is routinely past.
On a local 32,768-token window that is 8,192; on a local 131,072, 32,768; on
the shipped gpt-4o, 16,384.
A window nothing reported derives nothing: the documented fallback of 8,192
applies and the sentence says the window is unknown. The reply reserve follows
the same rule, bounded by an operator's generation cap where one is set; the
report stage has an order of its own, below. A value above 0 is
the operator's and is used as set; a stored setting keeps its value. Each
derivation is logged and recorded in `run_summary.generation.output_caps`
(`{agent: {tokens, derivation}}`), and the judge's is printed beside the
verdict wait. 0 no longer means unbounded.

**The report stage writes up to the model's own maximum.** A report is as
long as its evidence needs, so the report stage — each composer section and
the narrative round — does not take the analysts' quarter of the window. For
each model of the reporter's list, in order:

1. the operator's value: `composer_section_max_tokens` above 0 for a section
   (plus the reporter's own cap for reasoning, below), otherwise
   `llm.judge_max_tokens` above 0 — the reporter runs on the judge role and
   has always been built with the judge's cap; `llm.expert_max_tokens` is the
   analysts' and no longer reaches the report stage;
2. else the model's declared maximum output (the probe's model list, then the
   vendored `max_output` row);
3. else the analysts' derivation above: a quarter of the window for a runtime
   we run, the documented 8,192 for a hosted API that declares nothing.

It is never more than the model's maximum — its declared maximum output, or
the window it serves when it declares none — and a value held at it says so;
the reasoning room is inside that bound too. With thinking left on and no
`llm.judge_max_tokens`, the reasoning room is the model's whole maximum, so
any positive `composer_section_max_tokens` resolves to the model's maximum.
On DeepSeek's `deepseek-flash` with nothing set, a section may write 393,216
tokens, and the 1,048,576-token window leaves the remaining 655,360 for the
section's evidence.

A section's evidence is sized against the window only when the window was
learned. The 8,192-token fallback a failed probe leaves is a number printed
beside the word `fallback`, not a fact: the section's claims and tool answers
are then shown whole, and its budget is the operator's value, else the
model's declared maximum, else the documented 8,192. Where the window is
known, the evidence room is the window less the budget, never below zero,
and each call is held to what the window leaves after that call's own prompt
(at three characters a token) when its budget would not fit beside it — a
hosted API refuses a request whose prompt and `max_tokens` pass the window.
The call's cap is lowered for that call alone, under the field each server
reads — `max_completion_tokens` for OpenAI, `max_tokens` for DeepSeek and
Anthropic, `max_tokens` and `n_predict` in llama.cpp's request extras,
`max_output_tokens` for Gemini — and the worker log says so. An Ollama model
keeps the cap it was built with, since its client takes no per-call cap; a
model the llama.cpp self-heal rebuilt without the extras is sent the cap only
as `max_completion_tokens`, which ik_llama.cpp does not read. A prompt larger
than the whole window is recorded as a degradation: Ollama fits such a prompt
to `num_ctx` by cutting it from the front, which can drop the system prompt
and the round's rules, and says nothing. A budget that fills the
window — a gateway that declares its window as its maximum output, a local
`llm.judge_max_tokens` at or past the window — so leaves the section no room
for claims and tool answers. A section whose facts do not fit what the window
leaves records the degradation "the section's prompt without its claims and
tool answers … exceeds the … its model's context window leaves after the
reply", its claims and tool answers are shown as the no-room sentence, and
the section is still asked.

Every list a section's model writes — flow steps, configuration items,
commands, flags, C2 channels, citations — is kept whole; no count cuts it.

The narrative round (the executive summary, key findings and recommendations)
takes the same budget, is held per call the same way, and waits the way a
composer section does: 600 s until the reporter's pace is measured, then the
time its budget takes at that pace for each call it may make (its answer, the
one retry, and the structured attempt where the endpoint supports one).
Appendix B prints it as `narrative:round`. The worker log prints one line per section ("ReportComposer: section
'…' output budget: …"), and the run summary prints the derivation beside the
section's wait ("Output budget of `composer:section`: 393216 tokens — the
model's declared maximum output of 393216 (the vendored table's
'deepseek-flash' row, from …)"). A fixed budget dropped a live report's
section when the model's answer outgrew it.

So each of those calls waits `max(configured, derived)`. Where the model's reading rate is
measured and the call gives its prompt size (a composer section, the verdict),
`derived = (prompt_tokens / reading rate + max_tokens / generation rate) × 1.5`;
otherwise `derived = max_tokens / rate × 1.5` with the rate that includes the
prompt read. Appendix B prints which one each timeout took. The rates are
the model's own for this job, read off every answer it has already given
without a token of its own: Ollama's `eval_count` over `eval_duration`,
llama.cpp's `timings.predicted_n` over `predicted_ms` (the openai provider
carries the `timings` object the OpenAI-compatible client would drop into each
answer), and on an endpoint that reports neither the answer's output token
count over the call's wall clock (which includes reading the prompt, so that
rate is lower than the server's and the wait longer). The reading rate is
Ollama's `prompt_eval_count` over `prompt_eval_duration` or llama.cpp's
`timings.prompt_n` over `prompt_ms`. The margin, 1.5, covers the spread between
turns, and the prompt read where it is not timed on its own.
The HTTP request carrying a call is sized the same way. Every provider's
client is built with a 1,800 s request timeout
(`PROVIDER_REQUEST_TIMEOUT_SECONDS`; Gemini's was a fixed 90 s and is now the
same). httpx reads it as the longest silence it waits through, not as a
deadline for the whole answer, so it ended an answer only on a server that
sends nothing until it has finished — a non-streaming llama.cpp server, whose
answers it held to about 1,800 s of generation. A streamed answer, and
DeepSeek's, which sends keep-alive lines while it generates, were not ended
by it. Once the model's pace is measured, an OpenAI-compatible (chat
completions or Responses API), Anthropic or Gemini request whose output cap
takes longer at that pace than its client allows carries its own timeout, the
SDK's per-request option: that time, by the same arithmetic and margin, its
prompt counted at three characters a token. Any other request keeps its
client's timeout. So no derived wait is held under 1,800 s any more: at 3.8
tokens a second the judge's 8,192 tokens need 8,192 / 3.8 × 1.5 ≈ 3,234 s and
get it, where 600 s allowed about 2,280 of them, and a 393,216-token section
at 40 tokens a second gets 393,216 / 40 × 1.5 ≈ 14,746 s. The Ollama client
streams every answer, so its 1,800 s bounds the silence between two pieces of
an answer. The function summariser's wait follows its request's.

These waits have no upper bound of their own. A server that stays connected
but stops generating, or a call left running on a single-slot llama.cpp
server after its loop gave up on it, is held for the whole derived time — at
3.8 tokens a second 32,768 tokens take about 12,900 s — where 1,800 s used to
release it. The last resort is the analysis job's own arq timeout, 8 hours
(`job_timeout` in `apps/api/app/worker/analysis_worker.py`). A composer section is its answer and the one retry its validation
allows, so its wait holds two calls of its output cap: at 3.8 tokens a second
a budget of 8,192 needs 2 × 8,192 / 3.8 × 1.5 ≈ 6,467 s; an operator's budget
of 900 with the reporter's `disable_thinking` on needs 2 × 900 / 3.8 × 1.5 ≈
710 s.
A fast model's derived time falls under its
configured one, which then stands. Until a model has answered once, and for a
call with no output budget, the configured value stands. Rates are kept per
model and per server, so one tag served by a local and a remote Ollama is two
paces. The verdict call starts its model list on its sized wait. The report
stage starts the reporter's list once; each section then measures the list's
turn deadline against its own wait, with the job's `llm.fallback_turn_share`,
without putting the list back on its first model — a model that failed as a
provider in one section is not waited out again in the next, and a switch
holds for the rest of the report stage.

The section budget is also the section's real cap, and a model's reasoning
counts against it: Ollama's `num_predict` and llama.cpp's `n_predict` include
the thinking channel. The budget at 0 already is the model's whole reply
room. With an operator's own `composer_section_max_tokens`, where the
reporter's provider has been told to keep reasoning out
(`llm.ollama.disable_thinking` or `llm.openai.disable_thinking`), the
composer's model is capped at that value alone; where it has not, the cap is
that value plus the reporter's own output cap (`judge_max_tokens`, else the
model's declared maximum, else derived) for the reasoning, and the sum is held
at the model's maximum. Each model of the reporter's list is capped by its
own provider's switch, and the wait is sized from the largest cap: the platform
cannot tell a reasoning tag from its name, and sending `think: false` to a
model that does not reason is an error on Ollama. A section the cap cut is
recorded as cut at that cap, not as a schema failure. On Ollama every output
cap — this one, `judge_max_tokens`, `expert_max_tokens` — now reaches the
server as `num_predict`, which `ChatOllama` otherwise drops, so a thinking
model's reasoning counts against the judge's and the analysts' caps too;
`disable_thinking`, or a larger cap, is the remedy. The verdict call records
whether it reached `judge_max_tokens`, Ollama's `done_reason: "length"`
included. `run_summary.generation` records
each model's rate, tokens, seconds, calls and source, its prompt reading rate
where the server reports one (`prompt_tokens_per_second`, `prompt_tokens`,
`prompt_seconds`, `prompt_sources`), and for each sized call
the configured value, the budget, the rate, the derived and the applied
seconds; the report's Run Summary prints the same numbers.

### Loops have no default limit

No agent loop has a step or time limit unless you set one.
`core.react_agent_max_steps` and `core.react_agent_timeout` are empty by
default, the two deprecated `core.react_agent_*_overrides` maps ship empty, no
built-in agent definition carries `max_steps` or `timeout_seconds`, and an
ask's `core.agents.delegation_steps` / `delegation_timeout_seconds` are empty
too. A number you set — on an agent's card, in a map, or deployment-wide — is
kept to exactly as before. The judge's tool loop reads its budget the same way
every agent's loop does (`loop_limits("judge")`): the `judge` entries of the
maps, then the deployment's values.

A loop with no limit ends when its model answers, or at one of the stops that
are not a count: the repeat guard (a model re-asking for answers it already
has), the conversation's room (a tool answer that no longer fits the window),
and the job's spend ceiling below. The arq job timeout is the last resort. A
loop with no time limit has no clock of its own. Every model request still has
a whole-call deadline Maljan enforces itself: the request timeout sized in the
section above (its output cap at the model's measured pace, prompt read
included), or the client's own timeout — `PROVIDER_REQUEST_TIMEOUT_SECONDS`,
1,800 s — where nothing is measured. The client's timeout stays as a second
guard, on silence: httpx reads it as the longest gap it waits through, so a
server that trickles keep-alive bytes or answers slowly but steadily was held
by nothing else. A model list gives no turn deadline in such a loop; a stalled
model is ended at its whole-call deadline, which the list reads as a provider
failure and moves on from. The run-state block says `budget remaining: no step
limit, no time limit` rather than a number, and the run summary's `budget` rows
carry `max_steps` / `timeout_s` as `null`.

The other fixed limits were decided one by one: `core.negotiation.max_iterations`
stays an explicit setting (5), the runaway stop on a negotiation that never
converges; `core.react_agent_tool_call_budget` only ever logs a warning;
capa and FLOSS on the analysis server have no wall clock of their own and run
for as long as their caller asks (the triage pack passes
`core.static.capa.timeout_seconds` and what is left of
`core.triage.budget_seconds`), and their manifest declares none and marks them
`long_running`. A model's call of either is waited for with no client deadline
unless you set `core.mcp.breaker.call_timeout_seconds`; a timeout or a
cancellation of such a call is not counted by the breaker; a call the client
gives up on, or a job that ends, is cancelled at the server, which kills the
tool's child process with its process group; and a second call of the same
run (the same tool, sample and arguments) joins the one already going instead
of starting another child;
`ANSWER_SHARE`, the share of the window one tool answer is sized from, stays a
documented derivation constant; the Ghidra sink pre-pass — run for every agent
whose own static provider is Ghidra, the static analyst, a clone of it and a
generic agent given Ghidra's tools alike — waits one tool call's
deployment budget (`core.mcp.breaker.call_timeout_seconds`, derived as that
row says), or as long as Ghidra takes with none.

**The spend ceiling.** `core.llm.max_spend_usd_per_job` is the most one job may
spend on its models, in US dollars; empty, the default, is none. It is a hard
bound against the platform's own measure of a prompt — its characters over
three, the measure the window accounting uses — so nothing is sent that could
take the job past it by that measure. A prompt that tokenises denser than that
(long runs of hex or base64) costs more input than was reserved for it, and the
job can pass the ceiling by that difference; the charged cost is what is
settled either way.

*What a call costs* is what it was charged. Where the provider reports the
call's cost in its answer (an OpenRouter-style `cost`), that figure is used and
no price is read. Otherwise the call's provider-reported usage — the input
tokens read from the prompt cache, the other input tokens and the output
tokens, reasoning included — is priced at the rates in force *when its request
was sent* (every model client stamps its answers with that time), from
`core.llm.model_prices` first, keyed by the model name the provider serves:

```json
{"deepseek-v4-pro": {"input_usd_per_mtok": 0.66,
                     "cached_input_usd_per_mtok": 0.022,
                     "output_usd_per_mtok": 1.98,
                     "source": "our contract",
                     "windows": [{"utc_from": "01:00", "utc_to": "04:00",
                                  "days": ["mon", "tue", "wed", "thu", "fri"],
                                  "input_usd_per_mtok": 1.32,
                                  "cached_input_usd_per_mtok": 0.044,
                                  "output_usd_per_mtok": 3.96,
                                  "source": "our contract, peak hours"}]}}
```

then a `prices` row of the vendored model table
(`data/model_context_windows_v1.json`), which carries DeepSeek's documented
prices for `deepseek-flash` and `deepseek-v4-pro` with the page they are
documented on — data, not a limit. A row's own figures are its price outside
every window; a window is a span of the day in UTC (its start in it, its end
not; a window whose end is before its start runs past midnight), on the
weekdays it names (none is every day), with its own figures and source. The
vendored rows carry DeepSeek's peak hours, 01:00–04:00 and 06:00–10:00 UTC
Monday to Friday, at twice the off-peak rate of every other hour. DeepSeek
also takes Chinese public holidays out of its peak hours, which no window
names, so a call in a peak window on such a day is counted at the peak rate,
above what it cost; its page does not say whether a request is timed at its
start or its end, and the platform times it at its start. A price key keeps a
model's tag (`qwen3:8b` and `qwen3:32b` are two models); the base name answers
only where no row names the tag. `run_summary.spend.prices_from` names, per
model, every rate its calls were priced at, or `provider-reported`. A call
whose provider reported no usage is counted, and the spend is then said as "at
least X; N calls reported no usage"; a model that never reports usage cannot
trip the ceiling, and the log says so once. A model with no price and no
reported cost is named once in the log and in `run_summary.spend`
(`unpriced_models`), and its calls are not counted: the figure compared is what
the job spent at least. Nothing is guessed.

*Before each call* — every model call the platform makes, each tool-loop turn,
revision, mediation, verdict, report section and function summary — its output
cap is held to what the spend it may use pays for at its model's output price,
after its prompt priced as uncached input, both at the highest rate in force
between now and the call's own deadline — the deadline its caller gives it,
else the whole-call deadline its request is sent with (so a call sent across a
window's edge never settles above its reservation). The call is refused only when that is
below the smallest answer it can give, measured per group: for a tool-loop turn
the largest turn (reasoning and answer together) this job has measured of that
model, for any other call the largest single-shot or verdict/report answer
measured of it, and with none of its group measured the call's own configured
output cap — there is no fixed floor. A call that cannot be handed a cap of
its own (a model that takes no output cap per call, the judge's mediation
turns, the structured technique question and mediation extraction) is made
only at its whole cap. A call the ceiling refuses is not sent: a revision leaves
the analyst's answer in force, the mediator's fast path leaves no reasoning
(no agreement), the extraction falls back to reading the text, a summary keeps
the raw text, a report section is recorded as not written, and a verdict the
ceiling refuses takes the judge node's fallback for a verdict call that fails:
a conservative Suspicious verdict written by the pipeline, not a model, with
the run marked degraded and the report saying why. Each hold and each refusal is logged with its numbers and
listed in `run_summary.spend.held_calls`. Every admitted call reserves its
worst case — its prompt and its held cap — until it returns and is settled at
what it was charged, so calls running at the same time never spend the same
remainder. A tool loop's turn also keeps room for the loop's closing answer:
it is sent only when what is left after it still pays for the smallest answer.

*The reserve for the verdict and the report.* At the start of a job the
verdict call and the report calls (one per section the composer writes, and
the narrative round) are planned, each with the prompt the window accounting
allows it: its model's window less its report-stage output budget, from what is
already known of the window. The reserve is derived from that plan and this
job's own calls, with no fixed fraction:

- the verdict: its prompt as uncached input plus the answer its admission
  will demand (its configured cap until a single-shot answer is measured, then
  the largest such answer), so what is kept for it is what it needs to be made;
- the first report call: its prompt as uncached input plus the planned answer;
- every report call after the first, which shares the first one's prefix: its
  prompt at this job's cache-hit share for the model — cached input tokens over
  input tokens, measured only over calls that were not the first of their
  conversation (a tool loop's turns after its first), since a conversation's
  first call has nothing cached to read — and at the model's cached rate while
  no such share is measured, plus the planned answer.

A planned call's prompt is the largest prompt of its own kind once one was
sent; before that the verdict's is the largest single-shot prompt sent (a
revision's prompt carries the same reports), bounded by its allowance, and a
report call's is its allowance. A tool loop's conversation is never used. The
planned answer is the largest single-shot or verdict/report answer measured of
the model, else its largest tool-loop turn; with no answer measured the reserve
is not sized. All at the rates in force. Tool-loop turns, revisions,
negotiation rounds, asks and summaries spend only above the whole reserve; a
verdict or report call spends above the reserve of the planned calls after it,
so the verdict cannot take the report's share and an unplanned retry spends
only what is left above the plan. `run_summary.spend.reserve` shows the
derivation, row by row, as it stood when the summary was written.

The first refusal exhausts the spend: from then on every gate reads it as the
ceiling reached, `run_summary.spend` says `exhausted` with when and why, no
further negotiation round, chunk or tool loop is started, an ask is refused,
every running tool loop ends its tool phase and its agent writes its answer
from what it gathered, and only the verdict, the report and a loop's closing
answer are made, each where it fits. A revision that is not made leaves the
analyst's answer in force standing. A report section whose call is refused is
recorded as not written, with the refusal's numbers. The run summary's
degradation reasons say the ceiling ended the tool phases.

A report section's call is held to the smallest of three limits, and the log
line for the call names the one that applied: the section's output budget
(and how it was derived), what the model's window leaves after the prompt, or
the spend ceiling's hold. A section whose answer is cut at that limit with no
text written — a reasoning model that spent the whole allowance thinking — is
asked again only when the second call would have more room; otherwise it is
recorded as not written, with the limit and where it came from. The platform
does not lower a model's reasoning effort to make an answer fit.

**What the judge and the pack are shown.** The judge's verdict prompt and its
technique question show every analyst's report, the evidence summary (every
technique and every source), the negotiation history and each remembered
case's summary whole when the judge's window, less its output cap, holds them.
When it does not, the largest parts are shortened first to one shared width,
each ending in `…`, the prompt says which parts and to what width, and the run
records it as a degradation reason. The triage pack is rendered whole when it
fits its room (the upstream bound, `core.reporting.upstream_findings_max_chars`,
derived from the window by default); when it does not, the detail every line
shows — names listed, characters of a text, decoded strings and detection
labels — is derived from that room, the most at which the pack fits, and each
line says what it left out and that the rest is a tool call away.

**An analyst's input.** `core.max_token_limit` (was 128,000 tokens) is
empty by default: an analyst's input text may take the room its window holds
before the reply, less the system prompt, the pack and the run-state block
around it. With no window learned the input goes whole; a number you set wins.
Input over the room is shortened as a document — a JSON input keeps every key
and loses elements off its largest lists, text keeps its head and ends in
`…` — the text the model reads begins with a note saying so, and the run
records a degradation reason ("The static analyst's input was shortened: …").
The function summariser's prompts are held to the same window room and say
when they were shortened; the PE loader's markdown lists every import, export
and string, and the generic MCP provider's prompt names every tool.

**What the report leaves out, it says.** The markdown report keeps its layout
bounds — a long table value is cut to fit the page, a long list shows its
first rows — and every one now says what it left out and where the whole is:
a cut value ends in `…` and the methodology appendix says the JSON report and
the evidence ledger carry it whole; a list shown in part ends with "N more …
not shown here; the JSON report carries every one." The evidence sections do
the same ("N more rows not shown here; the evidence endpoint carries every one
under ev_…", a long text "Cut here at … characters"), a figure's legend counts
what it did not draw, a drafted YARA or Suricata rule says in a comment how
many published indicators it does not match on, and the STIX export carries
every process root.

### The evidence budget

`reporting.evidence_budget_bytes` (512 KiB by default) is how many bytes of
tool output one agent may keep in the evidence ledger. Entries past it still
record the call — the tool, the arguments, the outcome and the timing — and
carry no output, and the report states how many were trimmed. Raise it for a
deep reversing loop whose decompilation is the evidence; set it to `0` to keep
every output, which is a supportable choice on a machine with room for it and
a way to fill a JSONB column and a context window on one that has not.

Half a megabyte holds one loop's whole tool output up to a served window of
about 183,000 tokens, which follows from the cap above: a loop's answers come
to at most `(window − reply reserve) × 3` characters. `evidence_corpus_bytes`
(16 MB, the run-wide grounding corpus) holds six such loops at 131,072 tokens
and about five and a half at a million. Neither is scaled with the window on
purpose — they bound the worker's memory and a database column rather than the
model's context, and a machine that also runs the model cannot answer a bigger
window by holding a proportionally bigger corpus. Past either, what happens is
what always happened: the ledger entry keeps the call and drops the output and
the report says how many, and the corpus reports itself incomplete so that an
absence measured against it is advisory.

### The live conversation

Two settings under **Live events** govern the feed the console draws a running
analysis from. Neither turns the feed off: the events are what the console
shows, and a run that published none would be a spinner again.

`events.stream_deltas` (on) publishes an agent's text while its loop is still
running, as `agent_message_delta`. What is published is one model turn's text
as the loop produces it, not a token at a time — the loop reads its graph as a
stream of whole states and that is the smallest thing there is to publish.
Turn it off on a deployment whose browsers are on a thin link; every finished
message is unaffected.

`events.retention_days` (30) is how long a finished run's feed stays in
`job_events` before the worker's nightly sweep removes it. The feed is what
makes a failed or cancelled run readable at all — no report is written for
one — and is what a reader wants while a run is fresh. The transcript, the
agent findings and the evidence ledger are kept by the report and the job and
are not touched by the sweep, so shortening this does not shorten how long a
finished analysis is readable.

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

`floss`, the emulating string decoder, runs FLOSS (Apache-2.0) as FLARE's
pinned standalone Linux build, v3.1.1 (zip sha256
`40c05a869f34f7e2417b17ca290cc54bd3671ee1f0a2d9bd5103284c01a54666`), outside the
Python environment. The backend image installs it at `/usr/local/bin/floss` in
a checksum-verified build stage; on a host, `scripts/install_floss.sh` installs
it at `~/.local/share/maljan/tools/floss-3.1.1/floss`. To use a
build elsewhere, set `MALJAN_FLOSS_PATH` in the `analysis` server's `env`. The
tool runs only the executable whose sha256 is the pinned one. Without it the
capability manifest marks `floss` unavailable with the reason and the remedy and
the model is not offered the tool; with it, the first call on a sample emulates
for up to ten minutes (the tool's declared `timeout_s`) within 4 GiB of address
space, and later pages of the answer come from the kept result. The triage pack
runs the same function once on every PE, reading `MALJAN_FLOSS_PATH` and
`MALJAN_STAGING_DIR` from this process's environment with the `analysis`
server's `env` over it. Name a build in the server's `env` and the pack and
the tool find the same one; a `MALJAN_FLOSS_PATH` set only in the worker's own
environment reaches the pack and not the tool, whose child environment carries
only the server's `env` and its allowed keys. Without a build the pack's entry
says so and names the remedy.

Five teams ship built in; they are listed under **Teams** below. `default` is
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

### Where r2mcp is looked for

`core.static.r2.binary_path` defaults to the bare name `r2mcp`. `r2pm -ci
r2mcp` installs it under radare2's own prefix and does not touch PATH, so the
provider resolves the name when it starts: a value with a directory in it is
used as it is; a bare name is looked up on the worker's PATH, then in
`$R2PM_BINDIR`, `$R2PM_PREFIX/bin` and `radare2/prefix/bin` under the user's
data directory (`$XDG_DATA_HOME`, else `~/.local/share`) — where r2pm puts it.
Nothing past those is guessed. Not found, r2 degrades as it always has: the
run goes on without it, the log names every place looked, and the run summary
carries `static provider 'r2' unavailable: …` with the remedy (install it with
`r2pm -ci r2mcp`, or set `binary_path` to the executable's absolute path). The
connection test resolves the same way and names the same places.

### Running Ghidra lighter

The `ghidra-mcp` service reads three variables from `docker/.env`, each
defaulting to the value it has always had: `GHIDRA_JAVA_OPTS` (the JVM's
options, `-Xmx4g -XX:+UseG1GC`), `GHIDRA_MEM_LIMIT` (the container's memory
and swap limit together, `6g`) and `GHIDRA_RESTART` (`unless-stopped`). Keep
the memory limit about 2g above the heap: Ghidra's database is memory-mapped
and its direct buffers live outside the heap. A host short of memory runs it
with `GHIDRA_JAVA_OPTS="-Xmx2g -XX:+UseG1GC"` and `GHIDRA_MEM_LIMIT=4g`, and
`GHIDRA_RESTART=no` keeps a stopped container stopped across a reboot, for a
host that starts Ghidra only for the runs that need it
(`docker compose -f docker/docker-compose.yml up -d ghidra-mcp`, then `stop`).
A binary larger than the lighter heap can analyse fails its Ghidra calls
rather than the host.

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

`virustotal` is referenced by every agent that reads the file or weighs the
run: the `static` and `network` analysts, the judge, and the seeded `triage`,
`android_static` and `reverser` agents. Their prompts say what to do with an
answer — look the hash up once, cite it like any other tool result, and treat
a reputation label as one source rather than as the verdict. The judge opens
its own tool loop when it holds a reputation server (`virustotal` or
`threatintel`) and no entry in the run's evidence ledger came from one, so the
identity question is asked once even on a run nobody disagreed about. What
decides it is the ledger rather than the analysts' prose: a sentence saying no
family could be determined is what an analyst writes when it consulted
nothing. A disabled server contributes no tools and no
degradation reason, so every one of those references costs nothing until the
server is registered.

`services/threatintel-mcp` is unchanged: it still offers VirusTotal and
AbuseIPDB lookups over their REST APIs with `VIRUSTOTAL_API_KEY` and
`ABUSEIPDB_API_KEY`. Where both are on, `virustotal` supersedes its VirusTotal
half — it is VirusTotal's own server, richer and maintained by them — while
the AbuseIPDB half stays the only source for IP abuse reports. A deployment
with an API key and no agent token keeps working exactly as before.

Both names reach that sidecar through its `env_allow`, and both are defaults
rather than fixtures: an operator who clears that list in the Configuration tab
stops the keys reaching the child — for an engagement where the sample must not
be looked up, or to stay inside a rate-limit budget — and they stay cleared
until the operator puts them back. The server then answers from its mock, as it
does on a host that never held a key. See
[which directories a sidecar may read](#which-directories-a-sidecar-may-read)
for the three names that a built-in does keep whatever the stored registry
says.

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
| `kind` | `triage`, `analysis`, `debate`, `verdict` or `report`. |
| `agents` | Definition keys this stage runs. Empty on a triage or debate stage. |
| `depends_on` | Earlier stage keys this one runs after. |
| `when` | Condition deciding whether it runs. Empty means always. |
| `mode` | `sequential` (default) or `parallel`, for an analysis stage. |
| `inject_upstream` | `none`, `findings` (default) or `full`. |
| `debate` | Round limit, consensus threshold and sycophancy check, for a debate stage. |
| `builtin_tools` | `false` withholds every built-in server (`analysis`, `knowledge`, `network`, `threatintel`, `virustotal`) from this stage's agents. |

### Checking a team before it is saved

The team editor checks every team as it is edited. Once typing pauses, the
console sends the staged teams, the staged agent map and the staged active
team to `POST /api/v1/settings/lint-teams`, which stores nothing and answers
with every finding and each team's layout. Beside each team the console draws
the stage graph that layout describes — stages as boxes in run order,
`depends_on` as arrows, a conditional stage dashed — and marks each stage that
has a finding; the same findings are listed in words under the graph and on
each stage card.

An **error** is a team apply refuses, and the lint reports it in the words
apply refuses it with: the lint reads its errors off the same functions the
settings model raises from (`maljan.core.team_lint`), and the apply path
refuses from the lint. A test holds the two together: every refusal the
settings model makes about a team is a lint error, word for word. The errors:

- a team with no stages;
- a stage key declared twice, or a key that is not a slug;
- a stage that depends on itself, on a stage that does not exist, or on a
  stage declared after it — and, named as such, a loop of stages that depend
  on each other;
- an agent in two analysis stages; an analysis stage with no agent;
- a triage stage that names an agent, or is keyed like a node the pipeline
  names itself;
- a debate with no analysis stage upstream of it, one that names an agent, or
  one that hands over to more than one node;
- a stage naming an agent that does not exist, is disabled (a built-in team
  may keep a disabled member while it is not the active team), or has the
  judge or reporter role in an analysis stage;
- not exactly one verdict stage, or a verdict stage not run by the judge;
- more than one report stage, a report stage not run by the reporter, or one
  that is not last;
- a `when` the condition grammar refuses, reported by the parser that runs it;
- a field of the wrong type or value, in pydantic's own words;
- a built-in team edited beyond its debate options, its built-in-tool switch
  and its excluded servers;
- a team key that is not a slug.

A **warning** is a team that saves and runs and will not do what it looks
like it does. A warning never blocks apply, and each is decided from the team
as written, never from a guess about the sample:

- a stage the verdict stage does not run after (the judge does not wait for
  it), or one that runs after the verdict, other than the report;
- a condition that names no field and is false, so the stage never runs;
- a condition reading `stages.<key>` for a stage the team does not have, or
  for a stage this one does not run after;
- an enabled agent that no team names and no agent asks;
- an agent reading the static provider's tools while the static provider is
  `none` (the note apply already returns).

The layout the graph uses is `maljan.core.team_layout`: a stage one row below
the lowest stage it runs after, stages that share a row side by side in the
order they are written. The team diagrams on the architecture page are drawn
with the same layout.

### The teams that ship

| Team | Stages | What it is for |
| :-- | :-- | :-- |
| `default` | `triage_pack` → `analysis` (static, dynamic, network) → `debate` → `verdict` → `report` | The general case. |
| `measurement` | The four after the pack, with every tool server withheld and no pack | What the ensemble contributes with nothing to call and nothing established. |
| `mobile` | `triage_pack` → `triage` → `android_static` → `dynamic` → `debate` → `verdict` → `report` | An APK or a DEX. |
| `deep_static` | `triage_pack` → `triage` → `static` → `reversing` → `network` → `debate` → `verdict` → `report` | Reading the code. |
| `team_lead` | `triage_pack` → `lead` (lead) → `verdict` → `report` | One lead agent gives the specialists their work; see *Delegation* below. The one seeded team with no debate: a debate over a single analyst costs a second full loop and cannot change a position. |

`triage_pack` is a stage of kind `triage`: the pipeline itself running the
deterministic tools over the sample and writing each result to the evidence
ledger before any analyst starts (see *The triage pack* in
[architecture.md](architecture.md)). Every team but `measurement` ships with
it first, a team written by hand may leave it out, and a stored team gains it
on upgrade (`make migrate`). Its five settings sit in the Analysis layers
group: `triage.enabled` (off leaves the stage in place and makes it decline
with that reason), `triage.strings_head` (how many printable runs the strings
entry keeps; 300), `triage.reputation` (`auto` asks the enabled reputation
server once for the sample hash — VirusTotal's own server when enabled, else
the threat-intel sidecar, never one the team lists in `exclude_servers` — and
`off` records a skipped entry instead), `triage.budget_seconds` (1200; a
step that would start after the budget is spent is recorded as not run) and
`triage.memory_floor_mb` (10,240: what the host must still have available
after capa's measured peak and FLOSS's 4 GiB bound for the two to run together;
0 checks only that both fit, and the worker's cgroup limit is always checked). The
pack runs the real tools in mock mode too, so a local observation run with a
reputation server enabled makes that one outbound call; a team that withholds
the server, or `triage.reputation = off`, keeps such a run offline.

The technique check's one heuristic part has five settings in the same
group: `validation.alignment_gate` (`auto` runs the alignment gate only on a
worker whose ATT&CK index is already built; `off` never),
`validation.alignment_gate_build` (false; true lets the first run that wants
the gate build the index once, on a thread, and go without it),
`validation.weak_alignment` (false — the ranking is recorded on the claim and
shown to the judge, and nothing is asked again; true lets it question a claim,
at one correction turn per batch), `validation.alignment_threshold` (0.05, the
paper's gate) and `validation.alignment_margin` (0.20, how far a candidate from
the sample's own domain and another tactic must beat the claimed id before it
is questioned). The measurement behind the default off is in *The technique
check* in [architecture.md](architecture.md).

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

Like every built-in team, all five are editable only in their debate options,
their `builtin_tools` switches and `exclude_servers`. Everything else means
cloning the team, which the console does in one click.

The reverser is handed addresses to start from. The triage pack every agent
reads names each decoded string with the routine that produced it and its call
site, and each capa rule with the places it matched, all as offsets from the
image base; the seeded prompt tells it to go there first, to confirm or refute
each upstream finding at function level, and then to look for what only
reading the code shows: command dispatch, environment checks, persistence and
cleanup, the logic that decides when and how it contacts a remote host, and
the routines that decode its data. An agent on Ghidra — the reverser given
`static_provider: "ghidra"` included — also gets the sink-reachability
pre-pass's priority functions on its first turn, and the sample is mirrored for
its provider even when that is not the deployment's global one.

### An all-tools team

`docs/examples/profiles/all-tools.json` is a team to import rather than one
that ships: the triage pack and `triage`; one `static` stage of three analysts
on three tools — `static` (the analysis, knowledge and VirusTotal servers, on
the global provider), `all_tools_static_r2` (`static_provider: "r2"` with the analysis
and knowledge servers) and `all_tools_qu1cksc0pe` (a generic agent on the
`qu1cksc0pe` server); `reversing` with `all_tools_reverser_ghidra`, the seeded reverser
prompt on `static_provider: "ghidra"`; `dynamic` when there is a sandbox
report; `network` when there is a capture or a sandbox report; then `debate`,
`verdict` and `report`. The later stages depend on every earlier analysis
stage and read their findings (`inject_upstream: findings`).

It is a settings import document (`maljan-settings/1`) holding
`core.agents.definitions` and `core.agents.profiles`. Each of those is one
setting holding a whole map, and an import replaces what it names, so merge the
document into your own export first. The document's keys are all `all_tools_*`
(the team is `all_tools`), so it adds entries and replaces none of yours:

```bash
curl -s http://localhost:8000/api/v1/settings/export \
  -H "Authorization: Bearer $TOKEN" > current.json
jq -s '{format: "maljan-settings/1", values: {
  "core.agents.definitions": ((.[0].values["core.agents.definitions"] // {})
                              + .[1].values["core.agents.definitions"]),
  "core.agents.profiles":    ((.[0].values["core.agents.profiles"] // {})
                              + .[1].values["core.agents.profiles"])}}' \
  current.json docs/examples/profiles/all-tools.json > merged.json
curl -s -X POST http://localhost:8000/api/v1/settings/import \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d @merged.json
```

What the team needs besides the document: an enabled `qu1cksc0pe` entry under
`core.mcp.servers` (the import refuses a reference to a server that does not
exist); Ghidra with `core.static.ghidra.enabled` true, `transport` set to
`http` explicitly (its shipped value is `stdio`), `url` the address the worker
reaches it at — `http://localhost:8089` for a worker on the host,
`http://ghidra-mcp:8089` for one inside the compose network — and `auth_token`
the container's `GHIDRA_MCP_AUTH_TOKEN` (see *A team that needs Ghidra waits
for it* above); `core.static.r2.enabled` on and r2mcp findable by the worker —
setting `core.static.r2.binary_path` to its absolute path is the sure way, since
where r2pm put it depends on the environment r2pm ran in (see *Where r2mcp is
looked for*; switched off or not found, r2 attaches nothing and the clone runs
on its two servers alone); and, so that each static analyst reads a
tool of its own, `core.static.provider` set to `none` — with the global
provider on Ghidra the `static` analyst opens Ghidra as well. Run it by naming it on the job (`{"config": {"profile":
"all_tools"}}`) or by making it `core.agents.profile`. A test
(`tests/api/test_the_all_tools_team_document.py`) loads the document through
the import's validation and resolves every agent against stub servers.

### What a clone is given when it names no tools

A definition that is not a built-in and has no `tools` key takes the tool list
of its role's seed: a clone written as `{"role": "static", "static_provider":
"r2"}` — by a script, an import or a hand-edited export — keeps the analysis,
knowledge and VirusTotal servers the `static` seed reads, as a clone the
console copies does. A `tools` key that is present is the operator's, and an
empty list means no server at all. The roles with a seed of their own are
`static`, `dynamic`, `network`, `report` and `lead`; a `generic` definition
has none to inherit and keeps what it wrote. The settings API stores the list
it resolved, so what the console shows is what the run reads.

### Delegation

A definition's `tools` list takes four kinds of reference. `mcp` names a
server (and optionally one tool of it), `provider` means the agent's own static
provider's tools, `sandbox` the in-process tools over the job's sandbox report,
and `agent` names another definition:

```json
{"kind": "agent", "agent": "static"}
```

Bound to an agent, that reference is a tool named `ask_static` in its toolbox:
the model hands the static analyst a `task` (and, when it helps, a `context`),
the static analyst works on it with its own tools under the same job, and its
answer — its claims with the ledger ids they cite — comes back as the tool
result, unedited. The console's agent editor offers every other analyst-role
definition under **Ask another agent** in the Tools tree; the settings model
refuses a reference to an agent that does not exist, to the definition itself,
to the judge or the reporter, and any such reference on the judge or the
reporter. A disabled callee is refused when it is asked, by name, so a built-in
team may keep a disabled member while another team runs, and so is an ask that
would come back with a server the asking stage withholds — a stage with
**Built-in tools** off cannot reach them through a colleague that no stage
narrows. A `provider` reference is valid on a `generic` or a `lead` definition;
every other role opens its provider itself.

The seeded `lead` definition (role `lead`, prompt in
`src/maljan/agents/prompts/lead.md`) references `static`, `dynamic`,
`network`, `reverser` and `triage`, and keeps the `knowledge` server; the
`team_lead` team runs it as its one analysis stage. A team of your own may put
a reference on any analyst: a static clone that asks the network analyst is as
legal as a lead.

Three settings govern it, in the Agents group. `agents.delegation_depth` (2)
bounds the nesting: a stage's agent asking a specialist is depth 1, that
specialist asking another is depth 2, and an ask that would go deeper is
refused with a message the model reads. It bounds the nesting, never the
number of asks.

`agents.delegation_steps` and `agents.delegation_timeout_seconds` are what
one ask gets, and both are empty — no limit — unless you set them. They are
the delegation's own budget, not a share of the caller's: an ask carries them
whole, whatever the caller has spent, and the caller's own step budget is not
reduced by what its specialists do. The one thing the two really share is the
wall clock: where the caller's loop has a time limit, the caller waits inside
it, so an ask is cut to what the caller has left and refused only when that is
below the floor a first model turn needs. A caller with no time limit waits
for a busy callee until it frees up, unless that callee is itself waiting on
the caller, which is refused in words the model reads. A callee that reaches a
step limit writes up what it gathered, the way an analyst at its own does.

A budget is part of the definition, so a clone of a team carries the budget
its agents need; the console draws the two as **Steps per loop** and **Seconds
per loop** on the agent's card, and a blank box inherits the deployment's
`react_agent_max_steps` / `react_agent_timeout` — both empty, no limit, by
default. No built-in definition carries a budget: the seeded `lead` has none
either. The `ask_<key>` tool's description says what an ask gets ("no step
limit and no time limit of its own", or the numbers you set) and, where both
the caller and the ask have a time limit, how many asks fit
(`delegation._asks_that_fit`). The two `react_agent_*_overrides` maps are
deprecated and operator-only: they ship empty, and an entry you write is still
read for an agent whose definition sets neither, before the deployment's
value; a definition's own value wins over them. A map entry that is not a
whole number of at least one is dropped with a warning when the settings are
built, the same bound the definition's own fields carry. See *Delegation* in [architecture.md](architecture.md) for
what the ledger and the transcript record.

### A name a later release takes

Seeding a built-in takes a name. `triage`, `android_static`, `reverser`,
`lead`, `mobile`, `deep_static` and `team_lead` were all legal names for an
operator's own agent or team before they were seeded, and a stored entry under
one of them would otherwise be refused as tampering with a built-in — on every
read, which is to say at boot.

So a stored entry under one of those seven names that is not the seed is renamed
out of the way on load: `reverser` becomes `reverser_custom`, and every
reference to it moves with it — the teams that named it, the per-agent model
entry under `llm.agents`, each server's `agents` binding and both
`react_*_overrides` maps. The rename is logged once at warning level, and
`alembic upgrade head` writes it into the stored document so the console shows
the new name rather than renaming the same document on every read.

A seeded definition whose prompt a later release rewrote is not such an entry.
A save stores the whole definition map, seeds included, so a database holds
each seeded row with the prompt it had on the day of its last save; a prompt
the seed itself shipped with before (`FORMER_SEED_PROMPT_DIGESTS` in
`maljan.core.config`, by SHA-256 of the exact text) is read as the seed's, and
the row loads as the seed rather than being renamed. A release that rewrites a
seeded prompt adds the one it replaced to that list.

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

### Long agent keys in the conversation

An agent key is a slug of at most 32 characters. Keep it well under that, for
one reason: everything the live feed publishes as prose is scrubbed by the
publisher, and a run of 24 or more letters, digits, `_` and `-` is the shape a
credential has. A key that long is redacted to `***` **inside a sentence** —
`"windows_pe_static_analyst failed"` reaches a reader as `"*** failed"`.

Nothing is lost but the name in that sentence. The identity fields a line is
filed under — `speaker`, `agent`, `stage`, `label`, `display_name` — are
exempt by name in the publisher and travel whole, so the console still files
the line under the right participant and still draws it with the label you
gave it. No shipped key is anywhere near the floor; the longest is
`android_static`, at fourteen.

The scrubber is deliberately not told the roster. It is one pure function
shared by every job on the worker, and a rule that depended on which run was
publishing would be a rule whose answer changed with the configuration — which
is the property a redaction rule cannot have. A shorter key costs nothing and
reads better in the conversation.

### Conditions

`when` is an expression in a small language evaluated on the worker. It is
Python's own grammar with an allow-list on top: comparisons (`==`, `!=`, `in`,
`not in`, `<`, `<=`, `>`, `>=`), `and`, `or`, `not`, literals, and tuples or
lists of literals. There are no function calls, no arithmetic, no
comprehensions and no attribute access except into `stages` and `triage`. A condition that
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
| `triage.<field>` | What the triage pack established: `has_signature`, `reputation_malicious` (a count, or `None` when no lookup answered with one), `yara_hits`, `capa_hits`. |

`stages["triage"].ran` is the same lookup as `stages.triage.ran`. A stage the
run never reached reads as one that did not run, so naming a stage that was
itself skipped is not an error. A team without a triage pack reads `triage`
as nothing established: `false`, `None`, `0`, `0`.

Examples:

```
platform == "windows"
extension in ("apk", "dex")
has_pcap and stages.triage.claim_count > 0
"T1055" in stages.static.technique_ids
not stages.detonate.ran
size > 10485760
triage.yara_hits > 0 or triage.capa_hits > 0
not triage.has_signature and triage.reputation_malicious != None and triage.reputation_malicious > 0
```

### What a stage reads

`inject_upstream` decides what a stage is told about the stages it depends on.
`none` tells it nothing, which is what the default team uses — its analysts
have never seen each other's work before the debate. `findings` gives it each
upstream agent's claims with their technique, confidence and evidence id.
`full` adds each upstream agent's prose report. Both are capped by
`core.reporting.upstream_findings_max_chars`, and a block that is cut says so.
It ships at **0**, which derives the cap from the window this job's models
serve the way a tool answer's cap is: the share one answer may take (an
eighth) of what the window leaves after the reply room, at three characters a
token — 294,912 characters on a 1,048,576-token window with a 262,144-token
reply room. A window nothing reported derives nothing, and the documented
6,000 applies. A positive value is the operator's, used whatever the window.

The block arrives as an `upstream_findings` field inside the stage's first
chunk when that chunk is a JSON document, and in front of it when it is not. A
static or generic agent's first chunk is JSON with a contract on it — the
container-visible `analysis_file_path` is read back out of it, and putting
prose in front would leave the agent inventing a path again.

Injection never changes whether a stage has data. An agent whose loaders
produced nothing but a "no data available" placeholder is still skipped, with
or without a block to read.

Two blocks every agent reads regardless of `inject_upstream`: the triage pack,
one line per fact with its ledger id, at the head of the agent's first human
turn under *Facts established before analysis*, cut at the same
`core.reporting.upstream_findings_max_chars`; and the run-state block in the
system turn — sample, identity, signature, reputation, stages run or skipped,
ledger count, failed tools, remaining steps and seconds — regenerated on every
turn. Neither is a setting of the stage: a team without a triage stage has no
pack and its agents see only the run state. See *The triage pack* in
[architecture.md](architecture.md).

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
transport on another host. Two environment variables configure that, and with
`MALJAN_SAMPLE_ROOTS` — defined once in the next section, and seen by the
`network` sidecar as well — they are the only ones it is allowed to see:

| variable | default | meaning |
| :-- | :-- | :-- |
| `MALJAN_STAGING_DIR` | a `maljan-analysis-mcp` directory under the system temp dir | the base uploads land under |
| `MALJAN_STAGING_TTL_HOURS` | `24` | how long a staged sample, and a payload carved out of one, is kept; `0` disables pruning |

`MALJAN_STAGING_DIR` is the **base**, and each job writes into one directory of
its own inside it — `job-<the job's id>`, holding that job's uploads and its
`carved/<sha256>/` trees. The name is composed by the process that starts the
sidecar and handed over as a third variable, `MALJAN_STAGING_JOB`; it is a
single directory name, never a path, so an operator's `MALJAN_STAGING_DIR` is
the base whatever else is configured. That variable is not read from the
environment and is not something to set: a sidecar started without one writes
into the base itself, which is what a settings probe and a server run by hand
do.

Both the base and the job directory are created with mode 0o700 and refused if
what is already at that path is a symlink or belongs to another user — the
default name is predictable and the system temp directory is shared. Each file
is created with `O_CREAT|O_EXCL|O_NOFOLLOW` at 0o600 rather than written and
then chmodded, and every `put_sample*` call prunes past the TTL: the files of a
job directory still in use, the whole directory of one whose newest file is
past the cutoff, and the flat files an older release left in the base. So a
long-lived server accumulates neither samples nor job directories, and an
upgrade has nothing to migrate.

A job directory is pruned whole only once the newest file anywhere inside it is
past the cutoff, and a running job keeps its own directory current while it
refreshes its owner heartbeat — so a run longer than the TTL does not lose its
carved payloads to a second worker's sidecar sweeping the same base. Set the
TTL below the longest run this deployment can have and that marker is the only
thing standing between a live job and its own directory; there is no reason to.

The sandbox capture a job fetches lands in a `captures/` child of the same
directory and obeys every rule above: 0700, files 0600 from their first byte,
removed with the job, swept by the same TTL, and unreachable from another job.
The directory an earlier release used, `maljan-cape-pcap` under the system temp
directory, is swept as well and is no longer written.

One configuration would widen this if nothing else stopped it: a
`MALJAN_SAMPLE_ROOTS` entry containing the staging base — the deployment's
whole samples directory, say, with the base inside it — which names every
job's directory as one a sidecar may read. `confined_to_this_job` refuses it
anyway: a path argument resolving under the base but outside this job's own
directory is refused whatever the roots say, so the job directory is the
boundary and the roots cannot loosen it.

### Which directories a sidecar may read

A sample is adversary-authored content and the analyst model reads it, so the
path a tool is asked for is a path the sample's author may have written. Both
file-reading sidecars — `analysis` and `network` — therefore resolve every
`path`, `pcap_path` and `ruleset` argument (symlinks followed) and refuse
anything that lands outside the directories they were given:

* this job's staging directory, where their own uploads land, and
* every directory in `MALJAN_SAMPLE_ROOTS`.

This job's, not the base: a path that resolves into another job's staging
directory is refused even when a sample root happens to contain the base, so
the job directory is the boundary whatever the roots are configured as.

A capture is named relative to the job's own directory wherever a model sees
it (`captures/<file>`), never by host path. When the job has exactly one
capture, `pcap_path` is hidden from the schema the built-in servers' tools are
bound with and filled in by the platform, the way the sample's own path is
(`agents.tool_pinning`); with several it stays the model's to give, a relative
value is read inside the job's directory, and a refusal lists the job's
captures by those names — or says there is none — instead of advising a caller
to leave out an argument the tool requires. A filled-in capture the server
cannot read comes back as that failure, naming the capture by its job-relative
name and saying the platform filled it in. Every capture tool reads the whole
capture as a stream and states the packets it read and the packets in the
capture; `packet_limit` has no default and applies only when a caller passes
it, and `read_pcap_summary` with none answers the capture's facts rather than
a line per packet.

`carved_path` on the `analysis` sidecar is narrower than both, because it is
the one file argument a *model* chooses rather than the platform: it is held to
`<staging>/job-<id>/carved/<sha256 of the file the call is pinned to>/` and to
that file itself, so a run reaches the payloads it carved and nothing another
run carved or uploaded — two jobs on the same sample carve into two directories
and neither can name the other's. The resolved value must be a regular file; a
directory, a FIFO, a device or a socket is refused.

| variable | default | meaning | seen by |
| :-- | :-- | :-- | :-- |
| `MALJAN_SAMPLE_ROOTS` | empty | the directories a `path`, `pcap_path` or delivered sample may be read in, separated by `:` | `analysis`, `network` |
| `MALJAN_STAGING_DIR` | a `maljan-analysis-mcp` directory under the system temp dir | where a delivered sample lands, and a root for both | `analysis`, `network` |

Those two, plus `MALJAN_STAGING_TTL_HOURS` above, are the whole of what the
`analysis` sidecar's `env_allow` carries; the `network` sidecar's carries the
two in this table and nothing else. Neither sees a credential of any kind.

**How the variable reaches a sidecar.** A stdio child is started with a built
environment rather than the worker's own: the general-purpose names (`PATH`,
`HOME`, the locale and temp ones), then exactly the names that server's
`env_allow` lists, then its `env` map. `MALJAN_SAMPLE_ROOTS` is therefore named
on the two file-reading built-ins and on no others — a variable that says where
this host keeps malware is not something every child Maljan starts has any
business reading. A tool server an operator adds receives it only when they
put the name in its own `env_allow`, which is the same switch a server of
theirs that takes paths would need anyway.

The environment is copied into the child when it is spawned, so the roots have
to be complete before a job's first sidecar starts — and they are: the worker
exports its download directory and sample mirrors at startup, the mirror step
and a sandbox capture fetch name theirs while the run is still assembling its
inputs, and a run that was handed a sample path names that file's directory
before the pipeline builds. A job's servers are attached after all of it, and a
sidecar held over from an earlier job is closed and started again for the new
job, so nothing has to be restarted mid-run for a root to take effect.

**The names a built-in always gets.** Three names are not an operator's to
take away: `MALJAN_SAMPLE_ROOTS` and `MALJAN_STAGING_DIR` on `analysis` and
`network`, and `MALJAN_STAGING_TTL_HOURS` on `analysis`. They are what a
sidecar cannot work out for itself — which directories it may read, where a
delivered sample lands and how long it is kept — so they are put back on load,
on save, in the Configuration tab's own view and in the connection test. The
tab draws them above the box as names that are always passed, so a deletion is
never accepted and then quietly undone; what stays editable there is the rest
of the list. The registry is stored as one row holding every server, written
whole whenever
anything in it is saved, so without that floor a deployment that had configured
its servers
before a sidecar gained a variable would keep starting that sidecar without
it — which for `MALJAN_SAMPLE_ROOTS` means every tool call on the run's own
sample refused with `path_outside_roots`.

Every other name a built-in ships with is a default rather than a floor:
`threatintel`'s `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` are the
deployment's own credentials, and an `env_allow` an admin empties stays empty
everywhere that list is read. A name an admin adds to a built-in is kept, after
the required ones. A server an operator added is left exactly as they typed it,
required names and all: it reads the sample roots only when its own `env_allow`
names them.

A refusal is the ordinary structured error with the code `path_outside_roots`
and a remedy, and it names no host path.

The worker fills `MALJAN_SAMPLE_ROOTS` in for itself: its download directory
(`UPLOAD_TEMP_DIR`), the sample mirrors under `SAMPLES_DIR` and the directory a
sandbox capture is fetched to are exported before any sidecar starts, so a
default deployment needs no configuration. Set the variable when a sample lives
somewhere the worker did not put it — a corpus directory an operator points the
CLI at, or an HTTP sidecar on another host that is handed paths rather than
uploads. `ruleset` is held to the rule corpora instead: the repository's `data`
tree and whatever `MALJAN_YARA_RULES_DIR` and `MALJAN_SIGMA_RULES_DIR` name.

### A tool server that keeps failing is rested

Per job and per tool server, three settings under **Tool servers → Resilience**:

| Setting | Default | Where the default came from |
|---|---|---|
| `core.mcp.breaker.failures_to_open` | 3 | The number of attempts the platform already gives a model call that drops its connection before calling it a failure. No recorded live run had a tool server fail at the transport, so it is a judgement, not a measurement. |
| `core.mcp.breaker.cooldown_seconds` | 60 | A judgement: long enough for a sidecar being restarted to come back, short against the analysts' own loop budgets. |
| `core.mcp.breaker.call_timeout_seconds` | 0 (derived) | Derived from the longest tool budget the deployment configures — `core.static.capa.timeout_seconds`, 300 by default and 900 on a slow host — so a call never times out before the analysis it runs may finish. A tool whose server declares a longer budget in its manifest gets that; thirty seconds of grace are added either way. |
| `core.mcp.breaker.max_concurrent_calls` | 4 | A judgement: the shipped teams run their analysts one after another, and four lets one analyst's parallel tool calls through while bounding a team that fans out. `0` leaves the calls uncapped, as every server was before. |

An unanswered call is either a transport failure — a timeout, a refused or
dropped connection, the server's process gone — or a call that did not finish
within its caller's own budget (a loop's or an ask's) while it waited on the
server. Every call is sent with a deadline (above), so a server that hangs
times out and is counted; a call its caller's budget cut short is counted too,
under its own reason, rather than let go. After that many in a row the
server rests: a call is not sent, and the model is answered with a tool error
in the structured shape —

```json
{"error": {"code": "server_resting",
           "message": "tool server 'analysis' is resting after 3 calls in a row it did not answer; it will be tried again in 60 s",
           "remediation": "this server did not answer several calls in a row and is not being called for now; use another tool, or call this one again after the time the message names"},
 "tool": "pe_info"}
```

— which the ledger records as a failed call like any other. After the cooldown
one call is let through (the others are told that one call is trying the server
again and nothing more is sent until it answers); a success ends the rest and
its own failure to answer starts another. The guard covers every server the job's
registry attaches; the Ghidra and CAPE providers' own toolkits are outside it. A tool that answers with its own error (a bad argument, a file
that is not there) has answered, and never counts. Each rest is published as a
`tool_server_rested` event, drawn in the conversation, and kept in
`run_summary.server_rests`, which the report and the console's "What the run
spent" print. The call cap queues calls per event loop: a handle is opened per
loop, and for a stdio server that is one child process per loop.

## Writing a tool server

Any MCP server works: Maljan reads its manifest and calls its tools. Two
optional conventions make a server a better citizen of a run, and the four
built-in sidecars follow both.

**The capability manifest.** A tool named `capabilities`, taking no argument,
answers what the server can do on the host it runs on:

```json
{"server": "analysis", "version": "1.0.0",
 "tools": [{"name": "document_info", "optional_dependency": "olefile",
            "available": false, "reason": "olefile is not installed",
            "timeout_s": null,
            "remediation": "install the optional tool libraries on the host that runs this server: uv sync --extra tools",
            "without": "the PDF and OOXML halves"}]}
```

Compute it when the server starts, by probing — an import, a `which`, an
environment variable — never by asserting; `maljan.tools.capabilities.manifest`
does that for a list of `ToolNeeds` and is what the sidecars use. The registry
reads the manifest once per job when it attaches the server and keeps it on
the server's entry; the connection test (`POST /api/v1/settings/test/mcp`)
returns it under `details.capabilities`, and the console's server card lists
the unavailable tools with their reason before any run. When an analysis
stage's agent starts, each tool it binds that its server's manifest marks
unavailable is recorded once as
`server.<key>.<tool>_unavailable(<reason>); still answers <without>; <remediation>`
in the run's degradation reasons, instead of being discovered by a failed call
mid-run. `timeout_s` is the tool's real timeout, taken from the constant the
tool itself uses, so a manifest cannot say a call has none when it gives up
after fifteen seconds. An unavailable tool does not make the run degraded on its own; a
server that could not be attached still does.

**Errors that name their remedy.** A tool that cannot answer returns, never
raises:

```json
{"error": {"code": "missing_dependency",
           "message": "olefile is not installed",
           "remediation": "install the optional tool libraries: uv sync --extra tools"},
 "tool": "document_info"}
```

The codes are `missing_dependency`, `timeout`, `bad_argument`, `no_such_file`,
`unsupported_format`, `not_configured` and `tool_failed`; a code of your own is
kept as written. `maljan.tools.errors.tool_error(code, message, tool=...)`
builds the shape with the authored remediation for the code, and each sidecar's
guard maps an exception it catches to a code. The older flat shape,
`{"error": "<text>"}`, is still read: the sidecars rewrite it into the
structured one on the way out, inferring the code from the text, and the
ledger reads either. A returned error is a failed ledger entry: `ok` false,
`error` the message, `remediation` the hint — the report header lists each
distinct failure once with its remedy, the console's evidence row shows both,
and `GET /api/v1/jobs/{id}/evidence` serves them.

**The budget meter** needs nothing from a server. The tool loop emits
`budget_tick` every five steps and once more when it ends (steps used against
the cap, seconds against the limit, prompt characters, the characters of the
tool definitions sent with every request, ledger entries so far)
and `stage_ended_at_cap` when a cap ended the work — `steps`, `time`,
`repeats` or, for the triage pack, `budget_seconds`; `run_summary.budget` sums
the spend per agent with the caps it hit and keeps the largest
`tool_definition_chars` of its loops, and the console's pipeline panel
says beside the step which cap ended it.

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
