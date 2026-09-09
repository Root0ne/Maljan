# Settings redesign — design

Date: 2026-09-08. Scope: the `/settings` area of `apps/web`, plus two small catalog
annotations on the backend that the new layout needs. Every feature the current
Settings section offers is kept; the full inventory that this design was checked
against lives in `other/audit/2026-09-07-live-e2e/settings-inventory.md` (239 catalog
entries, 4 composite editors, 14 probes, 10 endpoints, the behaviour pinned by the
three `settings-*.spec.ts` files).

## Goals

1. An operator finds a setting by what it is for, not by which Pydantic prefix it
   lives under, and can send a colleague a link to it.
2. A group of forty fields reads as a few short sections with the rare knobs folded
   away, not as one wall of prose.
3. The confirm step before Apply is reviewable for every kind of change, including the
   server map and the agent definitions.
4. One vocabulary: one wording for when a change takes effect, one meaning for
   "reset", one secret control, one place to edit a per-agent model.
5. No feature is removed and no catalog key changes meaning; the API contract is
   extended, never broken.

6. An operator who has never seen the catalog can connect a model, a static analyser,
   a sandbox, a tool server or a new analyst by answering a short sequence of
   questions, testing as they go, and confirming one review list at the end.

Non-goals: a settings history view, an import path for `.env` files, new settings.

## Information architecture

`/settings` becomes a small area with its own layout (heading, description, top
navigation as links) and three pages:

| Route | Page | Who |
|---|---|---|
| `/settings/profile` | User profile and password (today's General tab, unchanged) | every user |
| `/settings/api-keys` | API keys (today's tab, plus a copy button for a freshly created key) | every user |
| `/settings/setup` | the setup hub: one card per guide with its current status | ADMIN |
| `/settings/setup/[guide]?step=N` | one setup guide | ADMIN |
| `/settings/configuration/[section]/[group]` | the admin console | ADMIN |

`/settings` redirects to `/settings/profile`; `/settings/configuration` redirects to the
first group of the first section. Non-admins see the Configuration link disabled with
the same "Admin role required" title as today, and the page itself renders the same
forbidden notice if reached directly.

The sixteen backend groups keep their keys and titles and are arranged under five
sections. The mapping is a frontend table (`sections.ts`); a group the table does not
know lands in a trailing "Other" entry of the Platform section, so a group added on the
backend can never disappear.

| Section (route segment) | Groups, in order |
|---|---|
| Models (`models`) | `llm` LLM & model · `providers` Providers |
| Analysis tools (`tools`) | `static` Static analysis provider · `sandbox` Sandbox provider · `mcp` Tool servers (MCP) · `memory` Memory / LTM (Qdrant) |
| Agents and pipeline (`agents`) | `agents` Agents · `profiles` Profiles (see below) · `negotiation` Negotiation · `chunking` Chunking |
| Layers and reporting (`layers`) | `analysis` Analysis layers · `reporting` Reporting |
| Platform (`platform`) | `enrichment` Enrichment / threat intelligence · `api` API · `tracing` Tracing · `frontier` Frontier arms · `system` System (read-only) |

`profiles` is a frontend-only split of the backend `agents` group: the page shows the
`core.agents.profiles` editor and the `core.agents.profile` selector; the `agents` page
shows `core.agents.definitions` and the ReAct limits. Both pages read the same schema
group; staged keys are tracked per catalog key, so the dirty badges on the rail count
correctly for each page.

The left rail lists sections as headings with their groups underneath, the active
group highlighted (`aria-current="page"`), and a numeric badge of staged changes per
group (a visually hidden "N unsaved changes" label replaces today's bare `•`). On small
screens the rail collapses to a select.

## Backend additions

Two optional fields on `Annotation` and `CatalogEntry`, both exposed through the schema
endpoint and typed on the web side:

- `subgroup: str` — a heading inside the group. Entries without one render first under
  no heading. Subgroups render in first-seen order after sorting by `order`, `key`.
- `advanced: bool` — the entry renders inside a closed "Advanced" disclosure at the end
  of its subgroup (or of the group). A staged or `ui`-sourced advanced entry forces the
  disclosure open on load so an override is never hidden.

`SettingsGroup` gains `description: str` from a new `GROUP_DESCRIPTIONS` table next to
`GROUP_ORDER`; the frontend renders it under the group title.

Assignments (no key moves group; only headings and folding change):

- `providers`: subgroup per vendor — "OpenAI", "Anthropic", "Google Gemini", "Ollama".
  The three flat shortcut keys (`core.openai_api_key`, `core.anthropic_api_key`,
  `core.google_api_key`) are `advanced`, and their description says which key they
  promote into. `core.llm.ollama.keep_alive`, `core.llm.openai.repetition_penalty`,
  `core.llm.openai.disable_thinking` are `advanced`.
- `llm`: `core.llm.agents` is `advanced`; its description points at the Agents page,
  which is the primary editor. `view_decomposition_*` share the subgroup
  "View decomposition".
- `static`: the Ghidra and radare2 blocks use subgroups "Connection" (`transport`,
  `command`, `args`, `cwd`, `url`, `auth_token`, `binary_path`, `mirror_dir`, `enabled`)
  and "Tool selection" (`tool_selection`, `use_all_tools`); `env` and `env_allow` are
  `advanced`. capa/YARA fields share the subgroup "Rules".
- `sandbox`: the CAPE MCP block follows the same Connection / Tool selection / advanced
  split; Triage, Upload and REST fields keep their `applies_when` gates. The REST
  editor's own fieldsets stay as they are.
- `analysis`: subgroups "Feature switches" (every `use_*` bool), "Reference data"
  (every `*_path`, `sigma_rules_dir`), "Thresholds and limits" (numbers), "Function
  summarizer" (`summarizer_*`). The four `*_min_alignment*` / `*_min_score` thresholds
  and `sink_reachability_max_funcs`, `static_function_rag_*`, `function_hash_*` are
  `advanced`.
- `agents`: `core.react_agent_max_steps_overrides` and
  `core.react_agent_timeout_overrides` are `advanced` under the subgroup "Limits" with
  the other `react_*` keys and `core.max_token_limit`.
- `reporting`: subgroups "Report content" (`enabled`, `composer_*`, `narrative_max_tokens`,
  `auto_generate_detection_rules`, `include_extended_stix`, `html_export_enabled`) and
  "Document metadata" (`default_tlp`, `author_team`, `product_type`, `publisher`,
  `report_number_prefix`).
- `frontier`: description states it is evaluation-only and read by nothing in the
  production pipeline; pricing and parameter-count keys are `advanced`.
- `memory`, `negotiation`, `chunking`, `tracing`, `enrichment`, `api`, `system`:
  description only.

The catalog unit tests gain assertions that every `subgroup`/`advanced` annotation
names an existing key and that no entry is both hidden by an empty `applies_when` and
advanced (the three "Ignored: provider-owned" leaves stay hidden as today).

## Field row

One row, one line when the control is short:

```
Title                       [control            ]  ● modified
core.llm.expert_max_tokens · ui · next analysis      Discard · Remove override
Per-call output cap for the analyst LLM; 0 means unbounded. more…
```

- Title is a `<label>` for single-widget rows (kept for the e2e test that checks
  `id` and `name`); composite rows keep a `<span>`.
- Meta line: the key as a copy button with visible "copied" feedback for two seconds,
  the source badge (`default` / `env` / `ui`) and the applies badge.
- Description: first sentence shown, the rest behind "more" when it exceeds one line.
- The applies vocabulary is one table used by the row, the group header, the changes
  bar and the post-apply status: `next_job → "next analysis"`, `live → "immediately"`,
  `restart → "after a restart"`.
- Row actions: "Discard" (drops the staged edit) and, when `source === "ui"`,
  "Remove override" (today's "Reset to env": an immediate delete, followed by a reload;
  the button title says "Removes the stored value now, without Apply").
- Wide controls (JSON, lists, textareas, the composite editors) drop below the title
  as today.

Widgets keep their behaviour (`widgets.tsx`) and gain one shared `SecretField`
component used by the secret row type and by the server card's auth token, with one
set of verbs: status line, "Set new value" / "Replace", "Stage", "Cancel", "Clear".

## Group page

Header: title, description, the probe buttons for the group's distinct probes (every
probe id has a label: Qdrant, Redis, VirusTotal, AbuseIPDB and the `capa`/`cape` aliases
included), a probe result line that is cleared when any input the probe reads is
staged (the two card editors already do this; the group header will too), and "Remove
all overrides in this group" with a confirmation dialog naming the count.

Body: subgroup headings, rows, one closed "Advanced (N)" disclosure per subgroup that
needs one. Provider groups render the selector first and the dependent rows under a
heading named after the selected provider, so the page is never empty when the
provider is `none` or `mock`: a one-line note says what that choice means.

Toolbar (shared across groups): search box, "Only changed" toggle (filters rows to
`source === "ui"` or staged), "Export overrides" as a button with a download icon and
a toast, and the secrets-read-only warning as a full-width banner with the env name.
Search navigates to `/settings/configuration/search?q=…`, which lists matches grouped
by section › group with a link into each group; the rail shows no active group there.

## Changes bar

Sticky bottom bar while anything is staged: "N changes" plus "M hidden by the current
provider selection". "Review" opens the review list; "Apply" is only enabled from the
review; "Discard all" un-stages everything (confirm when N > 3).

The review list is grouped by section › group. Each item is one catalog key with a
human summary produced by `describeChange(entry, before, after)`:

- scalar and enum: `Title: 4096 → 8192`; bool: `Title: on → off`; secret: `Title: new
  value` / `Title: cleared`; list and dict: `+2 −1 entries` with an expandable diff;
  null: `unset`.
- `core.mcp.servers`: per server key — `added`, `removed`, `disabled`, `enabled`,
  `changed: transport, url, tools (3 → 5)`.
- `core.agents.definitions`: per agent — `added (clone of static)`, `removed`,
  `disabled`, `changed: prompt, tools, static provider`.
- `core.agents.profiles` / `core.agents.profile`: `profile full: analysts reordered
  (static, static_r2, …)`, `active profile: default → full`.
- `core.llm.agents`: per agent — `judge: ollama/qwen3:4b (temp 0.1)` or `override
  removed`.
- `core.sandbox.rest.mapping.*`: `channel dns: $.a → $.b`.

Every item ends with the applies wording. The bar keeps today's contract: one `PATCH`
with the whole pending map, 422 errors land on rows and cards, "foreign" errors show the
existing banner, the post-apply status counts by bucket.

## Composite editors

All four keep their staged-whole-value model, their key rules, their probe wiring and
their test ids. What changes is the layout.

**Tool servers** (`core.mcp.servers`): master–detail. Left: a list of servers with
name, transport, enabled state, a "changed" dot and the last probe verdict; "Add server"
at the bottom with the same key validation. Right: the selected server's form in three
sections — Connection (transport and its dependent fields, the shared `SecretField`
for the token), Tools (selection mode, force-all, and the tick list; when no manifest
is loaded the section shows "Run Test to load the tool list" with the Test button
inline), Agents (the four role checkboxes). Header of the detail: enabled switch,
Test, Remove or Disable. Editing a probe input still drops the manifest, and the
section says so.

**Agents** (`core.agents.definitions` + `core.llm.agents`): master–detail with the
same shape. Left: agents with role badge, built-in marker, enabled state, changed dot,
resolve verdict; "Add agent". Right: Identity (label, role for custom agents, static
provider for static/generic roles), Prompt (with the resolved built-in prompt shown
read-only after Resolve), Model override (provider, model with the datalist, temperature;
the same `putLlm` rules), Tools as a tree: "its static provider's tools" (generic only),
then one node per server with "all allowed tools" and, once listed, its tools indented
under it. Header: enabled, Resolve, Clone (never on the judge), Remove or Disable.

**Profiles** (`core.agents.profiles` + `core.agents.profile`): a card per profile as
today, with the analyst list as numbered rows, larger move buttons with arrow icons,
"Set active" as a radio-style button in the card header, and the "needs at least one
analyst" alert kept.

**REST sandbox**: unchanged fieldsets and mapping table; the table gains a sticky header
and the preview textarea moves into a "Test with a sample response" disclosure so the
page is shorter when no preview is wanted.

## Setup guides

The guides are the friendly front door to the same settings. They create no new
state: every control in a guide is the catalog entry's own widget (the same `FieldRow`
in a `variant="guide"` layout), every test is the group's own probe, and the last step
is the same review list and the same single `PATCH` the console uses. Leaving a guide
half-way loses nothing: the staged values stay in the shared context and show in the
console and in the changes bar. Every step carries an "Open in the full settings" link
to its group, and every console group whose keys a guide covers carries a "Set up with
the guide" link back.

### Hub — `/settings/setup`

One card per guide with a title, one sentence, a status line computed from current
values, and a button:

| Guide (`[guide]`) | Status line |
|---|---|
| `llm` Connect a language model | provider and the expert/judge models, or "not configured" |
| `static` Choose a static analyser | provider, or "none" |
| `sandbox` Connect a sandbox | provider, or "mock (built-in fixtures)" |
| `tool-server` Add a tool server | count of enabled servers |
| `agent` Create an analyst | count of enabled custom agents and the active profile |
| `memory` Set up long-term memory | backend, and the Qdrant URL when qdrant |
| `enrichment` Enable threat-intelligence enrichment | on/off and which keys are set |

The hub is also linked from the console rail ("Setup guides") and is the landing page
of `/settings/configuration` when no LLM provider has a usable configuration (no API
key for a hosted provider, or `ollama` with an empty base URL); otherwise the console
lands on the first group as before.

### Step contract

A guide is an ordered list of steps declared in `guides.ts`:

```ts
interface GuideStep {
  id: string;                 // route query ?step=<id>
  title: string;
  intro?: string;             // one or two sentences of plain language
  keys?: string[];            // catalog keys rendered with FieldRow variant="guide"
  respectAppliesWhen?: boolean; // default true: hidden keys are skipped
  probe?: string;             // renders the probe button + result for this step
  component?: "server-form" | "agent-form" | "profile-picker" | "rest-mapping";
  canContinue?: (ctx: GuideContext) => string | null; // reason to block, or null
}
```

The guide page renders a step indicator, the step body, "Back", "Continue" (blocked
with the reason from `canContinue`, for example "run the connection test first" or
"pick a model"), and on the last step the review list from `describeChange` with
"Apply". Probe results are per step and are cleared when a key the probe reads is
staged, as in the console. A guide can be reopened at any time to change a choice; it
pre-fills from current values.

### The seven guides

**Connect a language model** — provider (`core.llm.provider`) → credentials and
endpoint for that provider only (the vendor's `api_key`, `base_url`, and for Ollama
`num_ctx`, `keep_alive` under "Advanced") → "Test connection and fetch models" → expert
and judge model pickers filled from the fetched list (free text stays possible) →
optional "Limits" step (`expert_max_tokens`, `judge_max_tokens`, `parallel_analysts`,
view decomposition) → review.

**Choose a static analyser** — provider with a one-line description per choice
(`core.static.provider`) → that provider's fields (Ghidra connection; radare2 binary
path and mirror dir; capa/YARA rule dirs; the generic MCP server picker with a link to
the tool-server guide when the list is empty) → the matching probe → review.

**Connect a sandbox** — provider with descriptions (`core.sandbox.provider`) → provider
fields (CAPE, Triage, Upload; REST splits into Connection / Submit / Status / Report
steps and, for the generic format, a Mapping step with the paste-and-preview table) →
probe → review.

**Add a tool server** — name (same key rules) → transport and connection
(`server-form` Connection section) → test and tick tools → bind agents → review. The
guide can also edit an existing server chosen on the first step.

**Create an analyst** — start from a built-in (clone) or a blank generic agent → name
and label → role, static provider, prompt (with the resolved built-in prompt visible)
→ tools (the same tree) → model override → Resolve → "Add to a profile" (`profile-picker`:
pick an existing profile, or create one from the current active profile plus this
agent; optionally set it active) → review. Writes `core.agents.definitions`,
`core.llm.agents`, `core.agents.profiles`, `core.agents.profile` exactly as the console
editors do.

**Set up long-term memory** — backend → Qdrant URL, key, collections, `top_k` → test →
review.

**Enable threat-intelligence enrichment** — switch and lookup budget → VirusTotal and
AbuseIPDB keys with their tests → review.

Nothing in a guide is reachable only through the guide: the console still exposes
every key and every editor.

## State and data flow

`useSettings` moves into a React context provided by `settings/configuration/layout.tsx`
so schema, values, pending edits, errors and probe models survive navigation between
groups; the `beforeunload` guard stays. Group pages read the group by route param;
the search page reads all groups. The context exposes what the tab exposes today
(`stage`, `unstage`, `apply`, `reset`, `resetGroup`, `probeValues`, `hiddenKeys`) plus
`stagedCountByGroup`. No new endpoints; `GET /schema` and `GET /` are called once per
mount as today.

## Testing

- Unit (vitest is not set up; keep to Playwright and Python): the `describeChange`
  summariser and `sections.ts` mapping get a Playwright spec that mounts the page with
  mocked schema/values and asserts the review text for each key kind.
- The three `settings-*.spec.ts` files are updated to the new routes and layout with
  every existing assertion kept (one PATCH, secret never rendered, probe body carries
  every staged input, group reset only for `ui`, hidden staged edit counted, non-admin
  gating, built-in Disable, judge has no Clone, clone naming, error placement).
- New Playwright checks: deep link to a group opens it; rail badge counts; "Only
  changed" filter; advanced disclosure opens for an overridden key; group reset asks
  for confirmation; probe result clears when an input is staged; API key copy button.
- Backend: catalog tests for `subgroup`/`advanced`/`description`; the API type test
  for the schema shape.
- Manual: a Chrome DevTools walkthrough of every group and both master–detail editors
  on the running stack, screenshots stored under `other/audit/`.

## Delivery

One feature branch from `dev`, four PRs into `dev`:

1. Backend annotations and group descriptions; web routes, layout, rail, context,
   compact field row, group page with subgroups/advanced, toolbar, search page, changes
   bar with `describeChange`; `settings-configuration.spec.ts` updated.
2. Master–detail Tool servers and Agents editors, shared `SecretField`, Profiles and
   REST refinements; `settings-servers.spec.ts` and `settings-agents.spec.ts` updated.
3. Setup hub and the seven guides on top of the shared context, `FieldRow`
   `variant="guide"`, the `server-form` / `agent-form` / `profile-picker` /
   `rest-mapping` step components extracted from the editors; a `settings-setup.spec.ts`
   that walks every guide against mocked endpoints and asserts the PATCH body.
4. Polish found in the walkthrough, API key copy button, screenshots, and the ledger.

Constraints carried from the project: no changes under `tests/evaluation/`; Playwright
runs only named specs and never while an LLM job runs; PRs into `dev`; promotion to
`main` at the end of this work (requested in advance on 2026-09-08).
