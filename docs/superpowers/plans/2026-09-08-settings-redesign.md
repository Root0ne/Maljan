# Settings Redesign Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reshape `/settings` into a routed, sectioned console with compact rows, a reviewable apply step, master–detail editors and seven setup guides, keeping every one of the 239 catalog entries, 4 composite editors, 14 probes and 10 endpoints in reach.

**Architecture:** The backend catalog gains two optional annotations (`subgroup`, `advanced`) and a per-group description; the web app moves settings into Next.js App Router routes under `apps/web/src/app/(app)/settings/**`, keeps all staged state in one React context (`SettingsProvider`, wrapping today's `useSettings`), and builds the console pages, the changes bar and the guides on top of that one context. Guides render the same `FieldRow` widgets and the same probes, and end in the same `PATCH`.

**Tech Stack:** Next.js 16 App Router, React 19, TypeScript, Tailwind 4, Playwright (e2e, `apps/web/e2e`), vitest (new, pure modules only), FastAPI + Pydantic catalog (`src/maljan/core/settings_catalog.py`, `apps/api`).

**Spec:** `docs/superpowers/specs/2026-09-08-settings-redesign-design.md` (read it first). Feature inventory used as the no-loss checklist: `other/audit/2026-09-07-live-e2e/settings-inventory.md` (local file; if absent, derive from the spec's §Setup guides and §Composite editors).

## Global Constraints

- No file under `tests/evaluation/` changes (CI gate rejects it).
- No catalog key is renamed, removed or moved to another group; `GROUP_ORDER` keys and titles stay.
- API contract is extended only: new optional fields on `CatalogEntryDTO` (`subgroup: str | None = None`, `advanced: bool = False`) and on `GroupDTO` (`description: str = ""`).
- Every existing probe id, endpoint and `data-testid` (`server-map-editor`, `agent-definitions-editor`, `profiles-editor`, `rest-sandbox-editor`, `data-server`, `data-agent`, `data-profile`, `data-token-state`) stays.
- One vocabulary for `applies`, imported from `apps/web/src/app/(app)/settings/configuration/vocabulary.ts`: `next_job → "next analysis"`, `live → "immediately"`, `restart → "after a restart"`; the review-list sentence is `takes effect on the next analysis` / `takes effect immediately` / `takes effect after a restart`; the post-apply status is `Applied N setting(s) · X on the next analysis · Y immediately · Z after a restart`.
- Secret values are never rendered, logged or echoed; the wire value of a stored secret is `null`/mask.
- Commands: web checks are `cd apps/web && npx tsc --noEmit && npm run lint && npm run test:unit`; a Playwright spec is run by name only: `cd apps/web && npx playwright test e2e/<spec>.spec.ts --project=chromium` and never while an analysis job runs; backend checks are `make lint format-check typecheck` and `uv run pytest tests/unit/core/test_settings_catalog.py tests/unit/api -q`.
- Machine rule: one heavy workload at a time (no `next build`, no Playwright, no full pytest in parallel with each other or with an LLM job); check `free -g` (available ≥ 10 GB) before any of them.
- Commits: conventional prefix, no AI attribution trailer, no question sentences in headings, comments or docs.
- Branch: everything lands on `feat/settings-redesign` (from `dev`); PRs into `dev` after each phase below.

## File structure

Backend (modify):
- `src/maljan/core/settings_annotations.py` — `Annotation` gains `subgroup`, `advanced`; new `GROUP_DESCRIPTIONS`; assignments per spec.
- `src/maljan/core/settings_catalog.py` — `CatalogEntry.subgroup`, `.advanced`; copied from annotations.
- `apps/api/app/services/settings_catalog_api.py` — API entries pass `subgroup=None, advanced=False` (dataclass defaults cover it).
- `apps/api/app/schemas/settings.py` — DTO fields; `apps/api/app/api/v1/settings.py` — `GroupDTO(description=...)`.
- Tests: `tests/unit/core/test_settings_catalog.py`, `tests/unit/api/test_settings_catalog_api_types.py`.

Web (create unless noted; all under `apps/web/src/app/(app)/settings/`):
- `layout.tsx` — heading + top nav links (Profile, API keys, Setup, Configuration).
- `page.tsx` (modify → redirect to `/settings/profile`).
- `profile/page.tsx`, `api-keys/page.tsx` — moved from today's `page.tsx`.
- `configuration/vocabulary.ts` — applies wording.
- `configuration/sections.ts` — section table, `groupsBySection(schema)`, `sectionForGroup(key)`, `firstGroupPath(schema)`.
- `configuration/describeChange.ts` — review summaries.
- `configuration/SettingsContext.tsx` — `SettingsProvider`, `useSettingsContext()`.
- `configuration/layout.tsx` — provider + rail + toolbar + changes bar shell.
- `configuration/page.tsx` — redirect (hub or first group, see Task 16).
- `configuration/[section]/[group]/page.tsx` — group page.
- `configuration/search/page.tsx` — cross-group results.
- `configuration/SectionRail.tsx`, `configuration/Toolbar.tsx`, `configuration/ChangesBar.tsx` (replaces `ApplyBar.tsx`), `configuration/GroupPage.tsx`, `configuration/GroupHeader.tsx` (modify), `configuration/FieldRow.tsx` (modify), `configuration/SecretField.tsx`, `configuration/ServerMapEditor.tsx` (modify to master–detail), `configuration/AgentDefinitionsEditor.tsx` (modify), `configuration/ProfilesEditor.tsx` (modify), `configuration/RestSandboxEditor.tsx` (modify), `configuration/useSettings.ts` (modify: add `stagedCountByGroup`).
- `setup/page.tsx` (hub), `setup/[guide]/page.tsx`, `setup/guides.ts`, `setup/GuidePage.tsx`, `setup/steps/ServerFormStep.tsx`, `setup/steps/AgentFormStep.tsx`, `setup/steps/ProfilePickerStep.tsx`, `setup/steps/RestMappingStep.tsx`, `setup/status.ts`.
- Types: `apps/web/src/types/settings.ts` (modify).
- Tests: `apps/web/src/app/(app)/settings/configuration/__tests__/*.test.ts` (vitest), `apps/web/e2e/settings-configuration.spec.ts`, `settings-servers.spec.ts`, `settings-agents.spec.ts` (modify), `apps/web/e2e/settings-setup.spec.ts` (create), `apps/web/vitest.config.ts` (create).
- CI: `.github/workflows/ci.yml` frontend job gains `npm run test:unit`.

---

## Phase 1 — catalog metadata, routes, console shell, compact rows, reviewable apply (PR 1)

### Task 1: Catalog metadata — `subgroup`, `advanced`, group descriptions

**Files:**
- Modify: `src/maljan/core/settings_annotations.py` (Annotation TypedDict at :16-27; add `GROUP_DESCRIPTIONS` after `GROUP_ORDER` :30-47)
- Modify: `src/maljan/core/settings_catalog.py` (`CatalogEntry` :42-70, construction :180-202)
- Modify: `apps/api/app/schemas/settings.py` (`CatalogEntryDTO` :16-37, `GroupDTO` :40-43)
- Modify: `apps/api/app/api/v1/settings.py` (:82-84)
- Test: `tests/unit/core/test_settings_catalog.py`, `tests/unit/api/test_settings_catalog_api_types.py`

**Interfaces:**
- Produces: `CatalogEntry.subgroup: str | None = None`, `CatalogEntry.advanced: bool = False`; `GROUP_DESCRIPTIONS: dict[str, str]` with one sentence for all 16 group keys; `GroupDTO.description: str`; `CatalogEntryDTO.subgroup`, `.advanced`.

- [ ] **Step 1: Failing tests**

Append to `tests/unit/core/test_settings_catalog.py`:

```python
def test_every_group_has_a_description() -> None:
    from maljan.core.settings_annotations import GROUP_DESCRIPTIONS, GROUP_ORDER

    for key, _title in GROUP_ORDER:
        assert GROUP_DESCRIPTIONS.get(key), f"group {key!r} has no description"


def test_subgroup_and_advanced_default_off_and_are_typed() -> None:
    from maljan.core.settings_catalog import core_catalog

    entries = {e.key: e for e in core_catalog()}
    assert entries["core.negotiation.max_iterations"].subgroup is None
    assert entries["core.negotiation.max_iterations"].advanced is False
    for e in entries.values():
        assert e.subgroup is None or isinstance(e.subgroup, str)
        assert isinstance(e.advanced, bool)
```

Append to `tests/unit/api/test_settings_catalog_api_types.py`:

```python
def test_schema_dto_carries_subgroup_advanced_and_group_description() -> None:
    from app.schemas.settings import CatalogEntryDTO, GroupDTO

    assert CatalogEntryDTO.model_fields["subgroup"].default is None
    assert CatalogEntryDTO.model_fields["advanced"].default is False
    assert GroupDTO.model_fields["description"].default == ""
```

- [ ] **Step 2: Run, expect failure**

`uv run pytest tests/unit/core/test_settings_catalog.py tests/unit/api/test_settings_catalog_api_types.py -q` → the three new tests fail (`ImportError`/`AttributeError`/`KeyError`).

- [ ] **Step 3: Implement**

`settings_annotations.py`: add to `Annotation`
```python
    subgroup: NotRequired[str]  # heading inside the group; absent = top of the group
    advanced: NotRequired[bool]  # folded into the group's closed "Advanced" disclosure
```
and after `GROUP_ORDER`:
```python
GROUP_DESCRIPTIONS: dict[str, str] = {
    "llm": "Which language model backend the analysts and the judge call, and the per-call limits.",
    "providers": "Credentials, endpoints and model names for each LLM vendor; only the selected provider is used.",
    "frontier": "Evaluation-only comparison endpoints and their cost accounting; nothing in the analysis pipeline reads them.",
    "static": "The static analysis provider behind the static analyst and its connection details.",
    "sandbox": "Where samples are detonated, or which uploaded report stands in for a detonation.",
    "mcp": "Tool servers the agents may call, with the tools each one is allowed to expose.",
    "memory": "Long-term memory of past analyses: the backend, the collections and how many neighbours are recalled.",
    "analysis": "Deterministic pre-analysis layers: feature switches, reference data files and their thresholds.",
    "negotiation": "How many rounds the analysts negotiate and when consensus is reached.",
    "chunking": "How large inputs are split before they reach a model.",
    "reporting": "What the final report contains and the metadata stamped on it.",
    "agents": "The analysts Maljan can run, the profile that selects them, and the ReAct limits.",
    "tracing": "LangSmith tracing of every model call.",
    "enrichment": "Threat-intelligence lookups for the indicators a report names.",
    "api": "Request limits and login protection of the HTTP API; changes take effect immediately.",
    "system": "Deployment values read from the environment at start; shown for reference and changed by restarting.",
}
```
`settings_catalog.py`: add fields to `CatalogEntry` after `editor`:
```python
    subgroup: str | None = None
    advanced: bool = False
```
and in the constructor call: `subgroup=(ann.get("subgroup") if ann else None), advanced=bool(ann.get("advanced", False)) if ann else False,`.
`schemas/settings.py`: `subgroup: str | None = None`, `advanced: bool = False` on `CatalogEntryDTO`; `description: str = ""` on `GroupDTO`.
`api/v1/settings.py:82-84`: `GroupDTO(key=g, title=t, description=GROUP_DESCRIPTIONS.get(g, ""), entries=by_group[g])` (import `GROUP_DESCRIPTIONS` next to `GROUP_ORDER`). Check that the DTO is built with `CatalogEntryDTO(**d)` from `asdict(e)`, so the new dataclass fields flow through automatically.

- [ ] **Step 4: Run tests and quality**

`uv run pytest tests/unit/core/test_settings_catalog.py tests/unit/api -q` → pass. `make lint format-check typecheck` → clean.

- [ ] **Step 5: Commit** — `feat(settings): subgroup and advanced annotations, group descriptions`

### Task 2: Assign subgroups and advanced flags per the spec

**Files:**
- Modify: `src/maljan/core/settings_annotations.py` (annotation dicts for the keys named in the spec §Backend additions; the MCP block helper `mcp_server_annotations` :973-1020 gets two parameters)
- Test: `tests/unit/core/test_settings_catalog.py`

**Interfaces:** none new; the catalog now returns `subgroup`/`advanced` per spec.

- [ ] **Step 1: Failing test** — append:

```python
def test_subgroup_and_advanced_assignments_follow_the_design() -> None:
    from maljan.core.settings_catalog import core_catalog

    e = {x.key: x for x in core_catalog()}
    assert e["core.openai_api_key"].advanced and e["core.anthropic_api_key"].advanced
    assert e["core.google_api_key"].advanced
    assert e["core.llm.openai.api_key"].subgroup == "OpenAI"
    assert e["core.llm.ollama.base_url"].subgroup == "Ollama"
    assert e["core.llm.ollama.keep_alive"].advanced
    assert e["core.llm.agents"].advanced
    assert e["core.llm.view_decomposition_mode"].subgroup == "View decomposition"
    assert e["core.static.r2.binary_path"].subgroup == "Connection"
    assert e["core.static.r2.tool_selection"].subgroup == "Tool selection"
    assert e["core.static.r2.env"].advanced and e["core.static.ghidra.env_allow"].advanced
    assert e["core.static.capa.rules_dir"].subgroup == "Rules"
    assert e["core.sandbox.cape2.mcp.transport"].subgroup == "Connection"
    assert e["core.preprocessing.use_packer_signatures"].subgroup == "Feature switches"
    assert e["core.preprocessing.packer_signatures_path"].subgroup == "Reference data"
    assert e["core.analysis.sigma_rules_dir"].subgroup == "Reference data"
    assert e["core.preprocessing.max_tool_output_chars"].subgroup == "Thresholds and limits"
    assert e["core.preprocessing.attck_case_rag_min_score"].advanced
    assert e["core.preprocessing.summarizer_model"].subgroup == "Function summarizer"
    assert e["core.react_agent_max_steps_overrides"].advanced
    assert e["core.react_agent_timeout"].subgroup == "Limits"
    assert e["core.reporting.default_tlp"].subgroup == "Document metadata"
    assert e["core.reporting.composer_enabled"].subgroup == "Report content"
    assert e["core.llm.frontier.input_usd_per_mtok"].advanced
    # An entry hidden for good must not also be folded away as advanced.
    for x in e.values():
        if x.applies_when and any(v == [] for v in x.applies_when.values()):
            assert not x.advanced, x.key
```

- [ ] **Step 2: Run, expect failure.**

- [ ] **Step 3: Implement** by editing the annotation dicts. For the repeated MCP blocks extend `mcp_server_annotations(...)` so `transport, command, args, cwd, url, auth_token, enabled` (and the r2-only `binary_path`, `mirror_dir`) get `subgroup="Connection"`, `tool_selection`/`use_all_tools` get `subgroup="Tool selection"`, and `env`/`env_allow` get `advanced=True`. Full list per group is in the spec; every `use_*` bool in `preprocessing` → "Feature switches"; every `*_path` and `core.analysis.sigma_rules_dir` → "Reference data"; `summarizer_*` → "Function summarizer"; remaining numeric/enum preprocessing keys → "Thresholds and limits", with `attck_autocorrect_min_alignment`, `attck_autocorrect_min_alignment_semantic`, `attck_case_rag_min_score`, `family_rag_min_score`, `sink_reachability_max_funcs`, `static_function_rag_min_chunks`, `static_function_rag_top_k`, `function_hash_max_matches`, `function_hash_min_instructions` also `advanced`. Frontier: `input_usd_per_mtok`, `output_usd_per_mtok`, `active_params_b`, `total_params_b`, `quantisation`, `count_reasoning_tokens`, `free_tier` advanced. Also amend the three shortcut keys' descriptions to name the key they promote into, and `core.llm.agents`'s description to say "edited from the Agents page; this raw view is for bulk edits".

- [ ] **Step 4: Run** the catalog tests, `make lint format-check typecheck`, and the golden/snapshot tests that read annotations: `uv run pytest tests/unit/core tests/unit/api tests/api -q`.

- [ ] **Step 5: Commit** — `feat(settings): subgroup and advanced assignments for every group`

### Task 3: Web types, vocabulary, sections table, vitest

**Files:**
- Modify: `apps/web/src/types/settings.ts` (`CatalogEntry` gains `subgroup: string | null; advanced: boolean;`, `SettingsGroup` gains `description: string;`)
- Create: `apps/web/src/app/(app)/settings/configuration/vocabulary.ts`, `sections.ts`, `__tests__/sections.test.ts`, `apps/web/vitest.config.ts`
- Modify: `apps/web/package.json` (devDependency `vitest`, script `"test:unit": "vitest run"`), `.github/workflows/ci.yml` (frontend job: `- name: Unit tests` / `run: npm run test:unit` after Lint)
- Modify: `apps/web/e2e/mocks.ts` (the mocked schema groups gain `description`, entries gain `subgroup: null, advanced: false`)

**Interfaces (produces):**

```ts
// vocabulary.ts
import type { Applies } from "@/types/settings";
export const APPLIES_LABEL: Record<Applies, string> = { next_job: "next analysis", live: "immediately", restart: "after a restart" };
export const APPLIES_SENTENCE: Record<Applies, string> = { next_job: "takes effect on the next analysis", live: "takes effect immediately", restart: "takes effect after a restart" };
export function appliesSummary(counts: Partial<Record<Applies, number>>, total: number): string; // "Applied 3 settings · 2 on the next analysis · 1 immediately"

// sections.ts
export interface SectionDef { key: "models" | "tools" | "agents" | "layers" | "platform"; title: string; groups: string[] }
export const SECTIONS: SectionDef[]; // per spec table; "agents" lists ["agents","profiles","negotiation","chunking"]
export const VIRTUAL_GROUPS: Record<string, { fromGroup: string; title: string; description: string; keys: string[] }>;
// { profiles: { fromGroup: "agents", title: "Profiles", description: "...", keys: ["core.agents.profiles","core.agents.profile"] } }
export interface RailGroup { key: string; title: string; path: string; section: SectionDef["key"] }
export function groupsBySection(schema: SettingsSchema): { section: SectionDef; groups: RailGroup[] }[]; // unknown backend groups → platform, after "system", titled from the schema
export function resolveGroup(schema: SettingsSchema, section: string, group: string): { title: string; description: string; entries: CatalogEntry[]; backendGroup: string } | null;
// "profiles" returns the two keys; "agents" returns the agents group minus those two keys
export function firstGroupPath(schema: SettingsSchema): string; // "/settings/configuration/models/llm"
export function pathForKey(schema: SettingsSchema, key: string): string; // deep link to the page that renders the key
```

- [ ] **Step 1: vitest setup** — `cd apps/web && npm i -D vitest` ; `vitest.config.ts`:
```ts
import { defineConfig } from "vitest/config";
import path from "node:path";
export default defineConfig({ test: { include: ["src/**/__tests__/**/*.test.ts"] }, resolve: { alias: { "@": path.resolve(__dirname, "src") } } });
```
- [ ] **Step 2: Failing test** `__tests__/sections.test.ts`:
```ts
import { describe, expect, it } from "vitest";
import { firstGroupPath, groupsBySection, pathForKey, resolveGroup } from "../sections";
import type { SettingsSchema, CatalogEntry } from "@/types/settings";
const entry = (key: string, group: string): CatalogEntry => ({ key, namespace: "core", path: key.slice(5), type: "int", default: 1, nullable: false, choices: null, minimum: null, maximum: null, secret: false, group, title: key, description: "", applies: "next_job", editable: true, reason: null, probe: null, applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false });
const schema: SettingsSchema = { secrets_available: true, groups: [
  { key: "agents", title: "Agents", description: "", entries: [entry("core.agents.profiles", "agents"), entry("core.agents.profile", "agents"), entry("core.react_agent_timeout", "agents")] },
  { key: "llm", title: "LLM & model", description: "", entries: [entry("core.llm.provider", "llm")] },
  { key: "mystery", title: "Mystery", description: "", entries: [entry("core.mystery.x", "mystery")] },
] };
describe("sections", () => {
  it("orders sections and puts unknown groups last under platform", () => {
    const s = groupsBySection(schema);
    expect(s.map((x) => x.section.key)).toEqual(["models", "agents", "platform"]);
    expect(s.at(-1)!.groups.map((g) => g.key)).toEqual(["mystery"]);
  });
  it("splits profiles out of the agents group", () => {
    expect(resolveGroup(schema, "agents", "profiles")!.entries.map((e) => e.key)).toEqual(["core.agents.profiles", "core.agents.profile"]);
    expect(resolveGroup(schema, "agents", "agents")!.entries.map((e) => e.key)).toEqual(["core.react_agent_timeout"]);
    expect(resolveGroup(schema, "agents", "nope")).toBeNull();
  });
  it("links keys to the page that renders them", () => {
    expect(firstGroupPath(schema)).toBe("/settings/configuration/models/llm");
    expect(pathForKey(schema, "core.agents.profile")).toBe("/settings/configuration/agents/profiles");
    expect(pathForKey(schema, "core.mystery.x")).toBe("/settings/configuration/platform/mystery");
  });
});
```
- [ ] **Step 3: Run** `npm run test:unit` → fails (module missing).
- [ ] **Step 4: Implement** `vocabulary.ts`, `sections.ts`, the type additions, the mock additions, the CI step.
- [ ] **Step 5: Run** `npx tsc --noEmit && npm run lint && npm run test:unit` → clean (tsc will flag every place that builds a `CatalogEntry`/`SettingsGroup` literal; fix them).
- [ ] **Step 6: Commit** — `feat(settings-web): sections table, applies vocabulary, vitest`

### Task 4: `describeChange` review summaries

**Files:**
- Create: `configuration/describeChange.ts`, `__tests__/describeChange.test.ts`

**Interfaces (produces):**
```ts
export interface ChangeLine { key: string; title: string; summary: string; detail?: string[]; applies: Applies }
export function describeChange(entry: CatalogEntry, before: unknown, after: unknown): ChangeLine;
```
Rules (from the spec §Changes bar): scalar/enum `"<before> → <after>"` with `unset` for null/undefined; bool `on → off`; secret `new value` / `cleared`; `list`/`dict`/`json` without a special key: `"+A −R entries"` and `detail` = the added/removed items (`"+ foo"`, `"− bar"`, for dicts `"~ k: a → b"`); `core.mcp.servers`: per server key `added` / `removed` / `enabled` / `disabled` / `changed: <fields>` where tools changes read `tools (3 → 5)`; `core.agents.definitions`: `added (clone of <src>)` when the label ends with `(copy)` and a same-role source exists, else `added`; `removed`, `enabled`, `disabled`, `changed: prompt, tools, static provider, label, role`; `core.agents.profiles`: per profile `added` / `removed` / `analysts reordered (a, b, c)` / `analysts changed (+x −y)` / `label changed`; `core.agents.profile`: `active profile: a → b`; `core.llm.agents`: per agent `<provider>/<model> (temp t)` or `override removed`; `core.sandbox.rest.mapping.*`: `channel <name>: <before> → <after>` (channel = last path segment). Long strings are cut to 60 chars with `…`. Secret detection: `entry.secret`, plus `auth_token` values inside the server map render as `token replaced` / `token cleared`, never the value.

- [ ] **Step 1: Failing tests** — cover each rule with one `it`, e.g.
```ts
it("summarises a server map", () => {
  const before = { network: { enabled: true, transport: "stdio", tools: null }, old: { enabled: true, transport: "stdio" } };
  const after = { network: { enabled: false, transport: "stdio", tools: null }, r2: { enabled: true, transport: "stdio", tools: ["a", "b"] } };
  const line = describeChange(serversEntry, before, after);
  expect(line.detail).toEqual(["network: disabled", "old: removed", "r2: added"]);
});
it("never prints a token", () => {
  const line = describeChange(serversEntry, { s: { auth_token: "old" } }, { s: { auth_token: "new" } });
  expect(JSON.stringify(line)).not.toContain("new");
  expect(line.detail).toEqual(["s: changed: token replaced"]);
});
```
- [ ] **Step 2–4:** run (fail) → implement → run (pass), `tsc`, `lint`.
- [ ] **Step 5: Commit** — `feat(settings-web): human summaries for every kind of staged change`

### Task 5: Routes and pages for profile and API keys; settings layout

**Files:**
- Create: `settings/layout.tsx`, `settings/profile/page.tsx`, `settings/api-keys/page.tsx`
- Modify: `settings/page.tsx` → `redirect("/settings/profile")` (server component using `next/navigation`)
- Modify: `apps/web/e2e/settings-configuration.spec.ts` non-admin block (`:594-605`) and any spec that clicks the "Configuration" tab button — keep the assertions, change the navigation to the new routes (full rewrite of that spec happens in Task 10; here only make it compile and keep the non-admin test passing).

**Interfaces:** `layout.tsx` renders `<h1>Settings</h1>`, the group description line, and `<nav aria-label="Settings sections">` with links Profile (`/settings/profile`), API keys (`/settings/api-keys`), Setup guides (`/settings/setup`, admin only), Configuration (`/settings/configuration`, admin only). Non-admins see the two admin links rendered as `<span aria-disabled="true" title="Admin role required">`. Active link: `aria-current="page"` by `usePathname()` prefix.

- [ ] **Step 1:** Move today's General tab JSX and state (`page.tsx:16-28, 67-85, 111-146, 217-323`) into `profile/page.tsx`; API Keys JSX and state (`page.tsx:29-40, 48-65, 86-107, 148-181, 326-451, 461-517`) into `api-keys/page.tsx`; add a **Copy** button next to the created key using `navigator.clipboard.writeText` with a two-second "Copied" label and a fallback message "Select and copy the key" when the clipboard API is unavailable. Keep every id, message and modal behaviour listed in the inventory §1.
- [ ] **Step 2:** `settings/layout.tsx` as above; `settings/page.tsx` redirect.
- [ ] **Step 3:** Playwright: update `e2e/pages.spec.ts` / `auth.spec.ts` if they visit `/settings` (grep `"/settings"` in `apps/web/e2e`); update the non-admin block to `page.goto("/settings/profile")` and assert the disabled Configuration link and the absent `#settings-search`.
- [ ] **Step 4:** `npx tsc --noEmit && npm run lint`; then, with `free -g` ≥ 10 GB and no dev server running, `npx playwright test e2e/settings-configuration.spec.ts --project=chromium -g "non-admin"` → pass.
- [ ] **Step 5: Commit** — `feat(settings-web): routed profile and API-key pages, settings layout`

### Task 6: `SettingsProvider`, configuration layout, rail, redirect

**Files:**
- Create: `configuration/SettingsContext.tsx`, `configuration/layout.tsx`, `configuration/SectionRail.tsx`, `configuration/page.tsx`, `configuration/[section]/[group]/page.tsx` (temporary body: renders `GroupPage` from Task 7, or until then the existing `ConfigurationTab` group body)
- Modify: `configuration/useSettings.ts` (add `stagedCountByGroup: Record<string, number>` computed from `pending` × `entries[].group`, and `entriesByKey: Record<string, CatalogEntry>`)

**Interfaces (produces):**
```ts
export function SettingsProvider({ children }: { children: React.ReactNode }): JSX.Element; // calls useSettings once; renders the forbidden notice / loading / loadError states itself
export function useSettingsContext(): ReturnType<typeof useSettings> & { models: string[]; setModels: (m: string[]) => void; hiddenKeys: string[]; effectiveValue: (key: string) => unknown; isVisible: (entry: CatalogEntry) => boolean; probeValues: (probeId: string) => Record<string, unknown> };
```
(`effectiveValue`, `isVisible`, `hiddenKeys`, `probeValues` move out of `ConfigurationTab.tsx:27-46, 118-125, 283-288`.) The `beforeunload` guard moves into the provider.

- [ ] **Step 1:** Implement the provider and hook; `configuration/layout.tsx` = `<SettingsProvider><div class="grid lg:grid-cols-[240px_1fr]"><SectionRail/><div>{children}</div></div><ChangesBar/></SettingsProvider>` (ChangesBar arrives in Task 8; until then render the existing `ApplyBar` wired to the context).
- [ ] **Step 2:** `SectionRail`: sections as `<h3>` with `<ul>` of `<Link>`s from `groupsBySection(schema)`; active by `usePathname()`; per-group badge `<span class="badge">{n}</span><span class="sr-only">{n} unsaved changes</span>` when `stagedCountByGroup[backendGroup]` > 0 (for the virtual `profiles` page count only its two keys, and subtract them from `agents`); a "Setup guides" link at the top; on `< lg` a `<select>` that navigates on change. `data-testid="settings-rail"`.
- [ ] **Step 3:** `configuration/page.tsx`: client component that redirects to `firstGroupPath(schema)` once the schema is loaded (Task 16 changes this to prefer the hub when the LLM is unconfigured).
- [ ] **Step 4:** `[section]/[group]/page.tsx`: reads params, `resolveGroup(...)`, renders `notFound()`-style message "No such settings group" when null, else the group body (Task 7).
- [ ] **Step 5:** `tsc`, `lint`; visit `/settings/configuration` in the dev server and confirm the rail and a group render. Commit — `feat(settings-web): settings context, configuration layout and rail`

### Task 7: Group page — header, subgroups, advanced, compact rows, toolbar, search

**Files:**
- Create: `configuration/GroupPage.tsx`, `configuration/Toolbar.tsx`, `configuration/search/page.tsx`, `configuration/SecretField.tsx`
- Modify: `configuration/FieldRow.tsx`, `configuration/GroupHeader.tsx`, `configuration/widgets.tsx` (SecretWidget delegates to `SecretField`)
- Delete: `configuration/ConfigurationTab.tsx` (after everything it did lives in the pieces above)

**Interfaces:**
```ts
// FieldRow
variant?: "console" | "guide";   // guide: no key/meta line, description always full, no Discard/Remove links
// GroupHeader
{ title: string; description: string; probes: string[]; overridden: boolean; overriddenCount: number; onProbe; onResetGroup; guideHref?: string; probeInputsStaged: (probeId: string) => boolean }
// SecretField
{ id: string; name: string; status: "set" | "not-set" | "staged" | "cleared"; hint?: string | null; source?: "default" | "env" | "ui"; editable: boolean; reason?: string | null; onStage: (value: string) => void; onClear: () => void; onCancel: () => void; labels?: { replace?: string } }
```
Behaviour to implement (spec §Field row, §Group page):
- Row layout: title + control on one line for `bool`, `int`, `float`, `enum`, `str`, `secret`; meta line = copy-key button (visible "Copied" for 2 s; on failure "Copy unavailable"), source badge, applies badge (`APPLIES_LABEL`), "modified" badge; description first sentence + "more"/"less" toggle when the text is longer than 140 chars; actions "Discard" and "Remove override" (title "Removes the stored value now, without Apply"); `id="setting-<key>"`, `label htmlFor` and control `id`/`name` as today.
- GroupPage: header; entries sorted `order, key`; visible per `isVisible`; grouped by `subgroup` (null first); each subgroup renders its non-advanced rows, then `<details data-testid="advanced-<subgroup|group>"><summary>Advanced (N)</summary>…</details>`, opened by default when any advanced entry is staged or `source === "ui"`. Provider groups (`static`, `sandbox`): the selector row first, then a heading "<Provider title> settings" over the dependent rows; when the selection reveals no rows, a note: `none` → "No static provider: the static analyst works from the pre-extracted data only." / `mock` → "Mock sandbox: built-in fixture reports stand in for a detonation." The REST subset still goes through `RestSandboxEditor`.
- GroupHeader: probe buttons for the group's distinct probe ids with labels for every id (`llm`, `r2`, `ghidra`, `capa_yara`, `capa`, `cape2`, `cape`, `triage`, `rest`, `mcp`, `agent`, `qdrant: "Test Qdrant"`, `redis: "Test Redis"`, `virustotal: "Test VirusTotal"`, `abuseipdb: "Test AbuseIPDB"`); a result is cleared when `probeInputsStaged(id)` flips true after it was shown (track the pending snapshot of the probe's keys); "Remove all overrides in this group (N)" opens a confirm dialog (`role="dialog"`, buttons "Remove N overrides" / "Keep them") before calling `resetGroup`.
- Toolbar (rendered by `configuration/layout.tsx` above the page): search input (`#settings-search`, submit or debounce 300 ms → `router.push('/settings/configuration/search?q=…')`), "Only changed" switch (context flag `onlyChanged`, GroupPage filters rows to staged or `source === "ui"` and shows "No overrides in this group" when empty), Export button with icon + toast, secrets banner (`role="status"`, full width) when `secrets_available === false`.
- Search page: results grouped `Section › Group` with a link to the group; each row is a full `FieldRow` (so editing from search works, as today); rail shows no active group; empty state "No settings match “q”." Selecting a rail group clears the query (it navigates away).

- [ ] **Step 1:** Implement `SecretField` and make `SecretWidget` use it (same status strings as today: `set · …hint · source`, `not set`, `new value staged`, `will be cleared`; buttons "Set new value" → password input + "Stage"/"Cancel"; "Clear").
- [ ] **Step 2:** Implement FieldRow changes, GroupHeader, GroupPage, Toolbar, search page; wire `[section]/[group]/page.tsx`; delete `ConfigurationTab.tsx`.
- [ ] **Step 3:** `tsc`, `lint`, `test:unit`; walk `/settings/configuration/tools/static`, `/tools/sandbox` (switch providers), `/layers/analysis` (subgroups + advanced), `/platform/system` in the dev server.
- [ ] **Step 4: Commit** — `feat(settings-web): group pages with subgroups, advanced folds, compact rows and search`

### Task 8: Changes bar with the review list

**Files:**
- Create: `configuration/ChangesBar.tsx`; Delete: `configuration/ApplyBar.tsx`

**Behaviour:** hidden when nothing is pending; summary `N change(s)` + `· M hidden by the current provider selection`; buttons "Review", "Discard all" (confirm dialog when N > 3: "Discard N changes?" / "Discard" / "Keep"). Review panel: items grouped by section › group (via `pathForKey`), each `<li>`: `<strong>{title}</strong> {summary}` + optional `<ul>` of `detail` lines + `<em>{APPLIES_SENTENCE[applies]}</em>`; hidden keys get the suffix "(hidden by the current provider selection)"; a link "edit" to the key's page. Buttons in the panel: "Confirm and apply" (label "Saving…" while saving) and "Back". After apply: status line from `appliesSummary(lastResult.applies, lastResult.applied.length)` shown for 6 s, `role="status"`. Errors: 422 keeps the panel open and shows "N field(s) need attention" with links.

- [ ] **Step 1:** Implement; wire into `configuration/layout.tsx`.
- [ ] **Step 2:** `tsc`, `lint`; stage a scalar, a server-map change and a definitions change in the dev server and read the review list.
- [ ] **Step 3: Commit** — `feat(settings-web): changes bar with a readable review list`

### Task 9: Update `settings-configuration.spec.ts` to the new console

**Files:** Modify `apps/web/e2e/settings-configuration.spec.ts`, `apps/web/e2e/mocks.ts` (mock schema: add `description`, `subgroup`, `advanced`; add one `advanced: true` entry with `source: "ui"` to the Negotiation group so the fold-open rule is testable).

Keep every existing assertion (inventory §7) with these navigation changes: `page.goto("/settings/configuration/agents/negotiation")` instead of clicking the tab; rail links are `getByRole("link", { name })`; "Apply" → click "Review" then "Confirm and apply"; the pending text is `1 change`; probe labels unchanged; reset-group now confirms (`getByRole("button", { name: /Remove 1 override/ })`); "Reset to env" → "Remove override"; "Discard change" → "Discard". Add tests: deep link opens the group; rail badge shows `1` after staging; "Only changed" hides the default-sourced row; the advanced fold is open when its entry is `ui`-sourced; probe result disappears when its input is staged; search page lists the match under "Agents › Negotiation".

- [ ] **Step 1:** rewrite; **Step 2:** `npx playwright test e2e/settings-configuration.spec.ts --project=chromium` (dev server stopped, `free -g` ≥ 10) → all pass; **Step 3:** Commit — `test(e2e): settings console spec for the routed layout`.

### Task 10: Phase 1 close — build, PR into dev

- [ ] `cd apps/web && npm run build` (nothing else heavy running) → success; `make lint format-check typecheck` and `uv run pytest tests/unit tests/api -q` → green.
- [ ] Push `feat/settings-redesign`, open PR into `dev` titled `feat(settings): routed console with sections, compact rows and a reviewable apply`, body from the ledger; wait for CI; merge; continue on the same branch (rebase onto `dev`).

---

## Phase 2 — master–detail editors (PR 2)

### Task 11: Tool servers master–detail

**Files:** Modify `configuration/ServerMapEditor.tsx`; use `SecretField`.

**Layout:** `<div data-testid="server-map-editor" class="grid md:grid-cols-[260px_1fr]">`. Left `<ul role="listbox" aria-label="Tool servers">` with one `<li role="option" data-server={key} aria-selected>` per server: key (mono), transport, enabled dot, "changed" dot when the staged entry differs from the current one, last probe verdict (`ok`/`failed`). "Add server" form below the list (same `mapKeyError` rules, same `EMPTY_SERVER`). Right: detail for the selected server (`data-server-detail={key}`): header (key, label input, enabled switch, Test, Remove or Disable for built-ins); sections `Connection` (transport select; stdio → command, args textarea, cwd, env map field, env_allow; http* → URL and `SecretField` for the token with `labels.replace="Replace token"` and the same `data-token-state` values), `Tools` (tool_selection select disabled while `use_all_tools`, the force-all checkbox, then the tick list `Tools the model may call (N of M)` when a manifest exists, else the note "Run Test to load the tool list" with an inline Test button; editing a probe input drops the manifest and the note says "Connection changed; run Test again"), `Agents` (four role checkboxes). Selection is local state defaulting to the first server; a newly added server becomes selected. Every staged value semantics stays identical (whole map staged; first tick converts `tools: null` into a list).

- [ ] Implement; `tsc`, `lint`; walk in dev server; Commit — `feat(settings-web): tool servers as a master–detail editor`.

### Task 12: Agents master–detail

**Files:** Modify `configuration/AgentDefinitionsEditor.tsx`.

**Layout:** same grid; left list `aria-label="Agents"` items `data-agent={key}` with role badge, "built in", enabled dot, changed dot, resolve verdict; "Add agent" below. Right detail (`data-agent-detail={key}`): header (key, label, enabled, Resolve, Clone unless judge, Remove or Disable); sections `Identity` (role select for custom agents only, static provider select for static/generic), `Prompt` (textarea; built-in: read-only with the resolved prompt after Resolve or the same placeholder), `Model override` (provider/model/temperature with the same `putLlm` rules and messages), `Tools` as a tree (`<ul>` with a top item "its static provider's tools" for generic agents, then one `<li>` per server with the "(all allowed tools)" checkbox and a "List tools" button; listed tools render as a nested `<ul>` indented under the server). Resolve status line as today; resolve inputs clear the result; validation errors land on the detail of the offending key and the list item gets an error dot.

- [ ] Implement; `tsc`, `lint`; Commit — `feat(settings-web): agents as a master–detail editor with a tool tree`.

### Task 13: Profiles and REST refinements

**Files:** Modify `configuration/ProfilesEditor.tsx`, `configuration/RestSandboxEditor.tsx`.

- Profiles: numbered rows (`<ol>` with visible numbers), move buttons with `aria-label="Move up"`/`"Move down"` and arrow glyphs (↑ ↓) at normal button size, "Set active" in the header as a toggle button `aria-pressed`, everything else unchanged.
- REST: mapping table gets `thead` sticky; the paste-and-preview block moves into `<details><summary>Test with a sample response</summary>` opened automatically when a preview result exists.
- [ ] Implement; `tsc`, `lint`; Commit — `feat(settings-web): profile ordering controls and a folded REST preview`.

### Task 14: Update `settings-servers.spec.ts` and `settings-agents.spec.ts`

Keep every assertion (inventory §7 Servers/Agents). Navigation: `page.goto("/settings/configuration/tools/mcp")` and `/settings/configuration/agents/agents`, `/agents/profiles`; select an item via `page.locator('[data-server="r2"]').click()` before interacting with its detail; "Apply" → "Review" → "Confirm and apply". Add: selecting another server keeps the first one's staged edits; the tools section shows "Run Test to load the tool list" before a probe; the agent tool tree nests listed tools under their server.

- [ ] Rewrite; run each spec by name (dev server stopped); Commit — `test(e2e): server and agent editors as master–detail`.

### Task 15: Phase 2 close — build, PR into dev (same steps as Task 10; title `feat(settings): master–detail tool server and agent editors`).

---

## Phase 3 — setup hub and guides (PR 3)

### Task 16: Guide framework — `guides.ts`, status, hub, guide page

**Files:**
- Create: `setup/guides.ts`, `setup/status.ts`, `setup/page.tsx`, `setup/[guide]/page.tsx`, `setup/GuidePage.tsx`, `setup/layout.tsx` (wraps in `SettingsProvider` so guides share staged state with the console; the console layout must not double-wrap — move `SettingsProvider` up to `settings/layout.tsx` for admins), `__tests__/status.test.ts`
- Modify: `configuration/page.tsx` (landing rule), `configuration/GroupHeader.tsx` (renders `guideHref` as "Set up with the guide")

**Interfaces (produces):**
```ts
export type GuideId = "llm" | "static" | "sandbox" | "tool-server" | "agent" | "memory" | "enrichment";
export interface GuideContext { effective: (key: string) => unknown; staged: Record<string, unknown>; probeOk: (probeId: string) => boolean; schema: SettingsSchema; state: Record<string, unknown> } // state = per-guide scratch (selected server key, clone source), kept in the guide page
export interface GuideStep { id: string; title: string; intro?: string; keys?: string[]; respectAppliesWhen?: boolean; probe?: string; component?: "server-form" | "agent-form" | "profile-picker" | "rest-mapping" | "provider-choice" | "review"; canContinue?: (ctx: GuideContext) => string | null }
export interface GuideDef { id: GuideId; title: string; blurb: string; groupHref: string; steps: (ctx: GuideContext) => GuideStep[] } // steps may depend on choices (provider)
export const GUIDES: GuideDef[];
// status.ts
export function guideStatus(id: GuideId, effective: (key: string) => unknown): string; // per spec hub table
export function llmLooksConfigured(effective: (key: string) => unknown): boolean; // hosted provider with a key set, or ollama with a base_url
```
`GuidePage`: reads `?step=`, renders `<ol aria-label="Steps">` indicator, the step (keys → `FieldRow variant="guide"` for visible entries; `probe` → the probe button + result, cleared when inputs change; `component` → the step component), Back/Continue (`Continue` disabled with the `canContinue` reason shown next to it), "Open in the full settings" link (`groupHref`), and on the `review` step the same list `ChangesBar` renders (extract the list into `configuration/ReviewList.tsx` and reuse) with "Apply" → `apply()` → success message with a link to the console group and "Run another guide" (hub). The hub lists `GUIDES` with `guideStatus`. `configuration/page.tsx`: redirect to `/settings/setup` when `!llmLooksConfigured(effective)`, else `firstGroupPath`.

- [ ] **Step 1: Failing unit test** for `guideStatus` and `llmLooksConfigured` (ollama without base_url → not configured; openai with key `is_set` → configured; static `none` → "none"; sandbox `mock` → "mock (built-in fixtures)"; tool-server count of enabled; agent count of enabled custom + active profile; memory backend + url; enrichment on/off + keys).
- [ ] **Step 2:** implement `status.ts`; test passes.
- [ ] **Step 3:** implement the framework, hub, guide page with an empty `GUIDES` list plus the `llm` guide only (provider-choice step: radio cards with the provider titles and one line each; credentials step keys per provider: openai → `core.llm.openai.api_key`, `core.llm.openai.base_url`, advanced `disable_thinking`, `repetition_penalty`; anthropic → `api_key`; gemini → `api_key`; ollama → `base_url`, advanced `num_ctx`, `keep_alive`; probe step `llm` with `canContinue` "run the connection test first" until `probeOk("llm")`; models step keys `core.llm.<provider>.expert_model`, `.judge_model` with the datalist; limits step keys `core.llm.expert_max_tokens`, `core.llm.judge_max_tokens`, `core.llm.parallel_analysts`, `core.llm.view_decomposition_mode`, `core.llm.view_decomposition_views`; review).
- [ ] **Step 4:** `tsc`, `lint`, `test:unit`; walk `/settings/setup` and the LLM guide in the dev server. Commit — `feat(settings-web): setup hub, guide framework and the language-model guide`.

### Task 17: Step components extracted from the editors

**Files:** Create `setup/steps/ServerFormStep.tsx`, `AgentFormStep.tsx`, `ProfilePickerStep.tsx`, `RestMappingStep.tsx`; refactor `ServerMapEditor.tsx` and `AgentDefinitionsEditor.tsx` so their detail panes are exported components (`ServerDetail`, `AgentDetail`) that both the editors and the steps render.

- `ServerFormStep`: props `{ serverKey: string; section: "connection" | "tools" | "agents" }` — renders that section of `ServerDetail` for the server in `state.serverKey`; the guide's first step ("Which server") has a name box (same key rules) or a picker of existing servers.
- `AgentFormStep`: props `{ agentKey: string; section: "identity" | "prompt" | "tools" | "model" | "resolve" }`.
- `ProfilePickerStep`: radio list of profiles + "Create a new profile from <active>" with a name box; checkbox "Make it the active profile"; stages `core.agents.profiles` (append the new agent) and optionally `core.agents.profile`.
- `RestMappingStep`: the mapping table + preview from `RestSandboxEditor` (export `RestMappingTable`).
- [ ] Implement; `tsc`, `lint`; re-run `settings-servers.spec.ts` and `settings-agents.spec.ts` by name to prove the editors still pass. Commit — `refactor(settings-web): editor detail panes shared with the guides`.

### Task 18: The remaining six guides

**Files:** Modify `setup/guides.ts`.

- `static`: provider-choice (`core.static.provider`, one line per choice: none / Ghidra MCP / radare2 MCP / capa + YARA / generic MCP server) → fields step with `keys` = the visible entries of the `static` group for that provider (use `respectAppliesWhen`; `generic_mcp` step shows a link to the tool-server guide when `core.mcp.servers` has no enabled non-built-in server) → probe step (`ghidra` / `r2` / `capa_yara`; none for `none`/`generic_mcp`) → review.
- `sandbox`: provider-choice (`mock` / `cape2` / `upload` / `triage` / `rest`) → fields (cape2: api_token, base_url, poll, timeout, then advanced MCP block; triage: token, base_url, profile, fetch_pcap, poll, timeout; upload: allowed_formats, max_report_bytes; rest: four steps Connection (`base_url`, `auth.*`, `verify_tls`, timeouts), Submit (`submit.*`), Status (`status.*`), Report (`report.*`) and, when `report.format === "generic"`, `rest-mapping`) → probe (`cape2` / `triage` / `rest`) → review.
- `tool-server`: "Which server" (new name or existing) → `server-form connection` → `server-form tools` (canContinue "run Test to load the tools, or keep all tools" — allowed to continue without a manifest) → `server-form agents` → review.
- `agent`: "Start from" (radio: clone a built-in static/dynamic/network, or blank generic) + name → `agent-form identity` → `agent-form prompt` → `agent-form tools` → `agent-form model` → `agent-form resolve` (canContinue "run Resolve first") → `profile-picker` → review.
- `memory`: `core.memory.backend` → keys `qdrant_url`, `qdrant_api_key`, `qdrant_collection`, `qdrant_function_hash_collection`, `top_k` (skipped when backend is `memory`) → probe `qdrant` → review.
- `enrichment`: `api.enrichment_enabled`, `api.enrichment_max_lookups` → `api.virustotal_api_key` with probe `virustotal` → `api.abuseipdb_api_key` with probe `abuseipdb` → review.
- [ ] Implement; `tsc`, `lint`; walk each guide in the dev server. Commit — `feat(settings-web): static, sandbox, tool-server, agent, memory and enrichment guides`.

### Task 19: `settings-setup.spec.ts`

Create `apps/web/e2e/settings-setup.spec.ts` (admin user via `test.use`). Mock schema must include the keys each guide touches (extend `mocks.ts` with a `MOCK_SETTINGS_SCHEMA_FULL` covering llm/providers/static/sandbox/mcp/agents/memory/enrichment groups). Tests: hub shows seven cards with statuses; LLM guide: choose ollama → base_url → Continue blocked until the probe → probe mocked ok with models → pick models → review lists three lines → Apply sends one PATCH whose body has exactly the staged keys; static guide with `r2` sends `core.static.provider` and `core.static.r2.binary_path`; tool-server guide creates a server and the PATCH body's `core.mcp.servers` has the new key; agent guide clones `static` into `static_r2`, adds it to a new profile `full` and activates it (body has `core.agents.definitions`, `core.agents.profiles`, `core.agents.profile`); leaving a guide mid-way and opening the console shows the staged count in the rail; `/settings/configuration` lands on the hub when the LLM is unconfigured and on the first group otherwise.

- [ ] Write; run by name; Commit — `test(e2e): setup guides`.

### Task 20: Phase 3 close — build, PR into dev (title `feat(settings): setup hub and guides`).

---

## Phase 4 — walkthrough, polish, ledger, promotion (PR 4)

### Task 21: Live walkthrough and polish

- With the API and web dev server running (no LLM job), use Chrome DevTools MCP to open every section page, both master–detail editors, the search page, the changes bar review with one change of each kind, and every guide to its review step; screenshot each to `other/audit/2026-09-08-settings-redesign/`. Fix anything that reads wrong (copy, spacing, focus order, keyboard reachability of the rail select, dark/light contrast), keeping the e2e specs green (re-run the affected spec by name after each fix).
- Verify the no-loss checklist: open `other/audit/2026-09-07-live-e2e/settings-inventory.md` and tick every item by finding it in the new UI; record the tick list in the ledger.
- [ ] Commit — `fix(settings-web): walkthrough polish`.

### Task 22: Close-out

- [ ] PR 4 into `dev`; CI; merge. Then open the promotion PR `dev → main` (requested in advance), wait for CI, merge, delete the feature branch locally and remotely; only `main` and `dev` remain.
- [ ] Update `other/audit/2026-09-08-settings-redesign/progress.md` (ledger) and the memory notes; restore `apps/web/.env.local` `NEXT_PUBLIC_AUTH_DISABLED=true`; stop the dev server, API and worker.
