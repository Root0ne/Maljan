# Provider layer design — Maljan sub-project A

Status: approved by the user on 2026-09-03 (plan mode); implemented on branch `feat/provider-layer`,
PR into `dev`. Companion plan: `docs/plans/2026-09-03-provider-layer.md`.

## 1. Problem

Maljan is bound to Ghidra for static analysis and to CAPEv2 for dynamic analysis:

- `MCPConfig` declares exactly two servers, `ghidra` and `cape` (`src/maljan/core/config.py:735-741`);
  `SandboxConfig.backend` is `Literal["mock", "cape2"]` with flat `cape2_*` fields (`:394-419`).
- The static analyst's system prompt hard-codes a twenty-tool Ghidra workflow and the allow-list
  `_GHIDRA_ALLOWED_TOOLS` (`src/maljan/agents/static_analyst.py:21-173`); the dynamic analyst's prompt
  hard-codes CAPE MCP tool names (`dynamic_analyst.py:17-38,117-130`).
- There is no neutral sandbox report: `SubmissionResult.report` is the raw CAPEv2 JSON and nine
  consumers read CAPE keys directly (`extractors/dynamic_extractor.py`, `extractors/network_extractor.py`,
  `parsers/dynamic_parser.py`, `parsers/network_parser.py`, `extractors/persistence_extractor.py`,
  `extractors/attribution.py`, `analysis/sigma_layer.py`, `analysis/lolbin_layer.py`, `src/maljan/app.py:126`).
- Function-hash attribution (`pipeline/nodes.py:1516-1560`) and the worker's sample mirror
  (`apps/api/app/worker/analysis_worker.py:496-554`) are gated on `mcp.ghidra.transport == "http"`.

The user wants any static tool and any sandbox to be attachable, chosen and configured from the web
UI, on the way to a fully composable multi-agent framework.

## 2. Decisions taken with the user

1. Both models: core contracts (`StaticProvider`, `SandboxProvider`) with built-in adapters, plus a
   generic adapter so a user's own tool attaches as an MCP server (sub-project A) or a REST contract
   (sub-project B).
2. Full agent composition arrives in sub-project C (agent definitions from the UI, graph built from
   definitions).
3. The default profile reproduces today's architecture exactly: three analysts, judge, Ghidra and CAPE,
   the same prompts and allow-lists. `tests/evaluation/*` artefacts and `make facts` stay byte-identical;
   `tests/evaluation/test_suite_count.json` is not re-measured.
4. First-cut adapters: static Ghidra (existing), radare2 (`radareorg/radare2-mcp`, stdio), capa + YARA
   (no tool server); sandbox CAPEv2 (existing), mock (existing), report upload, Hatching Triage.
5. Delivery: three sub-projects, three PRs into `dev`, each with its own spec, plan and review loop.

## 3. Invariant

With `static.provider=ghidra` and `sandbox.provider` in `{cape2, mock}` no prompt byte, tool
allow-list, sandbox report dict or extractor output changes. Golden tests captured from `dev` before
the refactor enforce this on every task.

## 4. Package and contracts

```
src/maljan/providers/{__init__,base,registry,errors,cape_view}.py
src/maljan/providers/static/{ghidra,r2,capa_yara,generic_mcp,null}.py
src/maljan/providers/sandbox/{cape2,mock,upload,triage,formats,_legacy}.py
src/maljan/schemas/sandbox_report.py
```

The registry copies `src/maljan/llm/registry.py`: `@register_static_provider("ghidra")`,
`@register_sandbox_provider("cape2")`, `static_provider_ids()`, `sandbox_provider_ids()`. Those id
functions are the single vocabulary; the settings `Literal` choices must equal them (a test enforces it).

### 4.1 Capabilities

```python
@dataclass(frozen=True)
class StaticCapabilities:
    provides_tools: bool = False
    provides_evidence: bool = False
    provides_function_hashes: bool = False
    needs_sample_mirror: bool = False
    supports_tool_curation: bool = False
    degrade_on_failure: bool = False

@dataclass(frozen=True)
class SandboxCapabilities:
    can_submit: bool = False
    can_poll: bool = False
    can_fetch_report: bool = True
    can_fetch_pcap: bool = False
    accepts_uploaded_report: bool = False
    provides_tools: bool = False
    report_format: Literal["cape2", "cuckoo", "triage", "mock", "generic"] = "generic"
    degrade_on_failure: bool = True
```

| Provider | Flags |
| :-- | :-- |
| ghidra | tools, function_hashes (computed per instance: http transport only), mirror, curation; degrade off |
| r2 | tools, mirror, curation (fixed subset); degrade on |
| capa_yara | evidence only; degrade on |
| generic_mcp | tools, curation (allow-list from settings); degrade on |
| none | nothing; reproduces today's `mcp.ghidra.enabled=false` branch |
| cape2 | submit, poll, report, pcap, tools; format cape2 |
| mock | submit, poll, report; format mock |
| upload | report, accepts_uploaded_report; format sniffed |
| triage | submit, poll, report, pcap; format triage |

### 4.2 Lifecycle and methods

Both sides: `from_settings(cfg) -> provider`, `capabilities`, `async probe() -> ProviderProbe`,
`open(job)`, work, `close()`.

`StaticProvider`: `get_tools() -> list[BaseTool]`, `select_tools(tools, categories) -> list[BaseTool]`,
`prompt_fragment() -> str`, `collect_evidence(sample_path) -> StaticEvidenceBundle | None`,
`function_hashes(job) -> list[tuple[str, str]]`, `mirror_spec() -> MirrorSpec | None`.

`StaticJobContext`: `host_sample_path`, `mirror_sample_path` (today's `state["static_sample_path"]`),
`sha256`, `file_type`, `platform`, `capability_categories`, `output_guardrail`, `max_output_chars`.

`StaticEvidenceBundle`: `api_capabilities: dict[str, int]`, `technique_hits: list[dict]`,
`strings: list[dict]`, `technical_evidence: dict[str, str]` (capped by `schemas/tool_evidence.py`).

`SandboxProvider`: `submit(sample_path, job) -> task_id`, `wait_for_completion(task_id, timeout_seconds,
poll_interval_seconds) -> status`, `fetch(task_id) -> SandboxRun`, `fetch_pcap(task_id, dest_dir) -> str | None`,
`attach_report(blob, *, filename) -> SandboxRun`, `dynamic_tools() -> list[BaseTool]`,
`dynamic_prompt_fragment() -> str`.

`SandboxRun`: `task_id, sample_sha256, sample_name, status, report: SandboxReport, raw: dict, error`.

`SubmissionResult` (`src/maljan/loaders/sandbox_client.py`) stays and gains
`normalized: SandboxReport | None = None`. `providers/sandbox/_legacy.py::as_sandbox_client(provider)`
wraps a provider in the old `SandboxClient` protocol; `container.get_sandbox_client()` returns that in A,
so `src/maljan/app.py:136-190` and existing tests are untouched.

Decision: the generic MCP static provider ships in A (it re-parametrises `agents/mcp_client.py` and
`agents/ghidra_http_client.py`; the r2 provider is this class with defaults). The generic REST sandbox
ships in B (no code to reuse; its endpoint and JSONPath mapping needs B's structured editor). A's
"any sandbox" story is the upload provider.

## 5. Normalised sandbox report

`SandboxReport` (`src/maljan/schemas/sandbox_report.py`): `provider`, `source_format`, `task_id`,
`target {sha256, md5, name, file_type, mime_type, size}`, `processes` (pid, ppid, name, command_line,
first_seen, calls), `apistats` (pid -> api -> count, CAPE shape kept), `generic_events`, `signatures`
(name, description, severity, marks, ttp_tags), `network {dns, http, tcp, udp, hosts, domains, tls,
pcap_local_path}`, `dropped_files`, `registry`, `screenshots`, `cti`, `unavailable: list[str]`, `raw`.

Decision, raw first with identity for CAPE: `SandboxReport` is the provider output contract;
`providers/cape_view.py::to_cape_shaped_dict(report) -> dict` renders it into the dict today's
consumers read. When `source_format in {"cape2", "mock"}` and `raw` is non-empty the function returns
`report.raw` itself (`rendered is raw`). Non-CAPE providers get a real render. No consumer moves in A;
they move in B/C, each behind its own golden test.

Golden test `tests/providers/test_cape_normalization_golden.py`, over every CAPE-shaped JSON under
`data/samples/*/sample_1.json` and `tests/fixtures/**`: (a) identity of the rendered object; (b)
`build_dynamic_behavior` and `build_network_iocs` equal on rendered and raw; (c) with `raw={}` the render
reproduces every key the consumers read (the table in §1 of the plan lists them).

## 6. Settings shape

```
static.provider: Literal["ghidra","r2","capa_yara","generic_mcp","none"] = "ghidra"
static.ghidra.*     (StaticGhidraConfig, an MCPServerConfig; moved from mcp.ghidra)
static.r2.*         (MCPServerConfig + binary_path, mirror_dir)
static.capa.*       (rules_dir="data/capa-rules", signatures_dir, timeout_seconds, backend)
static.yara.*       (rules_dir, timeout_seconds)
static.generic.*    (MCPServerConfig; becomes mcp.servers["<name>"] in B)
sandbox.provider: Literal["mock","cape2","upload","triage"] = "mock"
sandbox.cape2.*     (base_url, api_token, timeout_seconds, poll_interval_seconds, mcp: MCPServerConfig)
sandbox.triage.*    (base_url="https://tria.ge/api/v0", api_token, profile, timeout_seconds=900,
                     poll_interval_seconds=15, fetch_pcap=True)
sandbox.upload.*    (max_report_bytes=64 MiB, allowed_formats=["cape2","cuckoo","triage"])
```

Legacy keys keep working through a `model_validator(mode="before")` on `Settings` that applies a static
alias table (`mcp.ghidra -> static.ghidra`, `mcp.cape -> sandbox.cape2.mcp`, `sandbox.backend ->
sandbox.provider`, `sandbox.cape2_* -> sandbox.cape2.*`), applied only when the new key is absent, with
one warning per process. Task A2 opens with a test that proves the validator sees the env-derived
nested dict; the fallback is a `settings_customise_sources` pre-pass with the same table.

Stored UI overrides are renamed by an idempotent alembic data migration. `_env_literal` export derives
names from the catalog path and therefore emits the new names. Every new leaf gets an entry in
`settings_annotations.py`; `GROUP_ORDER` gains `static` and renames `sandbox` to "Sandbox provider".

Probes: `ghidra` (inputs re-pointed), `triage`, `r2` (stdio initialize, 5 s), `capa` (rules dir,
import, rule count); `cape` stays one release as an alias of `cape2`.

Per-job: `_KnownJobConfig` gains `static_provider`, `sandbox_provider`, `sandbox_report_id`;
`build_job_settings` folds the first two into `static.provider` and `sandbox.provider`, the third
forces `sandbox.provider=upload`.

## 7. Agent decoupling

- The static system prompt splits into a provider-independent head and tail with a provider-supplied
  middle; `GhidraStaticProvider.prompt_fragment()` returns today's text as a moved constant. The
  assembled prompt equals a snapshot captured from `dev` (`tests/agents/test_prompt_byte_identity.py`,
  `tests/fixtures/prompts/`). The dynamic analyst gets the same treatment with the CAPE fragment.
- `_GHIDRA_ALLOWED_TOOLS` and `agents/ghidra_tool_selector.py` move unchanged into
  `providers/static/ghidra.py`; `static_analyst.py` keeps deprecated re-exports until task A23.
- `_initialize_mcp_client` becomes: resolve provider; return if not `provides_tools`; `open(job)`;
  `get_tools`; `select_tools`. The http/stdio branch, `GhidraHTTPClient`, `child_env`,
  `resolve_mcp_args`, the output guardrail and `_run_async` move verbatim into `GhidraStaticProvider.open()`.
- `degrade_on_failure` is read in exactly one place, the analyst's exception handler; Ghidra keeps
  "fail loudly", every sandbox keeps "degrade".
- Evidence-only providers run from the static preparation node next to `build_static_analysis`:
  `api_capabilities` counters are summed, `api_technique_hits` extended, free text goes to
  `technical_evidence["capa"]` and `["yara"]`.
- The sample mirror runs only when `needs_sample_mirror`; `provider.mirror_spec()` supplies
  `MirrorSpec(work_subdir, container_prefix)`; `state["static_sample_path"]` keeps its name and meaning.
- Function-hash attribution keys on `capabilities.provides_function_hashes` and calls
  `provider.function_hashes(job)`.

## 8. Upload provider

`POST /api/v1/samples/{sample_id}/sandbox-reports` (multipart `file`, `.json` or `.json.gz`) returns
`{id, format, task_id, size_bytes, sample_sha256_match}`; `GET .../sandbox-reports`;
`DELETE .../sandbox-reports/{report_id}`. Storage is MinIO under
`sandbox-reports/{sha[:2]}/{sha}/{report_id}.json`. Validation: streamed size cap, JSON parse,
inflated-size cap for gzip, sniffed format in `allowed_formats`; a `target.sha256` mismatch is a warning
carried into `run_summary` and the job page. `providers/sandbox/formats.py::sniff_format` orders Triage,
CAPE2, Cuckoo, most specific first, and the provider re-sniffs on load. Table `sandbox_reports(id,
sample_id, storage_path, format, task_id, size_bytes, sha256_of_blob, uploaded_by, created_at)` with an
alembic migration. When `sandbox_report_id` is set the worker forces `sandbox.provider=upload` and
`MaljanApp` takes the `attach_report` path instead of submit-and-wait.

## 9. Triage adapter

Endpoints from the public documentation, verified by task A16 before implementation:
`POST /samples` (multipart with `_json`), `GET /samples/{id}` (status `reported` is terminal),
`GET /samples/{id}/overview.json`, `GET /samples/{id}/{task}/report_triage.json`,
`GET /samples/{id}/{task}/dump.pcap`. Bearer auth, 15 s poll with 1.5x backoff capped at 60 s,
`Retry-After` honoured, 900 s timeout. `unavailable = ["apistats", "calls", "registry",
"generic_events"]`; injection detection and sigma process rules stay empty and the report says so
(`DynamicBehavior.unavailable`, rendered by HTML, Markdown and the dynamic page).

## 10. r2 and capa + YARA

r2: `radareorg/radare2-mcp` over stdio; tool names enumerated with `tools/list` and pinned in a fixture
at the start of task A18; `R2StaticProvider` is `GenericMCPStaticProvider` with defaults; the sample
reaches r2 by path (`needs_sample_mirror`, `static.r2.mirror_dir`, `sample_files.work_dir()` when
co-located).

capa + YARA: `flare-capa` plus the existing `analysis/yara_layer.py`; optional imports guarded like
`SandboxNotAvailableError`; a missing library lowers `provides_evidence` to False with a warning. capa
namespaces feed `api_capabilities`, matches with ATT&CK ids feed `api_technique_hits`, tables and YARA
hits feed `technical_evidence`.

## 11. Web UI

`CatalogEntry` gains `applies_when: dict[str, list[str]] | None` and `order: int`, fed from
`settings_annotations.py` and mirrored in `apps/web/src/types/settings.ts`. `ConfigurationTab.tsx`
filters by staged-or-current values; hidden dirty fields stay in `pending` and `ApplyBar` counts them.
Provider selectors are `EnumWidget`s with `order=-1`. `GroupHeader.tsx` shows the probes of the visible
entries. The job submit dialog gains optional static and sandbox provider selects and an "Attach
sandbox report" input; omitted keys mean "inherit from settings". e2e cases: provider switch reveals
Triage fields and hides CAPE fields; submit with an uploaded report.

## 12. Test and paper safety

Gates: prompt byte identity (static ghidra, dynamic cape2); allow-list identity (20 Ghidra names, 13 CAPE
essentials); CAPE normalisation golden test; legacy env aliases; the existing catalog test; default
profile smoke test. Ghidra-specific test modules move under `tests/providers/static/` and
`test_dynamic_degrades_without_cape.py` under `tests/providers/sandbox/` in the last task, import paths
only. `tests/evaluation/**` is not modified (CI grep gate); `make facts` stays byte-identical; the pinned
test count is not re-measured.

## 13. Interfaces frozen for B and C

- Provider ids from the registry are the vocabulary B turns into dynamic enum choices and C references
  from profiles.
- `mcp.servers: dict[str, MCPServerConfig]` (a dict: the catalog renders `dict[str, BaseModel]` as
  `json`, and misrenders `list[BaseModel]`); `MCPServerConfig` gains `tools: list[str]` and
  `description` in B.
- `AgentDefinition = {name, role, prompt, llm{provider, model, temperature}, tools: [ToolRef],
  providers{static?, sandbox?}, enabled}`, `ToolRef = {kind: mcp | builtin | provider, server?, name}`;
  per-agent LLM keys stay under `llm.agents.<name>.*`.
- `profile: str = "default"` and `profiles: dict[str, ProfileDefinition]`; the default profile is the
  frozen reproduction of today's architecture and the golden tests are its conformance suite.
- `SandboxReport` and `StaticEvidenceBundle` do not change shape after A.

## 14. Verification before merge

1. `make lint format-check typecheck`; `uv run pytest tests/ -q`.
2. `make facts && git status --short tests/evaluation/` empty; `git diff dev -- tests/evaluation/` empty.
3. Golden gates green; `grep -rn "mcp\.ghidra\|mcp\.cape" src apps/api` shows only the alias table and
   the Ghidra and CAPE providers.
4. `apps/web`: `tsc --noEmit`, `npm run lint`, `npm run build`; Playwright `settings-configuration.spec.ts`
   on chromium and firefox.
5. Live run (mock sandbox, local llama, CPU cap first): default profile completes a job with today's
   `.env`; `sandbox.provider=upload` completes a job from an uploaded CAPE JSON; `static.provider=capa_yara`
   fills the static section with capa hits while Ghidra is off; switching the sandbox selector to Triage
   swaps the visible fields and its probe fails legibly without a key; `static.provider=r2` runs end to
   end when r2mcp is installed and its probe fails legibly otherwise.
6. PR into `dev`, CI green including Semgrep; merge left to the user.

## 15. Amendments from plan writing (2026-09-04)

Source facts found while writing `docs/plans/2026-09-03-provider-layer.md`; the plan is authoritative
where it differs from the sections above.

- The CAPE golden corpus is `data/cape_reports/*.json` (97 reports) plus `data/samples/dynamic/sample_1.json`;
  `tests/fixtures/` did not exist and is created by Task 1.
- The static system prompt names Ghidra at `static_analyst.py:23`, before four provider-neutral
  sentences, so the byte-identical seam sits after line 22 and those sentences travel inside each
  provider's fragment. Sub-project C removes that duplication.
- `static.provider=none` is a new, tool-free choice. Today's `mcp.ghidra.enabled=false` behaviour
  (full Ghidra prompt, no tools) is reproduced by the alias table as `static.provider=ghidra` with
  `static.ghidra.enabled=false`.
- `MCPServerConfig.tools` never existed; the dynamic analyst's `getattr(cfg.mcp.cape, "tools", [])`
  branch was dead and is dropped in Task 11. The field arrives in sub-project B.
- `Settings.mcp` survives Tasks 2–11 as a two-way mirror of `static.ghidra` and `sandbox.cape2.mcp`
  and is deleted in Task 12, whose grep gate enforces §14 item 3.
- `DynamicBehavior.unavailable` adds one key to every extractor golden; Task 17 regenerates them in
  the same commit and reviews the diff so every changed line is exactly the new empty list.
