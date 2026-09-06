# Tool servers design — Maljan sub-project B

Status: implemented on branch feat/tool-servers; PR into dev pending final review. Plan `docs/plans/2026-09-04-tool-servers.md` (22 tasks). Builds on sub-project A (`docs/specs/2026-09-03-provider-layer-design.md`,
PR #5 into `dev`). Companion plan: `docs/plans/2026-09-04-tool-servers.md`.

## 1. Problem

After sub-project A an operator can pick a static provider and a sandbox provider, and can point the
`generic_mcp` static provider at one custom MCP server. Three gaps remain between that and "connect
any tool":

- Only one custom MCP server can exist (`static.generic`), it exposes the server's whole tool
  manifest to the model (`MCPServerConfig` has no allow-list, `src/maljan/core/config.py:680-707`),
  and it can serve only the static analyst.
- The two sidecars every run depends on, `network-mcp` and `threatintel-mcp`, are started from
  constants inside the agents (`src/maljan/agents/network_analyst.py:73-111`,
  `src/maljan/agents/judge_agent.py:131-158`): no settings, no probe, no allow-list, no way to
  replace or add to them.
- A sandbox that is neither CAPE nor Triage can only be used through report upload. There is no way
  to describe a sandbox's HTTP API and have Maljan drive it.
- The settings UI edits any nested object as a raw JSON textarea (`JsonWidget`,
  `apps/web/src/app/(app)/settings/configuration/widgets.tsx:260`), enum choices are frozen at catalog
  build time, and the samples page carries its own hard-coded provider lists
  (`apps/web/src/app/(app)/samples/page.tsx:10`).

## 2. Decisions

| Decision | Choice | Reason |
| :-- | :-- | :-- |
| Where servers live | `mcp.servers: dict[str, MCPServerConfig]`, keyed by a slug | One registry for built-ins and custom servers; the catalog already renders `dict[str, BaseModel]` as one `json` leaf, which the new editor replaces |
| Which agent uses a server | `agents: list[AgentRole]` on each server entry, applied in B | The operator's question ("xyz's MCP for static analysis") is answered from the UI in B; sub-project C reads this list as the default `tools` of its agent definitions and generalises it without replacing it |
| Tool exposure | `tools: list[str] | None`: `None` = every tool (built-ins only), `[]` = nothing, names = allow-list | A custom server exposes nothing until the operator ticks tools from the probe's manifest; today's built-in behaviour is preserved with `None` |
| Custom sandbox | `sandbox.provider=rest` driven by `sandbox.rest.*`, response fields selected with RFC 9535 JSONPath | JSONPath is the standardised selector language (RFC 9535, 2024); `jsonpath-rfc9535` 1.0.0 is a pure, dependency-free implementation |
| Mapping preview | Server-side endpoint, no JSONPath in the browser | One implementation, one set of error messages |
| Sidecar migration | `network-mcp` and `threatintel-mcp` become built-in entries with today's command, cwd and env filter | Their tool sets stay identical (pinned by a fixture from a live handshake); they gain a probe and an allow-list for free |
| Failure policy | Custom and built-in servers degrade; Ghidra's loud failure is untouched | Same rule as A: only the evaluated static provider may fail a job |

## 3. Settings shape

### 3.1 `MCPServerConfig` (extended)

```python
AgentRole = Literal["static", "dynamic", "network", "judge"]

class MCPServerConfig(BaseModel):
    enabled: bool = False
    transport: Literal["stdio", "http", "streamable-http", "sse"] = "stdio"
    command: str = ""
    args: list[str] = []
    env: dict[str, str] = {}
    cwd: str = ""                       # new; empty = repo root
    env_allow: list[str] = []           # new; names passed through child_env(allow=...)
    url: str = ""
    auth_token: SecretStr = SecretStr("")   # was str; existing values migrate unchanged
    tool_selection: Literal["curated", "dynamic", "all"] = "dynamic"
    use_all_tools: bool = False
    tools: list[str] | None = None      # new; allow-list, see §2
    agents: list[AgentRole] = []        # new; who receives this server's tools
    label: str = ""                     # new; display name, defaults to the key
```

`auth_token` becomes `SecretStr` so it renders through the secret widget and is redacted in
snapshots; A's `static.ghidra.auth_token`, `sandbox.cape2.mcp.auth_token` and `static.generic`
follow the same change (their values are already redacted by the annotations' `secret` flag; the type
change closes the gap in `settings_snapshot`). Tokens entered for `mcp.servers.<key>` in the UI are stored as one encrypted secret row per server (`core.mcp.servers.<key>.auth_token`), never inside the JSON map row; without `SETTINGS_ENCRYPTION_KEY` the UI refuses them the way it refuses every other secret. `tool_selection` and `use_all_tools` stay because the
Ghidra provider reads them; the new editor shows them only for `static.ghidra`.

### 3.2 `MCPConfig`

```python
class MCPConfig(BaseModel):
    servers: dict[str, MCPServerConfig] = Field(default_factory=_builtin_servers)
```

`_builtin_servers()` returns two entries, byte-for-byte today's launch parameters:

| Key | command | args | cwd | env_allow | agents | tools |
| :-- | :-- | :-- | :-- | :-- | :-- | :-- |
| `network` | `sys.executable` (resolved at load) | `["network-mcp/server.py"]` | `network-mcp` | `[]` | `["network"]` | `None` |
| `threatintel` | `sys.executable` | `["threatintel-mcp/server.py"]` | `threatintel-mcp` | `["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"]` | `["judge"]` | `None` |

Both are `enabled=True`. Deleting a built-in from the UI sets `enabled=False` instead of removing the
key (the entry is re-seeded on load); a removed custom key is removed. Keys are slugs
(`^[a-z][a-z0-9_-]{0,31}$`); `network`, `threatintel`, `ghidra`, `cape` are reserved for built-ins
and provider-owned servers. The read-only `ghidra` / `cape` compatibility views from A stay.

### 3.3 `static.generic` becomes a reference

```python
class StaticGenericConfig(BaseModel):
    server: str = ""    # key in mcp.servers; empty = provider unusable, probe says so
```

A's `static.generic.*` leaves are migrated: if any of them holds a non-default override, the override
set is copied into `mcp.servers.custom.*` with `agents=["static"]`, `static.generic.server` is set to
`custom`, and the old keys are deleted (alembic data migration, same shape as A's key rename). The
env aliases `STATIC__GENERIC__COMMAND`, `STATIC__GENERIC__URL`, `STATIC__GENERIC__AUTH_TOKEN`,
`STATIC__GENERIC__TRANSPORT`, `STATIC__GENERIC__ARGS`, `STATIC__GENERIC__ENV` map to
`MCP__SERVERS__CUSTOM__*` plus `STATIC__GENERIC__SERVER=custom` through `SETTINGS_ALIASES`, logged
once like the A aliases.

### 3.4 `sandbox.rest`

```python
class RestAuthConfig(BaseModel):
    header: str = "Authorization"          # header carrying the credential
    scheme: str = "Bearer"                  # prefix; empty = raw value
    token: SecretStr = SecretStr("")

class RestSubmitConfig(BaseModel):
    method: Literal["POST", "PUT"] = "POST"
    path: str = "/samples"
    file_field: str = "file"
    extra_fields: dict[str, str] = {}      # sent as additional multipart fields
    task_id_path: str = "$.id"             # JSONPath into the response

class RestStatusConfig(BaseModel):
    path: str = "/samples/{task_id}"       # {task_id} substituted
    state_path: str = "$.status"
    done_values: list[str] = ["reported", "completed", "finished"]
    failed_values: list[str] = ["failed", "error"]

class RestReportConfig(BaseModel):
    path: str = "/samples/{task_id}/report"
    format: Literal["cape2", "cuckoo", "triage", "generic"] = "generic"
    pcap_path: str = ""                    # empty = no pcap

class RestMappingConfig(BaseModel):        # used only when report.format == "generic"
    target_sha256: str = "$.target.sha256"
    processes: str = ""                    # each match: {pid, ppid, name, command_line}
    calls: str = ""                        # each match: {pid, api, args, timestamp}
    signatures: str = ""                   # each match: {name, description, severity, ttps}
    dns: str = ""                          # each match: {request, type, answers[]}
    http: str = ""
    tcp: str = ""                          # each match: {dst, dport}
    udp: str = ""
    hosts: str = ""                        # each match: string
    domains: str = ""
    dropped_files: str = ""                # each match: {name, sha256, size}
    registry: str = ""                     # each match: string
    field_names: dict[str, str] = {}       # optional per-row renames, "processes.command_line": "cmdline"

class SandboxRestConfig(BaseModel):
    base_url: str = ""
    auth: RestAuthConfig
    submit: RestSubmitConfig
    status: RestStatusConfig
    report: RestReportConfig
    mapping: RestMappingConfig
    timeout_seconds: int = 900
    poll_interval_seconds: int = 15
    verify_tls: bool = True
```

`SandboxConfig.provider` gains `"rest"`; `SandboxCapabilities.report_format` gains nothing (the
adapter reports the configured `report.format`). Every `sandbox.rest.*` leaf is annotated with
`applies_when={"core.sandbox.provider": ["rest"]}`; the mapping leaves additionally carry
`applies_when` on `core.sandbox.rest.report.format == generic` (the catalog's `applies_when` is a
dict of key → allowed values, so two keys are two entries in the same dict, both required).

## 4. Server registry and lifecycle

New module `src/maljan/providers/servers.py`:

```python
class ServerHandle:                         # one per enabled server, per job
    name: str
    config: MCPServerConfig
    def open(job_id: str) -> None           # same-job short-circuit, close-then-reopen otherwise
    def tools() -> list[BaseTool]           # already filtered by the allow-list
    def close() -> None                     # idempotent

class ServerRegistry:
    def __init__(cfg: Settings)
    def for_agent(role: AgentRole) -> list[ServerHandle]   # enabled servers whose agents contains role
    def get(name: str) -> ServerHandle
    def close_all() -> None
```

Construction mirrors `GenericMCPStaticProvider.open()` (transport switch, `child_env(extra=env,
allow=env_allow)`, `resolve_mcp_args`, `MCPLangChainToolkit`, the output guard, `_run_async`), moved
into `ServerHandle` so the provider and the registry share one implementation; the static provider
`generic_mcp` becomes `ServerHandle(cfg.mcp.servers[cfg.static.generic.server])` wrapped in the
provider interface. `ServiceContainer.get_server_registry()` builds one registry per container;
`aclose` closes it.

Agent wiring:

- `NetworkAnalyst._initialize_mcp_client` and `JudgeAgent._initialize_mcp_client` read
  `registry.for_agent("network")` / `for_agent("judge")` and concatenate their tools. With the default
  registry each list holds exactly its built-in server, so the tool lists are identical to today
  (pinned in §8).
- `StaticAnalyst` keeps the provider's tools first and appends `for_agent("static")` tools after
  them, excluding the server the provider itself owns (so a `generic_mcp` server bound to `static`
  is not attached twice). `DynamicAnalyst` appends `for_agent("dynamic")` after the sandbox
  provider's tools.
- A failed `open()` of any registry server logs a warning naming the server, marks the run degraded
  with reason `mcp server '<name>' unavailable`, and continues with the remaining tools. This is
  independent of the provider's `degrade_on_failure` flag: Ghidra as the static provider still
  fails loud; a custom server bound to static never does.
- Tool name collisions across servers are resolved by prefixing the later server's tools with
  `<key>__` and logging it once; built-ins are attached first and never renamed.

## 5. Generic REST sandbox provider

`src/maljan/providers/sandbox/rest.py`, `@register_sandbox_provider("rest")`.

Capabilities: `can_submit=True`, `can_poll=True`, `can_fetch_report=True`,
`can_fetch_pcap=bool(report.pcap_path)`, `accepts_uploaded_report=False`, `provides_tools=False`,
`report_format=report.format`, `degrade_on_failure=True`.

Flow, reusing Triage's helpers (poll deadline checked every iteration, `Retry-After` parsed as
seconds or HTTP-date and clamped to the remaining budget, backoff 1.5× to 60 s, `ProviderError` on
non-2xx):

1. `submit`: multipart `{file_field: (name, bytes)}` plus `extra_fields`, response JSON → `task_id_path`;
   a missing or non-scalar match is a `ProviderError` naming the path.
2. `wait_for_completion`: GET `status.path` with `{task_id}`; `state_path` value compared
   case-insensitively against `done_values` / `failed_values`; anything else keeps polling.
3. `fetch`: GET `report.path`; if `format` is `cape2`, `cuckoo` or `triage`, the body goes through the
   same mappers the upload provider uses (`to_sandbox_report` for CAPE-shaped, the Triage mapper
   for Triage); if `generic`, through `RestMappingConfig`.
4. `fetch_pcap`: GET `pcap_path` when set, streamed to `dest_dir`.

Generic mapping (`src/maljan/providers/sandbox/rest_mapping.py`):

- Every non-empty channel path is compiled once at provider construction with `jsonpath_rfc9535`;
  a syntax error is a `ProviderConfigurationError` naming the channel, raised by `from_settings`
  and by the probe.
- Each match is coerced to the consumer row shape listed in §3.4; a row missing a required field is
  dropped and counted; the count per channel is logged once per fetch.
- Channels with an empty path go into `SandboxReport.unavailable`, so the report says what the
  sandbox did not provide, exactly as A does for Triage.
- `to_cape_shaped_dict` already renders any `SandboxReport` for the consumers; nothing downstream
  changes.

Preview and probe:

- `POST /api/v1/settings/test/rest`: `from_settings` (compiles paths), then GET `base_url` +
  `status.path` with `task_id=probe` under the configured auth; any HTTP answer other than a
  connection or auth failure counts as reachable ("reachable, status endpoint answered 404 for a
  fake task" is a pass with that detail).
- `POST /api/v1/settings/sandbox-rest/preview` (admin): body `{sample: <json>, mapping: <RestMappingConfig>}`;
  response per channel: `{matched: int, kept: int, dropped: int, sample_rows: [...3]}` and, for
  `target_sha256`, the value. Errors per channel carry the JSONPath error text. This is the only
  place mapping errors are shown to the operator before a job.

## 6. Settings UI

- **Catalog**: `CatalogEntry` gains `choices_from: Literal["static_providers", "sandbox_providers",
  "mcp_servers", "agent_roles"] | None` and `editor: Literal["server_map", "rest_sandbox"] | None`.
  The API resolves `choices_from` when it serialises the catalog (registry ids; `mcp.servers` keys
  from the effective settings) so `choices` is always populated for the web; the web never computes
  choices itself. `core.static.generic.server` uses `choices_from="mcp_servers"`.
- **Server map editor** (`ServerMapEditor.tsx`) renders the `core.mcp.servers` leaf: a list of
  cards, one per key, with add (slug validated client- and server-side), remove (built-ins show
  "disable" instead), and a form per card built from the `MCPServerConfig` annotations (labels,
  descriptions, widgets by type, secret handling); a "Test" button calls
  `POST /settings/test/mcp?server=<key>` with the staged values and shows latency plus the tool
  manifest as checkboxes that fill `tools`; an "Agents" multi-select fills `agents`. Staging is
  one pending change for the whole leaf (the PATCH body is the full dict), so the apply bar and the
  hidden-dirty logic from A apply unchanged.
- **REST sandbox editor** (`RestSandboxEditor.tsx`) renders the `core.sandbox.rest.*` leaves as
  four fieldsets (connection, submit, status, report) plus a mapping table (channel, JSONPath,
  matched/kept/dropped after preview) with a "Paste a sample response" textarea and a "Preview
  mapping" button calling the preview endpoint. Each field is still an ordinary catalog leaf, so
  staging, reset and export work per key.
- **Samples page**: the two provider selects read `choices` of `core.static.provider` /
  `core.sandbox.provider` from the catalog (one fetch, cached); the constants are deleted.
- **Probe labels**: `mcp` (custom servers, label from the entry) and `rest` ("Test sandbox API").

## 7. Probes

- `mcp`: `POST /settings/test/mcp?server=<key>`; body optional staged values for that key;
  launches the server through `ServerHandle` with a 5 s budget (stdio: initialize + tools/list;
  http: same over the URL), kills the child on timeout, returns `ok`, latency and
  `detail="<n> tools: a, b, c…"` plus `models=None`; the tool names travel in a new optional
  `tools: list[str] | None` field of `ProbeResponse` so the editor can render checkboxes.
- `rest`: §5.
- The r2 and generic probes from A are re-implemented on `ServerHandle` so there is one stdio
  handshake implementation.

## 8. Invariants and tests

1. Default profile byte-identical: prompt byte-identity, extractor goldens, CAPE identity, and a new
   `tests/servers/test_builtin_tool_sets.py` that pins the tool names of `network-mcp` and
   `threatintel-mcp` from a live handshake into `tests/fixtures/golden/mcp_tools/{network,threatintel}.json`
   and asserts `registry.for_agent("network")` / `("judge")` attach exactly those names.
2. `tests/evaluation/**` untouched (CI gate from A); `make facts` byte-identical; the pinned test
   count artefact untouched.
3. Every new leaf annotated (existing catalog test); `SandboxConfig.provider` literal, registry ids and
   the job schema literal in parity (existing tests plus `rest`).
4. Alias table covers `STATIC__GENERIC__*`; migration test: A-era overrides for `static.generic.*`
   become `mcp.servers.custom.*` + `static.generic.server=custom`.
5. REST adapter: a FastAPI stub sandbox under `tests/servers/rest_stub.py` (submit → id, status
   queue → reported, report in a synthetic `xyz` shape, optional pcap) drives an end-to-end test
   through `MaljanApp`; golden for the generic mapping of the stub's report; unit tests for
   `task_id_path` failures, failed states, timeout, Retry-After, TLS flag, format passthrough
   (`cape2` body → identity path).
6. UI: `apps/web/e2e/settings-servers.spec.ts` (add a server, probe returns tools, tick two, bind to
   static, apply; disable a built-in; REST editor preview shows matched counts) on chromium in the
   task, chromium + firefox in the final gate.
7. Security tests: `auth_token` never in snapshots or logs; `env_allow` is the only way to pass
   secrets to a child; `cwd` must resolve inside the repo or an absolute path that exists; probe
   subprocesses are killed on timeout; the preview endpoint requires admin and caps the sample at
   4 MiB.

## 9. Security

- A custom server exposes nothing until tools are ticked; the manifest is fetched only by an
  explicit probe; the README's trust-boundary paragraph from A is rewritten to describe the
  allow-list.
- `command` is executed with `child_env`, never through a shell; `args` is a list; `cwd` is
  validated; `env` values are visible settings, secrets go through `env_allow` names that the API
  process already holds.
- REST credentials are `SecretStr`, sent only in the configured header; `verify_tls` defaults on and
  turning it off is a warning in the probe detail.
- Preview and probe endpoints are admin-only and rate-limited by the existing settings throttle.

## 10. Live verification (final gate)

1. Default profile: a job on `dev`-equivalent settings completes; the network and judge tool lists in
   the log equal the pinned fixtures.
2. Register r2mcp as `mcp.servers.r2custom` from the UI, probe it, tick `open_file`, `analyze`,
   `list_imports`, bind to `static` with `static.provider=none`; the static analyst attaches exactly
   those three tools.
3. Run the REST stub locally, configure `sandbox.provider=rest` from the UI with the stub's
   endpoints and mapping, preview the pasted sample, run a job: dynamic and network sections filled,
   `unavailable` names the unmapped channels.
4. Disable `threatintel` from the UI: the judge runs without it and the run summary says so.
5. Legacy env: `STATIC__GENERIC__COMMAND=...` alone yields `mcp.servers.custom` and the one-time
   alias warning.

## 11. Out of scope (sub-project C)

Profiles, agent definitions, graph construction from definitions, per-job server selection, new
agent roles beyond the four.

## 12. Risks

- Tool set drift in the built-in sidecars between environments: the fixture is captured on this
  machine; the test compares names only, not schemas.
- Long-running stdio servers per job: each server is opened lazily on first agent use and closed at
  job end; a job that never reaches the judge never starts `threatintel`.
- JSONPath on very large reports: matches are streamed per channel and rows capped at 5 000 per
  channel with a logged count.
