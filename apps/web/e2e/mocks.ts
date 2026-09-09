import type { Page, Route, WebSocketRoute } from "@playwright/test";
import type { SettingsSchema, SettingsValues } from "@/types/settings";

/**
 * The whole API surface the E2E suite is allowed to touch — and a trap for
 * everything it is not.
 *
 * ## Why this file exists
 *
 * The mocks used to live in `fixtures.ts` and covered five endpoints. The pages
 * under test call rather more than five, and `lib/api.ts` used to default to
 * `http://127.0.0.1:8000`, so on any machine running the dev backend every
 * uncovered call quietly reached the real API and returned real data. Tests
 * asserting on live database rows looked exactly like tests asserting on
 * mocks — until the backend was down, or the data changed.
 *
 * Two things close that. `playwright.config.ts` points NEXT_PUBLIC_API_URL at
 * the Next server's own origin, so a stray call can no longer leave the test
 * process's reach; and the catch-all below turns it into a named failure
 * instead of a silent 501 nobody reads.
 *
 * ## Route precedence
 *
 * Playwright uses the route registered **last** among those that match, so the
 * catch-all is registered **first** and everything after it — the defaults
 * here, then any `page.route(...)` a spec adds — takes precedence. Verified
 * empirically rather than assumed: with the catch-all first, its handler is not
 * merely out-voted, it is never invoked at all.
 *
 * Two glob details, also measured rather than inferred, because both look like
 * they should collide and do not. A pattern is matched against the full URL
 * *including the query string*, so a pattern ending in `jobs` matches only the
 * bare collection path and leaves the one ending in `jobs?` + wildcard to serve
 * the paginated list. And a single `*` never crosses a slash, so a pattern
 * ending `jobs/` + `*` cannot swallow `jobs/{id}/events`.
 *
 * ## Adding an endpoint
 *
 * Add it to `installApiMocks` if every spec wants the same answer; override it
 * with `page.route(...)` inside the spec if only one does. Do not reach for the
 * real backend — if a test needs live data, it is an integration test, not this.
 */

/** URLs that reached the catch-all, per page. Read by `assertNoUnmockedCalls`. */
const unmockedByPage = new WeakMap<Page, string[]>();

const JSON_HEADERS = { "content-type": "application/json" };

function json(route: Route, body: unknown, status = 200) {
  return route.fulfill({
    status,
    contentType: "application/json",
    headers: JSON_HEADERS,
    body: JSON.stringify(body),
  });
}

/* ── Default payloads ───────────────────────────────────
 * Shapes follow the DTOs in lib/api.ts. `getJob` and `getSystemStatus` assert
 * their shape at runtime and `console.warn` on drift, so a hand-waved mock
 * turns every run into a wall of [api-schema-drift] noise — these match
 * `_JOB_SCHEMA` and `_SYSTEM_STATUS_SCHEMA` field for field. */

export const MOCK_USER = {
  id: "user-1",
  email: "test@example.com",
  full_name: "Test User",
  role: "analyst",
};

export const MOCK_JOB_SUMMARY = {
  id: "job-1",
  sample_id: "sample-1",
  sample_filename: "invoice_scan.exe",
  status: "completed",
  verdict: "Malware",
  overall_confidence: 0.93,
  created_at: "2026-07-26T10:00:00Z",
  completed_at: "2026-07-26T10:12:00Z",
  duration_seconds: 720,
};

/** Matches `_JOB_SCHEMA`. Defaults to `running`: a spec that cares about a
 *  terminal state says so, and a spec that just needs the page to mount gets
 *  the live path, which is the one with the moving parts. */
export const MOCK_JOB_DETAIL = {
  id: "00000000-0000-0000-0000-000000000000",
  sample_id: "sample-1",
  sample_filename: "invoice_scan.exe",
  status: "running",
  config: null,
  created_at: "2026-07-26T10:00:00Z",
  started_at: "2026-07-26T10:00:05Z",
  completed_at: null,
  duration_seconds: null,
  error_message: null,
};

export const MOCK_DASHBOARD_STATS = {
  total_jobs: 42,
  total_samples: 15,
  jobs_by_status: {
    pending: 5,
    running: 2,
    completed: 30,
    failed: 3,
    cancelled: 2,
  },
  verdict_distribution: {
    Malware: 25,
    Benign: 3,
    Suspicious: 2,
  },
  avg_duration_seconds: 120,
};

/** Matches `_SYSTEM_STATUS_SCHEMA`. */
export const MOCK_SYSTEM_STATUS = {
  app_name: "Maljan",
  app_version: "0.1.0",
  mock_mode_allowed: false,
  enrichment_enabled: true,
  has_virustotal_key: true,
  has_abuseipdb_key: false,
};

export const MOCK_SAMPLE = {
  id: "sample-1",
  sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  md5: "5d41402abc4b2a76b9719d911017c592",
  original_filename: "invoice_scan.exe",
  file_size_bytes: 204800,
  mime_type: "application/x-dosexec",
  uploaded_at: "2026-07-26T10:00:00Z",
};

export const MOCK_SANDBOX_REPORT = {
  id: "sandbox-report-1",
  format: "cape2",
  task_id: "1000",
  size_bytes: 512,
  sample_sha256_match: true,
  warning: null,
  uploaded_at: "2026-07-26T10:05:00Z",
};

export const MOCK_REPORT_SUMMARY = {
  id: "report-1",
  job_id: "job-1",
  sample_filename: "invoice_scan.exe",
  // Raw backend spelling: the UI must render "Malicious".
  verdict: "Malware",
  overall_confidence: 0.93,
  malware_category: "trojan",
  created_at: "2026-07-26T10:00:00Z",
  techniques_count: 7,
  findings_count: 12,
};

export const MOCK_AUDIT_LOG = {
  id: "log-1",
  user_id: "user-1",
  action: "job.create",
  resource_type: "job",
  resource_id: "job-1abc2def-0000-0000-0000-000000000000",
  details: null,
  ip_address: "10.0.0.5",
  created_at: "2026-07-26T10:00:00Z",
};

export const MOCK_API_KEY = {
  id: "key-1",
  user_id: "user-1",
  key_prefix: "mlj_a1b2",
  name: "CI/CD integration",
  expires_at: null,
  last_used_at: null,
  is_active: true,
  created_at: "2026-07-26T10:00:00Z",
  updated_at: "2026-07-26T10:00:00Z",
};

/**
 * Matches `apps/api/app/schemas/settings.py::SchemaResponse` /
 * `apps/web/src/types/settings.ts::SettingsSchema`. Five groups: four field
 * shapes in "negotiation" (plain int, a second int pre-seeded with a `"ui"`
 * source in `MOCK_SETTINGS_VALUES` below so per-row / group reset visibility
 * — shown only for a `"ui"`-sourced value — has something to contrast
 * against the `"default"`/`"env"` rows that must not show it, an
 * `advanced: true` int also `"ui"`-sourced so the "Advanced" fold has a
 * reason to default open, and a `list` field defaulting to `[]` for
 * `ListWidget` coverage), one secret in
 * "providers", "sandbox" and "static" — a provider selector each
 * (`order: -1`, `choices_from` naming the registry it was resolved from),
 * "sandbox" also carrying two `applies_when`-gated fields for conditional
 * visibility, and "mcp" — the server-map leaf (`editor: "server_map"`) plus
 * the `generic_mcp` static provider's server picker (`choices_from:
 * "mcp_servers"`).
 */
export const MOCK_SETTINGS_SCHEMA = {
  secrets_available: true,
  groups: [
    {
      key: "negotiation",
      title: "Negotiation",
      description: "",
      entries: [
        {
          key: "core.negotiation.max_iterations",
          namespace: "core",
          path: "negotiation.max_iterations",
          type: "int",
          default: 5,
          nullable: false,
          choices: null,
          minimum: 1,
          maximum: null,
          secret: false,
          group: "negotiation",
          title: "Max iterations",
          description: "Hard ceiling on negotiation rounds.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: null,
          applies_when: null,
          order: 0,
          choices_from: null,
          editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.negotiation.retry_delay",
          namespace: "core",
          path: "negotiation.retry_delay",
          type: "int",
          default: 2,
          nullable: false,
          choices: null,
          minimum: 0,
          maximum: null,
          secret: false,
          group: "negotiation",
          title: "Retry delay seconds",
          description: "Delay between negotiation retries.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: null,
          applies_when: null,
          order: 0,
          choices_from: null,
          editor: null, subgroup: null, advanced: false,
        },
        // Task 9: an `advanced: true`, `"ui"`-sourced entry so the fold-open
        // rule (open on mount when something inside it is staged or
        // ui-sourced) has something to prove itself against.
        {
          key: "core.negotiation.advanced_knob",
          namespace: "core",
          path: "negotiation.advanced_knob",
          type: "int",
          default: 1,
          nullable: false,
          choices: null,
          minimum: null,
          maximum: null,
          secret: false,
          group: "negotiation",
          title: "Advanced knob",
          description: "Rarely-tuned negotiation internal.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: null,
          applies_when: null,
          order: 0,
          choices_from: null,
          editor: null, subgroup: null, advanced: true,
        },
        {
          key: "core.negotiation.blocked_hosts",
          namespace: "core",
          path: "negotiation.blocked_hosts",
          type: "list",
          default: [],
          nullable: false,
          choices: null,
          minimum: null,
          maximum: null,
          secret: false,
          group: "negotiation",
          title: "Blocked hosts",
          description: "Hostnames the negotiator refuses to contact.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: null,
          applies_when: null,
          order: 0,
          choices_from: null,
          editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "providers",
      title: "Providers",
      description: "",
      entries: [
        {
          key: "core.llm.openai.api_key",
          namespace: "core",
          path: "llm.openai.api_key",
          type: "secret",
          default: null,
          nullable: true,
          choices: null,
          minimum: null,
          maximum: null,
          secret: true,
          group: "providers",
          title: "OpenAI-compatible API key",
          description: "Bearer token for the OpenAI-compatible endpoint.",
          applies: "next_job",
          editable: true,
          reason: null,
          probe: "llm",
          applies_when: null,
          order: 0,
          choices_from: null,
          editor: null, subgroup: null, advanced: false,
        },
        // Task C14 fix: real `core_catalog()` leaves the agent-definitions
        // editor's LLM section falls back to — `llm.provider` exists (an
        // enum), `llm.model` does not (models are per-provider, e.g.
        // `llm.openai.expert_model`), so only the provider entry is mocked.
        {
          key: "core.llm.provider", namespace: "core", path: "llm.provider",
          type: "enum", default: "openai", nullable: false,
          choices: ["openai", "anthropic", "ollama", "gemini"],
          minimum: null, maximum: null, secret: false, group: "providers",
          title: "Provider", description: "Selects which LLM backend serves both the expert and judge roles.",
          applies: "next_job", editable: true, reason: null, probe: "llm",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        // `llm.agents` (`dict[str, AgentLLMConfig]`) is one JSON leaf, staged
        // as a whole exactly like `core.mcp.servers` — the agent-definitions
        // editor's LLM section reads and writes this map directly, one entry
        // per agent key.
        {
          key: "core.llm.agents", namespace: "core", path: "llm.agents",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "providers",
          title: "Per-agent LLM overrides",
          description: "Per-agent LLM overrides for the heterogeneous model ensemble.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    // A second group whose leaf declares the same `"llm"` probe. The real
    // catalog files `llm.provider` and the per-provider base URL/model leaves
    // in different groups, and the probe reads all of them, so the button in
    // either group has to send the other group's staged values too.
    {
      key: "llm",
      title: "LLM & model",
      description: "",
      entries: [
        {
          key: "core.llm.ollama.base_url", namespace: "core", path: "llm.ollama.base_url",
          type: "str", default: "http://localhost:11434", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "llm",
          title: "Ollama base URL",
          description: "Base URL of the local Ollama server.",
          applies: "next_job", editable: true, reason: null, probe: "llm",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    // Task A21: `applies_when` drives conditional visibility; `order: -1`
    // puts the selector first.
    {
      key: "sandbox",
      title: "Sandbox provider",
      description: "",
      entries: [
        {
          key: "core.sandbox.provider", namespace: "core", path: "sandbox.provider",
          type: "enum", default: "mock", nullable: false,
          choices: ["mock", "cape2", "upload", "triage", "rest"],
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Sandbox provider", description: "Which sandbox produces the dynamic evidence.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: "sandbox_providers", editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.cape2.base_url", namespace: "core", path: "sandbox.cape2.base_url",
          type: "str", default: "http://localhost:8000", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "CAPEv2 base URL", description: "Base URL of the CAPEv2 REST API.",
          applies: "next_job", editable: true, reason: null, probe: "cape2",
          applies_when: { "core.sandbox.provider": ["cape2"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.triage.base_url", namespace: "core", path: "sandbox.triage.base_url",
          type: "str", default: "https://tria.ge/api/v0", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Triage API base URL", description: "Hatching Triage cloud API root.",
          applies: "next_job", editable: true, reason: null, probe: "triage",
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        // Task B17/B18: the REST sandbox's own fields, grouped and rendered by
        // `RestSandboxEditor` — `editor: "rest_sandbox"` is what routes them
        // there instead of the plain `FieldRow` the entries above use. The two
        // mapping rows are additionally gated on the report format: a
        // structured `cape2`/`triage` report has nothing to map.
        {
          key: "core.sandbox.rest.base_url", namespace: "core", path: "sandbox.rest.base_url",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "REST sandbox base URL", description: "Base URL of the REST-flavoured sandbox.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.sandbox.provider": ["rest"] }, order: 0,
          choices_from: null, editor: "rest_sandbox", subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.rest.report.format", namespace: "core", path: "sandbox.rest.report.format",
          type: "enum", default: "generic", nullable: false, choices: ["generic", "cape2"],
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Report format", description: "Whether the report needs the mapping below.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.sandbox.provider": ["rest"] }, order: 0,
          choices_from: null, editor: "rest_sandbox", subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.rest.mapping.processes", namespace: "core", path: "sandbox.rest.mapping.processes",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Mapping: processes", description: "JSONPath selecting the process rows.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: {
            "core.sandbox.provider": ["rest"],
            "core.sandbox.rest.report.format": ["generic"],
          }, order: 0,
          choices_from: null, editor: "rest_sandbox", subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.rest.mapping.dns", namespace: "core", path: "sandbox.rest.mapping.dns",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Mapping: dns", description: "JSONPath selecting the DNS rows.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: {
            "core.sandbox.provider": ["rest"],
            "core.sandbox.rest.report.format": ["generic"],
          }, order: 0,
          choices_from: null, editor: "rest_sandbox", subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.rest.mapping.target_sha256", namespace: "core",
          path: "sandbox.rest.mapping.target_sha256",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Mapping: target sha256", description: "JSONPath selecting the sample's hash.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: {
            "core.sandbox.provider": ["rest"],
            "core.sandbox.rest.report.format": ["generic"],
          }, order: 0,
          choices_from: null, editor: "rest_sandbox", subgroup: null, advanced: false,
        },
      ],
    },
    // Task B15: the static provider selector, mirroring the sandbox one
    // above — `choices_from` names where the API resolved the list from.
    {
      key: "static",
      title: "Static provider",
      description: "",
      entries: [
        {
          key: "core.static.provider", namespace: "core", path: "static.provider",
          type: "enum", default: "ghidra", nullable: false,
          choices: ["ghidra", "r2", "capa_yara", "generic_mcp", "none"],
          minimum: null, maximum: null, secret: false, group: "static",
          title: "Static provider", description: "Which tool the static analyst attaches.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: "static_providers", editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    // Task B15/B16: the server map is one leaf with its own editor; its
    // choices come resolved from the API.
    {
      key: "mcp",
      title: "Tool servers (MCP)",
      description: "",
      entries: [
        {
          key: "core.mcp.servers", namespace: "core", path: "mcp.servers",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "mcp",
          title: "Tool servers",
          description: "Every MCP server Maljan can attach, keyed by a short name.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: "server_map", subgroup: null, advanced: false,
        },
        {
          key: "core.static.generic.server", namespace: "core", path: "static.generic.server",
          type: "str", default: "", nullable: false, choices: ["", "network", "threatintel"],
          minimum: null, maximum: null, secret: false, group: "mcp",
          title: "Custom MCP server",
          description: "Which registry entry the generic_mcp static provider drives.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: "mcp_servers", editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    // Task C14/C15: named profiles and operator-defined analysts, both
    // composite `json` leaves the way the server map is one.
    {
      key: "agents",
      title: "Agents",
      description: "",
      entries: [
        {
          key: "core.agents.profile", namespace: "core", path: "agents.profile",
          type: "enum", default: "default", nullable: false,
          choices: ["default", "lean"],
          minimum: null, maximum: null, secret: false, group: "agents",
          title: "Active profile", description: "Which analyst profile a new job runs.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: "profiles", editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.agents.definitions", namespace: "core", path: "agents.definitions",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "agents",
          title: "Agent definitions",
          description: "Every analyst Maljan can run, keyed by a short name.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: "agent_definitions", subgroup: null, advanced: false,
        },
        {
          key: "core.agents.profiles", namespace: "core", path: "agents.profiles",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "agents",
          title: "Profiles",
          description: "Named analyst line-ups a job can select.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: "profiles", subgroup: null, advanced: false,
        },
      ],
    },
  ],
};

export const MOCK_SETTINGS_VALUES = {
  values: {
    "core.negotiation.max_iterations": {
      value: 5,
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.negotiation.retry_delay": {
      value: 10,
      is_set: null,
      hint: null,
      source: "ui",
      updated_at: "2026-08-01T00:00:00Z",
      updated_by: "user-1",
    },
    "core.negotiation.advanced_knob": {
      value: 2,
      is_set: null,
      hint: null,
      source: "ui",
      updated_at: "2026-08-01T00:00:00Z",
      updated_by: "user-1",
    },
    "core.negotiation.blocked_hosts": {
      value: [],
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.llm.openai.api_key": {
      value: null,
      is_set: true,
      hint: "1234",
      source: "env",
      updated_at: null,
      updated_by: null,
    },
    "core.llm.provider": {
      value: "openai",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.llm.ollama.base_url": {
      value: "http://localhost:11434",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.llm.agents": {
      value: {},
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.provider": {
      value: "cape2",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.cape2.base_url": {
      value: "http://localhost:8000",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.triage.base_url": {
      value: "https://tria.ge/api/v0",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.static.provider": {
      value: "ghidra",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.rest.base_url": {
      value: "",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.rest.report.format": {
      value: "generic",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.rest.mapping.processes": {
      value: "",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.rest.mapping.dns": {
      value: "",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.sandbox.rest.mapping.target_sha256": {
      value: "",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.mcp.servers": {
      value: {
        network: {
          enabled: true, transport: "stdio", command: "python",
          args: ["services/network-mcp/server.py"], env: {}, cwd: "services/network-mcp",
          env_allow: [], url: "", auth_token: "", auth_token_source: "default",
          tool_selection: "dynamic", use_all_tools: false, tools: null,
          agents: ["network"], label: "Network MCP",
        },
        threatintel: {
          enabled: true, transport: "stdio", command: "python",
          args: ["services/threatintel-mcp/server.py"], env: {}, cwd: "services/threatintel-mcp",
          env_allow: ["VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY"], url: "",
          auth_token: "**********", auth_token_source: "env",
          tool_selection: "dynamic", use_all_tools: false, tools: null,
          agents: ["judge"], label: "Threat intel MCP",
        },
        // Task 16: a non-built-in server, so the agent-definitions editor has
        // a server to reference from a generic analyst's tool list.
        strings: {
          enabled: true, transport: "stdio", command: "strings-mcp",
          args: [], env: {}, cwd: "", env_allow: [], url: "",
          auth_token: "", auth_token_source: "default",
          tool_selection: "dynamic", use_all_tools: false,
          tools: ["extract_strings"], agents: [], label: "Strings MCP",
        },
      },
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.static.generic.server": {
      value: "",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.agents.profile": {
      value: "default",
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.agents.definitions": {
      value: {
        static: {
          role: "static", label: "Static analyst", prompt: null, tools: [],
          static_provider: null, enabled: true,
        },
        dynamic: {
          role: "dynamic", label: "Dynamic analyst", prompt: null, tools: [],
          static_provider: null, enabled: true,
        },
        network: {
          role: "network", label: "Network analyst", prompt: null, tools: [],
          static_provider: null, enabled: true,
        },
        judge: {
          role: "judge", label: "Judge", prompt: null, tools: [],
          static_provider: null, enabled: true,
        },
      },
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
    "core.agents.profiles": {
      value: {
        default: { label: "Default", analysts: ["static", "dynamic", "network"] },
      },
      is_set: null,
      hint: null,
      source: "default",
      updated_at: null,
      updated_by: null,
    },
  },
};

/**
 * The setup-guides' own schema/values fixture (Task 19).
 *
 * `settings-setup.spec.ts` walks all seven `/settings/setup/<guide>` guides,
 * which together touch a much wider slice of the catalog than
 * `MOCK_SETTINGS_SCHEMA` above covers — every guide's own group, in the
 * groups the real console rail expects (`sections.ts`), so `pathForKey` and
 * the rail badges resolve exactly the way they do against the real backend.
 *
 * `core.llm.provider` starts on `openai` with no key stored: "not configured"
 * per `llmStatus`, and staging `ollama` in the LLM guide is a real change
 * (`stage()` only writes a key when it differs from what's saved) — the guide
 * spec depends on the provider actually appearing in the Apply's PATCH body,
 * which it could not if the fixture's starting provider already were the one
 * the guide walkthrough picks.
 *
 * Groups deliberately split the way the real catalog does: "llm" carries the
 * provider selector and the token-budget/parallelism knobs, "providers"
 * carries the per-provider credentials and model names — so the rail's dirty
 * badge after the LLM guide lands on "LLM & model" (just the provider) and
 * "Providers" (the three ollama fields), never a combined count on one.
 */
export const MOCK_SETTINGS_SCHEMA_FULL: SettingsSchema = {
  secrets_available: true,
  groups: [
    {
      key: "llm",
      title: "LLM & model",
      description: "",
      entries: [
        {
          key: "core.llm.provider", namespace: "core", path: "llm.provider",
          type: "enum", default: "openai", nullable: false,
          choices: ["openai", "anthropic", "ollama", "gemini"],
          minimum: null, maximum: null, secret: false, group: "llm",
          title: "Provider", description: "Selects which LLM backend serves both the expert and judge roles.",
          applies: "next_job", editable: true, reason: null, probe: "llm",
          applies_when: null, order: -1, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.expert_max_tokens", namespace: "core", path: "llm.expert_max_tokens",
          type: "int", default: 4096, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "llm",
          title: "Expert max tokens", description: "Token budget for one analyst turn.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.judge_max_tokens", namespace: "core", path: "llm.judge_max_tokens",
          type: "int", default: 4096, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "llm",
          title: "Judge max tokens", description: "Token budget for the judge's verdict.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.parallel_analysts", namespace: "core", path: "llm.parallel_analysts",
          type: "int", default: 3, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "llm",
          title: "Parallel analysts", description: "How many analysts run at once.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.view_decomposition_mode", namespace: "core", path: "llm.view_decomposition_mode",
          type: "enum", default: "single", nullable: false, choices: ["single", "split"],
          minimum: null, maximum: null, secret: false, group: "llm",
          title: "View decomposition mode", description: "Whether a large sample is split into multiple views.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.view_decomposition_views", namespace: "core", path: "llm.view_decomposition_views",
          type: "int", default: 1, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "llm",
          title: "View decomposition views", description: "How many views a split sample is divided into.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "providers",
      title: "Providers",
      description: "",
      entries: [
        {
          key: "core.llm.ollama.base_url", namespace: "core", path: "llm.ollama.base_url",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "providers",
          title: "Ollama base URL", description: "Base URL of the local Ollama server.",
          applies: "next_job", editable: true, reason: null, probe: "llm",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.ollama.expert_model", namespace: "core", path: "llm.ollama.expert_model",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "providers",
          title: "Ollama expert model", description: "Model the analysts run on.",
          applies: "next_job", editable: true, reason: null, probe: "llm",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.ollama.judge_model", namespace: "core", path: "llm.ollama.judge_model",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "providers",
          title: "Ollama judge model", description: "Model the judge writes the verdict on.",
          applies: "next_job", editable: true, reason: null, probe: "llm",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.ollama.num_ctx", namespace: "core", path: "llm.ollama.num_ctx",
          type: "int", default: 8192, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "providers",
          title: "Ollama context length", description: "The context window Ollama is asked to serve.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.ollama.keep_alive", namespace: "core", path: "llm.ollama.keep_alive",
          type: "str", default: "5m", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "providers",
          title: "Ollama keep-alive", description: "How long Ollama keeps the model loaded after a request.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.llm.openai.api_key", namespace: "core", path: "llm.openai.api_key",
          type: "secret", default: null, nullable: true, choices: null,
          minimum: null, maximum: null, secret: true, group: "providers",
          title: "OpenAI-compatible API key", description: "Bearer token for the OpenAI-compatible endpoint.",
          applies: "next_job", editable: true, reason: null, probe: "llm",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "static",
      title: "Static provider",
      description: "",
      entries: [
        {
          key: "core.static.provider", namespace: "core", path: "static.provider",
          type: "enum", default: "ghidra", nullable: false,
          choices: ["ghidra", "r2", "capa_yara", "generic_mcp", "none"],
          minimum: null, maximum: null, secret: false, group: "static",
          title: "Static provider", description: "Which tool the static analyst attaches.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: "static_providers", editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.static.r2.binary_path", namespace: "core", path: "static.r2.binary_path",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "static",
          title: "radare2 binary path", description: "Where the radare2 binary lives on disk.",
          applies: "next_job", editable: true, reason: null, probe: "r2",
          applies_when: { "core.static.provider": ["r2"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.static.r2.mirror_dir", namespace: "core", path: "static.r2.mirror_dir",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "static",
          title: "radare2 mirror directory", description: "Where a copy of the sample is written before analysis.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.static.provider": ["r2"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.static.generic.server", namespace: "core", path: "static.generic.server",
          type: "str", default: "", nullable: false, choices: ["", "network"],
          minimum: null, maximum: null, secret: false, group: "static",
          title: "Custom MCP server", description: "Which registry entry the generic_mcp static provider drives.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.static.provider": ["generic_mcp"] }, order: 0,
          choices_from: "mcp_servers", editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "sandbox",
      title: "Sandbox provider",
      description: "",
      entries: [
        {
          key: "core.sandbox.provider", namespace: "core", path: "sandbox.provider",
          type: "enum", default: "mock", nullable: false,
          choices: ["mock", "cape2", "upload", "triage", "rest"],
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Sandbox provider", description: "Which sandbox produces the dynamic evidence.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: "sandbox_providers", editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.triage.api_token", namespace: "core", path: "sandbox.triage.api_token",
          type: "secret", default: null, nullable: true, choices: null,
          minimum: null, maximum: null, secret: true, group: "sandbox",
          title: "Triage API token", description: "Hatching Triage cloud API token.",
          applies: "next_job", editable: true, reason: null, probe: "triage",
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.triage.base_url", namespace: "core", path: "sandbox.triage.base_url",
          type: "str", default: "https://tria.ge/api/v0", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Triage API base URL", description: "Hatching Triage cloud API root.",
          applies: "next_job", editable: true, reason: null, probe: "triage",
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.triage.profile", namespace: "core", path: "sandbox.triage.profile",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Triage profile", description: "The analysis profile Triage runs the sample under.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.triage.fetch_pcap", namespace: "core", path: "sandbox.triage.fetch_pcap",
          type: "bool", default: false, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "sandbox",
          title: "Fetch the pcap", description: "Whether to download the capture alongside the report.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.triage.poll_interval_seconds", namespace: "core",
          path: "sandbox.triage.poll_interval_seconds",
          type: "int", default: 30, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "sandbox",
          title: "Poll interval (seconds)", description: "How often the poller checks the task's status.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.sandbox.triage.timeout_seconds", namespace: "core",
          path: "sandbox.triage.timeout_seconds",
          type: "int", default: 600, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "sandbox",
          title: "Timeout (seconds)", description: "How long to wait for the task before giving up.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: { "core.sandbox.provider": ["triage"] }, order: 0,
          choices_from: null, editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "mcp",
      title: "Tool servers (MCP)",
      description: "",
      entries: [
        {
          key: "core.mcp.servers", namespace: "core", path: "mcp.servers",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "mcp",
          title: "Tool servers",
          description: "Every MCP server Maljan can attach, keyed by a short name.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: "server_map", subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "agents",
      title: "Agents",
      description: "",
      entries: [
        {
          key: "core.agents.profile", namespace: "core", path: "agents.profile",
          type: "enum", default: "default", nullable: false,
          choices: ["default"],
          minimum: null, maximum: null, secret: false, group: "agents",
          title: "Active profile", description: "Which analyst profile a new job runs.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: "profiles", editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.agents.definitions", namespace: "core", path: "agents.definitions",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "agents",
          title: "Agent definitions",
          description: "Every analyst Maljan can run, keyed by a short name.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: "agent_definitions", subgroup: null, advanced: false,
        },
        {
          key: "core.agents.profiles", namespace: "core", path: "agents.profiles",
          type: "json", default: {}, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "agents",
          title: "Profiles",
          description: "Named analyst line-ups a job can select.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: "profiles", subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "memory",
      title: "Memory",
      description: "",
      entries: [
        {
          key: "core.memory.backend", namespace: "core", path: "memory.backend",
          type: "enum", default: "memory", nullable: false, choices: ["memory", "qdrant"],
          minimum: null, maximum: null, secret: false, group: "memory",
          title: "Backend", description: "In-process memory, or a Qdrant instance that survives a restart.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: -1, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.memory.qdrant_url", namespace: "core", path: "memory.qdrant_url",
          type: "str", default: "", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "memory",
          title: "Qdrant URL", description: "Where the Qdrant instance lives.",
          applies: "next_job", editable: true, reason: null, probe: "qdrant",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.memory.qdrant_api_key", namespace: "core", path: "memory.qdrant_api_key",
          type: "secret", default: null, nullable: true, choices: null,
          minimum: null, maximum: null, secret: true, group: "memory",
          title: "Qdrant API key", description: "Credential for a hosted Qdrant instance.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.memory.qdrant_collection", namespace: "core", path: "memory.qdrant_collection",
          type: "str", default: "maljan_findings", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "memory",
          title: "Qdrant collection", description: "Collection findings are written to and read from.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.memory.qdrant_function_hash_collection", namespace: "core",
          path: "memory.qdrant_function_hash_collection",
          type: "str", default: "maljan_function_hashes", nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "memory",
          title: "Qdrant function-hash collection", description: "Collection function hashes are written to and read from.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "core.memory.top_k", namespace: "core", path: "memory.top_k",
          type: "int", default: 5, nullable: false, choices: null,
          minimum: 1, maximum: null, secret: false, group: "memory",
          title: "Neighbours per lookup", description: "How many prior findings a lookup returns.",
          applies: "next_job", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
      ],
    },
    {
      key: "enrichment",
      title: "Enrichment",
      description: "",
      entries: [
        {
          key: "api.enrichment_enabled", namespace: "api", path: "enrichment_enabled",
          type: "bool", default: false, nullable: false, choices: null,
          minimum: null, maximum: null, secret: false, group: "enrichment",
          title: "Enrichment enabled", description: "Look indicators up against threat-intelligence sources.",
          applies: "live", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "api.enrichment_max_lookups", namespace: "api", path: "enrichment_max_lookups",
          type: "int", default: 10, nullable: false, choices: null,
          minimum: 0, maximum: null, secret: false, group: "enrichment",
          title: "Max lookups per analysis", description: "Caps how many lookups a single analysis may spend.",
          applies: "live", editable: true, reason: null, probe: null,
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "api.virustotal_api_key", namespace: "api", path: "virustotal_api_key",
          type: "secret", default: null, nullable: true, choices: null,
          minimum: null, maximum: null, secret: true, group: "enrichment",
          title: "VirusTotal API key", description: "Leave empty to skip VirusTotal.",
          applies: "live", editable: true, reason: null, probe: "virustotal",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
        {
          key: "api.abuseipdb_api_key", namespace: "api", path: "abuseipdb_api_key",
          type: "secret", default: null, nullable: true, choices: null,
          minimum: null, maximum: null, secret: true, group: "enrichment",
          title: "AbuseIPDB API key", description: "Leave empty to skip AbuseIPDB.",
          applies: "live", editable: true, reason: null, probe: "abuseipdb",
          applies_when: null, order: 0, choices_from: null, editor: null, subgroup: null, advanced: false,
        },
      ],
    },
  ],
};

function unset(source: "default" | "env" | "ui" = "default"): {
  is_set: null;
  hint: null;
  source: "default" | "env" | "ui";
  updated_at: null;
  updated_by: null;
} {
  return { is_set: null, hint: null, source, updated_at: null, updated_by: null };
}

/** Values matching `MOCK_SETTINGS_SCHEMA_FULL`, every entry default-sourced
 *  unless noted. `core.llm.provider` is `"openai"` with no key stored — "not
 *  configured" per `llmStatus` — and every ollama field starts empty, so the
 *  hub reads "Not configured" and the LLM guide walkthrough starts from a
 *  clean slate. */
export const MOCK_SETTINGS_VALUES_FULL: SettingsValues = {
  values: {
    "core.llm.provider": { value: "openai", ...unset() },
    "core.llm.expert_max_tokens": { value: 4096, ...unset() },
    "core.llm.judge_max_tokens": { value: 4096, ...unset() },
    "core.llm.parallel_analysts": { value: 3, ...unset() },
    "core.llm.view_decomposition_mode": { value: "single", ...unset() },
    "core.llm.view_decomposition_views": { value: 1, ...unset() },
    "core.llm.ollama.base_url": { value: "", ...unset() },
    "core.llm.ollama.expert_model": { value: "", ...unset() },
    "core.llm.ollama.judge_model": { value: "", ...unset() },
    "core.llm.ollama.num_ctx": { value: 8192, ...unset() },
    "core.llm.ollama.keep_alive": { value: "5m", ...unset() },
    "core.llm.openai.api_key": { value: null, is_set: false, hint: null, source: "default", updated_at: null, updated_by: null },
    "core.static.provider": { value: "ghidra", ...unset() },
    "core.static.r2.binary_path": { value: "", ...unset() },
    "core.static.r2.mirror_dir": { value: "", ...unset() },
    "core.static.generic.server": { value: "", ...unset() },
    "core.sandbox.provider": { value: "mock", ...unset() },
    "core.sandbox.triage.api_token": { value: null, is_set: false, hint: null, source: "default", updated_at: null, updated_by: null },
    "core.sandbox.triage.base_url": { value: "https://tria.ge/api/v0", ...unset() },
    "core.sandbox.triage.profile": { value: "", ...unset() },
    "core.sandbox.triage.fetch_pcap": { value: false, ...unset() },
    "core.sandbox.triage.poll_interval_seconds": { value: 30, ...unset() },
    "core.sandbox.triage.timeout_seconds": { value: 600, ...unset() },
    "core.mcp.servers": {
      value: {
        network: {
          enabled: true, transport: "stdio", command: "python",
          args: ["services/network-mcp/server.py"], env: {}, cwd: "services/network-mcp",
          env_allow: [], url: "", auth_token: "", auth_token_source: "default",
          tool_selection: "dynamic", use_all_tools: false, tools: null,
          agents: ["network"], label: "Network MCP",
        },
      },
      ...unset(),
    },
    "core.agents.profile": { value: "default", ...unset() },
    "core.agents.definitions": {
      value: {
        static: { role: "static", label: "Static analyst", prompt: null, tools: [], static_provider: null, enabled: true },
        dynamic: { role: "dynamic", label: "Dynamic analyst", prompt: null, tools: [], static_provider: null, enabled: true },
        network: { role: "network", label: "Network analyst", prompt: null, tools: [], static_provider: null, enabled: true },
        judge: { role: "judge", label: "Judge", prompt: null, tools: [], static_provider: null, enabled: true },
      },
      ...unset(),
    },
    "core.agents.profiles": {
      value: { default: { label: "Default", analysts: ["static", "dynamic", "network"] } },
      ...unset(),
    },
    "core.memory.backend": { value: "memory", ...unset() },
    "core.memory.qdrant_url": { value: "", ...unset() },
    "core.memory.qdrant_api_key": { value: null, is_set: false, hint: null, source: "default", updated_at: null, updated_by: null },
    "core.memory.qdrant_collection": { value: "maljan_findings", ...unset() },
    "core.memory.qdrant_function_hash_collection": { value: "maljan_function_hashes", ...unset() },
    "core.memory.top_k": { value: 5, ...unset() },
    "api.enrichment_enabled": { value: false, ...unset() },
    "api.enrichment_max_lookups": { value: 10, ...unset() },
    "api.virustotal_api_key": { value: null, is_set: false, hint: null, source: "default", updated_at: null, updated_by: null },
    "api.abuseipdb_api_key": { value: null, is_set: false, hint: null, source: "default", updated_at: null, updated_by: null },
  },
};

export interface MockOptions {
  /**
   * Handler for `**​/ws/analysis/**`. The default accepts the connection and
   * stays silent, which is enough for pages that merely mount `useWebSocket`.
   * Pass `null` to leave the socket unrouted so the spec can install its own —
   * explicit, rather than relying on which `routeWebSocket` registration wins.
   */
  webSocket?: ((ws: WebSocketRoute) => void) | null;
  /**
   * Overrides the `auth/me` payload. The default fixture user is role
   * `"analyst"`; specs covering the admin-only Configuration tab pass a
   * `{ ...MOCK_USER, role: "admin" }` variant via `test.use({ mockOptions })`
   * rather than a second fixture, following this file's one-surface pattern.
   */
  user?: typeof MOCK_USER;
  /** Overrides the settings schema/values pair `/settings/schema` and the
   *  GET branch of `/settings` answer with. Defaults to `MOCK_SETTINGS_SCHEMA`
   *  / `MOCK_SETTINGS_VALUES` — `settings-setup.spec.ts` passes
   *  `MOCK_SETTINGS_SCHEMA_FULL` / `MOCK_SETTINGS_VALUES_FULL` (or its own
   *  variant of the values) instead, without moving what every other spec
   *  already receives. */
  settingsSchema?: SettingsSchema;
  settingsValues?: SettingsValues;
}

/**
 * Register the full default mock surface on `page`.
 *
 * Must be called before the first navigation. `fixtures.ts` does this for both
 * the `page` and `authenticatedPage` fixtures, so specs get it for free.
 */
export async function installApiMocks(
  page: Page,
  options: MockOptions = {}
): Promise<void> {
  const unmocked: string[] = [];
  unmockedByPage.set(page, unmocked);

  // FIRST, so everything registered below beats it.
  await page.route("**/api/v1/**", async (route) => {
    const url = route.request().url();
    unmocked.push(`${route.request().method()} ${new URL(url).pathname}`);
    await json(
      route,
      { detail: `E2E: no mock registered for ${url}. See e2e/mocks.ts.` },
      501
    );
  });

  /* ── Auth ─────────────────────────────────────────── */
  // The refresh token is an HttpOnly cookie now: the browser holds it, not
  // localStorage, and these mocks answer with the access token alone.
  await page.route("**/api/v1/auth/login", (route) =>
    json(route, { access_token: "mock_access_token", token_type: "bearer" })
  );
  await page.route("**/api/v1/auth/register", (route) =>
    json(route, { access_token: "mock_access_token", token_type: "bearer" })
  );
  await page.route("**/api/v1/auth/me", (route) => json(route, options.user ?? MOCK_USER));
  // Armed by AuthProvider at login. The stub access token is not a JWT, so the
  // timer defaults to ~14 min and this never fires inside a test — mocked
  // anyway, because "never fires" is a property of the fixture data, not a
  // guarantee, and a real call here would be invisible.
  await page.route("**/api/v1/auth/refresh", (route) =>
    json(route, { access_token: "mock_access_token_2", token_type: "bearer" })
  );
  await page.route("**/api/v1/auth/logout", (route) =>
    route.fulfill({ status: 204, body: "" })
  );

  /* ── Dashboard ────────────────────────────────────── */
  await page.route("**/api/v1/dashboard/stats", (route) =>
    json(route, MOCK_DASHBOARD_STATS)
  );
  await page.route("**/api/v1/system/status", (route) =>
    json(route, MOCK_SYSTEM_STATUS)
  );

  /* ── Jobs ─────────────────────────────────────────── */
  await page.route("**/api/v1/jobs?**", (route) =>
    json(route, { items: [MOCK_JOB_SUMMARY], total: 1, page: 1, page_size: 10 })
  );
  // These two do not overlap, so their relative order is irrelevant: a
  // Playwright `*` does not cross a `/`, so `jobs/*` cannot match `jobs/x/events`.
  await page.route("**/api/v1/jobs/*/events**", (route) =>
    json(route, { job_id: MOCK_JOB_DETAIL.id, events: [], count: 0 })
  );
  await page.route("**/api/v1/jobs/*", (route) => {
    const id = new URL(route.request().url()).pathname.split("/").pop() ?? "";
    return json(route, { ...MOCK_JOB_DETAIL, id });
  });

  // The collection path has no query string and no trailing segment, so
  // neither `jobs?**` (literal `?`) nor `jobs/*` matches it. POST /jobs is what
  // the Analyze button on /samples fires.
  await page.route("**/api/v1/jobs", (route) =>
    json(route, { ...MOCK_JOB_DETAIL, id: "job-created", status: "pending" })
  );

  /* ── Reports ──────────────────────────────────────── */
  await page.route("**/api/v1/reports?**", (route) =>
    json(route, {
      items: [MOCK_REPORT_SUMMARY],
      total: 1,
      page: 1,
      page_size: 50,
    })
  );
  // 404 by default: a report does not exist until a run finishes, and the
  // running job above is the default. Specs that assert on a finished report
  // override this.
  await page.route("**/api/v1/reports/job/*", (route) =>
    json(route, { detail: "Report not found" }, 404)
  );
  // Sub-resources. Timeline, STIX and MITRE are fetched on mount by the
  // /process and /detection tabs; signatures and enrich are button-driven.
  await page.route("**/api/v1/reports/*/timeline", (route) =>
    json(route, { rounds: [], confidence_series: [] })
  );
  await page.route("**/api/v1/reports/*/stix", (route) =>
    json(route, { type: "bundle", id: "bundle--mock", objects: [] })
  );
  await page.route("**/api/v1/reports/*/mitre", (route) =>
    json(route, { techniques: [] })
  );
  // C4: the IOC export, reachable from the summary tab's export row.
  await page.route("**/api/v1/reports/*/iocs**", (route) =>
    json(route, { items: [], total: 0 })
  );
  await page.route("**/api/v1/reports/*/signatures/*", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/plain",
      body: "rule Maljan_Mock { condition: false }",
    })
  );
  await page.route("**/api/v1/reports/*/enrich", (route) =>
    json(route, { status: "queued", detail: "Enrichment queued." })
  );

  /* ── Samples ──────────────────────────────────────── */
  await page.route("**/api/v1/samples?**", (route) =>
    json(route, { items: [MOCK_SAMPLE], total: 1, page: 1, page_size: 50 })
  );
  await page.route("**/api/v1/samples/*", (route) => json(route, MOCK_SAMPLE));
  // After `samples/*`, which also matches this path — last registration wins.
  await page.route("**/api/v1/samples/upload", (route) => json(route, MOCK_SAMPLE));
  // A single `*` never crosses a slash, so `samples/*` above cannot match this
  // extra segment — order does not matter here, but it is grouped with the
  // other samples routes for readability. POST uploads a report; GET lists
  // the ones already attached to the sample (empty by default).
  await page.route("**/api/v1/samples/*/sandbox-reports", (route) =>
    route.request().method() === "POST"
      ? json(route, MOCK_SANDBOX_REPORT, 201)
      : json(route, { items: [], total: 0 })
  );
  await page.route("**/api/v1/samples/*/sandbox-reports/*", (route) =>
    route.fulfill({ status: 204, body: "" })
  );

  /* ── Runtime settings (admin) ─────────────────────────
   * Route precedence matters here more than elsewhere: `/settings/schema`,
   * `/settings/export` and `/settings/*` (the per-key DELETE) all have one
   * path segment after `settings`, so the generic `settings/*` handler is
   * registered FIRST and the two literal paths AFTER it, exactly like the
   * jobs section above — last registration wins when patterns overlap.
   * `/settings/test/*` has two segments after `settings` so it never
   * overlaps with `settings/*` and its position doesn't matter.
   * The bare "settings" pattern (no query) and the "settings" + query
   * pattern below are disjoint by construction — a bare-"settings" glob
   * does not match a URL with a "?" per the note atop this file — so
   * GET/PATCH (values, no query) and DELETE-by-group ("?group=") can't
   * collide either. */
  await page.route("**/api/v1/settings/*", (route) => {
    const key = new URL(route.request().url()).pathname.split("/").pop() ?? "";
    return json(route, { reset: [key] });
  });
  await page.route("**/api/v1/settings/schema", (route) =>
    json(route, options.settingsSchema ?? MOCK_SETTINGS_SCHEMA)
  );
  await page.route("**/api/v1/settings/export", (route) =>
    route.fulfill({
      status: 200,
      contentType: "text/plain",
      body: "CORE_NEGOTIATION_RETRY_DELAY=10\n",
    })
  );
  await page.route("**/api/v1/settings/test/*", (route) =>
    json(route, { ok: true, latency_ms: 42, detail: "mock probe ok", models: null, tools: null })
  );
  // Task B15: registered after the generic `test/*` handler above, so it
  // wins for the one probe route that carries a query string.
  //
  // Task 16: the `network` server's manifest matches its real tools
  // (`extract_dns`, `read_pcap_summary`, see `services/network-mcp/server.py`) — the
  // agent-definitions editor's "list tools then check one" flow depends on
  // this list actually containing the tool it checks.
  await page.route("**/api/v1/settings/test/mcp?**", (route) => {
    const server = new URL(route.request().url()).searchParams.get("server");
    const tools =
      server === "network" ? ["extract_dns", "read_pcap_summary"] : ["open_file", "analyze", "list_imports"];
    return json(route, {
      ok: true, latency_ms: 12, detail: `${tools.length} tools: ${tools.join(", ")}`,
      models: null, tools,
    });
  });
  // Task C12: the agent probe, resolving a definition without an LLM call.
  await page.route("**/api/v1/settings/test/agent?**", (route) => {
    // Task C14 fix: the probe returns the full resolved prompt, not just its
    // length — operator text, not a secret (spec §11) — so a built-in card
    // can show it read-only and a clone can seed its copy from it. The tools
    // in `detail`/`tools` below are the network analyst's real ones
    // (`extract_dns`, `read_pcap_summary`), so this prompt describes that
    // role too — used by the "network" card's Resolve button.
    const prompt =
      "You are the network analyst. Inspect captured traffic, DNS queries " +
      "and contacted hosts for indicators of command-and-control, data " +
      "exfiltration or malicious downloads, and report only findings the " +
      "extracted network evidence actually backs, citing the specific " +
      "packets, hosts or domains involved rather than speculating about " +
      "traffic the capture does not show. Stay provisional about each " +
      "claim it cannot confirm.";
    return json(route, {
      ok: true, latency_ms: 8, detail: "2 tools: extract_dns, read_pcap_summary",
      models: null, tools: ["extract_dns", "read_pcap_summary"],
      details: {
        prompt_chars: prompt.length,
        prompt_sha256: "a".repeat(64),
        prompt,
        llm: { provider: "openai", model: "" },
        static_provider: "ghidra",
        servers: [{ key: "network", tools: ["extract_dns"], status: "ok" }],
      },
    });
  });
  // Task B18: what `RestSandboxEditor`'s "Preview mapping" button calls —
  // one channel with rows, one with none, one carrying a channel-local error.
  await page.route("**/api/v1/settings/sandbox-rest/preview", (route) =>
    json(route, {
      target_sha256: "ab",
      channels: {
        processes: {
          matched: 2, kept: 1, dropped: 1, truncated: true,
          sample_rows: [{ pid: 1 }], error: null,
        },
        dns: {
          matched: 0, kept: 0, dropped: 0, truncated: false, sample_rows: [],
          error: "JSONPath syntax error at position 3",
        },
      },
    })
  );
  await page.route("**/api/v1/settings", (route) =>
    route.request().method() === "PATCH"
      ? json(route, {
          applied: Object.keys(
            (route.request().postDataJSON() as { changes: Record<string, unknown> }).changes
          ),
          applies: { next_job: 1 },
        })
      : json(route, options.settingsValues ?? MOCK_SETTINGS_VALUES)
  );
  await page.route("**/api/v1/settings?**", (route) => json(route, { reset: [] }));

  /* ── Audit & API keys ─────────────────────────────── */
  await page.route("**/api/v1/audit/logs?**", (route) =>
    json(route, { items: [MOCK_AUDIT_LOG], total: 1, page: 1, page_size: 20 })
  );
  await page.route("**/api/v1/audit/api-keys?**", (route) =>
    json(route, { items: [MOCK_API_KEY], total: 1, page: 1, page_size: 50 })
  );
  await page.route("**/api/v1/audit/api-keys", (route) =>
    json(route, { ...MOCK_API_KEY, id: "key-2", name: "new key", raw_key: "mlj_secret_value" })
  );
  await page.route("**/api/v1/audit/api-keys/*", (route) =>
    route.fulfill({ status: 204, body: "" })
  );

  /* ── WebSocket ────────────────────────────────────── */
  const wsHandler =
    options.webSocket === undefined
      ? () => {
          /* Connected and silent. Not calling connectToServer() is what keeps
           * this from dialling a real backend. */
        }
      : options.webSocket;
  if (wsHandler) {
    await page.routeWebSocket("**/ws/analysis/**", wsHandler);
  }
}

/**
 * Fail if the page made an API call nobody mocked.
 *
 * Called from the fixture teardown, so it covers every spec without each one
 * remembering to. The point is the name: an uncovered endpoint should say which
 * endpoint it was, not disappear into a 501 the assertion happens to survive.
 */
export function assertNoUnmockedCalls(page: Page): void {
  const unmocked = unmockedByPage.get(page);
  if (!unmocked?.length) return;
  const unique = [...new Set(unmocked)];
  throw new Error(
    `E2E hermeticity: ${unique.length} unmocked API call(s) reached the ` +
      `catch-all and were answered 501:\n  ${unique.join("\n  ")}\n` +
      `Add a handler in e2e/mocks.ts, or page.route(...) in the spec.`
  );
}
