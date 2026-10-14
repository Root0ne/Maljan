/**
 * DTOs for the runtime-settings admin API, mirrored from
 * `apps/api/app/schemas/settings.py`. Kept dumb by design: no logic here,
 * just the wire shapes the settings pages and the `api` client share.
 */

export type FieldType =
  | "bool"
  | "int"
  | "float"
  | "str"
  | "secret"
  | "enum"
  | "list"
  | "dict"
  | "json";

export type Applies = "next_job" | "live" | "restart";

export type ChoicesFrom =
  | "static_providers"
  | "sandbox_providers"
  | "mcp_servers"
  | "agent_roles"
  | "profiles"
  | "memory_backends"
  | "sandbox_report_readers";

export type Editor = "server_map" | "rest_sandbox" | "agent_definitions" | "stages" | "tool_facts";

export interface CatalogEntry {
  key: string;
  namespace: "core" | "api";
  path: string;
  type: FieldType;
  default: unknown;
  nullable: boolean;
  choices: string[] | null;
  minimum: number | null;
  maximum: number | null;
  secret: boolean;
  group: string;
  title: string;
  description: string;
  applies: Applies;
  editable: boolean;
  reason: string | null;
  probe: string | null;
  /** Show this entry only while every listed key holds one of the listed
   *  values. Null means "always". The API never hides anything: a setting the
   *  form does not show is still in effect, and the values endpoint says so. */
  applies_when: Record<string, string[]> | null;
  /** Rank inside the group; lower first. Provider selectors use -1. */
  order: number;
  /** A choice list the API resolves as it serialises the catalog — registry
   *  ids, or the current tool-server keys. When this is set, `choices` is
   *  already filled in: the web never computes a choice list itself. */
  choices_from: ChoicesFrom | null;
  /** A composite editor renders this leaf instead of the type's widget. */
  editor: Editor | null;
  /** A finer bucket inside `group`, or null for the group's main list. */
  subgroup: string | null;
  /** Hidden behind an "Advanced" disclosure until the operator opens it. */
  advanced: boolean;
  /** For the tool-server map alone: per built-in server, the environment names
   *  the API always passes it whatever the stored registry says
   *  (`REQUIRED_ENV_ALLOW`). Resolved by the API as it serialises the catalog,
   *  the way `choices` is, so the editor draws the rule the save enforces
   *  rather than a copy of it. Null on every other entry, and absent from an
   *  API older than the field — which the editor reads as "no fixed names",
   *  so a server card from such an API offers every name as removable rather
   *  than failing to draw. */
  required_env?: Record<string, readonly string[]> | null;
  /** The short phrase a choice declares for display beside it (a memory
   *  backend's "in-process"), keyed by choice; absent when none declares one. */
  choice_labels?: Record<string, string> | null;
  /** For a provider selector: the title each registered provider declares
   *  for itself, its one-line description, and the facts the console reads
   *  about it (`ChoiceFacts`). The console keeps no table of providers. */
  choice_titles?: Record<string, string> | null;
  choice_descriptions?: Record<string, string> | null;
  choice_facts?: Record<string, ChoiceFacts> | null;
  /** For the tool-server map: the built-in server keys and the keys no
   *  operator's server may take, as core defines them. */
  builtin_servers?: string[] | null;
  reserved_servers?: string[] | null;
  /** For the agent definitions: per capability a seeded definition references
   *  (`kind: "capability"`), the servers it stands for, as resolution reads
   *  them. Absent from an API older than the field: a capability row is then
   *  drawn without the servers it reaches. */
  capability_servers?: Record<string, readonly string[]> | null;
}

/** What a provider declares about itself, served on its selector's entry.
 *  Every field is optional: an LLM provider carries the credential and model
 *  ones, a static or sandbox provider its test and settings introduction. */
export interface ChoiceFacts {
  hosted?: boolean;
  credential_keys?: string[];
  base_url_key?: string | null;
  /** The keys a setup step shows up front, and those it folds under
   *  "Advanced"; the same meaning on every provider selector. */
  guide_keys?: string[];
  guide_advanced_keys?: string[];
  model_keys?: string[];
  agent_base_url?: boolean;
  effort_key?: string | null;
  /** The probe id that tests this choice; null when it has no test. */
  probe?: string | null;
  probe_note?: string;
  intro?: string;
}

/**
 * One entry of the `mcp.servers` map, keyed by a short server name.
 *
 * Mirrors `apps/api/app/services/settings_service.py`'s masking of the
 * per-server token: `auth_token` carries the mask when a token is set, `""`
 * when it is not, and never the value itself. The token is not a catalog
 * entry of its own — there is no separate column on `CatalogEntry` for it —
 * it rides inside this map value, and the API splits it back out into its
 * own encrypted row on PATCH.
 */
export interface McpServerEntry {
  enabled: boolean;
  transport: string;
  command: string;
  args: string[];
  env: Record<string, string>;
  cwd: string;
  env_allow: string[];
  url: string;
  /** The mask `"**********"` when a token is set, `""` when it is not — never
   *  the value. Sending the mask back unchanged means "leave the stored token
   *  alone"; sending a new string replaces it; sending `null` clears it. */
  auth_token: string;
  /** Where the effective token comes from, reported the way every other
   *  row's `source` is: a UI-saved secret row, or the built-in default. */
  auth_token_source: "ui" | "default";
  tools: string[] | null;
  agents: string[];
  label: string;
  /** How long one call of the server's tools may go unanswered, in seconds
   *  (zero: no deadline of its own; null: the deployment's floor). Optional because an API older than the
   *  field sends none; the server editor keeps it as stored. */
  call_timeout_seconds?: number | null;
  /* The server's declaration (`maljan.core.tool_declarations`): what the
   * platform reads about the server and its tools. Optional because an API
   * older than a field sends none, and a new server sends none until the
   * operator writes one; the API fills a built-in's from what it ships. */
  sample_open?: SampleOpenEntry;
  sample_mount?: string;
  work_dir?: string;
  error_patterns?: ErrorPatternEntry[];
  roles?: string[];
  prompt_fragment?: string;
  required_env_allow?: string[];
  variable_names?: string[];
  reads_staged_sample?: boolean;
  platform_owned?: boolean;
  auto_name_prefixes?: string[];
  reference_urls?: string[];
  /** Per tool, as served: its changes over the shipped declaration of that
   *  tool (the changed fields, `null` for a removed shipped tool, the whole
   *  declaration of a tool it does not ship; for a server an operator added,
   *  its whole map), marked as such by `"": "changes"`. */
  tool_facts?: Record<string, ToolFactsEntry | null | "changes">;
  /** How the server's credential is obtained by one request, or null when its
   *  token is typed in (`core.tool_declarations.CredentialBootstrap`). */
  credential_bootstrap?: CredentialBootstrapEntry | null;
}

/** A server's declared credential bootstrap, as the API stores it. */
export interface CredentialBootstrapEntry {
  url: string;
  body?: Record<string, unknown>;
  token_json_path: string;
  token_prefix?: string;
  family?: string;
  facts?: Record<string, string>;
  note?: string;
}

/** Which of a server's tools opens a sample, and which select and analyse it. */
export interface SampleOpenEntry {
  open_tool: string;
  path_argument: string;
  name_field: string;
  select_tool: string;
  select_argument: string;
  analyse_tool: string;
  analyse_argument: string;
}

/** One way a server's plain-text answer says "error". */
export interface ErrorPatternEntry {
  match: string;
  code?: string;
  remediation?: string;
  remediation_with_path?: string;
  tools?: string[];
  applies_to?: string[];
  multiline?: boolean;
  message_group?: string;
}

/** What one tool's answer is and where its facts sit; every key optional. A
 *  declaration with no kind states the tool's other facts and leaves it read
 *  as a tool of no kind. */
export interface ToolFactsEntry {
  kind?: string;
  [field: string]: unknown;
}

/**
 * One tool source an agent definition asks for, mirroring
 * `maljan.core.config.ToolRef`. `kind: "mcp"` names a server and, optionally,
 * one of its tools — `name: null` means the server's whole allow-listed set.
 * `kind: "provider"` means "this agent's static provider's tools" and carries
 * nothing else. `kind: "sandbox"` means the job's sandbox report, read through
 * the in-process sandbox tool set, and likewise carries nothing else.
 * `kind: "agent"` names another definition: the agent gets a tool
 * `ask_<agent>` that hands that agent a task and returns its answer. The API
 * writes `agent` only on that kind, so the field is optional here.
 * `kind: "capability"` names a kind of tool (`capability: "reputation"`): every
 * server declaring a tool of that kind that leaves its binding to the
 * definitions. The API writes `capability` only on that kind.
 */
export interface ToolRefEntry {
  kind: "mcp" | "provider" | "sandbox" | "agent" | "capability";
  server: string | null;
  name: string | null;
  agent?: string | null;
  capability?: string | null;
}

/**
 * One entry of the `agents.definitions` map, keyed by a short agent name.
 *
 * `prompt: null` on a built-in role means "the built-in prompt", which the
 * editor renders read-only from the agent probe rather than inventing here —
 * the assembly depends on the agent's static provider and only the API knows
 * it. Nothing in this shape is a secret: prompts are operator text and are
 * exported as-is.
 */
export interface AgentDefinitionEntry {
  role: "static" | "dynamic" | "network" | "judge" | "generic" | "lead" | "report";
  label: string;
  prompt: string | null;
  tools: ToolRefEntry[];
  static_provider: string | null;
  enabled: boolean;
  /** How many ReAct steps one loop of this agent may take, and how long it may
   *  run. `null` means the deployment-wide default. A lead that asks six
   *  specialists needs both raised, and before they were fields of the
   *  definition an operator cloning that team got the tools and none of the
   *  budget to use them in. */
  max_steps: number | null;
  timeout_seconds: number | null;
  /** The console tab a section built from this agent's tool answers is drawn
   *  on when the tool's kind places none (`AgentDefinition.tab`); `null`
   *  places nothing. Optional because an API older than the field sends none. */
  tab?: string | null;
}

/** How hard one debate stage argues before it hands over, mirroring
 *  `maljan.core.config.DebateOptions`. `null` on a stage means the global
 *  negotiation settings it was seeded from. */
export interface DebateOptionsEntry {
  max_rounds: number;
  consensus_threshold: number;
  sycophancy_check: boolean;
}

export type StageKind = "triage" | "analysis" | "debate" | "verdict" | "report";
export type StageMode = "parallel" | "sequential";
export type InjectUpstream = "none" | "findings" | "full";

/**
 * One stage of a team, mirroring `maljan.core.config.StageDefinition`.
 *
 * `depends_on` may only name stages declared earlier, which is what makes the
 * card order the run order and a cycle unrepresentable. `when` is an
 * expression in the small condition language the API validates; empty means
 * the stage always runs.
 */
export interface StageEntry {
  key: string;
  label: string;
  kind: StageKind;
  agents: string[];
  depends_on: string[];
  when: string;
  /** `null` is unset: the stage follows the job's resolved `llm.parallel_analysts`. */
  mode: StageMode | null;
  inject_upstream: InjectUpstream;
  debate: DebateOptionsEntry | null;
  builtin_tools: boolean;
}

/**
 * One entry of the `agents.profiles` map: a team, as ordered stages.
 *
 * `analysts` is what a profile used to be. It is kept on the wire so a stored
 * document written before stages still round-trips, and the settings model
 * ignores it whenever `stages` is present.
 */
export interface ProfileEntry {
  label: string;
  stages: StageEntry[];
  analysts: string[];
  /** True while the stages are still a derivation of `analysts` rather than
   *  something an operator wrote. The API keeps re-deriving them from the
   *  global analyst-mode and negotiation settings until this is cleared, which
   *  is what the editor does on the first stage edit. Round-tripped, never
   *  shown. */
  derived_from_analysts?: boolean;
  exclude_servers?: string[];
  exclude_sandbox_tools?: boolean;
  static_provider?: string | null;
}

/**
 * One finding of `POST /settings/lint-teams`. An error is a refusal the apply
 * path would make, in the same words; a warning never blocks apply. `path` is
 * the dotted key a refusal would carry, so it routes to the same card.
 */
export interface TeamFinding {
  severity: "error" | "warning";
  code: string;
  message: string;
  /** Null for a finding about the agent map rather than one team. */
  team: string | null;
  stage: string | null;
  field: string | null;
  agent: string | null;
  path: string;
}

/** One stage as the shared team layout places it. */
export interface TeamGraphNode {
  key: string;
  label: string;
  kind: string;
  agents: string[];
  when: string;
  reads: string;
  mode: string;
  row: number;
  column: number;
}

/** A `depends_on` edge; `implicit` is the triage pack adopting a root stage,
 *  `legal: false` a dependency on a stage written further down. */
export interface TeamGraphEdge {
  source: string;
  target: string;
  implicit: boolean;
  legal: boolean;
}

export interface TeamGraph {
  nodes: TeamGraphNode[];
  edges: TeamGraphEdge[];
  rows: number;
  columns: number;
}

export interface TeamLintResult {
  findings: TeamFinding[];
  graphs: Record<string, TeamGraph>;
}

/** `ProbeResult.details` as the agent probe fills it in. */
export interface AgentProbeDetails {
  prompt_chars: number;
  prompt_sha256: string;
  /** The full resolved prompt, with the platform's sentence about the
   *  agent's tools. Operator text, not a secret (spec §11) — the settings UI
   *  shows it read-only on a built-in card. */
  prompt: string;
  /** The same prompt without the sentence about tools: what a clone seeds its
   *  copy from, since the clone gets a sentence of its own for its own tool
   *  list. Absent from a probe taken before the field existed. */
  authored_prompt?: string;
  llm: { provider: string; model: string };
  static_provider: string;
  servers: { key: string; tools: string[]; status: string }[];
}

export interface SettingsGroup {
  key: string;
  title: string;
  description: string;
  entries: CatalogEntry[];
}

export interface SettingsSchema {
  groups: SettingsGroup[];
  /** The label of every connection test the API answers, by probe id. */
  probe_labels?: Record<string, string>;
  /** Every post-verdict enrichment source in force, in its declared order. */
  enrichment_sources?: EnrichmentSourceFacts[];
  /** Every tool server in force that declares how its credential is
   *  obtained, by key. */
  credential_servers?: Record<string, CredentialServerFacts>;
  /** How a tool declaration's fields split, as the API reads them. */
  tool_declaration_fields?: ToolDeclarationFields;
  /** Per block (`mcp.servers.<key>` or a provider block's path), the tools
   *  whose stored change the API leaves out because it does not validate
   *  over what this release ships; each is in force as shipped. */
  tool_facts_conflicts?: Record<string, string[]>;
  /** Each stored triage pack step the API leaves out, by id (else
   *  `#<position>`), with why; the shipped step it changed, if any, runs
   *  instead. */
  pack_steps_left_out?: Record<string, string>;
}

/** The word naming no kind, and each kind-free and kind-dependent field of a
 *  tool declaration with its default (`core.tool_declarations.
 *  declaration_fields`); a field counts as set only when it differs from its
 *  default. */
export interface ToolDeclarationFields {
  no_kind: string;
  kind_free: Record<string, unknown>;
  kind_dependent: Record<string, unknown>;
}

/** What the schema says about one enrichment source; never a credential. */
export interface EnrichmentSourceFacts {
  key: string;
  label: string;
  kinds: string[];
  enabled: boolean;
  /** The catalog key holding its credential, or null when it holds its own
   *  (`own_credential`) or needs none. */
  credential_key: string | null;
  own_credential: boolean;
  server: string | null;
  /** For a server source, whether its server is enabled; null otherwise. */
  server_enabled?: boolean | null;
  /** Whether it declares a connection test, run under its key. */
  probe: boolean;
}

/** What the schema says about a server whose credential can be obtained. */
export interface CredentialServerFacts {
  label: string;
  family: string;
  note: string;
}

export interface SettingValue {
  value: unknown;
  is_set: boolean | null;
  hint: string | null;
  source: "default" | "ui";
  updated_at: string | null;
  updated_by: string | null;
}

export interface SettingsValues {
  values: Record<string, SettingValue>;
}

export interface PatchResult {
  applied: string[];
  applies: Partial<Record<Applies, number>>; // only the buckets that changed are present
  /** Advisory notes about the configuration that resulted, keyed by the same
   *  dotted path a 422 error uses. A warning never refused the write; it is
   *  drawn on the card it names. */
  warnings?: Record<string, string>;
}

/** The wire format `GET /settings/export` writes, mirrored from
 *  `EXPORT_FORMAT` in `apps/api/app/api/v1/settings.py`. */
export const SETTINGS_EXPORT_FORMAT = "maljan-settings/2";
/** Every format `POST /settings/import` reads (`IMPORT_FORMATS`): `/1`, written
 *  before a built-in block's tool declarations were stored per tool, too. */
export const SETTINGS_IMPORT_FORMATS: readonly string[] = [SETTINGS_EXPORT_FORMAT, "maljan-settings/1"];

export interface ExportResponse {
  format: string;
  exported_at: string;
  values: Record<string, unknown>;
  /** Catalog keys the export left out because their stored value is a
   *  secret, plus informational nested paths (a server's dropped auth
   *  token) — see the API docstring. Not something the console renders
   *  today; kept on the type so a caller that wants it does not have to
   *  guess the shape. */
  secrets_omitted: string[];
}

export interface ImportRequest {
  format: string;
  values: Record<string, unknown>;
}

/** One tool of a server's capability manifest: what it needs on the server's
 *  host and whether it is there. `without` names what the tool still does
 *  when its dependency is missing. */
export interface CapabilityCell {
  name: string;
  optional_dependency: string | null;
  available: boolean;
  reason: string | null;
  timeout_s: number | null;
  remediation?: string;
  without?: string;
}

/** A server's `capabilities()` answer, computed on its host when it started. */
export interface CapabilityManifest {
  server: string;
  version: string;
  tools: CapabilityCell[];
}

/**
 * The context window the configured models serve, and what it buys one tool
 * answer. Mirrors `ContextWindowResponse` in
 * `apps/api/app/schemas/settings.py`.
 *
 * `source` is one of four words: `declared` (the settings name the window),
 * `probed` (the server reported it), `table` (the vendored figure for this
 * model family) and `fallback` (nothing answered). `cap` is what one answer
 * may take on an empty conversation, which is the most it can be; `derived`
 * is false when the operator set the cap themselves, and the window then
 * decides nothing.
 */
export interface ContextWindow {
  tokens: number;
  source: "declared" | "probed" | "table" | "fallback";
  detail: string;
  chars_per_token: number;
  reply_tokens: number;
  answer_share: number;
  cap: number;
  derived: boolean;
  setting: number;
  /** What an operator does about an unknown window. Empty when the window is
   *  known and there is nothing to do. */
  remedy: string;
}

/**
 * What a per-agent effort field may offer for one provider and model.
 * Mirrors `EffortOptionsResponse` in `apps/api/app/schemas/settings.py`.
 *
 * `takes_effort` false: the provider sends no reasoning effort and the field
 * is not drawn. `levels` is the list to choose from, or `null` where each
 * endpoint names its own levels and the value is typed as written.
 * `global_key`/`global_value` are the provider-wide setting a blank field
 * inherits.
 */
export interface EffortOptions {
  provider: string;
  model: string;
  takes_effort: boolean;
  levels: string[] | null;
  /** Offered levels the Models API's description said nothing about: the
   *  run sends them and the API answers, so they are offered and marked. */
  undescribed_levels: string[];
  levels_source: "models_api" | "settings" | "none";
  global_key: string | null;
  global_value: string | null;
}

export interface ProbeResult {
  ok: boolean;
  latency_ms: number;
  detail: string;
  models: string[] | null;
  /** The probed server's whole manifest, for the allow-list tick boxes. */
  tools: string[] | null;
  /** Probe-specific structured facts; the agent probe fills this in, and an
   *  MCP probe of a server that offers `capabilities` puts the manifest under
   *  `capabilities`. */
  details: AgentProbeDetails | { capabilities: CapabilityManifest } | Record<string, unknown> | null;
}

/** The unavailable tools of a probe result, or none when the server offers no
 *  manifest. */
export function unavailableTools(result: ProbeResult | null | undefined): CapabilityCell[] {
  const details = result?.details as { capabilities?: CapabilityManifest } | null | undefined;
  const cells = details?.capabilities?.tools;
  if (!Array.isArray(cells)) return [];
  return cells.filter((cell) => cell && cell.available === false);
}

/** What `POST /settings/servers/{key}/credential` answers with. The token
 *  never appears: `auth_token` is the same mask a stored server credential
 *  shows, and `facts` are the answer's values the server's declaration names
 *  (the service's own names for this deployment). */
export interface CredentialBootstrapResult {
  server: string;
  enabled: boolean;
  transport: string;
  url: string;
  auth_token: string;
  facts: Record<string, string>;
  tools: string[] | null;
}

export interface ChannelPreview {
  matched: number;
  kept: number;
  dropped: number;
  truncated: boolean;
  sample_rows: unknown[];
  error: string | null;
}

export interface MappingPreview {
  target_sha256: string;
  channels: Record<string, ChannelPreview>;
}

/* ── The ATT&CK cache (`/settings/attck*`) ─────────────────────────────── */

export type AttckDomain = "enterprise" | "mobile" | "ics";

/** What the cache holds for one domain, as the worker that holds it reads it. */
export interface AttckCached {
  present: boolean;
  /** False when a file is there and does not parse; `reason` says why. */
  readable?: boolean;
  reason?: string;
  version?: string;
  /** The release's own date (its collection's `modified`). */
  released?: string;
  techniques?: number;
  /** When the file was written or last confirmed current. */
  cached_at?: string;
  age_days?: number;
  written_by?: string;
}

export interface AttckDomainStatus extends AttckCached {
  domain: AttckDomain;
  label: string;
  next_check_at: string | null;
}

export interface AttckRelease {
  version: string;
  released: string;
}

export interface AttckCaller {
  user_id?: string;
  name?: string;
}

export interface AttckChange {
  domain: AttckDomain;
  label: string;
  from: string;
  to: string;
  released: string;
  techniques: number;
}

export interface AttckUpdateResult {
  ok: boolean;
  /** `updated`, `up_to_date`, `failed` or `busy`. */
  outcome: string;
  reason: string;
  started_at?: string;
  finished_at?: string;
  trigger?: string;
  triggered_by?: AttckCaller;
  changes: AttckChange[];
  kept_previous?: boolean;
}

export interface AttckCheckRow {
  domain: AttckDomain;
  label: string;
  cached: AttckCached;
  latest: AttckRelease | null;
  /** `current`, `outdated`, `missing` or `unlisted`; absent when the check failed. */
  state?: string;
}

export interface AttckCheckResult {
  ok: boolean;
  /** `up_to_date`, `outdated` or `failed`. A failed check is never up to date. */
  outcome: string;
  reason: string;
  checked_at: string | null;
  triggered_by?: AttckCaller;
  refresh_days: number | null;
  next_check_at: string | null;
  domains: AttckCheckRow[];
}

export interface AttckStatus {
  refresh_days: number;
  next_check_at: string | null;
  domains: AttckDomainStatus[];
  last_check: AttckCheckResult | null;
  last_update: AttckUpdateResult | null;
  running: { started_at?: string; trigger?: string; triggered_by?: AttckCaller } | null;
}

export interface AttckUpdateProgress {
  job_id: string;
  state: "queued" | "running" | "done" | "unknown";
  result: AttckUpdateResult | null;
}

export class SettingsValidationError extends Error {
  constructor(public errors: Record<string, string>) {
    super("validation failed");
  }
}
