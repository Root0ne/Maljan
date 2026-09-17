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
  | "profiles";

export type Editor = "server_map" | "rest_sandbox" | "agent_definitions" | "stages";

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
 */
export interface ToolRefEntry {
  kind: "mcp" | "provider" | "sandbox" | "agent";
  server: string | null;
  name: string | null;
  agent?: string | null;
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
  mode: StageMode;
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

/** `ProbeResult.details` as the agent probe fills it in. */
export interface AgentProbeDetails {
  prompt_chars: number;
  prompt_sha256: string;
  /** The full resolved prompt. Operator text, not a secret (spec §11) — the
   *  settings UI shows it read-only on a built-in card and a clone seeds its
   *  copy from it. */
  prompt: string;
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

/** The wire format both `GET /settings/export` and `POST /settings/import`
 *  speak, mirrored from `ExportResponse` / `ImportRequest` in
 *  `apps/api/app/schemas/settings.py`. */
export const SETTINGS_EXPORT_FORMAT = "maljan-settings/1";

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

/** What `POST /settings/virustotal/register` answers with. The token never
 *  appears: `auth_token` is the same mask a stored server credential shows,
 *  and the agent id and public handle are VirusTotal's own names for this
 *  deployment. */
export interface VirustotalRegistration {
  server: string;
  enabled: boolean;
  transport: string;
  url: string;
  auth_token: string;
  agent_id: string;
  public_handle: string;
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

export class SettingsValidationError extends Error {
  constructor(public errors: Record<string, string>) {
    super("validation failed");
  }
}
