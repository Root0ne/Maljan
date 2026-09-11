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

export type Editor = "server_map" | "rest_sandbox" | "agent_definitions" | "profiles";

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
  tool_selection: string;
  use_all_tools: boolean;
  tools: string[] | null;
  agents: string[];
  label: string;
}

/**
 * One tool source an agent definition asks for, mirroring
 * `maljan.core.config.ToolRef`. `kind: "mcp"` names a server and, optionally,
 * one of its tools — `name: null` means the server's whole allow-listed set.
 * `kind: "provider"` means "this agent's static provider's tools" and carries
 * nothing else.
 */
export interface ToolRefEntry {
  kind: "mcp" | "provider";
  server: string | null;
  name: string | null;
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
  role: "static" | "dynamic" | "network" | "judge" | "generic";
  label: string;
  prompt: string | null;
  tools: ToolRefEntry[];
  static_provider: string | null;
  enabled: boolean;
}

/** One entry of the `agents.profiles` map: an ordered list of analyst keys. */
export interface ProfileEntry {
  label: string;
  analysts: string[];
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
  secrets_available: boolean;
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
}

export interface ProbeResult {
  ok: boolean;
  latency_ms: number;
  detail: string;
  models: string[] | null;
  /** The probed server's whole manifest, for the allow-list tick boxes. */
  tools: string[] | null;
  /** Probe-specific structured facts; the agent probe fills this in. */
  details: AgentProbeDetails | Record<string, unknown> | null;
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
