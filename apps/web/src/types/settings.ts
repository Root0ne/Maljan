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

export type ChoicesFrom = "static_providers" | "sandbox_providers" | "mcp_servers" | "agent_roles";

export type Editor = "server_map" | "rest_sandbox";

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
   *  row's `source` is: a UI-saved secret row, `.env`, or nothing set. */
  auth_token_source: "ui" | "env" | "default";
  tool_selection: string;
  use_all_tools: boolean;
  tools: string[] | null;
  agents: string[];
  label: string;
}

export interface SettingsGroup {
  key: string;
  title: string;
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
  source: "default" | "env" | "ui";
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
