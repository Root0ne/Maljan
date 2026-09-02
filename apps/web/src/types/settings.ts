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
  applies: Record<Applies, number>;
}

export interface ProbeResult {
  ok: boolean;
  latency_ms: number;
  detail: string;
  models: string[] | null;
}

export class SettingsValidationError extends Error {
  constructor(public errors: Record<string, string>) {
    super("validation failed");
  }
}
