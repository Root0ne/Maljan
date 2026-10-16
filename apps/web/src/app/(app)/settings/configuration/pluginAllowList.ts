/**
 * The plugin allow-list editor's rules, from what `GET /settings/plugins` serves.
 *
 * Kept apart from the component so each rule is tested on its own: the list
 * holds names only and ticking keeps the other entries in their order; a row
 * says what the metadata says of its plugin, and apart from it what the API
 * process made of it where the API loaded it, never as the worker's; a
 * plugin the metadata refuses cannot be ticked; and an entry no installed
 * package declares stays in view until it is removed.
 */

import type { InstalledPlugin, PluginKind, PluginsListing } from "@/types/settings";

/** The setting the editor writes. */
export const PLUGIN_ALLOW_LIST_KEY = "core.plugins.allowed";

/** What allowing a plugin trusts, said above the list. */
export const TRUST_NOTE =
  "Allowing a plugin runs its package's code in the workers, and in the API where it runs that " +
  "plugin's own code, with their access to the settings, the samples and the network. Nothing " +
  "installed is loaded until it is allowed here.";

/** Where a worker's load result is, said above the list. */
export const WORKER_NOTE =
  "Whether an allowed plugin loads in the analysis worker is written to the worker's log: each " +
  "load with its package and version, each failure with its reason. The API column is the API " +
  "process's own load, where it ran the plugin's code.";

/** The allow-list a staged or saved value holds: its names, in order. */
export function allowListOf(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((v): v is string => typeof v === "string") : [];
}

/** The list with `entry` allowed or not; every other entry stays where it was. */
export function withEntry(list: string[], entry: string, allowed: boolean): string[] {
  const without = list.filter((e) => e !== entry);
  return allowed ? [...without, entry] : without;
}

export type StatusTone = "ok" | "error" | "muted";

/** What a row says of its plugin from the metadata, against the list the next apply leaves. */
export function pluginStatus(
  plugin: InstalledPlugin,
  allowedNext: boolean
): { text: string; tone: StatusTone } {
  if (plugin.state === "refused") return { text: `Refused: ${plugin.error}`, tone: "error" };
  if (allowedNext === plugin.allowed) {
    return allowedNext
      ? { text: "Allowed", tone: "ok" }
      : { text: "Not allowed; its code is not loaded", tone: "muted" };
  }
  return allowedNext
    ? { text: "Allowed once the change is applied", tone: "muted" }
    : { text: "Not allowed once the change is applied", tone: "muted" };
}

/** What the API process made of the plugin, where it loaded it; empty when it never did. */
export function apiStatus(plugin: InstalledPlugin): { text: string; tone: StatusTone } {
  switch (plugin.api_state) {
    case "loaded":
      return { text: "Loaded in the API", tone: "ok" };
    case "failed":
      return { text: `Failed in the API: ${plugin.api_error}`, tone: "error" };
    case "refused":
      return { text: `Refused in the API: ${plugin.api_error}`, tone: "error" };
    default:
      return { text: "Not loaded in the API", tone: "muted" };
  }
}

export interface PluginRow {
  name: string;
  entry: string;
  distribution: string;
  version: string;
  /** Ticked: what the next apply leaves in force. */
  allowed: boolean;
  /** Refused by its metadata whatever the list says (a built-in id, two packages). */
  refused: boolean;
  status: string;
  tone: StatusTone;
  api: string;
  apiTone: StatusTone;
}

/** One kind's plugins as the editor draws them, against the list the next apply leaves. */
export function pluginRows(kind: PluginKind, list: string[]): PluginRow[] {
  const allowed = new Set(list);
  return kind.plugins.map((plugin) => {
    const next = allowed.has(plugin.entry);
    const { text, tone } = pluginStatus(plugin, next);
    const api = apiStatus(plugin);
    return {
      name: plugin.name,
      entry: plugin.entry,
      distribution: plugin.distribution,
      version: plugin.version,
      allowed: next,
      refused: plugin.state === "refused",
      status: text,
      tone,
      api: api.text,
      apiTone: api.tone,
    };
  });
}

/** The list's entries that no installed package declares, in the list's order. */
export function absentEntries(listing: PluginsListing, list: string[]): string[] {
  const installed = new Set(listing.kinds.flatMap((kind) => kind.plugins.map((p) => p.entry)));
  return list.filter((entry) => !installed.has(entry));
}
