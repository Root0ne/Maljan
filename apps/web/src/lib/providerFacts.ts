/**
 * What the settings schema says about each provider, read in one place.
 *
 * Every registered provider declares its own title, description, credential
 * keys, whether it is hosted, its connection test, whether an agent may give
 * it an endpoint of its own and its effort setting; the API serves those on
 * the provider selector's catalog entry and the probe labels at the top of
 * the schema. Nothing here names a provider: a provider registered tomorrow
 * is described the day it is registered, and one the schema says nothing
 * about reads as its own id.
 */

import type { CatalogEntry, ChoiceFacts, SettingsSchema } from "@/types/settings";

export const LLM_SELECTOR = "core.llm.provider";
export const STATIC_SELECTOR = "core.static.provider";
export const SANDBOX_SELECTOR = "core.sandbox.provider";

/** The catalog entry for `key`, or undefined when the schema has none. */
export function catalogEntry(
  schema: SettingsSchema | null | undefined,
  key: string
): CatalogEntry | undefined {
  for (const group of schema?.groups ?? []) {
    const found = group.entries.find((entry) => entry.key === key);
    if (found) return found;
  }
  return undefined;
}

/** The title a provider declares for itself, else its id. */
export function choiceTitle(
  schema: SettingsSchema | null | undefined,
  selectorKey: string,
  choice: string
): string {
  return catalogEntry(schema, selectorKey)?.choice_titles?.[choice] || choice;
}

/** The one-line description a provider declares, or "". */
export function choiceDescription(
  schema: SettingsSchema | null | undefined,
  selectorKey: string,
  choice: string
): string {
  return catalogEntry(schema, selectorKey)?.choice_descriptions?.[choice] ?? "";
}

/** The facts a provider declares about itself, or an empty object. */
export function choiceFacts(
  schema: SettingsSchema | null | undefined,
  selectorKey: string,
  choice: string
): ChoiceFacts {
  return catalogEntry(schema, selectorKey)?.choice_facts?.[choice] ?? {};
}

/** The label of a connection test, as the API names it; "Test <id>" otherwise. */
export function probeLabelFrom(
  schema: SettingsSchema | null | undefined,
  probeId: string
): string {
  return schema?.probe_labels?.[probeId] ?? `Test ${probeId}`;
}

/** The LLM providers whose models an agent may point at an endpoint of its own. */
export function agentEndpointProviders(
  schema: SettingsSchema | null | undefined
): ReadonlySet<string> {
  const facts = catalogEntry(schema, LLM_SELECTOR)?.choice_facts ?? {};
  return new Set(
    Object.entries(facts)
      .filter(([, fact]) => fact.agent_base_url === true)
      .map(([provider]) => provider)
  );
}

function serverMapEntry(schema: SettingsSchema | null | undefined): CatalogEntry | undefined {
  for (const group of schema?.groups ?? []) {
    const found = group.entries.find((entry) => entry.editor === "server_map");
    if (found) return found;
  }
  return undefined;
}

/** The built-in tool-server keys, as core defines them. */
export function builtinServerKeys(schema: SettingsSchema | null | undefined): ReadonlySet<string> {
  return new Set(serverMapEntry(schema)?.builtin_servers ?? []);
}

/** The tool-server keys no operator's server may take, as core defines them. */
export function reservedServerKeys(schema: SettingsSchema | null | undefined): ReadonlySet<string> {
  return new Set(serverMapEntry(schema)?.reserved_servers ?? []);
}
