/**
 * What an agent is called, wherever it is named.
 *
 * An operator names an analyst when they create it — ahmet, mehmet, cemal —
 * and that name is `label`. The key is the slug the settings map is keyed by
 * and the pipeline publishes under, which is the same string only until
 * somebody makes a second analyst and gets `ahmet_1`. Every list that showed
 * the key showed the slug: the stage list, the roster, the picker.
 *
 * So the label leads and the key follows it, quietly, where a reader needs to
 * match what they see against a settings map or a log line. An agent whose
 * label is empty, or the same as its key, is named once.
 */

import type { AgentDefinitionEntry } from "@/types/settings";

/** The name to draw, which is the operator's when there is one. */
export function agentDisplayName(
  key: string,
  definitions: Record<string, AgentDefinitionEntry> | null | undefined,
): string {
  const label = definitions?.[key]?.label?.trim();
  return label || key;
}

/** The key, when it says something the name does not. */
export function agentKeySuffix(
  key: string,
  definitions: Record<string, AgentDefinitionEntry> | null | undefined,
): string {
  return agentDisplayName(key, definitions) === key ? "" : key;
}

/** Both at once, for a place that has room for one string only. */
export function agentFullName(
  key: string,
  definitions: Record<string, AgentDefinitionEntry> | null | undefined,
): string {
  const suffix = agentKeySuffix(key, definitions);
  return suffix ? `${agentDisplayName(key, definitions)} (${suffix})` : key;
}
