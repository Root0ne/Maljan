/* One agent's ordered model list, as the agent editor stages it.
 *
 * Kept apart from the editor so the rules a stored list follows can be read
 * and tested without a component around them.
 */

import type { EffortOptions } from "@/types/settings";

/** One model of an agent's list, mirroring `maljan.core.config.ModelChoice`. */
export interface ModelChoice {
  provider: string;
  model: string;
  temperature?: number | null;
  base_url?: string | null;
  /** This model's own reasoning effort; absent inherits the global effort
   *  setting its provider declares. */
  effort?: string | null;
}

/** Whether a provider takes a per-agent endpoint: the providers that declare
 *  one, as the settings schema serves them (`agentEndpointProviders`). */
export function hasEndpoint(provider: string, endpointProviders: ReadonlySet<string>): boolean {
  return endpointProviders.has(provider);
}

/** A fallback as it is stored: blank fields dropped, an endpoint only where
 *  the provider takes one. `null` for a row with no model yet, which is
 *  kept on screen and not staged. */
export function storedChoice(
  choice: ModelChoice,
  endpointProviders: ReadonlySet<string>
): ModelChoice | null {
  if (!choice.provider || !choice.model) return null;
  const out: ModelChoice = { provider: choice.provider, model: choice.model };
  if (choice.temperature !== null && choice.temperature !== undefined) {
    out.temperature = choice.temperature;
  }
  if (choice.base_url && hasEndpoint(choice.provider, endpointProviders)) {
    out.base_url = choice.base_url;
  }
  if (choice.effort && choice.effort.trim()) out.effort = choice.effort.trim();
  return out;
}

/** The choice moved to `provider`. An effort belongs to the provider it was
 *  chosen for (each names its own levels, and some take none), so a change
 *  of provider drops it rather than staging one the API would refuse. */
export function withProvider<T extends ModelChoice>(choice: T, provider: string): T {
  if (choice.provider === provider) return choice;
  const next = { ...choice, provider };
  delete next.effort;
  return next;
}

/** An agent entry with `next` merged in. Its effort is kept unless the
 *  provider in force changes: a blank provider is the global one, so naming
 *  the global provider explicitly keeps an effort chosen for it. */
export function mergeEntry<T extends ModelChoice>(
  base: T,
  next: Partial<T>,
  globalProvider: string | null,
): T {
  const merged: T = { ...base, ...next };
  if (next.provider === undefined) return merged;
  const was = base.provider || globalProvider || "";
  const now = next.provider || globalProvider || "";
  if (was !== now) delete merged.effort;
  return merged;
}

/** How the effort field is drawn, from what the backend served for the
 *  provider and model on screen. */
export type EffortField =
  | { kind: "hidden" }
  | { kind: "select"; choices: { value: string; label: string }[] }
  | { kind: "text"; placeholder: string };

export function effortField(options: EffortOptions | null, value: string): EffortField {
  if (options === null) return { kind: "text", placeholder: "inherit" };
  if (!options.takes_effort) return { kind: "hidden" };
  const inherited = options.global_value ?? "the model's default";
  if (options.levels === null) {
    return { kind: "text", placeholder: `inherit (${inherited})` };
  }
  const choices = [
    { value: "", label: `Inherit (${inherited})` },
    ...options.levels.map((level) => ({
      value: level,
      label: (options.undescribed_levels ?? []).includes(level)
        ? `${level} (not described for this model)`
        : level,
    })),
  ];
  if (value && !options.levels.includes(value)) {
    choices.push({ value, label: `${value} (not offered for this model)` });
  }
  return { kind: "select", choices };
}

/** The list with the row at `index` moved by `by` places, clamped to the ends. */
export function moveChoice(list: ModelChoice[], index: number, by: number): ModelChoice[] {
  const target = Math.max(0, Math.min(list.length - 1, index + by));
  if (target === index) return list;
  const next = [...list];
  const [row] = next.splice(index, 1);
  next.splice(target, 0, row!);
  return next;
}

/** An agent's own ceiling as typed into its field: a positive number, `null`
 *  for a blank field (no ceiling), or `undefined` for text that is neither,
 *  which is not staged. `whole` takes integers only (the token ceiling). */
export function ceilingValue(raw: string, whole = false): number | null | undefined {
  const text = raw.trim();
  if (text === "") return null;
  const parsed = Number(text);
  if (!Number.isFinite(parsed) || parsed <= 0) return undefined;
  if (whole && !Number.isInteger(parsed)) return undefined;
  return parsed;
}

/** An agent's own ceilings, mirroring `AgentLLMConfig.max_spend_usd` and
 *  `max_unpriced_tokens`. Absent is no ceiling. */
export interface AgentCeilings {
  max_spend_usd?: number | null;
  max_unpriced_tokens?: number | null;
}

/** The ceilings an entry stores: each one set, and none left as `null`, so
 *  an entry with no ceiling is staged exactly as it was before they existed. */
export function storedCeilings(entry: AgentCeilings): AgentCeilings {
  const out: AgentCeilings = {};
  if (typeof entry.max_spend_usd === "number" && entry.max_spend_usd > 0) {
    out.max_spend_usd = entry.max_spend_usd;
  }
  if (typeof entry.max_unpriced_tokens === "number" && entry.max_unpriced_tokens > 0) {
    out.max_unpriced_tokens = entry.max_unpriced_tokens;
  }
  return out;
}
