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
  /** This model's own reasoning effort; absent inherits the provider's
   *  global one (`llm.anthropic.effort` / `llm.openai.reasoning_effort`). */
  effort?: string | null;
}

/** Whether a provider takes a per-agent endpoint. */
export function hasEndpoint(provider: string): boolean {
  return provider === "openai" || provider === "ollama";
}

/** A fallback as it is stored: blank fields dropped, an endpoint only where
 *  the provider takes one. `null` for a row with no model yet, which is
 *  kept on screen and not staged. */
export function storedChoice(choice: ModelChoice): ModelChoice | null {
  if (!choice.provider || !choice.model) return null;
  const out: ModelChoice = { provider: choice.provider, model: choice.model };
  if (choice.temperature !== null && choice.temperature !== undefined) {
    out.temperature = choice.temperature;
  }
  if (choice.base_url && hasEndpoint(choice.provider)) out.base_url = choice.base_url;
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
    ...options.levels.map((level) => ({ value: level, label: level })),
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
