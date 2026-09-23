/* One agent's ordered model list, as the agent editor stages it.
 *
 * Kept apart from the editor so the rules a stored list follows can be read
 * and tested without a component around them.
 */

/** One model of an agent's list, mirroring `maljan.core.config.ModelChoice`. */
export interface ModelChoice {
  provider: string;
  model: string;
  temperature?: number | null;
  base_url?: string | null;
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
  return out;
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
