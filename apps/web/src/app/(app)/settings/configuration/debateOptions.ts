import type { DebateOptionsEntry } from "@/types/settings";

/**
 * The debate options after one box changed.
 *
 * The card used to fill the fields the operator had not touched with numbers
 * of its own (3 rounds, a 0.8 threshold) and read an emptied box as 0, so one
 * edit wrote values nobody chose, copies of defaults that drift from the API's.
 * Now only what the operator set is sent: a field left out takes the value the
 * API gives it, and a box emptied again is left out. `null` when nothing is
 * left, which is "inherit the global settings".
 */
export function patchDebate(
  current: DebateOptionsEntry | null,
  field: keyof DebateOptionsEntry,
  value: number | boolean | null,
): DebateOptionsEntry | null {
  const next: Record<string, number | boolean> = { ...(current ?? {}) };
  if (value === null || (typeof value === "number" && !Number.isFinite(value))) delete next[field];
  else next[field] = value;
  // The sycophancy check is on unless said otherwise, so a lone "on" says
  // nothing: with no other field set, that is no debate options at all.
  const keys = Object.keys(next);
  if (keys.length === 0) return null;
  if (keys.length === 1 && next.sycophancy_check === true) return null;
  return next as DebateOptionsEntry;
}

/** A number box's text as a value: `null` for an empty box, never 0. */
export function boxNumber(text: string): number | null {
  const trimmed = text.trim();
  if (trimmed === "") return null;
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : null;
}

/** The debate line of a change summary, naming only what is set. */
export function describeDebate(debate: DebateOptionsEntry | null): string {
  if (!debate) return "debate options cleared";
  const parts: string[] = [];
  if (debate.max_rounds !== undefined) parts.push(`${debate.max_rounds} round(s)`);
  if (debate.consensus_threshold !== undefined) parts.push(`threshold ${debate.consensus_threshold}`);
  // Named when it is off (the unusual case) or is all that is set.
  if (debate.sycophancy_check === false || (parts.length === 0 && debate.sycophancy_check === true)) {
    parts.push(`sycophancy check ${debate.sycophancy_check ? "on" : "off"}`);
  }
  return `debate ${parts.join(", ")}`;
}

/**
 * What the API uses for a debate field the stage leaves out: the defaults of
 * `maljan.core.config.DebateOptions`. The settings schema does not serve them
 * (needs API), so they are named here once, with their source, and only ever
 * shown, never sent.
 */
export const DEBATE_MODEL_DEFAULTS = { max_rounds: 3, consensus_threshold: 0.8 } as const;

/** The placeholder of an empty debate box. A stage with no debate options at
 *  all inherits the global settings it was seeded from; one with some set
 *  gives the rest the model's default, and the box says that number. */
export function debatePlaceholder(
  debate: DebateOptionsEntry | null,
  field: keyof typeof DEBATE_MODEL_DEFAULTS,
): string {
  return debate === null ? "global" : `${DEBATE_MODEL_DEFAULTS[field]} (default)`;
}
