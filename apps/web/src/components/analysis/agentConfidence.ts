/**
 * An agent's confidence in its OWN claim, as a whole percent, or null when
 * the finding states none (a missing value would otherwise draw "NaN%" or,
 * coerced, "0%").
 */
export function confidencePercent(value: unknown): number | null {
  if (typeof value !== "number" || !Number.isFinite(value)) return null;
  return Math.round(value * 100);
}

/**
 * The colour of a confidence bar. Confidence is how sure the agent is, not
 * how dangerous the sample is: a benign finding at 100% is not a red bar, so
 * the bar is one neutral colour at every level.
 */
export const CONFIDENCE_BAR_COLOR = "var(--accent, var(--text-secondary))";
