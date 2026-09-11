import type { Applies } from "@/types/settings";

/** The two places a setting's value can come from, once the mandatory
 *  encryption key retired the third (`.env`, removed in an earlier task on
 *  this branch): the catalog's built-in default, or a value an operator
 *  saved through the UI. */
export const SOURCE_LABEL: Record<"default" | "ui", string> = {
  default: "default",
  ui: "ui",
};

export const APPLIES_LABEL: Record<Applies, string> = {
  next_job: "next analysis",
  live: "immediately",
  restart: "after a restart",
};

export const APPLIES_SENTENCE: Record<Applies, string> = {
  next_job: "takes effect on the next analysis",
  live: "takes effect immediately",
  restart: "takes effect after a restart",
};

const APPLIES_ORDER: Applies[] = ["next_job", "live", "restart"];

/** Per-bucket count suffix — distinct from `APPLIES_LABEL` because
 *  `next_job` needs the "on the" connector here and doesn't in the rail
 *  label ("next analysis" vs. "2 on the next analysis"). */
const APPLIES_COUNT_SUFFIX: Record<Applies, string> = {
  next_job: "on the next analysis",
  live: "immediately",
  restart: "after a restart",
};

/** "Applied 3 settings · 2 on the next analysis · 1 immediately" */
export function appliesSummary(
  counts: Partial<Record<Applies, number>>,
  total: number
): string {
  const parts = [`Applied ${total} setting${total === 1 ? "" : "s"}`];
  for (const key of APPLIES_ORDER) {
    const n = counts[key];
    if (n) parts.push(`${n} ${APPLIES_COUNT_SUFFIX[key]}`);
  }
  return parts.join(" · ");
}
