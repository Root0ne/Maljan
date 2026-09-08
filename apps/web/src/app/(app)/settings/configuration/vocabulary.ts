import type { Applies } from "@/types/settings";

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

/** "Applied 3 settings · 2 on the next analysis · 1 immediately" */
export function appliesSummary(
  counts: Partial<Record<Applies, number>>,
  total: number
): string {
  const parts = [`Applied ${total} setting${total === 1 ? "" : "s"}`];
  for (const key of APPLIES_ORDER) {
    const n = counts[key];
    if (n) parts.push(`${n} ${APPLIES_LABEL[key]}`);
  }
  return parts.join(" · ");
}
