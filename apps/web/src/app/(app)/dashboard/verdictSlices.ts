import { verdictBucket, verdictLabel, type VerdictBucket } from "@/lib/verdict";

/**
 * The verdict chart's slices from the API's distribution. Every bucket is
 * drawn, "Unknown" included: a run with no verdict (inconclusive, or written
 * without one) is a run, and dropping it made the chart add up to fewer runs
 * than the page's own total.
 */
export function verdictSlices(
  distribution: Record<string, number> | null | undefined,
): { bucket: VerdictBucket; name: string; value: number }[] {
  const totals: Record<VerdictBucket, number> = { malicious: 0, suspicious: 0, benign: 0, unknown: 0 };
  for (const [key, value] of Object.entries(distribution ?? {})) {
    if (typeof value === "number" && Number.isFinite(value)) totals[verdictBucket(key)] += value;
  }
  return (["malicious", "suspicious", "benign", "unknown"] as const)
    .map((bucket) => ({ bucket, name: verdictLabel(bucket), value: totals[bucket] }))
    .filter((slice) => slice.value > 0);
}
