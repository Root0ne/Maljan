/**
 * Shared verdict taxonomy helpers.
 *
 * The backend's comprehensive report emits the verdict vocabulary
 * "Malware" | "Suspicious" | "Benign" (see backend `reporting/models.py`),
 * while the UI's display + filter convention (dashboard pie, reports filter
 * chips, analysis header badge) uses "Malicious" / "Suspicious" / "Benign".
 *
 * Left unmapped, a raw "Malware" verdict matched none of the "malicious"
 * filter buckets — every report fell into Malicious(0) and the filter showed
 * nothing (audit M1) — and the analysis summary card rendered the bare
 * "Malware" string while the header showed "Malicious" for the same report
 * (audit L1). These helpers are the single normalization point so every
 * surface agrees.
 */

export type VerdictBucket = "malicious" | "suspicious" | "benign" | "unknown";

/** Normalize any backend/legacy verdict string to a canonical bucket key. */
export function verdictBucket(v?: string | null): VerdictBucket {
  const s = (v ?? "").trim().toLowerCase();
  if (s === "malware" || s === "malicious") return "malicious";
  if (s === "suspicious") return "suspicious";
  if (s === "benign") return "benign";
  return "unknown";
}

const VERDICT_LABELS: Record<VerdictBucket, string> = {
  malicious: "Malicious",
  suspicious: "Suspicious",
  benign: "Benign",
  unknown: "Unknown",
};

/** Human-facing display label, consistent across every surface. */
export function verdictLabel(v?: string | null): string {
  return VERDICT_LABELS[verdictBucket(v)];
}
