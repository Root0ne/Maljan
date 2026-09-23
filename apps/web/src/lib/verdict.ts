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
 * nothing — and the analysis summary card rendered the bare "Malware"
 * string while the header showed "Malicious" for the same report. These
 * helpers are the single normalization point so every
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

export interface VerdictTone {
  /** The text colour class. */
  text: string;
  /** The border class a chip or a badge is outlined with. */
  border: string;
  /** The CSS colour a chart paints with. */
  fill: string;
}

/**
 * How each verdict is coloured, in one place.
 *
 * The dashboard's pie, its latest-runs chips, the analyses list, the search
 * palette and the analysis header each kept a map of their own, and nothing
 * but care kept the five agreeing. The colour is never the whole message:
 * every surface prints `verdictLabel` beside it.
 */
export const VERDICT_TONE: Record<VerdictBucket, VerdictTone> = {
  malicious: {
    text: "text-status-red",
    border: "border-status-red/40",
    fill: "var(--status-red)",
  },
  suspicious: {
    text: "text-status-orange",
    border: "border-status-orange/40",
    fill: "var(--status-orange)",
  },
  benign: {
    text: "text-status-green",
    border: "border-status-green/40",
    fill: "var(--status-green)",
  },
  unknown: {
    text: "text-text-muted",
    border: "border-text-muted/40",
    fill: "var(--text-muted)",
  },
};

/** The tone of any backend or legacy verdict string. */
export function verdictTone(v?: string | null): VerdictTone {
  return VERDICT_TONE[verdictBucket(v)];
}
