/**
 * The severity ladder: its order and its colours, in one place.
 *
 * Severity was coloured in three maps that disagreed — Medium was purple on
 * the Summary and blue on DETECTION, Low blue on one and grey on the other —
 * and ordered nowhere: a list sorted by its label would put High before
 * Informational before Low before Medium, which is the alphabet rather than
 * the ladder. Every surface that compares a severity or colours one asks this
 * module, and a sort asks for the rank, never the label.
 *
 * The rungs are the judge's five words (`SEVERITY_RATINGS` in
 * `src/maljan/schemas/judgement.py`). A word is read without regard to case,
 * because the rule-match rows spell them in lower case. A word that is not a
 * rung has no rank and sorts below Informational rather than being placed by
 * guess; its colour is Informational's, and its own word is still what is
 * printed beside it, so the colour never carries the meaning alone.
 */

import type { SeverityRating } from "@/types/malware-report";

/** Highest first. */
export const SEVERITY_LADDER: readonly SeverityRating[] = [
  "Critical",
  "High",
  "Medium",
  "Low",
  "Informational",
];

/** The rung a word names, or null for a word that is not on the ladder. */
export function severityRung(label: string | null | undefined): SeverityRating | null {
  const wanted = String(label ?? "").trim().toLowerCase();
  return SEVERITY_LADDER.find((rung) => rung.toLowerCase() === wanted) ?? null;
}

/** Critical 4 down to Informational 0; -1 for a word that is not a rung. */
export function severityRank(label: string | null | undefined): number {
  const rung = severityRung(label);
  return rung === null ? -1 : SEVERITY_LADDER.length - 1 - SEVERITY_LADDER.indexOf(rung);
}

/** A comparator that puts the higher severity first. */
export function bySeverityDesc(a: string | null | undefined, b: string | null | undefined): number {
  return severityRank(b) - severityRank(a);
}

/** Items ordered highest severity first; equal severities keep their order. */
export function sortBySeverity<T>(items: readonly T[], severityOf: (item: T) => string): T[] {
  return [...items].sort((a, b) => bySeverityDesc(severityOf(a), severityOf(b)));
}

/** One dot per rung from Informational up (1 to 5); none for a word that is
 *  not a rung, which has no place on the ladder to draw. */
export function ladderDots(label: string | null | undefined): number {
  return severityRung(label) === null ? 0 : severityRank(label) + 1;
}

/** Whether `label` sits at or above `floor` on the ladder. A word that is not
 *  a rung is at or above nothing. */
export function atLeast(label: string | null | undefined, floor: SeverityRating): boolean {
  return severityRung(label) !== null && severityRank(label) >= severityRank(floor);
}

export interface SeverityTone {
  text: string;
  bg: string;
  border: string;
  /** A solid mark, for the dots a rule row draws. */
  dot: string;
}

const TONES: Record<SeverityRating, SeverityTone> = {
  Critical: {
    text: "text-status-red",
    bg: "bg-status-red/10",
    border: "border-status-red/30",
    dot: "bg-status-red",
  },
  High: {
    text: "text-status-orange",
    bg: "bg-status-orange/10",
    border: "border-status-orange/30",
    dot: "bg-status-orange",
  },
  Medium: {
    text: "text-status-purple",
    bg: "bg-status-purple/10",
    border: "border-status-purple/30",
    dot: "bg-status-purple",
  },
  Low: {
    text: "text-status-blue",
    bg: "bg-status-blue/10",
    border: "border-status-blue/30",
    dot: "bg-status-blue",
  },
  Informational: {
    text: "text-text-muted",
    bg: "bg-text-muted/10",
    border: "border-text-muted/30",
    dot: "bg-text-muted",
  },
};

/** How a severity word is coloured. */
export function severityTone(label: string | null | undefined): SeverityTone {
  return TONES[severityRung(label) ?? "Informational"];
}

/** The rung's own spelling, for a word that arrived in another case. */
export function severityWord(label: string | null | undefined): string {
  return severityRung(label) ?? String(label ?? "");
}

/** The tone of a number whose scale is not known: no rung, no colour. */
export const NEUTRAL_TONE: SeverityTone = {
  text: "text-text-secondary",
  bg: "bg-bg-active",
  border: "border-border",
  dot: "bg-text-muted",
};

export interface SignatureScale {
  /** The scale's own name, for the reader. */
  name: string;
  max: number;
  /** The rung each score from 1 to `max` means, by the scale's own
   *  documented reading of it. */
  rungs: readonly SeverityRating[];
}

/** Where a run summary records the signature scale its sandbox provider
 *  declared (`SIGNATURE_SCALE_KEY` in `src/maljan/core/report_formats.py`). */
export const SIGNATURE_SCALE_KEY = "sandbox_signature_scale";

/**
 * The legacy reader: the scales of the sandboxes whose scale was documented,
 * keyed by the provider a run records in `run_summary.settings_snapshot`
 * (`sandbox.provider`). Read only for a run summary without
 * `sandbox_signature_scale` (every run recorded before scales were recorded on
 * the run), so a stored run is drawn exactly as it always was.
 *
 * - `cape2`: a CAPEv2 signature declares a severity from 1 to 3 — low,
 *   medium, high.
 * - `triage`: a Hatching Triage signature carries a `score` from 1 to 10, the
 *   same scale as its sample score. 1 is no malicious behaviour; 2 to 5 is
 *   likely benign; 6 and 7 are suspicious; 8 and 9 are likely malicious; 10 is
 *   known bad.
 *
 * `upload`, `rest` and `mock` carried whatever report they were handed, so
 * they have none here.
 */
const LEGACY_SIGNATURE_SCALES: Record<string, SignatureScale> = {
  cape2: { name: "CAPE 1–3", max: 3, rungs: ["Low", "Medium", "High"] },
  triage: {
    name: "Triage 1–10",
    max: 10,
    rungs: [
      "Informational",
      "Low",
      "Low",
      "Low",
      "Low",
      "Medium",
      "Medium",
      "High",
      "High",
      "Critical",
    ],
  },
};

/** The legacy table's scale for a recorded provider, or null. */
export function legacySignatureScale(provider: string | null | undefined): SignatureScale | null {
  return LEGACY_SIGNATURE_SCALES[String(provider ?? "").trim().toLowerCase()] ?? null;
}

/** A recorded scale as a run summary carries it, or null when it is not one. */
function recordedScale(value: unknown): SignatureScale | null {
  if (!value || typeof value !== "object") return null;
  const { name, max, rungs } = value as { name?: unknown; max?: unknown; rungs?: unknown };
  if (typeof name !== "string" || !Array.isArray(rungs) || rungs.length === 0) return null;
  const read = rungs.map((r) => severityRung(typeof r === "string" ? r : null));
  if (read.some((r) => r === null)) return null;
  if (typeof max === "number" && max !== read.length) return null;
  return { name, max: read.length, rungs: read as SeverityRating[] };
}

/**
 * The scale a run's sandbox signatures are read on.
 *
 * A run summary that carries `sandbox_signature_scale` is read from it: the
 * scale the run's provider or report format declared, or null where it
 * declared none. A summary without the key is read by the legacy table, from
 * the provider in its settings snapshot.
 */
export function runSignatureScale(runSummary: unknown): SignatureScale | null {
  const summary =
    runSummary && typeof runSummary === "object" ? (runSummary as Record<string, unknown>) : null;
  if (summary && SIGNATURE_SCALE_KEY in summary) {
    return recordedScale(summary[SIGNATURE_SCALE_KEY]);
  }
  const snapshot = summary?.settings_snapshot as Record<string, unknown> | null | undefined;
  const provider = snapshot?.["sandbox.provider"];
  return legacySignatureScale(typeof provider === "string" ? provider : null);
}

export interface SignatureScore {
  tone: SeverityTone;
  /** The rung the score means on its scale, or null off it. */
  rung: SeverityRating | null;
  /** "8/10" on a known scale, the bare number otherwise. */
  label: string;
  /** The scale's name, or null when the run's scale is not known. */
  scale: string | null;
  /** What the badge prints: the rung in words beside the number — "High,
   *  8/10" — or "unrated" beside a number whose scale is not known, so the
   *  colour never carries the reading alone. */
  text: string;
}

/**
 * How a sandbox signature's number is drawn on `scale` (`runSignatureScale`).
 *
 * A whole score inside the scale takes the rung it means and prints as
 * "n/max". Anything else — no scale, or a number outside it — is drawn in one
 * neutral tone with the number as it came, rather than coloured by a guess.
 */
export function signatureScore(
  score: number | null,
  scale: SignatureScale | null | undefined
): SignatureScore {
  if (score === null || score === undefined) {
    // The sandbox gave no number: unknown, in the neutral tone, never a zero.
    return {
      tone: NEUTRAL_TONE,
      rung: null,
      label: "unknown",
      scale: scale?.name ?? null,
      text: "unknown",
    };
  }
  const whole = Number.isInteger(score);
  if (!scale || !whole || score < 1 || score > scale.max) {
    const label = String(score);
    return {
      tone: NEUTRAL_TONE,
      rung: null,
      label,
      scale: scale?.name ?? null,
      text: `unrated, ${label}`,
    };
  }
  const rung = scale.rungs[score - 1];
  const label = `${score}/${scale.max}`;
  return { tone: TONES[rung], rung, label, scale: scale.name, text: `${rung}, ${label}` };
}

/** Orders signatures by severity, highest first; an unknown (`null`) severity after every number. */
export function bySignatureSeverity(
  a: { severity: number | null },
  b: { severity: number | null }
): number {
  if (a.severity === null) return b.severity === null ? 0 : 1;
  if (b.severity === null) return -1;
  return b.severity - a.severity;
}
