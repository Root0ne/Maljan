/**
 * The two top-line facts about a run, and what to say when they disagree.
 *
 * The PuTTY run headlined **Malicious · Confidence: 95/100** over a severity
 * card reading **Informational 0.5/10**, category `legitimate-software`, and
 * prose calling the sample "a legitimate, widely used administrative tool".
 * Both facts were on one screen, each stated confidently, with nothing saying
 * they contradicted each other — the worst thing a malware console can do,
 * because a reader has no way to know which one to believe.
 *
 * The console does not get to pick a winner: the verdict is the judge's and
 * the severity is the judge's, and overruling either here would be this view
 * inventing a finding. What it can do is say so. When the severity a verdict
 * implies and the severity the run actually assessed are more than one band
 * apart, the header carries both, attributed, in one line.
 *
 * The confidence is printed here and nowhere else, in one notation, which is
 * the other half of the same rule: it used to read `92/100` in the header and
 * `Confidence 0.92.` in the summary paragraph two hundred pixels below.
 */

import { verdictBucket, verdictLabel } from "./verdict";
import type { VerdictBucket } from "./verdict";
import type { SeverityRating } from "@/types/malware-report";

/** Severity ratings from least to most severe, which is what "a band" means. */
export const SEVERITY_ORDER: SeverityRating[] = [
  "Informational",
  "Low",
  "Medium",
  "High",
  "Critical",
];

/**
 * The severity band each verdict implies.
 *
 * Inclusive index pairs into `SEVERITY_ORDER`. A verdict of Malicious is
 * consistent with Medium and above, Benign with Low and below, and Suspicious
 * with everything in between; an unknown verdict implies nothing, so it can
 * never disagree with anything.
 */
const IMPLIED_BAND: Record<VerdictBucket, [number, number] | null> = {
  malicious: [2, 4],
  suspicious: [1, 3],
  benign: [0, 1],
  unknown: null,
};

/** Whether the verdict and the assessed severity are more than a band apart. */
export function verdictSeverityConflict(
  verdict: string | null | undefined,
  rating: SeverityRating | null | undefined,
): boolean {
  if (!rating) return false;
  const band = IMPLIED_BAND[verdictBucket(verdict)];
  if (!band) return false;
  const at = SEVERITY_ORDER.indexOf(rating);
  if (at < 0) return false;
  return at < band[0] || at > band[1];
}

/**
 * The confidence, in the one notation the console uses for it.
 *
 * `null` is not zero. A run whose judge never answered — the pipeline's own
 * fallback verdict — has no confidence at all, and zero is a confidence: the
 * lowest one there is.
 */
export function formatConfidence(value: number | null | undefined): string {
  return value === null || value === undefined ? "not assessed" : value.toFixed(2);
}

export interface VerdictHeadline {
  /** The one line the header chip carries. */
  text: string;
  /** Whether the two facts disagree, which is what the chip is coloured on. */
  conflict: boolean;
}

/**
 * The header's verdict chip.
 *
 * Agreeing, it is the verdict and its confidence. Disagreeing, it names both
 * facts and whose they are, so the contradiction is on the top line rather
 * than left for a reader to find two cards down.
 */
export function verdictHeadline(
  verdict: string | null | undefined,
  confidence: number | null | undefined,
  rating: SeverityRating | null | undefined,
): VerdictHeadline {
  const label = verdictLabel(verdict);
  const number = formatConfidence(confidence);
  if (!verdictSeverityConflict(verdict, rating)) {
    return { text: `${label} · Confidence: ${number}`, conflict: false };
  }
  return {
    text: `Judge: ${label} ${number} · Severity: ${rating}`,
    conflict: true,
  };
}

/** The sentence under a disagreeing header, which says what to do about it. */
export const VERDICT_CONFLICT_NOTE =
  "The verdict and the severity rating of this run disagree. Both are the " +
  "judge's own; read the severity card and the conversation before quoting " +
  "either.";
