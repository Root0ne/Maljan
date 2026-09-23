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

interface SignatureScale {
  /** The provider's own name for the scale, for the reader. */
  name: string;
  max: number;
  /** The rung each score from 1 to `max` means, by the provider's own
   *  documented reading of it. */
  rungs: readonly SeverityRating[];
}

/**
 * The signature scales of the sandboxes whose scale is documented, keyed by
 * the provider a run records in `run_summary.settings_snapshot`
 * (`sandbox.provider`).
 *
 * - `cape2`: a CAPEv2 (and Cuckoo) signature declares a severity from 1 to 3 —
 *   low, medium, high.
 * - `triage`: a Hatching Triage signature carries a `score` from 1 to 10, the
 *   same scale as its sample score. 1 is no malicious behaviour; 2 to 5 is
 *   likely benign; 6 and 7 are suspicious; 8 and 9 are likely malicious; 10 is
 *   known bad. The provider writes that score into the same `severity` field
 *   (`src/maljan/schemas/sandbox_report.py`), which is why the scale has to
 *   come from the provider and never from the number.
 *
 * `upload`, `rest` and `mock` carry whatever report they were handed, which
 * may be on either scale, so they have none here.
 */
const SIGNATURE_SCALES: Record<string, SignatureScale> = {
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

export interface SignatureScore {
  tone: SeverityTone;
  /** The rung the score means on its provider's scale, or null off it. */
  rung: SeverityRating | null;
  /** "8/10" on a known scale, the bare number otherwise. */
  label: string;
  /** The scale's name, or null when the provider's scale is not known. */
  scale: string | null;
}

/**
 * How a sandbox signature's number is drawn.
 *
 * On a provider whose scale is documented, a whole score inside that scale
 * takes the rung it means and prints as "n/max". Anything else — a provider
 * whose report could be on either scale, one this console does not know, or a
 * number outside its provider's scale — is drawn in one neutral tone with the
 * number as it came, rather than coloured by a guess.
 */
export function signatureScore(score: number, provider: string | null | undefined): SignatureScore {
  const scale = SIGNATURE_SCALES[String(provider ?? "").trim().toLowerCase()];
  const whole = Number.isInteger(score);
  if (!scale || !whole || score < 1 || score > scale.max) {
    return { tone: NEUTRAL_TONE, rung: null, label: String(score), scale: scale?.name ?? null };
  }
  const rung = scale.rungs[score - 1];
  return { tone: TONES[rung], rung, label: `${score}/${scale.max}`, scale: scale.name };
}
