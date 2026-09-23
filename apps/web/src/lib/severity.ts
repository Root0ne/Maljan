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

/**
 * How a sandbox signature's numeric severity is coloured.
 *
 * The number is the sandbox's own and is printed as it is; this only picks
 * the colour it is drawn in, from the same ladder, with the thresholds the
 * DYNAMIC tab has always used: 7 and above as Critical, 4 and above as High,
 * anything lower as Informational.
 */
export function scoreTone(score: number): SeverityTone {
  if (score >= 7) return TONES.Critical;
  if (score >= 4) return TONES.High;
  return TONES.Informational;
}
