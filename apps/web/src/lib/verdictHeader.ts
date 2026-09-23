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
 * inventing a finding. What it can do is say so. Where the two contradict
 * each other — and only there, see `CONTRADICTS` — the header carries both,
 * attributed, in one line.
 *
 * The confidence is printed here and nowhere else, in one notation, which is
 * the other half of the same rule: it used to read `92/100` in the header and
 * `Confidence 0.92.` in the summary paragraph two hundred pixels below.
 */

import { atLeast, severityRank } from "./severity";
import { verdictBucket, verdictLabel } from "./verdict";
import type { VerdictBucket } from "./verdict";
import type { VerdictReading } from "@/lib/api";
import type { MalwareReport, SeverityRating } from "@/types/malware-report";

/**
 * What a run says about its own severity, as three answers rather than two
 * absences.
 *
 * `null` and `undefined` were carrying that distinction, and nothing but a
 * comment stopped a caller writing `?? null` for "there is no report" — which
 * would have put the disagreement line on every running job. These are the
 * three states, and `assessedSeverity` is the one place that reads them off a
 * report, so no caller has to know which absence is which.
 */
export const NO_SEVERITY = "assessed none";
export const NO_REPORT = "no report yet";
export type AssessedSeverity = SeverityRating | typeof NO_SEVERITY | typeof NO_REPORT;

/** What a report says about its severity, in the three states above. */
export function assessedSeverity(
  malwareReport: MalwareReport | null | undefined,
): AssessedSeverity {
  if (!malwareReport) return NO_REPORT;
  return malwareReport.severity?.rating ?? NO_SEVERITY;
}

/**
 * The severity a verdict has to be read against before it contradicts it.
 *
 * Narrow on purpose. A Malicious verdict at Low severity is what adware,
 * unwanted programs and riskware look like on a coherent report, and telling
 * that reader the run disagrees with itself — and not to trust either number —
 * would spend exactly the trust this rule exists to protect. Two shapes are
 * left, and both are the kind a reader has to be told about:
 *
 * * a malicious verdict over the lowest rating there is, or over no rating at
 *   all, which is the PuTTY run the audit found: "Malicious 0.95" over
 *   "Informational 0.5/10" and prose calling the sample legitimate;
 * * a benign verdict over High or Critical, which is the same fault mirrored.
 *
 * Suspicious sits between the two by definition and can disagree with nothing;
 * an unknown verdict implies nothing, so it disagrees with nothing either.
 */
const CONTRADICTS: Partial<Record<VerdictBucket, (severity: AssessedSeverity) => boolean>> = {
  // The bottom rung of the ladder, whatever it is called, or no rung at all.
  malicious: (severity) => severity === NO_SEVERITY || severityRank(severity) === 0,
  benign: (severity) => atLeast(severity, "High"),
};

/**
 * Whether the verdict and the assessed severity contradict each other.
 *
 * `NO_SEVERITY` is a run with a severity block and a judge that assessed no
 * rating into it — a malicious verdict with nothing behind it, which is worth
 * saying. `NO_REPORT` is a run with no structured report at all: one still
 * going, or one written before the report payload existed. There is no
 * severity there to disagree with, and announcing a contradiction would be
 * this view inventing one out of a report nobody has written yet.
 */
export function verdictSeverityConflict(
  verdict: string | null | undefined,
  severity: AssessedSeverity,
): boolean {
  if (severity === NO_REPORT) return false;
  const against = CONTRADICTS[verdictBucket(verdict)];
  return against ? against(severity) : false;
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
  severity: AssessedSeverity,
): VerdictHeadline {
  const label = verdictLabel(verdict);
  const number = formatConfidence(confidence);
  if (!verdictSeverityConflict(verdict, severity)) {
    return { text: `${label} · Confidence: ${number}`, conflict: false };
  }
  const rating = severity === NO_SEVERITY ? "not assessed" : severity;
  // The number is labelled only where it is not one: "Malicious 0.95" reads as
  // a confidence in the place a reader expects one, but "Malicious not
  // assessed" does not read as anything.
  const judged = confidence === null || confidence === undefined
    ? `${label} · Confidence: ${number}`
    : `${label} ${number}`;
  return { text: `Judge: ${judged} · Severity: ${rating}`, conflict: true };
}

/** The sentence under a disagreeing header, which says what to do about it. */
export const VERDICT_CONFLICT_NOTE =
  "The verdict and the severity rating of this run disagree. Both are the " +
  "judge's own; read the severity card and the conversation before quoting " +
  "either.";

/**
 * What to say beside a verdict the judge did not state.
 *
 * Three of the four readings publish the inconclusive verdict, which is one of
 * the same three words a judge may state, so the word alone cannot be read: a
 * `Suspicious` the judge concluded and a `Suspicious` the pipeline fell back to
 * look identical. The markdown header has said which since the reading existed;
 * this is the same sentence for the two surfaces a reader actually opens.
 *
 * `stated`, and an absent reading — every report stored before the field —
 * draw nothing.
 */
const READING_NOTES: Partial<Record<VerdictReading, string>> = {
  unrecognised:
    "The judge answered with something this pipeline could not read as a " +
    "verdict, so the verdict above is not the judge's. Its own answer is in " +
    "the degraded-run reasons, and no confidence is published for it.",
  unstated:
    "The judge stated no verdict, so the verdict above was read from the " +
    "objects in its bundle rather than from anything it said, and no " +
    "confidence is published for it.",
  fallback:
    "The judge did not answer with a bundle, so the verdict above was read " +
    "out of its text, or written by the pipeline when there was no text to " +
    "read, and no confidence is published for it.",
};

/** The one-line note a reading earns beside the verdict, or `null`. */
export function verdictReadingNote(
  reading: VerdictReading | null | undefined,
): string | null {
  return (reading && READING_NOTES[reading]) || null;
}
