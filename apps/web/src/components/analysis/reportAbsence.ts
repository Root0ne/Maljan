/**
 * What a tab says when there is no report to draw from, and why there is none.
 *
 * Every report tab reads its blocks off the report and, finding none, printed
 * its empty state: "No identifying tool answered", "This run wrote no
 * defensive recommendation", "No rule fired on this sample". With no report
 * at all — a run still going, a by-job fetch that failed, a run that ended
 * before writing one — each of those is a negative finding the run never
 * made, and the Summary told the reader the report "predates the structured
 * payload". A missing report is not an empty one, so a tab says which absence
 * it is looking at instead of drawing the negative.
 *
 * `null` when there is a report: the tab then draws what it holds, empty
 * states included, because those are then the run's own answers.
 */

import type { JobDTO, ReportDetailDTO } from "@/lib/api";
import { jobFinished } from "@/lib/runFailure";

export interface ReportState {
  report: ReportDetailDTO | null;
  job: JobDTO | null;
  /** Why the report could not be read, when the read failed. */
  reportError?: string | null;
}

export type ReportAbsence =
  | { kind: "unanswered"; text: string }
  | { kind: "unreadable"; text: string }
  | { kind: "running"; text: string }
  | { kind: "none"; text: string };

export function reportAbsence({ report, job, reportError }: ReportState): ReportAbsence | null {
  if (report) return null;
  if (reportError) {
    return {
      kind: "unreadable",
      text:
        `The report could not be loaded (${reportError}). What this tab would show ` +
        "is unknown, not empty.",
    };
  }
  // No job yet means the API has never answered this page: nothing is known
  // about the run, not even that it is running.
  if (!job) {
    return { kind: "unanswered", text: "Not loaded yet: the API has not answered." };
  }
  if (!jobFinished(job.status)) {
    return {
      kind: "running",
      text: "The analysis is still running. This tab fills in once the report is written.",
    };
  }
  return {
    kind: "none",
    text:
      "This run ended without writing a report, so nothing here was established " +
      "either way.",
  };
}
