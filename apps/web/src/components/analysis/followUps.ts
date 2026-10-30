/** What the console decides about follow-up questions on a job, kept apart from the drawing. */

import type { FollowUp } from "@/types/malware-report";

/** The states a job is still producing its run in; the API refuses a follow-up then. */
const UNFINISHED = new Set(["pending", "running"]);

/** Whether a job in `status` can be asked a follow-up question. */
export function canAskFollowUp(status: string | null | undefined): boolean {
  return Boolean(status) && !UNFINISHED.has(String(status));
}

/** A question as it is sent: one line, its blanks trimmed; empty when it says nothing. */
export function questionToSend(text: string): string {
  return text.split(/\s+/).filter(Boolean).join(" ");
}

/** The follow-ups to draw, oldest first, a row without a question left out. */
export function followUpRows(rows: FollowUp[] | null | undefined): FollowUp[] {
  return (rows ?? []).filter((row) => typeof row?.question === "string" && row.question.trim());
}

/** Where the answer's model came from, said beside its label. */
export function modelLine(row: FollowUp): string {
  const model = row.model.trim() || "no model";
  return row.model_source.trim() ? `${model} (${row.model_source.trim()})` : model;
}

/** The window event a newly answered follow-up is announced on, with the row as its detail. */
export const FOLLOW_UP_EVENT = "maljan:follow-up";
