/** What the console decides about follow-up questions on a job, kept apart from the drawing. */

import type { FollowUp, MalwareReport } from "@/types/malware-report";

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

/**
 * What a key press in the chat composer does: Enter sends, Shift+Enter (or
 * any modified Enter) is a new line, and an Enter that ends an input
 * method's composition is the composition's, never a send.
 */
export function composerKey(e: { key: string; shiftKey: boolean; altKey?: boolean; ctrlKey?: boolean; metaKey?: boolean; isComposing?: boolean }): "send" | "newline" | null {
  if (e.key !== "Enter" || e.isComposing) return null;
  return e.shiftKey || e.altKey || e.ctrlKey || e.metaKey ? "newline" : "send";
}

const SUGGESTIONS = 3;

/**
 * The questions the analysis itself left open, offered as the next thing to
 * ask: each open question its answers rest on, from the questions it was
 * asked at submission and from the follow-ups since, newest first. Only a
 * text written as a question is offered, as it was written; one already
 * asked is not offered again.
 */
export function suggestedQuestions(
  mr: Pick<MalwareReport, "question_answers"> | null | undefined,
  rows: FollowUp[] | null | undefined,
): string[] {
  const asked = new Set(followUpRows(rows).map((r) => r.question.trim().toLowerCase()));
  const open = [
    ...followUpRows(rows)
      .slice()
      .reverse()
      .flatMap((r) => r.answer?.open_questions ?? []),
    ...(mr?.question_answers ?? []).flatMap((a) => a?.open_questions ?? []),
  ];
  const out: string[] = [];
  for (const raw of open) {
    const q = String(raw ?? "").trim();
    if (!q.endsWith("?") || asked.has(q.toLowerCase())) continue;
    if (out.some((o) => o.toLowerCase() === q.toLowerCase())) continue;
    out.push(q);
    if (out.length === SUGGESTIONS) break;
  }
  return out;
}
