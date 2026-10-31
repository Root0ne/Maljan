"use client";

import EvidenceChips from "@/components/analysis/EvidenceChips";
import SafeMarkdown from "@/components/analysis/SafeMarkdown";
import { REPORT_MODEL_VOICE, outcomeLine } from "@/components/analysis/reportProse";
import { followUpRows, modelLine } from "@/components/analysis/followUps";
import { citedIds } from "@/components/analysis/overview";
import type { FollowUp } from "@/types/malware-report";

/* ── Follow-up questions on a finished run ───────────────────────────
 *
 * A question asked after the job finished, answered from what the run stored:
 * no tool is called and nothing is analysed again, so the stored evidence
 * either settles it or the answer is "not determinable from this run". Each
 * answer is a record beside the report, which it never changes. The answer
 * the model wrote is drawn as Markdown (`SafeMarkdown`: no HTML, linked only
 * where the allowlist allows) with its citations as evidence marks; every
 * other text the model or the analyst wrote is drawn as plain text. The
 * question is asked from the chat drawer, which lists every answer with
 * `FollowUpAnswer`.
 */

/** One answer: its outcome, the answer, its evidence and what the checks said. */
export function FollowUpAnswer({ row, jobId }: { row: FollowUp; jobId: string }) {
  const cited = citedIds(row.answer.answer);
  const uncited = row.answer.evidence_ids.filter((id) => !cited.has(id));
  return (
    <div className="space-y-1.5">
      <p className="text-xs">
        <span className="mr-2 text-text-muted">Outcome</span>
        <span className={row.answer.answered ? "text-status-orange" : "text-text-secondary"}>
          {outcomeLine(row.answer)}
        </span>
      </p>
      {row.answer.answer.trim() && (
        <div className="space-y-1">
          <SafeMarkdown
            markdown={row.answer.answer}
            cite
            regionName={`Answer ${row.id}`}
            className="space-y-2 text-sm leading-6 text-text-primary"
          />
          <p className="text-xs text-text-muted">
            {uncited.length > 0 && (
              <>
                {cited.size > 0 ? "Also from" : "Evidence"} <EvidenceChips ids={uncited} jobId={jobId} />{" "}
              </>
            )}
            <span className="text-[11px] italic">{REPORT_MODEL_VOICE}</span>
          </p>
        </div>
      )}
      {!row.answer.answer.trim() && row.answer.evidence_ids.length > 0 && (
        <p className="text-xs text-text-muted">
          Evidence <EvidenceChips ids={row.answer.evidence_ids} jobId={jobId} />
        </p>
      )}
      {row.answer.looked_at.length > 0 && (
        <p className="text-xs text-text-muted">
          Also looked at <EvidenceChips ids={row.answer.looked_at} jobId={jobId} />
        </p>
      )}
      {row.answer.open_questions.length > 0 && (
        <p className="text-xs text-text-muted">Open questions it rests on: {row.answer.open_questions.join("; ")}</p>
      )}
      {row.answer.checks.map((check, j) => (
        <p key={j} className="text-[11px] italic text-text-muted">
          Check: {check}
        </p>
      ))}
      {row.notes.map((note, j) => (
        <p key={`n${j}`} className="text-[11px] italic text-text-muted">
          Note: {note}
        </p>
      ))}
      <p className="text-[11px] text-text-muted">
        Model: {modelLine(row)}. Answered from the stored report{" "}
        <code className="font-mono">{row.report_sha256.slice(0, 12)}</code>
        {row.record ? ", recorded on the audit chain." : "."}
      </p>
    </div>
  );
}

/**
 * The follow-ups asked so far as a conversation, oldest first: each question
 * as the reader's turn, then its `FollowUpAnswer`. `pending` is a question
 * sent and not yet answered, drawn as a turn waiting for its answer.
 */
export function FollowUpList({
  rows,
  jobId,
  pending = null,
}: {
  rows: FollowUp[];
  jobId: string;
  pending?: string | null;
}) {
  const shown = followUpRows(rows);
  if (shown.length === 0 && !pending) {
    return <p className="text-xs text-text-muted">No follow-up question has been asked.</p>;
  }
  return (
    <ol className="space-y-5">
      {shown.map((row) => (
        <li key={row.id} className="space-y-2">
          <Question text={row.question} />
          <FollowUpAnswer row={row} jobId={jobId} />
        </li>
      ))}
      {pending && (
        <li className="space-y-2" aria-busy="true">
          <Question text={pending} />
          <p role="status" className="text-xs text-text-muted">
            Answering from what this analysis stored…
          </p>
        </li>
      )}
    </ol>
  );
}

function Question({ text }: { text: string }) {
  return (
    <p className="ml-auto w-fit max-w-[85%] whitespace-pre-wrap break-words rounded-md bg-bg-active px-3 py-2 text-sm text-text-primary">
      <span className="sr-only">You asked: </span>
      {text}
    </p>
  );
}
