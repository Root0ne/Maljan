"use client";

import CitedProse from "@/components/analysis/CitedProse";
import EvidenceChips from "@/components/analysis/EvidenceChips";
import { REPORT_MODEL_VOICE, outcomeLine } from "@/components/analysis/reportProse";
import { followUpRows, modelLine } from "@/components/analysis/followUps";
import type { FollowUp } from "@/types/malware-report";

/* ── Follow-up questions on a finished run ───────────────────────────
 *
 * A question asked after the job finished, answered from what the run stored:
 * no tool is called and nothing is analysed again, so the stored evidence
 * either settles it or the answer is "not determinable from this run". Each
 * answer is a record beside the report, which it never changes. Every text the
 * model or the analyst wrote is drawn as plain text. The question is asked
 * from the header's Ask menu; Overview lists every answer with this.
 */

/** The follow-ups asked so far, each with its outcome, its answer and what the checks said. */
export function FollowUpList({ rows, jobId }: { rows: FollowUp[]; jobId: string }) {
  const shown = followUpRows(rows);
  if (shown.length === 0) {
    return <p className="text-xs text-text-muted">No follow-up question has been asked.</p>;
  }
  return (
    <ol className="space-y-4">
      {shown.map((row, i) => (
        <li key={row.id} className="space-y-1.5">
          <p className="text-sm text-text-primary font-medium">
            F{i + 1}. {row.question}
          </p>
          <p className="text-xs">
            <span className="text-text-muted mr-2">Outcome</span>
            <span className={row.answer.answered ? "text-status-orange" : "text-text-secondary"}>
              {outcomeLine(row.answer)}
            </span>
          </p>
          {row.answer.answer.trim() && (
            <p className="text-sm text-text-secondary leading-relaxed">
              <CitedProse text={row.answer.answer} />
              <EvidenceChips ids={row.answer.evidence_ids} jobId={jobId} />{" "}
              <span className="text-[11px] italic text-text-muted">{REPORT_MODEL_VOICE}</span>
            </p>
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
            <p className="text-xs text-text-muted">
              Open questions it rests on: {row.answer.open_questions.join("; ")}
            </p>
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
        </li>
      ))}
    </ol>
  );
}
