"use client";

import { useEffect, useState } from "react";

import EvidenceChips from "@/components/analysis/EvidenceChips";
import { REPORT_MODEL_VOICE, outcomeLine } from "@/components/analysis/reportProse";
import {
  canAskFollowUp,
  followUpRows,
  modelLine,
  questionToSend,
} from "@/components/analysis/followUps";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import type { FollowUp } from "@/types/malware-report";

/* ── Follow-up questions on a finished run ───────────────────────────
 *
 * A question asked after the job finished, answered from what the run stored:
 * no tool is called and nothing is analysed again, so the stored evidence
 * either settles it or the answer is "not determinable from this run". Each
 * answer is a record beside the report, which it never changes. Every text the
 * model or the analyst wrote is drawn as plain text.
 */
export default function FollowUpQuestions({
  jobId,
  status,
}: {
  jobId: string;
  status: string | null | undefined;
}) {
  const [rows, setRows] = useState<FollowUp[]>([]);
  const [draft, setDraft] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const open = canAskFollowUp(status);

  useEffect(() => {
    if (!jobId || !open) return;
    let live = true;
    api
      .getFollowUps(jobId)
      .then((res) => {
        if (live) setRows(followUpRows(res.follow_ups));
      })
      .catch((err) => {
        if (live) setMessage(`Could not read the follow-up questions: ${getErrorMessage(err)}`);
      });
    return () => {
      live = false;
    };
  }, [jobId, open]);

  if (!jobId || !open) return null;

  const question = questionToSend(draft);
  const ask = async () => {
    if (!question || busy) return;
    setBusy(true);
    setMessage(null);
    try {
      const row = await api.askFollowUp(jobId, question);
      setRows((held) => followUpRows([...held, row]));
      setDraft("");
    } catch (err) {
      setMessage(`The question was not answered: ${getErrorMessage(err)}`);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="bg-bg-reading border border-border rounded">
      <div className="px-4 py-3 border-b border-border flex items-baseline gap-3">
        <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
          Follow-up questions
        </h2>
        <span className="text-[11px] italic text-text-muted">
          Answered from what this run stored; nothing is analysed again.
        </span>
      </div>
      <div className="p-4 space-y-4">
        <FollowUpList rows={rows} jobId={jobId} />
        <div className="space-y-2">
          <label htmlFor="follow-up-question" className="block text-xs text-text-muted">
            Ask this run a new question
          </label>
          <textarea
            id="follow-up-question"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            rows={2}
            disabled={busy}
            className="w-full text-sm bg-bg-surface border border-border rounded px-2 py-1.5 text-text-primary"
          />
          <button
            onClick={ask}
            disabled={!question || busy}
            className="px-3 py-1 text-xs text-text-secondary border border-border rounded hover:text-text-primary hover:border-text-muted disabled:text-text-disabled disabled:cursor-not-allowed"
          >
            {busy ? "answering..." : "Ask"}
          </button>
          {message && (
            <p className="text-xs text-text-secondary bg-bg-active border border-border rounded px-2 py-1.5">
              {message}
            </p>
          )}
        </div>
      </div>
    </div>
  );
}

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
            <span className="uppercase tracking-wider text-text-muted mr-2">Outcome</span>
            <span className={row.answer.answered ? "text-status-orange" : "text-text-secondary"}>
              {outcomeLine(row.answer)}
            </span>
          </p>
          {row.answer.answer.trim() && (
            <p className="text-sm text-text-secondary leading-relaxed">
              {row.answer.answer}{" "}
              <span className="text-[11px] italic text-text-muted">{REPORT_MODEL_VOICE}</span>
            </p>
          )}
          {row.answer.evidence_ids.length > 0 && (
            <p className="text-xs text-text-muted">
              Evidence <EvidenceChips ids={row.answer.evidence_ids} jobId={jobId} className="ml-1" />
            </p>
          )}
          {row.answer.looked_at.length > 0 && (
            <p className="text-xs text-text-muted">
              Looked at <EvidenceChips ids={row.answer.looked_at} jobId={jobId} className="ml-1" />
            </p>
          )}
          {row.answer.open_questions.length > 0 && (
            <p className="text-xs text-text-muted">
              Open questions it rests on: {row.answer.open_questions.join("; ")}
            </p>
          )}
          {row.answer.checks.map((check, j) => (
            <p key={j} className="text-[11px] italic text-text-muted">
              Platform check: {check}
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
