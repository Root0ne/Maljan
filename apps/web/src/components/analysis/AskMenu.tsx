"use client";

import { useEffect, useId, useRef, useState } from "react";
import { ChevronDown } from "lucide-react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import Button, { buttonClass } from "@/components/ui/Button";
import type { FollowUp } from "@/types/malware-report";
import { FOLLOW_UP_EVENT } from "./followUps";

/**
 * "Ask": a follow-up question about a finished analysis, answered from what
 * the analysis stored.
 *
 * A panel under the header button rather than a form on the page, so the
 * question is one click from every tab and takes no room until it is wanted.
 * Its submit is the panel's one primary action. The earlier questions are
 * read when the panel first opens.
 */
export default function AskMenu({ jobId }: { jobId: string }) {
  const [open, setOpen] = useState(false);
  const [question, setQuestion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<FollowUp[] | null>(null);
  const root = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  const field = useRef<HTMLTextAreaElement>(null);
  const panelId = useId();
  const fieldId = useId();

  useEffect(() => {
    if (!open) return;
    field.current?.focus();
    const onDown = (e: MouseEvent) => {
      if (root.current && !root.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        setOpen(false);
        button.current?.focus();
      }
    };
    document.addEventListener("mousedown", onDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  const toggle = () => {
    const next = !open;
    setOpen(next);
    if (next && history === null) {
      api
        .getFollowUps(jobId)
        .then((list) => setHistory(list.follow_ups ?? []))
        .catch(() => setHistory([]));
    }
  };

  const ask = async (e: React.FormEvent) => {
    e.preventDefault();
    const q = question.trim();
    if (!q) return;
    setBusy(true);
    setError(null);
    try {
      const answer = await api.askFollowUp(jobId, q);
      setHistory((h) => [...(h ?? []), answer]);
      window.dispatchEvent(new CustomEvent(FOLLOW_UP_EVENT, { detail: answer }));
      setQuestion("");
    } catch (err) {
      setError(`The question was not answered: ${getErrorMessage(err)}`);
    } finally {
      setBusy(false);
    }
  };

  const latest = history && history.length > 0 ? history[history.length - 1] : null;

  return (
    <div ref={root} className="relative inline-block">
      <button
        ref={button}
        type="button"
        data-variant="secondary"
        aria-expanded={open}
        aria-controls={open ? panelId : undefined}
        onClick={toggle}
        className={buttonClass("secondary", "sm")}
      >
        Ask
        <ChevronDown aria-hidden="true" className="h-3.5 w-3.5" />
      </button>
      {open && (
        <div
          id={panelId}
          className="absolute right-0 z-40 mt-1 w-80 max-w-[calc(100vw-2rem)] rounded-md border border-border bg-bg-surface p-3 shadow-lg"
        >
          <form onSubmit={(e) => void ask(e)} className="space-y-2">
            <label htmlFor={fieldId} className="block text-xs font-medium text-text-secondary">
              Ask a question about this analysis
            </label>
            <textarea
              id={fieldId}
              ref={field}
              rows={3}
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Which hosts does it contact first?"
              className="w-full resize-y rounded border border-border bg-bg-deep px-2 py-1.5 text-sm text-text-primary"
            />
            <div className="flex items-center justify-between gap-2">
              <span className="text-[11px] text-text-muted">
                {history === null
                  ? "Reading earlier questions…"
                  : history.length === 0
                    ? "No questions asked yet."
                    : `${history.length} asked so far.`}
              </span>
              <Button type="submit" variant="primary" size="sm" disabled={busy || !question.trim()}>
                {busy ? "Asking…" : "Ask"}
              </Button>
            </div>
          </form>
          {error && (
            <p role="alert" className="mt-2 text-xs text-status-red">
              {error}
            </p>
          )}
          {latest && (
            <div className="mt-3 border-t border-border-light pt-2">
              <p className="text-xs font-medium text-text-primary">{latest.question}</p>
              <p className="mt-1 whitespace-pre-wrap text-xs text-text-secondary">
                {latest.answer?.answer || "No answer was recorded."}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
