"use client";

import { useCallback, useEffect, useId, useRef, useState } from "react";
import { X } from "lucide-react";
import { api } from "@/lib/api";
import { getErrorMessage } from "@/lib/errors";
import Button from "@/components/ui/Button";
import { inertOutside, trappedFocus } from "@/components/ui/Drawer";
import type { FollowUp, MalwareReport } from "@/types/malware-report";
import { FollowUpList } from "./FollowUpQuestions";
import { FOLLOW_UP_EVENT, composerKey, followUpRows, questionToSend, suggestedQuestions } from "./followUps";

/**
 * Chat: questions about a finished analysis, answered from what it stored.
 *
 * A panel that slides in from the right edge under the app header, 420 px
 * wide, holding the whole conversation: every earlier question and its
 * answer (`getFollowUps`), the question waiting for its answer, the open
 * questions the analysis left as suggestions, and the composer at the
 * bottom (Enter sends, Shift+Enter starts a new line). A new answer is
 * announced on `FOLLOW_UP_EVENT` so the rest of the page updates.
 *
 * Wide enough (`docked`), the panel sits beside the page: the page makes room
 * for it, the tabs stay usable and the conversation stays open from tab to
 * tab, so it is a non-modal dialog. Narrower, it covers the page: a modal
 * dialog with the page behind it inert and Tab kept inside it. Either way
 * Escape closes it and focus returns to the control that opened it. The
 * slide is the only motion, and it is dropped under reduced motion.
 */

type Load = "idle" | "ready" | "error";

export default function ChatDrawer({
  id,
  jobId,
  mr,
  open,
  docked,
  onClose,
  returnFocusTo = null,
}: {
  /** The control that opened the panel; focus goes back to it on close.
   *  Without one, whatever had focus at opening. */
  returnFocusTo?: HTMLElement | null;
  /** The panel's id, which the Chat buttons control. */
  id: string;
  jobId: string;
  mr: MalwareReport | null;
  open: boolean;
  /** Whether the panel sits beside the page rather than over it. */
  docked: boolean;
  onClose: () => void;
}) {
  const titleId = useId();
  const fieldId = useId();
  const hintId = useId();
  const root = useRef<HTMLDivElement>(null);
  const panel = useRef<HTMLDivElement>(null);
  const field = useRef<HTMLTextAreaElement>(null);
  const thread = useRef<HTMLDivElement>(null);
  const [rows, setRows] = useState<FollowUp[]>([]);
  const [load, setLoad] = useState<Load>("idle");
  const [loadError, setLoadError] = useState<string | null>(null);
  const [question, setQuestion] = useState("");
  const [pending, setPending] = useState<string | null>(null);
  const [askError, setAskError] = useState<{ question: string; message: string } | null>(null);
  const closeHandler = useRef(onClose);
  const returnTarget = useRef(returnFocusTo);
  useEffect(() => {
    closeHandler.current = onClose;
    returnTarget.current = returnFocusTo;
  }, [onClose, returnFocusTo]);

  /* The earlier questions are read when the panel first opens, and again
   * when the reader asks after a failed read; until the answer arrives an
   * open panel says it is reading. */
  const asked = useRef(false);
  useEffect(() => {
    if (!open || load !== "idle" || asked.current) return;
    asked.current = true;
    api
      .getFollowUps(jobId)
      .then((list) => {
        setRows(followUpRows(list.follow_ups));
        setLoad("ready");
      })
      .catch((err) => {
        setLoadError(`Could not read the earlier questions: ${getErrorMessage(err)}`);
        setLoad("error");
      });
  }, [open, load, jobId]);
  const readAgain = useCallback(() => {
    asked.current = false;
    setLoadError(null);
    setLoad("idle");
  }, []);

  /* An answer that arrives from elsewhere on the page joins the thread. */
  useEffect(() => {
    const onAnswer = (e: Event) => {
      const row = (e as CustomEvent<FollowUp>).detail;
      if (row) setRows((held) => (held.some((r) => r.id === row.id) ? held : followUpRows([...held, row])));
    };
    window.addEventListener(FOLLOW_UP_EVENT, onAnswer);
    return () => window.removeEventListener(FOLLOW_UP_EVENT, onAnswer);
  }, []);

  /* Opening moves focus to the composer; closing puts it back on the opener.
   * Covering the page, the panel is modal: everything else is inert. */
  useEffect(() => {
    if (!open) return;
    const opener = returnTarget.current ?? document.activeElement;
    const restoreInert = !docked && root.current ? inertOutside(root.current) : () => {};
    field.current?.focus({ preventScroll: true });
    return () => {
      restoreInert();
      if (opener instanceof HTMLElement && opener.isConnected) opener.focus({ preventScroll: true });
    };
  }, [open, docked]);

  /* The width of the page scroller's scrollbar, read whenever its box changes. */
  const [gutter, setGutter] = useState(0);
  useEffect(() => {
    const main = document.getElementById("main-content");
    if (!main || typeof ResizeObserver !== "function") return;
    const observer = new ResizeObserver(() => setGutter(Math.max(0, main.offsetWidth - main.clientWidth)));
    observer.observe(main);
    return () => observer.disconnect();
  }, []);

  /* The newest turn is in view. */
  useEffect(() => {
    const box = thread.current;
    if (box && open) box.scrollTop = box.scrollHeight;
  }, [rows, pending, open, askError]);

  const send = async (text: string) => {
    const q = questionToSend(text);
    if (!q || pending) return;
    setPending(q);
    setAskError(null);
    setQuestion("");
    try {
      const answer = await api.askFollowUp(jobId, q);
      setRows((held) => followUpRows([...held, answer]));
      window.dispatchEvent(new CustomEvent(FOLLOW_UP_EVENT, { detail: answer }));
    } catch (err) {
      setAskError({ question: q, message: `The question was not answered: ${getErrorMessage(err)}` });
      setQuestion((now) => now || q);
    } finally {
      setPending(null);
    }
  };

  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key === "Escape") {
      e.preventDefault();
      e.stopPropagation();
      closeHandler.current();
      return;
    }
    if (e.key !== "Tab" || docked || !panel.current) return;
    const next = trappedFocus(panel.current, document.activeElement, e.shiftKey);
    if (next) {
      e.preventDefault();
      next.focus();
    }
  };

  const suggestions = load === "ready" && !pending ? suggestedQuestions(mr, rows) : [];

  return (
    <div ref={root}>
      {!docked && open && (
        <div aria-hidden="true" className="fixed inset-x-0 bottom-0 top-12 z-40 bg-black/40" onClick={onClose} />
      )}
      <div
        ref={panel}
        id={id}
        role="dialog"
        aria-modal={docked ? undefined : true}
        aria-labelledby={titleId}
        onKeyDown={onKeyDown}
        data-testid="chat-drawer"
        /* Beside the page it stops at the page scroller's scrollbar, which
         * stays visible and usable; over the page it takes the full width. */
        style={docked ? { right: gutter } : undefined}
        /* Displayed at once on opening, so focus can land in it, and slid in
         * from its starting style; taken out of the layout only once the
         * slide out has finished, so a closed panel widens nothing. */
        className={`fixed bottom-0 right-0 top-12 z-40 w-full flex-col border-l border-border bg-bg-surface shadow-xl transition-[transform,display] transition-discrete duration-200 ease-out motion-reduce:transition-none sm:w-[420px] print:hidden ${
          open ? "flex translate-x-0 starting:translate-x-full" : "hidden translate-x-full"
        }`}
      >
        <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3">
          <div className="min-w-0">
            <h2 id={titleId} className="text-base font-semibold text-text-primary">
              Chat about this analysis
            </h2>
            <p className="mt-0.5 text-xs text-text-muted">
              Answered from what this analysis stored. Nothing is analysed again.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close chat"
            className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-text-secondary hover:bg-bg-hover hover:text-text-primary"
          >
            <X aria-hidden="true" className="h-4 w-4" />
          </button>
        </div>

        <div
          ref={thread}
          role="log"
          aria-label="Questions and answers"
          tabIndex={0}
          className="min-h-0 flex-1 space-y-4 overflow-y-auto overscroll-contain px-4 py-4 focus-visible:outline focus-visible:-outline-offset-2 focus-visible:outline-accent"
        >
          {load === "idle" && <p className="text-xs text-text-muted">Reading earlier questions…</p>}
          {load === "error" && (
            <div role="alert" className="space-y-2 text-xs text-status-red">
              <p>{loadError}</p>
              <Button size="sm" onClick={readAgain}>
                Read them again
              </Button>
            </div>
          )}
          {load === "ready" && rows.length === 0 && !pending && (
            <p className="text-sm text-text-secondary">
              Ask what the report does not say outright: which host it contacts first, what a decoded string is for,
              whether a behaviour was seen running.
            </p>
          )}
          {(rows.length > 0 || pending) && <FollowUpList rows={rows} jobId={jobId} pending={pending} />}
          {askError && (
            <div role="alert" className="space-y-2 rounded border border-status-red/30 bg-status-red/10 px-3 py-2 text-xs text-status-red">
              <p>{askError.message}</p>
              <Button size="sm" onClick={() => void send(askError.question)}>
                Ask again
              </Button>
            </div>
          )}
          {suggestions.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-xs text-text-muted">Left open by the analysis</p>
              <ul className="space-y-1.5">
                {suggestions.map((s) => (
                  <li key={s}>
                    <button
                      type="button"
                      onClick={() => void send(s)}
                      className="w-full rounded border border-border px-3 py-1.5 text-left text-sm text-text-primary hover:border-text-muted hover:bg-bg-hover"
                    >
                      {s}
                    </button>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        <form
          className="border-t border-border px-4 py-3"
          onSubmit={(e) => {
            e.preventDefault();
            void send(question);
          }}
        >
          <label htmlFor={fieldId} className="sr-only">
            Your question about this analysis
          </label>
          <textarea
            id={fieldId}
            ref={field}
            rows={2}
            value={question}
            aria-describedby={hintId}
            onChange={(e) => setQuestion(e.target.value)}
            onKeyDown={(e) => {
              const action = composerKey({ ...e, isComposing: e.nativeEvent.isComposing });
              if (action === "send") {
                e.preventDefault();
                void send(question);
              }
            }}
            placeholder="Which hosts does it contact first?"
            className="max-h-48 min-h-[3.5rem] w-full resize-y rounded border border-border bg-bg-deep px-3 py-2 text-sm text-text-primary"
          />
          <div className="mt-2 flex items-center justify-between gap-2">
            <span id={hintId} className="text-[11px] text-text-muted">
              Enter sends, Shift+Enter adds a line.
            </span>
            <Button type="submit" variant="primary" size="sm" disabled={Boolean(pending) || !question.trim()}>
              {pending ? "Asking…" : "Ask"}
            </Button>
          </div>
        </form>
      </div>
    </div>
  );
}
