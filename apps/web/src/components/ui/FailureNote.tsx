"use client";

/* What a failed run tells the operator, in the two places it is told.
 *
 * The run header and the conversation's closing line both draw a failure, and
 * both used to draw it as one sentence with the id the log entries are filed
 * under buried inside it. It lives on the shared shelf rather than with either
 * of them because it belongs to both, and the conversation components already
 * reach into the analysis ones — putting it under either feature would have
 * that feature's neighbour import it back across. The id is the whole point of the line: it is the
 * only handle from this screen to the traceback, so it is labelled, selectable
 * and copyable, and one sentence says where it leads.
 */

import { useState } from "react";

import { copyToClipboard } from "@/lib/report-utils";
import { FAILURE_LOG_NOTE, type RunFailure } from "@/lib/runFailure";

/**
 * What the copy control is called, in each of its two states.
 *
 * The button's visible word is "Copy", and a failed run draws this note twice
 * — in the header and at the end of the conversation — so a screen reader's
 * button list held two buttons called "Copy" and nothing about what either of
 * them copies. The visible word stays inside the name it is given, which is
 * what keeps the name usable by voice (WCAG 2.5.3).
 */
export function copyErrorIdLabel(copied: boolean): string {
  return copied ? "Error id copied" : "Copy error id";
}

export default function FailureNote({
  failure,
  className,
}: {
  failure: RunFailure;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [copyFailed, setCopyFailed] = useState(false);

  async function copy(id: string) {
    const done = await copyToClipboard(id);
    setCopied(done);
    setCopyFailed(!done);
    if (done) setTimeout(() => setCopied(false), 1500);
  }

  return (
    <div className={`text-xs text-status-red ${className ?? ""}`}>
      {failure.sentence && <p>{failure.sentence}</p>}
      {failure.errorId && (
        <>
          <p className="mt-1 flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="uppercase tracking-wider text-text-muted">Error id</span>
            {/* `select-all` so one click takes the whole id: the reader's next
                move is a search of the log for exactly this string. */}
            <code className="select-all break-all font-mono text-text-primary">
              {failure.errorId}
            </code>
            <button
              type="button"
              aria-label={copyErrorIdLabel(copied)}
              onClick={() => void copy(failure.errorId as string)}
              className="rounded border border-border px-1.5 py-0.5 text-[11px] text-text-secondary hover:border-text-muted hover:text-text-primary"
            >
              {copied ? "copied" : "Copy"}
            </button>
          </p>
          {/* The swap of the button's own word confirms the copy to a reader
              who can see it. Rendered whether or not there is anything in it,
              because a live region that arrives with its first content is
              announced by some screen readers and not by others. */}
          <p role="status" className="sr-only">
            {copied ? copyErrorIdLabel(true) : ""}
          </p>
          <p className="mt-1 text-text-muted">{FAILURE_LOG_NOTE}</p>
          {/* A clipboard the browser refuses is not a failure to report as
              nothing: the id is on screen and selectable, and saying so is
              what keeps the reader from pressing the button again. */}
          {copyFailed && (
            <p role="alert" className="mt-1 text-text-muted">
              The clipboard could not be reached. Select the id above and copy it.
            </p>
          )}
        </>
      )}
    </div>
  );
}
