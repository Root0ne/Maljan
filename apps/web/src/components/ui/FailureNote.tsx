"use client";

/* What a failed run tells the operator, in the two places it is told.
 *
 * The run header and the conversation's closing line both draw a failure, and
 * both used to draw it as one sentence with the id the log entries are filed
 * under buried inside it. The id is the whole point of the line: it is the
 * only handle from this screen to the traceback, so it is labelled, selectable
 * and copyable, and one sentence says where it leads.
 */

import { useState } from "react";

import { copyToClipboard } from "@/lib/report-utils";
import { FAILURE_LOG_NOTE, type RunFailure } from "@/lib/runFailure";

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
              onClick={() => void copy(failure.errorId as string)}
              className="rounded border border-border px-1.5 py-0.5 text-[11px] text-text-secondary hover:border-text-muted hover:text-text-primary"
            >
              {copied ? "copied" : "Copy"}
            </button>
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
