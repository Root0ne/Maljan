"use client";

/* A speaker's run of tool calls, folded into one line.
 *
 * A call is machine work, not something an agent said, and a run of forty of
 * them used to bury the three sentences the agent wrote around them. The
 * strip says how many calls, how long they took and how many failed; opening
 * it lists the calls, and opening a call shows its result laid out as data.
 *
 * The event a call arrives as carries only a preview of the result, cut to a
 * line. A call filed in the evidence ledger is read from there when it is
 * opened, so the reader sees the whole answer and its arguments; the preview
 * is shown only when there is no record to read, or the read failed — and
 * says so. The ledger id stays a link to the record itself.
 */

import Link from "next/link";
import { useEffect, useId, useState } from "react";
import { ChevronRight, CircleCheck, CircleX, Loader, Wrench } from "lucide-react";

import StructuredValue from "@/components/analysis/StructuredValue";
import {
  emptyOutputNote,
  entryNotes,
  formatCallDuration,
  outputPreview,
  structuredOutput,
} from "@/components/analysis/evidenceRows";
import { evidenceRecordHref } from "@/components/analysis/overview";
import { stripLabel, stripSummary } from "@/lib/chatLayout";
import type { ConversationItem } from "@/lib/conversation";
import { getErrorMessage } from "@/lib/errors";
import { loadEvidenceEntry } from "@/lib/evidenceEntry";
import type { EvidenceEntry } from "@/types/evidence";
import type { AgentTone } from "./agentIdentity";

const HEADING = "mb-1 text-[11px] font-medium text-text-secondary";

export default function ToolStrip({
  calls,
  jobId,
  tone,
  defaultOpen,
}: {
  calls: ConversationItem[];
  jobId: string;
  tone: AgentTone;
  /** Open on arrival, which is how the strip is read when the reader has
   *  asked to see the tool calls or the failures. */
  defaultOpen: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const [followed, setFollowed] = useState(defaultOpen);
  if (followed !== defaultOpen) {
    setFollowed(defaultOpen);
    setOpen(defaultOpen);
  }
  const listId = useId();
  const summary = stripSummary(calls);
  const names = [...new Set(calls.map((c) => c.tool?.name ?? ""))].filter(Boolean);
  const shownNames = names.slice(0, 3).join(", ") + (names.length > 3 ? `, +${names.length - 3}` : "");

  return (
    <div className="max-w-[min(72ch,100%)]">
      <button
        type="button"
        aria-expanded={open}
        aria-controls={listId}
        onClick={() => setOpen((value) => !value)}
        className="flex max-w-full items-center gap-1.5 rounded-full border border-border-light bg-bg-surface px-2.5 py-0.5 text-[11px] text-text-secondary hover:border-border hover:text-text-primary focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
      >
        <ChevronRight
          size={12}
          aria-hidden="true"
          className={`shrink-0 motion-safe:transition-transform ${open ? "rotate-90" : ""}`}
        />
        <Wrench size={11} aria-hidden="true" className="shrink-0" style={{ color: tone.color }} />
        <span className="shrink-0 font-medium">
          {stripLabel({ ...summary, failed: 0 })}
          {summary.failed > 0 && <span className="text-status-red"> · {summary.failed} failed</span>}
        </span>
        {shownNames && <span className="min-w-0 truncate text-text-muted">{shownNames}</span>}
      </button>
      {open && (
        <ol id={listId} className="mt-1.5 space-y-1 border-l pl-3" style={{ borderLeftColor: tone.color }}>
          {calls.map((call) => (
            <li key={call.id}>
              <ToolCall call={call} jobId={jobId} />
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

function StatusMark({ ok }: { ok: boolean | null }) {
  if (ok === null) {
    return (
      <span className="flex shrink-0 items-center gap-1 text-text-muted">
        <Loader size={11} aria-hidden="true" className="motion-safe:animate-spin" />
        running
      </span>
    );
  }
  return ok ? (
    <span className="flex shrink-0 items-center text-status-green">
      <CircleCheck size={11} aria-hidden="true" />
      {/* The shape says it to a reader; this says it to a screen reader,
        * which cannot see either the icon or its colour. */}
      <span className="sr-only">succeeded</span>
    </span>
  ) : (
    <span className="flex shrink-0 items-center gap-1 text-status-red">
      <CircleX size={11} aria-hidden="true" />
      failed
    </span>
  );
}

function ToolCall({ call, jobId }: { call: ConversationItem; jobId: string }) {
  const [open, setOpen] = useState(false);
  const detailId = useId();
  const tool = call.tool;
  if (!tool) return null;
  const took = tool.durationMs > 0 ? formatCallDuration(tool.durationMs) : "";
  const name = `${tool.server ? `${tool.server}.` : ""}${tool.name}`;

  return (
    <div className="text-[11px]">
      <div className="flex min-w-0 flex-wrap items-center gap-x-2 gap-y-0.5">
        <button
          type="button"
          aria-expanded={open}
          aria-controls={detailId}
          onClick={() => setOpen((value) => !value)}
          className="flex min-w-0 items-center gap-1.5 rounded px-1 py-0.5 text-left hover:bg-bg-active focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
        >
          <ChevronRight
            size={11}
            aria-hidden="true"
            className={`shrink-0 text-text-muted motion-safe:transition-transform ${open ? "rotate-90" : ""}`}
          />
          <span className="font-mono text-text-primary">{name}</span>
        </button>
        <StatusMark ok={tool.ok} />
        {took && <span className="tabular-nums text-text-secondary">{took}</span>}
        {tool.evidenceId && (
          <Link
            href={evidenceRecordHref(jobId, tool.evidenceId)}
            className="rounded bg-accent/15 px-1.5 font-mono text-accent-strong hover:underline"
            title="Open this call in the evidence"
          >
            {tool.evidenceId}
          </Link>
        )}
      </div>
      {/* The preview the event carried, as one line under the call. */}
      {!open && call.text && (
        <p className="truncate pl-6 text-text-muted" title={call.text}>
          {call.text}
        </p>
      )}
      {open && (
        <div id={detailId} className="mt-1 space-y-2 pl-6">
          <ToolResult key={tool.evidenceId} call={call} jobId={jobId} />
        </div>
      )}
    </div>
  );
}

type Load =
  | { state: "loading" }
  | { state: "loaded"; entry: EvidenceEntry }
  | { state: "missing" }
  | { state: "failed"; message: string };

function ToolResult({ call, jobId }: { call: ConversationItem; jobId: string }) {
  const evidenceId = call.tool?.evidenceId ?? "";
  const [load, setLoad] = useState<Load>(evidenceId ? { state: "loading" } : { state: "missing" });

  useEffect(() => {
    if (!evidenceId) return;
    let cancelled = false;
    loadEvidenceEntry(jobId, evidenceId)
      .then((entry) => {
        if (!cancelled) setLoad(entry ? { state: "loaded", entry } : { state: "missing" });
      })
      .catch((err: unknown) => {
        if (!cancelled) setLoad({ state: "failed", message: getErrorMessage(err) });
      });
    return () => {
      cancelled = true;
    };
  }, [jobId, evidenceId]);

  if (load.state === "loading") {
    return <p className="text-text-muted">Reading the full result from the evidence…</p>;
  }
  if (load.state === "loaded") return <EntryResult entry={load.entry} />;

  return (
    <>
      <Preview call={call} />
      <p className="text-text-muted">
        {load.state === "failed"
          ? `This is the preview the event carried; the full result could not be read (${load.message}).`
          : call.tool?.ok === null
            ? "The call is still running."
            : "This is the preview the event carried; the call has no evidence record to read."}
      </p>
    </>
  );
}

/** The event's own preview: laid out when it is whole JSON, literal otherwise. */
function Preview({ call }: { call: ConversationItem }) {
  const text = call.text;
  if (!text) return null;
  const parsed = structuredOutput(text);
  return parsed !== null ? (
    <StructuredValue value={parsed} source={text} name={`Preview of call ${call.id}`} />
  ) : (
    <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded border border-border-light bg-bg-surface px-3 py-2 font-mono text-[11px] leading-5 text-text-secondary">
      {text}
    </pre>
  );
}

/** The record as the ledger holds it: what went wrong, the arguments, the
 *  answer. */
function EntryResult({ entry }: { entry: EvidenceEntry }) {
  const [full, setFull] = useState(false);
  const parsed = structuredOutput(entry.output);
  const preview = outputPreview(entry.output, full);
  const notes = entryNotes(entry);
  return (
    <>
      {entry.error && (
        <div>
          <h4 className={HEADING}>Error</h4>
          <p className="whitespace-pre-wrap break-words text-status-red">{entry.error}</p>
          {entry.remediation && (
            <p className="mt-1 whitespace-pre-wrap break-words text-text-secondary">{entry.remediation}</p>
          )}
        </div>
      )}
      {entry.args && Object.keys(entry.args).length > 0 && (
        <div>
          <h4 className={HEADING}>Arguments</h4>
          <StructuredValue value={entry.args} name={`Arguments of ${entry.entry_id} in the conversation`} />
        </div>
      )}
      <div>
        <h4 className={HEADING}>Result</h4>
        {entry.output && parsed !== null ? (
          <StructuredValue value={parsed} source={entry.output} name={`Result of ${entry.entry_id} in the conversation`} />
        ) : entry.output ? (
          <>
            {/* Text, not data: shown as written. */}
            <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded border border-border-light bg-bg-surface px-3 py-2 font-mono text-[11px] leading-5 text-text-secondary">
              {preview.text}
            </pre>
            {(preview.hidden > 0 || full) && (
              <button
                type="button"
                className="text-text-secondary hover:text-text-primary"
                onClick={() => setFull((value) => !value)}
              >
                {full ? "Show less" : `Show more (${preview.hidden} more characters)`}
              </button>
            )}
          </>
        ) : entry.structured != null ? null : (
          <p className="text-text-muted">{emptyOutputNote(entry)}</p>
        )}
        {entry.structured != null && (
          <div className={entry.output ? "mt-2" : ""}>
            <StructuredValue value={entry.structured} name={`Structured result of ${entry.entry_id} in the conversation`} />
          </div>
        )}
      </div>
      {notes.map((note) => (
        <p key={note} className="text-text-muted">
          {note}
        </p>
      ))}
    </>
  );
}
