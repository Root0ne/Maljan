"use client";

import { useMemo, useState } from "react";

import Drawer from "@/components/ui/Drawer";
import type { MalwareReport, ProcessNode } from "@/types/malware-report";
import { PROCESS_ROWS_FIRST, behaviourPids, processRows, type ProcessRow } from "../processTree";

/**
 * The sandbox's process tree: the sample's path open and marked, the
 * processes beside it folded, and a bounded number of rows drawn at a time
 * (`processTree.ts`). A process's name opens its details in the side panel:
 * its full command line, what it injects into, and why it is on the path.
 */
export default function ProcessTree({ roots, mr }: { roots: ProcessNode[]; mr: MalwareReport | null | undefined }) {
  const tied = useMemo(() => behaviourPids(mr), [mr]);
  const [open, setOpen] = useState<Record<string, boolean>>({});
  const [unfolded, setUnfolded] = useState<ReadonlySet<string>>(new Set());
  const [limit, setLimit] = useState(PROCESS_ROWS_FIRST);
  const [detail, setDetail] = useState<{ row: Extract<ProcessRow, { kind: "process" }>; opener: HTMLElement } | null>(null);

  const rows = processRows(roots, tied, { open, unfolded });
  const shown = rows.slice(0, limit);

  return (
    <>
      <ul className="font-mono text-xs" aria-label="Process tree">
        {shown.map((row) =>
          row.kind === "fold" ? (
            <li key={`fold-${row.key}`} style={{ paddingLeft: row.depth * 16 + 4 }} className="py-0.5">
              <button
                type="button"
                onClick={() => setUnfolded((s) => new Set([...s, row.key]))}
                className="font-sans text-[11px] text-accent-strong hover:underline"
              >
                {row.count.toLocaleString("en-US")} other process{row.count === 1 ? "" : "es"}
              </button>
            </li>
          ) : (
            <li
              key={row.key}
              data-on-path={row.onPath ? "true" : undefined}
              className={`flex flex-wrap items-start gap-x-2 rounded py-0.5 pr-1 ${row.flagged ? "bg-status-red/5" : ""}`}
              style={{ paddingLeft: row.depth * 16 + 4 }}
            >
              {row.hasChildren ? (
                <button
                  type="button"
                  aria-expanded={row.open}
                  aria-label={`${row.open ? "Collapse" : "Expand"} ${row.node.name || "process"} ${row.node.pid}`}
                  onClick={() => setOpen((s) => ({ ...s, [row.key]: !row.open }))}
                  className="inline-flex h-4 w-4 shrink-0 items-center justify-center rounded text-text-muted hover:bg-bg-hover hover:text-text-primary"
                >
                  {row.open ? "−" : "+"}
                </button>
              ) : (
                <span aria-hidden="true" className="inline-block w-4 shrink-0 text-center text-text-muted">
                  ·
                </span>
              )}
              <span className="shrink-0 text-status-blue">{row.node.pid}</span>
              <button
                type="button"
                onClick={(e) => setDetail({ row, opener: e.currentTarget })}
                className={`shrink-0 hover:underline ${row.onPath ? "font-semibold text-text-primary" : "text-text-secondary"}`}
              >
                {row.node.name || "(unknown)"}
              </button>
              {row.node.command_line && (
                <span className="min-w-0 max-w-full break-all text-text-secondary sm:flex-1 sm:truncate" title={row.node.command_line}>
                  {row.node.command_line}
                </span>
              )}
              {(row.node.injected_into ?? []).length > 0 && (
                <span className="shrink-0 rounded bg-status-red/10 px-1 font-sans text-[11px] text-status-red">
                  injects into {(row.node.injected_into ?? []).join(", ")}
                </span>
              )}
            </li>
          ),
        )}
      </ul>
      {rows.length > shown.length && (
        <div className="mt-2 flex flex-wrap items-center gap-3 text-[11px] text-text-muted">
          <span>
            Showing {shown.length} of {rows.length} rows.
          </span>
          <button
            type="button"
            onClick={() => setLimit((n) => n + PROCESS_ROWS_FIRST)}
            className="text-accent-strong hover:underline"
          >
            Show {Math.min(PROCESS_ROWS_FIRST, rows.length - shown.length)} more
          </button>
        </div>
      )}
      <Drawer
        open={detail !== null}
        title={detail ? `${detail.row.node.name || "Process"} (${detail.row.node.pid})` : ""}
        onClose={() => setDetail(null)}
        returnFocusTo={detail?.opener ?? null}
      >
        {detail && <ProcessDetail row={detail.row} />}
      </Drawer>
    </>
  );
}

export function ProcessDetail({ row }: { row: Extract<ProcessRow, { kind: "process" }> }) {
  const n = row.node;
  return (
    <dl className="space-y-3 text-sm">
      <Pair label="Process id">{n.pid}</Pair>
      <Pair label="Parent process id">{n.ppid || "0"}</Pair>
      <Pair label="Command line">
        <code className="break-all font-mono text-xs">{n.command_line || "Not recorded"}</code>
      </Pair>
      <Pair label="Injects into">{(n.injected_into ?? []).length > 0 ? (n.injected_into ?? []).join(", ") : "Nothing recorded"}</Pair>
      <Pair label="Child processes">{n.children?.length ?? 0}</Pair>
      <Pair label="Why it is on the sample's path">
        {row.reasons.length > 0
          ? row.reasons.join("; ")
          : row.onPath
            ? "Started by, or the parent of, a process the report ties to the sample"
            : "Not on the sample's path"}
      </Pair>
    </dl>
  );
}

function Pair({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-text-muted">{label}</dt>
      <dd className="text-text-primary">{children}</dd>
    </div>
  );
}
