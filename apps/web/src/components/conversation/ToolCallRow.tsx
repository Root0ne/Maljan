"use client";

/* One tool call, on one line.
 *
 * A call is not something an agent said, so it is not drawn as a bubble: it
 * is the machine work under a speaker, in the console's monospaced voice. The
 * ledger id is a link rather than printed text, because a citation is only
 * worth showing if the reader can follow it — it opens the row that holds the
 * arguments and the full result, which live in the evidence ledger and are
 * not repeated here.
 */

import Link from "next/link";
import { CircleCheck, CircleX, Loader, Wrench } from "lucide-react";

import type { ConversationItem } from "@/lib/conversation";
import { agentColor } from "./agentIdentity";

function duration(ms: number): string {
  if (ms <= 0) return "";
  if (ms < 1000) return `${ms} ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)} s`;
  return `${Math.floor(ms / 60_000)}m ${Math.round((ms % 60_000) / 1000)}s`;
}

export default function ToolCallRow({
  item,
  jobId,
  showSpeaker,
}: {
  item: ConversationItem;
  jobId: string;
  showSpeaker: boolean;
}) {
  const tool = item.tool;
  if (!tool) return null;
  const running = tool.ok === null;
  const took = duration(tool.durationMs);

  return (
    <div className="flex gap-2.5">
      <span className="w-7 shrink-0" aria-hidden="true" />
      <div className="flex min-w-0 flex-1 flex-wrap items-baseline gap-x-2 gap-y-0.5 px-3 py-1 text-[11px]">
        {showSpeaker && (
          <span style={{ color: agentColor(item.speaker) }}>{item.displayName}</span>
        )}
        <Wrench size={11} aria-hidden="true" className="self-center text-text-muted" />
        <span className="font-mono text-text-primary">
          {tool.server ? `${tool.server}.` : ""}
          {tool.name}
        </span>
        {running ? (
          <span className="flex items-center gap-1 text-text-muted">
            <Loader size={11} aria-hidden="true" className="animate-spin" />
            running
          </span>
        ) : tool.ok ? (
          <CircleCheck size={11} aria-hidden="true" className="self-center text-status-green" />
        ) : (
          <CircleX size={11} aria-hidden="true" className="self-center text-status-red" />
        )}
        {took && <span className="font-mono text-text-muted">{took}</span>}
        {tool.evidenceId && (
          <Link
            href={`/analysis/${jobId}/evidence?evidence=${encodeURIComponent(tool.evidenceId)}`}
            className="rounded bg-accent/15 px-1.5 font-mono text-accent-strong hover:underline"
            title="Open this call in the evidence ledger"
          >
            {tool.evidenceId}
          </Link>
        )}
        {item.text && <span className="min-w-0 truncate text-text-secondary">{item.text}</span>}
      </div>
    </div>
  );
}
