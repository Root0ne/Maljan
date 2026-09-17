"use client";

/* Something the room said about the conversation.
 *
 * A validator correction and a cap notice are not participants speaking, so
 * they are centred notes rather than bubbles — the same distinction a group
 * thread draws between a message and a date divider. A correction names the
 * rule it applied and which retry it was, because the whole point of showing
 * it is that the answer the reader is about to read is the second one.
 */

import { Info, ShieldAlert } from "lucide-react";

import type { ConversationItem } from "@/lib/conversation";

export default function NoticeRow({ item }: { item: ConversationItem }) {
  const correction = item.kind === "validation_feedback";
  const Icon = correction ? ShieldAlert : Info;
  return (
    <div className="flex justify-center">
      <div
        className={`flex max-w-[46rem] items-baseline gap-2 rounded border px-2.5 py-1 text-[11px] ${
          correction
            ? "border-status-orange/30 bg-status-orange/10 text-status-orange"
            : "border-border bg-bg-surface text-text-muted"
        }`}
      >
        <Icon size={12} aria-hidden="true" className="self-center" />
        {correction && (
          <>
            <span className="font-mono">{item.code}</span>
            {item.retryIndex ? <span>retry {item.retryIndex}</span> : null}
            {item.displayName && <span className="text-text-secondary">{item.displayName}</span>}
          </>
        )}
        <span className="text-text-secondary">{item.text}</span>
      </div>
    </div>
  );
}
