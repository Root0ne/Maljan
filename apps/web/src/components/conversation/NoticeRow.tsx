"use client";

/* Something the room said about the conversation.
 *
 * A validator correction and a cap notice are not participants speaking, so
 * they are centred notes rather than bubbles — the same distinction a group
 * thread draws between a message and a date divider. A correction names the
 * rule it applied and which retry it was, because the whole point of showing
 * it is that the answer the reader is about to read is the second one.
 *
 * One violation is one note. The run publishes it as the producer is shown it
 * and again as the retry fixes it or fails to, and the three states used to be
 * drawn identically — one violation reading as two or three unrelated lines.
 * The note now says where the violation ended up, in words, and keeps what
 * came before it underneath as its history.
 */

import { Info, ShieldAlert, ShieldCheck, ShieldX } from "lucide-react";
import type { LucideIcon } from "lucide-react";

import type { ConversationItem, FeedbackEntry, ValidationState } from "@/lib/conversation";

/** How each state is told apart: by its own words first, with an icon and a
 *  colour behind them rather than instead of them. */
const STATE: Record<ValidationState, { word: string; icon: LucideIcon; tone: string }> = {
  retried: {
    word: "sent back for correction",
    icon: ShieldAlert,
    tone: "border-status-orange/30 bg-status-orange/10 text-status-orange",
  },
  resolved: {
    word: "fixed on the retry",
    icon: ShieldCheck,
    tone: "border-status-green/30 bg-status-green/10 text-status-green",
  },
  survived: {
    word: "not fixed",
    icon: ShieldX,
    tone: "border-status-red/30 bg-status-red/10 text-status-red",
  },
};

const PLAIN_NOTICE = "border-border bg-bg-surface text-text-muted";

/** What one earlier state of a violation reads as, under the line it belongs
 *  to. The message rides along only where it says something the latest one
 *  does not. */
function historyLine(entry: FeedbackEntry, latest: string): string {
  const retry = entry.retryIndex ? `retry ${entry.retryIndex} · ` : "";
  const message = entry.message && entry.message !== latest ? ` — ${entry.message}` : "";
  return `${retry}${STATE[entry.state].word}${message}`;
}

export default function NoticeRow({ item }: { item: ConversationItem }) {
  const correction = item.kind === "validation_feedback";
  const states = item.feedback ?? [];
  /* A correction the builder folded always states where it ended; one from a
   * feed this view was handed some other way is read as the correction turn
   * it was published as. */
  const latest = states[states.length - 1]?.state ?? "retried";
  const style = STATE[latest];
  const Icon: LucideIcon = correction ? style.icon : Info;
  const earlier = states.slice(0, -1);
  return (
    <div className="flex justify-center">
      <div
        /* The rule key and the producer's locator are what a log line is
           grepped for, not what a reader needs beside the sentence the rule
           already writes out. They stay on the row as its title, which is
           where the other machine identifiers on this page live. */
        title={correction ? [item.code, item.path].filter(Boolean).join(" · ") : undefined}
        className={`max-w-[46rem] rounded border px-2.5 py-1 text-[11px] ${
          correction ? style.tone : PLAIN_NOTICE
        }`}
      >
        <div className="flex items-baseline gap-2">
          <Icon size={12} aria-hidden="true" className="self-center" />
          {correction && <span className="uppercase tracking-wider">{style.word}</span>}
          {correction && item.retryIndex ? <span>retry {item.retryIndex}</span> : null}
          {/* A notice still comes from somewhere, and which validator or which
            * watcher raised it is the first thing a reader wants. */}
          {item.displayName && <span className="text-text-primary">{item.displayName}</span>}
          <span className="text-text-secondary">{item.text}</span>
        </div>
        {earlier.length > 0 && (
          <ul className="mt-1 space-y-0.5 pl-5 text-text-muted">
            {earlier.map((entry, index) => (
              <li key={`${entry.state}-${entry.retryIndex}-${index}`}>
                {historyLine(entry, item.text)}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
