"use client";

/* One thing a participant said.
 *
 * Everybody sits on the left. The reader is a spectator here, and
 * right-alignment in a chat means "sent by me" — claiming one of the agents
 * on the reader's behalf would be a lie about who said what. Identity is
 * carried the way a group thread carries it instead: the avatar and name the
 * group draws once over a speaker's consecutive bubbles, and the bubble's own
 * label, which names the speaker and the time for a screen reader.
 *
 * A line that answers a question opens with a quote of it, and the quote is a
 * button that takes the reader to the question. The judge and the mediator
 * speak in the moderator's bubble, apart from the team's.
 *
 * Claims and the speaker's full prose are both real and both often long, so
 * each sits behind a disclosure that renders only when it is open — a
 * collapsed report must not be findable by a text search the reader did not
 * ask for.
 */

import { memo, useState } from "react";
import { ArrowRight, CircleHelp, CornerUpLeft, Gavel } from "lucide-react";

import { retryAddedLabel, type ConversationItem } from "@/lib/conversation";
import { statusTone } from "@/lib/status";
import type { AgentTone } from "./agentIdentity";

const STATUS_BADGE: Record<string, { label: string; cls: string }> = {
  no_data: { label: "no data", cls: "border-status-orange/30 bg-status-orange/10 text-status-orange" },
  no_claims: { label: "no report", cls: "border-status-orange/30 bg-status-orange/10 text-status-orange" },
  // The run's own "failed" colour (`lib/status.ts`).
  failed: {
    label: "failed",
    cls: `${statusTone("failed").border} ${statusTone("failed").bg} ${statusTone("failed").text}`,
  },
  timeout: { label: "timed out", cls: "border-status-red/30 bg-status-red/10 text-status-red" },
};

/** `12:04` from an ISO timestamp; empty when there is not one. */
export function clock(ts: string): string {
  if (!ts) return "";
  const at = new Date(ts);
  if (Number.isNaN(at.getTime())) return "";
  return at.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

/** The element id a line is reached by, for a reply that points at it. */
export function lineAnchor(id: string): string {
  return `line-${id.replace(/[^a-zA-Z0-9_-]/g, "-")}`;
}

/** The first words of a line, for the quote of it an answer opens with. */
export function excerpt(text: string, limit = 160): string {
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length > limit ? `${flat.slice(0, limit - 1).trimEnd()}…` : flat;
}

export interface ReplyRef {
  item: ConversationItem;
  /** Who asked, as the conversation names them. */
  author: string;
  /** The text the quote is cut from (a moderator's line without its
   *  self-introduction). */
  text: string;
  tone: AgentTone;
}

function MessageBubble({
  item,
  speakerName,
  text,
  tone,
  first,
  replyTo,
  onJump,
}: {
  item: ConversationItem;
  /** The name the group header shows; part of the bubble's label. */
  speakerName: string;
  /** What to draw as the message, which for a moderator is its line without
   *  the name it introduced itself with. */
  text: string;
  tone: AgentTone;
  /** The first bubble of its group, which takes the corner the header sits on. */
  first: boolean;
  replyTo?: ReplyRef;
  onJump?: (id: string) => void;
}) {
  const [openClaims, setOpenClaims] = useState(false);
  const [openReport, setOpenReport] = useState(false);

  const verdict = item.kind === "verdict";
  const question = item.kind === "judge_question";
  const badge = item.status ? STATUS_BADGE[item.status] : undefined;
  const confidence =
    item.confidence === undefined || Number.isNaN(item.confidence)
      ? ""
      : `${Math.round(item.confidence * 100)}%`;
  const time = clock(item.ts);

  /* A moderator's bubble is washed in the moderator's tone; a verdict, the
   * line the run ends on, is the strongest of them. The team's bubbles sit on
   * the surface colour, with nothing but the avatar to colour them. */
  const shell = tone.moderator
    ? verdict
      ? "border-accent/50 bg-accent/10"
      : "border-accent/30 bg-accent/5"
    : "border-border-light bg-bg-surface";

  return (
    <article
      id={lineAnchor(item.id)}
      tabIndex={-1}
      aria-label={[speakerName || "Room", time].filter(Boolean).join(", ")}
      className={`w-fit max-w-[min(72ch,100%)] scroll-mt-32 rounded-2xl border px-3.5 py-2 focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${shell} ${
        first ? "rounded-tl-md" : ""
      }`}
    >
      {replyTo && (
        <button
          type="button"
          onClick={() => onJump?.(replyTo.item.id)}
          className="mb-1.5 block w-full rounded-md border-l-2 bg-bg-active/60 px-2 py-1 text-left hover:bg-bg-active focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
          style={{ borderLeftColor: replyTo.tone.color }}
          aria-label={`Replying to ${replyTo.author}: ${excerpt(replyTo.text, 80)}. Go to the question.`}
        >
          <span className="flex items-center gap-1 text-[11px] font-medium" style={{ color: replyTo.tone.ink }}>
            <CornerUpLeft size={11} aria-hidden="true" />
            {replyTo.author}
          </span>
          <span className="line-clamp-2 text-[11px] leading-snug text-text-secondary">
            {excerpt(replyTo.text)}
          </span>
        </button>
      )}

      {verdict && (
        <span className="mb-1 flex items-center gap-1.5 text-[11px] font-medium text-accent-strong">
          <Gavel size={12} aria-hidden="true" />
          Verdict
        </span>
      )}
      {question && (
        <span className="mb-1 flex items-center gap-1.5 text-[11px] font-medium text-accent-strong">
          <CircleHelp size={12} aria-hidden="true" />
          Question
          {item.addressedToName && (
            <>
              <ArrowRight size={11} aria-hidden="true" />
              <span>{item.addressedToName}</span>
            </>
          )}
        </span>
      )}

      {/* What the agent said, as it said it: messages quote command lines
          and Windows paths, so every backslash, asterisk and underscore
          stays literal. A turn still arriving is drawn as far as it has
          come, with the cursor after it. */}
      <p className="whitespace-pre-wrap break-words text-xs leading-relaxed text-text-primary">
        {text}
        {item.streaming && (
          <span
            className="ml-1 inline-block h-3 w-1.5 align-middle bg-text-muted motion-safe:animate-pulse"
            aria-hidden="true"
          />
        )}
      </p>

      {item.dissent.length > 0 && (
        <p className="mt-1.5 text-[11px] text-status-orange">Disputes: {item.dissent.join("; ")}</p>
      )}

      {openClaims && (
        <ul className="mt-2 space-y-1.5 border-t border-border-light pt-2">
          {item.claims.map((claim, i) => (
            <li key={`${item.id}-claim-${i}`} className="text-[11px] leading-relaxed">
              <span className="text-text-primary">{claim.claim}</span>
              {claim.evidence_ref && (
                <span className="block font-mono text-text-muted">{claim.evidence_ref}</span>
              )}
              {/* Secondary rather than tertiary: a verdict bubble is washed,
                  where tertiary falls under 4.5:1. */}
              <span className="text-text-secondary">
                {claim.technique_id ? `${claim.technique_id} · ` : ""}
                {claim.confidence === null
                  ? "no confidence stated"
                  : `${Math.round(claim.confidence * 100)}%`}
                {claim.added_by_retry_in_round !== undefined
                  ? ` · ${retryAddedLabel(claim.added_by_retry_in_round)}`
                  : ""}
              </span>
            </li>
          ))}
        </ul>
      )}

      {openReport && item.report && (
        <div className="mt-2 border-t border-border-light pt-2">
          {/* Literal, like the message: a report quotes paths and commands.
              It scrolls with the page, never in a box of its own. */}
          <p className="whitespace-pre-wrap break-words text-[11px] leading-relaxed text-text-secondary">
            {item.report}
          </p>
          {item.reportTruncated && (
            <p className="mt-2 text-[11px] italic text-text-muted">
              The producer cut this report at its size limit.
            </p>
          )}
        </div>
      )}

      {/* The bubble's foot: what to open, how the line ended, and when. */}
      <div className="mt-1 flex flex-wrap items-center justify-end gap-x-3 gap-y-1">
        {item.claims.length > 0 && (
          <button
            type="button"
            aria-expanded={openClaims}
            onClick={() => setOpenClaims((open) => !open)}
            className="mr-auto text-[11px] text-accent-strong hover:underline"
          >
            {openClaims ? "Hide" : "Show"} {item.claims.length} claim
            {item.claims.length === 1 ? "" : "s"}
          </button>
        )}
        {item.report && (
          <button
            type="button"
            aria-expanded={openReport}
            onClick={() => setOpenReport((open) => !open)}
            className={`${item.claims.length > 0 ? "" : "mr-auto"} text-[11px] text-accent-strong hover:underline`}
          >
            {openReport ? "Hide" : "Read"} full report
          </button>
        )}
        {badge && <span className={`rounded border px-1.5 text-[11px] ${badge.cls}`}>{badge.label}</span>}
        {confidence && (
          <span className="text-[11px] text-text-secondary" title="Confidence the speaker stated">
            {confidence}
          </span>
        )}
        {time && (
          <time dateTime={item.ts} className="text-[11px] tabular-nums text-text-secondary">
            {time}
          </time>
        )}
      </div>
    </article>
  );
}

/* Memoised on the item, which the conversation builder keeps identical for a
 * line nothing has changed — so a three-thousand-line replay redraws the line
 * that just arrived rather than every line before it. */
export default memo(MessageBubble);
