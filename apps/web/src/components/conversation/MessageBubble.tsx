"use client";

/* One thing a participant said.
 *
 * Everybody sits on the left. The reader is a spectator here, and
 * right-alignment in a chat means "sent by me" — claiming one of the agents
 * on the reader's behalf would be a lie about who said what. Identity is
 * carried the way a group thread carries it instead: a coloured name, an
 * avatar, and a rule down the side, with consecutive lines from one speaker
 * sharing a single header.
 *
 * The body stays one line. Claims and the speaker's full prose are both real
 * and both often long, so each sits behind a disclosure that renders only
 * when it is open — a collapsed report must not be findable by a text search
 * the reader did not ask for.
 */

import { useState } from "react";
import { ArrowRight, CircleHelp, Gavel } from "lucide-react";

import type { ConversationItem } from "@/lib/conversation";
import { agentColor } from "./agentIdentity";

const STATUS_BADGE: Record<string, { label: string; cls: string }> = {
  no_data: { label: "no data", cls: "border-status-orange/30 bg-status-orange/10 text-status-orange" },
  no_claims: { label: "no report", cls: "border-status-orange/30 bg-status-orange/10 text-status-orange" },
  failed: { label: "failed", cls: "border-status-red/30 bg-status-red/10 text-status-red" },
  timeout: { label: "timed out", cls: "border-status-red/30 bg-status-red/10 text-status-red" },
};

/** `12:04` from an ISO timestamp; empty when there is not one. */
function clock(ts: string): string {
  if (!ts) return "";
  const at = new Date(ts);
  if (Number.isNaN(at.getTime())) return "";
  return at.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

export default function MessageBubble({
  item,
  initials,
  showHeader,
}: {
  item: ConversationItem;
  initials: string;
  showHeader: boolean;
}) {
  const [openClaims, setOpenClaims] = useState(false);
  const [openReport, setOpenReport] = useState(false);

  const color = agentColor(item.speaker);
  const verdict = item.kind === "verdict";
  const badge = item.status ? STATUS_BADGE[item.status] : undefined;
  const confidence =
    item.confidence === undefined ? "" : `${Math.round(item.confidence * 100)}%`;

  return (
    <div className="flex gap-2.5">
      <div className="w-7 shrink-0">
        {showHeader && (
          <span
            className="flex h-7 w-7 items-center justify-center rounded-full border text-[11px] font-semibold"
            style={{ borderColor: color, color }}
            aria-hidden="true"
          >
            {initials}
          </span>
        )}
      </div>

      <div className="min-w-0 flex-1">
        {showHeader && (
          <div className="mb-1 flex flex-wrap items-baseline gap-x-2 gap-y-1">
            <span className="text-xs font-semibold" style={{ color }}>
              {item.displayName}
            </span>
            {item.addressedToName && (
              <span className="flex items-center gap-1 text-[11px] text-text-muted">
                <ArrowRight size={11} aria-hidden="true" />
                {item.addressedToName}
              </span>
            )}
            {badge && (
              <span className={`rounded border px-1.5 text-[11px] uppercase tracking-wider ${badge.cls}`}>
                {badge.label}
              </span>
            )}
            {confidence && (
              <span className="font-mono text-[11px] text-text-muted">{confidence}</span>
            )}
            <span className="font-mono text-[11px] text-text-tertiary">{clock(item.ts)}</span>
          </div>
        )}

        <div
          className={`rounded border px-3 py-2 ${
            verdict
              ? "border-accent/40 bg-bg-elevated"
              : item.kind === "judge_question"
                ? "border-status-purple/30 bg-bg-surface"
                : "border-border bg-bg-surface"
          }`}
          style={verdict ? undefined : { borderLeftColor: color, borderLeftWidth: 2 }}
        >
          {verdict && (
            <span className="mb-1 flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-accent-strong">
              <Gavel size={12} aria-hidden="true" />
              Verdict
            </span>
          )}
          {item.kind === "judge_question" && (
            <span className="mb-1 flex items-center gap-1.5 text-[11px] uppercase tracking-wider text-status-purple">
              <CircleHelp size={12} aria-hidden="true" />
              Question
            </span>
          )}
          <p className="whitespace-pre-wrap text-xs leading-relaxed text-text-primary">
            {item.text}
            {item.streaming && (
              <span className="ml-1 inline-block h-3 w-1.5 align-middle bg-text-muted animate-pulse" aria-hidden="true" />
            )}
          </p>

          {item.dissent.length > 0 && (
            <p className="mt-1.5 text-[11px] text-status-orange">
              Disputes: {item.dissent.join("; ")}
            </p>
          )}

          {(item.claims.length > 0 || item.report) && (
            <div className="mt-1.5 flex gap-3">
              {item.claims.length > 0 && (
                <button
                  type="button"
                  onClick={() => setOpenClaims((open) => !open)}
                  className="text-[11px] text-accent-strong hover:underline"
                >
                  {openClaims ? "Hide" : "Show"} {item.claims.length} claim
                  {item.claims.length === 1 ? "" : "s"}
                </button>
              )}
              {item.report && (
                <button
                  type="button"
                  onClick={() => setOpenReport((open) => !open)}
                  className="text-[11px] text-accent-strong hover:underline"
                >
                  {openReport ? "Hide" : "Read"} full report
                </button>
              )}
            </div>
          )}

          {openClaims && (
            <ul className="mt-2 space-y-1.5 border-t border-border-light pt-2">
              {item.claims.map((claim, i) => (
                <li key={`${item.id}-claim-${i}`} className="text-[11px] leading-relaxed">
                  <span className="text-text-primary">{claim.claim}</span>
                  {claim.evidence_ref && (
                    <span className="block font-mono text-text-muted">{claim.evidence_ref}</span>
                  )}
                  {/* Secondary rather than tertiary: a verdict bubble is
                      `bg-bg-elevated`, where tertiary is 4.10:1. */}
                  <span className="text-text-secondary">
                    {claim.technique_id ? `${claim.technique_id} · ` : ""}
                    {Math.round(claim.confidence * 100)}%
                  </span>
                </li>
              ))}
            </ul>
          )}

          {openReport && item.report && (
            <pre className="mt-2 max-h-80 overflow-auto whitespace-pre-wrap border-t border-border-light pt-2 font-sans text-[11px] leading-relaxed text-text-secondary">
              {item.report}
              {item.reportTruncated ? "\n\n[The producer cut this report at its size limit.]" : ""}
            </pre>
          )}
        </div>
      </div>
    </div>
  );
}
