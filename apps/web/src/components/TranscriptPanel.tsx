"use client";

/* The agent conversation, as a conversation.
 *
 * Used unchanged in two places: the LIVE tab while the pipeline runs, and the
 * PROCESS tab afterwards. Both pass `TranscriptMessage[]` built by
 * lib/transcript.ts, so a run and its replay cannot render differently.
 *
 * Layout follows the pipeline's own shape rather than a generic chat: domain
 * analysts sit on the left as participants, while the stages that rule on them
 * — mediator, sycophancy detector, judge — span the full width, because they
 * are speaking *about* the conversation rather than in it.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import {
  isStageSpeaker,
  type TranscriptMessage,
  type TranscriptStatus,
} from "@/lib/transcript";

const SPEAKER_COLORS: Record<string, string> = {
  static: "#79c0ff",
  dynamic: "#ff7b72",
  network: "#ffa657",
  code: "#7ee787",
  yara: "#d2a8ff",
  sigma: "#f2cc60",
  mediator: "#a5d6ff",
  judge: "#e3b341",
};
const FALLBACK_COLOR = "#8b949e";

function speakerColor(speaker: string): string {
  const key = speaker.toLowerCase().replace(/\s*analyst$/, "").trim();
  return SPEAKER_COLORS[key] ?? FALLBACK_COLOR;
}

function speakerLabel(speaker: string): string {
  const trimmed = speaker.trim();
  if (!trimmed) return "Unknown";
  // Registry names arrive lower-case ("static"); persisted rows may already be
  // title-cased ("Static Analyst"). Normalise so the same agent does not appear
  // under two names in one transcript.
  return trimmed.charAt(0).toUpperCase() + trimmed.slice(1);
}

const STATUS_BADGE: Record<TranscriptStatus, { label: string; cls: string } | null> = {
  complete: null,
  no_data: {
    label: "no data",
    cls: "bg-status-orange/10 text-status-orange border-status-orange/30",
  },
  failed: {
    label: "failed",
    cls: "bg-status-red/10 text-status-red border-status-red/30",
  },
  timeout: {
    label: "timed out",
    cls: "bg-status-red/10 text-status-red border-status-red/30",
  },
};

const ROLE_LABEL: Record<string, string> = {
  analyst: "initial analysis",
  reviser: "revised",
  negotiator: "mediation",
  judge: "verdict",
  system: "system",
};

interface Props {
  messages: TranscriptMessage[];
  /** Live mode: auto-scroll, and show who is currently working. */
  live?: boolean;
  /** Agent currently running, for the live "working" row. */
  activeSpeaker?: string | null;
  /** Rendered when there is nothing to show yet. */
  emptyHint?: string;
}

export default function TranscriptPanel({
  messages,
  live = false,
  activeSpeaker = null,
  emptyHint,
}: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [roleFilter, setRoleFilter] = useState<"all" | "analysts" | "stages">("all");
  const endRef = useRef<HTMLDivElement | null>(null);

  const visible = useMemo(() => {
    if (roleFilter === "analysts") {
      return messages.filter((m) => !isStageSpeaker(m.role));
    }
    if (roleFilter === "stages") {
      return messages.filter((m) => isStageSpeaker(m.role));
    }
    return messages;
  }, [messages, roleFilter]);

  // Only follow the tail while live. Scrolling a finished transcript out from
  // under someone who is reading it is worse than making them scroll.
  useEffect(() => {
    if (!live) return;
    endRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [live, visible.length]);

  const toggle = (id: string) =>
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });

  const claimTotal = messages.reduce((sum, m) => sum + m.claims.length, 0);

  return (
    <div className="bg-bg-surface border border-border rounded flex flex-col">
      <div className="px-4 py-3 border-b border-border flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <h2 className="text-xs font-medium text-text-primary uppercase tracking-wider">
            Agent Transcript
          </h2>
          {live && (
            <span className="flex items-center gap-1.5 text-[11px] text-status-green">
              <span className="w-1.5 h-1.5 rounded-full bg-status-green animate-pulse" />
              live
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-text-muted">
            {messages.length} message{messages.length === 1 ? "" : "s"}
            {claimTotal > 0 && ` · ${claimTotal} claim${claimTotal === 1 ? "" : "s"}`}
          </span>
          <div className="flex border border-border rounded overflow-hidden">
            {(
              [
                ["all", "All"],
                ["analysts", "Analysts"],
                ["stages", "Stages"],
              ] as const
            ).map(([key, label]) => (
              <button
                key={key}
                onClick={() => setRoleFilter(key)}
                aria-pressed={roleFilter === key}
                className={`px-2 py-0.5 text-[11px] transition-colors ${
                  roleFilter === key
                    ? "bg-bg-hover text-text-primary"
                    : "text-text-muted hover:text-text-secondary"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
      </div>

      {visible.length === 0 ? (
        <p className="px-4 py-8 text-sm text-text-muted text-center">
          {emptyHint ??
            (live
              ? "Waiting for the first agent to report…"
              : "No agent transcript was recorded for this run.")}
        </p>
      ) : (
        <div className="divide-y divide-border-light max-h-[70vh] overflow-y-auto">
          {visible.map((message, index) => {
            const previous = index > 0 ? visible[index - 1] : null;
            const newRound = !previous || previous.round !== message.round;
            return (
              <div key={message.id}>
                {newRound && message.round > 0 && (
                  <div className="px-4 py-1.5 bg-bg-base/40 flex items-center gap-2">
                    <span className="text-[10px] uppercase tracking-wider text-text-muted">
                      Negotiation round {message.round}
                    </span>
                    <span className="flex-1 h-px bg-border-light" />
                  </div>
                )}
                <MessageRow
                  message={message}
                  expanded={expanded.has(message.id)}
                  onToggle={() => toggle(message.id)}
                />
              </div>
            );
          })}
          {live && activeSpeaker && (
            <div className="flex gap-3 px-4 py-3">
              <Avatar speaker={activeSpeaker} />
              <div className="flex items-center gap-2 text-sm text-text-muted">
                <span style={{ color: speakerColor(activeSpeaker) }}>
                  {speakerLabel(activeSpeaker)}
                </span>
                <span className="flex gap-1" aria-label="analysing">
                  {[0, 150, 300].map((delay) => (
                    <span
                      key={delay}
                      className="w-1 h-1 rounded-full bg-text-muted animate-pulse"
                      style={{ animationDelay: `${delay}ms` }}
                    />
                  ))}
                </span>
                <span className="text-xs">analysing…</span>
              </div>
            </div>
          )}
          <div ref={endRef} />
        </div>
      )}
    </div>
  );
}

function Avatar({ speaker }: { speaker: string }) {
  const color = speakerColor(speaker);
  return (
    <div
      className="shrink-0 w-7 h-7 rounded flex items-center justify-center text-[11px] font-medium border"
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}15` }}
      aria-hidden="true"
    >
      {speakerLabel(speaker).slice(0, 2)}
    </div>
  );
}

function MessageRow({
  message,
  expanded,
  onToggle,
}: {
  message: TranscriptMessage;
  expanded: boolean;
  onToggle: () => void;
}) {
  const color = speakerColor(message.speaker);
  const badge = STATUS_BADGE[message.status];
  const stage = isStageSpeaker(message.role);
  const hasDetail = message.claims.length > 0 || message.dissent.length > 0;

  return (
    <div
      className={`flex gap-3 px-4 py-3 hover:bg-bg-hover transition-colors ${
        stage ? "bg-bg-base/30" : ""
      }`}
    >
      <Avatar speaker={message.speaker} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-1">
          <span className="text-xs font-medium" style={{ color }}>
            {speakerLabel(message.speaker)}
          </span>
          <span className="text-[10px] text-text-muted uppercase tracking-wider">
            {ROLE_LABEL[message.role] ?? message.role}
          </span>
          {badge && (
            <span className={`px-1.5 py-0.5 text-[10px] rounded border ${badge.cls}`}>
              {badge.label}
            </span>
          )}
          {message.confidence !== undefined && (
            <span
              className="text-[11px] text-text-muted font-mono"
              /* Self-reported confidence in the agent's OWN claim — not a
               * probability of maliciousness. The title spells that out because
               * the audit found "Malicious · 100% · no malicious behaviour"
               * being read as a verdict. */
              title="The agent's confidence in its own finding, not a maliciousness score"
            >
              {Math.round(message.confidence * 100)}%
            </span>
          )}
        </div>

        {message.text && (
          <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap break-words">
            {message.text}
          </p>
        )}

        {hasDetail && (
          <>
            <button
              onClick={onToggle}
              aria-expanded={expanded}
              className="mt-2 text-[11px] text-text-muted hover:text-text-primary transition-colors"
            >
              {expanded ? "▾" : "▸"} {message.claims.length} claim
              {message.claims.length === 1 ? "" : "s"}
              {message.dissent.length > 0 &&
                ` · ${message.dissent.length} dissent`}
            </button>

            {expanded && (
              <div className="mt-2 space-y-2">
                {message.claims.map((claim, i) => (
                  <div
                    key={i}
                    className="border-l-2 pl-3 py-0.5"
                    style={{ borderColor: `${color}55` }}
                  >
                    <div className="flex items-baseline gap-2 flex-wrap">
                      <span className="text-sm text-text-primary">{claim.claim}</span>
                      {claim.technique_id && (
                        <span className="px-1 py-0.5 text-[10px] font-mono rounded bg-bg-base text-text-muted border border-border">
                          {claim.technique_id}
                        </span>
                      )}
                      <span className="text-[11px] text-text-muted font-mono">
                        {Math.round(claim.confidence * 100)}%
                      </span>
                    </div>
                    {claim.evidence_ref && (
                      /* Every claim must cite a concrete artefact — that is the
                       * grounding rule the analysts are held to, so the evidence
                       * is shown next to the claim rather than hidden a click away. */
                      <p className="text-[11px] text-text-muted font-mono mt-0.5 break-all">
                        {claim.evidence_ref}
                      </p>
                    )}
                  </div>
                ))}

                {message.dissent.length > 0 && (
                  <div className="border-l-2 border-status-orange/50 pl-3 py-0.5">
                    <p className="text-[10px] uppercase tracking-wider text-status-orange mb-1">
                      Still disputes
                    </p>
                    <ul className="space-y-0.5">
                      {message.dissent.map((item, i) => (
                        <li key={i} className="text-xs text-text-secondary">
                          {item}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
