"use client";

/* The agent conversation, rendered as one.
 *
 * Used unchanged in two places: the LIVE tab while the pipeline runs, and the
 * PROCESS tab afterwards. Both pass `TranscriptMessage[]` built by
 * lib/transcript.ts, so a run and its replay cannot render differently.
 *
 * This is a group chat and the reader is a spectator, so **every speaker sits
 * on the left**. Nobody is "you": right-alignment in a messaging app means
 * "sent by me", and claiming one of the agents on the reader's behalf would be
 * a lie about who said what. What carries identity instead is the same thing
 * that carries it in any group thread — a coloured name, an avatar, and
 * grouping: consecutive messages from one speaker share a single header, so a
 * three-round argument reads as a conversation rather than a table.
 *
 * Two things are deliberately *not* bubbles. Round changes are centred chips,
 * like the date dividers in WhatsApp, because they mark time rather than
 * speech. And `role: "system"` — the sycophancy detector — is a centred
 * notice, because it is the room telling you something, not a participant
 * making a claim.
 *
 * Message bodies stay one line. The evidence behind a claim and the agent's
 * full prose report are both real, both often long, and both live behind
 * disclosures that render only when opened: an unexpanded thread must stay
 * skimmable, and a collapsed report must not exist in the DOM to be found by
 * a text search that the reader did not ask for.
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
  // Previously fell through to grey, which read as an unremarkable participant.
  // It is an intervention, and it is the reason a round exists.
  "sycophancy detector": "#f0883e",
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

/* What this message is, *within* its round.
 *
 * `analyst` is deliberately blank: the round chip above the group already says
 * "Initial analysis", and every bubble under it would have repeated the same
 * two words. The others earn their label — inside one negotiation round a
 * revision, a mediation and a verdict are genuinely different acts. */
const ROLE_LABEL: Record<string, string> = {
  analyst: "",
  reviser: "revised",
  negotiator: "mediation",
  judge: "verdict",
  system: "system",
};

/** `12:04` from an ISO timestamp; empty when there isn't one. */
function clock(ts?: string): string {
  if (!ts) return "";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "";
  return d.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit" });
}

interface Props {
  messages: TranscriptMessage[];
  /** Live mode: auto-scroll, and show who is currently working. */
  live?: boolean;
  /** Agent currently running, for the live "typing" row. */
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
  const [openClaims, setOpenClaims] = useState<Set<string>>(new Set());
  const [openReports, setOpenReports] = useState<Set<string>>(new Set());
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

  const toggler =
    (set: (fn: (prev: Set<string>) => Set<string>) => void) => (id: string) =>
      set((prev) => {
        const next = new Set(prev);
        if (next.has(id)) next.delete(id);
        else next.add(id);
        return next;
      });
  const toggleClaims = toggler(setOpenClaims);
  const toggleReport = toggler(setOpenReports);

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
        <div className="bg-bg-base/20 max-h-[70vh] overflow-y-auto px-3 py-3 space-y-1">
          {visible.map((message, index) => {
            const previous = index > 0 ? visible[index - 1] : null;
            const newRound = !previous || previous.round !== message.round;
            /* Same speaker, same round, uninterrupted — one header for the
             * run, exactly as a messaging app groups a burst. A round chip
             * always breaks the group: it is a new moment in the argument. */
            const grouped =
              !newRound &&
              previous !== null &&
              previous.speaker === message.speaker &&
              previous.role === message.role;

            return (
              <div key={message.id}>
                {newRound && <RoundChip round={message.round} />}
                {message.role === "system" ? (
                  <SystemNotice message={message} />
                ) : (
                  <Bubble
                    message={message}
                    grouped={grouped}
                    claimsOpen={openClaims.has(message.id)}
                    reportOpen={openReports.has(message.id)}
                    onToggleClaims={() => toggleClaims(message.id)}
                    onToggleReport={() => toggleReport(message.id)}
                  />
                )}
              </div>
            );
          })}
          {live && activeSpeaker && <TypingRow speaker={activeSpeaker} />}
          <div ref={endRef} />
        </div>
      )}
    </div>
  );
}

/** Centred divider marking where a round begins — the date-chip pattern. */
function RoundChip({ round }: { round: number }) {
  return (
    <div className="flex justify-center py-2">
      <span className="px-2.5 py-0.5 rounded-full bg-bg-surface border border-border text-[10px] uppercase tracking-wider text-text-muted">
        {round > 0 ? `Negotiation round ${round}` : "Initial analysis"}
      </span>
    </div>
  );
}

/**
 * A centred notice rather than a bubble.
 *
 * The sycophancy detector is not a participant — it is the process telling the
 * reader that the agreement it just watched was not earned. Rendering it as a
 * message from a sixth agent would bury the one line most worth noticing.
 */
function SystemNotice({ message }: { message: TranscriptMessage }) {
  return (
    <div className="flex justify-center py-2">
      <div className="max-w-[85%] px-3 py-2 rounded-lg bg-status-orange/10 border border-status-orange/25 text-center">
        <p className="text-[11px] uppercase tracking-wider text-status-orange mb-0.5">
          {speakerLabel(message.speaker)}
        </p>
        <p className="text-xs text-text-secondary leading-relaxed whitespace-pre-wrap break-words">
          {message.text}
        </p>
      </div>
    </div>
  );
}

function Avatar({ speaker }: { speaker: string }) {
  const color = speakerColor(speaker);
  return (
    <div
      className="shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-[11px] font-medium border"
      style={{ color, borderColor: `${color}55`, backgroundColor: `${color}15` }}
      aria-hidden="true"
    >
      {speakerLabel(speaker).slice(0, 2)}
    </div>
  );
}

function TypingRow({ speaker }: { speaker: string }) {
  return (
    <div className="flex gap-2 items-end pt-1">
      <Avatar speaker={speaker} />
      <div className="px-3 py-2 rounded-2xl rounded-bl-sm bg-bg-surface border border-border flex items-center gap-2">
        <span className="text-xs" style={{ color: speakerColor(speaker) }}>
          {speakerLabel(speaker)}
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
      </div>
    </div>
  );
}

function Bubble({
  message,
  grouped,
  claimsOpen,
  reportOpen,
  onToggleClaims,
  onToggleReport,
}: {
  message: TranscriptMessage;
  grouped: boolean;
  claimsOpen: boolean;
  reportOpen: boolean;
  onToggleClaims: () => void;
  onToggleReport: () => void;
}) {
  const color = speakerColor(message.speaker);
  const badge = STATUS_BADGE[message.status];
  const hasClaims = message.claims.length > 0 || message.dissent.length > 0;
  const time = clock(message.ts);

  return (
    <div className={`flex gap-2 items-end ${grouped ? "pt-0.5" : "pt-2"}`}>
      {/* A spacer keeps grouped messages aligned under the first one's avatar. */}
      {grouped ? (
        <div className="shrink-0 w-7" aria-hidden="true" />
      ) : (
        <Avatar speaker={message.speaker} />
      )}

      <div
        className={`max-w-[85%] min-w-0 bg-bg-surface border border-border px-3 py-2 rounded-2xl ${
          grouped ? "rounded-bl-2xl" : "rounded-bl-sm"
        }`}
        style={{ borderLeftColor: `${color}66` }}
      >
        {!grouped && (
          <div className="flex items-baseline gap-2 mb-1 flex-wrap">
            <span className="text-xs font-medium" style={{ color }}>
              {speakerLabel(message.speaker)}
            </span>
            {(ROLE_LABEL[message.role] ?? message.role) && (
              <span className="text-[10px] uppercase tracking-wider text-text-muted">
                {ROLE_LABEL[message.role] ?? message.role}
              </span>
            )}
          </div>
        )}

        {message.text && (
          <p className="text-sm text-text-secondary leading-relaxed whitespace-pre-wrap break-words">
            {message.text}
          </p>
        )}

        {(hasClaims || message.report) && (
          <div className="flex items-center gap-2 mt-1.5 flex-wrap">
            {hasClaims && (
              <button
                onClick={onToggleClaims}
                aria-expanded={claimsOpen}
                className="text-[11px] text-text-muted hover:text-accent transition-colors"
              >
                {claimsOpen ? "▾" : "▸"} {message.claims.length} claim
                {message.claims.length === 1 ? "" : "s"}
                {message.dissent.length > 0 &&
                  ` · ${message.dissent.length} dispute${
                    message.dissent.length === 1 ? "" : "s"
                  }`}
              </button>
            )}
            {message.report && (
              <button
                onClick={onToggleReport}
                aria-expanded={reportOpen}
                className="text-[11px] text-text-muted hover:text-accent transition-colors"
              >
                {reportOpen ? "▾" : "▸"} full report
              </button>
            )}
          </div>
        )}

        {claimsOpen && hasClaims && <ClaimList message={message} color={color} />}

        {reportOpen && message.report && (
          /* Bounded and scrollable: these run to thousands of characters, and
           * an unbounded one would push every other message off the screen —
           * which is exactly the failure the one-line body exists to avoid. */
          <div className="mt-2 pt-2 border-t border-border-light">
            <pre className="text-[11px] text-text-secondary leading-relaxed whitespace-pre-wrap break-words font-sans max-h-64 overflow-y-auto">
              {message.report}
            </pre>
            {message.reportTruncated && (
              <p className="mt-1 text-[10px] text-text-muted italic">
                Truncated — the full text is in the report export.
              </p>
            )}
          </div>
        )}

        <div className="flex items-center gap-2 mt-1 justify-end flex-wrap">
          {badge && (
            <span
              className={`px-1.5 py-0.5 text-[10px] uppercase tracking-wider border rounded ${badge.cls}`}
            >
              {badge.label}
            </span>
          )}
          {message.confidence !== undefined && (
            <span className="text-[10px] text-text-muted tabular-nums">
              {Math.round(message.confidence * 100)}%
            </span>
          )}
          {time && <span className="text-[10px] text-text-muted">{time}</span>}
        </div>
      </div>
    </div>
  );
}

function ClaimList({
  message,
  color,
}: {
  message: TranscriptMessage;
  color: string;
}) {
  return (
    <div className="mt-2 pt-2 border-t border-border-light space-y-2">
      {message.claims.map((claim, i) => (
        <div
          key={`${message.id}-claim-${i}`}
          className="pl-2 border-l-2"
          style={{ borderColor: `${color}55` }}
        >
          <p className="text-xs text-text-primary leading-relaxed break-words">
            {claim.claim}
          </p>
          <div className="flex items-center gap-2 mt-0.5 flex-wrap">
            {claim.technique_id && (
              <span className="px-1 py-0.5 text-[10px] rounded bg-bg-base border border-border text-text-muted">
                {claim.technique_id}
              </span>
            )}
            <span className="text-[10px] text-text-muted tabular-nums">
              {Math.round(claim.confidence * 100)}%
            </span>
            {claim.evidence_ref && (
              <span className="text-[10px] text-text-muted font-mono break-all">
                {claim.evidence_ref}
              </span>
            )}
          </div>
        </div>
      ))}

      {message.dissent.length > 0 && (
        <div className="pl-2 border-l-2 border-status-orange/50">
          <p className="text-[10px] uppercase tracking-wider text-status-orange mb-0.5">
            Still disputes
          </p>
          {message.dissent.map((item, i) => (
            <p
              key={`${message.id}-dissent-${i}`}
              className="text-xs text-text-secondary leading-relaxed break-words"
            >
              {item}
            </p>
          ))}
        </div>
      )}
    </div>
  );
}
